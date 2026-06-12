"""Unit tests for ``autopwn.core.shell_verify`` (v4.0.4 — echo PWNED).

Per ``upgraded.md`` §3.1 v4.0.4: the sole visible success signal is
``echo PWNED`` being echoed back by the shell.  This module tests
:func:`verify_shell` (the ``echo PWNED`` protocol) and
:func:`record_success_verified` (silent dispatch + silent report gate).

We use a small in-process ``pwnlib.tubes.tube`` mock rather than
spawning a real binary, to keep CI fast and deterministic.
"""
from __future__ import annotations

import io
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# verify_shell — echo PWNED protocol
# ---------------------------------------------------------------------------


class _FakeTube:
    """Minimal pwntools-tube stand-in for verify_shell tests.

    Captures sent bytes and feeds a pre-canned receive queue.  The
    real ``verify_shell`` calls ``sendline``, ``recv``, ``recvuntil``,
    and ``recvline``; we implement just those.
    """

    def __init__(self, recv_queue: list[bytes], sent: io.BytesIO | None = None):
        self._recv_queue = list(recv_queue)
        self._sent = sent if sent is not None else io.BytesIO()
        self._closed = False

    def sendline(self, data: bytes) -> int:
        self._sent.write(data + b"\n")
        return len(data) + 1

    def recv(self, timeout: float = 0.1) -> bytes:
        if not self._recv_queue:
            return b""
        return self._recv_queue.pop(0)

    def recvuntil(self, needle: bytes, timeout: float = 2.0) -> bytes:
        # Concatenate the queue until we see ``needle``.  Push back
        # any tail (after the needle) so a subsequent ``recvline`` can
        # see it.
        buf = b""
        while self._recv_queue:
            buf += self._recv_queue.pop(0)
        idx = buf.find(needle)
        if idx >= 0:
            tail = buf[idx + len(needle):]
            if tail:
                self._recv_queue.insert(0, tail)
            return buf[: idx + len(needle)]
        raise EOFError(f"needle {needle!r} not found in queue")

    def recvline(self, timeout: float = 2.0) -> bytes:
        # Find the first newline in the queue, return up to and
        # including it.  Re-push any tail after the newline.
        buf = b""
        while self._recv_queue:
            buf += self._recv_queue.pop(0)
        idx = buf.find(b"\n")
        if idx >= 0:
            tail = buf[idx + 1:]
            if tail:
                self._recv_queue.insert(0, tail)
            return buf[: idx + 1]
        if not buf:
            raise EOFError("no newline in queue")
        return buf + b"\n"

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed


class TestVerifyShellEchoPwned:
    """``verify_shell`` must send ``echo PWNED`` and look for ``PWNED``."""

    def test_sends_echo_pwned_and_returns_token_on_match(self):
        from autopwn.core.shell_verify import verify_shell

        sent = io.BytesIO()
        # After ``recvuntil("PWNED")`` returns, ``recvline`` must still
        # have bytes to consume.  Provide a queue that has the PWNED
        # token AND a trailing newline in the SAME byte buffer so
        # recvline can read the line.
        tube = _FakeTube(
            recv_queue=[b"$ ", b"PWNED\n"],
            sent=sent,
        )
        ok, out = verify_shell(tube, timeout=2.0)
        assert ok is True
        assert "PWNED" in out
        # The probe command was sent verbatim.
        assert sent.getvalue() == b"echo PWNED\n"

    def test_returns_false_when_no_pwned_in_output(self):
        from autopwn.core.shell_verify import verify_shell

        tube = _FakeTube(
            recv_queue=[b"some shell output\n", b"no token here\n"],
        )
        ok, out = verify_shell(tube, timeout=0.1)
        assert ok is False
        assert out == ""

    def test_returns_false_on_eof(self):
        from autopwn.core.shell_verify import verify_shell

        # No output at all — recvuntil will raise EOFError.
        tube = _FakeTube(recv_queue=[])
        ok, out = verify_shell(tube, timeout=0.1)
        assert ok is False
        assert out == ""

    def test_tube_is_closed_in_finally(self):
        """verify_shell must close the tube on all exit paths (v4.0.4)."""
        from autopwn.core.shell_verify import verify_shell

        tube = _FakeTube(recv_queue=[b"PWNED\n"])
        verify_shell(tube, timeout=2.0)
        assert tube.closed is True

    def test_keep_alive_true_preserves_tube(self):
        """v4.0.4: keep_alive=True must NOT close the tube — strategy
        needs the live tube to call ``io.interactive()`` and drop the
        user into a real shell.
        """
        from autopwn.core.shell_verify import verify_shell

        # Banner + PWNED output as two separate items so the initial
        # ``io.recv(0.1)`` drains the banner and ``recvuntil`` still
        # sees PWNED.
        tube = _FakeTube(recv_queue=[b"$ ", b"PWNED\n"])
        ok, _ = verify_shell(tube, timeout=2.0, keep_alive=True)
        assert ok is True
        assert tube.closed is False  # CRITICAL: tube must stay alive

    def test_keep_alive_false_still_closes_tube(self):
        """Backward compat: keep_alive=False (default) closes the tube."""
        from autopwn.core.shell_verify import verify_shell

        tube = _FakeTube(recv_queue=[b"PWNED\n"])
        verify_shell(tube, timeout=2.0, keep_alive=False)
        assert tube.closed is True

    def test_keep_alive_true_on_failure_does_not_close(self):
        """Even on verify failure, keep_alive=True must not close the
        tube (caller might want to inspect manually after timeout).
        """
        from autopwn.core.shell_verify import verify_shell

        tube = _FakeTube(recv_queue=[])  # no PWNED → verify fails
        ok, _ = verify_shell(tube, timeout=0.1, keep_alive=True)
        assert ok is False
        assert tube.closed is False


# ---------------------------------------------------------------------------
# record_success_verified — silent success, no banner
# ---------------------------------------------------------------------------


class TestRecordSuccessVerifiedSilent:
    """v4.0.4: no banner print, docx generated only on verify_ok=True."""

    def _make_info(self):
        from autopwn.report.model import ExploitInfo

        return ExploitInfo(
            exploit_type="ret2system - x64",
            payload=b"A" * 23,
            padding=23,
            addresses={"system_addr": 0x401040},
            vulnerability_type="Buffer Overflow",
            architecture="x64",
            target_binary="rip",
        )

    def test_no_banner_printed_on_success(self, capsys):
        """v4.0.4: must NOT print ``EXPLOITATION SUCCESSFUL!`` banner."""
        from autopwn.core.shell_verify import record_success_verified

        info = self._make_info()
        with mock.patch("autopwn.report.record_success") as mock_record:
            ok = record_success_verified(info, True, "PWNED\n")

        assert ok is True
        # record_success dispatched (docx generated)
        assert mock_record.called
        # BUT no banner was printed
        captured = capsys.readouterr()
        assert "EXPLOITATION SUCCESSFUL" not in captured.out
        assert "Dropping to shell" not in captured.out

    def test_stamps_verify_output_on_info_and_ctx(self):
        """info.id_output + ctx.id_output = canonical "PWNED\\n"."""
        from autopwn.core.shell_verify import record_success_verified

        info = self._make_info()
        ctx = mock.MagicMock()
        with mock.patch("autopwn.report.record_success"):
            record_success_verified(info, True, "PWNED\n", ctx)

        assert info.id_output == "PWNED\n"
        assert ctx.id_output == "PWNED\n"

    def test_no_dispatch_on_failure(self):
        """verify_ok=False → no record_success call, no banner, return False."""
        from autopwn.core.shell_verify import record_success_verified

        info = self._make_info()
        with mock.patch("autopwn.report.record_success") as mock_record:
            ok = record_success_verified(info, False, "", ctx=None)

        assert ok is False
        assert not mock_record.called
        assert info.id_output == ""  # not mutated
