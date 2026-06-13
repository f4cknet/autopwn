"""Unit tests for ``autopwn.core.tee`` (v4.1.8 — stdout/stderr mirroring).

Per ``upgraded.md`` §3.2 v4.1.8: ``cli.main()`` wraps ``sys.stdout``
and ``sys.stderr`` with :class:`autopwn.core.tee.Tee` to mirror
output to ``logs/{challenge_name}/run.log``.  This file covers the
:class:`Tee` class behaviors (write fan-out, flush fan-out, TTY
detection, attribute delegation, error isolation).
"""
from __future__ import annotations

import io
import sys

import pytest

from autopwn.core.tee import Tee


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_tee_requires_at_least_one_stream():
    """Empty constructor raises ``ValueError`` (defensive)."""
    with pytest.raises(ValueError, match="at least one"):
        Tee()


def test_tee_accepts_single_stream():
    """A single-stream ``Tee`` is a valid identity-like wrapper."""
    buf = io.StringIO()
    tee = Tee(buf)
    assert tee.write("hi") == 2
    assert buf.getvalue() == "hi"


# ---------------------------------------------------------------------------
# write — fan-out
# ---------------------------------------------------------------------------


def test_tee_write_fans_out_to_all_streams():
    """``write()`` writes the same data to every underlying stream."""
    a, b, c = io.StringIO(), io.StringIO(), io.StringIO()
    tee = Tee(a, b, c)
    n = tee.write("hello\n")
    assert n == len("hello\n")
    assert a.getvalue() == "hello\n"
    assert b.getvalue() == "hello\n"
    assert c.getvalue() == "hello\n"


def test_tee_write_coerces_non_string_to_str():
    """Non-string input is coerced (matches Python file semantics)."""
    buf = io.StringIO()
    tee = Tee(buf)
    tee.write(42)  # int input
    assert buf.getvalue() == "42"


def test_tee_write_isolates_stream_failure():
    """A failing stream does not break writes to the others."""
    class BadStream(io.StringIO):
        def write(self, data):
            raise OSError("disk full")

    good = io.StringIO()
    tee = Tee(BadStream(), good)
    # Should not raise even though the first stream fails
    tee.write("survived\n")
    assert good.getvalue() == "survived\n"


# ---------------------------------------------------------------------------
# flush — fan-out
# ---------------------------------------------------------------------------


def test_tee_flush_calls_all_streams():
    """``flush()`` is invoked on every underlying stream."""
    flushed = []

    class FlakyStream(io.StringIO):
        def __init__(self, name):
            super().__init__()
            self._name = name

        def flush(self):
            flushed.append(self._name)

    a, b = FlakyStream("a"), FlakyStream("b")
    tee = Tee(a, b)
    tee.write("x")
    tee.flush()
    assert flushed == ["a", "b"]


# ---------------------------------------------------------------------------
# isatty — TTY detection
# ---------------------------------------------------------------------------


def test_tee_isatty_true_when_any_stream_is_tty():
    """``isatty()`` is ``True`` if **any** stream is interactive."""

    class TtyStream(io.StringIO):
        def isatty(self):
            return True

    tee = Tee(io.StringIO(), TtyStream())
    assert tee.isatty() is True


def test_tee_isatty_false_when_no_stream_is_tty():
    """``isatty()`` is ``False`` when all streams are buffers."""
    tee = Tee(io.StringIO(), io.StringIO())
    assert tee.isatty() is False


def test_tee_isatty_handles_missing_isatty():
    """A stream without ``isatty`` attribute is skipped silently."""

    class WeirdStream:
        def write(self, data):
            pass

        def flush(self):
            pass

        # No isatty attribute

    tee = Tee(WeirdStream())
    assert tee.isatty() is False


# ---------------------------------------------------------------------------
# fileno — fd delegation
# ---------------------------------------------------------------------------


def test_tee_fileno_delegates_to_first_real_stream():
    """``fileno()`` returns the first underlying stream's fd."""
    real = io.StringIO()  # StringIO has no real fd

    class FdStream(io.StringIO):
        def fileno(self):
            return 7  # arbitrary

    tee = Tee(real, FdStream())
    assert tee.fileno() == 7


def test_tee_fileno_raises_when_no_stream_has_fileno():
    """``fileno()`` raises ``OSError`` if no stream exposes one."""

    class NoFdStream:
        def write(self, data):
            pass

    tee = Tee(NoFdStream())
    with pytest.raises(OSError):
        tee.fileno()


# ---------------------------------------------------------------------------
# Attribute delegation
# ---------------------------------------------------------------------------


def test_tee_delegates_known_attributes_to_first_stream():
    """``encoding`` / ``newlines`` etc. are read from first stream."""
    real_stdout = sys.stdout
    tee = Tee(real_stdout)
    # sys.stdout has an ``encoding`` attribute — we should see the
    # same value via Tee (no override defined).
    assert tee.encoding == real_stdout.encoding


def test_tee_attribute_lookup_raises_when_no_stream_has_it():
    """Unknown attribute access raises ``AttributeError``."""
    tee = Tee(io.StringIO())
    with pytest.raises(AttributeError, match="nonexistent_xyz"):
        tee.nonexistent_xyz


# ---------------------------------------------------------------------------
# v4.1.8 integration: real-world stdout replacement
# ---------------------------------------------------------------------------


def test_tee_can_replace_sysstdout_round_trip():
    """Replace ``sys.stdout`` with Tee, write, restore — no leakage."""
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = Tee(real, buf)
    try:
        print("captured line", end="")
    finally:
        sys.stdout = real

    # The buffer should have received "captured line" (no newline,
    # because ``end=""`` and print() doesn't auto-add a newline here).
    assert "captured line" in buf.getvalue()


# ---------------------------------------------------------------------------
# cli._resolve_log_path — v4.1.8 log path resolution
# ---------------------------------------------------------------------------


def test_resolve_log_path_for_local_binary(tmp_path, monkeypatch):
    """Local binary → ``logs/{stem}/run.log`` (cwd-relative)."""
    monkeypatch.chdir(tmp_path)
    from autopwn.cli import _resolve_log_path
    args = type("A", (), {"local": "Challenge/level3_x64", "ip": None, "port": None})()
    p = _resolve_log_path(args)
    assert p is not None
    assert p.name == "run.log"
    assert p.parent.name == "level3_x64"
    assert p.parent.parent.name == "logs"
    # Directory was auto-created
    assert p.parent.is_dir()


def test_resolve_log_path_for_remote(tmp_path, monkeypatch):
    """Remote target → ``logs/remote_{ip}_{port}/run.log``."""
    monkeypatch.chdir(tmp_path)
    from autopwn.cli import _resolve_log_path
    args = type("A", (), {"local": None, "ip": "10.0.0.1", "port": 9999})()
    p = _resolve_log_path(args)
    assert p is not None
    assert p.name == "run.log"
    assert p.parent.name == "remote_10.0.0.1_9999"


def test_resolve_log_path_returns_none_when_no_identifier(tmp_path, monkeypatch):
    """No ``-l`` and no ``-ip`` → ``None`` (skip log capture)."""
    monkeypatch.chdir(tmp_path)
    from autopwn.cli import _resolve_log_path
    args = type("A", (), {"local": None, "ip": None, "port": None})()
    assert _resolve_log_path(args) is None
