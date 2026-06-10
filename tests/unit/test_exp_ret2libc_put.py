"""Unit tests for ``autopwn.exp.strategies.ret2libc_put_x32`` +
``autopwn.exp.strategies.ret2libc_put_x64`` (P7.4).

Per ``rebuild.md`` §6.8 P7.4 + ``refactor.md`` §3.2.2, every
strategy needs:

  * :attr:`priority` matches 附录 A (``RET2LIBC_PUT = 120``).
  * :attr:`requires_*` filter correctly (arch + remote + ``has_puts``).
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no puts / no gadgets / no libc) and does NOT raise.
  * The 2-stage flow is wired correctly: stage 1 leak → leak
    parse → stage 2 system.  Verified via mock patching of
    ``pwn.process`` / ``pwn.remote`` + primitive IO.

The real ``run()`` end-to-end (with actual process spawn) is
exercised by §2.6 (5-binary serial verify) on real
``Challenge/`` binaries.  P9.4 integration tests will add
explicit per-binary coverage.

Reuses the P7.3 ``importlib.reload`` autouse fixture pattern
to defeat Python's ``sys.modules`` import cache that otherwise
skips the second @register execution.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.strategy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset registry + reload strategy modules (per P7.3 lesson).

    Python's ``sys.modules`` caches imports; a plain second
    ``import`` does NOT re-execute the @register decorator,
    leaving the registry empty.  ``importlib.reload`` forces
    re-execution.
    """
    import importlib

    from autopwn.exp.registry import reset

    reset()
    import autopwn.exp.strategies.ret2libc_put_x32  # noqa: F401
    import autopwn.exp.strategies.ret2libc_put_x64  # noqa: F401
    importlib.reload(autopwn.exp.strategies.ret2libc_put_x32)
    importlib.reload(autopwn.exp.strategies.ret2libc_put_x64)
    yield
    reset()


def _ctx_32(mode: str = "local", *, has_puts: bool = True, **overrides):
    """Build a x32 ctx with has_puts set (matching case by default)."""
    ctx = ctx_for("canary", bit=32, **overrides)
    ctx.mode = mode
    ctx.has_puts = has_puts
    return ctx


def _ctx_64(mode: str = "local", *, has_puts: bool = True, **overrides):
    """Build a x64 ctx with has_puts + gadgets set."""
    from autopwn.context import RopGadgetsX64

    ctx = ctx_for("rip", bit=64, **overrides)
    ctx.mode = mode
    ctx.has_puts = has_puts
    ctx.gadgets_x64 = RopGadgetsX64(
        pop_rdi=0x401234,
        pop_rsi=0x401238,
        ret=0x40123c,
    )
    return ctx


# ---------------------------------------------------------------------------
# Priority / metadata
# ---------------------------------------------------------------------------


class TestRet2LibcPutPriority:
    """All 4 ret2libc-put strategies share ``priority = RET2LIBC_PUT = 120``."""

    def test_x32_local_priority_is_ret2libc_put(self):
        from autopwn.exp.priorities import RET2LIBC_PUT
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        assert Ret2LibcPutX32LocalStrategy.priority == RET2LIBC_PUT == 120

    def test_x32_remote_priority_is_ret2libc_put(self):
        from autopwn.exp.priorities import RET2LIBC_PUT
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32RemoteStrategy,
        )

        assert Ret2LibcPutX32RemoteStrategy.priority == RET2LIBC_PUT == 120

    def test_x64_local_priority_is_ret2libc_put(self):
        from autopwn.exp.priorities import RET2LIBC_PUT
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        assert Ret2LibcPutX64LocalStrategy.priority == RET2LIBC_PUT == 120

    def test_x64_remote_priority_is_ret2libc_put(self):
        from autopwn.exp.priorities import RET2LIBC_PUT
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64RemoteStrategy,
        )

        assert Ret2LibcPutX64RemoteStrategy.priority == RET2LIBC_PUT == 120

    def test_ret2libc_put_lt_ret2system_lt_canary(self):
        """Per 附录 A: canary=200 > ret2system=150 > ret2libc_put=120."""
        from autopwn.exp.priorities import (
            CANARY,
            RET2LIBC_PUT,
            RET2SYSTEM,
        )

        assert CANARY > RET2SYSTEM > RET2LIBC_PUT


class TestRet2LibcPutMetadata:
    """The 4 strategies declare the right ``requires_*`` metadata."""

    def test_x32_local_arch_32_remote_false_has_puts(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        s = Ret2LibcPutX32LocalStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is False
        assert s.requires == ("has_puts",)

    def test_x32_remote_arch_32_remote_true_has_puts(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32RemoteStrategy,
        )

        s = Ret2LibcPutX32RemoteStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is True
        assert s.requires == ("has_puts",)

    def test_x64_local_arch_64_remote_false_has_puts(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        s = Ret2LibcPutX64LocalStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is False
        assert s.requires == ("has_puts",)

    def test_x64_remote_arch_64_remote_true_has_puts(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64RemoteStrategy,
        )

        s = Ret2LibcPutX64RemoteStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is True
        assert s.requires == ("has_puts",)

    def test_name_is_set_for_log_lines(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
            Ret2LibcPutX32RemoteStrategy,
        )
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
            Ret2LibcPutX64RemoteStrategy,
        )

        for cls in [
            Ret2LibcPutX32LocalStrategy,
            Ret2LibcPutX32RemoteStrategy,
            Ret2LibcPutX64LocalStrategy,
            Ret2LibcPutX64RemoteStrategy,
        ]:
            assert cls.name, f"{cls.__name__} has empty name"
            assert "ret2libc-put" in cls.name


# ---------------------------------------------------------------------------
# matches()
# ---------------------------------------------------------------------------


class TestRet2LibcPutMatches:
    """``matches`` filter behavior on each variant."""

    def test_x32_local_matches_x32_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        assert Ret2LibcPutX32LocalStrategy().matches(_ctx_32()) is True

    def test_x32_local_rejects_x64_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        assert Ret2LibcPutX32LocalStrategy().matches(_ctx_64()) is False

    def test_x32_local_rejects_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcPutX32LocalStrategy().matches(ctx) is False

    def test_x32_local_rejects_no_has_puts(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        ctx = _ctx_32(has_puts=False)
        assert Ret2LibcPutX32LocalStrategy().matches(ctx) is False

    def test_x32_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32RemoteStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcPutX32RemoteStrategy().matches(ctx) is True

    def test_x32_remote_rejects_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32RemoteStrategy,
        )

        assert Ret2LibcPutX32RemoteStrategy().matches(_ctx_32()) is False

    def test_x64_local_matches_x64_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        assert Ret2LibcPutX64LocalStrategy().matches(_ctx_64()) is True

    def test_x64_local_rejects_x32_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        assert Ret2LibcPutX64LocalStrategy().matches(_ctx_32()) is False

    def test_x64_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64RemoteStrategy,
        )

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcPutX64RemoteStrategy().matches(ctx) is True


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestRet2LibcPutCandidates:
    """``candidates(ctx)`` returns the right ret2libc-put variant."""

    def test_candidates_x32_local_ctx_returns_x32_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_32())
        names = [s.name for s in result]
        assert "ret2libc-put-x32" in names
        assert "ret2libc-put-x32-remote" not in names
        assert "ret2libc-put-x64" not in names
        assert "ret2libc-put-x64-remote" not in names

    def test_candidates_x64_local_ctx_returns_x64_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_64())
        names = [s.name for s in result]
        assert "ret2libc-put-x64" in names
        assert "ret2libc-put-x32" not in names
        assert "ret2libc-put-x32-remote" not in names
        assert "ret2libc-put-x64-remote" not in names

    def test_candidates_x32_remote_ctx_returns_x32_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2libc-put-x32-remote" in names
        assert "ret2libc-put-x32" not in names

    def test_candidates_x64_remote_ctx_returns_x64_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2libc-put-x64-remote" in names
        assert "ret2libc-put-x64" not in names

    def test_candidates_no_has_puts_returns_no_ret2libc_put(self):
        """``has_puts=False`` filters out all ret2libc-put strategies."""
        from autopwn.exp import candidates

        result = candidates(_ctx_32(has_puts=False))
        for s in result:
            assert s.name not in (
                "ret2libc-put-x32",
                "ret2libc-put-x32-remote",
                "ret2libc-put-x64",
                "ret2libc-put-x64-remote",
            )


# ---------------------------------------------------------------------------
# run() graceful-skip conditions
# ---------------------------------------------------------------------------


class TestRet2LibcPutRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx."""

    def test_x32_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        s = Ret2LibcPutX32LocalStrategy()
        # Nonexistent binary → primitive's _lookup returns (None, None, None)
        # → payload = b"" → run() returns False
        ctx = _ctx_32()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        result = s.run(ctx)
        assert result is False

    def test_x64_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        s = Ret2LibcPutX64LocalStrategy()
        ctx = _ctx_64()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        result = s.run(ctx)
        assert result is False

    def test_x32_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32RemoteStrategy,
        )

        s = Ret2LibcPutX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        result = s.run(ctx)
        assert result is False

    def test_x64_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64RemoteStrategy,
        )

        s = Ret2LibcPutX64RemoteStrategy()
        ctx = _ctx_64()
        ctx.remote = None
        result = s.run(ctx)
        assert result is False

    def test_x64_local_run_returns_false_when_gadgets_missing(self):
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        s = Ret2LibcPutX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = None
        result = s.run(ctx)
        assert result is False

    def test_x64_local_run_returns_false_when_gadgets_have_zero_pop_rdi(self):
        """Defensive: pop_rdi=0 means ropper didn't find the gadget."""
        from autopwn.context import RopGadgetsX64
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        s = Ret2LibcPutX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0,  # missing
            pop_rsi=0x401238,
            ret=0x40123c,
        )
        result = s.run(ctx)
        assert result is False


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestRet2LibcPutModuleStructure:
    """The 2 strategy modules are importable + export their classes."""

    def test_x32_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2libc_put_x32
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
            Ret2LibcPutX32RemoteStrategy,
        )

        assert ret2libc_put_x32.Ret2LibcPutX32LocalStrategy is Ret2LibcPutX32LocalStrategy
        assert ret2libc_put_x32.Ret2LibcPutX32RemoteStrategy is Ret2LibcPutX32RemoteStrategy
        assert set(ret2libc_put_x32.__all__) == {
            "Ret2LibcPutX32LocalStrategy",
            "Ret2LibcPutX32RemoteStrategy",
        }

    def test_x64_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2libc_put_x64
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
            Ret2LibcPutX64RemoteStrategy,
        )

        assert ret2libc_put_x64.Ret2LibcPutX64LocalStrategy is Ret2LibcPutX64LocalStrategy
        assert ret2libc_put_x64.Ret2LibcPutX64RemoteStrategy is Ret2LibcPutX64RemoteStrategy
        assert set(ret2libc_put_x64.__all__) == {
            "Ret2LibcPutX64LocalStrategy",
            "Ret2LibcPutX64RemoteStrategy",
        }

    def test_no_strategy_inherits_exploitresult(self):
        from autopwn.primitives.base import ExploitResult
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        assert not issubclass(Ret2LibcPutX32LocalStrategy, ExploitResult)


# ---------------------------------------------------------------------------
# End-to-end (mocked IO) — 2-stage flow verification
# ---------------------------------------------------------------------------


class TestRet2LibcPutRunInvokesRecordSuccess:
    """Mock ``pwn.process`` to confirm the 2-stage flow reaches ``record_success``.

    The strategy must:
      1. Open process, send stage 1 (leak), parse 4-byte leak.
      2. Build stage 2 via primitive, send.
      3. Construct ExploitInfo + call record_success.
      4. io.interactive().
    """

    def test_x32_local_2stage_flow_completes(self):
        """Mock recv to return a known 4-byte leak value."""
        from autopwn.context import LibcInfo
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = Ret2LibcPutX32LocalStrategy()
        ctx = _ctx_32()
        # Stage 2 needs libc to resolve system + /bin/sh.  Set ctx.libc.path
        # to the real /lib32/libc.so.6 used by the canary binary.
        ctx.libc = LibcInfo(path=Path("/lib32/libc.so.6"))

        # Stage 1: build stage1 payload via primitive.  Real canary has
        # puts@plt, so primitive returns a non-empty payload.
        # Patch the primitive to return known stage1/stage2 payloads.
        mock_io = MagicMock()
        # recvuntil returns a buffer ending in 0xf7 followed by some bytes
        # (the libc address has 0xf7 as high byte in 32-bit Linux).
        mock_io.recvuntil.return_value = b"XXXX\xf7XYZ"
        mock_io.recv.return_value = b""

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_put_x32.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        # record_success called once
        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "ret2libc (puts) - x32"
        assert info_arg.architecture == "x32"
        # The leak puts_addr should be in addresses
        assert "puts_addr" in info_arg.addresses
        # IO was actually used
        assert mock_io.sendline.call_count == 2  # stage 1 + stage 2
        assert mock_verify_shell.call_count == 1

    def test_x64_local_2stage_flow_completes(self):
        """Same 2-stage contract for x64."""
        from autopwn.context import LibcInfo
        from autopwn.exp.strategies.ret2libc_put_x64 import (
            Ret2LibcPutX64LocalStrategy,
        )

        s = Ret2LibcPutX64LocalStrategy()
        ctx = _ctx_64()
        # Stage 2 needs libc.  rip binary uses the system 64-bit libc.
        ctx.libc = LibcInfo(path=Path("/lib/x86_64-linux-gnu/libc.so.6"))

        mock_io = MagicMock()
        # 6 bytes ending in 0x7f + padding
        mock_io.recvuntil.return_value = b"AAAAAA\x7fBBBBB"
        mock_io.recv.return_value = b""

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_put_x64.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "ret2libc (puts) - x64"
        assert info_arg.architecture == "x64"
        assert "puts_addr" in info_arg.addresses
        assert mock_io.sendline.call_count == 2
        assert mock_verify_shell.call_count == 1

    def test_x32_local_leak_parse_failure_returns_false(self):
        """If the leak recv raises, the strategy returns False (not crash)."""
        from autopwn.exp.strategies.ret2libc_put_x32 import (
            Ret2LibcPutX32LocalStrategy,
        )

        s = Ret2LibcPutX32LocalStrategy()
        ctx = _ctx_32()

        mock_io = MagicMock()
        # recvuntil raises — simulates a bad leak / closed connection.
        mock_io.recvuntil.side_effect = EOFError("connection closed")

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_put_x32.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            result = s.run(ctx)

        assert result is False
        # record_success should NOT be called on leak failure
        assert mock_record.call_count == 0
