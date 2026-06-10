"""Unit tests for ``autopwn.exp.strategies.ret2libc_write_x32`` +
``autopwn.exp.strategies.ret2libc_write_x64`` (P7.5).

Per ``rebuild.md`` §6.8 P7.5 + ``refactor.md`` §3.2.2, every
strategy needs:

  * :attr:`priority` matches 附录 A (``RET2LIBC_WRITE = 110``).
  * :attr:`requires_*` filter correctly (arch + remote + ``has_write``).
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no write / no gadgets / no libc) and does NOT raise.
  * The 2-stage flow is wired correctly: stage 1 leak → leak
    parse → stage 2 system.  Verified via mock patching.

Reuses the P7.3 ``importlib.reload`` autouse fixture pattern
to defeat Python's ``sys.modules`` import cache.
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

    Also reloads P7.3 + P7.4 strategy modules so the candidates
    tests can verify cross-strategy priority ordering (e.g.
    ret2libc_put winning over ret2libc_write when both apply).
    """
    import importlib

    from autopwn.exp.registry import reset

    reset()
    # Reload P7.3 + P7.4 + P7.5 strategy modules so @register
    # side-effects fire for all of them (P7.3 fix).
    import autopwn.exp.strategies.ret2system_x32  # noqa: F401
    import autopwn.exp.strategies.ret2system_x64  # noqa: F401
    import autopwn.exp.strategies.ret2libc_put_x32  # noqa: F401
    import autopwn.exp.strategies.ret2libc_put_x64  # noqa: F401
    import autopwn.exp.strategies.ret2libc_write_x32  # noqa: F401
    import autopwn.exp.strategies.ret2libc_write_x64  # noqa: F401
    importlib.reload(autopwn.exp.strategies.ret2system_x32)
    importlib.reload(autopwn.exp.strategies.ret2system_x64)
    importlib.reload(autopwn.exp.strategies.ret2libc_put_x32)
    importlib.reload(autopwn.exp.strategies.ret2libc_put_x64)
    importlib.reload(autopwn.exp.strategies.ret2libc_write_x32)
    importlib.reload(autopwn.exp.strategies.ret2libc_write_x64)
    yield
    reset()


def _ctx_32(mode: str = "local", *, has_write: bool = True, **overrides):
    """Build a x32 ctx with has_write set (matching case by default)."""
    ctx = ctx_for("canary", bit=32, **overrides)
    ctx.mode = mode
    ctx.has_write = has_write
    return ctx


def _ctx_64(mode: str = "local", *, has_write: bool = True, **overrides):
    """Build a x64 ctx with has_write + gadgets set (x64 needs pop_rdi+pop_rsi+ret)."""
    from autopwn.context import RopGadgetsX64

    ctx = ctx_for("rip", bit=64, **overrides)
    ctx.mode = mode
    ctx.has_write = has_write
    ctx.gadgets_x64 = RopGadgetsX64(
        pop_rdi=0x401234,
        pop_rsi=0x401238,
        ret=0x40123c,
    )
    return ctx


# ---------------------------------------------------------------------------
# Priority / metadata
# ---------------------------------------------------------------------------


class TestRet2LibcWritePriority:
    """All 4 ret2libc-write strategies share ``priority = RET2LIBC_WRITE = 110``."""

    def test_x32_local_priority_is_ret2libc_write(self):
        from autopwn.exp.priorities import RET2LIBC_WRITE
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        assert Ret2LibcWriteX32LocalStrategy.priority == RET2LIBC_WRITE == 110

    def test_x32_remote_priority_is_ret2libc_write(self):
        from autopwn.exp.priorities import RET2LIBC_WRITE
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32RemoteStrategy,
        )

        assert Ret2LibcWriteX32RemoteStrategy.priority == RET2LIBC_WRITE == 110

    def test_x64_local_priority_is_ret2libc_write(self):
        from autopwn.exp.priorities import RET2LIBC_WRITE
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        assert Ret2LibcWriteX64LocalStrategy.priority == RET2LIBC_WRITE == 110

    def test_x64_remote_priority_is_ret2libc_write(self):
        from autopwn.exp.priorities import RET2LIBC_WRITE
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64RemoteStrategy,
        )

        assert Ret2LibcWriteX64RemoteStrategy.priority == RET2LIBC_WRITE == 110

    def test_ret2libc_write_lt_ret2libc_put_lt_ret2system(self):
        """Per 附录 A: ret2system=150 > ret2libc_put=120 > ret2libc_write=110."""
        from autopwn.exp.priorities import (
            RET2LIBC_PUT,
            RET2LIBC_WRITE,
            RET2SYSTEM,
        )

        assert RET2SYSTEM > RET2LIBC_PUT > RET2LIBC_WRITE


class TestRet2LibcWriteMetadata:
    """The 4 strategies declare the right ``requires_*`` metadata."""

    def test_x32_local_arch_32_remote_false_has_write(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        s = Ret2LibcWriteX32LocalStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is False
        assert s.requires == ("has_write",)

    def test_x32_remote_arch_32_remote_true_has_write(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32RemoteStrategy,
        )

        s = Ret2LibcWriteX32RemoteStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is True
        assert s.requires == ("has_write",)

    def test_x64_local_arch_64_remote_false_has_write(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is False
        assert s.requires == ("has_write",)

    def test_x64_remote_arch_64_remote_true_has_write(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64RemoteStrategy,
        )

        s = Ret2LibcWriteX64RemoteStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is True
        assert s.requires == ("has_write",)

    def test_name_is_set_for_log_lines(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
            Ret2LibcWriteX32RemoteStrategy,
        )
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
            Ret2LibcWriteX64RemoteStrategy,
        )

        for cls in [
            Ret2LibcWriteX32LocalStrategy,
            Ret2LibcWriteX32RemoteStrategy,
            Ret2LibcWriteX64LocalStrategy,
            Ret2LibcWriteX64RemoteStrategy,
        ]:
            assert cls.name, f"{cls.__name__} has empty name"
            assert "ret2libc-write" in cls.name


# ---------------------------------------------------------------------------
# matches()
# ---------------------------------------------------------------------------


class TestRet2LibcWriteMatches:
    """``matches`` filter behavior on each variant."""

    def test_x32_local_matches_x32_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        assert Ret2LibcWriteX32LocalStrategy().matches(_ctx_32()) is True

    def test_x32_local_rejects_x64_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        assert Ret2LibcWriteX32LocalStrategy().matches(_ctx_64()) is False

    def test_x32_local_rejects_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcWriteX32LocalStrategy().matches(ctx) is False

    def test_x32_local_rejects_no_has_write(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        assert Ret2LibcWriteX32LocalStrategy().matches(_ctx_32(has_write=False)) is False

    def test_x32_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32RemoteStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcWriteX32RemoteStrategy().matches(ctx) is True

    def test_x32_remote_rejects_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32RemoteStrategy,
        )

        assert Ret2LibcWriteX32RemoteStrategy().matches(_ctx_32()) is False

    def test_x64_local_matches_x64_local_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        assert Ret2LibcWriteX64LocalStrategy().matches(_ctx_64()) is True

    def test_x64_local_rejects_x32_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        assert Ret2LibcWriteX64LocalStrategy().matches(_ctx_32()) is False

    def test_x64_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64RemoteStrategy,
        )

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert Ret2LibcWriteX64RemoteStrategy().matches(ctx) is True


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestRet2LibcWriteCandidates:
    """``candidates(ctx)`` returns the right ret2libc-write variant."""

    def test_candidates_x32_local_ctx_returns_x32_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_32())
        names = [s.name for s in result]
        assert "ret2libc-write-x32" in names
        assert "ret2libc-write-x32-remote" not in names
        assert "ret2libc-write-x64" not in names
        assert "ret2libc-write-x64-remote" not in names

    def test_candidates_x64_local_ctx_returns_x64_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_64())
        names = [s.name for s in result]
        assert "ret2libc-write-x64" in names
        assert "ret2libc-write-x32" not in names
        assert "ret2libc-write-x32-remote" not in names
        assert "ret2libc-write-x64-remote" not in names

    def test_candidates_x32_remote_ctx_returns_x32_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2libc-write-x32-remote" in names
        assert "ret2libc-write-x32" not in names

    def test_candidates_x64_remote_ctx_returns_x64_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2libc-write-x64-remote" in names
        assert "ret2libc-write-x64" not in names

    def test_candidates_no_has_write_returns_no_ret2libc_write(self):
        """``has_write=False`` filters out all ret2libc-write strategies."""
        from autopwn.exp import candidates

        result = candidates(_ctx_32(has_write=False))
        for s in result:
            assert s.name not in (
                "ret2libc-write-x32",
                "ret2libc-write-x32-remote",
                "ret2libc-write-x64",
                "ret2libc-write-x64-remote",
            )

    def test_candidates_put_wins_over_write_when_both_present(self):
        """When both has_puts and has_write are set, ret2libc_put (120) wins
        over ret2libc_write (110) on a 32-bit local ctx."""
        from autopwn.exp import candidates

        ctx = _ctx_32()  # has_write=True (matching case)
        ctx.has_puts = True  # also has puts
        result = candidates(ctx)
        names = [s.name for s in result]
        # Both strategies are present
        assert "ret2libc-put-x32" in names
        assert "ret2libc-write-x32" in names
        # But put comes first (higher priority)
        put_idx = names.index("ret2libc-put-x32")
        write_idx = names.index("ret2libc-write-x32")
        assert put_idx < write_idx, "ret2libc_put (120) should come before ret2libc_write (110)"


# ---------------------------------------------------------------------------
# run() graceful-skip conditions
# ---------------------------------------------------------------------------


class TestRet2LibcWriteRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx."""

    def test_x32_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        s = Ret2LibcWriteX32LocalStrategy()
        ctx = _ctx_32()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        assert s.run(ctx) is False

    def test_x64_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        ctx = _ctx_64()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        assert s.run(ctx) is False

    def test_x32_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32RemoteStrategy,
        )

        s = Ret2LibcWriteX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        assert s.run(ctx) is False

    def test_x64_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64RemoteStrategy,
        )

        s = Ret2LibcWriteX64RemoteStrategy()
        ctx = _ctx_64()
        ctx.remote = None
        assert s.run(ctx) is False

    def test_x64_local_run_returns_false_when_gadgets_missing(self):
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = None
        assert s.run(ctx) is False

    def test_x64_local_run_returns_false_when_pop_rsi_missing(self):
        """Defensive: pop_rsi=0 (missing) is a graceful skip."""
        from autopwn.context import RopGadgetsX64
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0x401234,
            pop_rsi=0,  # missing
            ret=0x40123c,
        )
        assert s.run(ctx) is False

    def test_x64_local_run_returns_false_when_pop_rdi_missing(self):
        """Defensive: pop_rdi=0 (missing) is a graceful skip."""
        from autopwn.context import RopGadgetsX64
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0,  # missing
            pop_rsi=0x401238,
            ret=0x40123c,
        )
        assert s.run(ctx) is False


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestRet2LibcWriteModuleStructure:
    """The 2 strategy modules are importable + export their classes."""

    def test_x32_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2libc_write_x32
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
            Ret2LibcWriteX32RemoteStrategy,
        )

        assert ret2libc_write_x32.Ret2LibcWriteX32LocalStrategy is Ret2LibcWriteX32LocalStrategy
        assert ret2libc_write_x32.Ret2LibcWriteX32RemoteStrategy is Ret2LibcWriteX32RemoteStrategy
        assert set(ret2libc_write_x32.__all__) == {
            "Ret2LibcWriteX32LocalStrategy",
            "Ret2LibcWriteX32RemoteStrategy",
        }

    def test_x64_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2libc_write_x64
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
            Ret2LibcWriteX64RemoteStrategy,
        )

        assert ret2libc_write_x64.Ret2LibcWriteX64LocalStrategy is Ret2LibcWriteX64LocalStrategy
        assert ret2libc_write_x64.Ret2LibcWriteX64RemoteStrategy is Ret2LibcWriteX64RemoteStrategy
        assert set(ret2libc_write_x64.__all__) == {
            "Ret2LibcWriteX64LocalStrategy",
            "Ret2LibcWriteX64RemoteStrategy",
        }

    def test_no_strategy_inherits_exploitresult(self):
        from autopwn.primitives.base import ExploitResult
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        assert not issubclass(Ret2LibcWriteX32LocalStrategy, ExploitResult)


# ---------------------------------------------------------------------------
# End-to-end (mocked IO) — 2-stage flow verification
# ---------------------------------------------------------------------------


class TestRet2LibcWriteRunInvokesRecordSuccess:
    """Mock ``pwn.process`` to confirm the 2-stage flow reaches ``record_success``.

    The strategy must:
      1. Open process, send stage 1 (leak), parse 4-byte (x32) or 8-byte (x64) leak.
      2. Build stage 2 via primitive, send.
      3. Construct ExploitInfo + call record_success.
      4. io.interactive().
    """

    def test_x32_local_2stage_flow_completes(self):
        """Mock primitive to return known stage1/stage2 payloads (since no
        Challenge/ x32 binary has write@plt, primitive lookup is
        mocked)."""
        from autopwn.context import LibcInfo
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = Ret2LibcWriteX32LocalStrategy()
        ctx = _ctx_32()
        ctx.libc = LibcInfo(path=Path("/lib32/libc.so.6"))

        mock_io = MagicMock()
        # Stage 1 recv: 4 raw bytes of a libc write address.
        mock_io.recv.return_value = b"\x10\x20\x30\x40"
        mock_io.recvuntil.return_value = b""

        # Mock the primitive to return non-empty stage1 / stage2 payloads.
        # The real canary/fmtstr1 have no write@plt, so the primitive
        # would naturally return b"" on the real binary; we mock around
        # this since the strategy-level IO wiring is what we're testing.
        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = b"\x90" * 64 + b"\x10\x20\x30\x40"
        mock_primitive.build_stage2_payload.return_value = b"\x90" * 64 + b"\xaa\xbb\xcc\xdd"

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_write_x32.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.ret2libc_write_x32.Ret2LibcWriteX32", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "ret2libc (write) - x32"
        assert info_arg.architecture == "x32"
        assert "write_addr" in info_arg.addresses
        assert mock_io.sendline.call_count == 2
        assert mock_verify_shell.call_count == 1

    def test_x64_local_2stage_flow_completes(self):
        """Same 2-stage contract for x64 (8-byte leak + gadget chain)."""
        from autopwn.context import LibcInfo
        from autopwn.exp.strategies.ret2libc_write_x64 import (
            Ret2LibcWriteX64LocalStrategy,
        )

        s = Ret2LibcWriteX64LocalStrategy()
        ctx = _ctx_64()
        ctx.libc = LibcInfo(path=Path("/lib/x86_64-linux-gnu/libc.so.6"))

        mock_io = MagicMock()
        mock_io.recv.return_value = b"\x10\x20\x30\x40\x50\x60\x70\x80"
        mock_io.recvuntil.return_value = b""

        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = b"\x90" * 64 + b"\x10\x20\x30\x40\x50\x60\x70\x80"
        mock_primitive.build_stage2_payload.return_value = b"\x90" * 64 + b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_write_x64.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.ret2libc_write_x64.Ret2LibcWriteX64", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "ret2libc (write) - x64"
        assert info_arg.architecture == "x64"
        assert "write_addr" in info_arg.addresses
        assert mock_io.sendline.call_count == 2
        assert mock_verify_shell.call_count == 1

    def test_x32_local_leak_parse_failure_returns_false(self):
        """If the leak recv raises, the strategy returns False (not crash)."""
        from autopwn.exp.strategies.ret2libc_write_x32 import (
            Ret2LibcWriteX32LocalStrategy,
        )

        s = Ret2LibcWriteX32LocalStrategy()
        ctx = _ctx_32()

        mock_io = MagicMock()
        # recv raises — simulates a bad leak / closed connection.
        mock_io.recv.side_effect = EOFError("connection closed")

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2libc_write_x32.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            result = s.run(ctx)

        assert result is False
        assert mock_record.call_count == 0
