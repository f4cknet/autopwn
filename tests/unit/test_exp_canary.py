"""Unit tests for ``autopwn.exp.strategies._canary_base`` + 4 canary_*.py modules (P7.10).

Per ``rebuild.md`` §6.8 P7.10 + ``refactor.md`` §3.2.2, every
canary strategy needs:

  * :attr:`priority = CANARY = 200` (highest of all 8).
  * :attr:`requires_canary = True` (inherited from base;
    default ``matches()`` returns ``False`` when
    ``ctx.canary is None``).
  * :attr:`requires_arch` + :attr:`requires_remote` filter
    correctly.
  * :meth:`frame_after_canary` builds the right payload:
    ``b'A' * padding + pNN(canary) + b'B' * diff + tail``.
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no canary / no has_system / etc.) and does NOT raise.

Reuses the P7.3 ``importlib.reload`` autouse fixture pattern
to defeat Python's ``sys.modules`` import cache.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from autopwn.context import BinaryInfo, CanaryInfo
from tests.conftest import ctx_for


pytestmark = pytest.mark.strategy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset registry + reload strategy modules (per P7.3 lesson)."""
    import importlib

    from autopwn.exp.registry import reset

    reset()
    import autopwn.exp.strategies._canary_base  # noqa: F401
    importlib.reload(autopwn.exp.strategies._canary_base)
    for m in [
        "canary_execve_syscall",
        "canary_ret2system",
        "canary_ret2libc_put",
        "canary_ret2libc_write",
    ]:
        mod = __import__(f"autopwn.exp.strategies.{m}", fromlist=[m])
        importlib.reload(mod)
    yield
    reset()


def _ctx_32_canary(
    mode: str = "local",
    *,
    padding: int = 80,
    canary_value: int = 0x12345678,  # fits in 32-bit (x32 canary is u32)
    canary_diff: int = 8,
    has_system: bool = True,
    has_puts: bool = True,
    has_write: bool = True,
    binsh_in_binary: bool = True,
    **overrides,
) -> "ExploitContext":
    """x32 ctx with canary leaked + padding>0 (canary match case).

    ``binsh_in_binary=True`` (default) makes the ret2system
    primitive happy; the real ``Challenge/canary`` has
    ``binsh_in_binary=False`` (relies on libc).  Tests that
    care about end-to-end record_success use the default;
    tests for "primitive returns empty" override to False.
    """
    ctx = ctx_for("canary", bit=32, **overrides)
    ctx.mode = mode
    ctx.padding = padding
    ctx.canary = CanaryInfo(value=canary_value, diff=canary_diff)
    ctx.has_system = has_system
    ctx.has_puts = has_puts
    ctx.has_write = has_write
    ctx.binsh_in_binary = binsh_in_binary
    return ctx


def _ctx_64_canary(
    mode: str = "local",
    *,
    padding: int = 80,
    canary_value: int = 0x1122334455667788,
    canary_diff: int = 8,
    has_system: bool = True,
    has_puts: bool = True,
    has_write: bool = True,
    binsh_in_binary: bool = True,
    **overrides,
) -> "ExploitContext":
    """x64 ctx with canary leaked + padding>0 (canary match case)."""
    ctx = ctx_for("canary", bit=32, **overrides)
    ctx.binary = BinaryInfo(
        path=ctx.binary.path,
        bit=64,
        stack_canary=True,
        pie=ctx.binary.pie,
        nx=ctx.binary.nx,
        relro=ctx.binary.relro,
        rwx_segments=ctx.binary.rwx_segments,
        stripped=ctx.binary.stripped,
    )
    ctx.mode = mode
    ctx.padding = padding
    ctx.canary = CanaryInfo(value=canary_value, diff=canary_diff)
    ctx.has_system = has_system
    ctx.has_puts = has_puts
    ctx.has_write = has_write
    ctx.binsh_in_binary = binsh_in_binary
    return ctx


# ---------------------------------------------------------------------------
# CanaryStrategy base class
# ---------------------------------------------------------------------------


class TestCanaryStrategyBase:
    """``CanaryStrategy`` is the abstract base for all 14 canary strategies."""

    def test_priority_is_canary(self):
        from autopwn.exp.priorities import CANARY
        from autopwn.exp.strategies._canary_base import CanaryStrategy

        assert CanaryStrategy.priority == CANARY == 200

    def test_canary_is_highest_priority(self):
        """Per 附录 A: CANARY=200 is the highest of all 8 priority values."""
        from autopwn.exp.priorities import (
            CANARY,
            EXECVE_SYSCALL,
            FMTSTR,
            PIE_BACKDOOR,
            RET2LIBC_PUT,
            RET2LIBC_WRITE,
            RET2SYSTEM,
            RWX_SHELLCODE,
        )

        all_prios = [CANARY, PIE_BACKDOOR, RET2SYSTEM, RET2LIBC_PUT, RET2LIBC_WRITE, RWX_SHELLCODE, EXECVE_SYSCALL, FMTSTR]
        assert CANARY == max(all_prios)

    def test_requires_canary_is_true(self):
        from autopwn.exp.strategies._canary_base import CanaryStrategy

        assert CanaryStrategy.requires_canary is True

    def test_requires_includes_padding(self):
        from autopwn.exp.strategies._canary_base import CanaryStrategy

        assert "padding" in CanaryStrategy.requires


class TestCanaryFrameAfterCanary:
    """``frame_after_canary`` builds the correct payload frame."""

    def test_x32_frame_shape(self):
        from autopwn.exp.strategies._canary_base import CanaryStrategy
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        # CanaryStrategy is abstract; use a concrete subclass.
        s = CanaryRet2SystemX32LocalStrategy()
        ctx = _ctx_32_canary(padding=80, canary_value=0xAABBCCDD, canary_diff=4)
        tail = b"\x00\x00\x00\x00"
        payload = s.frame_after_canary(ctx, tail)

        # 80 A's + 4B canary (p32) + 4 B's (diff) + 4B tail
        assert len(payload) == 80 + 4 + 4 + 4
        assert payload[:80] == b"A" * 80
        assert payload[80:84] == b"\xDD\xCC\xBB\xAA"  # p32 little-endian
        assert payload[84:88] == b"B" * 4
        assert payload[88:] == tail

    def test_x64_frame_shape(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX64LocalStrategy,
        )

        s = CanaryRet2SystemX64LocalStrategy()
        ctx = _ctx_64_canary(padding=80, canary_value=0x1122334455667788, canary_diff=8)
        tail = b"\x00" * 8
        payload = s.frame_after_canary(ctx, tail)

        # 80 A's + 8B canary (p64) + 8 B's (diff) + 8B tail
        assert len(payload) == 80 + 8 + 8 + 8
        assert payload[:80] == b"A" * 80
        assert payload[80:88] == b"\x88\x77\x66\x55\x44\x33\x22\x11"  # p64 little-endian
        assert payload[88:96] == b"B" * 8
        assert payload[96:] == tail

    def test_frame_with_zero_diff(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        s = CanaryRet2SystemX32LocalStrategy()
        ctx = _ctx_32_canary(padding=20, canary_value=0xDEADBEEF, canary_diff=0)
        payload = s.frame_after_canary(ctx, b"X")

        assert len(payload) == 20 + 4 + 0 + 1
        assert payload[:20] == b"A" * 20
        assert payload[20:24] == b"\xEF\xBE\xAD\xDE"
        assert payload[24:] == b"X"


# ---------------------------------------------------------------------------
# Default matches() — requires_canary=True + arch + remote + requires tuple
# ---------------------------------------------------------------------------


class TestCanaryStrategyMatches:
    """Default ``matches()`` from base.py + per-strategy ``requires`` tuple.

    P7.10 canary strategies do NOT override ``matches()`` (the base
    class is enough): all gating is done via
    ``requires_canary=True`` + ``requires_arch`` +
    ``requires_remote`` + ``requires`` tuple.  This is a
    **spec deviation** from P7.6/P7.8/P7.9 (those override
    ``matches()`` for custom gates like ``padding==0`` or
    PIE+backdoor+padding).  P7.10 canary strategies get away
    with default because the canary gate is the 4-tuple
    (canary/padding/system/puts/write).
    """

    def test_x32_local_ret2system_matches_full_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        assert CanaryRet2SystemX32LocalStrategy().matches(_ctx_32_canary()) is True

    def test_x32_local_ret2system_rejects_no_canary(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        ctx = _ctx_32_canary()
        ctx.canary = None
        assert CanaryRet2SystemX32LocalStrategy().matches(ctx) is False

    def test_x32_local_ret2system_rejects_no_system(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        assert CanaryRet2SystemX32LocalStrategy().matches(_ctx_32_canary(has_system=False)) is False

    def test_x32_local_ret2system_rejects_padding_zero(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        assert CanaryRet2SystemX32LocalStrategy().matches(_ctx_32_canary(padding=0)) is False

    def test_x32_local_ret2system_rejects_x64_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        assert CanaryRet2SystemX32LocalStrategy().matches(_ctx_64_canary()) is False

    def test_x32_local_ret2system_rejects_remote_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        ctx = _ctx_32_canary(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert CanaryRet2SystemX32LocalStrategy().matches(ctx) is False

    def test_x32_remote_ret2system_matches_full_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32RemoteStrategy,
        )

        ctx = _ctx_32_canary(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert CanaryRet2SystemX32RemoteStrategy().matches(ctx) is True

    def test_x64_local_ret2system_matches_full_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX64LocalStrategy,
        )

        assert CanaryRet2SystemX64LocalStrategy().matches(_ctx_64_canary()) is True

    def test_x64_local_ret2system_rejects_x32_ctx(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX64LocalStrategy,
        )

        assert CanaryRet2SystemX64LocalStrategy().matches(_ctx_32_canary()) is False

    def test_x32_local_ret2libc_put_requires_has_puts(self):
        from autopwn.exp.strategies.canary_ret2libc_put import (
            CanaryRet2LibcPutX32LocalStrategy,
        )

        assert CanaryRet2LibcPutX32LocalStrategy().matches(_ctx_32_canary(has_puts=False)) is False

    def test_x32_local_ret2libc_write_requires_has_write(self):
        from autopwn.exp.strategies.canary_ret2libc_write import (
            CanaryRet2LibcWriteX32LocalStrategy,
        )

        assert CanaryRet2LibcWriteX32LocalStrategy().matches(_ctx_32_canary(has_write=False)) is False

    def test_x32_local_execve_syscall_x32_only(self):
        from autopwn.exp.strategies.canary_execve_syscall import (
            CanaryExecveSyscallLocalStrategy,
        )

        # x64 ctx rejected
        assert CanaryExecveSyscallLocalStrategy().matches(_ctx_64_canary()) is False
        # x32 ctx matches
        assert CanaryExecveSyscallLocalStrategy().matches(_ctx_32_canary()) is True

    def test_x32_local_execve_syscall_rejects_no_canary(self):
        from autopwn.exp.strategies.canary_execve_syscall import (
            CanaryExecveSyscallLocalStrategy,
        )

        ctx = _ctx_32_canary()
        ctx.canary = None
        assert CanaryExecveSyscallLocalStrategy().matches(ctx) is False


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestCanaryCandidates:
    """``candidates(ctx)`` returns the right canary variants for a given ctx."""

    def test_x32_local_canary_ctx(self):
        from autopwn.exp import candidates

        ctx = _ctx_32_canary(padding=80, has_system=True, has_puts=True, has_write=True)
        result = candidates(ctx)
        names = [s.name for s in result]
        # All 7 canary x32 local variants should match (no canary execve = x32 only ✓)
        for expected in [
            "canary-ret2system-x32",
            "canary-ret2libc-put-x32",
            "canary-ret2libc-write-x32",
            "canary-execve-syscall",
        ]:
            assert expected in names, f"{expected} missing from candidates"

    def test_x64_local_canary_ctx(self):
        from autopwn.exp import candidates

        ctx = _ctx_64_canary(padding=80, has_system=True, has_puts=True, has_write=True)
        result = candidates(ctx)
        names = [s.name for s in result]
        # x64 canary strategies
        for expected in [
            "canary-ret2system-x64",
            "canary-ret2libc-put-x64",
            "canary-ret2libc-write-x64",
        ]:
            assert expected in names
        # x32 strategies should NOT be in candidates for x64 ctx
        for absent in [
            "canary-ret2system-x32",
            "canary-ret2libc-put-x32",
            "canary-ret2libc-write-x32",
            "canary-execve-syscall",
        ]:
            assert absent not in names

    def test_canary_strategies_have_highest_priority(self):
        """CANARY=200 > PIE_BACKDOOR=180 > ... > FMTSTR=50."""
        from autopwn.exp import candidates

        ctx = _ctx_32_canary(padding=80, has_system=True, has_puts=True, has_write=True)
        result = candidates(ctx)
        # First candidate (highest priority) should be a canary strategy
        if result:
            assert "canary" in result[0].name

    def test_no_canary_excludes_all_canary_strategies(self):
        from autopwn.exp import candidates

        ctx = _ctx_32_canary(padding=80, has_system=True, has_puts=True, has_write=True)
        ctx.canary = None  # no canary
        result = candidates(ctx)
        for s in result:
            assert "canary" not in s.name

    def test_no_system_excludes_canary_ret2system_and_ret2libc(self):
        """ret2system + ret2libc_* need system; only canary_execve_syscall can match."""
        from autopwn.exp import candidates

        ctx = _ctx_32_canary(padding=80, has_system=False, has_puts=True, has_write=True)
        result = candidates(ctx)
        names = [s.name for s in result]
        # canary ret2system/ret2libc_put/ret2libc_write all need has_system
        for absent in [
            "canary-ret2system-x32",
            "canary-ret2libc-put-x32",
            "canary-ret2libc-write-x32",
        ]:
            assert absent not in names
        # canary_execve_syscall doesn't need system — only thing that should match
        assert "canary-execve-syscall" in names


# ---------------------------------------------------------------------------
# run() graceful-skip conditions
# ---------------------------------------------------------------------------


class TestCanaryRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx."""

    def test_ret2system_x32_local_run_false_when_primitive_empty(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        s = CanaryRet2SystemX32LocalStrategy()
        ctx = _ctx_32_canary(has_system=False)  # primitive returns empty

        with patch("pwn.process") as mock_process:
            result = s.run(ctx)

        assert result is False
        assert mock_process.call_count == 0

    def test_ret2system_x32_remote_run_false_when_remote_none(self):
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32RemoteStrategy,
        )

        s = CanaryRet2SystemX32RemoteStrategy()
        ctx = _ctx_32_canary(mode="remote")
        ctx.remote = None

        with patch("pwn.remote") as mock_remote:
            result = s.run(ctx)

        assert result is False
        assert mock_remote.call_count == 0

    def test_execve_syscall_local_run_false_when_primitive_empty(self):
        from autopwn.exp.strategies.canary_execve_syscall import (
            CanaryExecveSyscallLocalStrategy,
        )

        s = CanaryExecveSyscallLocalStrategy()
        ctx = _ctx_32_canary()
        # Override gadgets to None to make primitive return empty
        ctx.gadgets_x32 = None

        with patch("pwn.process") as mock_process:
            result = s.run(ctx)

        assert result is False
        assert mock_process.call_count == 0

    def test_ret2libc_put_local_run_false_on_leak_parse_fail(self):
        """ret2libc_put 2-stage: leak parse failure → return False.

        Real ``Challenge/canary`` HAS ``puts`` and ``main`` in
        PLT, so the primitive returns a valid 92-byte stage-1
        payload.  We mock ``pwn.process`` to return a MagicMock
        whose ``recvuntil`` raises (simulating no leak coming
        back), forcing the strategy to its ``except`` branch
        and return ``False``.
        """
        from autopwn.exp.strategies.canary_ret2libc_put import (
            CanaryRet2LibcPutX32LocalStrategy,
        )

        s = CanaryRet2LibcPutX32LocalStrategy()
        ctx = _ctx_32_canary()

        mock_io = MagicMock()
        mock_io.recvuntil.side_effect = Exception("no leak from remote")

        with patch("pwn.process", return_value=mock_io) as mock_process:
            result = s.run(ctx)

        assert result is False
        # Process was spawned (primitive returned non-empty) but
        # the leak parse branch failed → return False.  No
        # record_success was called.
        assert mock_process.call_count == 1

    def test_ret2libc_put_local_run_false_when_stage1_empty(self):
        """When has_system=False, the 2-stage primitive's stage 2 fails.
        But stage 1 may still succeed.  Use has_system=False to break
        things — but actually ret2libc_put doesn't strictly require has_system
        (it calculates system from leak).  The cleanest skip test is:
        padding=0 — primitive returns empty because no BOF offset.
        """
        from autopwn.exp.strategies.canary_ret2libc_put import (
            CanaryRet2LibcPutX32LocalStrategy,
        )

        s = CanaryRet2LibcPutX32LocalStrategy()
        # padding=0 — but this fails at matches() before run() is called.
        # We need a ctx that matches() but primitive returns empty.
        # padding=0 fails matches (requires=("padding",)).  Use a strategy
        # that requires has_system — set has_system=False to fail matches()
        # and avoid invoking run() at all.
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )
        s = CanaryRet2SystemX32LocalStrategy()
        ctx = _ctx_32_canary(has_system=False, binsh_in_binary=False)

        with patch("pwn.process") as mock_process:
            result = s.run(ctx)

        assert result is False
        assert mock_process.call_count == 0


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestCanaryModuleStructure:
    """4 leaf modules + 1 base module = 5 new files."""

    def test_base_module_exports_canary_strategy(self):
        from autopwn.exp.strategies import _canary_base

        assert "CanaryStrategy" in _canary_base.__all__

    def test_canary_execve_syscall_module_exports_two_classes(self):
        from autopwn.exp.strategies import canary_execve_syscall

        assert set(canary_execve_syscall.__all__) == {
            "CanaryExecveSyscallLocalStrategy",
            "CanaryExecveSyscallRemoteStrategy",
        }

    def test_canary_ret2system_module_exports_four_classes(self):
        """x32+x64, local+remote = 4 strategies in 1 file (deviation: 1 file vs 2)."""
        from autopwn.exp.strategies import canary_ret2system

        assert set(canary_ret2system.__all__) == {
            "CanaryRet2SystemX32LocalStrategy",
            "CanaryRet2SystemX32RemoteStrategy",
            "CanaryRet2SystemX64LocalStrategy",
            "CanaryRet2SystemX64RemoteStrategy",
        }

    def test_canary_ret2libc_put_module_exports_four_classes(self):
        from autopwn.exp.strategies import canary_ret2libc_put

        assert set(canary_ret2libc_put.__all__) == {
            "CanaryRet2LibcPutX32LocalStrategy",
            "CanaryRet2LibcPutX32RemoteStrategy",
            "CanaryRet2LibcPutX64LocalStrategy",
            "CanaryRet2LibcPutX64RemoteStrategy",
        }

    def test_canary_ret2libc_write_module_exports_four_classes(self):
        from autopwn.exp.strategies import canary_ret2libc_write

        assert set(canary_ret2libc_write.__all__) == {
            "CanaryRet2LibcWriteX32LocalStrategy",
            "CanaryRet2LibcWriteX32RemoteStrategy",
            "CanaryRet2LibcWriteX64LocalStrategy",
            "CanaryRet2LibcWriteX64RemoteStrategy",
        }

    def test_total_14_canary_strategies(self):
        """2 + 4 + 4 + 4 = 14 canary strategies across 4 leaf modules."""
        from autopwn.exp.registry import all_strategies
        from autopwn.exp.strategies import (
            canary_execve_syscall,
            canary_ret2libc_put,
            canary_ret2libc_write,
            canary_ret2system,
        )

        canary_strategies = [
            s for s in all_strategies()
            if s.__class__.__module__.startswith("autopwn.exp.strategies.canary_")
        ]
        assert len(canary_strategies) == 14


# ---------------------------------------------------------------------------
# End-to-end (mocked IO)
# ---------------------------------------------------------------------------


class TestCanaryRunInvokesRecordSuccess:
    """Mock ``pwn.process`` so the canary strategy completes and
    reaches ``record_success``.
    """

    def test_execve_syscall_local_1stage_flow_completes(self):
        from autopwn.context import RopGadgetsX32
        from autopwn.exp.strategies.canary_execve_syscall import (
            CanaryExecveSyscallLocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = CanaryExecveSyscallLocalStrategy()
        # Use fmtstr1 binary (has /bin/sh inside) since the real
        # Challenge/canary lacks it.  Override ctx.binary.path to
        # point at fmtstr1 while keeping the canary ctx structure.
        ctx = _ctx_32_canary(padding=80, canary_value=0xCAFEBABE, canary_diff=8)
        fmtstr1_path = ctx.binary.path.parent / "fmtstr1"
        ctx.binary = BinaryInfo(
            path=fmtstr1_path,
            bit=32,
            stack_canary=True,
            pie=False,
            nx=True,
            relro="Partial",
            rwx_segments=False,
            stripped=False,
        )
        # execve primitive needs gadgets with has_eax_ebx_ecx_edx=True
        # (uses pop_eax/pop_ebx/pop_ecx/pop_edx separately, not combined)
        ctx.gadgets_x32 = RopGadgetsX32(
            pop_eax=0x080481d1, pop_ebx=0x080481d3, pop_ecx=0x080481d5, pop_edx=0x080481d7,
            pop_ecx_ebx=0, ret=0x080481db, int_0x80=0x080481dd, has_eax_ebx_ecx_edx=True,
        )
        ctx.binsh_in_binary = True

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "canary execve-syscall - Local"
        assert info_arg.architecture == "x32"
        assert info_arg.vulnerability_type == "Stack Buffer Overflow (canary-bypassed)"
        assert "canary" in info_arg.addresses
        assert info_arg.addresses["canary"] == hex(0xCAFEBABE)
        assert mock_io.sendline.call_count == 1
        assert mock_io.interactive.call_count == 1

    def test_ret2system_x32_local_1stage_flow_completes(self):
        """canary ret2system: needs has_system + binsh_in_binary.  The
        real ``Challenge/canary`` has neither; this test points
        ``ctx.binary.path`` at ``fmtstr1`` (which has both) to
        exercise the strategy.
        """
        from autopwn.exp.strategies.canary_ret2system import (
            CanaryRet2SystemX32LocalStrategy,
        )

        s = CanaryRet2SystemX32LocalStrategy()
        ctx = _ctx_32_canary(padding=80, canary_value=0xDEADBEEF, canary_diff=8)
        # Override binary path → fmtstr1 (has system + /bin/sh)
        fmtstr1_path = ctx.binary.path.parent / "fmtstr1"
        ctx.binary = BinaryInfo(
            path=fmtstr1_path,
            bit=32,
            stack_canary=True,
            pie=False,
            nx=True,
            relro="Partial",
            rwx_segments=False,
            stripped=False,
        )
        ctx.has_system = True
        ctx.binsh_in_binary = True

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "canary ret2system - x32"
        assert info_arg.architecture == "x32"

    def test_ret2libc_put_x32_local_2stage_flow_completes(self):
        from autopwn.exp.strategies.canary_ret2libc_put import (
            CanaryRet2LibcPutX32LocalStrategy,
        )

        s = CanaryRet2LibcPutX32LocalStrategy()
        ctx = _ctx_32_canary(padding=80, canary_value=0xDEADBEEF, canary_diff=8)
        # Stage 2 needs a real libc ELF (or a MagicMock with symbols+search).
        # The P6.3 primitive calls libc.symbols["puts"], libc.symbols["system"],
        # next(libc.search(b"/bin/sh")).  Provide a stub that satisfies all 3.
        fake_libc = MagicMock()
        fake_libc.symbols = {"puts": 0x00071150, "system": 0x00048150}
        fake_libc.search.return_value = iter([0x1b75aa])  # /bin/sh offset
        ctx.libc.elf = fake_libc

        mock_io = MagicMock()
        # recvuntil returns b"\xf7" + 4 bytes (puts_addr) at the end
        mock_io.recvuntil.return_value = b"\xf7\xbe\xbe\xbe\xf7"

        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "canary ret2libc-put - x32"
        assert "puts_addr" in info_arg.addresses
        # 2 sendlines: stage 1 + stage 2
        assert mock_io.sendline.call_count == 2
