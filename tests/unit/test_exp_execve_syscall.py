"""Unit tests for ``autopwn.exp.strategies.execve_syscall``
(local + remote, x32 only) (P7.7).

Per ``rebuild.md`` §6.8 P7.7 + ``refactor.md`` §3.2.2, every
strategy needs:

  * :attr:`priority` matches 附录 A (``EXECVE_SYSCALL = 80``).
  * :attr:`requires_*` filter correctly (arch = 32 only; remote
    flag splits local vs remote; ``requires = ()``).
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no gadgets / primitive empty / remote is None for remote
    variant) and does NOT raise.
  * 1-stage flow (no leak): build payload → sendline → record.

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
    """Reset registry + reload strategy modules (per P7.3 lesson)."""
    import importlib

    from autopwn.exp.registry import reset

    reset()
    import autopwn.exp.strategies.execve_syscall  # noqa: F401
    importlib.reload(autopwn.exp.strategies.execve_syscall)
    yield
    reset()


def _gadgets_x32(*, pop_ecx_ebx: int = 0, pop_ecx: int = 0x401234, **overrides) -> "RopGadgetsX32":
    """Build a x32 RopGadgetsX32 with default has_eax_ebx_ecx_edx=True."""
    from autopwn.context import RopGadgetsX32

    fields = dict(
        pop_eax=0x401200,
        pop_ebx=0x401204,
        pop_ecx=pop_ecx,
        pop_edx=0x40120c,
        pop_ecx_ebx=pop_ecx_ebx,
        ret=0x401210,
        int_0x80=0x401280,
        has_eax_ebx_ecx_edx=True,
    )
    fields.update(overrides)
    return RopGadgetsX32(**fields)


def _ctx_32(mode: str = "local", *, gadgets: "RopGadgetsX32" = None, **overrides):
    """Build a x32 ctx with gadgets set (matching case by default).

    Default gadgets use the **separate** variant (pop_ecx != 0);
    the **combined** variant (pop_ecx=0, pop_ecx_ebx!=0) is
    selectable via ``gadgets=_gadgets_x32(pop_ecx=0, pop_ecx_ebx=0x401208)``.
    """
    ctx = ctx_for("fmtstr1", bit=32, **overrides)
    ctx.mode = mode
    ctx.gadgets_x32 = gadgets if gadgets is not None else _gadgets_x32()
    return ctx


# ---------------------------------------------------------------------------
# Priority / metadata
# ---------------------------------------------------------------------------


class TestExecveSyscallPriority:
    """Both execve_syscall strategies share ``priority = EXECVE_SYSCALL = 80``."""

    def test_local_priority_is_execve_syscall(self):
        from autopwn.exp.priorities import EXECVE_SYSCALL
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        assert ExecveSyscallX32LocalStrategy.priority == EXECVE_SYSCALL == 80

    def test_remote_priority_is_execve_syscall(self):
        from autopwn.exp.priorities import EXECVE_SYSCALL
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        assert ExecveSyscallX32RemoteStrategy.priority == EXECVE_SYSCALL == 80

    def test_execve_lt_rwx_lt_ret2libc_write(self):
        """Per 附录 A: ret2libc_write=110 > rwx=90 > execve=80 > fmtstr=50."""
        from autopwn.exp.priorities import (
            EXECVE_SYSCALL,
            FMTSTR,
            RET2LIBC_WRITE,
            RWX_SHELLCODE,
        )

        assert RET2LIBC_WRITE > RWX_SHELLCODE > EXECVE_SYSCALL > FMTSTR


class TestExecveSyscallMetadata:
    """Both strategies declare the right ``requires_*`` metadata."""

    def test_local_arch_32_remote_false(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        s = ExecveSyscallX32LocalStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is False
        assert s.requires == ()

    def test_remote_arch_32_remote_true(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        s = ExecveSyscallX32RemoteStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is True
        assert s.requires == ()

    def test_no_x64_variant(self):
        """execve_syscall is x32 only (per 附录 A 备注 '仅 x32' + 64-bit uses syscall instruction)."""
        from autopwn.exp import strategies
        from autopwn.exp.strategies import execve_syscall

        exported = execve_syscall.__all__
        for name in exported:
            cls = getattr(execve_syscall, name)
            # All exported classes must be x32-only
            assert cls.requires_arch == 32, f"{name} has requires_arch={cls.requires_arch}, expected 32"
            # No name should contain "x64"
            assert "x64" not in name, f"{name} contains 'x64' but execve_syscall is x32 only"

    def test_name_is_set_for_log_lines(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
            ExecveSyscallX32RemoteStrategy,
        )

        for cls in [ExecveSyscallX32LocalStrategy, ExecveSyscallX32RemoteStrategy]:
            assert cls.name, f"{cls.__name__} has empty name"
            assert "execve" in cls.name
            assert "syscall" in cls.name


# ---------------------------------------------------------------------------
# matches()
# ---------------------------------------------------------------------------


class TestExecveSyscallMatches:
    """``matches`` filter behavior on each variant."""

    def test_local_matches_x32_local_ctx(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        assert ExecveSyscallX32LocalStrategy().matches(_ctx_32()) is True

    def test_local_rejects_x64_ctx(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        # Try matching against an x64 ctx (no gadgets set, but
        # arch mismatch should reject before gadgets check).
        from autopwn.context import RopGadgetsX64

        ctx = ctx_for("rip", bit=64)
        ctx.gadgets_x64 = RopGadgetsX64(pop_rdi=0x401234, pop_rsi=0x401238, ret=0x40123c)
        assert ExecveSyscallX32LocalStrategy().matches(ctx) is False

    def test_local_rejects_remote_ctx(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert ExecveSyscallX32LocalStrategy().matches(ctx) is False

    def test_local_matches_with_empty_requires(self):
        """``requires = ()`` → matches() only checks arch + remote."""
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        # A x32 local ctx with NO gadgets set still matches
        # (the requires tuple is empty; the primitive will
        # return b"" at run() time if gadgets are missing).
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.gadgets_x32 = None
        assert ExecveSyscallX32LocalStrategy().matches(ctx) is True

    def test_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert ExecveSyscallX32RemoteStrategy().matches(ctx) is True

    def test_remote_rejects_local_ctx(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        assert ExecveSyscallX32RemoteStrategy().matches(_ctx_32()) is False


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestExecveSyscallCandidates:
    """``candidates(ctx)`` returns the right execve_syscall variant."""

    def test_candidates_x32_local_returns_x32_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_32())
        names = [s.name for s in result]
        assert "execve-syscall-x32" in names
        assert "execve-syscall-x32-remote" not in names

    def test_candidates_x32_remote_returns_x32_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "execve-syscall-x32-remote" in names
        assert "execve-syscall-x32" not in names

    def test_candidates_x64_never_returns_execve(self):
        """x64 ctx → no execve_syscall (x32 only)."""
        from autopwn.context import RopGadgetsX64
        from autopwn.exp import candidates

        ctx = ctx_for("rip", bit=64)
        ctx.gadgets_x64 = RopGadgetsX64(pop_rdi=0x401234, pop_rsi=0x401238, ret=0x40123c)
        result = candidates(ctx)
        for s in result:
            assert "execve-syscall" not in s.name


# ---------------------------------------------------------------------------
# run() graceful-skip conditions
# ---------------------------------------------------------------------------


class TestExecveSyscallRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx."""

    def test_local_run_returns_false_when_gadgets_missing(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        s = ExecveSyscallX32LocalStrategy()
        ctx = _ctx_32()
        ctx.gadgets_x32 = None
        assert s.run(ctx) is False

    def test_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        s = ExecveSyscallX32LocalStrategy()
        ctx = _ctx_32()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        assert s.run(ctx) is False

    def test_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        s = ExecveSyscallX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        assert s.run(ctx) is False

    def test_remote_run_returns_false_when_gadgets_missing(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        s = ExecveSyscallX32RemoteStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        ctx.gadgets_x32 = None
        assert s.run(ctx) is False

    def test_remote_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        s = ExecveSyscallX32RemoteStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        ctx.binary.path = Path("/nonexistent/fake_binary")
        assert s.run(ctx) is False


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestExecveSyscallModuleStructure:
    """The strategy module is importable + exports its classes."""

    def test_module_exports_two_classes(self):
        from autopwn.exp.strategies import execve_syscall
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
            ExecveSyscallX32RemoteStrategy,
        )

        assert execve_syscall.ExecveSyscallX32LocalStrategy is ExecveSyscallX32LocalStrategy
        assert execve_syscall.ExecveSyscallX32RemoteStrategy is ExecveSyscallX32RemoteStrategy
        assert set(execve_syscall.__all__) == {
            "ExecveSyscallX32LocalStrategy",
            "ExecveSyscallX32RemoteStrategy",
        }

    def test_no_strategy_inherits_exploitresult(self):
        from autopwn.primitives.base import ExploitResult
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )

        assert not issubclass(ExecveSyscallX32LocalStrategy, ExploitResult)


# ---------------------------------------------------------------------------
# End-to-end (mocked IO) — 1-stage flow + combined/separate variant coverage
# ---------------------------------------------------------------------------


class TestExecveSyscallRunInvokesRecordSuccess:
    """Mock ``pwn.process`` to confirm the 1-stage flow reaches ``record_success``.

    Tests cover both **separate** and **combined** gadget variants
    to verify the ExploitInfo addresses dict has the right shape
    (per v3.1's ``handle_exploitation_success`` call).
    """

    def test_local_separate_variant_flow(self):
        """Default (separate) variant — pop_ecx != 0."""
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = ExecveSyscallX32LocalStrategy()
        ctx = _ctx_32()  # default: pop_ecx != 0 (separate)

        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = (
            b"A" * 64
            + b"\x10\x20\x30\x40"  # pop_eax
            + b"\x00\x00\x00\x0b"  # SYSCALL_EXECVE
            + b"\x50\x60\x70\x80"  # pop_ebx
            + b"\x90\xa0\xb0\xc0"  # binsh
            + b"\xd0\xe0\xf0\x00"  # pop_ecx + 0
            + b"\x10\x11\x12\x13"  # pop_edx
            + b"\x00\x00\x00\x00"  # 0
            + b"\x20\x21\x22\x23"  # int_0_80
        )

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.execve_syscall.ExecveSyscallX32", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "execve syscall - x32 (separate)"
        assert info_arg.architecture == "x32"
        # Separate variant: 4 pop gadgets + binsh in addresses
        assert {"pop_eax_addr", "pop_ebx_addr", "pop_ecx_addr", "pop_edx_addr", "int_0_80"} <= set(info_arg.addresses)
        assert "pop_ecx_ebx_addr" not in info_arg.addresses
        assert mock_io.sendline.call_count == 1
        assert mock_io.interactive.call_count == 1

    def test_local_combined_variant_flow(self):
        """Combined variant — pop_ecx == 0, pop_ecx_ebx != 0."""
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32LocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = ExecveSyscallX32LocalStrategy()
        ctx = _ctx_32(gadgets=_gadgets_x32(pop_ecx=0, pop_ecx_ebx=0x401208))

        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = (
            b"A" * 64
            + b"\x10\x20\x30\x40"  # pop_eax
            + b"\x00\x00\x00\x0b"  # SYSCALL_EXECVE
            + b"\x50\x60\x70\x80"  # pop_ecx_ebx
            + b"\x00\x00\x00\x00"  # 0 (ecx)
            + b"\x90\xa0\xb0\xc0"  # binsh (ebx)
            + b"\xd0\xe0\xf0\x00"  # pop_edx + 0
            + b"\x20\x21\x22\x23"  # int_0_80
        )

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.execve_syscall.ExecveSyscallX32", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "execve syscall - x32 (ecx_ebx)"
        # Combined variant: 3 pop gadgets + binsh in addresses
        assert {"pop_eax_addr", "pop_ecx_ebx_addr", "pop_edx_addr", "int_0_80"} <= set(info_arg.addresses)
        assert "pop_ebx_addr" not in info_arg.addresses
        assert "pop_ecx_addr" not in info_arg.addresses

    def test_remote_separate_variant_flow(self):
        """Same 1-stage contract for remote variant."""
        from autopwn.exp.strategies.execve_syscall import (
            ExecveSyscallX32RemoteStrategy,
        )

        s = ExecveSyscallX32RemoteStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)

        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = b"A" * 64 + b"\x10" * 36

        mock_io = MagicMock()
        with patch("pwn.remote", return_value=mock_io), \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.execve_syscall.ExecveSyscallX32", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "execve syscall - x32 (separate)"
        assert mock_io.sendline.call_count == 1
        assert mock_io.interactive.call_count == 1
