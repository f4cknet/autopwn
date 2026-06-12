"""Unit tests for ``autopwn.exp.strategies.fmtstr`` (P7.8).

Per ``rebuild.md`` §6.8 P7.8 + ``refactor.md`` §3.2.2, every
strategy needs:

  * :attr:`priority` matches 附录 A (``FMTSTR = 50``).
  * :attr:`requires_*` filter correctly (arch + remote + custom
    ``padding == 0`` gate per v3.1 main() logic).
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no fmtstr_buf / no fmtstr_offset / primitive empty) and
    does NOT raise.
  * 1-stage flow: build payload → sendline → record_success →
    interactive (or leak loop for the bypass variant).

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
    import autopwn.exp.strategies.fmtstr  # noqa: F401
    importlib.reload(autopwn.exp.strategies.fmtstr)
    yield
    reset()


def _ctx_32(
    mode: str = "local",
    *,
    padding: int = 0,
    fmtstr_buf: int = 0x804a080,
    fmtstr_offset: int = 63,
    **overrides,
):
    """Build a x32 ctx with padding=0 (fmtstr match case) by default."""
    ctx = ctx_for("fmtstr1", bit=32, **overrides)
    ctx.mode = mode
    ctx.padding = padding
    ctx.fmtstr_buf = fmtstr_buf
    ctx.fmtstr_offset = fmtstr_offset
    return ctx


def _ctx_64(
    mode: str = "local",
    *,
    padding: int = 0,
    fmtstr_buf: int = 0x404040,
    fmtstr_offset: int = 11,
    **overrides,
):
    """Build a x64 ctx with padding=0 (fmtstr match case) by default."""
    ctx = ctx_for("fmtstr1", bit=32, **overrides)
    # Override bit to 64 (ctx_for uses "fmtstr1" which is x32)
    ctx.binary = ctx.binary.__class__(
        path=ctx.binary.path,
        bit=64,
        stack_canary=ctx.binary.stack_canary,
        pie=ctx.binary.pie,
        nx=ctx.binary.nx,
        relro=ctx.binary.relro,
        rwx_segments=ctx.binary.rwx_segments,
        stripped=ctx.binary.stripped,
    )
    ctx.mode = mode
    ctx.padding = padding
    ctx.fmtstr_buf = fmtstr_buf
    ctx.fmtstr_offset = fmtstr_offset
    return ctx


# ---------------------------------------------------------------------------
# Priority / metadata
# ---------------------------------------------------------------------------


class TestFmtstrPriority:
    """All 6 fmtstr strategies share ``priority = FMTSTR = 50``."""

    def test_x32_local_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        assert FmtstrX32LocalStrategy.priority == FMTSTR == 50

    def test_x64_local_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrX64LocalStrategy

        assert FmtstrX64LocalStrategy.priority == FMTSTR == 50

    def test_x32_remote_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        assert FmtstrX32RemoteStrategy.priority == FMTSTR == 50

    def test_x64_remote_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrX64RemoteStrategy

        assert FmtstrX64RemoteStrategy.priority == FMTSTR == 50

    def test_bypass_x32_local_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32LocalStrategy

        assert FmtstrPrintStringsX32LocalStrategy.priority == FMTSTR == 50

    def test_bypass_x32_remote_priority_is_fmtstr(self):
        from autopwn.exp.priorities import FMTSTR
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32RemoteStrategy

        assert FmtstrPrintStringsX32RemoteStrategy.priority == FMTSTR == 50

    def test_fmtstr_is_lowest_priority(self):
        """Per 附录 A: FMTSTR=50 is the 兜底 (fallback) — lowest of all 8."""
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
        assert FMTSTR == min(all_prios)


class TestFmtstrMetadata:
    """All 6 strategies declare the right ``requires_*`` metadata."""

    def test_x32_local_arch_32_remote_false(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        s = FmtstrX32LocalStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is False
        assert s.requires == ()

    def test_x64_local_arch_64_remote_false(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX64LocalStrategy

        s = FmtstrX64LocalStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is False
        assert s.requires == ()

    def test_x32_remote_arch_32_remote_true(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        s = FmtstrX32RemoteStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is True
        assert s.requires == ()

    def test_x64_remote_arch_64_remote_true(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX64RemoteStrategy

        s = FmtstrX64RemoteStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is True
        assert s.requires == ()

    def test_name_contains_fmtstr(self):
        from autopwn.exp.strategies.fmtstr import (
            FmtstrX32LocalStrategy,
            FmtstrX64LocalStrategy,
            FmtstrX32RemoteStrategy,
            FmtstrX64RemoteStrategy,
            FmtstrPrintStringsX32LocalStrategy,
            FmtstrPrintStringsX32RemoteStrategy,
        )

        for cls in [
            FmtstrX32LocalStrategy,
            FmtstrX64LocalStrategy,
            FmtstrX32RemoteStrategy,
            FmtstrX64RemoteStrategy,
            FmtstrPrintStringsX32LocalStrategy,
            FmtstrPrintStringsX32RemoteStrategy,
        ]:
            assert "fmtstr" in cls.name


# ---------------------------------------------------------------------------
# matches() — the custom padding==0 gate
# ---------------------------------------------------------------------------


class TestFmtstrMatches:
    """``matches`` filter behavior on each variant.

    All variants share the **custom** ``padding == 0`` gate per
    v3.1 main() logic (the fmtstr branch is only entered when
    no BOF is found).  Test this behavior explicitly.
    """

    def test_x32_local_matches_padding_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        assert FmtstrX32LocalStrategy().matches(_ctx_32(padding=0)) is True

    def test_x32_local_rejects_padding_nonzero(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf both None
        → no match.  v3.1's ``padding == 0`` gate is preserved for
        the no-fmtstr case (when the orchestrator never populated
        the primitive fields)."""
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        ctx = _ctx_32(padding=112, fmtstr_buf=None, fmtstr_offset=None)
        assert FmtstrX32LocalStrategy().matches(ctx) is False

    def test_x32_local_matches_padding_nonzero_when_fmtstr_fields_set(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf populated
        → match (fmtstr strategy is the correct exploit for
        canary+fmtstr binaries like Challenge/fmtstr1)."""
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        ctx = _ctx_32(padding=112, fmtstr_buf=0x804a080, fmtstr_offset=63)
        assert FmtstrX32LocalStrategy().matches(ctx) is True

    def test_x32_local_rejects_x64_ctx(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        assert FmtstrX32LocalStrategy().matches(_ctx_64()) is False

    def test_x32_local_rejects_remote_ctx(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert FmtstrX32LocalStrategy().matches(ctx) is False

    def test_x64_local_matches_padding_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX64LocalStrategy

        assert FmtstrX64LocalStrategy().matches(_ctx_64(padding=0)) is True

    def test_x64_local_rejects_padding_nonzero(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf both None
        → no match (per FmtstrX32LocalStrategy.matches gate)."""
        from autopwn.exp.strategies.fmtstr import FmtstrX64LocalStrategy

        ctx = _ctx_64(padding=112, fmtstr_buf=None, fmtstr_offset=None)
        assert FmtstrX64LocalStrategy().matches(ctx) is False

    def test_x32_remote_matches_remote_padding_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert FmtstrX32RemoteStrategy().matches(ctx) is True

    def test_x32_remote_rejects_padding_nonzero(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf both None
        → no match (per FmtstrX32LocalStrategy.matches gate)."""
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        ctx = _ctx_32(mode="remote", padding=112, fmtstr_buf=None, fmtstr_offset=None)
        ctx.remote = ("127.0.0.1", 9999)
        assert FmtstrX32RemoteStrategy().matches(ctx) is False

    def test_bypass_x32_local_matches_padding_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32LocalStrategy

        assert FmtstrPrintStringsX32LocalStrategy().matches(_ctx_32(padding=0)) is True

    def test_bypass_x32_local_rejects_padding_nonzero(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf both None
        → no match (per FmtstrX32LocalStrategy.matches gate)."""
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32LocalStrategy

        ctx = _ctx_32(padding=112, fmtstr_buf=None, fmtstr_offset=None)
        assert FmtstrPrintStringsX32LocalStrategy().matches(ctx) is False

    def test_bypass_x32_remote_matches_remote_padding_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32RemoteStrategy

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert FmtstrPrintStringsX32RemoteStrategy().matches(ctx) is True


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestFmtstrCandidates:
    """``candidates(ctx)`` returns the right fmtstr variant."""

    def test_candidates_x32_local_ctx(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_32())
        names = [s.name for s in result]
        assert "fmtstr-x32" in names
        # Main fmtstr path AND bypass
        assert "fmtstr-print-strings-x32" in names

    def test_candidates_x64_local_ctx(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_64())
        names = [s.name for s in result]
        assert "fmtstr-x64" in names
        assert "fmtstr-print-strings-x32" not in names  # bypass is x32 only

    def test_candidates_x32_remote_ctx(self):
        from autopwn.exp import candidates

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "fmtstr-x32-remote" in names
        assert "fmtstr-print-strings-x32-remote" in names
        assert "fmtstr-x32" not in names

    def test_candidates_x64_remote_ctx(self):
        from autopwn.exp import candidates

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "fmtstr-x64-remote" in names

    def test_candidates_padding_nonzero_with_fmtstr_fields_includes_fmtstr(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf populated
        → candidates() returns the fmtstr strategy (the canary+fmtstr
        case for binaries like Challenge/fmtstr1)."""
        from autopwn.exp import candidates

        ctx = _ctx_32(padding=112, fmtstr_buf=0x804a080, fmtstr_offset=63)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "fmtstr-x32" in names

    def test_candidates_padding_nonzero_without_fmtstr_fields_excludes_fmtstr(self):
        """v4.0.2c1: padding != 0 + fmtstr_offset/buf both None
        → candidates() filters out all fmtstr strategies (v3.1
        behavior preserved for the no-fmtstr case)."""
        from autopwn.exp import candidates

        ctx = _ctx_32(padding=112, fmtstr_buf=None, fmtstr_offset=None)
        result = candidates(ctx)
        for s in result:
            assert "fmtstr" not in s.name


# ---------------------------------------------------------------------------
# run() graceful-skip conditions
# ---------------------------------------------------------------------------


class TestFmtstrRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx."""

    def test_x32_local_run_returns_false_when_fmtstr_buf_missing(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        s = FmtstrX32LocalStrategy()
        ctx = _ctx_32()
        ctx.fmtstr_buf = None  # missing
        assert s.run(ctx) is False

    def test_x32_local_run_returns_false_when_fmtstr_offset_missing(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        s = FmtstrX32LocalStrategy()
        ctx = _ctx_32()
        ctx.fmtstr_offset = None  # missing
        assert s.run(ctx) is False

    def test_x32_local_run_returns_false_when_fmtstr_offset_zero(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        s = FmtstrX32LocalStrategy()
        ctx = _ctx_32()
        ctx.fmtstr_offset = 0  # invalid (offset must be > 0)
        assert s.run(ctx) is False

    def test_x32_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        s = FmtstrX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        assert s.run(ctx) is False

    def test_x32_remote_run_returns_false_when_fmtstr_buf_missing(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32RemoteStrategy

        s = FmtstrX32RemoteStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        ctx.fmtstr_buf = None
        assert s.run(ctx) is False

    def test_bypass_x32_local_run_returns_false_leak_loop_no_win(self):
        """The bypass always returns False (it's a leak-only branch, never "wins")."""
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32LocalStrategy

        s = FmtstrPrintStringsX32LocalStrategy()
        ctx = _ctx_32()

        # Mock pwn.process so the 100-sendline loop doesn't spawn real processes.
        with patch("pwn.process") as mock_process:
            mock_io = MagicMock()
            mock_process.return_value = mock_io
            mock_io.recv.return_value = b""  # no leak
            result = s.run(ctx)

        # Bypass doesn't win — orchestrator moves to next candidate
        assert result is False

    def test_bypass_x32_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.fmtstr import FmtstrPrintStringsX32RemoteStrategy

        s = FmtstrPrintStringsX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        assert s.run(ctx) is False


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestFmtstrModuleStructure:
    """The strategy module exports 6 classes (4 main + 2 bypass)."""

    def test_module_exports_six_classes(self):
        from autopwn.exp.strategies import fmtstr

        expected = {
            "FmtstrX32LocalStrategy",
            "FmtstrX64LocalStrategy",
            "FmtstrX32RemoteStrategy",
            "FmtstrX64RemoteStrategy",
            "FmtstrPrintStringsX32LocalStrategy",
            "FmtstrPrintStringsX32RemoteStrategy",
        }
        assert set(fmtstr.__all__) == expected

    def test_no_strategy_inherits_exploitresult(self):
        from autopwn.primitives.base import ExploitResult
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        assert not issubclass(FmtstrX32LocalStrategy, ExploitResult)


# ---------------------------------------------------------------------------
# End-to-end (mocked IO)
# ---------------------------------------------------------------------------


class TestFmtstrRunInvokesRecordSuccess:
    """Mock ``pwn.process`` to confirm the 1-stage flow reaches ``record_success``."""

    def test_x32_local_1stage_flow_completes(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy
        from autopwn.report.model import ExploitInfo

        s = FmtstrX32LocalStrategy()
        ctx = _ctx_32()

        # Mock the primitive to return a known payload (since
        # the real fmtstr1's primitive behavior is system-dependent).
        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = (
            b"\x80\xa0\x04\x08"  # buf_addr p32
            + b"%" + b"63" + b"$n"  # %63$n
        )

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.fmtstr.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.fmtstr.FmtstrX32", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "Format String - Local"
        assert info_arg.architecture == "x32"
        assert info_arg.vulnerability_type == "Format String Vulnerability"
        # fmtstr has no BOF padding — padding == 0
        assert info_arg.padding == 0
        # buf_addr + offset in addresses
        assert "buf_addr" in info_arg.addresses
        assert "offset" in info_arg.addresses
        assert mock_io.sendline.call_count == 1
        assert mock_verify_shell.call_count == 1

    def test_x64_local_1stage_flow_completes(self):
        from autopwn.exp.strategies.fmtstr import FmtstrX64LocalStrategy

        s = FmtstrX64LocalStrategy()
        ctx = _ctx_64()

        mock_primitive = MagicMock()
        mock_primitive.build_payload.return_value = (
            b"\x40\x40\x40\x00\x00\x00\x00\x00"  # buf_addr p64
            + b"%" + b"11" + b"$n"
        )

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.fmtstr.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record, \
             patch("autopwn.exp.strategies.fmtstr.FmtstrX64", return_value=mock_primitive):
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "Format String - Local (x64)"
        assert info_arg.architecture == "x64"
        assert mock_io.sendline.call_count == 1

    def test_x32_local_no_record_success_when_primitive_empty(self):
        """Primitive empty (no fmtstr_buf/offset) → strategy returns False, no record_success."""
        from autopwn.exp.strategies.fmtstr import FmtstrX32LocalStrategy

        s = FmtstrX32LocalStrategy()
        ctx = _ctx_32(fmtstr_buf=None, fmtstr_offset=None)

        with patch("pwn.process") as mock_process, \
             patch("autopwn.report.record_success") as mock_record:
            result = s.run(ctx)

        assert result is False
        assert mock_record.call_count == 0
