"""Unit tests for ``autopwn.exp.strategies.ret2system_x32`` +
``autopwn.exp.strategies.ret2system_x64`` (P7.3).

Per ``rebuild.md`` §6.8 P7.3 + ``refactor.md`` §3.2.2, every
strategy needs:

  * :attr:`priority` matches 附录 A (``RET2SYSTEM = 150``).
  * :attr:`requires_*` filter correctly (arch + remote + requires).
  * :meth:`run` returns ``False`` for graceful-skip conditions
    (no system / no binsh / no gadgets / no remote address)
    and does NOT raise.
  * :meth:`run` is **not called** by the test directly when it
    would actually open a process (we use ``run.return_value``
    patches or skip these to keep the test process-clean).

For the real ``run()`` smoke we only assert the metadata
contract; the actual exploitation is exercised end-to-end
by §2.6 (5-binary serial verify) where rip/level3_x64 etc.
are real targets and the run does go to completion.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.strategy


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the registry before/after each test.

    Strategies are registered on import via @register.  Per
    :mod:`autopwn.exp.registry` design (P7.2), the
    ``@register`` decorator appends to a module-level list.
    Once a module is imported, Python caches it in
    ``sys.modules``; re-importing the same module does NOT
    re-execute the @register decorator.  We therefore use
    ``importlib.reload`` to force the strategy modules to
    re-execute and re-register.

    P7.11 will switch to explicit ``exp/strategies/__init__.py``
    imports that re-trigger registration; for now each test
    must work in isolation.
    """
    import importlib

    from autopwn.exp.registry import reset

    reset()
    import autopwn.exp.strategies.ret2system_x32  # noqa: F401
    import autopwn.exp.strategies.ret2system_x64  # noqa: F401
    importlib.reload(autopwn.exp.strategies.ret2system_x32)
    importlib.reload(autopwn.exp.strategies.ret2system_x64)
    yield
    reset()


def _ctx_32(mode: str = "local", *, has_system: bool = True, binsh: bool = True, **overrides):
    """Build a x32 ctx with has_system + binsh_in_binary set (matching case).

    Defaults: no canary, partial RELRO, bit=32, mode=local, has_system=True, binsh=True.
    Pass has_system=False / binsh=False to test the filter.
    """
    ctx = ctx_for("fmtstr1", bit=32, **overrides)
    ctx.mode = mode
    ctx.has_system = has_system
    ctx.binsh_in_binary = binsh
    return ctx


def _ctx_64(mode: str = "local", *, has_system: bool = True, binsh: bool = True, **overrides):
    """Build a x64 ctx with has_system + binsh_in_binary + gadgets set."""
    from autopwn.context import RopGadgetsX64

    ctx = ctx_for("rip", bit=64, **overrides)
    ctx.mode = mode
    ctx.has_system = has_system
    ctx.binsh_in_binary = binsh
    ctx.gadgets_x64 = RopGadgetsX64(
        pop_rdi=0x401234,
        pop_rsi=0x401238,
        ret=0x40123c,
    )
    return ctx


# ---------------------------------------------------------------------------
# Priority / metadata
# ---------------------------------------------------------------------------


class TestRet2SystemPriority:
    """All 4 ret2system strategies share ``priority = RET2SYSTEM = 150``."""

    def test_x32_local_priority_is_ret2system(self):
        from autopwn.exp.priorities import RET2SYSTEM
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        assert Ret2SystemX32LocalStrategy.priority == RET2SYSTEM == 150

    def test_x32_remote_priority_is_ret2system(self):
        from autopwn.exp.priorities import RET2SYSTEM
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32RemoteStrategy,
        )

        assert Ret2SystemX32RemoteStrategy.priority == RET2SYSTEM == 150

    def test_x64_local_priority_is_ret2system(self):
        from autopwn.exp.priorities import RET2SYSTEM
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        assert Ret2SystemX64LocalStrategy.priority == RET2SYSTEM == 150

    def test_x64_remote_priority_is_ret2system(self):
        from autopwn.exp.priorities import RET2SYSTEM
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64RemoteStrategy,
        )

        assert Ret2SystemX64RemoteStrategy.priority == RET2SYSTEM == 150


class TestRet2SystemMetadata:
    """The 4 strategies declare the right ``requires_*`` metadata."""

    def test_x32_local_arch_32_remote_false(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is False
        assert s.requires == ("has_system", "binsh_in_binary")

    def test_x32_remote_arch_32_remote_true(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32RemoteStrategy,
        )

        s = Ret2SystemX32RemoteStrategy()
        assert s.requires_arch == 32
        assert s.requires_remote is True
        assert s.requires == ("has_system", "binsh_in_binary")

    def test_x64_local_arch_64_remote_false(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is False
        assert s.requires == ("has_system", "binsh_in_binary")

    def test_x64_remote_arch_64_remote_true(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64RemoteStrategy,
        )

        s = Ret2SystemX64RemoteStrategy()
        assert s.requires_arch == 64
        assert s.requires_remote is True
        assert s.requires == ("has_system", "binsh_in_binary")

    def test_name_is_set_for_log_lines(self):
        """Every strategy has a non-empty ``name`` for the P7 registry log line."""
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
            Ret2SystemX32RemoteStrategy,
        )
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
            Ret2SystemX64RemoteStrategy,
        )

        for cls in [
            Ret2SystemX32LocalStrategy,
            Ret2SystemX32RemoteStrategy,
            Ret2SystemX64LocalStrategy,
            Ret2SystemX64RemoteStrategy,
        ]:
            assert cls.name, f"{cls.__name__} has empty name"
            assert "ret2system" in cls.name


# ---------------------------------------------------------------------------
# matches()
# ---------------------------------------------------------------------------


class TestRet2SystemMatches:
    """``matches`` filter behavior on each variant."""

    def test_x32_local_matches_x32_local_ctx(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        assert s.matches(_ctx_32()) is True

    def test_x32_local_rejects_x64_ctx(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        assert s.matches(_ctx_64()) is False

    def test_x32_local_rejects_remote_ctx(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert s.matches(ctx) is False

    def test_x32_local_rejects_no_has_system(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        ctx = _ctx_32(has_system=False)
        assert s.matches(ctx) is False

    def test_x32_local_rejects_no_binsh(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        ctx = _ctx_32(has_system=True, binsh=False)
        assert s.matches(ctx) is False

    def test_x32_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32RemoteStrategy,
        )

        s = Ret2SystemX32RemoteStrategy()
        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert s.matches(ctx) is True

    def test_x32_remote_rejects_local_ctx(self):
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32RemoteStrategy,
        )

        s = Ret2SystemX32RemoteStrategy()
        assert s.matches(_ctx_32()) is False  # mode=local

    def test_x64_local_matches_x64_local_ctx(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        assert s.matches(_ctx_64()) is True

    def test_x64_local_rejects_x32_ctx(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        assert s.matches(_ctx_32()) is False

    def test_x64_remote_matches_remote_ctx(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64RemoteStrategy,
        )

        s = Ret2SystemX64RemoteStrategy()
        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        assert s.matches(ctx) is True


# ---------------------------------------------------------------------------
# candidates() integration
# ---------------------------------------------------------------------------


class TestRet2SystemCandidates:
    """``candidates(ctx)`` returns the right ret2system variant for ctx."""

    def test_candidates_x32_local_ctx_returns_x32_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_32())
        names = [s.name for s in result]
        assert "ret2system-x32" in names
        assert "ret2system-x32-remote" not in names
        assert "ret2system-x64" not in names
        assert "ret2system-x64-remote" not in names

    def test_candidates_x64_local_ctx_returns_x64_local(self):
        from autopwn.exp import candidates

        result = candidates(_ctx_64())
        names = [s.name for s in result]
        assert "ret2system-x64" in names
        assert "ret2system-x32" not in names
        assert "ret2system-x32-remote" not in names
        assert "ret2system-x64-remote" not in names

    def test_candidates_x32_remote_ctx_returns_x32_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_32(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2system-x32-remote" in names
        assert "ret2system-x32" not in names
        assert "ret2system-x64" not in names

    def test_candidates_x64_remote_ctx_returns_x64_remote(self):
        from autopwn.exp import candidates

        ctx = _ctx_64(mode="remote")
        ctx.remote = ("127.0.0.1", 9999)
        result = candidates(ctx)
        names = [s.name for s in result]
        assert "ret2system-x64-remote" in names
        assert "ret2system-x64" not in names

    def test_candidates_no_has_system_returns_no_ret2system(self):
        """``has_system=False`` filters out all ret2system strategies."""
        from autopwn.exp import candidates

        ctx = _ctx_32(has_system=False)
        result = candidates(ctx)
        for s in result:
            assert s.name not in (
                "ret2system-x32",
                "ret2system-x32-remote",
                "ret2system-x64",
                "ret2system-x64-remote",
            )


# ---------------------------------------------------------------------------
# run() graceful-skip conditions (no actual IO)
# ---------------------------------------------------------------------------


class TestRet2SystemRunGracefulSkip:
    """``run`` returns ``False`` (not raise) for non-applicable ctx.

    These tests use a ctx that the strategy *matches* but
    where the primitive's ``build_payload`` will return
    ``b""`` (e.g. empty padding + missing real ELF).
    We assert the strategy returns ``False`` cleanly.

    Note: We do NOT actually call run() against real binaries
    here — that would spawn a process.  P7.12 (integration test)
    and the §2.6 5-binary serial verify cover the end-to-end
    flow on the real Challenge/ binaries.
    """

    def test_x32_local_run_returns_false_when_primitive_empty(self):
        """When the binary has no ``/bin/sh`` or no ``system`` symbol,
        the primitive returns ``b""`` and the strategy must
        return ``False`` (not raise, not return ``True``)."""
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        s = Ret2SystemX32LocalStrategy()
        # ctx points at a nonexistent path → primitive's ELF lookup
        # raises → _lookup returns (None, None) → payload = b""
        # → run() returns False.
        ctx = _ctx_32()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        result = s.run(ctx)
        assert result is False

    def test_x64_local_run_returns_false_when_primitive_empty(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        ctx = _ctx_64()
        ctx.binary.path = Path("/nonexistent/fake_binary")
        result = s.run(ctx)
        assert result is False

    def test_x32_remote_run_returns_false_when_remote_is_none(self):
        """Remote strategy with ``ctx.remote is None`` skips cleanly."""
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32RemoteStrategy,
        )

        s = Ret2SystemX32RemoteStrategy()
        ctx = _ctx_32()
        ctx.remote = None
        result = s.run(ctx)
        assert result is False

    def test_x64_remote_run_returns_false_when_remote_is_none(self):
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64RemoteStrategy,
        )

        s = Ret2SystemX64RemoteStrategy()
        ctx = _ctx_64()
        ctx.remote = None
        result = s.run(ctx)
        assert result is False

    def test_x64_local_run_returns_false_when_gadgets_missing(self):
        """``ctx.gadgets_x64 is None`` is a defensive skip in x64 strategy."""
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        ctx = _ctx_64()
        ctx.gadgets_x64 = None
        result = s.run(ctx)
        assert result is False


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------


class TestRet2SystemModuleStructure:
    """The 2 strategy modules are importable + export their classes."""

    def test_x32_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2system_x32
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
            Ret2SystemX32RemoteStrategy,
        )

        assert ret2system_x32.Ret2SystemX32LocalStrategy is Ret2SystemX32LocalStrategy
        assert ret2system_x32.Ret2SystemX32RemoteStrategy is Ret2SystemX32RemoteStrategy
        assert set(ret2system_x32.__all__) == {
            "Ret2SystemX32LocalStrategy",
            "Ret2SystemX32RemoteStrategy",
        }

    def test_x64_module_exports_two_classes(self):
        from autopwn.exp.strategies import ret2system_x64
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
            Ret2SystemX64RemoteStrategy,
        )

        assert ret2system_x64.Ret2SystemX64LocalStrategy is Ret2SystemX64LocalStrategy
        assert ret2system_x64.Ret2SystemX64RemoteStrategy is Ret2SystemX64RemoteStrategy
        assert set(ret2system_x64.__all__) == {
            "Ret2SystemX64LocalStrategy",
            "Ret2SystemX64RemoteStrategy",
        }

    def test_no_strategy_inherits_exploitresult(self):
        """Strategies are not primitives; they don't subclass ``ExploitResult``.

        Sanity check that the two layers (P6 primitive, P7 strategy)
        are kept separate.
        """
        from autopwn.primitives.base import ExploitResult
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )

        assert not issubclass(Ret2SystemX32LocalStrategy, ExploitResult)


# ---------------------------------------------------------------------------
# End-to-end (mocked IO) — run() reaches record_success
# ---------------------------------------------------------------------------


class TestRet2SystemRunInvokesRecordSuccess:
    """Mock ``pwn.process`` to confirm ``run`` calls ``record_success``.

    This is the "P7 strategy wires P3.4 report layer" contract:
    a successful run() must construct ExploitInfo and call
    record_success(info), which then dispatches to the docx
    generator.
    """

    def test_x32_local_run_calls_record_success_with_exploitinfo(self):
        """Mock pwn.process; verify run() reaches ``record_success``."""
        from autopwn.exp.strategies.ret2system_x32 import (
            Ret2SystemX32LocalStrategy,
        )
        from autopwn.report.model import ExploitInfo

        s = Ret2SystemX32LocalStrategy()
        ctx = _ctx_32()

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2system_x32.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        # record_success was called exactly once
        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        # It's an ExploitInfo with the right shape
        assert isinstance(info_arg, ExploitInfo)
        assert info_arg.exploit_type == "ret2system - x32"
        assert info_arg.architecture == "x32"
        assert info_arg.vulnerability_type == "Buffer Overflow"
        assert info_arg.target_binary == ctx.binary.path.name
        # addresses dict has both keys
        assert "system_addr" in info_arg.addresses
        assert "bin_sh_addr" in info_arg.addresses
        # io was actually used
        assert mock_io.sendline.call_count == 1
        assert mock_verify_shell.call_count == 1

    def test_x64_local_run_calls_record_success(self):
        """Same contract for the x64 strategy."""
        from autopwn.exp.strategies.ret2system_x64 import (
            Ret2SystemX64LocalStrategy,
        )

        s = Ret2SystemX64LocalStrategy()
        ctx = _ctx_64()

        mock_io = MagicMock()
        with patch("pwn.process", return_value=mock_io), \
             patch("autopwn.exp.strategies.ret2system_x64.verify_shell",
                  return_value=(True, "uid=0(root) gid=0(root)")) as mock_verify_shell, \
             patch("autopwn.report.record_success") as mock_record:
            s.run(ctx)

        assert mock_record.call_count == 1
        info_arg = mock_record.call_args[0][0]
        assert info_arg.exploit_type == "ret2system - x64"
        assert info_arg.architecture == "x64"
        # x64 report has 4 addresses (incl. gadgets)
        assert {"system_addr", "bin_sh_addr", "pop_rdi_addr", "ret_addr"} <= set(info_arg.addresses)
