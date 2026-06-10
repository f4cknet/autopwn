"""Unit tests for ``autopwn.orchestrator`` (P8.1 + P8.2 + P8.3).

Per ``rebuild.md`` §6.9 P8.1 / P8.2, this module tests:

  * :func:`run` — top-level dispatcher wires the three phases in
    order (recon → detect → strategy) and returns the strategy
    phase's exit code.
  * :func:`run_recon_phase` — populates ``ctx.binary`` /
    ``ctx.has_*`` / ``ctx.gadgets_*`` (mocked to avoid
    checksec/ropper subprocs; the underlying recon modules
    have their own unit tests at ``test_recon_*``).
  * :func:`run_detect_phase` — populates ``ctx.binsh_in_binary``
    and ``ctx.padding`` (mocked similarly).
  * :func:`run_strategy_phase` — iterates ``candidates(ctx)`` in
    priority order, returns 0 on first success, 1 on all-fail.
  * **No ``sys.exit``** in the orchestrator (``refactor.md``
    §11 R1 + §6.8 Reviewer checklist).
  * **CLI dispatch**: ``autopwn.cli.main`` is the entry point
    that wires argparse + ctx construction + orchestrator.run
    (P8.3 spec at §6.9).

Test approach: heavy use of ``unittest.mock`` to stub out the
``recon`` / ``detect`` modules + a clean ``reset()`` of the
strategy registry before each test that inspects candidate
order.  This keeps the tests fast and deterministic.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from unittest import mock

import pytest

from autopwn.context import BinaryInfo, ExploitContext, LibcInfo
from autopwn.exp import ExploitStrategy, candidates, register, reset
from autopwn.orchestrator import (
    run,
    run_detect_phase,
    run_recon_phase,
    run_strategy_phase,
)


pytestmark = pytest.mark.orchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ctx(tmp_path: Path, *, bit: int = 64, canary: bool = False) -> ExploitContext:
    """Build a minimal :class:`ExploitContext` for orchestrator tests.

    The ``binary.path`` points to a real file in ``tmp_path`` (so
    recon stubs that check existence don't choke); all other
    fields use the dataclass defaults.
    """
    fake_bin = tmp_path / "fake_binary"
    fake_bin.write_bytes(b"\x7fELF")  # minimal magic
    info = BinaryInfo(
        path=fake_bin,
        bit=bit,
        stack_canary=canary,
        pie=False,
        nx=True,
        relro="Partial",
        rwx_segments=False,
        stripped=False,
    )
    return ExploitContext(binary=info, mode="local")


def _stub_recon_ctx() -> dict:
    """Return a dict of fake return values for the recon phase."""
    return {
        "binary": None,        # set per-test
        "has_system": True,
        "has_puts": True,
        "has_write": True,
        "has_printf": True,
        "has_backdoor": False,
        "has_callsystem": False,
        "binsh": True,
        "padding": 64,
        "gadgets_x64": None,
        "gadgets_x32": None,
    }


class _StubStrategy(ExploitStrategy):
    """Throwaway strategy whose ``run`` returns a configured bool.

    The :class:`ExploitStrategy` ABC requires ``name`` /
    ``priority`` and a concrete :meth:`run`.  The
    ``returns`` attribute is the value ``run`` will return
    (tests configure it to test "first success wins" / "all
    fail" scenarios).  ``calls`` accumulates the contexts the
    strategy was invoked with.
    """

    instances: list = []  # class-level list — tests reset between cases

    def __init__(self, name: str, priority: int, returns: bool) -> None:
        self.name = name
        self.priority = priority
        self.returns = returns
        self.calls: list = []
        _StubStrategy.instances.append(self)

    def run(self, ctx: ExploitContext) -> bool:
        self.calls.append(ctx)
        return self.returns

    def __repr__(self) -> str:
        return f"_StubStrategy(name={self.name!r}, priority={self.priority}, returns={self.returns})"


@pytest.fixture
def clean_registry():
    """Snapshot + restore the strategy registry around each test."""
    from autopwn.exp import registry as _reg
    snapshot = list(_reg._REGISTRY)
    _reg._REGISTRY.clear()
    yield _reg
    _reg._REGISTRY.clear()
    _reg._REGISTRY.extend(snapshot)


# ---------------------------------------------------------------------------
# run_strategy_phase
# ---------------------------------------------------------------------------


class TestRunStrategyPhase:
    """Phase 3: iterate candidates(ctx) and try each in priority order."""

    def test_returns_zero_on_first_success(self, clean_registry, tmp_path):
        """The first strategy that returns True wins; phase exits 0."""
        ctx = _make_ctx(tmp_path)
        high = _StubStrategy("high", priority=100, returns=False)
        low = _StubStrategy("low", priority=50, returns=True)

        # candidates() pulls from the registry; we register 2 strats
        # and ensure high is tried first (higher priority).
        register(high)
        register(low)

        result = run_strategy_phase(ctx)
        assert result == 0
        # high was tried first (higher priority), then low succeeded
        assert high.calls == [ctx]
        assert low.calls == [ctx]

    def test_returns_one_when_all_candidates_fail(self, clean_registry, tmp_path):
        """If every candidate returns False, the phase exits 1."""
        ctx = _make_ctx(tmp_path)
        a = _StubStrategy("a", priority=100, returns=False)
        b = _StubStrategy("b", priority=50, returns=False)
        register(a)
        register(b)

        result = run_strategy_phase(ctx)
        assert result == 1
        assert a.calls == [ctx]
        assert b.calls == [ctx]

    def test_returns_one_when_no_candidates(self, clean_registry, tmp_path):
        """An empty candidate list yields 1 (orchestrator exits with failure)."""
        ctx = _make_ctx(tmp_path)
        # No strategies registered
        result = run_strategy_phase(ctx)
        assert result == 1

    def test_strategy_exception_is_logged_and_continues(self, clean_registry, tmp_path, capsys):
        """A strategy that raises must NOT abort the whole phase."""
        ctx = _make_ctx(tmp_path)

        class _Boom(ExploitStrategy):
            name = "boom"
            priority = 100

            def run(self, ctx):
                raise RuntimeError("simulated strategy crash")

        boom = _Boom()
        good = _StubStrategy("good", priority=50, returns=True)
        register(boom)
        register(good)

        result = run_strategy_phase(ctx)
        # boom crashed but phase continued to good, which returned True
        assert result == 0
        assert good.calls == [ctx]
        # Warning line was emitted
        out = capsys.readouterr()
        assert "boom failed: simulated strategy crash" in out.out + out.err

    def test_priority_ordering_is_highest_first(self, clean_registry, tmp_path):
        """Candidates must be tried highest-priority-first."""
        ctx = _make_ctx(tmp_path)
        order: list = []
        for prio in (10, 30, 20):
            s = _StubStrategy(f"p{prio}", priority=prio, returns=False)
            s.calls_observer = lambda c, s=s: order.append(s.name)  # type: ignore[attr-defined]
            register(s)
            original_run = s.run
            def make_run(orig, observer):
                def wrapped(c):
                    observer(c)
                    return orig(c)
                return wrapped
            s.run = make_run(original_run, s.calls_observer)  # type: ignore[method-assign]

        run_strategy_phase(ctx)
        # Highest-priority strategy was tried first
        assert order[0] == "p30"
        assert set(order) == {"p10", "p20", "p30"}


# ---------------------------------------------------------------------------
# run_recon_phase
# ---------------------------------------------------------------------------


class TestRunReconPhase:
    """Phase 1: populate ctx.binary / ctx.has_* / ctx.gadgets_*."""

    def test_calls_set_permission(self, tmp_path):
        """``set_permission`` is called with the binary path."""
        ctx = _make_ctx(tmp_path)

        with mock.patch("autopwn.orchestrator.recon.set_permission") as perm, \
             mock.patch("autopwn.orchestrator.recon.checksec") as cs, \
             mock.patch("autopwn.orchestrator.recon.libc") as libc_mod, \
             mock.patch("autopwn.orchestrator.recon.plt") as plt_mod, \
             mock.patch("autopwn.orchestrator.recon.rop") as rop_mod:
            perm.return_value = True
            cs.collect.return_value = ctx.binary
            cs.display = mock.MagicMock()
            libc_mod.detect.return_value = LibcInfo(path=Path("/libc.so.6"))
            plt_mod.scan.return_value = {}
            rop_mod.find_x64.return_value = None
            rop_mod.find_x32.return_value = None

            run_recon_phase(ctx)

        perm.assert_called_once_with(ctx.binary.path)

    def test_64bit_calls_find_x64(self, tmp_path):
        """bit=64 routes to ``rop.find_x64``; ``find_x32`` is not called."""
        ctx = _make_ctx(tmp_path, bit=64)

        with mock.patch("autopwn.orchestrator.recon.set_permission"), \
             mock.patch("autopwn.orchestrator.recon.checksec") as cs, \
             mock.patch("autopwn.orchestrator.recon.libc") as libc_mod, \
             mock.patch("autopwn.orchestrator.recon.plt") as plt_mod, \
             mock.patch("autopwn.orchestrator.recon.rop") as rop_mod:
            cs.collect.return_value = ctx.binary
            cs.display = mock.MagicMock()
            libc_mod.detect.return_value = LibcInfo()
            plt_mod.scan.return_value = {}
            rop_mod.find_x64.return_value = None

            run_recon_phase(ctx)

        rop_mod.find_x64.assert_called_once()
        rop_mod.find_x32.assert_not_called()

    def test_32bit_calls_find_x32(self, tmp_path):
        """bit=32 routes to ``rop.find_x32``; ``find_x64`` is not called."""
        ctx = _make_ctx(tmp_path, bit=32)

        with mock.patch("autopwn.orchestrator.recon.set_permission"), \
             mock.patch("autopwn.orchestrator.recon.checksec") as cs, \
             mock.patch("autopwn.orchestrator.recon.libc") as libc_mod, \
             mock.patch("autopwn.orchestrator.recon.plt") as plt_mod, \
             mock.patch("autopwn.orchestrator.recon.rop") as rop_mod:
            cs.collect.return_value = ctx.binary
            cs.display = mock.MagicMock()
            libc_mod.detect.return_value = LibcInfo()
            plt_mod.scan.return_value = {}
            rop_mod.find_x32.return_value = None

            run_recon_phase(ctx)

        rop_mod.find_x32.assert_called_once()
        rop_mod.find_x64.assert_not_called()

    def test_uses_custom_libc_path_when_set(self, tmp_path):
        """If ``ctx.libc.path`` is set, ``libc.detect`` is NOT called (override)."""
        ctx = _make_ctx(tmp_path)
        ctx.libc = LibcInfo(path=Path("/custom/libc.so.6"))

        with mock.patch("autopwn.orchestrator.recon.set_permission"), \
             mock.patch("autopwn.orchestrator.recon.checksec") as cs, \
             mock.patch("autopwn.orchestrator.recon.libc") as libc_mod, \
             mock.patch("autopwn.orchestrator.recon.plt") as plt_mod, \
             mock.patch("autopwn.orchestrator.recon.rop") as rop_mod:
            cs.collect.return_value = ctx.binary
            cs.display = mock.MagicMock()
            plt_mod.scan.return_value = {}
            rop_mod.find_x64.return_value = None

            run_recon_phase(ctx)

        # libc.detect must NOT be called when user provided -libc
        libc_mod.detect.assert_not_called()


# ---------------------------------------------------------------------------
# run_detect_phase
# ---------------------------------------------------------------------------


class TestRunDetectPhase:
    """Phase 2: populate ctx.binsh_in_binary and ctx.padding (and canary)."""

    def test_calls_check_binsh(self, tmp_path):
        """``binsh.check_binsh`` is called and ``ctx.binsh_in_binary`` is set."""
        ctx = _make_ctx(tmp_path, bit=64, canary=False)

        def _fake_check_binsh(c: ExploitContext, _p) -> bool:
            c.binsh_in_binary = True
            return True

        with mock.patch("autopwn.orchestrator.detect.detect_binsh") as binsh_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_overflow") as ov_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_canary") as canary_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_fmtstr") as fmtstr_mod:
            # Manual padding override (skip the dynamic test)
            ctx.padding = 64
            # The real ``detect_binsh.check_binsh`` mutates ctx.binsh_in_binary
            # in-place and returns the same bool.  Mirror that contract.
            binsh_mod.check_binsh.side_effect = _fake_check_binsh

            run_detect_phase(ctx)

        binsh_mod.check_binsh.assert_called_once_with(ctx, ctx.binary.path)
        assert ctx.binsh_in_binary is True

    def test_canary_branch_runs_canary_fuzz(self, tmp_path):
        """``stack_canary=True`` triggers ``leakage_canary_value`` + ``canary_fuzz``."""
        ctx = _make_ctx(tmp_path, bit=64, canary=True)
        ctx.padding = 64  # skip dynamic overflow test

        with mock.patch("autopwn.orchestrator.detect.detect_binsh") as binsh_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_overflow"), \
             mock.patch("autopwn.orchestrator.detect.detect_canary") as canary_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_fmtstr") as fmtstr_mod:
            binsh_mod.check_binsh.return_value = False
            probe = mock.MagicMock()
            probe.vulnerable = True
            fmtstr_mod.detect_format_string_vulnerability.return_value = probe
            canary_mod.leakage_canary_value.return_value = [(1, "0x1234")]
            canary_mod.canary_fuzz.return_value = None  # fuzz failure

            run_detect_phase(ctx)

        fmtstr_mod.detect_format_string_vulnerability.assert_called_once()
        canary_mod.leakage_canary_value.assert_called_once()
        canary_mod.canary_fuzz.assert_called_once()

    def test_no_canary_skips_canary_branch(self, tmp_path):
        """``stack_canary=False`` skips ``leakage_canary_value`` entirely."""
        ctx = _make_ctx(tmp_path, bit=64, canary=False)
        ctx.padding = 64

        with mock.patch("autopwn.orchestrator.detect.detect_binsh") as binsh_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_overflow"), \
             mock.patch("autopwn.orchestrator.detect.detect_canary") as canary_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_fmtstr") as fmtstr_mod:
            binsh_mod.check_binsh.return_value = False

            run_detect_phase(ctx)

        canary_mod.leakage_canary_value.assert_not_called()
        canary_mod.canary_fuzz.assert_not_called()
        fmtstr_mod.detect_format_string_vulnerability.assert_not_called()

    def test_manual_padding_skips_overflow_test(self, tmp_path):
        """``ctx.padding != 0`` (from ``-f``) skips the dynamic overflow test."""
        ctx = _make_ctx(tmp_path)
        ctx.padding = 120  # manual override

        with mock.patch("autopwn.orchestrator.detect.detect_binsh") as binsh_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_overflow") as ov_mod, \
             mock.patch("autopwn.orchestrator.detect.detect_canary"), \
             mock.patch("autopwn.orchestrator.detect.detect_fmtstr"):
            binsh_mod.check_binsh.return_value = True

            run_detect_phase(ctx)

        ov_mod.test_stack_overflow.assert_not_called()


# ---------------------------------------------------------------------------
# run (top-level)
# ---------------------------------------------------------------------------


class TestRunTopLevel:
    """``run(ctx)`` wires the three phases in order."""

    def test_phases_run_in_order(self, tmp_path):
        """recon → detect → strategy (verified via mock call order)."""
        ctx = _make_ctx(tmp_path)
        call_log: list = []

        with mock.patch("autopwn.orchestrator.run_recon_phase",
                        side_effect=lambda c: call_log.append("recon")) as recon, \
             mock.patch("autopwn.orchestrator.run_detect_phase",
                        side_effect=lambda c: call_log.append("detect")) as detect, \
             mock.patch("autopwn.orchestrator.run_strategy_phase",
                        side_effect=lambda c: (call_log.append("strategy"), 0)[1]) as strat:
            result = run(ctx)

        assert call_log == ["recon", "detect", "strategy"]
        assert result == 0
        recon.assert_called_once_with(ctx)
        detect.assert_called_once_with(ctx)
        strat.assert_called_once_with(ctx)

    def test_strategy_return_propagates(self, tmp_path):
        """``run()`` returns whatever ``run_strategy_phase`` returns."""
        ctx = _make_ctx(tmp_path)

        with mock.patch("autopwn.orchestrator.run_recon_phase"), \
             mock.patch("autopwn.orchestrator.run_detect_phase"), \
             mock.patch("autopwn.orchestrator.run_strategy_phase",
                        return_value=1):
            assert run(ctx) == 1

    def test_does_not_call_sys_exit(self, tmp_path):
        """``run()`` MUST NOT call :func:`sys.exit` (R1 mitigation).

        The orchestrator module does not import ``sys`` at all (it
        returns int exit codes; ``cli.py`` translates to SystemExit).
        Verify this by inspecting the module's source — if anyone
        adds an ``import sys`` later, the grep below will catch it.
        """
        ctx = _make_ctx(tmp_path)

        with mock.patch("autopwn.orchestrator.run_recon_phase"), \
             mock.patch("autopwn.orchestrator.run_detect_phase"), \
             mock.patch("autopwn.orchestrator.run_strategy_phase",
                        return_value=0):
            result = run(ctx)

        # Returns int, not raises SystemExit
        assert result == 0
        assert isinstance(result, int)

        # Module-level invariant: orchestrator does not import ``sys``
        import autopwn.orchestrator as orch_mod
        assert not hasattr(orch_mod, "sys"), (
            "orchestrator.py must not import sys; "
            "the orchestrator returns int, cli.py does SystemExit"
        )


# ---------------------------------------------------------------------------
# CLI dispatch (P8.3)
# ---------------------------------------------------------------------------


class TestCliDispatch:
    """``autopwn.cli.main`` wires argparse + ctx + orchestrator."""

    def test_main_returns_strategy_exit_code(self, tmp_path):
        """``main()`` returns the orchestrator's exit code (0/1)."""
        fake_bin = tmp_path / "bin"
        fake_bin.write_bytes(b"\x7fELF")
        args = argparse.Namespace(
            local=str(fake_bin),
            ip=None, port=None,
            libc=None, fill=0, verbose=False,
            no_report=False, report_dir=None,
        )

        with mock.patch("autopwn.cli._build_argparser") as parser, \
             mock.patch("autopwn.cli.orchestrator_run",
                        return_value=0) as orch:
            parser.return_value.parse_args.return_value = args
            from autopwn.cli import main
            assert main() == 0
            orch.assert_called_once()

    def test_main_exits_one_on_context_error(self, tmp_path, capsys):
        """``ContextError`` from ``from_args`` becomes exit 1 with red error."""
        from autopwn.cli import main
        from autopwn.context import ContextError

        args = argparse.Namespace(
            local="/nonexistent/binary",
            ip=None, port=None,
            libc=None, fill=0, verbose=False,
            no_report=False, report_dir=None,
        )

        with mock.patch("autopwn.cli._build_argparser") as parser, \
             mock.patch("autopwn.cli.orchestrator_run") as orch:
            parser.return_value.parse_args.return_value = args
            result = main()

        assert result == 1
        # orchestrator was NOT called (we exited early)
        orch.assert_not_called()
