"""Unit tests for ``autopwn.exp.registry`` + ``autopwn.exp.priorities`` (P7.2).

Per ``rebuild.md`` §6.8 P7.2 + §11 附录 A (Owner-signed 2026-06-08,
P7.2a / B-003) + ``refactor.md`` §3.2.2, this module tests:

  * :func:`priorities` constants — match 附录 A row-for-row.
  * :func:`register` — both class-decorator and function-call forms.
  * :func:`candidates` — ``matches`` filter + priority sort.
  * :func:`all_strategies` — full registry snapshot.
  * :func:`reset` — test-only helper.
  * End-to-end: register 3 stub strategies, ``candidates`` returns
    them in priority order filtered by ctx.

P7.3+ will add real strategy classes; these tests use throwaway
classes defined in the test body to verify the registry protocol
itself.
"""
from __future__ import annotations

from typing import List

import pytest

from autopwn.context import BinaryInfo, ExploitContext, CanaryInfo, LibcInfo
from autopwn.exp import (
    CANARY,
    EXECVE_SYSCALL,
    FMTSTR,
    PIE_BACKDOOR,
    RET2LIBC_PUT,
    RET2LIBC_WRITE,
    RET2SYSTEM,
    RWX_SHELLCODE,
    STRATEGY_PRIORITY_HUMAN,
    ExploitStrategy,
    all_strategies,
    candidates,
    register,
    reset,
)
from autopwn.exp import priorities as priorities_mod
from autopwn.exp.registry import _REGISTRY


pytestmark = pytest.mark.strategy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the registry before AND after each test.

    The :func:`reset` helper exists specifically for this.  We
    use it as ``autouse`` so any test can safely call ``register``
    without polluting other tests' registry state.
    """
    reset()
    yield
    reset()


def _ctx(bit: int = 32, *, mode: str = "local", canary: bool = False,
         has_system: bool = True, binsh_in_binary: bool = True,
         pie: bool = False, rwx_segments: bool = False) -> ExploitContext:
    """Build a fully-specified :class:`ExploitContext` for testing.

    Defaults produce a "best case" ctx: x32, local, no canary,
    has_system+binsh — this matches most strategies' ideal target.
    Tests override individual fields to assert on :func:`candidates`.
    """
    ctx = ExploitContext(
        binary=BinaryInfo(
            path=__import__("pathlib").Path("/tmp/x"),
            bit=bit,
            stack_canary=canary,
            pie=pie,
            nx=True,
            relro="Partial",
            rwx_segments=rwx_segments,
            stripped=False,
        ),
        mode=mode,
    )
    if canary:
        ctx.canary = CanaryInfo(value=0x1, diff=8)
    ctx.has_system = has_system
    ctx.binsh_in_binary = binsh_in_binary
    return ctx


class _StubStrat(ExploitStrategy):
    """Concrete strategy with a single knob: ``priority`` (default 100).

    Subclass this or set class attributes directly to build
    tailored fixtures.
    """
    name = "stub"
    priority = 100

    def run(self, ctx) -> bool:  # noqa: ARG002
        return True


# ---------------------------------------------------------------------------
# Priorities constants
# ---------------------------------------------------------------------------


class TestPrioritiesMatchAppendixA:
    """Hardcoded priority values must match ``rebuild.md`` §11 附录 A."""

    def test_canary_is_200(self):
        assert CANARY == 200

    def test_pie_backdoor_is_180(self):
        assert PIE_BACKDOOR == 180

    def test_ret2system_is_150(self):
        assert RET2SYSTEM == 150

    def test_ret2libc_put_is_120(self):
        assert RET2LIBC_PUT == 120

    def test_ret2libc_write_is_110(self):
        assert RET2LIBC_WRITE == 110

    def test_rwx_shellcode_is_90(self):
        assert RWX_SHELLCODE == 90

    def test_execve_syscall_is_80(self):
        assert EXECVE_SYSCALL == 80

    def test_fmtstr_is_50(self):
        assert FMTSTR == 50

    def test_priority_order_matches_appendix_a(self):
        """The 8 priority values are monotonically decreasing top-to-bottom."""
        order = [
            CANARY, PIE_BACKDOOR, RET2SYSTEM, RET2LIBC_PUT,
            RET2LIBC_WRITE, RWX_SHELLCODE, EXECVE_SYSCALL, FMTSTR,
        ]
        # Strictly decreasing (each is strictly less than the previous)
        for prev, curr in zip(order, order[1:]):
            assert prev > curr, f"{prev} should be > {curr}"

    def test_human_labels_cover_all_priorities(self):
        """``STRATEGY_PRIORITY_HUMAN`` has a label for every priority constant."""
        for prio in [
            CANARY, PIE_BACKDOOR, RET2SYSTEM, RET2LIBC_PUT,
            RET2LIBC_WRITE, RWX_SHELLCODE, EXECVE_SYSCALL, FMTSTR,
        ]:
            assert prio in STRATEGY_PRIORITY_HUMAN, f"missing human label for priority {prio}"
            assert isinstance(STRATEGY_PRIORITY_HUMAN[prio], str)
            assert len(STRATEGY_PRIORITY_HUMAN[prio]) > 0

    def test_priorities_module_exports_everything(self):
        """``autopwn.exp.priorities`` exports all 9 public names."""
        expected = {
            "CANARY", "PIE_BACKDOOR", "RET2SYSTEM", "RET2LIBC_PUT",
            "RET2LIBC_WRITE", "RWX_SHELLCODE", "EXECVE_SYSCALL",
            "FMTSTR", "STRATEGY_PRIORITY_HUMAN",
        }
        assert set(priorities_mod.__all__) == expected


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------


class TestRegisterAsDecorator:
    """``@register`` on a class appends an instance and preserves the class binding."""

    def test_decorator_appends_instance(self):
        @register
        class S(ExploitStrategy):
            name = "s1"
            priority = 100
            def run(self, ctx): return True

        assert len(all_strategies()) == 1
        registered = all_strategies()[0]
        assert isinstance(registered, S)

    def test_decorator_preserves_class_binding(self):
        """The class name `S` should still point to the class, not the instance."""
        @register
        class S(ExploitStrategy):
            name = "s2"
            priority = 100
            def run(self, ctx): return True

        # `S` is still the class, not the registered instance
        assert isinstance(S, type)
        assert issubclass(S, ExploitStrategy)

    def test_decorator_multiple_classes(self):
        @register
        class A(ExploitStrategy):
            name = "a"; priority = 10
            def run(self, ctx): return True
        @register
        class B(ExploitStrategy):
            name = "b"; priority = 20
            def run(self, ctx): return True

        assert len(all_strategies()) == 2
        # Both registered as instances
        assert isinstance(all_strategies()[0], A)
        assert isinstance(all_strategies()[1], B)


class TestRegisterAsFunction:
    """``register(instance)`` appends the instance unchanged."""

    def test_function_call_appends_instance(self):
        s = _StubStrat()
        register(s)
        assert all_strategies() == [s]

    def test_function_call_returns_instance(self):
        """``register`` returns what was passed in (identity for instance form)."""
        s = _StubStrat()
        result = register(s)
        assert result is s

    def test_function_call_accepts_arbitrary_instances(self):
        """A class isn't required — any :class:`ExploitStrategy` instance works."""
        s1 = _StubStrat(); s1.priority = 1
        s2 = _StubStrat(); s2.priority = 2
        register(s1)
        register(s2)
        assert all_strategies() == [s1, s2]


# ---------------------------------------------------------------------------
# candidates()
# ---------------------------------------------------------------------------


class TestCandidatesEmpty:
    """Empty registry ⇒ empty candidates list."""

    def test_empty_registry_returns_empty_list(self):
        assert candidates(_ctx()) == []

    def test_empty_registry_no_error(self):
        """``candidates`` must not raise on empty registry."""
        # The orchestrator path needs this — no candidate = "no match"
        result = candidates(_ctx())
        assert isinstance(result, list)
        assert len(result) == 0


class TestCandidatesFilter:
    """``candidates`` filters by :meth:`ExploitStrategy.matches`."""

    def test_filter_excludes_non_matching_arch(self):
        """A x32-only strategy is filtered out for a x64 ctx."""
        s = _StubStrat()
        s.requires_arch = 32
        register(s)
        # x64 ctx → strategy doesn't match
        assert candidates(_ctx(bit=64)) == []
        # x32 ctx → strategy matches
        assert len(candidates(_ctx(bit=32))) == 1

    def test_filter_excludes_non_matching_remote(self):
        """A local-only strategy is filtered out for a remote ctx."""
        s = _StubStrat()
        s.requires_remote = False
        register(s)
        assert candidates(_ctx(mode="local")) != []
        assert candidates(_ctx(mode="remote")) == []

    def test_filter_excludes_non_matching_canary(self):
        s = _StubStrat()
        s.requires_canary = True
        register(s)
        # no canary → no match
        assert candidates(_ctx(canary=False)) == []
        # canary present → match
        assert len(candidates(_ctx(canary=True))) == 1

    def test_filter_excludes_missing_requires(self):
        s = _StubStrat()
        s.requires = ("has_system", "binsh_in_binary")
        register(s)
        # missing has_system → no match
        assert candidates(_ctx(has_system=False)) == []
        # missing binsh_in_binary → no match
        assert candidates(_ctx(binsh_in_binary=False)) == []
        # both present → match
        assert len(candidates(_ctx(has_system=True, binsh_in_binary=True))) == 1

    def test_filter_combined(self):
        """Multiple filters compose: all must pass for a match."""
        s = _StubStrat()
        s.requires_arch = 32
        s.requires_canary = True
        s.requires = ("has_system",)
        register(s)
        # wrong arch
        assert candidates(_ctx(bit=64, canary=True, has_system=True)) == []
        # wrong canary
        assert candidates(_ctx(bit=32, canary=False, has_system=True)) == []
        # all pass
        assert len(candidates(_ctx(bit=32, canary=True, has_system=True))) == 1


class TestCandidatesSort:
    """``candidates`` returns matches sorted by priority descending."""

    def test_single_strategy(self):
        register(_StubStrat())
        result = candidates(_ctx())
        assert len(result) == 1

    def test_priority_sort_highest_first(self):
        """When multiple strategies match, highest priority is first."""
        # Register in arbitrary order; sort must reorder
        s_low = _StubStrat(); s_low.priority = 50; s_low.name = "low"; register(s_low)
        s_high = _StubStrat(); s_high.priority = 200; s_high.name = "high"; register(s_high)
        s_mid = _StubStrat(); s_mid.priority = 100; s_mid.name = "mid"; register(s_mid)

        result = candidates(_ctx())
        assert [s.name for s in result] == ["high", "mid", "low"]
        assert [s.priority for s in result] == [200, 100, 50]

    def test_priority_sort_with_filters(self):
        """Non-matching strategies are excluded before sort."""
        s_match = _StubStrat(); s_match.priority = 50; s_match.name = "match"
        s_nomatch = _StubStrat(); s_nomatch.priority = 999; s_nomatch.name = "skip"
        s_nomatch.requires_arch = 64  # never matches x32 ctx
        register(s_match)
        register(s_nomatch)

        result = candidates(_ctx(bit=32))
        assert [s.name for s in result] == ["match"]

    def test_priority_stable_sort_on_ties(self):
        """Ties are broken by registration order (Python stable sort)."""
        a = _StubStrat(); a.priority = 100; a.name = "a"; register(a)
        b = _StubStrat(); b.priority = 100; b.name = "b"; register(b)
        c = _StubStrat(); c.priority = 100; c.name = "c"; register(c)

        result = candidates(_ctx())
        # Stable sort: ties preserve insertion order
        assert [s.name for s in result] == ["a", "b", "c"]


class TestCandidatesIntegration:
    """End-to-end: register + candidates + matches with realistic priority values."""

    def test_realistic_priority_chain(self):
        """Register 4 strategies with the 附录 A priorities, verify order."""
        @register
        class Can(ExploitStrategy):
            name = "canary"; priority = CANARY
            requires_canary = True
            def run(self, ctx): return True
        @register
        class RS(ExploitStrategy):
            name = "ret2system"; priority = RET2SYSTEM
            requires = ("has_system", "binsh_in_binary")
            def run(self, ctx): return True
        @register
        class FS(ExploitStrategy):
            name = "fmtstr"; priority = FMTSTR
            requires = ("has_system", "binsh_in_binary")
            def run(self, ctx): return True
        @register
        class Pie(ExploitStrategy):
            name = "pie_backdoor"; priority = PIE_BACKDOOR
            requires = ("has_backdoor",)
            requires_arch = 32
            def run(self, ctx): return True

        # ctx with canary + has_system + binsh → canary, ret2system, fmtstr match
        # (canary=200 first; pie_backdoor filtered: arch=32 ✓ but no has_backdoor)
        ctx_canary = _ctx(canary=True, has_system=True, binsh_in_binary=True)
        result = candidates(ctx_canary)
        assert [s.name for s in result] == ["canary", "ret2system", "fmtstr"]

        # ctx with has_system + binsh but no canary → canary filtered out
        # (requires_canary=True fails because ctx.canary is None)
        ctx = _ctx(canary=False, has_system=True, binsh_in_binary=True)
        result = candidates(ctx)
        assert [s.name for s in result] == ["ret2system", "fmtstr"]

        # ctx with has_backdoor=1, arch=32, no has_system/binsh → pie_backdoor alone
        ctx_pie = _ctx(bit=32, has_system=False, binsh_in_binary=False)
        ctx_pie.has_backdoor = True
        result = candidates(ctx_pie)
        assert [s.name for s in result] == ["pie_backdoor"]

    def test_canary_wins_over_ret2system_when_canary_present(self):
        """Canary priority (200) > ret2system (150) when canary is set."""
        @register
        class Can(ExploitStrategy):
            name = "canary"; priority = CANARY
            requires_canary = True
            requires = ("has_system", "binsh_in_binary")
            def run(self, ctx): return True
        @register
        class RS(ExploitStrategy):
            name = "ret2system"; priority = RET2SYSTEM
            requires = ("has_system", "binsh_in_binary")
            def run(self, ctx): return True

        ctx = _ctx(canary=True, has_system=True, binsh_in_binary=True)
        result = candidates(ctx)
        assert [s.name for s in result] == ["canary", "ret2system"]


# ---------------------------------------------------------------------------
# all_strategies() / reset()
# ---------------------------------------------------------------------------


class TestAllStrategies:
    """``all_strategies`` returns the full registry (not filtered)."""

    def test_returns_all_regardless_of_match(self):
        """Non-matching strategies are still in ``all_strategies``."""
        s_match = _StubStrat(); s_match.priority = 50; register(s_match)
        s_nomatch = _StubStrat(); s_nomatch.priority = 999
        s_nomatch.requires_arch = 64  # won't match x32 ctx
        register(s_nomatch)

        assert len(all_strategies()) == 2  # both registered

    def test_returns_shallow_copy(self):
        """Mutating the returned list doesn't affect the registry."""
        register(_StubStrat())
        snap = all_strategies()
        snap.clear()
        # Internal registry is intact
        assert len(all_strategies()) == 1

    def test_empty_returns_empty_list(self):
        assert all_strategies() == []


class TestReset:
    """``reset()`` clears the registry (test-only helper)."""

    def test_reset_clears_registry(self):
        register(_StubStrat())
        register(_StubStrat())
        assert len(all_strategies()) == 2
        reset()
        assert all_strategies() == []

    def test_reset_idempotent(self):
        """Calling ``reset`` on an empty registry is a no-op (no error)."""
        reset()
        reset()
        assert all_strategies() == []

    def test_can_reregister_after_reset(self):
        """After reset, registering again works as expected."""
        register(_StubStrat())
        reset()
        # Register a new strategy
        s = _StubStrat()
        register(s)
        assert all_strategies() == [s]


# ---------------------------------------------------------------------------
# Module-level state hygiene
# ---------------------------------------------------------------------------


class TestModuleStateHygiene:
    """The registry is module-level; tests must not pollute each other."""

    def test_registry_module_attribute_is_list(self):
        """``_REGISTRY`` is a list (Pydantic-style invariant)."""
        assert isinstance(_REGISTRY, list)

    def test_register_returns_preserves_binding(self):
        """The decorator returns the class; ``register(instance)`` returns the instance.

        Both forms leave the module-level registry in a consistent
        shape (instances only).
        """
        @register
        class S(ExploitStrategy):
            name = "s"; priority = 10
            def run(self, ctx): return True
        # Returned value (the class) is not the registered instance
        assert isinstance(S, type)
        # Registered value is the instance
        assert isinstance(all_strategies()[0], S)
        assert all_strategies()[0] is not S

    def test_registered_strategies_are_instances_not_classes(self):
        """Sanity: after registration, ``all_strategies`` contains instances only."""
        @register
        class A(ExploitStrategy):
            name = "a"; priority = 10
            def run(self, ctx): return True
        @register
        class B(ExploitStrategy):
            name = "b"; priority = 20
            def run(self, ctx): return True

        for s in all_strategies():
            assert isinstance(s, ExploitStrategy), f"expected instance, got {type(s)}"


# ---------------------------------------------------------------------------
# exp/__init__.py re-exports
# ---------------------------------------------------------------------------


class TestExpPackageReExports:
    """``autopwn.exp`` re-exports the public API of P7.1 + P7.2."""

    def test_exp_package_imports_clean(self):
        """All 13 public names are importable from ``autopwn.exp``."""
        from autopwn import exp
        for name in [
            "ExploitStrategy", "CANARY", "PIE_BACKDOOR", "RET2SYSTEM",
            "RET2LIBC_PUT", "RET2LIBC_WRITE", "RWX_SHELLCODE",
            "EXECVE_SYSCALL", "FMTSTR", "STRATEGY_PRIORITY_HUMAN",
            "register", "candidates", "all_strategies", "reset",
        ]:
            assert hasattr(exp, name), f"autopwn.exp missing {name!r}"

    def test_exp_package_all_is_complete(self):
        """``__all__`` in ``autopwn/exp/__init__.py`` lists every public name."""
        from autopwn import exp
        assert set(exp.__all__) >= {
            "ExploitStrategy", "register", "candidates",
            "CANARY", "RET2SYSTEM", "FMTSTR",
        }
