"""Unit tests for ``autopwn.exp.base`` (P7.1).

Per ``rebuild.md`` §6.8 P7.1 + ``refactor.md`` §3.2.2,
:class:`ExploitStrategy` is the ABC foundation of the P7
strategies layer.  This module tests:

  * ABC contract — direct instantiation forbidden;
    subclasses must implement :meth:`run`.
  * :meth:`matches` — declarative filter on
    ``requires_arch`` / ``requires_remote`` /
    ``requires_canary`` / ``requires`` tuple.
  * :meth:`matches` subclass override — ``super().matches()``
    is composable.
  * :meth:`__repr__` — canonical format for log lines and
    P9 registry tests.
  * :attr:`primitive` — optional link to an
    :class:`ExploitPrimitive` subclass.

P7.2 will add the ``@register`` decorator + ``candidates()``
function; P7.3-P7.10 will fill in concrete strategy classes.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.strategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _StubStrategy:
    """Bare-minimum ``ExploitStrategy`` subclass for testing.

    Defines a single :meth:`run` returning ``True`` so the
    ABC contract is satisfied.  Tests that want to assert
    on a particular ``requires_*`` value set
    :attr:`requires_arch` etc. directly on this class.
    """

    def __init__(self) -> None:
        pass

    @property
    def name(self) -> str:
        return type(self).__name__


def _make_strat(**overrides) -> "ExploitStrategy":  # noqa: F821
    """Build a fully-populated concrete :class:`ExploitStrategy` subclass.

    Defaults satisfy all ``requires_*`` (matches any ctx).
    Tests override individual fields to assert on :meth:`matches`.
    """
    from autopwn.exp.base import ExploitStrategy

    class _Concrete(ExploitStrategy):
        name = "stub"
        priority = 100

        def run(self, ctx) -> bool:  # noqa: ARG002
            return True

    for key, value in overrides.items():
        setattr(_Concrete, key, value)
    return _Concrete()


# ---------------------------------------------------------------------------
# ABC contract
# ---------------------------------------------------------------------------


class TestExploitStrategyABC:
    """``exp.base.ExploitStrategy`` — abstract base contract."""

    def test_cannot_instantiate_directly(self):
        """The ABC raises ``TypeError`` when instantiated without a ``run`` impl."""
        from autopwn.exp.base import ExploitStrategy

        with pytest.raises(TypeError) as exc_info:
            ExploitStrategy()  # noqa: B017  (intentional ABC violation)
        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_run(self):
        """A subclass without ``run`` is also non-instantiable."""
        from autopwn.exp.base import ExploitStrategy

        class Incomplete(ExploitStrategy):
            name = "incomplete"
            # NOTE: no run override — should be non-instantiable

        with pytest.raises(TypeError):
            Incomplete()  # noqa: B017

    def test_subclass_with_run_is_instantiable(self):
        """A complete subclass instantiates and runs."""
        from autopwn.exp.base import ExploitStrategy

        class Complete(ExploitStrategy):
            name = "complete"
            priority = 42

            def run(self, ctx) -> bool:
                return True

        inst = Complete()
        assert inst.name == "complete"
        assert inst.priority == 42
        assert inst.run(None) is True

    def test_name_default_is_empty(self):
        """Class attribute ``name`` defaults to ``""`` — subclasses MUST override."""
        from autopwn.exp.base import ExploitStrategy

        class Nameless(ExploitStrategy):
            def run(self, ctx) -> bool:
                return False

        assert Nameless().name == ""

    def test_priority_default_is_zero(self):
        """Class attribute ``priority`` defaults to 0."""
        from autopwn.exp.base import ExploitStrategy

        class Default(ExploitStrategy):
            def run(self, ctx) -> bool:
                return False

        assert Default().priority == 0

    def test_requires_default_is_empty_tuple(self):
        """Class attribute ``requires`` defaults to ``()`` (no ctx deps)."""
        from autopwn.exp.base import ExploitStrategy

        class Default(ExploitStrategy):
            def run(self, ctx) -> bool:
                return False

        assert Default().requires == ()

    def test_primitive_default_is_none(self):
        """``primitive`` link defaults to ``None`` (subclasses may set a type)."""
        from autopwn.exp.base import ExploitStrategy

        class Default(ExploitStrategy):
            def run(self, ctx) -> bool:
                return False

        assert Default().primitive is None

    def test_primitive_can_be_set_to_a_type(self):
        """Subclasses can set ``primitive`` to an ``ExploitPrimitive`` subclass."""
        from autopwn.exp.base import ExploitStrategy
        from autopwn.primitives.base import ExploitPrimitive

        class _Prim(ExploitPrimitive):
            name = "stub-prim"

            def build_payload(self, ctx) -> bytes:  # noqa: ARG002
                return b""

        class WithPrim(ExploitStrategy):
            name = "with-prim"
            primitive = _Prim

            def run(self, ctx) -> bool:  # noqa: ARG002
                return True

        assert WithPrim().primitive is _Prim


# ---------------------------------------------------------------------------
# matches() — declarative filter
# ---------------------------------------------------------------------------


class TestMatchesNoRequirements:
    """``matches`` with no ``requires_*`` set → always True."""

    def test_no_requirements_matches_local_ctx(self):
        """A strategy with no declarative requirements matches local ctx."""
        strat = _make_strat()
        ctx = ctx_for("canary", bit=32)
        assert strat.matches(ctx) is True

    def test_no_requirements_matches_remote_ctx(self):
        """A strategy with no declarative requirements matches remote ctx."""
        strat = _make_strat()
        from autopwn.context import ExploitContext, BinaryInfo

        ctx = ExploitContext(
            binary=BinaryInfo(
                path=Path("/tmp/x"),
                bit=64,
                stack_canary=False,
                pie=False,
                nx=True,
                relro="Partial",
                rwx_segments=False,
                stripped=False,
            ),
            mode="remote",
            remote=("127.0.0.1", 9999),
        )
        assert strat.matches(ctx) is True


class TestMatchesArch:
    """``matches`` arch filter (requires_arch=32|64|None)."""

    def test_arch_32_matches_32bit_ctx(self):
        strat = _make_strat(requires_arch=32)
        ctx = ctx_for("canary", bit=32)
        assert strat.matches(ctx) is True

    def test_arch_32_rejects_64bit_ctx(self):
        strat = _make_strat(requires_arch=32)
        ctx = ctx_for("level3_x64", bit=64)
        assert strat.matches(ctx) is False

    def test_arch_64_matches_64bit_ctx(self):
        strat = _make_strat(requires_arch=64)
        ctx = ctx_for("level3_x64", bit=64)
        assert strat.matches(ctx) is True

    def test_arch_64_rejects_32bit_ctx(self):
        strat = _make_strat(requires_arch=64)
        ctx = ctx_for("canary", bit=32)
        assert strat.matches(ctx) is False

    def test_arch_none_matches_both(self):
        """``requires_arch=None`` (default) is arch-agnostic."""
        strat_32 = _make_strat(requires_arch=None)
        for bit, bin_name in [(32, "canary"), (64, "level3_x64")]:
            ctx = ctx_for(bin_name, bit=bit)
            assert strat_32.matches(ctx) is True, f"failed for {bin_name}"


class TestMatchesRemote:
    """``matches`` mode filter (requires_remote=True|False|None)."""

    def test_remote_true_matches_remote_ctx(self):
        strat = _make_strat(requires_remote=True)
        from autopwn.context import ExploitContext, BinaryInfo

        ctx = ExploitContext(
            binary=BinaryInfo(
                path=Path("/tmp/x"),
                bit=32, stack_canary=False, pie=False, nx=True,
                relro="Partial", rwx_segments=False, stripped=False,
            ),
            mode="remote", remote=("127.0.0.1", 9999),
        )
        assert strat.matches(ctx) is True

    def test_remote_true_rejects_local_ctx(self):
        strat = _make_strat(requires_remote=True)
        ctx = ctx_for("canary", bit=32)
        assert ctx.mode == "local"
        assert strat.matches(ctx) is False

    def test_remote_false_matches_local_ctx(self):
        strat = _make_strat(requires_remote=False)
        ctx = ctx_for("canary", bit=32)
        assert strat.matches(ctx) is True

    def test_remote_false_rejects_remote_ctx(self):
        strat = _make_strat(requires_remote=False)
        from autopwn.context import ExploitContext, BinaryInfo

        ctx = ExploitContext(
            binary=BinaryInfo(
                path=Path("/tmp/x"),
                bit=32, stack_canary=False, pie=False, nx=True,
                relro="Partial", rwx_segments=False, stripped=False,
            ),
            mode="remote", remote=("127.0.0.1", 9999),
        )
        assert strat.matches(ctx) is False

    def test_remote_none_matches_both(self):
        """``requires_remote=None`` (default) is mode-agnostic."""
        strat = _make_strat(requires_remote=None)
        ctx_local = ctx_for("canary", bit=32)
        from autopwn.context import ExploitContext, BinaryInfo

        ctx_remote = ExploitContext(
            binary=BinaryInfo(
                path=Path("/tmp/x"),
                bit=32, stack_canary=False, pie=False, nx=True,
                relro="Partial", rwx_segments=False, stripped=False,
            ),
            mode="remote", remote=("127.0.0.1", 9999),
        )
        assert strat.matches(ctx_local) is True
        assert strat.matches(ctx_remote) is True


class TestMatchesCanary:
    """``matches`` canary filter (requires_canary=True|False)."""

    def test_requires_canary_true_rejects_ctx_without_canary(self):
        from autopwn.context import CanaryInfo

        strat = _make_strat(requires_canary=True)
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        assert ctx.canary is None  # default from ctx_for
        assert strat.matches(ctx) is False

    def test_requires_canary_true_accepts_ctx_with_canary(self):
        from autopwn.context import CanaryInfo

        strat = _make_strat(requires_canary=True)
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.canary = CanaryInfo(value=0x1234567890ABCDEF, diff=24)
        assert strat.matches(ctx) is True

    def test_requires_canary_false_default_accepts_both(self):
        """``requires_canary=False`` (default) accepts both canary and non-canary ctx."""
        from autopwn.context import CanaryInfo

        strat = _make_strat()
        ctx_no = ctx_for("canary", bit=32)
        ctx_yes = ctx_for("canary", bit=32, stack_canary=True)
        ctx_yes.canary = CanaryInfo(value=0x1, diff=8)
        assert strat.matches(ctx_no) is True
        assert strat.matches(ctx_yes) is True


class TestRequiresTuple:
    """``matches`` ctx-attribute tuple filter (requires=("has_X", ...))."""

    def test_requires_empty_tuple_matches_any_ctx(self):
        strat = _make_strat(requires=())
        ctx = ctx_for("canary", bit=32)
        assert strat.matches(ctx) is True

    def test_requires_all_present(self):
        strat = _make_strat(requires=("has_system", "binsh_in_binary"))
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.has_system = True
        ctx.binsh_in_binary = True
        assert strat.matches(ctx) is True

    def test_requires_one_missing(self):
        strat = _make_strat(requires=("has_system", "binsh_in_binary"))
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.has_system = True
        ctx.binsh_in_binary = False  # missing
        assert strat.matches(ctx) is False

    def test_requires_all_missing(self):
        strat = _make_strat(requires=("has_system", "binsh_in_binary"))
        ctx = ctx_for("fmtstr1", bit=32)
        assert strat.matches(ctx) is False

    def test_requires_attribute_error_returns_false(self):
        """If a ``requires`` key doesn't exist on ctx, ``getattr`` raises → match=False.

        Per :meth:`matches` impl: ``all(getattr(ctx, k) for k in self.requires)``.
        An unknown attribute propagates ``AttributeError`` from
        ``getattr`` (no default).  Strategy authors MUST use
        valid ctx field names; an unknown name effectively
        disqualifies the strategy via the raised exception.
        """
        strat = _make_strat(requires=("does_not_exist",))
        ctx = ctx_for("canary", bit=32)
        with pytest.raises(AttributeError):
            strat.matches(ctx)


class TestMatchesCombined:
    """``matches`` — combined requirements (arch + remote + canary + tuple)."""

    def test_all_filters_must_pass(self):
        """All four ``requires_*`` filters must pass for ``matches() == True``."""
        from autopwn.context import CanaryInfo

        strat = _make_strat(
            requires_arch=32,
            requires_remote=False,
            requires_canary=True,
            requires=("has_system",),
        )
        # Fulfills all 4
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.canary = CanaryInfo(value=0x1, diff=8)
        ctx.has_system = True
        assert strat.matches(ctx) is True

        # Breaks arch
        ctx_wrong_arch = ctx_for("canary", bit=64, stack_canary=True)
        ctx_wrong_arch.canary = CanaryInfo(value=0x1, diff=8)
        ctx_wrong_arch.has_system = True
        assert strat.matches(ctx_wrong_arch) is False

    def test_short_circuits_on_arch(self):
        """arch mismatch short-circuits before remote/canary/requires are checked.

        This isn't strictly a correctness invariant — it's an
        efficiency note.  We assert the observable behaviour
        (False return) only; ordering of checks is an
        implementation detail of :meth:`matches`.
        """
        strat = _make_strat(requires_arch=32, requires_remote=True, requires_canary=True)
        ctx = ctx_for("canary", bit=64)  # arch mismatch
        # Even though remote/canary would also fail, arch is checked first
        # so we get a clean False without exceptions.
        assert strat.matches(ctx) is False


class TestMatchesSubclassOverride:
    """Subclasses can override :meth:`matches` and compose with ``super().matches()``."""

    def test_subclass_override_composes_with_super(self):
        from autopwn.exp.base import ExploitStrategy

        class Gated(ExploitStrategy):
            name = "gated"
            requires_arch = 32  # declarative: only x32

            def matches(self, ctx) -> bool:
                # Custom check: libc must be set
                if ctx.libc is None or ctx.libc.path is None:
                    return False
                return super().matches(ctx)

            def run(self, ctx) -> bool:  # noqa: ARG002
                return True

        # No libc → False (custom check rejects)
        ctx = ctx_for("canary", bit=32)
        assert Gated().matches(ctx) is False

        # With libc + arch=32 → True (custom + super both pass)
        from autopwn.context import LibcInfo

        ctx.libc = LibcInfo(path=Path("/lib/x86_64-linux-gnu/libc.so.6"))
        assert Gated().matches(ctx) is True

        # With libc but wrong arch → False (super rejects)
        ctx64 = ctx_for("level3_x64", bit=64)
        ctx64.libc = LibcInfo(path=Path("/lib/x86_64-linux-gnu/libc.so.6"))
        assert Gated().matches(ctx64) is False


# ---------------------------------------------------------------------------
# __repr__
# ---------------------------------------------------------------------------


class TestRepr:
    """``__repr__`` — canonical format for log lines + P9 registry tests."""

    def test_repr_includes_name_priority_arch_remote(self):
        strat = _make_strat(name="my-strat", priority=120, requires_arch=32, requires_remote=False)
        r = repr(strat)
        assert "my-strat" in r
        assert "120" in r
        assert "32" in r
        assert "False" in r  # requires_remote

    def test_repr_uses_class_name(self):
        strat = _make_strat(name="x", priority=10, requires_arch=None, requires_remote=None)
        r = repr(strat)
        # Class name is e.g. ``_Concrete`` (the helper's inner class)
        assert "_Concrete" in r
        assert "x" in r
        assert "10" in r

    def test_repr_does_not_include_requires_tuple(self):
        """``requires`` tuple is verbose; the repr keeps the 4 main fields.

        The orchestrator can call ``strat.requires`` directly
        when full debug output is needed.
        """
        strat = _make_strat(
            name="x", priority=10, requires_arch=32, requires_remote=False,
            requires=("has_system", "binsh_in_binary"),
        )
        r = repr(strat)
        assert "has_system" not in r
        assert "binsh_in_binary" not in r
