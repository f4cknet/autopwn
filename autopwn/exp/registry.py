"""P7.2: ``@register`` decorator + ``candidates(ctx)`` priority-sorted list.

The registry is the **single dispatch point** for the P8 orchestrator
(``autopwn/orchestrator.py``, scheduled for P8.2).  The orchestrator
flow reduces to::

    for strat in candidates(ctx):
        ctx.log(f"→ trying {strat.name}")
        if strat.run(ctx):
            record_success(ctx, ctx.last_exploit)
            return 0
    return 1  # no strategy matched / succeeded

Per ``rebuild.md`` §6.8 P7.2 + ``refactor.md`` §3.2.2 + 附录 A
(Owner-signed 2026-06-08, P7.2a / B-003).

Public API
----------
- :func:`register` — register a strategy class or instance.
- :func:`candidates` — return matching strategies sorted by priority.
- :func:`all_strategies` — return the full registry (for P9.3 tests).
- :func:`reset` — clear the registry (test-only helper).

Design notes
------------
* **Class decorator + function form both supported**: ``@register``
  on a class auto-instantiates it; ``register(instance)`` appends
  the instance as-is.  This matches the P7.3 spec example in
  ``refactor.md §3.2.2`` (``@register class ...``) while also
  accepting the function form for late binding.
* **Order is "highest priority first"**: ``sorted(..., reverse=True)``
  per :class:`ExploitStrategy.priority` documentation in
  ``exp/base.py``.  Ties are broken by class registration order
  (stable sort).
* **No implicit import of strategy modules**: P7.11
  (``exp/strategies/__init__.py``) is responsible for the explicit
  imports that trigger ``@register``.  The registry itself doesn't
  import any strategy module — that would create an import cycle
  and violate the "single dependency direction" rule (§6.8 Reviewer
  checklist).
* **No mutation of registered instances**: P7.3+ strategies must
  not store per-run state on ``self``; per-run state lives on
  ``ctx.last_exploit`` and the local ``io`` object.  Enforced
  via convention + the P9.3 registry test (which checks instance
  identity stability across calls).
"""
from __future__ import annotations

from typing import List, Union

from autopwn.context import ExploitContext
from autopwn.exp.base import ExploitStrategy


# The global strategy registry.  Module-level list — Python
# guarantees single instantiation per module, so P7.11's
# import chain is safe even if multiple test files trigger it.
_REGISTRY: List[ExploitStrategy] = []


def register(
    strategy: Union[type[ExploitStrategy], ExploitStrategy],
) -> Union[type[ExploitStrategy], ExploitStrategy]:
    """Register a strategy with the global registry.

    Two calling patterns are supported:

    1. **As a class decorator** (preferred for P7.11 auto-import)::

        @register
        class Ret2SystemX32Strategy(ExploitStrategy):
            priority = 150
            ...
            def run(self, ctx): ...

       The decorator instantiates the class and appends the
       instance.  The class binding is preserved
       (``Ret2SystemX32Strategy`` still points to the class,
       not the instance) so isinstance checks and type
       annotations keep working.

    2. **As a function call** (preferred for late binding)::

        strategy = Ret2SystemX32Strategy()
        register(strategy)

       Caller has full control over instantiation timing
       (useful for tests that want to construct strategies
       with custom state).

    Both forms append the same instance shape to ``_REGISTRY``;
    :func:`candidates` returns instances only (not classes).

    Args:
        strategy: either an :class:`ExploitStrategy` subclass
            (decorator form) or an :class:`ExploitStrategy`
            instance (function form).

    Returns:
        The argument unchanged — decorator form returns the
        class (so the class binding is preserved), function
        form returns the instance (so callers can store it
        in a variable if needed).
    """
    # Class-decorator form: instantiate the class and append the instance.
    # isinstance(cls, type) is True for any class object.
    # issubclass(cls, ExploitStrategy) is True for ABC subclasses.
    if isinstance(strategy, type) and issubclass(strategy, ExploitStrategy):
        _REGISTRY.append(strategy())
    else:
        _REGISTRY.append(strategy)
    return strategy


def candidates(ctx: ExploitContext) -> List[ExploitStrategy]:
    """Return strategies that match ``ctx``, sorted by priority (highest first).

    The orchestrator iterates this list and tries each in
    priority order.  Returns ``[]`` when no strategy matches
    (the orchestrator logs a "no candidate" warning and exits 1).

    Args:
        ctx: a fully populated :class:`ExploitContext`.

    Returns:
        A new list of :class:`ExploitStrategy` **instances**,
        filtered by :meth:`ExploitStrategy.matches`, sorted
        by :attr:`ExploitStrategy.priority` descending.  The
        list is freshly constructed on each call (callers may
        safely mutate it; e.g. an orchestrator could ``[0:0]``
        inject a recovery strategy).

    Ties:
        When two strategies have the same priority, Python's
        stable sort preserves registration order.  This is
        deterministic per process but not globally stable
        across runs (depends on import order in P7.11).
    """
    return sorted(
        (s for s in _REGISTRY if s.matches(ctx)),
        key=lambda s: s.priority,
        reverse=True,
    )


def all_strategies() -> List[ExploitStrategy]:
    """Return ALL registered strategies, regardless of match.

    Used by the P9.3 registry tests to assert "X strategies
    are registered" without needing a fully populated ctx,
    and by the P8 orchestrator for diagnostic logging
    ("X strategies registered, Y candidates for this ctx").

    The returned list is a shallow copy; mutating it doesn't
    affect the registry.
    """
    return list(_REGISTRY)


def reset() -> None:
    """Clear the registry. **Test-only helper.**

    NOT for production use — P7.11 imports all strategy
    modules to trigger ``@register``; a test that calls
    ``reset()`` must re-import the strategy modules to
    repopulate.  See ``tests/unit/test_exp_registry.py``
    for the canonical pattern.

    Production code paths NEVER call this function.
    """
    _REGISTRY.clear()


__all__ = [
    "register",
    "candidates",
    "all_strategies",
    "reset",
]
