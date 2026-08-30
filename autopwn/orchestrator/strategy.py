"""AutoPwn orchestrator — Phase 3 (strategy).

Split out from the monolithic ``autopwn/orchestrator.py`` (P11.5,
2026-06-10) for line-count governance.  The function signature,
behaviour, and log markers are **unchanged** — this is a pure
file split, not a refactor.
"""
from __future__ import annotations

from typing import List

from autopwn.context import ExploitContext
from autopwn.core.logging import (
    print_info,
    print_warning,
)
from autopwn.exp.registry import ranked_candidates
from autopwn.exp import strategies as _strategies  # noqa: F401  -- import to trigger @register


def run_strategy_phase(ctx: ExploitContext) -> int:
    """Phase 3: iterate ``candidates(ctx)`` and try each in priority order.

    The first strategy whose :meth:`ExploitStrategy.run` returns
    ``True`` wins; this function returns ``0`` immediately.  If
    every candidate returns ``False`` (or raises), returns ``1``
    to signal "no strategy matched".

    Each strategy invocation is wrapped in a ``try/except`` that
    logs the failure and continues — a single strategy crash
    must not abort the whole run.

    Returns:
        ``0`` if any strategy succeeded; ``1`` otherwise.
    """
    ranked = ranked_candidates(ctx)
    match_list: List = [item.strategy for item in ranked]
    n = len(match_list)
    print_info(f"candidates: {n} strategies matched this context")
    if ctx.preferred_target is not None:
        print_info(
            f"preferred target: {ctx.preferred_target.name} "
            f"@ 0x{ctx.preferred_target.addr:x} "
            f"(score={ctx.preferred_target.score})"
        )
    if getattr(ctx, "exploit_hints", None):
        hint_kinds = ", ".join(hint.kind for hint in ctx.exploit_hints)
        print_info(f"active exploit hints: {hint_kinds}")
    for item in ranked:
        adjustment_text = ", ".join(item.adjustments) if item.adjustments else "base"
        print_info(
            f"candidate order: {item.strategy.name} "
            f"base={item.strategy.priority} "
            f"effective={item.effective_priority} "
            f"[{adjustment_text}]"
        )
    for strat in match_list:
        print_info(f"→ trying {strat.name}")
        try:
            if strat.run(ctx):
                return 0
        except Exception as exc:  # noqa: BLE001 — intentional, see docstring
            print_warning(f"{strat.name} failed: {exc}")
    if n == 0:
        print_warning("no exploitation strategy matched this context")
    else:
        print_warning(f"all {n} candidate strategies failed")
    return 1


__all__ = ["run_strategy_phase"]
