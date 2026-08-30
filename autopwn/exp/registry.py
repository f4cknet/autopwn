"""P7.2 registry with v4.1.19 effective-priority ranking.

`matches(ctx)` remains the hard gate; v4.1.19 only adds route-level
re-ranking from `ctx.exploit_hints`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Union

from autopwn.context import ExploitContext, ExploitHint
from autopwn.exp.base import ExploitStrategy


_REGISTRY: List[ExploitStrategy] = []


@dataclass(slots=True, frozen=True)
class RankedCandidate:
    """A matched strategy plus its effective-priority explanation."""

    strategy: ExploitStrategy
    effective_priority: int
    adjustments: tuple[str, ...] = ()


def register(
    strategy: Union[type[ExploitStrategy], ExploitStrategy],
) -> Union[type[ExploitStrategy], ExploitStrategy]:
    """Register a strategy class or instance with the global registry."""
    if isinstance(strategy, type) and issubclass(strategy, ExploitStrategy):
        _REGISTRY.append(strategy())
    else:
        _REGISTRY.append(strategy)
    return strategy


def ranked_candidates(ctx: ExploitContext) -> List[RankedCandidate]:
    """Return matching strategies with effective priorities and reasons."""
    ranked = []
    for strategy in _REGISTRY:
        if not strategy.matches(ctx):
            continue
        effective = strategy.priority
        adjustments: list[str] = []
        for hint in getattr(ctx, "exploit_hints", ()):
            delta = _hint_adjustment(ctx, strategy, hint)
            if delta == 0:
                continue
            effective += delta
            adjustments.append(f"{hint.kind} {delta:+d}")
        ranked.append(
            RankedCandidate(
                strategy=strategy,
                effective_priority=effective,
                adjustments=tuple(adjustments),
            )
        )
    return sorted(ranked, key=lambda item: item.effective_priority, reverse=True)


def candidates(ctx: ExploitContext) -> List[ExploitStrategy]:
    """Return matching strategies sorted by effective priority."""
    return [item.strategy for item in ranked_candidates(ctx)]


def all_strategies() -> List[ExploitStrategy]:
    """Return a shallow copy of the full registry."""
    return list(_REGISTRY)


def reset() -> None:
    """Clear the registry. Test-only helper."""
    _REGISTRY.clear()


def _hint_adjustment(
    ctx: ExploitContext,
    strategy: ExploitStrategy,
    hint: ExploitHint,
) -> int:
    name = strategy.name
    is_fmtstr = name.startswith("fmtstr-")
    is_fmtstr_write = is_fmtstr and "print-strings" not in name
    is_canary = bool(getattr(strategy, "requires_canary", False))

    if hint.kind == "fmt_then_bof":
        if is_fmtstr_write:
            return hint.score_delta
        if is_canary and ctx.canary is not None:
            return hint.score_delta // 2
        return 0

    if hint.kind == "canary_leakable":
        if is_fmtstr_write:
            return hint.score_delta
        if is_canary and ctx.canary is not None:
            return hint.score_delta
        return 0

    if hint.kind == "got_writable_no_pie":
        return hint.score_delta if is_fmtstr_write else 0

    if hint.kind == "local_nonfork_canary_bruteforce_penalty":
        if is_canary and ctx.canary is None:
            return hint.score_delta
        return 0

    return 0


__all__ = [
    "RankedCandidate",
    "register",
    "ranked_candidates",
    "candidates",
    "all_strategies",
    "reset",
]
