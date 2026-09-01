"""AutoPwn v5 minimal planner entry.

This module is the first thin slice of the v5 Planner layer: it does
not introduce search/backtracking yet, but it does turn the registry's
ranked legacy candidates into explicit plan objects backed by
capability metadata.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from autopwn.context import Capability, CapabilityKind, ExploitContext, FactScope
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.registry import RankedCandidate, ranked_candidates


@dataclass(slots=True, frozen=True)
class ExploitPlanStep:
    """One capability-backed step inside a planner-visible exploit plan."""

    capability_id: str
    kind: CapabilityKind
    scope: FactScope | None = None
    graph_name: str = ""
    fact_keys: tuple[str, ...] = ()
    step_ids: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()


@dataclass(slots=True, frozen=True)
class ExploitPlan:
    """A minimal executable route assembled from one legacy strategy."""

    plan_id: str
    strategy_name: str
    score: int
    steps: tuple[ExploitPlanStep, ...] = ()
    graph_names: tuple[str, ...] = ()
    prerequisite_facts: tuple[str, ...] = ()
    provided_facts: tuple[str, ...] = ()
    adjustments: tuple[str, ...] = ()

    @property
    def capability_ids(self) -> tuple[str, ...]:
        return tuple(step.capability_id for step in self.steps)


@dataclass(slots=True, frozen=True)
class PlannedCandidate:
    """A ranked legacy strategy paired with its explicit plan object."""

    ranked: RankedCandidate
    plan: ExploitPlan

    @property
    def strategy(self) -> ExploitStrategy:
        return self.ranked.strategy


def planned_candidates(ctx: ExploitContext) -> List[PlannedCandidate]:
    """Build planner-visible candidates while preserving registry ordering."""
    planned: List[PlannedCandidate] = []
    for ranked in ranked_candidates(ctx):
        plan = build_plan(ctx, ranked)
        planned.append(PlannedCandidate(ranked=ranked, plan=plan))

    ctx.set_fact(
        "planner.plan_count",
        len(planned),
        scope=FactScope.ATTEMPT,
        source="planner",
    )
    ctx.set_fact(
        "planner.selected",
        planned[0].plan.plan_id if planned else "",
        scope=FactScope.ATTEMPT,
        source="planner",
    )
    return planned


def build_plan(ctx: ExploitContext, ranked: RankedCandidate) -> ExploitPlan:
    """Assemble one minimal plan from a ranked legacy candidate."""
    capabilities = _resolve_capabilities(ctx, ranked)
    steps = tuple(
        ExploitPlanStep(
            capability_id=capability.capability_id,
            kind=capability.kind,
            scope=capability.prereq.scope,
            graph_name=capability.binding.graph_name,
            fact_keys=capability.prereq.fact_keys,
            step_ids=capability.binding.step_ids,
            provides=capability.provides,
        )
        for capability in capabilities
    )
    plan = ExploitPlan(
        plan_id=f"plan.{ranked.strategy.name}",
        strategy_name=ranked.strategy.name,
        score=ranked.effective_priority,
        steps=steps,
        graph_names=_ordered_unique(step.graph_name for step in steps),
        prerequisite_facts=_ordered_unique(
            fact_key
            for step in steps
            for fact_key in step.fact_keys
        ),
        provided_facts=_ordered_unique(
            fact_key
            for step in steps
            for fact_key in step.provides
        ),
        adjustments=ranked.adjustments,
    )
    ctx.set_fact(
        f"plan.{ranked.strategy.name}",
        plan,
        scope=FactScope.ATTEMPT,
        source=f"planner.{ranked.strategy.name}",
    )
    return plan


def _resolve_capabilities(
    ctx: ExploitContext,
    ranked: RankedCandidate,
) -> tuple[Capability, ...]:
    capabilities = []
    for capability_id in ranked.capability_ids:
        capability = ctx.get_capability(capability_id, scope=FactScope.BINARY)
        if isinstance(capability, Capability):
            capabilities.append(capability)
    return tuple(capabilities)


def _ordered_unique(values) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


__all__ = [
    "ExploitPlanStep",
    "ExploitPlan",
    "PlannedCandidate",
    "planned_candidates",
    "build_plan",
]
