from __future__ import annotations

from pathlib import Path

import pytest

from autopwn.context import BinaryInfo, CapabilityKind, ExploitContext, FactScope, make_capability
from autopwn.exp import ExploitStrategy, FMTSTR, RET2SYSTEM, register, reset
from autopwn.planner import planned_candidates


def _ctx() -> ExploitContext:
    return ExploitContext(
        binary=BinaryInfo(
            path=Path("/tmp/planner"),
            bit=32,
            stack_canary=False,
            pie=False,
            nx=True,
            relro="Partial",
            rwx_segments=False,
            stripped=False,
        ),
        mode="local",
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    reset()
    yield
    reset()


class _BaseStrategy(ExploitStrategy):
    name = "base"
    priority = 0

    def run(self, ctx) -> bool:  # noqa: ARG002
        return False


def test_planner_builds_capability_backed_plan_and_records_attempt_facts():
    class CapStrategy(_BaseStrategy):
        name = "cap-strategy"
        priority = FMTSTR

        def describe_capabilities(self, ctx):
            return (
                make_capability(
                    "demo.leak",
                    CapabilityKind.LEAK,
                    strategy_name=self.name,
                    graph_name="demo",
                    fact_keys=("overflow.padding",),
                    scope=FactScope.BINARY,
                    step_ids=("leak",),
                    provides=("libc.puts_addr",),
                ),
                make_capability(
                    "demo.verify",
                    CapabilityKind.VERIFY,
                    strategy_name=self.name,
                    graph_name="demo",
                    fact_keys=("libc.puts_addr",),
                    scope=FactScope.PROCESS,
                    step_ids=("verify",),
                    provides=("shell.verified",),
                ),
            )

    register(CapStrategy())
    ctx = _ctx()
    ctx.set_fact("overflow.padding", 80, scope=FactScope.BINARY, source="test.padding")

    planned = planned_candidates(ctx)

    assert len(planned) == 1
    plan = planned[0].plan
    assert plan.plan_id == "plan.cap-strategy"
    assert plan.capability_ids == ("demo.leak", "demo.verify")
    assert plan.graph_names == ("demo",)
    assert plan.prerequisite_facts == ("overflow.padding", "libc.puts_addr")
    assert plan.provided_facts == ("libc.puts_addr", "shell.verified")
    assert ctx.get_fact("planner.selected", scope=FactScope.ATTEMPT) == "plan.cap-strategy"
    assert ctx.get_fact("planner.plan_count", scope=FactScope.ATTEMPT) == 1
    assert ctx.get_fact("plan.cap-strategy", scope=FactScope.ATTEMPT) is plan


def test_planner_preserves_effective_priority_order():
    high = _BaseStrategy()
    high.name = "high"
    high.priority = RET2SYSTEM

    low = _BaseStrategy()
    low.name = "low"
    low.priority = FMTSTR

    register(low)
    register(high)

    planned = planned_candidates(_ctx())
    assert [item.strategy.name for item in planned] == ["high", "low"]
    assert [item.plan.score for item in planned] == [RET2SYSTEM, FMTSTR]


def test_planner_keeps_legacy_strategy_without_capabilities():
    legacy = _BaseStrategy()
    legacy.name = "legacy-only"
    legacy.priority = RET2SYSTEM
    register(legacy)

    plan = planned_candidates(_ctx())[0].plan
    assert plan.capability_ids == ()
    assert plan.graph_names == ()
    assert plan.prerequisite_facts == ()
