from __future__ import annotations

from autopwn.context import BinaryInfo, ExploitContext, FactScope, InteractionGraph, InteractionKind


def _make_ctx(tmp_path, *, mode: str = "local") -> ExploitContext:
    fake_bin = tmp_path / f"{mode}_binary"
    fake_bin.write_bytes(b"\x7fELF")
    remote = ("127.0.0.1", 31337) if mode == "remote" else None
    return ExploitContext(
        binary=BinaryInfo(
            path=fake_bin, bit=64, stack_canary=False, pie=False,
            nx=True, relro="Partial", rwx_segments=False, stripped=False,
        ),
        mode=mode,
        remote=remote,
    )


def test_fact_store_exact_scope_lookup_and_snapshot(tmp_path):
    ctx = _make_ctx(tmp_path)
    record = ctx.set_fact("overflow.padding", 80, scope=FactScope.BINARY, source="test.padding")
    assert record.scope is FactScope.BINARY
    assert record.source == "test.padding"
    assert ctx.get_fact("overflow.padding", scope=FactScope.BINARY) == 80
    assert ctx.facts.snapshot(scope=FactScope.BINARY) == {"overflow.padding": 80}


def test_fact_store_prefers_narrower_scope_for_generic_lookup(tmp_path):
    ctx = _make_ctx(tmp_path)
    ctx.set_fact("canary.info", "binary-view", scope=FactScope.BINARY)
    ctx.set_fact("canary.info", "process-view", scope=FactScope.PROCESS)
    assert ctx.get_fact("canary.info") == "process-view"


def test_runtime_fact_scope_tracks_local_vs_remote(tmp_path):
    assert _make_ctx(tmp_path, mode="local").runtime_fact_scope is FactScope.PROCESS
    assert _make_ctx(tmp_path, mode="remote").runtime_fact_scope is FactScope.SESSION


def test_clear_scope_removes_only_target_scope(tmp_path):
    ctx = _make_ctx(tmp_path)
    ctx.set_fact("strings.binsh_in_binary", True, scope=FactScope.BINARY)
    ctx.set_fact("canary.fuzz_budget_exhausted", {"attempts": 1}, scope=FactScope.ATTEMPT)
    ctx.clear_facts(FactScope.ATTEMPT)
    assert ctx.get_fact("strings.binsh_in_binary", scope=FactScope.BINARY) is True
    assert not ctx.has_fact("canary.fuzz_budget_exhausted", scope=FactScope.ATTEMPT)


def test_interaction_graph_can_be_stored_and_record_events(tmp_path):
    ctx = _make_ctx(tmp_path)
    graph = InteractionGraph(name="two-stage-demo")
    graph.add_step("leak", InteractionKind.LEAK, produces=("libc.puts_addr",))
    graph.add_step("exec", InteractionKind.EXECUTE, requires=("libc.puts_addr",))
    graph.connect("leak", "exec", reason="need libc leak before stage 2")
    graph.record_event("leak", "puts=0xf7d638e0")
    ctx.set_interaction_graph(graph, scope=FactScope.PROCESS, source="test.graph")
    stored = ctx.get_interaction_graph("two-stage-demo", scope=FactScope.PROCESS)
    assert stored is graph
    assert stored.event_step_ids() == ("leak",)
    assert stored.edges[0].reason == "need libc leak before stage 2"
