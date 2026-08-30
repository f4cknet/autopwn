"""Detect-layer exploit-hint collection for v4.1.19.

Hints are route-level observations that influence strategy ordering but
never bypass a strategy's hard ``matches(ctx)`` gate.
"""
from __future__ import annotations

from pathlib import Path

from autopwn.context import ExploitContext, ExploitHint
from autopwn.recon.targets import inspect_functions


_PRINTF_LIKE_CALLS = frozenset(
    {
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "dprintf",
        "vprintf",
        "vfprintf",
        "vsprintf",
        "vsnprintf",
    }
)


def collect_static_hints(ctx: ExploitContext, program: Path) -> list[ExploitHint]:
    """Collect cheap structural hints before expensive runtime probing."""
    hints: list[ExploitHint] = []

    if ctx.mode == "local" and ctx.binary.stack_canary:
        hints.append(
            ExploitHint(
                kind="local_nonfork_canary_bruteforce_penalty",
                score_delta=-30,
                reason="local stack-canary target: avoid unbounded blind brute-force",
            )
        )

    for func in inspect_functions(program):
        if func.input_call_count >= 2:
            hints.append(
                ExploitHint(
                    kind="second_input_sink",
                    score_delta=0,
                    reason=(
                        f"{func.name} keeps {func.input_call_count} independent input sinks "
                        "for leak-then-bof style chains"
                    ),
                )
            )
            break

    return _dedupe_hints(hints)


def collect_fmtstr_hints(
    ctx: ExploitContext,
    program: Path,
    *,
    fmtstr_vulnerable: bool,
) -> list[ExploitHint]:
    """Promote runtime-confirmed format-string routes into scoring hints."""
    if not fmtstr_vulnerable:
        return []

    hints: list[ExploitHint] = []
    for func in inspect_functions(program):
        if func.input_call_count <= 0:
            continue
        if not any(call in _PRINTF_LIKE_CALLS for call in func.imported_calls):
            continue

        hints.append(
            ExploitHint(
                kind="fmtstr_sink",
                score_delta=0,
                reason=f"{func.name} combines attacker-controlled input with printf-like output",
            )
        )
        if func.input_call_count >= 2:
            hints.append(
                ExploitHint(
                    kind="fmt_then_bof",
                    score_delta=40,
                    reason=f"{func.name} keeps a second input sink after a format-string sink",
                )
            )
        break

    if ctx.binary.stack_canary:
        hints.append(
            ExploitHint(
                kind="canary_leakable",
                score_delta=20,
                reason="format-string leak can feed a later canary-bypass chain",
            )
        )
    if ctx.binary.relro == "Partial" and not ctx.binary.pie:
        hints.append(
            ExploitHint(
                kind="got_writable_no_pie",
                score_delta=15,
                reason="Partial RELRO + No PIE keeps classic fmtstr GOT overwrite viable",
            )
        )

    return _dedupe_hints(hints)


def _dedupe_hints(hints: list[ExploitHint]) -> list[ExploitHint]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ExploitHint] = []
    for hint in hints:
        key = (hint.kind, hint.reason)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hint)
    return deduped


__all__ = [
    "collect_static_hints",
    "collect_fmtstr_hints",
]
