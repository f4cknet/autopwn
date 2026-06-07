"""Detect layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.1 / §5 for the detect contracts.

P5 modules in this layer (all follow the same pattern: one or more
public functions taking a ``ctx`` (and optionally a ``program``
Path + ``bit``); the function writes results to ctx fields — the
P5 layer is the **only** layer authorized to mutate ``ctx`` per
``refactor.md`` §3.2.1; unit-testable in isolation under P5.5):

  * **P5.1** (``overflow``) — ``test_stack_overflow(ctx, program, bit)``
    and ``analyze_vulnerable_functions(ctx, program, bit)``;
    both write the discovered padding into ``ctx.padding``.
"""
from __future__ import annotations

from autopwn.detect.overflow import (
    test_stack_overflow as test_stack_overflow,
    analyze_vulnerable_functions as analyze_vulnerable_functions,
)

__all__: list[str] = [
    "test_stack_overflow",
    "analyze_vulnerable_functions",
]
