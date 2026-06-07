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
  * **P5.2** (``fmtstr``) — ``detect_format_string_vulnerability(ctx, program)``
    returning a :class:`FormatStringProbe` dataclass, and
    ``find_offset(ctx, program)`` returning the 1-based offset
    of the ``0x41414141`` sentinel in a leaked stack walk.
  * **P5.3** (``canary``) — ``leakage_canary_value(ctx, program)``
    returns list of ``(offset, hex_string)`` pairs; ``canary_fuzz(ctx, program, bit, leaks)``
    returns a :class:`CanaryInfo` (or ``None``) and writes it
    into ``ctx.canary``.
  * **P5.4** (``binsh``) — ``check_binsh(ctx, program)`` returns
    a bool (and writes it into ``ctx.binsh_in_binary``) indicating
    whether the binary contains the ``/bin/sh`` string.
"""
from __future__ import annotations

from autopwn.detect.overflow import (
    test_stack_overflow as test_stack_overflow,
    analyze_vulnerable_functions as analyze_vulnerable_functions,
)
from autopwn.detect.fmtstr import (
    FormatStringProbe as FormatStringProbe,
    detect_format_string_vulnerability as detect_format_string_vulnerability,
    find_offset as find_offset,
)
from autopwn.detect.canary import (
    leakage_canary_value as leakage_canary_value,
    canary_fuzz as canary_fuzz,
)
from autopwn.detect.binsh import (
    check_binsh as check_binsh,
)

__all__: list[str] = [
    "test_stack_overflow",
    "analyze_vulnerable_functions",
    "FormatStringProbe",
    "detect_format_string_vulnerability",
    "find_offset",
    "leakage_canary_value",
    "canary_fuzz",
    "check_binsh",
]
