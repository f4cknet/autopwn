"""Primitives layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.2 for the primitives contract.

P6 modules in this layer (all follow the same pattern: one
or more subclasses of :class:`ExploitPrimitive`, each implementing
``build_payload(ctx) -> bytes`` as a pure function — no
file writes, no process spawns, no ``ctx`` mutation; read-only
ELF parsing for symbol lookup is allowed and expected):

  * **P6.1** (``base``) — :class:`ExploitPrimitive` ABC +
    :class:`ExploitResult` dataclass (foundation for P6.2-P6.8).
  * **P6.2** (``ret2system``) — :class:`Ret2SystemX32` and
    :class:`Ret2SystemX64` (the first concrete primitive;
    ``ret2libc system('/bin/sh')`` with 64-bit stack-alignment
    gadget).
"""
from __future__ import annotations

from autopwn.primitives.base import (
    ExploitPrimitive as ExploitPrimitive,
    ExploitResult as ExploitResult,
)
from autopwn.primitives.ret2system import (
    Ret2SystemX32 as Ret2SystemX32,
    Ret2SystemX64 as Ret2SystemX64,
)

__all__: list[str] = [
    "ExploitPrimitive",
    "ExploitResult",
    "Ret2SystemX32",
    "Ret2SystemX64",
]
