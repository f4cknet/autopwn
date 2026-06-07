"""Primitives layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.2 for the primitives contract.

P6 modules in this layer (all follow the same pattern: one
or more subclasses of :class:`ExploitPrimitive`, each implementing
``build_payload(ctx) -> bytes`` as a pure function — no
subprocess, no file I/O, no globals writes):

  * **P6.1** (``base``) — :class:`ExploitPrimitive` ABC +
    :class:`ExploitResult` dataclass (foundation for P6.2-P6.8).
"""
from __future__ import annotations

from autopwn.primitives.base import (
    ExploitPrimitive as ExploitPrimitive,
    ExploitResult as ExploitResult,
)

__all__: list[str] = [
    "ExploitPrimitive",
    "ExploitResult",
]
