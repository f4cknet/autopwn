"""Recon layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.1 / §5 for the BinaryInfo contract.

P4.1: ``checksec`` binary introspection — first module in this layer.
Future P4.x modules (``libc`` / ``plt`` / ``rop`` / ``bss`` / ``asm``)
will be added here; each follows the same pattern:

  * one or more public functions taking a ``Path`` and/or an
    ``ExploitContext``
  * the function is a pure unit of work (no ``print_*``, no
    ``globals()`` writes); printing is the caller's responsibility
    (P8 orchestrator)
  * unit-testable in isolation under P9.1's pytest harness
"""
from __future__ import annotations

from autopwn.recon.checksec import (
    collect as collect,
    display as display,
)

__all__: list[str] = [
    "collect",
    "display",
]
