"""Recon layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.1 / §5 for the BinaryInfo / LibcInfo contracts.

P4 modules in this layer (all follow the same pattern: one or more
public functions taking a ``Path`` and/or an ``ExploitContext``; the
function is a pure unit of work — no ``print_*``, no ``globals()``
writes; unit-testable in isolation under P9.1's pytest harness):

  * **P4.1** (``checksec``) — ``collect(program) -> BinaryInfo`` +
    ``display(info)`` table printer
  * **P4.2** (``libc``)    — ``detect(ctx, program) -> LibcInfo``,
    consolidates v3.1's two duplicate ``detect_libc`` / ``ldd_libc``
    functions into a single typed entry point
"""
from __future__ import annotations

from autopwn.recon.checksec import (
    collect as collect,
    display as display,
)
from autopwn.recon.libc import (
    detect as detect,
)

__all__: list[str] = [
    "collect",
    "display",
    "detect",
]
