"""Recon layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.1 / §5 for the BinaryInfo / LibcInfo contracts.

P4 modules in this layer (all follow the same pattern: one or more
public functions taking a ``Path`` and/or an ``ExploitContext``; the
function is a pure unit of work — no ``print_*``, no ``globals()``
writes outside ctx mutation; unit-testable in isolation under P9.1):

  * **P4.1** (``checksec``) — ``collect(program) -> BinaryInfo`` +
    ``display(info)`` table printer
  * **P4.2** (``libc``)    — ``detect(ctx, program) -> LibcInfo``
  * **P4.3** (``plt``)     — ``scan(ctx, program) -> dict[str, int]``,
    mutates ``ctx.has_*`` (P4's only ctx-mutating module)
  * **P4.4** (``rop``)     — ``find_x64(ctx, program) -> RopGadgetsX64``
    and ``find_x32(ctx, program) -> RopGadgetsX32``
  * **P4.5** (``bss``)     — ``find_bss(program, ...) -> list[BSSSymbol]``
    + ``BSSSymbol`` dataclass
  * **P4.6** (``asm``)     — ``vuln_func_name(program) -> list[str]``,
    ``asm_stack_overflow(program, bit) -> int``, and
    ``analyze_vulnerable_functions(program, bit) -> int``
  * **P4.7** (``frame``)   — ``extract_frame_context(program, bit)
    -> Optional[FrameContext]`` and ``compute_required_ret_count(
    lea_offset, frame_size) -> Literal[0, 1]`` (v4.0.5; replaces
    the v4.0.2b magic-number heuristic with a typed
    ``FrameContext`` capturing the caller's frame structure)
"""
from __future__ import annotations

from autopwn.recon.checksec import (
    collect as collect,
    display as display,
)
from autopwn.recon.libc import (
    detect as detect,
)
from autopwn.recon.plt import (
    scan as scan,
)
from autopwn.recon.rop import (
    find_x64 as find_x64,
    find_x32 as find_x32,
)
from autopwn.recon.bss import (
    BSSSymbol as BSSSymbol,
    find_bss as find_bss,
)
from autopwn.recon.asm import (
    vuln_func_name as vuln_func_name,
    asm_stack_overflow as asm_stack_overflow,
    analyze_vulnerable_functions as analyze_vulnerable_functions,
)
from autopwn.recon.frame import (
    FrameContext as FrameContext,
    compute_required_ret_count as compute_required_ret_count,
    extract_frame_context as extract_frame_context,
)

__all__: list[str] = [
    "collect",
    "display",
    "detect",
    "scan",
    "find_x64",
    "find_x32",
    "BSSSymbol",
    "find_bss",
    "vuln_func_name",
    "asm_stack_overflow",
    "analyze_vulnerable_functions",
    "FrameContext",
    "compute_required_ret_count",
    "extract_frame_context",
]
