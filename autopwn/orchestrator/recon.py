"""AutoPwn orchestrator — Phase 1 (recon).

Split out from the monolithic ``autopwn/orchestrator.py`` (P11.5,
2026-06-10) for line-count governance — the original was 361
lines, exceeding the §6.9 P8 spec target of <250.  See
``rebuild.md`` §6.12 P11.5 for the rationale.

The function signature, behaviour, and log markers are
**unchanged** — this is a pure file split, not a refactor.
The orchestrator package re-exports ``run_recon_phase`` from
here so that ``from autopwn.orchestrator import
run_recon_phase`` keeps working.
"""
from __future__ import annotations

from autopwn.context import ExploitContext
from autopwn.core.fs import set_permission
from autopwn.core.logging import (
    print_info,
    print_section_header,
    print_warning,
)
from autopwn.recon import checksec, libc, plt, rop


def run_recon_phase(ctx: ExploitContext) -> None:
    """Phase 1: populate the binary's static profile into ``ctx``.

    Sequence (matches v3.1 ``main()`` L3121-3163, with the v4.0
    typed modules substituted for the v3.1 free functions):

    1. ``BINARY ANALYSIS PHASE`` section header + chmod +755.
    2. ``checksec.collect(program)`` → overwrite ``ctx.binary``
       with the populated :class:`BinaryInfo`.  Then
       ``checksec.display(info)`` prints the security table.
    3. ``FUNCTION ANALYSIS`` section header + ``plt.scan(ctx,
       program)`` (mutates ``ctx.has_*`` in-place).
    4. ``ROP GADGET DISCOVERY`` section header + ``rop.find_x64``
       or ``rop.find_x32`` (per ``ctx.binary.bit``).

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.binary``,
            ``ctx.libc``, ``ctx.has_*`` and ``ctx.gadgets_*`` are
            populated by this function.

    Returns:
        ``None`` — mutates ``ctx`` in place.

    Raises:
        ``autopwn.core.runner.ToolError``: propagated from
            ``checksec.collect`` when the underlying ``checksec``
            binary exits non-zero.
    """
    program = ctx.binary.path

    if ctx.libc.path is not None:
        print_info(f"using custom libc: {ctx.libc.path}")
    else:
        print_info("detecting libc path automatically")
        ctx.libc = libc.detect(ctx, program)

    print_section_header("BINARY ANALYSIS PHASE")
    print_info("setting executable permissions")
    if not set_permission(program):
        print_warning("failed to set permissions, continuing anyway")

    print_info("collecting binary security information")
    ctx.binary = checksec.collect(program)
    checksec.display(ctx.binary)

    print_section_header("FUNCTION ANALYSIS")
    print_info("scanning PLT functions")
    plt.scan(ctx, program)

    print_section_header("ROP GADGET DISCOVERY")
    if ctx.binary.bit == 64:
        print_info("searching for x64 ROP gadgets")
        ctx.gadgets_x64 = rop.find_x64(ctx, program)
    else:
        print_info("searching for x32 ROP gadgets")
        ctx.gadgets_x32 = rop.find_x32(ctx, program)


__all__ = ["run_recon_phase"]
