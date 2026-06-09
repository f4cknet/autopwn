"""AutoPwn orchestrator — recon + detect + strategy phase scheduler (P8.1 + P8.2).

Replaces the v3.1 monolith's ``main()`` decision tree
(``autopwn/_legacy.py`` L3016-3479) with a phase-separated, strategy-driven
exploitation flow.  Per ``rebuild.md`` §6.9 P8.1 / P8.2 + ``refactor.md`` §3.2.2
+ §11 R1 mitigation: **the orchestrator has no specific strategy names**;
strategy selection is driven entirely by :func:`autopwn.exp.registry.candidates`
which sorts by :attr:`ExploitStrategy.priority` (see ``rebuild.md`` §11
附录 A, Owner-signed 2026-06-08).

Public API
----------
* :func:`run` — top-level entry: takes a fully populated
  :class:`ExploitContext` (built by ``cli.py`` from argparse args),
  runs the three phases, returns ``0`` on successful exploitation
  and ``1`` on failure (no strategy succeeded).
* :func:`run_recon_phase` — Phase 1: ``recon/`` modules populate
  ``ctx.binary`` / ``ctx.libc`` / ``ctx.has_*`` / ``ctx.gadgets_*``.
* :func:`run_detect_phase` — Phase 2: ``detect/`` modules populate
  ``ctx.binsh_in_binary`` / ``ctx.canary`` / ``ctx.padding`` —
  the binary's vulnerability profile.
* :func:`run_strategy_phase` — Phase 3: iterate
  :func:`autopwn.exp.registry.candidates` (priority-sorted) and
  call ``strat.run(ctx)`` on each; first ``True`` wins.
* :func:`_print_strategy_log` — internal helper that emits the
  per-strategy "trying <name>" log line, **used by the integration
  tests** to assert strategy-ordering behaviour (P9.3).

Design notes
------------
* **Phase separation matches the refactor.md §3.2.1 dependency graph**:
  Phase 1 depends only on ``recon/`` (read-only binary probes);
  Phase 2 depends only on ``detect/`` (read+write ctx);
  Phase 3 depends only on ``exp/`` (read ctx, spawn exploit).  Each
  phase is unit-testable in isolation under P9.1/P9.2.
* **No ``sys.exit(0)`` in the orchestrator**: ``run()`` returns an
  int (0 or 1) and lets ``cli.py`` decide the process exit code.
  The legacy ``main()`` had 43 ``sys.exit(0)`` sites — they all
  collapse to ``return 0`` (or fall through to ``return 1``) here.
  Enforced by ``refactor.md`` §11 R1 + §6.8 Reviewer checklist.
* **Log marker preservation** (``rebuild.md`` §6.9 P8.4 acceptance):
  the orchestrator emits the **same section header + info lines**
  that v3.1's main() does (BINARY ANALYSIS PHASE, FUNCTION ANALYSIS,
  ROP GADGET DISCOVERY, PADDING CALCULATION, STRING ANALYSIS,
  CANARY PROTECTION DETECTED, EXPLOITATION PHASE).  These are the
  19 key behaviour markers the v3.1 ↔ v4.0 compare script
  (``tools/verify_v31_v40.py``) greps for.  v3.1-style log output
  is preserved bit-for-bit (modulo timestamp differences).
* **Exception isolation**: Phase 3 wraps each ``strat.run(ctx)`` in
  a ``try/except`` that logs the failure and continues to the next
  candidate.  This matches the v3.1 behaviour of "strategy failed;
  try the next one" without aborting the whole run.  Phases 1 and
  2 are **not** wrapped — a recon/detect failure (e.g. missing
  checksec tool) is a real error that should propagate.
* **Canary dispatch** mirrors v3.1's L3217-3297 branch:
  ``if ctx.binary.stack_canary:`` triggers ``canary.leak`` (format-
  string probe + canary fuzz) **before** the overflow path.  This
  is necessary because P7.10's canary strategies set
  ``requires_canary=True`` and would otherwise be filtered out by
  ``candidates()`` (their ``matches()`` returns False when
  ``ctx.canary is None``).
* **No global state writes**: the orchestrator reads and writes
  only ``ctx`` fields.  No ``globals()`` injection, no
  ``exploit_info[...] = ...`` writes.  P8.5 (✅ 2026-06-09) deleted
  the P2.3/P2.4 ``_compat`` bridge entirely; success-path writes
  go through ``autopwn.report.record_success(ctx, info)`` directly.
"""
from __future__ import annotations

from typing import List

from autopwn.context import ExploitContext
from autopwn.core.fs import set_permission
from autopwn.core.logging import (
    print_info,
    print_section_header,
    print_success,
    print_warning,
)
from autopwn.core.runner import run_objdump_disasm
from autopwn.detect import binsh as detect_binsh
from autopwn.detect import canary as detect_canary
from autopwn.detect import fmtstr as detect_fmtstr
from autopwn.detect import overflow as detect_overflow
from autopwn.exp.registry import candidates
from autopwn.exp import strategies as _strategies  # noqa: F401  -- import to trigger @register
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

    ``ctx.libc`` is set by :func:`_detect_libc` (called inline below
    to keep the libc detection message + ``print_debug`` between
    the banner and the BINARY ANALYSIS PHASE header, matching v3.1
    L3101-3118 byte-for-byte).

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.binary``,
            ``ctx.libc``, ``ctx.has_*`` and ``ctx.gadgets_*`` are
            populated by this function.  ``ctx.binary.path`` and
            ``ctx.padding`` (from ``-f``) are read; the placeholder
            ``BinaryInfo`` from ``from_args`` is **overwritten**.

    Returns:
        ``None`` — mutates ``ctx`` in place.

    Raises:
        ``autopwn.core.runner.ToolError``: propagated from
            ``checksec.collect`` when the underlying ``checksec``
            binary exits non-zero.  (v3.1 silently swallowed this;
            v4.0 propagates per the refactor.md §11 R5 mitigation.)
    """
    program = ctx.binary.path

    # v3.1 L3111-3118: libc path detection (with -libc override) is
    # surfaced *before* the BINARY ANALYSIS PHASE header.  The new
    # ``recon.libc.detect`` already handles the override; we only
    # need to emit the user-facing messages here.
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


def run_detect_phase(ctx: ExploitContext) -> None:
    """Phase 2: populate the binary's vulnerability profile into ``ctx``.

    Sequence (matches v3.1 ``main()`` L3165-3298, with the v4.0
    typed modules substituted):

    1. ``PADDING CALCULATION`` section header + overflow detection
       (skipped if ``-f/--fill`` was given — same as v3.1 L3168).
       On success, runs ``asm_stack_overflow`` adjustment +
       ``vuln_func_name`` + the per-function disassembly dump
       (v3.1 L3175-3202).  On failure, runs
       ``analyze_vulnerable_functions`` (v3.1 L3303-3308).
    2. ``STRING ANALYSIS`` section header + ``check_binsh`` sets
       ``ctx.binsh_in_binary`` (v3.1 L3210-3214).
    3. ``CANARY PROTECTION DETECTED`` section header (if canary):
       ``detect_format_string_vulnerability`` +
       ``leakage_canary_value`` + ``canary_fuzz`` (v3.1 L3216-3297).
    4. ``EXPLOITATION PHASE`` section header (always, v3.1 L3312).

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.padding``,
            ``ctx.binsh_in_binary`` and ``ctx.canary`` are populated
            by this function.  ``ctx.binary.stack_canary`` and
            ``ctx.padding`` are read.

    Returns:
        ``None`` — mutates ``ctx`` in place.

    Note:
        The padding branch is a **two-step** flow that mirrors v3.1
        L3165-3209 exactly.  The v3.1 logic is convoluted (manual
        ``-f`` override first; then dynamic test, then asm
        adjustment, then vuln_func_name display, then fallback to
        static analysis).  This function preserves that
        structure — the §2.6 baseline comparison requires it.
    """
    program = ctx.binary.path

    print_section_header("PADDING CALCULATION")

    # v3.1 L3168-3209: -f override → dynamic test → asm adjust →
    # vuln_func_name dump → static fallback.  Each branch's side
    # effects (setting ctx.padding, printing the vuln_func tables)
    # are preserved.
    if ctx.padding:
        # -f/--fill was given; ctx.padding was set in from_args
        print_info(f"using manual padding: {ctx.padding} bytes")
    else:
        print_info("performing dynamic stack overflow testing")
        detected = detect_overflow.test_stack_overflow(ctx, program, ctx.binary.bit)
        if detected:
            # v3.1 L3176-3178: re-adjust with asm-based detection.
            # asm_stack_overflow lives in the recon layer (per the
            # file mapping in rebuild.md §11 附录 B).
            from autopwn.recon import asm as recon_asm
            asm_padding = recon_asm.asm_stack_overflow(program, ctx.binary.bit)
            if asm_padding:
                ctx.padding = asm_padding
            # v3.1 L3180-3202: vuln_func_name + per-function
            # disassembly dump (preserved for log marker parity).
            results = recon_asm.vuln_func_name(program)
            if results:
                print_section_header("VULNERABLE FUNCTIONS IDENTIFIED")
                for func_name in results:
                    print_success(f"vulnerable function: {func_name}")
                print_section_header("ASSEMBLY CODE ANALYSIS")
                objdump_out = run_objdump_disasm(program, intel=True)
                lines = objdump_out.splitlines()
                for func_name in results:
                    print_info(f"disassembling function: {func_name}")
                    for i, line in enumerate(lines):
                        if func_name in line:
                            for chunk in [line] + lines[i + 1:i + 21]:
                                print(chunk)
                            break
        else:
            print_warning("no stack overflow vulnerability detected through dynamic testing")
            from autopwn.recon import asm as recon_asm
            static_padding = recon_asm.analyze_vulnerable_functions(program, ctx.binary.bit)
            if static_padding:
                ctx.padding = static_padding
                print_success(f"static analysis found padding: {ctx.padding} bytes")

    print_section_header("STRING ANALYSIS")
    print_info("searching for /bin/sh string in binary")
    detect_binsh.check_binsh(ctx, program)

    # v3.1 L3217-3297: canary branch
    if ctx.binary.stack_canary:
        print_section_header("CANARY PROTECTION DETECTED")
        print_warning("canary protection is enabled")
        print_info("testing for format string vulnerability to bypass canary")
        probe = detect_fmtstr.detect_format_string_vulnerability(ctx, program)
        if probe.vulnerable:
            print_success("format string vulnerability detected")
            print_info("attempting to leak canary value")
            leaks = detect_canary.leakage_canary_value(ctx, program)
            canary_info = detect_canary.canary_fuzz(ctx, program, ctx.binary.bit, leaks)
            if canary_info is None:
                print_warning("failed to leak canary value (will retry via candidates())")
            else:
                print_success("canary value successfully leaked")

    print_section_header("EXPLOITATION PHASE")
    print_info("initializing exploitation attempts")


def run_strategy_phase(ctx: ExploitContext) -> int:
    """Phase 3: iterate ``candidates(ctx)`` and try each in priority order.

    The first strategy whose :meth:`ExploitStrategy.run` returns
    ``True`` wins; this function returns ``0`` immediately.  If
    every candidate returns ``False`` (or raises), returns ``1``
    to signal "no strategy matched".

    Each strategy invocation is wrapped in a ``try/except`` that
    logs the failure and continues — a single strategy crash
    must not abort the whole run (this matches v3.1's behaviour
    of "strategy failed; try the next one").  Strategies MUST NOT
    call :func:`sys.exit` (per §6.8 Reviewer checklist); the
    success-path is signalled by returning ``True``.

    Args:
        ctx: a fully populated :class:`ExploitContext` (post
            recon + detect phases).

    Returns:
        ``0`` if any strategy succeeded; ``1`` otherwise.

    Side effects:
        * Calls :func:`autopwn.exp.registry.candidates` to get a
          priority-sorted list of matching strategies.
        * Logs one ``"→ trying <name>"`` info line per candidate
          (per P8.2 spec example at ``rebuild.md`` §6.9).
        * On strategy exception, logs a warning and continues.
    """
    match_list: List = candidates(ctx)
    n = len(match_list)
    print_info(f"candidates: {n} strategies matched this context")
    for strat in match_list:
        _print_strategy_log(ctx, strat)
        try:
            if strat.run(ctx):
                return 0
        except Exception as exc:  # noqa: BLE001 — intentional, see docstring
            print_warning(f"{strat.name} failed: {exc}")
    if n == 0:
        print_warning("no exploitation strategy matched this context")
    else:
        print_warning(f"all {n} candidate strategies failed")
    return 1


def _print_strategy_log(ctx: ExploitContext, strat) -> None:
    """Emit the per-strategy "trying <name>" info line.

    Format mirrors the v3.1 strategy call sites (no explicit
    log line; the legacy code went straight into the strategy
    function which printed its own header).  P7.3-P7.10 strategy
    implementations print their own "EXPLOITATION:" line on
    entry; the orchestrator's contribution is the
    "→ trying <name>" line that precedes it.

    Args:
        ctx: the run's :class:`ExploitContext` (read-only).
        strat: an :class:`ExploitStrategy` instance.
    """
    print_info(f"→ trying {strat.name}")


def run(ctx: ExploitContext) -> int:
    """Top-level orchestrator entry point.

    Runs the three phases in order:

    1. :func:`run_recon_phase` — populate the binary's static profile.
    2. :func:`run_detect_phase` — populate the binary's vulnerability profile.
    3. :func:`run_strategy_phase` — try each priority-sorted candidate.

    Returns the strategy-phase exit code (``0`` on success, ``1``
    on failure).  Does NOT call :func:`sys.exit` — the caller
    (``cli.py``) decides the process exit code (per
    ``refactor.md`` §11 R1 + §6.9 P8.3 spec).

    Args:
        ctx: a fully populated :class:`ExploitContext` (typically
            built by ``ExploitContext.from_args(args)`` in cli.py).

    Returns:
        ``0`` on successful exploitation; ``1`` otherwise.
    """
    run_recon_phase(ctx)
    run_detect_phase(ctx)
    return run_strategy_phase(ctx)


__all__ = [
    "run",
    "run_recon_phase",
    "run_detect_phase",
    "run_strategy_phase",
]
