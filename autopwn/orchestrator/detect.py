"""AutoPwn orchestrator — Phase 2 (detect).

Split out from the monolithic ``autopwn/orchestrator.py`` (P11.5,
2026-06-10) for line-count governance.  The function signature,
behaviour, and log markers are **unchanged** — this is a pure
file split, not a refactor.
"""
from __future__ import annotations

from autopwn.context import ExploitContext
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
from autopwn.detect import hints as detect_hints
from autopwn.detect import overflow as detect_overflow


def run_detect_phase(ctx: ExploitContext) -> None:
    """Phase 2: populate the binary's vulnerability profile into ``ctx``.

    Sequence (matches v3.1 ``main()`` L3165-3298, with the v4.0
    typed modules substituted):

    1. ``PADDING CALCULATION`` section header + overflow detection
       (skipped if ``-f/--fill`` was given).
    2. ``STRING ANALYSIS`` section header + ``check_binsh`` sets
       ``ctx.binsh_in_binary``.
    3. ``CANARY PROTECTION DETECTED`` section header (if canary):
       ``detect_format_string_vulnerability`` +
       ``leakage_canary_value`` + ``canary_fuzz``.
    4. ``EXPLOITATION PHASE`` section header (always).

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.padding``,
            ``ctx.binsh_in_binary`` and ``ctx.canary`` are populated
            by this function.

    Returns:
        ``None`` — mutates ``ctx`` in place.
    """
    program = ctx.binary.path

    _record_hints(ctx, detect_hints.collect_static_hints(ctx, program))

    print_section_header("PADDING CALCULATION")

    if ctx.padding:
        print_info(f"using manual padding: {ctx.padding} bytes")
    else:
        print_info("performing dynamic stack overflow testing")
        detected = detect_overflow.test_stack_overflow(ctx, program, ctx.binary.bit)
        if detected:
            from autopwn.recon import asm as recon_asm
            asm_padding = recon_asm.asm_stack_overflow(program, ctx.binary.bit)
            if asm_padding:
                ctx.padding = asm_padding
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

    if ctx.binary.stack_canary:
        print_section_header("CANARY PROTECTION DETECTED")
        print_warning("canary protection is enabled")
        print_info("testing for format string vulnerability to bypass canary")
        probe = detect_fmtstr.detect_format_string_vulnerability(ctx, program)
        _record_hints(
            ctx,
            detect_hints.collect_fmtstr_hints(
                ctx,
                program,
                fmtstr_vulnerable=probe.vulnerable,
            ),
        )
        if probe.vulnerable:
            print_success("format string vulnerability detected")
            same_session_plan = detect_canary.discover_same_session_canary_plan(
                ctx,
                program,
                ctx.binary.bit,
            )
            if same_session_plan is not None:
                print_success(
                    "same-session canary plan prepared: "
                    f"stack_index={same_session_plan.stack_index}, "
                    f"buffer_to_canary={same_session_plan.buffer_to_canary}, "
                    f"post_canary_padding={same_session_plan.post_canary_padding}"
                )
            else:
                print_info("attempting to leak canary value")
                leaks = detect_canary.leakage_canary_value(ctx, program)
                canary_info = detect_canary.canary_fuzz(
                    ctx,
                    program,
                    ctx.binary.bit,
                    leaks,
                    max_seconds=ctx.canary_max_seconds,
                )
                if canary_info is None:
                    print_warning("failed to leak canary value (will retry via candidates())")
                else:
                    print_success("canary value successfully leaked")
            # v4.0.2c1: when fmtstr is detected, populate the
            # primitive's input fields so FmtstrX{32,64}LocalStrategy
            # can build_payload (was previously gated on
            # ``ctx.padding == 0`` only, which excluded canary+fmtstr
            # binaries like Challenge/fmtstr1).
            try:
                ctx.fmtstr_offset = detect_fmtstr.find_offset(ctx, program)
                from autopwn.recon import bss as recon_bss
                bss_syms = recon_bss.find_bss(
                    program, min_size=2, name_filter=lambda n: "_" not in n
                )
                if bss_syms:
                    ctx.fmtstr_buf = bss_syms[0].address
                    print_success(
                        f"fmtstr inputs populated: offset={ctx.fmtstr_offset}, "
                        f"buf=0x{ctx.fmtstr_buf:x}"
                    )
            except Exception as e:
                print_warning(f"fmtstr offset/buf lookup failed: {e}")

    print_section_header("EXPLOITATION PHASE")
    print_info("initializing exploitation attempts")


def _record_hints(ctx: ExploitContext, hints) -> None:
    """Persist and log newly discovered exploit hints."""
    new_hints = []
    before = len(ctx.exploit_hints)
    for hint in hints:
        existing = ctx.add_exploit_hint(
            hint.kind,
            hint.score_delta,
            hint.reason,
        )
        if len(ctx.exploit_hints) > before + len(new_hints):
            new_hints.append(existing)

    if not new_hints:
        return

    print_section_header("EXPLOIT HINTS")
    for hint in new_hints:
        delta = f"{hint.score_delta:+d}"
        print_info(f"{hint.kind} ({delta}) — {hint.reason}")


__all__ = ["run_detect_phase"]
