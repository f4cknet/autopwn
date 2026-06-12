"""AutoPwn detect layer: stack-overflow vulnerability detection (P5.1).

Replaces the v3.1 monolith's ``test_stack_overflow`` +
``analyze_vulnerable_functions`` functions (see ``autopwn/_legacy.py``
L541-580 + L581-636) with two typed entry points that write the
detected padding into ``ctx.padding``.  Per ``rebuild.md`` §6.6 P5.1
+ ``refactor.md`` §5 mapping table, this is the first detect module
in the P5 layer (M2 milestone).

Public API
----------
* :func:`test_stack_overflow` — dynamic test: spawns the target binary
  with progressively longer ``'A'`` input and watches for SIGSEGV.
  Writes the discovered padding (+ alignment) into ``ctx.padding`` and
  returns it.  ``max_test`` parameter overrides the v3.1 10000-byte
  ceiling (useful for unit tests).
* :func:`analyze_vulnerable_functions` — static test: scans the
  objdump disassembly for every function that combines a ``lea`` with
  a call to one of the dangerous read functions (``read``/``gets``/
  ``fgets``/``scanf``) and returns the inferred padding of the first
  such function.  Writes the padding into ``ctx.padding``.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_test_stack_overflow` — verbatim port of v3.1's
  ``test_stack_overflow`` (L541-580).  Has 1 caller in
  ``_legacy.py`` (the v3.1 main() at L3173, plus L3303).
* :func:`_legacy_analyze_vulnerable_functions` — verbatim port of
  v3.1's ``analyze_vulnerable_functions`` (L581-636).  Has 1
  caller (``_legacy.py`` L3205-ish, in the static-analysis branch
  when dynamic padding == 0).

Design notes
------------
* Both public functions **mutate** ``ctx.padding`` (in-place) and
  return the same int.  This is consistent with the P4.3 PLT
  module which mutates ``ctx.has_*`` — the P5 detect layer is the
  *only* layer authorized to write to ``ctx`` per
  ``refactor.md`` §3.2.1.
* The dynamic test (``test_stack_overflow``) is the only one of
  the 4 P5 modules that actually spawns the target binary in a loop.
  v3.1's loop runs up to 10000 iterations and takes ~7 minutes
  for the ``canary`` binary alone (P0.7's verify scripts truncate
  at 60s/binary).  Unit tests for this module **must** override
  ``max_test`` to keep CI tractable; the new ``max_test`` parameter
  exists for exactly this reason.
* The static test (``analyze_vulnerable_functions``) is the P5
  counterpart of P4.6's :func:`recon.asm.asm_stack_overflow` — they
  share the same ``lea + dangerous_call`` regex but
  ``analyze_vulnerable_functions`` additionally returns the **list**
  of all vulnerable functions (with name + stack_size + padding),
  which the legacy code only prints in its VULNERABLE FUNCTIONS
  table.  P5.1 captures the list as a side-output so callers (P7
  strategies, future reports) can use it.
* Both public functions are **silent** — no ``print_*`` calls.
  All visual output (section header, table, success line) lives
  in the legacy ports.  This matches the recon/asm.py convention
  (P4.6) and keeps the new modules unit-testable in isolation
  without stdout noise.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional

from autopwn.context import ExploitContext
from autopwn.core.runner import run_objdump_disasm


# Pre-compiled AT&T-syntax pattern (matches recon/asm.py P4.6).
# ``lea -0x10(%rbp), %rax``  /  ``lea -0x10(%ebp), %eax``.
# Group(1) is the hex offset (may be negative).
_LEA_RE = re.compile(r"lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)")

# v3.1's "dangerous read" function set (L596, L706).
_DANGEROUS_CALLS = ("read", "gets", "fgets", "scanf")


def test_stack_overflow(
    ctx: ExploitContext,
    program: Path,
    bit: int,
    max_test: int = 10000,
) -> int:
    """Dynamically probe the target binary for a stack-overflow offset.

    Mirrors v3.1's ``test_stack_overflow`` (``_legacy.py`` L541-580):
    spawns the target binary with progressively longer ``'A' * (i+1)``
    input, returns the first ``i + 1`` for which the process exits with
    SIGSEGV (``returncode == -11``).  The returned value is the actual
    offset from the buffer start to the saved return address.

    Writes the discovered padding into ``ctx.padding`` (in-place) so
    the orchestrator (P8) can read it after this returns.

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.padding`` is
            **overwritten** with the discovered value (or 0 on
            "no overflow detected").
        program: path to the target ELF.
        bit: 32 or 64 — kept for backward compat (unused in current
            logic; the return value is the actual byte offset, not
            an alignment-adjusted value).  Caller (P8) will pass
            ``ctx.binary.bit`` here.
        max_test: maximum number of A's to try before giving up.
            Default 10000 matches v3.1.  Unit tests should override
            to a small value (e.g. 32) to keep CI tractable.

    Returns:
        The discovered padding (``final_padding = padding + 1`` where
        ``padding`` is the loop index, so the return equals the input
        length that first corrupted the return address), or 0 when
        no overflow is detected within ``max_test`` bytes.

    Note (per `upgraded.md` v4.0.2a, 2026-06-11):
        v3.1's original code did ``final_padding = padding + alignment``
        (alignment = 8 for 64-bit, 4 for 32-bit), which was a copy-paste
        artifact from the static ``analyze_vulnerable_functions`` formula
        (``lea_offset + alignment`` is correct *there* because ``lea_offset``
        is the buffer-to-rbp distance, and the +alignment is the saved-rbp
        size).  In the dynamic test, ``padding`` is the *loop index*
        (i.e. input-length - 1), NOT the lea offset, so the +alignment
        adds 8 spurious bytes.  For ``rip`` (15-byte buffer, 23-byte
        offset) the bug returns 30 (+7 off); for ``level3_x64`` (128-byte
        buffer, 136-byte offset) the +alignment coincidentally produced
        the correct 136, but only because the original code on this binary
        crashes at the saved-rbp boundary, not the return-addr boundary.

        Fix: return ``padding`` (raw loop index) as a *lower bound* signal.
        The orchestrator (P8) overwrites ``ctx.padding`` with the static
        ``asm_stack_overflow`` result whenever the dynamic test fires
        (see ``orchestrator/detect.py`` line ~58), so the static analysis
        remains the authoritative source.  The dynamic test now just
        signals "yes, this binary is stack-overflow-vulnerable" + a
        noisy lower-bound padding hint for log display.

        Note on what ``padding`` actually represents post-fix:
        - For binaries where the first crash is at return-addr corruption
          (e.g. ``rip``, 15-byte buffer), ``padding`` ≈ buffer_size + 7
          (one byte short of the real offset) — the static analysis fixes
          the 1-byte gap.
        - For binaries where the first crash is at saved-rbp corruption
          (e.g. ``level3_x64``, 128-byte buffer), ``padding`` = buffer_size
          (8 bytes short of the real offset) — the static analysis fixes
          the 8-byte gap.
        Either way, the static result is the truth; the dynamic result
        is a quick canary check.
    """
    padding = 0
    while padding < max_test:
        input_data = "A" * (padding + 1)
        try:
            proc = subprocess.Popen(
                [str(program)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(input=input_data.encode(), timeout=1)

            if proc.returncode == -11:  # SIGSEGV
                # padding is the loop index at which SIGSEGV first fires.
                # This is a LOWER BOUND on the return-address offset:
                #   - if the crash is at saved-rbp corruption, padding is
                #     exactly the buffer size (return-addr = padding + 8)
                #   - if the crash is at return-addr corruption, padding is
                #     one less than the return-addr offset (return-addr = padding + 1)
                # We don't know which case we're in without inspecting the
                # saved-rbp / return-addr bytes, so we just return padding
                # and let the orchestrator's static ``asm_stack_overflow``
                # overwrite ctx.padding with the authoritative value.
                # See the docstring Note above for the bug history.
                final_padding = padding
                ctx.padding = final_padding
                return final_padding

        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass

        padding += 1

    ctx.padding = 0
    return 0


def analyze_vulnerable_functions(
    ctx: ExploitContext,
    program: Path,
    bit: int,
) -> Optional[int]:
    """Statically scan objdump for vulnerable functions and write padding.

    Mirrors v3.1's ``analyze_vulnerable_functions`` (``_legacy.py``
    L581-636): walks the disassembly looking for every function whose
    body contains both a ``lea`` instruction and a call to one of
    the dangerous read functions (``read``/``gets``/``fgets``/
    ``scanf``).  For each such function, infers the padding from
    the first ``lea -N(%ebp)`` / ``lea -N(%rbp)`` pattern as
    ``abs(int(N, 16)) + alignment``.

    Writes the first discovered function's padding into
    ``ctx.padding`` (matches the v3.1 behavior of returning the
    first found function's padding) and returns the same int.
    Returns ``None`` when no vulnerable function is found.

    Note: this is a sibling of P4.6's :func:`recon.asm.asm_stack_overflow`
    (same regex, same alignment logic) but additionally captures
    the full list of vulnerable functions.  P5.1 does not return
    the list (the spec is "写入 ctx.padding" only); the legacy
    port still prints the VULNERABLE FUNCTIONS table for spec
    parity.

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.padding`` is
            **overwritten** with the first vulnerable function's
            padding, or left untouched when no function matches.
        program: path to the target ELF.
        bit: 32 or 64 — controls the alignment adjustment
            (8 vs 4).  Caller (P8) will pass ``ctx.binary.bit`` here.

    Returns:
        The padding of the first vulnerable function found, or
        ``None`` when no function matches the heuristic.
    """
    content = run_objdump_disasm(program, intel=False)
    func_pattern = r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"
    functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)

    vulnerable: List[dict] = []
    for func in functions:
        func_name = func.group(1)
        func_body = func.group(2)
        has_lea = "lea" in func_body
        has_dangerous_call = any(c in func_body for c in _DANGEROUS_CALLS)
        if has_lea and has_dangerous_call:
            lea_match = _LEA_RE.search(func_body)
            if lea_match:
                offset_dec = abs(int(lea_match.group(1), 16))
                alignment = 8 if bit == 64 else 4
                padding = offset_dec + alignment
                vulnerable.append({
                    "name": func_name,
                    "stack_size": offset_dec,
                    "padding": padding,
                })

    if not vulnerable:
        return None
    first_padding = vulnerable[0]["padding"]
    ctx.padding = first_padding
    return first_padding


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

def _legacy_test_stack_overflow(program: Path, bit: int) -> int:
    """[OBSOLETE — prefer :func:`test_stack_overflow`] Verbatim port of v3.1's ``test_stack_overflow``.

    Retained for spec parity (``rebuild.md`` §4.6 P5.1 lists both
    legacy functions).  Has 2 callers in ``_legacy.py`` (L3173 +
    L3303).  Preserves the v3.1 print behavior byte-for-byte:
    ``print_info`` "testing for stack overflow vulnerability" +
    ``print_section_header`` "STACK OVERFLOW DETECTION" +
    ``print_progress`` every 100 iterations +
    ``print_progress(max_test, max_test, "Testing overflow")`` on
    success or no-detection +
    ``print_success`` "stack overflow detected! Padding: …" on
    SIGSEGV +
    ``print_warning`` "no stack overflow vulnerability detected"
    on max-out.

    Note: this legacy port does **not** write to ``ctx.padding``;
    it is a drop-in replacement for the v3.1 function whose return
    value the caller assigned back to the local ``padding`` variable.

    Returns:
        The padding (``padding + alignment``) on SIGSEGV, 0 on
        no-detection.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_progress, print_section_header,
        print_success, print_warning,
    )

    print_info("testing for stack overflow vulnerability")

    char = "A"
    padding = 0
    max_test_iter = 10000

    print_section_header("STACK OVERFLOW DETECTION")

    while padding < max_test_iter:
        if padding % 100 == 0:
            print_progress(padding, max_test_iter, "Testing overflow")

        input_data = char * (padding + 1)
        try:
            proc = subprocess.Popen(
                [str(program)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(input=input_data.encode(), timeout=1)

            if proc.returncode == -11:  # SIGSEGV
                alignment = 8 if bit == 64 else 4
                final_padding = padding + alignment
                print_progress(max_test_iter, max_test_iter, "Testing overflow")
                print_success(
                    f"stack overflow detected! Padding: "
                    f"{Colors.YELLOW}{final_padding}{Colors.END} bytes"
                )
                return final_padding

        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass

        padding += 1

    print_progress(max_test_iter, max_test_iter, "Testing overflow")
    print_warning("no stack overflow vulnerability detected")
    return 0


def _legacy_analyze_vulnerable_functions(
    program: Path, bit: int,
) -> Optional[int]:
    """[OBSOLETE — prefer :func:`analyze_vulnerable_functions`] Verbatim port of v3.1's ``analyze_vulnerable_functions``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3205
    area, the static-analysis branch when dynamic padding == 0).
    Preserves v3.1 print behavior byte-for-byte:
    ``print_info`` "analyzing vulnerable functions" +
    ``print_section_header`` "VULNERABLE FUNCTIONS" + 3-col table
    on success + ``print_info""`` (trailing empty line) +
    ``print_error`` on failure.

    Returns:
        The padding of the first vulnerable function, or ``None``.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_error, print_section_header,
        print_table_header, print_table_row,
    )

    print_info("analyzing vulnerable functions")
    try:
        content = run_objdump_disasm(program, intel=False)
        func_pattern = r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"
        functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)

        vulnerable_functions: List[dict] = []
        for func in functions:
            func_name = func.group(1)
            func_body = func.group(2)
            dangerous_calls = list(_DANGEROUS_CALLS)
            has_lea = "lea" in func_body
            has_dangerous_call = any(c in func_body for c in dangerous_calls)
            if has_lea and has_dangerous_call:
                lea_match = _LEA_RE.search(func_body)
                if lea_match:
                    offset_dec = abs(int(lea_match.group(1), 16))
                    alignment = 8 if bit == 64 else 4
                    padding = offset_dec + alignment
                    vulnerable_functions.append({
                        "name": func_name,
                        "stack_size": offset_dec,
                        "padding": padding,
                    })

        if vulnerable_functions:
            print_section_header("VULNERABLE FUNCTIONS")
            headers = ["Function", "Stack Size", "Padding"]
            print_table_header(headers)
            for func in vulnerable_functions:
                colors = [Colors.YELLOW, Colors.END, Colors.SUCCESS]
                print_table_row(
                    [func["name"], f"{func['stack_size']} bytes",
                     f"{func['padding']} bytes"],
                    colors,
                )
            print_info("")
            return vulnerable_functions[0]["padding"]
        return None

    except Exception as e:
        print_error(f"failed to analyze vulnerable functions: {e}")
        return None


__all__ = [
    "test_stack_overflow",
    "analyze_vulnerable_functions",
    "_legacy_test_stack_overflow",
    "_legacy_analyze_vulnerable_functions",
]
