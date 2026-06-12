r"""AutoPwn recon layer: assembly-based vulnerability analysis (P4.6).

Replaces the v3.1 monolith's ``vuln_func_name`` + ``asm_stack_overflow``
+ ``analyze_vulnerable_functions`` functions (see ``autopwn/_legacy.py``
L581-674 + L676-719) with three typed entry points.  Per
``rebuild.md`` §6.5 P4.6 + ``refactor.md`` §5 mapping table, this is
the sixth recon module in the P4 layer (M2 milestone).

Public API
----------
* :func:`vuln_func_name` — pure; returns the list of function names
  whose assembly contains a ``lea`` instruction AND a call to one
  of the dangerous read functions (``read``/``gets``/``fgets``/
  ``scanf``).
* :func:`asm_stack_overflow` — pure; returns the dynamic padding
  adjustment (``offset_dec + 4`` for 32-bit or ``+ 8`` for 64-bit)
  inferred from the first ``lea -N(%ebp)`` / ``lea -N(%rbp)``
  pattern in a vulnerable function's assembly.
* :func:`analyze_vulnerable_functions` — pure; same heuristic as
  :func:`asm_stack_overflow` but returns the padding of the **first**
  vulnerable function in iteration order (and emits a "VULNERABLE
  FUNCTIONS" table when run via the legacy port).  P4.6 includes
  this third function for spec completeness — ``rebuild.md`` §4.5
  P4.6 mentions 2 source functions but the third is a small
  neighbor in the same module; documenting it here avoids a future
  P5+ PR having to touch ``_legacy.py`` again.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_vuln_func_name` — verbatim port of v3.1's
  ``vuln_func_name`` (L638-674).  Has 2 callers
  (``_legacy.py`` L3170, L3297).
* :func:`_legacy_asm_stack_overflow` — verbatim port of v3.1's
  ``asm_stack_overflow`` (L676-719).  Has 2 callers
  (``_legacy.py`` L3166, L3295).
* :func:`_legacy_analyze_vulnerable_functions` — verbatim port of
  v3.1's ``analyze_vulnerable_functions`` (L581-636).  Has 2
  callers (``_legacy.py`` L3195 + (would-be) 1 more).

Design notes
------------
* All 3 public functions read the binary's disassembly via
  :func:`core.runner.run_objdump_disasm(program, intel=False)` —
  **AT&T syntax** is required because the regexes (``lea -0x10(%rbp)``
  form) are AT&T-specific.  P1.5's runner wrapper accepts an
  ``intel=True/False`` flag (see P1.5 commit `7a6cbe0` "踩坑 #3"
  in ``rebuild.md`` §6.2 P1.5).
* The ``int 0x80`` / ``call read@plt`` regexes use ``\s+`` /
  ``.*`` flexibly so both AT&T (``call.*read@plt``) and intel
  (``call read@plt``) match — but in practice the legacy code only
  tested AT&T, so the regexes are AT&T-formal.
* All 3 functions are **pure** (no ``print_*``, no ``globals()``,
  no file I/O beyond the objdump subprocess).  Returns: list /
  optional int / optional int respectively.  Unit-testable in
  isolation.
* ``analyze_vulnerable_functions`` and ``asm_stack_overflow`` look
  almost identical but the legacy code keeps them as 2 separate
  functions with subtly different output paths (one prints a
  VULNERABLE FUNCTIONS table; the other prints a single "stack
  size" success line).  P4.6 preserves both for parity.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from autopwn.core.runner import run_objdump_disasm


# Pre-compiled AT&T-syntax patterns (v3.1 used raw strings inline;
# module-level compile is the P2.1 / P3.1 / P4.1+ pattern for hot
# regexes that fire on every call).

# ``lea -0x10(%rbp), %rax``  /  ``lea -0x10(%ebp), %eax``
# Group(1) is the hex offset (may be negative, hence the optional
# minus sign).  v3.1 L607 / L700 use the same pattern.
_LEA_RE = re.compile(r"lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)")

# ``call.*read@plt`` — matches both AT&T and intel-style call sites
_DANGEROUS_CALLS = ("read", "gets", "fgets", "scanf")

# v4.0.2c3: pattern for finding a dangerous call site in func body.
# Loose match — accepts ``call <addr> <name>@plt`` (AT&T objdump) or
# ``call <name>`` (intel).  Word-boundary-ish: the dangerous name
# must be followed by a non-letter (so "getegid" doesn't match "gets").
_DANGEROUS_CALL_RE_TPL = r"call\s+[\w<>, ]*?{name}(?![A-Za-z0-9_])"


def _extract_buffer_lea_padding(func_body: str, bit: int) -> Optional[int]:
    """v4.0.2c3: find the buffer-setup lea in a function body.

    Walks the disassembly to find:
      1. The FIRST dangerous call (``read``/``gets``/``fgets``/``scanf``)
      2. The LAST ``lea -N(%ebp/%rbp)`` BEFORE that call

    The second pattern is the buffer setup; the lea in the function
    epilogue (``lea -0x8(%ebp),%esp`` to restore esp) is AFTER the
    dangerous call and is correctly excluded.

    Returns the inferred padding (``abs(N) + 8`` for x64, + 4 for
    x32) or ``None`` when no buffer-setup lea was found before a
    dangerous call.

    Args:
        func_body: raw AT&T disassembly text of a single function
            (the ``group(2)`` of the per-function regex).
        bit: ``32`` or ``64`` (architecture).

    Note:
        Only matches ``%ebp``/``%rbp``-based leas.  Binaries that
        use ``and $0xf0,%esp; sub $N,%esp`` + ``lea -M(%esp)``
        (e.g. Challenge/fmtstr1) still return ``None`` — this is
        a pre-existing limitation.  The fix only addresses the
        **false positive** (epilogue lea being misread as buffer
        offset), not the false negative (buffer lea using %esp).
    """
    first_dangerous_pos = -1
    for dangerous in _DANGEROUS_CALLS:
        pattern = _DANGEROUS_CALL_RE_TPL.format(name=re.escape(dangerous))
        m = re.search(pattern, func_body)
        if m and (first_dangerous_pos == -1 or m.start() < first_dangerous_pos):
            first_dangerous_pos = m.start()
    if first_dangerous_pos == -1:
        return None

    # All lea -N(%ebp/rbp) matches; pick the LAST one before the
    # first dangerous call (the buffer setup lea is the closest
    # preceding lea, not the first one in the function).
    lea_matches = list(_LEA_RE.finditer(func_body))
    valid_leas = [m for m in lea_matches if m.start() < first_dangerous_pos]
    if not valid_leas:
        return None

    lea_match = valid_leas[-1]
    offset_dec = abs(int(lea_match.group(1), 16))
    return offset_dec + 8 if bit == 64 else offset_dec + 4


def vuln_func_name(program: Path) -> List[str]:
    """Return names of functions with ``lea`` + dangerous call (BOF candidates).

    Pure function: runs :func:`core.runner.run_objdump_disasm` with
    ``intel=False`` (AT&T syntax — required by the regexes), splits
    into per-function bodies, and returns the name of each function
    whose body contains both a ``lea`` instruction and a call to
    one of the dangerous read functions (``read``/``gets``/``fgets``/
    ``scanf``).

    Args:
        program: path to the target ELF.

    Returns:
        List of function name strings.  Empty when no vulnerable
        function is found.
    """
    content = run_objdump_disasm(program, intel=False)
    functions = re.split(r"\n\n", content.strip())

    results: List[str] = []
    for func in functions:
        func_name_match = re.search(r"<([^>]+)>", func)
        if not func_name_match:
            continue
        func_name = func_name_match.group(1)

        has_lea = bool(re.search(r"\s+lea\s", func))
        has_call_read = sum(
            bool(re.search(rf"call.*{name}@plt", func))
            for name in _DANGEROUS_CALLS
        )

        if has_lea and has_call_read:
            lea_match = re.search(r"lea\s+-\s*(0x[0-9a-f]+)", func)
            if lea_match:
                results.append(func_name)
    return results


def asm_stack_overflow(program: Path, bit: int) -> Optional[int]:
    """Infer dynamic padding from a vulnerable function's ``lea -N(%ebp)``.

    Pure function.  Scans the disassembly for the **first** function
    body that contains a ``lea -0xN(%ebp)`` / ``lea -0xN(%rbp)``
    pattern AND a call to a dangerous read function.  Returns the
    inferred padding: ``abs(offset) + 8`` for 64-bit, ``abs(offset)
    + 4`` for 32-bit (the +4/+8 accounts for the saved RBP / return
    address).

    v4.0.2c3: the buffer-setup lea is the **last** ``lea -N(%ebp/rbp)``
    before the first dangerous call (not the first lea in the function
    body, which can be the function epilogue ``lea -0x8(%ebp),%esp``).
    See :func:`_extract_buffer_lea_padding` for the extraction logic.

    Args:
        program: path to the target ELF.
        bit: ``32`` or ``64`` (architecture).

    Returns:
        The inferred padding in bytes, or ``None`` when no
        vulnerable pattern is found.
    """
    content = run_objdump_disasm(program, intel=False)

    # Per-function body regex — same as v3.1 L687.  Group(1) is the
    # function name; group(2) is the body up to the next function
    # header or end-of-file.
    func_pattern = r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"
    functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)

    for func in functions:
        func_body = func.group(2)
        has_lea = "lea" in func_body
        has_call = "call" in func_body
        if not (has_lea and has_call):
            continue
        # v4.0.2c3: find the buffer-setup lea (closest lea BEFORE
        # the first dangerous call) instead of the function's first
        # lea (which can be the epilogue ``lea -0x8(%ebp),%esp``).
        padding = _extract_buffer_lea_padding(func_body, bit)
        if padding is not None:
            return padding
    return None


def analyze_vulnerable_functions(program: Path, bit: int) -> Optional[int]:
    """List all vulnerable functions and return the first one's padding.

    Same heuristic as :func:`asm_stack_overflow` but **collects all**
    matching functions into a list, then returns the padding of the
    first.  P4.6 includes this for spec completeness — the legacy
    port (which prints the VULNERABLE FUNCTIONS table) is a small
    variation on the same parse loop.

    v4.0.2c3: also uses :func:`_extract_buffer_lea_padding` for
    epilogue-aware extraction (see :func:`asm_stack_overflow`).

    Args:
        program: path to the target ELF.
        bit: ``32`` or ``64`` (architecture).

    Returns:
        Padding (int) of the first vulnerable function, or ``None``.
    """
    content = run_objdump_disasm(program, intel=False)
    func_pattern = r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"
    functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)

    for func in functions:
        func_name = func.group(1)
        func_body = func.group(2)
        has_lea = "lea" in func_body
        if not has_lea:
            continue
        # v4.0.2c3: same epilogue-aware buffer-lea extraction as
        # :func:`asm_stack_overflow`.
        padding = _extract_buffer_lea_padding(func_body, bit)
        if padding is not None:
            return padding
    return None


# Legacy ports ----------------------------------------------------------------


def _legacy_vuln_func_name(program: Path) -> List[str]:
    """[OBSOLETE — prefer :func:`vuln_func_name`] Verbatim port of v3.1's ``vuln_func_name``.

    Retained for spec parity; has 2 callers (``_legacy.py`` L3170,
    L3297).  Preserves v3.1 print behavior byte-for-byte: silent on
    success, ``print_error`` on failure.
    """
    from autopwn.core.logging import print_error

    try:
        return vuln_func_name(program)
    except Exception as e:
        print_error(f"failed to find vulnerable function names: {e}")
        return []


def _legacy_asm_stack_overflow(program: Path, bit: int) -> Optional[int]:
    """[OBSOLETE — prefer :func:`asm_stack_overflow`] Verbatim port of v3.1's ``asm_stack_overflow``.

    Retained for spec parity; has 2 callers (``_legacy.py`` L3166,
    L3295).  Preserves the v3.1 print behavior byte-for-byte:
    ``print_info`` "performing assembly-based overflow analysis" +
    ``print_success`` "stack size: …" + ``print_success`` "overflow
    padding adjustment: …" + ``print_error`` on failure.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_success, print_error,
    )

    print_info("performing assembly-based overflow analysis")
    try:
        content = run_objdump_disasm(program, intel=False)
        func_pattern = r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"
        functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)

        for func in functions:
            func_body = func.group(2)
            dangerous_calls = list(_DANGEROUS_CALLS)
            has_lea = "lea" in func_body
            has_call = "call" in func_body
            has_dangerous_call = any(call in func_body for call in dangerous_calls)
            if has_lea and has_call and has_dangerous_call:
                lea_match = _LEA_RE.search(func_body)
                if lea_match:
                    offset_hex = lea_match.group(1)
                    offset_dec = abs(int(offset_hex, 16))
                    padding = offset_dec + 8 if bit == 64 else offset_dec + 4
                    print_success(f"stack size: {Colors.YELLOW}{offset_dec}{Colors.END} bytes")
                    print_success(
                        f"overflow padding adjustment: "
                        f"{Colors.YELLOW}{padding}{Colors.END} bytes"
                    )
                    return padding
        return None
    except Exception as e:
        print_error(f"failed to perform assembly analysis: {e}")
        return None


def _legacy_analyze_vulnerable_functions(
    program: Path, bit: int,
) -> Optional[int]:
    """[OBSOLETE — prefer :func:`analyze_vulnerable_functions`] Verbatim port.

    Retained for spec parity; has 2 callers (``_legacy.py`` L3195 +
    a 2nd site in the fmtstr branch).  Preserves the v3.1 print
    behavior byte-for-byte: ``print_info`` "analyzing vulnerable
    functions" + ``print_section_header`` "VULNERABLE FUNCTIONS" +
    3-col table + ``print_info""`` (trailing empty line) +
    ``print_error`` on failure.
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

        vulnerable_functions = []
        for func in functions:
            func_name = func.group(1)
            func_body = func.group(2)
            dangerous_calls = list(_DANGEROUS_CALLS)
            has_lea = "lea" in func_body
            has_dangerous_call = any(call in func_body for call in dangerous_calls)
            if has_lea and has_dangerous_call:
                lea_match = _LEA_RE.search(func_body)
                if lea_match:
                    offset_hex = lea_match.group(1)
                    offset_dec = abs(int(offset_hex, 16))
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
    "vuln_func_name",
    "asm_stack_overflow",
    "analyze_vulnerable_functions",
    "_legacy_vuln_func_name",
    "_legacy_asm_stack_overflow",
    "_legacy_analyze_vulnerable_functions",
]
