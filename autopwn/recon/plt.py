"""AutoPwn recon layer: PLT function scanning (P4.3).

Replaces the v3.1 monolith's ``scan_plt_functions`` + ``set_function_flags``
functions (see ``autopwn/_legacy.py`` L357-405) with a single typed entry
point that populates the ``ctx.has_*`` booleans and returns a
flags dict.  Per ``rebuild.md`` §6.5 P4.3 + ``refactor.md`` §5 mapping
table, this is the third recon module in the P4 layer (M2 milestone).

Public API
----------
* :func:`scan` — populates ``ctx.has_system`` / ``ctx.has_puts`` /
  ``ctx.has_write`` / ``ctx.has_printf`` / ``ctx.has_backdoor`` /
  ``ctx.has_callsystem`` in-place (matches the 6 bool fields on
  :class:`ExploitContext`); returns a ``dict[str, int]`` of the
  same flags for backward-compat with v3.1 callers.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_scan_plt_functions` — verbatim port of v3.1's
  ``scan_plt_functions`` (L357-399).  Preserves the FUNCTION ANALYSIS
  table printer.  Has 1 caller (``_legacy.py`` L3137).
* :func:`_legacy_set_function_flags` — verbatim port of v3.1's
  ``set_function_flags`` (L401-405).  Has 1 caller (``_legacy.py``
  L3138).  The ``globals()[func] = available`` side effect that
  follows in ``_legacy.py`` L3141-3142 is the **P4.7** cleanup task;
  this port retains the pure-dict shape only.

Design notes
------------
* :func:`scan` is **mutating but mostly pure**: it writes to
  ``ctx.has_*`` (in-place) and returns a dict.  No ``print_*`` calls,
  no ``globals()`` writes outside the ctx.  This is the FIRST recon
  module that mutates ctx — P4.1 returned ``BinaryInfo`` (P8 overwrites
  ``ctx.binary``), P4.2 returned ``LibcInfo`` (P8 overwrites ``ctx.libc``);
  PLT flags are 6 independent booleans with no obvious container, so
  in-place mutation is the cleanest fit.
* The 6 functions scanned (``write``/``puts``/``printf``/``system``/
  ``backdoor``/``callsystem``) match the 6 ``ctx.has_*`` fields
  exactly.  v3.1's ``scan_plt_functions`` also scanned ``main`` — we
  drop it here since ``main`` is never a strategy-gate (it is always
  present, has no ``has_main`` field, and main() in P8 will use
  ``ctx.binary.path`` directly instead).
* Parsing uses :func:`core.runner.run_objdump_disasm` (P1.3 wrapper).
  Match condition is identical to v3.1 L382 (``<{func}@plt>:`` or
  ``<{func}>:``), so the legacy port and the new module produce the
  same flag values on all 5 Challenge binaries.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict

from autopwn.context import ExploitContext
from autopwn.core.runner import run_objdump_disasm


# Functions whose PLT presence gates exploit strategies.  Kept in
# module scope (rather than recomputed per call) for readability
# and to avoid magic-string drift.
_PLT_FUNCS = ("write", "puts", "printf", "system", "backdoor", "callsystem")


def _parse_plt_addresses(objdump_out: str) -> Dict[str, str]:
    """Parse objdump disassembly output for PLT function addresses.

    Mirrors v3.1's L381-387 parser: for each target function, scan
    the objdump lines for ``<{func}@plt>:`` (PLT stub) or
    ``<{func}>:`` (the function itself if not PLT-stubbed).  Returns
    a dict mapping function name → address (hex string, no ``0x``
    prefix — matches v3.1 format).

    Args:
        objdump_out: raw objdump disassembly (intel syntax, with
            ``--no-show-raw-insn`` per ``core.runner.run_objdump_disasm``).

    Returns:
        ``{func_name: address_hex_str}`` for every function found.
        Functions not present in the binary are simply absent from
        the dict (caller checks with ``in``).
    """
    addresses: Dict[str, str] = {}
    for line in objdump_out.splitlines():
        for func in _PLT_FUNCS:
            if f"<{func}@plt>:" in line or f"<{func}>:" in line:
                if func not in addresses:  # first match wins (v3.1 L387 break)
                    addresses[func] = line.split()[0].strip(":")
                break
    return addresses


def scan(ctx: ExploitContext, program: Path) -> Dict[str, int]:
    """Probe PLT entries and populate ``ctx.has_*`` flags.

    Resolution flow (matches v3.1 ``main()`` L3137-3142, but typed):

    1. Run :func:`core.runner.run_objdump_disasm` to get intel-syntax
       disassembly with raw insns suppressed (P1.3 spec).
    2. Parse for the 6 ``_PLT_FUNCS`` entries; collect address strings.
    3. Build a ``{func: 1|0}`` flags dict; write the booleans into
       ``ctx.has_system`` / ``ctx.has_puts`` / etc.
    4. Return the flags dict (so callers that just want the bool can
       do ``flags["system"]``; matches v3.1 ``set_function_flags``
       return shape).

    The function is mutating (writes ``ctx.has_*``) but otherwise
    has no side effects — no ``print_*``, no ``globals()`` writes,
    no file I/O beyond the objdump subprocess.  Unit-testable in
    isolation: pass a fake ctx (with placeholder ``has_*=False``),
    assert the booleans flip after scan.

    Args:
        ctx: an :class:`ExploitContext`.  The 6 ``has_*`` fields are
            **overwritten** with the freshly-probed values.
        program: path to the target ELF.

    Returns:
        A ``{func: 1|0}`` dict for the 6 PLT functions.  Keys
        present in v3.1 (write/puts/printf/system/backdoor/callsystem)
        are always present in the result; values are 1 if the PLT
        entry was found, 0 otherwise.
    """
    objdump_out = run_objdump_disasm(program)
    addresses = _parse_plt_addresses(objdump_out)

    flags: Dict[str, int] = {func: (1 if func in addresses else 0) for func in _PLT_FUNCS}

    # In-place write to ctx (matches the 6 has_* fields exactly)
    ctx.has_write = bool(flags["write"])
    ctx.has_puts = bool(flags["puts"])
    ctx.has_printf = bool(flags["printf"])
    ctx.has_system = bool(flags["system"])
    ctx.has_backdoor = bool(flags["backdoor"])
    ctx.has_callsystem = bool(flags["callsystem"])

    return flags


def _legacy_scan_plt_functions(program: Path) -> Dict[str, str]:
    """[OBSOLETE — prefer :func:`scan`] Verbatim port of v3.1's ``scan_plt_functions``.

    Retained for spec parity (``rebuild.md`` §4.5 P4.3 lists both
    legacy functions; underscore prefix marks not-public-API).  Has
    1 caller (``_legacy.py`` L3137); the new :func:`scan` will be
    wired into the orchestrator at P8.

    Preserves v3.1 behavior byte-for-byte, including:

      * scans **7** functions (write/puts/printf/main/system/backdoor/callsystem)
        — note ``main`` is included here but **dropped** in :func:`scan`
        since it has no ``has_main`` field on ctx.
      * emits ``print_info`` "analyzing PLT table and available functions"
      * emits ``print_section_header`` "FUNCTION ANALYSIS" + 3-col table
      * per-function: ``print_table_row`` with address + YES/NO status

    Returns:
        ``{func_name: address_hex_str}`` for every function found
        (may be 0-7 entries).  Same shape as v3.1.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_error, print_section_header,
        print_table_header, print_table_row,
    )

    print_info("analyzing PLT table and available functions")
    try:
        objdump_out = run_objdump_disasm(program)
        # v3.1's target_functions list — 7 entries, includes "main"
        target_functions = ["write", "puts", "printf", "main", "system", "backdoor", "callsystem"]
        function_addresses: Dict[str, str] = {}
        found_functions: list = []
        lines = objdump_out.splitlines()

        print_section_header("FUNCTION ANALYSIS")
        headers = ["Function", "Address", "Available"]
        print_table_header(headers)

        for func in target_functions:
            found = False
            address = "N/A"
            for line in lines:
                if f"<{func}@plt>:" in line or f"<{func}>:" in line:
                    address = line.split()[0].strip(":")
                    function_addresses[func] = address
                    found_functions.append(func)
                    found = True
                    break
            status = "YES" if found else "NO"
            color = Colors.SUCCESS if found else Colors.ERROR
            colors = [Colors.END, Colors.YELLOW if found else Colors.END, color]
            print_table_row([func, address, status], colors)

        print_info("")
        return function_addresses

    except Exception as e:
        print_error(f"failed to scan PLT functions: {e}")
        return {}


def _legacy_set_function_flags(function_addresses: Dict[str, str]) -> Dict[str, int]:
    """[OBSOLETE — prefer :func:`scan`] Verbatim port of v3.1's ``set_function_flags``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3138).
    The ``globals()[func] = available`` side effect that follows in
    ``_legacy.py`` L3141-3142 is the **P4.7** cleanup task.

    Returns:
        ``{func: 1|0}`` for the 7 v3.1 target functions (includes
        ``main`` which the new :func:`scan` drops).
    """
    target_functions = ["write", "puts", "printf", "main", "system", "backdoor", "callsystem"]
    return {func: (1 if func in function_addresses else 0) for func in target_functions}


__all__ = ["scan", "_legacy_scan_plt_functions", "_legacy_set_function_flags"]
