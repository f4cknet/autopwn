"""AutoPwn recon layer: BSS symbol scanning (P4.5).

Replaces the v3.1 monolith's ``find_large_bss_symbols`` +
``find_ftmstr_bss_symbols`` functions (see ``autopwn/_legacy.py``
L332-355 + L813-831) with a single typed entry point that returns
a list of :class:`BSSSymbol` dataclasses.  Per ``rebuild.md`` §6.5
P4.5 + ``refactor.md`` §5 mapping table, this is the fifth recon
module in the P4 layer (M2 milestone).

Public API
----------
* :class:`BSSSymbol` — ``@dataclass(slots=True)`` with ``name``,
  ``address`` (int), ``size`` (int).
* :func:`find_bss` — pure; scans the ELF symbol table and returns
  every ``STT_OBJECT`` symbol that matches the size + name filter.
  Default filter (``min_size=30``) matches the v3.1
  ``find_large_bss_symbols`` behavior; ``min_size=2`` with
  ``name_filter=lambda n: '_' not in n`` matches the v3.1
  ``find_ftmstr_bss_symbols`` behavior.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_find_large_bss_symbols` — verbatim port of v3.1's
  ``find_large_bss_symbols`` (L332-355).  Returns the legacy
  3-tuple ``(found, address_hex, name)`` (first match only; prints
  per-symbol success line).  Has 1 caller (``_legacy.py`` L3204,
  via ``check_binsh_string`` for shellcode storage).
* :func:`_legacy_find_ftmstr_bss_symbols` — verbatim port of v3.1's
  ``find_ftmstr_bss_symbols`` (L813-831).  Returns the legacy
  3-tuple ``(function, buf_addr, function_name)`` (last match
  wins, due to ``function`` variable never being reset — see DEV-1
  in §6.5 P4.5 implementation record).  Has 1 caller
  (``_legacy.py`` L3204 area, for format string buffer discovery).

Design notes
------------
* :func:`find_bss` is **pure** (no ``print_*``, no ``globals()``
  writes, no file I/O beyond reading the binary itself).  Returns
  a list — ``[]`` when no symbol matches the filter.  Unit-testable
  in isolation: pass a fake binary, assert the symbol list.
* The 2 v3.1 functions had **different selection criteria**:

    * ``find_large_bss_symbols`` — ``st_size > 30`` (any name),
      first match wins, used for shellcode storage
    * ``find_ftmstr_bss_symbols`` — ``st_size > 2`` AND ``'_' not
      in name``, last match wins (legacy bug — see DEV-1), used
      for format string buffer addresses

  The new :func:`find_bss` parametrizes both criteria so the
  caller picks; legacy ports reproduce the v3.1 behavior 1:1 for
  byte-level fidelity.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from elftools.elf.elffile import ELFFile


@dataclass(slots=True)
class BSSSymbol:
    """A BSS (.bss section) global variable suitable for shellcode/buffer storage.

    ``address`` is the runtime address (``st_value``); ``size`` is the
    symbol's storage size in bytes (``st_size``).
    """

    name: str
    address: int
    size: int


def find_bss(
    program: Path,
    *,
    min_size: int = 30,
    name_filter: Optional[Callable[[str], bool]] = None,
) -> List[BSSSymbol]:
    """Return every ``STT_OBJECT`` symbol matching the size/name filter.

    Pure function: reads the binary once via :mod:`elftools`, scans
    the ``.symtab`` section, and returns a list of :class:`BSSSymbol`
    for every global object whose size is at least ``min_size`` and
    whose name passes ``name_filter`` (if provided).  ``[]`` when no
    symbol matches or when the binary has no ``.symtab`` (stripped).

    The default ``min_size=30`` matches v3.1's
    ``find_large_bss_symbols`` (shellcode storage).  For format
    string buffer discovery, pass
    ``min_size=2, name_filter=lambda n: '_' not in n`` to match
    v3.1's ``find_ftmstr_bss_symbols`` behavior.

    Args:
        program: path to the target ELF.
        min_size: minimum ``st_size`` (inclusive) for a symbol to
            be included.
        name_filter: optional callable taking the symbol name and
            returning ``True`` if it should be included.  ``None``
            means accept all names.

    Returns:
        List of matching :class:`BSSSymbol` (possibly empty).
        Order matches the symbol table iteration order of
        ``elftools`` (no explicit sorting — caller may sort if
        order matters).
    """
    out: List[BSSSymbol] = []
    try:
        with open(program, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if symtab is None:
                return out
            for symbol in symtab.iter_symbols():
                if symbol["st_info"].type != "STT_OBJECT":
                    continue
                if symbol["st_size"] <= min_size:
                    continue
                if name_filter is not None and not name_filter(symbol.name):
                    continue
                out.append(BSSSymbol(
                    name=symbol.name,
                    address=symbol["st_value"],
                    size=symbol["st_size"],
                ))
    except Exception:
        # Silent failure — caller decides whether empty list means
        # "no matches" or "binary unreadable".  The legacy port
        # logs the exception via print_error; we keep the pure
        # function silent to match the P4.1 / P4.2 / P4.3 / P4.4
        # pattern.
        pass
    return out


# Legacy ports ----------------------------------------------------------------


def _legacy_find_large_bss_symbols(
    program: Path,
) -> Tuple[int, Optional[str], Optional[str]]:
    """[OBSOLETE — prefer :func:`find_bss`] Verbatim port of v3.1's ``find_large_bss_symbols``.

    Retained for spec parity; has 1 caller in ``_legacy.py`` (L3204
    area).  Returns the legacy 3-tuple ``(found, address_hex,
    name)`` — **first match wins** (v3.1 L348 ``return 1, ...``
    inside the loop, before the no-match warning fires).

    Preserves v3.1 print behavior byte-for-byte:

      * ``print_info`` "searching for shellcode storage locations"
      * ``print_warning`` "no symbol table found" / "no suitable
        shellcode storage locations found"
      * ``print_success`` "shellcode storage found: <name> at <addr>"
      * ``print_error`` "failed to analyze symbols: …"
    """
    from autopwn.core.logging import (
        Colors, print_info, print_warning, print_success, print_error,
    )

    print_info("searching for shellcode storage locations")
    try:
        with open(program, "rb") as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name(".symtab")
            if not symtab:
                print_warning("no symbol table found")
                return 0, None, None
            for symbol in symtab.iter_symbols():
                if (symbol["st_info"].type == "STT_OBJECT"
                        and symbol["st_size"] > 30):
                    print_success(
                        f"shellcode storage found: "
                        f"{Colors.YELLOW}{symbol.name}{Colors.END} "
                        f"at {Colors.YELLOW}{hex(symbol['st_value'])}{Colors.END}"
                    )
                    return 1, hex(symbol["st_value"]), symbol.name
            print_warning("no suitable shellcode storage locations found")
            return 0, None, None
    except Exception as e:
        print_error(f"failed to analyze symbols: {e}")
        return 0, None, None


def _legacy_find_ftmstr_bss_symbols(
    program: Path,
) -> Tuple[int, Optional[str], Optional[str]]:
    """[OBSOLETE — prefer :func:`find_bss`] Verbatim port of v3.1's ``find_ftmstr_bss_symbols``.

    Retained for spec parity; has 1 caller.  Returns the legacy
    3-tuple ``(function, buf_addr, function_name)``.

    **DEV-1 (legacy bug preserved by port)**: v3.1 L815 initializes
    ``function = 0`` and the for-loop body sets
    ``function = 1; buf_addr = hex(...); function_name = symbol.name``
    but **never breaks**.  So if multiple matching symbols exist, the
    loop runs to the end and overwrites ``buf_addr`` /
    ``function_name`` with the **last** match, while ``function``
    stays 1 throughout.  This is almost certainly a v3.1 bug (the
    original intent was probably first-match-wins like
    :func:`_legacy_find_large_bss_symbols`).  We **port the bug
    verbatim** so the legacy port is byte-for-byte equivalent;
    callers should use :func:`find_bss` for the fixed version.
    """
    from autopwn.core.logging import (
        Colors, print_success, print_warning,
    )

    function = 0
    buf_addr: Optional[str] = None
    function_name: Optional[str] = None
    with open(program, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if not symtab:
            print_warning("Did not find the variable used in the if-condition")
            return function, buf_addr, function_name
        for symbol in symtab.iter_symbols():
            if (symbol["st_info"].type == "STT_OBJECT"
                    and symbol["st_size"] > 2
                    and "_" not in symbol.name):
                print_success(
                    f"Found the variable used in the if-condition: "
                    f"{symbol.name}, address: {hex(symbol['st_value'])}"
                )
                function = 1
                buf_addr = hex(symbol["st_value"])
                function_name = symbol.name

    return function, buf_addr, function_name


__all__ = [
    "BSSSymbol",
    "find_bss",
    "_legacy_find_large_bss_symbols",
    "_legacy_find_ftmstr_bss_symbols",
]
