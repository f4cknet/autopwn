"""AutoPwn recon layer: ROP gadget discovery (P4.4).

Replaces the v3.1 monolith's ``find_rop_gadgets_x64`` +
``find_rop_gadgets_x32`` functions (see ``autopwn/_legacy.py``
L407-535) with two typed entry points that return
:class:`RopGadgetsX64` and :class:`RopGadgetsX32` dataclasses.
Per ``rebuild.md`` §6.5 P4.4 + ``refactor.md`` §5 mapping table,
this is the fourth recon module in the P4 layer (M2 milestone).

Public API
----------
* :func:`find_x64` — returns a :class:`RopGadgetsX64` populated
  with ``pop_rdi`` / ``pop_rsi`` / ``ret`` addresses + the
  ``extra_rdi`` / ``extra_rsi`` flags (1 if the gadget also pops
  a trailing register like ``pop r15``).  P8 will assign the
  result to ``ctx.gadgets_x64``.
* :func:`find_x32` — returns a :class:`RopGadgetsX32` populated
  with ``pop_eax`` / ``pop_ebx`` / ``pop_ecx`` / ``pop_edx`` /
  ``pop_ecx_ebx`` / ``ret`` / ``int_0x80`` + the collapsed
  ``has_eax_ebx_ecx_edx`` bool (per R8 mitigation — 4 bools in
  v3.1's legacy 11-tuple folded into a single field).

Legacy ports (parity only)
--------------------------
* :func:`_legacy_find_rop_gadgets_x64` — verbatim port of v3.1's
  ``find_rop_gadgets_x64`` (L407-466).  Returns the legacy
  5-tuple ``(pop_rdi, pop_rsi, ret, other_rdi_registers,
  other_rsi_registers)`` directly.  Has 1 caller
  (``_legacy.py`` L3149).
* :func:`_legacy_find_rop_gadgets_x32` — verbatim port of v3.1's
  ``find_rop_gadgets_x32`` (L468-535).  Returns the legacy
  11-tuple ``(pop_eax, pop_ebx, pop_ecx, pop_edx, pop_ecx_ebx,
  ret, int_0x80, eax, ebx, ecx, edx)``.  Has 1 caller
  (``_legacy.py`` L3152-3153).

Design notes
------------
* The new functions are **return-only** (no ctx mutation): they
  return a fresh dataclass; P8's orchestrator will assign it to
  ``ctx.gadgets_x64`` / ``ctx.gadgets_x32``.  This matches the
  P4.1 (BinaryInfo) and P4.2 (LibcInfo) pattern.  P4.3 (PLT) was
  the exception because the 6 ``has_*`` booleans have no natural
  container.
* Parsing logic factored into the private :func:`_parse_ropper_lines`
  helper that takes ropper output + a set of regex patterns and
  returns a structured dict.  The two public functions then
  translate the dict into their respective dataclass.
* The ``extra_rdi`` / ``extra_rsi`` (a.k.a. ``other_*`` in v3.1)
  fields encode the "gadget also pops an extra register" case
  (e.g. ``pop rdi; pop r15; ret`` vs ``pop rdi; ret``).  The
  glibc strategy code uses this flag to decide whether to pad the
  ROP chain with a dummy address — see ``refactor.md`` §3.2.1
  ``RopGadgetsX64`` field docstring.
* For x32 the four individual bools ``eax``/``ebx``/``ecx``/``edx``
  are collapsed into ``has_eax_ebx_ecx_edx`` (true iff all four
  ``pop reg; ret`` gadgets were found).  v3.1's strategy code
  only checks ``if eax and ebx and ecx and edx:``, so the
  semantics are preserved.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional, Tuple

from autopwn.context import RopGadgetsX64, RopGadgetsX32
from autopwn.core.runner import run_ropper


# Skip the ropper [INFO] banner lines (banner ends in this token)
_INFO_BANNER_TOKEN = "[INFO]"


def _parse_ropper_lines(ropper_out: str) -> list:
    """Strip ropper's [INFO] banner and return the data lines.

    Args:
        roper_out: raw output of ``ropper --file X --search 'Y' --nocolor``.

    Returns:
        A list of non-empty lines that don't start with ``[INFO]``.
        Each remaining line is of the form
        ``<hex_address>: <instruction>`` (e.g. ``0x080490f6: pop rdi; ret;``).
    """
    return [
        line for line in ropper_out.splitlines()
        if line.strip() and _INFO_BANNER_TOKEN not in line
    ]


def _extract_x64_gadgets(ropper_combined: str) -> Dict[str, object]:
    """Parse ropper output (3 searches concatenated) for x64 gadgets.

    The combined ropper output (from searching for ``pop rdi``,
    ``pop rsi``, ``ret`` separately and concatenating) is parsed
    for these patterns (first match wins, matching v3.1 L437-459
    if/elif cascade order):

    * ``pop rdi; pop <reg>; ret`` → ``pop_rdi`` addr + ``extra_rdi=1``
    * ``pop rdi; ret``            → ``pop_rdi`` addr + ``extra_rdi=0``
    * ``pop rsi; pop <reg>; ret`` → ``pop_rsi`` addr + ``extra_rsi=1``
    * ``pop rsi; ret``            → ``pop_rsi`` addr + ``extra_rsi=0``
    * ``<addr>: ret``             → ``ret`` addr

    The ``<addr>:`` prefix is the hex address of the gadget.  We
    extract via ``line.split(":")[0].strip()`` (v3.1 L438).

    Args:
        ropper_combined: concatenated output of 3 ``run_ropper`` calls.

    Returns:
        ``{pop_rdi, pop_rsi, ret, extra_rdi, extra_rsi}`` — all values
        ``None`` / ``0`` when not found.
    """
    out: Dict[str, object] = {
        "pop_rdi": None, "pop_rsi": None, "ret": None,
        "extra_rdi": 0, "extra_rsi": 0,
    }

    for line in _parse_ropper_lines(ropper_combined):
        if "pop rdi;" in line and "pop rdi; pop" in line:
            out["pop_rdi"] = line.split(":")[0].strip()
            out["extra_rdi"] = 1
        elif "pop rdi; ret;" in line:
            out["pop_rdi"] = line.split(":")[0].strip()
            out["extra_rdi"] = 0
        elif "pop rsi;" in line and "pop rsi; pop" in line:
            out["pop_rsi"] = line.split(":")[0].strip()
            out["extra_rsi"] = 1
        elif "pop rsi; ret;" in line:
            out["pop_rsi"] = line.split(":")[0].strip()
            out["extra_rsi"] = 0
        elif "ret" in line and "ret " not in line:
            # v3.1 L457: only match "<addr>: ret" exactly, not lines
            # like "pop rdi; ret" (which we already handled above)
            out["ret"] = line.split(":")[0].strip()
    return out


def _extract_x32_gadgets(ropper_outputs: Dict[str, str]) -> Dict[str, object]:
    """Parse ropper output (4 register searches + ret + int 0x80) for x32 gadgets.

    Args:
        ropper_outputs: ``{search_term: ropper_output}`` for
            ``pop eax;`` / ``pop ebx;`` / ``pop ecx;`` / ``pop edx;``
            / ``ret;`` / ``int 0x80;``.

    Returns:
        ``{pop_eax, pop_ebx, pop_ecx, pop_edx, pop_ecx_ebx, ret,
        int_0x80, has_eax_ebx_ecx_edx}`` — all values ``None`` / ``False``
        when not found.  The trailing ``has_eax_ebx_ecx_edx`` is
        ``True`` iff all four ``pop reg; ret`` gadgets were found.
    """
    out: Dict[str, object] = {
        "pop_eax": None, "pop_ebx": None, "pop_ecx": None, "pop_edx": None,
        "pop_ecx_ebx": None, "ret": None, "int_0x80": None,
        "has_eax_ebx_ecx_edx": False,
    }

    register_searches = ("eax", "ebx", "ecx", "edx")
    found = {"eax": False, "ebx": False, "ecx": False, "edx": False}

    for reg in register_searches:
        for line in _parse_ropper_lines(ropper_outputs.get(f"pop {reg};", "")):
            if f"pop {reg}; ret;" in line:
                out[f"pop_{reg}"] = line.split(":")[0].strip()
                found[reg] = True
                break
            elif f"pop {reg}" in line and "pop ebx" in line and reg == "ecx":
                # v3.1 L503-507: catch "pop ecx; pop ebx; ret" combo
                out["pop_ecx_ebx"] = line.split(":")[0].strip()
                found[reg] = True
                break

    for line in _parse_ropper_lines(ropper_outputs.get("ret;", "")):
        if "ret" in line and "ret " not in line:
            out["ret"] = line.split(":")[0].strip()
            break

    for line in _parse_ropper_lines(ropper_outputs.get("int 0x80;", "")):
        if "int 0x80" in line:
            out["int_0x80"] = line.split(":")[0].strip()
            break

    # R8 mitigation: collapse 4 bools into 1 (v3.1 only ever
    # checked `if all 4`, so semantic preservation is trivial).
    out["has_eax_ebx_ecx_edx"] = all(found.values())

    return out


def find_x64(ctx, program: Path) -> RopGadgetsX64:
    """Find ROP gadgets for x64 (amd64) and return a typed dataclass.

    Concatenates the output of 3 :func:`core.runner.run_ropper` calls
    (matching v3.1 L424-427: ``pop rdi`` + ``pop rsi`` + ``ret``).
    The combined output is parsed for the 5 gadget types and packed
    into a :class:`RopGadgetsX64` dataclass.

    Pure function: no ``print_*``, no ``globals()`` writes, no ctx
    mutation (caller — P8 orchestrator — assigns the result to
    ``ctx.gadgets_x64``).  Unit-testable in isolation.

    Args:
        ctx: passed for symmetry with other recon functions; unused
            by this implementation.  Kept in the signature so
            ``recon.plt.scan`` / ``recon.rop.find_x64`` / etc.
            share a uniform ``func(ctx, program)`` shape.
        program: path to the target ELF.

    Returns:
        A :class:`RopGadgetsX64` with all 5 fields populated.  Missing
        gadgets are ``0`` for ``extra_*`` and ``None`` for addresses.
    """
    combined = ""
    for search in ("pop rdi", "pop rsi", "ret"):
        combined += run_ropper(program, search)
    parsed = _extract_x64_gadgets(combined)
    return RopGadgetsX64(
        pop_rdi=parsed["pop_rdi"],  # type: ignore[arg-type]
        pop_rsi=parsed["pop_rsi"],  # type: ignore[arg-type]
        ret=parsed["ret"],          # type: ignore[arg-type]
        extra_rdi=parsed["extra_rdi"],  # type: ignore[arg-type]
        extra_rsi=parsed["extra_rsi"],  # type: ignore[arg-type]
    )


def find_x32(ctx, program: Path) -> RopGadgetsX32:
    """Find ROP gadgets for x86 (i386) and return a typed dataclass.

    Runs 6 :func:`core.runner.run_ropper` calls (one per gadget
    type: ``pop eax;`` / ``pop ebx;`` / ``pop ecx;`` / ``pop edx;``
    / ``ret;`` / ``int 0x80;``) and packs the result into a
    :class:`RopGadgetsX32` dataclass.  The 4 individual bools
    ``eax``/``ebx``/``ecx``/``edx`` are collapsed into
    ``has_eax_ebx_ecx_edx`` per R8 mitigation.

    Pure function (same contract as :func:`find_x64`).

    Args:
        ctx: passed for symmetry; unused.
        program: path to the target ELF.

    Returns:
        A :class:`RopGadgetsX32` with all 8 fields populated.
    """
    ropper_outputs = {term: run_ropper(program, term) for term in (
        "pop eax;", "pop ebx;", "pop ecx;", "pop edx;", "ret;", "int 0x80;",
    )}
    parsed = _extract_x32_gadgets(ropper_outputs)
    return RopGadgetsX32(
        pop_eax=parsed["pop_eax"],          # type: ignore[arg-type]
        pop_ebx=parsed["pop_ebx"],          # type: ignore[arg-type]
        pop_ecx=parsed["pop_ecx"],          # type: ignore[arg-type]
        pop_edx=parsed["pop_edx"],          # type: ignore[arg-type]
        pop_ecx_ebx=parsed["pop_ecx_ebx"],  # type: ignore[arg-type]
        ret=parsed["ret"],                  # type: ignore[arg-type]
        int_0x80=parsed["int_0x80"],        # type: ignore[arg-type]
        has_eax_ebx_ecx_edx=parsed["has_eax_ebx_ecx_edx"],  # type: ignore[arg-type]
    )


# Legacy ports ----------------------------------------------------------------


def _legacy_find_rop_gadgets_x64(
    program: Path,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int], Optional[int]]:
    """[OBSOLETE — prefer :func:`find_x64`] Verbatim port of v3.1's ``find_rop_gadgets_x64``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3149).
    Returns the legacy 5-tuple shape directly; P4.7 will rewrite
    that caller to use :func:`find_x64` + the dataclass shape.

    Preserves v3.1 print behavior byte-for-byte (the ROP GADGETS
    x64 table).  Uses ``run_ropper`` (P1.3 wrapper) per P1.5's
    os.system cleanup.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_error, print_section_header,
        print_table_header, print_table_row,
    )

    print_info("searching for ROP gadgets (x64)")
    gadgets = {
        'pop_rdi': None, 'pop_rsi': None, 'ret': None,
        'other_rdi_registers': None, 'other_rsi_registers': None,
    }
    try:
        lines = []
        for search in ('pop rdi', 'pop rsi', 'ret'):
            ropper_out = run_ropper(program, search)
            lines.extend(ropper_out.splitlines())

        print_section_header("ROP GADGETS (x64)")
        headers = ["Gadget Type", "Address", "Instruction"]
        print_table_header(headers)

        for line in lines:
            if '[INFO]' in line:
                continue
            if "pop rdi;" in line and "pop rdi; pop" in line:
                gadgets['pop_rdi'] = line.split(":")[0].strip()
                gadgets['other_rdi_registers'] = 1
                print_table_row(["pop rdi (multi)", gadgets['pop_rdi'], "pop rdi; pop ...; ret"],
                                [Colors.END, Colors.YELLOW, Colors.END])
            elif "pop rdi; ret;" in line:
                gadgets['pop_rdi'] = line.split(":")[0].strip()
                gadgets['other_rdi_registers'] = 0
                print_table_row(["pop rdi", gadgets['pop_rdi'], "pop rdi; ret"],
                                [Colors.END, Colors.YELLOW, Colors.END])
            elif "pop rsi;" in line and "pop rsi; pop" in line:
                gadgets['pop_rsi'] = line.split(":")[0].strip()
                gadgets['other_rsi_registers'] = 1
                print_table_row(["pop rsi (multi)", gadgets['pop_rsi'], "pop rsi; pop ...; ret"],
                                [Colors.END, Colors.YELLOW, Colors.END])
            elif "pop rsi; ret;" in line:
                gadgets['pop_rsi'] = line.split(":")[0].strip()
                gadgets['other_rsi_registers'] = 0
                print_table_row(["pop rsi", gadgets['pop_rsi'], "pop rsi; ret"],
                                [Colors.END, Colors.YELLOW, Colors.END])
            elif "ret" in line and "ret " not in line:
                gadgets['ret'] = line.split(":")[0].strip()
                print_table_row(["ret", gadgets['ret'], "ret"],
                                [Colors.END, Colors.YELLOW, Colors.END])

        print_info("")
        return (
            gadgets['pop_rdi'], gadgets['pop_rsi'], gadgets['ret'],
            gadgets['other_rdi_registers'], gadgets['other_rsi_registers'],
        )
    except Exception as e:
        print_error(f"failed to find ROP gadgets: {e}")
        return None, None, None, None, None


def _legacy_find_rop_gadgets_x32(program) -> Tuple:
    """[OBSOLETE — prefer :func:`find_x32`] Verbatim port of v3.1's ``find_rop_gadgets_x32``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3152-3153).
    Returns the legacy 11-tuple shape: 7 gadget addresses (str) +
    4 individual bools (int 0/1).

    Preserves v3.1 print behavior byte-for-byte (the ROP GADGETS
    x32 table with FOUND / NOT FOUND status).
    """
    from autopwn.core.logging import (
        Colors, print_info, print_error, print_section_header,
        print_table_header, print_table_row,
    )

    print_info("searching for ROP gadgets (x32)")
    gadgets = {
        'pop_eax': None, 'pop_ebx': None, 'pop_ecx': None, 'pop_edx': None,
        'pop_ecx_ebx': None, 'ret': None, 'int_0x80': None,
    }
    registers_found = {'eax': 0, 'ebx': 0, 'ecx': 0, 'edx': 0}

    try:
        print_section_header("ROP GADGETS (x32)")
        headers = ["Gadget Type", "Address", "Status"]
        print_table_header(headers)

        register_searches = ['eax', 'ebx', 'ecx', 'edx']
        for reg in register_searches:
            ropper_out = run_ropper(program, f"pop {reg};")
            lines = ropper_out.splitlines()
            for line in lines:
                if '[INFO]' in line:
                    continue
                if f"pop {reg}; ret;" in line:
                    address = line.split(":")[0].strip()
                    gadgets[f'pop_{reg}'] = address
                    registers_found[reg] = 1
                    print_table_row([f"pop {reg}", address, "FOUND"],
                                    [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
                elif f"pop {reg}" in line and 'pop ebx' in line and reg == 'ecx':
                    address = line.split(":")[0].strip()
                    gadgets['pop_ecx_ebx'] = address
                    registers_found[reg] = 1
                    print_table_row(["pop ecx; pop ebx", address, "FOUND"],
                                    [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
            if registers_found[reg] == 0:
                print_table_row([f"pop {reg}", "N/A", "NOT FOUND"],
                                [Colors.END, Colors.END, Colors.ERROR])

        ret_out = run_ropper(program, "ret;")
        for line in ret_out.splitlines():
            if '[INFO]' in line:
                continue
            if "ret" in line and "ret " not in line:
                gadgets['ret'] = line.split(":")[0].strip()
                print_table_row(["ret", gadgets['ret'], "FOUND"],
                                [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                break

        int80_out = run_ropper(program, "int 0x80;")
        for line in int80_out.splitlines():
            if '[INFO]' in line:
                continue
            if "int 0x80" in line:
                gadgets['int_0x80'] = line.split(":")[0].strip()
                print_table_row(["int 0x80", gadgets['int_0x80'], "FOUND"],
                                [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                break

        print_info("")
        return (
            gadgets['pop_eax'], gadgets['pop_ebx'], gadgets['pop_ecx'], gadgets['pop_edx'],
            gadgets['pop_ecx_ebx'], gadgets['ret'], gadgets['int_0x80'],
            registers_found['eax'], registers_found['ebx'],
            registers_found['ecx'], registers_found['edx'],
        )
    except Exception as e:
        print_error(f"failed to find ROP gadgets: {e}")
        return (None,) * 11


__all__ = ["find_x64", "find_x32", "_legacy_find_rop_gadgets_x64", "_legacy_find_rop_gadgets_x32"]
