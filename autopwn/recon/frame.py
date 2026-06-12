"""AutoPwn recon layer: stack-frame context extraction (v4.0.5).

Per ``fix.md §3.1`` (2026-06-12 Owner 拍板): the architectural root
cause of bug v4.0.2b is that ``Ret2LibcWriteX64.build_stage2_payload``
hardcodes the ROP chain shape (``padding + pop_rdi + sh + ret + system``)
without knowing the **caller's** stack-frame structure.  Whether the
``ret`` alignment gadget is needed depends on the buffer-to-rbp
distance (``lea -N(%rbp)``), not on a magic ``padding`` threshold.

This module fixes that by introducing ``FrameContext``: a typed
dataclass that captures the caller's frame structure (``lea_offset``,
``frame_size``, ``vuln_func_addr``) and computes the correct
``required_ret_count`` (0 or 1) based on empirical do_system
movaps alignment.

Public API
----------
* :class:`FrameContext` — pure dataclass with 4 fields:
  ``vuln_func_addr``, ``lea_offset``, ``frame_size``, ``required_ret_count``.
* :func:`extract_frame_context` — static analysis: parses disasm,
  finds the first vulnerable function (lea + dangerous read call),
  extracts its frame structure.
* :func:`compute_required_ret_count` — pure function: given
  ``lea_offset`` (and optionally ``frame_size`` for diagnostics),
  returns ``0`` or ``1`` indicating whether the stack-alignment
  ``ret`` gadget is needed to make do_system's ``movaps`` happy.

Algorithm
---------
The relevant signal is ``lea_offset`` (the absolute value of the
``lea -N(%rbp)`` buffer-to-rbp distance), NOT ``frame_size`` (the
``sub $N, rsp`` value).  The empirical rule, validated on
``Challenge/rip`` (needs ret) and ``Challenge/level3_x64`` (does NOT
need ret) by ctf-pwn on 2026-06-11:

    lea_offset % 16 == 0  →  required_ret_count = 0  (skip alignment ret)
    lea_offset % 16 != 0  →  required_ret_count = 1  (include alignment ret)

Why ``lea_offset`` and not ``frame_size``?

After ``leave; ret`` the rsp at ROP start is determined by the
*function's frame setup* (push rbp; mov rsp, rbp; sub $N, rsp), which
is the same for both rip (sub $0x10) and level3_x64 (sub $0x80) in
mod-16 terms — so frame_size alone cannot distinguish them.  The
*actual* signal that flips movaps's required rsp alignment is the
length of the payload sent before the saved RIP, which is
``padding = lea_offset + 8`` (the +8 is the saved rbp slot).

Equivalent restatement: ``padding % 16 == 8`` → 0, else → 1.  Since
``padding = lea_offset + 8``, ``padding % 16 == 8`` iff
``lea_offset % 16 == 0``.  The function takes ``lea_offset`` because
that's what ``extract_frame_context`` parses directly from the
``lea`` instruction.

Reference data points
---------------------
* ``rip`` main (0x401142): ``lea -0xf(%rbp)`` → lea_offset = 0xf.
  ``0xf % 16 == 15`` → return 1.  ctf-pwn confirms: WITH ret works.
* ``level3_x64`` vulnerable_function (0x4005e6):
  ``lea -0x80(%rbp)`` → lea_offset = 0x80.
  ``0x80 % 16 == 0`` → return 0.  ctf-pwn confirms: WITHOUT ret works.

Note: this is an empirical encoding of the glibc 2.35 do_system
movaps pattern as observed on ctf-pwn 2026-06-11.  For other libc
versions the alignment math may differ.  This module encodes the
heuristic as data, not as scattered magic numbers in primitives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

from autopwn.core.runner import run_objdump_disasm


# Pre-compiled AT&T-syntax lea pattern (matches recon/asm.py P4.6).
# Group(1) is the hex offset (may be negative).
_LEA_RE = re.compile(r"lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)")

# v3.1's "dangerous read" function set (matches recon/asm.py).
_DANGEROUS_CALLS = ("read", "gets", "fgets", "scanf")


@dataclass(slots=True)
class FrameContext:
    """Static stack-frame context for the vulnerable function (v4.0.5).

    Populated by :func:`extract_frame_context` from disassembly; queried
    by primitives (e.g. ``Ret2LibcWriteX64.build_stage2_payload``) to
    decide payload shape **principled** (based on the caller's actual
    frame structure) rather than via magic-number heuristic
    (``padding < 32`` in v4.0.2b — see ``fix.md §2.1``).

    Fields:
      * ``vuln_func_addr``: the function's entry point (e.g. ``0x4005e6``
        for level3_x64's ``vulnerable_function``).  Used for diagnostic
        display and for canary strategies that need to leak the canary
        value at a specific stack offset.
      * ``lea_offset``: the absolute value of the lea offset (e.g. ``0x80``
        for ``lea -0x80(%rbp)``).  Indicates the buffer-to-rbp distance.
      * ``frame_size``: the sub $N, rsp value (e.g. ``0x80`` for
        ``sub $0x80, rsp``).  Indicates the function's local stack
        frame size.  Determines the rsp alignment at leave;ret
        (see :func:`compute_required_ret_count` for math).
      * ``required_ret_count``: 0 or 1.  Computed by
        :func:`compute_required_ret_count`.  Indicates whether the
        stack-alignment ``ret`` gadget is needed before ``system()``
        to satisfy do_system's movaps constraint.
    """

    vuln_func_addr: int = 0
    lea_offset: int = 0
    frame_size: int = 0
    required_ret_count: Literal[0, 1] = 1  # conservative default


def compute_required_ret_count(
    lea_offset: int = 0,
    frame_size: int = 0,  # diagnostic only; the decision is on lea_offset
) -> Literal[0, 1]:
    """Compute the number of ``ret`` gadgets needed for stack alignment.

    Per the module docstring: this encodes the do_system+0x73 movaps
    alignment math as data, not as scattered magic numbers.  The
    signal is ``lea_offset`` (the buffer-to-rbp distance parsed from
    ``lea -N(%rbp)``), NOT ``frame_size`` (the ``sub $N, rsp`` value).

    Args:
        lea_offset: absolute value of the lea offset (e.g. ``0x80``).
            This is the only input that affects the math.
        frame_size: the sub $N, rsp value (e.g. ``0x80``).  Kept
            for backward compatibility with earlier callers and for
            diagnostic display, but **does not affect the result**.

    Returns:
        0 if ``lea_offset % 16 == 0`` (no alignment ``ret`` needed —
        the ROP chain's 2-gadget shape leaves rsp 16-aligned at
        ``system`` entry, which is what do_system's movaps requires).
        1 if ``lea_offset % 16 != 0`` (alignment ``ret`` needed —
        without it, rsp at system entry is 8-mod-16 and movaps
        SIGSEGVs on do_system+0x73).
        1 (conservative default) if ``lea_offset <= 0`` (no frame
        info — preserves v4.0.1 always-align behaviour).

    Examples:
        >>> compute_required_ret_count(lea_offset=0xf)   # rip main
        1
        >>> compute_required_ret_count(lea_offset=0x80)  # level3 vuln_func
        0
    """
    if lea_offset <= 0:
        # No frame information — conservative default
        return 1
    if lea_offset % 16 == 0:
        return 0
    # lea_offset % 16 in {1..15} → 1 (conservative for unusual
    # alignments; future work could handle the {2,4,6,10,12,14}
    # 4-gadget case explicitly)
    return 1


def extract_frame_context(
    program: Path, bit: int = 64,
) -> Optional[FrameContext]:
    """Static analysis: extract the vulnerable function's frame context.

    Parses ``objdump`` disassembly; finds the first function whose
    body contains a ``lea -N(%ebp)`` / ``lea -N(%rbp)`` instruction
    AND a call to one of the dangerous read functions (``read`` /
    ``gets`` / ``fgets`` / ``scanf``); extracts that function's
    ``lea_offset`` and ``sub $N, rsp`` frame size; computes
    ``required_ret_count``.

    Args:
        program: path to the target ELF.
        bit: 32 or 64 (architecture).  Currently 64-bit-only is fully
            supported; 32-bit returns a conservative default
            FrameContext with ``required_ret_count=1``.

    Returns:
        A ``FrameContext`` populated from the disassembly, or ``None``
        if no vulnerable function pattern was found (per
        :func:`recon.asm.asm_stack_overflow` precedent — caller should
        fall back to a safe default like
        ``FrameContext(required_ret_count=1)``).
    """
    if bit != 64:
        # 32-bit alignment math differs (system@plt ABI different);
        # for v4.0.5 we only ship the 64-bit case
        return FrameContext(required_ret_count=1)

    try:
        content = run_objdump_disasm(program, intel=False)
    except Exception:
        return None

    # Find all function headers (with full hex addresses), then split
    # content by them.  We use a line-based split rather than a
    # complex non-greedy regex because hex addresses contain a-f
    # digits which `\d+` cannot match (caught during test authoring).
    func_header_re = re.compile(r"^([0-9a-f]+) <([\w.]+)>:$", re.MULTILINE)
    headers = list(func_header_re.finditer(content))
    for i, hdr in enumerate(headers):
        func_name = hdr.group(2)
        func_addr = int(hdr.group(1), 16)
        body_start = hdr.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(content)
        func_body = content[body_start:body_end]

        if not (("lea" in func_body) and
                any(c in func_body for c in _DANGEROUS_CALLS)):
            continue

        # Extract lea offset (negative offsets like -0x80 are also matched)
        lea_match = _LEA_RE.search(func_body)
        if not lea_match:
            continue
        lea_offset = abs(int(lea_match.group(1), 16))

        # Extract sub $N, rsp frame size.  AT&T syntax variants seen:
        #   sub    $0x10,%rsp         (short form, no space)
        #   sub    $0x388, %rsp       (with comma-space)
        #   add    $0xffffffffffffff80,%rsp   (sign-extended sub)
        # The third form encodes `sub $0x80, %rsp` via a negative 32-bit
        # immediate sign-extended to 64 bits.  We normalise by taking
        # the unsigned lower-32-bit absolute value.
        sub_match = re.search(
            r"sub\s+\$?(0x[0-9a-f]+|\d+)\s*,?\s*%rsp", func_body,
        )
        add_match = re.search(
            r"add\s+\$0x(f{6,8}[0-9a-f]+)\s*,?\s*%rsp", func_body,
        )
        if sub_match:
            tok = sub_match.group(1)
            frame_size = int(tok, 16) if tok.startswith("0x") else int(tok)
        elif add_match:
            # Sign-extended negative value: 0xffffffffffffff80 → -0x80 → 0x80
            tok = add_match.group(1)
            signed = int(tok, 16)
            if signed >= 0x80000000:
                # 32-bit sign-extended — take lower 32 bits and interpret as unsigned
                frame_size = signed & 0xFFFFFFFF
                if frame_size > 0x7FFFFFFF:
                    frame_size = (1 << 32) - frame_size  # convert negative to positive
            else:
                frame_size = signed
        else:
            # No sub → frame is 0
            frame_size = 0

        return FrameContext(
            vuln_func_addr=func_addr,
            lea_offset=lea_offset,
            frame_size=frame_size,
            required_ret_count=compute_required_ret_count(lea_offset=lea_offset),
        )

    return None


__all__ = [
    "FrameContext",
    "compute_required_ret_count",
    "extract_frame_context",
]
