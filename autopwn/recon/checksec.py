"""AutoPwn recon layer: ``checksec`` binary introspection (P4.1).

Replaces the v3.1 monolith's ``collect_binary_info`` + ``display_binary_info``
functions (see ``autopwn/_legacy.py`` L245-330) with a typed, side-effect-free
implementation.  Per ``rebuild.md`` §6.5 P4.1 + ``refactor.md`` §5 mapping
table, this is the first recon module in the P4 layer (M2 milestone).

Public API
----------
* :func:`collect`  — pure: ``checksec`` output → ``BinaryInfo`` dataclass.
* :func:`display`  — prints a section header + 3-column table from a
  ``BinaryInfo``.  Identical visual format to v3.1's
  ``display_binary_info``.

Legacy port (parity only)
-------------------------
* :func:`_legacy_information_collection` — verbatim port of v3.1's
  ``Information_Collection`` (L184-243).  Retained for spec parity
  (``rebuild.md`` §4.5 P4.1 mentions all three source functions);
  has **zero callers** in the codebase — main() uses
  ``collect_binary_info`` (the v2 version that returns a dict), which
  itself is now shadowed by the typed :func:`collect` above.  Underscore
  prefix signals "not the public API".

Design notes
------------
* :func:`collect` is **pure**: no ``print_*`` calls, no ``globals()``
  writes, no file I/O.  This is the only way it can be unit-tested
  in isolation under P9.  The legacy ``collect_binary_info`` returned
  a 5-tuple ``(dict, stack, rwx, bit, pie)`` — error-prone and dict
  mutation prone; the new typed ``BinaryInfo`` is slot-locked and
  frozen-by-default per ``context.py`` P2.1 convention.
* :func:`display` reuses ``core.logging`` (``print_section_header``,
  ``print_table_header``, ``print_table_row``) so the visual style
  matches v3.1 byte-for-byte.  Colors are mapped via the same risk
  palette (``HIGH``→``ERROR``, ``MEDIUM``→``WARNING``, ``LOW``→``SUCCESS``).
* The ``Arch:`` regex is compiled once at module load (P2.1 / P3.1
  pattern: avoid re-compiling on every call).
* This PR does **not** replace ``_legacy.py`` callers.  Wiring
  ``recon.collect()`` into the orchestrator is the responsibility of
  P8 (``orchestrator.py``).  The new module is a **parallel, testable**
  implementation that produces an equivalent ``BinaryInfo``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple

from autopwn.context import BinaryInfo
from autopwn.core.logging import (
    Colors,
    print_info,
    print_section_header,
    print_table_header,
    print_table_row,
)
from autopwn.core.runner import run_checksec


# ``Arch:       i386-32-little``  /  ``Arch:       amd64-64-little``
# Group(1) is the arch string.  Compiled once at import time so each
# call to ``collect()`` does a single ``re.search`` over the output.
_ARCH_RE = re.compile(r"Arch:\s+(\S+)")

# ``Stripped:   Yes``  /  ``Stripped:   No`` — see DEV-1 in §6.5 P4.1
# implementation record.  The literal spec field
# ``"Stripped" in out`` is a **label-vs-value bug** (checksec's output
# always contains the ``Stripped:`` label regardless of value, so
# ``"Stripped" in out`` returns True even for un-stripped binaries).
# We use a regex that captures the *value* after the colon so the
# boolean is correct in all cases.
_STRIPPED_RE = re.compile(r"Stripped:\s*(\S+)")


def collect(program: Path) -> BinaryInfo:
    """Probe the target ELF with ``checksec`` and return a typed ``BinaryInfo``.

    Pure function — no side effects, no logging, no I/O beyond the
    single ``checksec`` subprocess invocation.  Equivalent to v3.1's
    ``collect_binary_info`` (``_legacy.py`` L245-301) but typed: returns
    a ``BinaryInfo`` dataclass instead of a 5-tuple.

    The mapping from ``checksec`` textual output to ``BinaryInfo``
    fields (preserved bit-for-bit from v3.1 logic):

    * ``Arch:``         → ``bit``         (64 if "64" in arch else 32)
    * ``Stack:``        → ``stack_canary`` (True iff "Canary found")
    * ``PIE:``          → ``pie``         (True iff "PIE enabled")
    * ``NX:``           → ``nx``          (True iff "NX enabled")
    * ``RELRO:``        → ``relro``       ("Full" / "Partial" / "No")
    * ``RWX:``          → ``rwx_segments`` (True iff "Has RWX segments")
    * ``Stripped:``     → ``stripped``    (True iff "Stripped" present)

    Args:
        program: path to the target ELF.

    Returns:
        A fully populated ``BinaryInfo``.  Missing fields default to
        ``False`` / ``"No"`` / ``32`` so the dataclass is always
        constructible from any (even malformed) ``checksec`` output.

    Raises:
        ``autopwn.core.runner.ToolError``: propagated from
            ``run_checksec`` when the underlying ``checksec`` binary
            exits non-zero.
    """
    out = run_checksec(program)

    arch_match = _ARCH_RE.search(out)
    arch = arch_match.group(1) if arch_match else ""
    bit = 64 if "64" in arch else 32  # default to 32 when arch unknown

    # Stripped value parsing — see DEV-1 in §6.5 P4.1 implementation
    # record.  ``"Stripped" in out`` is wrong (matches the label, not
    # the value); we extract the actual value and compare to "Yes".
    stripped_match = _STRIPPED_RE.search(out)
    stripped = bool(stripped_match and stripped_match.group(1) == "Yes")

    return BinaryInfo(
        path=program,
        bit=bit,
        stack_canary="Canary found" in out,
        pie="PIE enabled" in out,
        nx="NX enabled" in out,
        relro=(
            "Full"
            if "Full RELRO" in out
            else "Partial"
            if "Partial RELRO" in out
            else "No"
        ),
        rwx_segments="Has RWX segments" in out,
        stripped=stripped,
    )


def display(info: BinaryInfo) -> None:
    """Print the security analysis table for a ``BinaryInfo``.

    Identical visual format to v3.1's ``display_binary_info``
    (``_legacy.py`` L303-330): a section header followed by a
    3-column table (Feature / Status / Risk Level) with color-coded
    risk column.  Risk palette is the legacy map:

      ``HIGH``   → ``Colors.ERROR``    (red)
      ``MEDIUM`` → ``Colors.WARNING``  (yellow)
      ``LOW``    → ``Colors.SUCCESS``  (green)
      ``INFO``   → ``Colors.INFO``     (blue)

    The status column strings are reconstructed from the typed fields
    (the legacy code stored the raw ``checksec`` line which included
    the PIE base address — we drop that detail since ``BinaryInfo``
    doesn't carry it; the table is informational only, the real
    exploit logic reads ``info.pie`` as a bool).

    Args:
        info: a populated ``BinaryInfo`` (typically from :func:`collect`).
    """
    print_section_header("BINARY SECURITY ANALYSIS")
    headers = ["Feature", "Status", "Risk Level"]
    print_table_header(headers)

    risk_colors = {
        "HIGH": Colors.ERROR,
        "MEDIUM": Colors.WARNING,
        "LOW": Colors.SUCCESS,
        "INFO": Colors.INFO,
    }

    security_analysis = {
        "RELRO": (
            "MEDIUM" if "Partial" in info.relro else "LOW",
            info.relro,
        ),
        "Stack Canary": (
            "HIGH" if not info.stack_canary else "LOW",
            "Canary found" if info.stack_canary else "No canary found",
        ),
        "NX Bit": (
            "HIGH" if not info.nx else "LOW",
            "NX enabled" if info.nx else "NX disabled",
        ),
        "PIE": (
            "MEDIUM" if not info.pie else "LOW",
            "PIE enabled" if info.pie else "No PIE",
        ),
        "RWX Segments": (
            "HIGH" if info.rwx_segments else "LOW",
            "Has RWX segments" if info.rwx_segments else "No RWX segments",
        ),
    }

    for feature, (risk, status) in security_analysis.items():
        colors = [Colors.END, Colors.END, risk_colors.get(risk, Colors.END)]
        print_table_row([feature, status, risk], colors)
    print()


def _legacy_information_collection(
    program: Path,
) -> Tuple[int, int, int, Optional[int]]:
    """[OBSOLETE — prefer :func:`collect`] Verbatim port of v3.1's ``Information_Collection``.

    Retained for spec parity (``rebuild.md`` §4.5 P4.1 mentions all
    three source functions; even though this one has zero callers, a
    spec-compliant refactor must "no information loss").  Underscore
    prefix marks it as not part of the public API.

    Behavior matches the v3.1 original (``_legacy.py`` L184-243)
    byte-for-byte, including the per-field ``print_info`` calls that
    the original emitted during probing.  Returns the same
    ``(stack, rwx, bit, pie)`` 4-tuple that v3.1 did, where:

      * ``stack`` — 0 (no canary) / 1 (canary) / 2 (executable)
      * ``rwx``   — 0 / 1
      * ``bit``   — 32 / 64
      * ``pie``   — None / 1
    """
    try:
        out = run_checksec(program)
        info_dict: dict = {}

        arch_match = _ARCH_RE.search(out)
        if arch_match:
            arch = arch_match.group(1)
            if "64" in arch:
                info_dict["bit"] = 64
            elif "32" in arch:
                info_dict["bit"] = 32

        for key in ("RELRO", "Stack", "NX", "PIE", "Stripped", "RWX"):
            for line in out.splitlines():
                if key in line and ":" in line:
                    info_dict[key] = line.split(":", 1)[1].strip()
                    break

        stack = 0
        if info_dict.get("Stack") == "No canary found":
            stack = 0
        elif info_dict.get("Stack") == "Canary found":
            stack = 1
        elif info_dict.get("Stack") == "Executable":
            stack = 2

        rwx = 1 if info_dict.get("RWX") == "Has RWX segments" else 0

        pie: Optional[int] = None
        if info_dict.get("PIE") == "PIE enabled":
            pie = 1

        # v3.1 emitted one print_info per parsed field.  Preserved for
        # fidelity; callers (none in the codebase) will see the same
        # interleaved output as the legacy code.
        for key, value in info_dict.items():
            print_info(f"{key}: {Colors.YELLOW}{value}{Colors.END}")

        return stack, rwx, info_dict.get("bit", 32), pie

    except Exception as e:
        print_info(f"failed to collect binary information: {e}")
        return 0, 0, 32, None


__all__ = ["collect", "display", "_legacy_information_collection"]
