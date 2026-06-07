"""core.runner — subprocess wrappers for external tools.

Refactored from autopwn._legacy (P1.3). P1.5 will switch call sites from
`os.system(\"tool ... > file\")` patterns to these in-process wrappers,
ending the cwd pollution and the 15 os.system shell-outs.

Layer: core (no upward dependency). Sibling to core.logging and core.fs
within the same layer (can import from them).
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class ToolError(RuntimeError):
    """Raised when a recon tool fails (e.g., checksec exits non-zero)."""


def run_checksec(program) -> str:
    """Run `checksec` on `program` and return combined output.

    checksec (pwntools) writes its banner + analysis to stderr, not
    stdout. The legacy `os.system("checksec X > file 2>&1")` combined
    both streams. We replicate that here by returning `stdout + stderr`.

    Raises ToolError on non-zero returncode (checksec must succeed for
    recon to make sense; other tools degrade gracefully below).
    """
    cp = subprocess.run(
        ["checksec", str(program)],
        capture_output=True, text=True, check=False,
    )
    if cp.returncode != 0:
        raise ToolError(f"checksec failed (rc={cp.returncode}): {cp.stderr.strip()}")
    return cp.stdout + cp.stderr


def run_ropper(program, search: str) -> str:
    """Run `ropper --file X --search 'Y' --nocolor` and return combined output.

    ropper writes matches to stdout and a banner to stderr. Legacy
    `os.system("ropper ... > file 2>&1")` combined both; we do the same.
    Do not raise on rc != 0 (ropper may exit non-zero on internal errors
    but still return useful partial output).
    """
    cp = subprocess.run(
        ["ropper", "--file", str(program), "--search", search, "--nocolor"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout + cp.stderr


def run_objdump_disasm(program) -> str:
    """Run `objdump -d -M intel X --no-show-raw-insn` and return stdout.

    objdump writes only to stdout (no banner on stderr). Intel syntax +
    no-raw-insn matches the spec in rebuild.md §6.2 P1.3.

    L580 in _legacy uses the basic `objdump -d`; P1.5 may use this same
    function for both since the extra flags are output-only and produce
    nicer (lossless) disassembly.
    """
    cp = subprocess.run(
        ["objdump", "-d", "-M", "intel", str(program), "--no-show-raw-insn"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


def run_ldd(program) -> str:
    """Run `ldd X` and return stdout.

    ldd writes only to stdout. L360 in _legacy pipes through `awk` to
    strip leading whitespace; P1.5 will do that in Python (split + strip),
    not in shell.
    """
    cp = subprocess.run(
        ["ldd", str(program)],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


__all__ = [
    "ToolError",
    "run_checksec", "run_ropper", "run_objdump_disasm", "run_ldd",
]
