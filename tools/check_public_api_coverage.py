#!/usr/bin/env python3
"""P6.9: Public API coverage verification (P6.9 acceptance criterion).

Per ``rebuild.md`` §6.7 P6.9: the primitive layer's public API
(non-``_legacy_*`` functions + classes) must achieve ≥ 80%
line coverage.  The legacy ports are explicitly excluded
because they're OBSOLETE and only kept for P8 byte-level
parity with the v3.1 monolith.

Usage::

    # 1. Run tests with coverage JSON output
    pytest tests/ -m "not integration" \\
        --cov=autopwn.primitives \\
        --cov-report=json \\
        --no-header -q

    # 2. Run this script
    python3 tools/check_public_api_coverage.py

The script reads ``coverage.json`` (default pytest-cov
output) and reports per-file public API coverage.  Exits 0 if
all files ≥ 80%, 1 otherwise.

Why a separate script
---------------------
``pytest-cov`` measures coverage over the whole file,
including legacy ports.  A blanket 80% threshold on raw
coverage would fail the P6.9 acceptance criterion because
the legacy ports are ~50% of each module's lines and are
not exercised by tests (they're deliberately preserved as
byte-level parity ports, not production code).

This script measures coverage on the **public API only**
(everything except ``_legacy_*`` functions), which is the
spec-correct metric.  The legacy ports can be measured
separately if needed (they're not part of the P6
acceptance).

Output
------
The script prints a table::

    File                                     Public%    Lines
    -----------------------------------------------------------------------
    base.py                                      93%     14/15
    execve_syscall.py                           100%     39/39
    fmtstr.py                                   100%     33/33
    pie_backdoor.py                              97%     37/38
    ret2libc_put.py                              91%     75/82
    ret2libc_write.py                            91%     75/82
    ret2system.py                               100%     42/42
    shellcode.py                                 98%     40/41
    -----------------------------------------------------------------------
    OVERALL public API                          95%    355/372
    ✅ PASS — all files ≥ 80%

Exit code 0 on PASS, 1 on FAIL.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COVERAGE_FILE = ROOT / "coverage.json"
PRIMITIVES_DIR = ROOT / "autopwn" / "primitives"
THRESHOLD_PCT = 80


def parse_legacy_lines(py_file: Path) -> set[int]:
    """Return the line numbers of all ``_legacy_*`` functions in ``py_file``."""
    with open(py_file) as f:
        tree = ast.parse(f.read())

    legacy_lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_legacy_"):
                for line in range(node.lineno, node.end_lineno + 1):
                    legacy_lines.add(line)
    return legacy_lines


def parse_public_lines(py_file: Path) -> set[int]:
    """Return the line numbers of all public (non-legacy) code in ``py_file``.

    "Public" here means: top-level public functions/classes, class
    methods, and module-level constants/imports.  Excludes
    ``_legacy_*`` functions and their entire bodies.
    """
    with open(py_file) as f:
        tree = ast.parse(f.read())

    public_lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_legacy_"):
                for line in range(node.lineno, node.end_lineno + 1):
                    public_lines.add(line)
        elif isinstance(node, ast.ClassDef):
            for line in range(node.lineno, node.end_lineno + 1):
                public_lines.add(line)
        else:
            # Module-level (Assign, Import, etc.)
            if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                for line in range(node.lineno, node.end_lineno + 1):
                    public_lines.add(line)
    return public_lines


def main() -> int:
    if not COVERAGE_FILE.exists():
        print(f"ERROR: {COVERAGE_FILE} not found.", file=sys.stderr)
        print("Run pytest with --cov-report=json first:", file=sys.stderr)
        print("  pytest tests/ -m 'not integration' \\", file=sys.stderr)
        print("        --cov=autopwn.primitives --cov-report=json", file=sys.stderr)
        return 1

    with open(COVERAGE_FILE) as f:
        data = json.load(f)

    files = data["files"]

    # coverage.json keys are relative to the cwd where pytest was
    # run (usually the project root).  Build a lookup dict keyed
    # by basename for robustness against relative-vs-absolute path
    # mismatch.
    files_by_basename: dict[str, tuple[str, dict]] = {}
    for path, fd in files.items():
        files_by_basename[Path(path).name] = (path, fd)

    print(f"\n{'File':<40} {'Public%':<10} {'Lines':<12}")
    print("-" * 65)

    total_pub_exec = 0
    total_pub_cov = 0
    failures: list[tuple[str, int, int]] = []

    for py_file in sorted(PRIMITIVES_DIR.glob("*.py")):
        if py_file.name == "__init__.py":
            continue

        if py_file.name not in files_by_basename:
            continue

        rel_path, fd = files_by_basename[py_file.name]
        executed = set(fd["executed_lines"])
        missing = set(fd["missing_lines"])
        all_exec = executed | missing

        public_lines = parse_public_lines(py_file)
        pub_exec = all_exec & public_lines
        pub_cov = pub_exec & executed

        total_pub_exec += len(pub_exec)
        total_pub_cov += len(pub_cov)

        if not pub_exec:
            continue

        pct = 100 * len(pub_cov) / len(pub_exec)
        status = "" if pct >= THRESHOLD_PCT else " ❌"
        print(f"{py_file.name:<40} {pct:>6.0f}%   {len(pub_cov):>4}/{len(pub_exec):<4}{status}")

        if pct < THRESHOLD_PCT:
            failures.append((py_file.name, len(pub_cov), len(pub_exec)))

    overall = 100 * total_pub_cov / total_pub_exec if total_pub_exec else 0
    print("-" * 65)
    print(f"{'OVERALL public API':<40} {overall:>6.0f}%   {total_pub_cov:>4}/{total_pub_exec:<4}")

    if failures:
        print(f"\n❌ FAIL — {len(failures)} file(s) below {THRESHOLD_PCT}% threshold:")
        for name, cov, total in failures:
            pct = 100 * cov / total
            print(f"   {name}: {pct:.0f}% ({cov}/{total})")
        return 1

    if overall >= THRESHOLD_PCT:
        print(f"\n✅ PASS — all files ≥ {THRESHOLD_PCT}% (overall {overall:.0f}%)")
        return 0
    else:
        print(f"\n❌ FAIL — overall {overall:.0f}% < {THRESHOLD_PCT}%")
        return 1


if __name__ == "__main__":
    sys.exit(main())
