#!/usr/bin/env python3
"""M2: Recon public API coverage verification.

Per ``rebuild.md`` §4.10 P9.6: the ``recon/`` public API
must achieve ≥ 60% line coverage.  This script gates CI on
that threshold.

Usage::

    # 1. Run recon unit tests with coverage JSON output
    pytest tests/unit/recon/ \\
        --cov=autopwn.recon \\
        --cov-report=json \\
        --no-header -q

    # 2. Run this script
    python3 tools/check_recon_coverage.py

Why a separate script (vs P6.9's check_public_api_coverage.py)
-------------------------------------------------------------
* P6.9's script excludes ``_legacy_*`` lines from the public-API
  tally (they're obsolete byte-level parity ports).  ``recon/``
  has no such legacy naming — all top-level functions/classes
  are pure production code.
* P6.9's threshold is 80%; recon's is 60% (per §4.10 P9.6 spec).
  Recon modules are thin wrappers around ``run_*`` calls, so
  their *raw* coverage is naturally lower than the primitive
  layer's.
* Separate script keeps the P6 (primitive) and M2 (recon)
  coverage gates independent — CI can run both in series
  without coupling.

Exit code 0 on PASS, 1 on FAIL.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COVERAGE_FILE = ROOT / "coverage.json"
RECON_DIR = ROOT / "autopwn" / "recon"
THRESHOLD_PCT = 60


def parse_public_lines(py_file: Path) -> set[int]:
    """Return the line numbers of all public (non-private) code in ``py_file``.

    "Public" here means: top-level public functions/classes (not
    starting with ``_``), class methods, and module-level
    constants/imports.  Recon has no ``_legacy_*`` convention, so
    the rule is simpler: exclude only ``_``-prefixed names.
    """
    with open(py_file) as f:
        tree = ast.parse(f.read())

    public_lines: set[int] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                for line in range(node.lineno, node.end_lineno + 1):
                    public_lines.add(line)
        elif isinstance(node, ast.ClassDef):
            if not node.name.startswith("_"):
                for line in range(node.lineno, node.end_lineno + 1):
                    public_lines.add(line)
        else:
            # Module-level (Assign, Import, etc.) — include if it has line numbers
            if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                for line in range(node.lineno, node.end_lineno + 1):
                    public_lines.add(line)
    return public_lines


def main() -> int:
    if not COVERAGE_FILE.exists():
        print(f"ERROR: {COVERAGE_FILE} not found.", file=sys.stderr)
        print("Run pytest with --cov-report=json first:", file=sys.stderr)
        print("  pytest tests/unit/recon/ \\", file=sys.stderr)
        print("        --cov=autopwn.recon --cov-report=json", file=sys.stderr)
        return 1

    with open(COVERAGE_FILE) as f:
        data = json.load(f)

    files = data["files"]

    files_by_basename: dict[str, dict] = {}
    for path, fd in files.items():
        files_by_basename[Path(path).name] = fd

    print(f"\n{'File':<40} {'Public%':<10} {'Lines':<12}")
    print("-" * 65)

    total_pub_exec = 0
    total_pub_cov = 0
    failures: list[tuple[str, int, int]] = []

    for py_file in sorted(RECON_DIR.glob("*.py")):
        if py_file.name == "__init__.py":
            continue

        if py_file.name not in files_by_basename:
            print(f"{py_file.name:<40} {'(no coverage data)':<10}")
            continue

        fd = files_by_basename[py_file.name]
        executed = set(fd["executed_lines"])
        missing = set(fd["missing_lines"])
        all_exec = executed | missing

        public_lines = parse_public_lines(py_file)
        pub_exec = all_exec & public_lines
        pub_cov = pub_exec & executed

        total_pub_exec += len(pub_exec)
        total_pub_cov += len(pub_cov)

        if not pub_exec:
            print(f"{py_file.name:<40} {'(no public lines)':<10}")
            continue

        pct = 100 * len(pub_cov) / len(pub_exec)
        status = "" if pct >= THRESHOLD_PCT else " ❌"
        print(f"{py_file.name:<40} {pct:>6.0f}%   {len(pub_cov):>4}/{len(pub_exec):<4}{status}")

        if pct < THRESHOLD_PCT:
            failures.append((py_file.name, len(pub_cov), len(pub_exec)))

    overall = 100 * total_pub_cov / total_pub_exec if total_pub_exec else 0
    print("-" * 65)
    print(f"{'OVERALL recon public API':<40} {overall:>6.0f}%   {total_pub_cov:>4}/{total_pub_exec:<4}")

    if failures:
        print(f"\nFAIL — {len(failures)} file(s) below {THRESHOLD_PCT}% threshold:")
        for name, cov, total in failures:
            pct = 100 * cov / total
            print(f"   {name}: {pct:.0f}% ({cov}/{total})")
        return 1

    if overall >= THRESHOLD_PCT:
        print(f"\nPASS — all files ≥ {THRESHOLD_PCT}% (overall {overall:.0f}%)")
        return 0
    else:
        print(f"\nFAIL — overall {overall:.0f}% < {THRESHOLD_PCT}%")
        return 1


if __name__ == "__main__":
    sys.exit(main())