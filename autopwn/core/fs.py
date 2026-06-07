"""core.fs — file system utilities (path, permission, temp workdir).

Refactored from autopwn._legacy (P1.2 + P1.6).

Layer: core (no upward dependency).
"""
from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from autopwn.core.logging import print_debug, print_error


def set_permission(program) -> bool:
    """Set executable permission (0755) on `program`.

    Accepts str or Path. Returns True on success, False on failure.

    P1.2 refactor: was `os.system(f"chmod +755 {program}")` in legacy.
    Switched to `os.chmod` per AGENTS.md §7.2 (P1 reviewer check) and
    rebuild.md §6.2 P1.2 spec example.
    """
    print_debug(f"chmod +x {program}")
    try:
        os.chmod(program, 0o755)
        return True
    except OSError as e:
        print_error(f"Failed to set permissions: {e}")
        return False


def add_current_directory_prefix(program):
    """Add ./ prefix to a program path if not already prefixed.

    Accepts str (or Path-like with __str__). Returns str.
    Preserves the legacy string-based contract — main() passes args.local
    (a str) and downstream code uses string interpolation.
    """
    program = str(program)
    if not program.startswith('./'):
        program = os.path.join('.', program)
    return program


@contextmanager
def temp_workdir():
    """Context manager: chdir into a fresh temp dir, restore cwd on exit.

    Replaces the legacy pattern of scattering ropper.txt / libc_path.txt /
    Information_Collection.txt into the user's cwd. Callers wrap the whole
    recon phase; all tool output that used to land in cwd now lands in
    the temp dir and is cleaned up on exit.

    P1.2: utility added. Adoption happens in P1.5 (runner) / P1.6 (cleanup).
    """
    with tempfile.TemporaryDirectory(prefix="autopwn-") as d:
        old = Path.cwd()
        os.chdir(d)
        try:
            yield Path(d)
        finally:
            os.chdir(old)


def cleanup_core_dumps(cwd: Path = None) -> int:
    """Remove core dump files/directories matching `core*` in `cwd`.

    P1.6: replaces the legacy
        os.system('rm -rf core* 2>/dev/null || del core* 2>nul || true')
    inside the cleanup_core_files background thread. Uses glob +
    os.unlink (files) / shutil.rmtree (directories). Best-effort; errors
    are silently dropped (matches legacy shell `2>/dev/null` behavior).

    Cross-platform: works on Linux (core dumps), macOS (core.NNNN).
    On Windows there's typically no core dump, but the `core*` glob
    is harmless (it just finds nothing to delete).

    Args:
      cwd: directory to scan; defaults to Path.cwd() at call time.

    Returns:
      Count of items removed (files + directories).
    """
    if cwd is None:
        cwd = Path.cwd()
    removed = 0
    for path in cwd.glob("core*"):
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink()
            removed += 1
        except OSError:
            pass  # best-effort; matches legacy 2>/dev/null suppression
    return removed


__all__ = [
    "set_permission",
    "add_current_directory_prefix",
    "temp_workdir",
    "cleanup_core_dumps",
]
