"""AutoPwn recon layer: libc path detection (P4.2).

Replaces the v3.1 monolith's ``detect_libc`` + ``ldd_libc`` functions
(see ``autopwn/_legacy.py`` L132-182) with a single typed entry point
that returns a :class:`autopwn.context.LibcInfo` dataclass.  Per
``rebuild.md`` §6.5 P4.2 + ``refactor.md`` §5 mapping table, this is
the second recon module in the P4 layer (M2 milestone).

Public API
----------
* :func:`detect` — pure: ``ctx`` + ``program`` → :class:`LibcInfo`
  dataclass.  Resolution order: user override (``ctx.libc.path``) →
  auto-detect via ``ldd`` → empty :class:`LibcInfo`.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_detect_libc` — verbatim port of v3.1's
  ``detect_libc`` (L132-158).  Has 1 caller (``_legacy.py`` L3119);
  retained for spec parity while :func:`detect` is the new public API.
* :func:`_legacy_ldd_libc` — verbatim port of v3.1's ``ldd_libc``
  (L160-182).  Has **zero callers** in the codebase (P1.5 found it
  dead).  Underscore prefix marks it as not part of the public API.

Design notes
------------
* :func:`detect` is **pure** (no ``print_*``, no ``globals()`` writes,
  no file I/O).  Parsing logic factored out into the private
  :func:`_parse_libc_path` helper.  The user-facing messages
  ("detecting libc path automatically" / "libc path detected: …") and
  the §2.6.1 key-node ``print_debug`` call are intentionally **not**
  emitted here — the new function is a parallel implementation; the
  production ``_legacy.py`` path still emits those messages so the
  v3.1 ↔ v4.0 log diff stays at 96% consistency.
* The ``ELF`` is **not** loaded here.  v3.1 lazily loaded it inside
  ``ret2libc_write_x64`` (L906-908); keeping the same lazy pattern
  means :class:`LibcInfo.elf` stays ``None`` until a strategy needs
  it.  This avoids an unnecessary pwntools import during recon.
* Detection is non-strict: missing ``ldd`` output or no ``libc.so.6``
  line returns :class:`LibcInfo` (with ``path=None``); the caller
  decides whether to fall back to ``LibcSearcher`` (P7 ret2libc
  strategies handle that branch).
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from autopwn.context import ExploitContext, LibcInfo
from autopwn.core.runner import run_ldd


def _parse_libc_path(ldd_out: str) -> Optional[str]:
    """Extract the libc.so.6 path from ``ldd`` output.

    Parses each line for ``libc.so.6`` (avoiding false positives from
    ``libc++.so`` or ``libcrypto.so`` by exact-substring match on the
    full shared-object name), splits on ``=>`` (v3.1 L146 / L170
    parser), and returns the first whitespace-separated token on the
    right side.  Returns ``None`` when the libc line is not found
    or the ``=>`` separator is absent (e.g. statically-linked
    binaries produce ``libc.so.6`` without a path).

    Args:
        ldd_out: raw ``ldd <program>`` output (stdout).

    Returns:
        The libc filesystem path (str), or ``None`` if no path is
        resolvable.
    """
    for line in ldd_out.splitlines():
        if "libc.so.6" in line:
            parts = line.strip().split("=>")
            if len(parts) > 1:
                return parts[1].strip().split()[0]
    return None


def detect(ctx: ExploitContext, program: Path) -> LibcInfo:
    """Detect libc for the target binary and return a typed :class:`LibcInfo`.

    Resolution order (matches v3.1 ``main()`` L3111-3119 logic):

    1. **User override**: if ``ctx.libc.path`` is set (the user passed
       ``-libc /path/to/libc.so``), use it as-is.  v3.1's main()
       validates the file exists and exits with code 1 on missing
       path; that preflight is the responsibility of
       :func:`autopwn.context.ExploitContext.from_args` (P2.2), so by
       the time :func:`detect` runs the path is guaranteed to exist
       (or :class:`ContextError` has already been raised).
    2. **Auto-detect** via ``ldd``: runs :func:`core.runner.run_ldd`
       and parses for the ``libc.so.6 => /path/to/libc.so.6`` line.
    3. **Not found**: returns :class:`LibcInfo` (with ``path=None``).
       The caller is responsible for falling back to ``LibcSearcher``
       (P7 ret2libc strategies).

    Pure function: no side effects, no logging, no I/O beyond the
    single :func:`run_ldd` subprocess invocation.  Does **not** load
    the libc ELF — that stays lazy in P7 strategy code.

    Args:
        ctx: an :class:`ExploitContext`.  Only ``ctx.libc.path`` is
            consulted; everything else is ignored.
        program: path to the target ELF.

    Returns:
        A populated :class:`LibcInfo`.  When detection succeeds,
        ``path`` is the absolute path to the libc.  When the user
        supplied a custom libc, ``path`` is that path verbatim.
        When neither is available, ``path`` is ``None``.
    """
    # 1) User-provided libc takes precedence (matches main() L3111-3116)
    if ctx.libc.path is not None:
        return LibcInfo(path=ctx.libc.path)

    # 2) Auto-detect via ldd (matches main() L3117-3119 + detect_libc L142-150)
    ldd_out = run_ldd(program)
    libc_path_str = _parse_libc_path(ldd_out)
    if libc_path_str is not None:
        return LibcInfo(path=Path(libc_path_str))

    # 3) Not found (matches detect_libc L152-153 silent-fail path)
    return LibcInfo()


def _legacy_detect_libc(program: Path) -> Optional[str]:
    """[OBSOLETE — prefer :func:`detect`] Verbatim port of v3.1's ``detect_libc``.

    Retained for spec parity (``rebuild.md`` §4.5 P4.2 merges both
    legacy functions; the §6.5 P4.2 implementation record shows
    that we still expose the legacy shape as a private helper).
    Underscore prefix marks it as not part of the public API.

    This is the **only** libc-detection function with a real
    caller in the legacy code (``_legacy.py`` L3119); the new
    :func:`detect` is wired into the orchestrator at P8.

    Preserves the v3.1 print behavior byte-for-byte:

      * ``print_debug`` (P0.7 §2.6.1 关键节点)
      * ``print_info`` "detecting libc path automatically"
      * ``print_success`` "libc path detected: …"
      * ``print_warning`` "libc path not found in ldd output"
      * ``print_error`` "failed to detect libc: …"

    Returns:
        The libc path (str) on success, or ``None`` on any failure.
    """
    # Local import keeps this module pwntools-free at import time.
    from autopwn.core.logging import (
        Colors, print_debug, print_info, print_success,
        print_warning, print_error,
    )

    print_debug(f"libc: detecting via ldd for {program}")
    print_info("detecting libc path automatically")
    libc_path: Optional[str] = None

    try:
        ldd_out = run_ldd(program)
        libc_path = _parse_libc_path(ldd_out)
        if libc_path:
            print_success(
                f"libc path detected: {Colors.YELLOW}{libc_path}{Colors.END}"
            )
        else:
            print_warning("libc path not found in ldd output")
    except Exception as e:
        print_error(f"failed to detect libc: {e}")

    return libc_path


def _legacy_ldd_libc(program: Path) -> Optional[str]:
    """[OBSOLETE — prefer :func:`detect`] Verbatim port of v3.1's ``ldd_libc``.

    Retained for spec parity (``rebuild.md`` §4.5 P4.2 mentions both
    functions).  Has **zero callers** in the codebase; underscore
    prefix marks it as not part of the public API.

    Note on port fidelity: v3.1 used ``subprocess.run(['ldd', program],
    capture_output=True, text=True)`` directly.  We preserve that
    direct subprocess call here (rather than going through
    :func:`core.runner.run_ldd`) to keep this port byte-for-byte
    equivalent to the original — so a future git-archaeology session
    that diffs the new module against ``_legacy.py`` L160-182 sees
    the same control flow, not a refactored version.

    Returns:
        The libc path (str) on success, or ``None`` on any failure.
    """
    from autopwn.core.logging import (
        Colors, print_info, print_warning, print_error,
    )

    libc_path: Optional[str] = None
    try:
        result = subprocess.run(
            ["ldd", str(program)], capture_output=True, text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "libc.so.6" in line:
                    parts = line.split("=>")
                    if len(parts) > 1:
                        libc_path = parts[1].strip().split()[0]
                        print_info(
                            f"automatically detected libc: "
                            f"{Colors.YELLOW}{libc_path}{Colors.END}"
                        )
                        break

        if not libc_path:
            print_warning("libc path not found automatically")
    except Exception as e:
        print_error(f"failed to detect libc: {e}")

    return libc_path


__all__ = ["detect", "_legacy_detect_libc", "_legacy_ldd_libc"]
