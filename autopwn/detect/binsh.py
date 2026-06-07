"""AutoPwn detect layer: ``/bin/sh`` string detection (P5.4).

Replaces the v3.1 monolith's ``check_binsh_string`` +
``check_binsh`` functions (see ``autopwn/_legacy.py`` L721-741 +
L743-747) with a single typed entry point.  Per ``rebuild.md``
§6.6 P5.4 + ``refactor.md`` §5 mapping table, this is the fourth
detect module in the P5 layer (M2 milestone).

Public API
----------
* :func:`check_binsh` — runs ``strings -n 4 <binary>`` and
  returns ``True`` when ``/bin/sh`` is present in the output.
  Writes the bool into ``ctx.binsh_in_binary`` (in-place) and
  returns the same bool.

Legacy ports (parity only)
--------------------------
* :func:`_legacy_check_binsh_string` — verbatim port of v3.1's
  ``check_binsh_string`` (L721-741).  Has 1 caller
  (``_legacy.py`` L3214, the initial verbose probe).
* :func:`_legacy_check_binsh` — verbatim port of v3.1's
  ``check_binsh`` (L743-747).  Has 1 caller
  (``_legacy.py`` L3320, the no-overflow branch).

Design notes
------------
* P5.4 is the simplest of the 4 detect modules — both source
  functions are 5-20 lines of trivial work.  The public API
  **collapses both into a single function** (returning a bool
  is the union of both v3.1 contracts); the legacy ports
  preserve v3.1's two-function split for spec parity.
* The public function mutates ``ctx.binsh_in_binary`` (in-place)
  and returns the same bool.  This is consistent with P5.1
  (``ctx.padding``) and P5.3 (``ctx.canary``).
* Implementation reuses :func:`autopwn.core.runner.run_strings`
  (P1.3a wrapper, no ``os.system("strings X | grep /bin/sh > file")``
  shell-out).  The default ``min_len=4`` matches v3.1's
  behavior of scanning strings of 4+ chars (binutils default).
"""
from __future__ import annotations

from pathlib import Path

from autopwn.context import ExploitContext
from autopwn.core.runner import run_strings


# v3.1 L739: the exact substring checked.
_BINSH = "/bin/sh"


def check_binsh(ctx: ExploitContext, program: Path) -> bool:
    """Return ``True`` when the target binary contains a ``/bin/sh`` string.

    Mirrors v3.1's ``check_binsh`` (``_legacy.py`` L743-747):
    runs ``strings`` (via :func:`core.runner.run_strings`) and
    checks for the ``/bin/sh`` substring.  Returns the bool and
    also writes it into ``ctx.binsh_in_binary`` (in-place) so
    P7 strategies can read it from ctx.

    Args:
        ctx: the run's :class:`ExploitContext`.  ``ctx.binsh_in_binary``
            is **overwritten** with the discovered bool.
        program: path to the target ELF.

    Returns:
        ``True`` if the binary contains ``/bin/sh`` (a libc
        import typically provides this); ``False`` otherwise.
    """
    content = run_strings(program)
    found = _BINSH in content
    ctx.binsh_in_binary = found
    return found


# =====================================================================
# Legacy ports (parity only) — preserve v3.1's print_* output verbatim
# =====================================================================

def _legacy_check_binsh_string(program: Path) -> bool:
    """[OBSOLETE — prefer :func:`check_binsh`] Verbatim port of v3.1's ``check_binsh_string``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3214).
    Preserves v3.1 print behavior byte-for-byte:
    ``print_info`` "checking for /bin/sh string" +
    ``print_success`` "/bin/sh string found in binary" +
    ``print_warning`` "/bin/sh string not found in binary" +
    ``print_error`` on failure.

    Returns:
        ``True`` if ``/bin/sh`` is found, ``False`` otherwise.
    """
    from autopwn.core.logging import (
        print_info, print_success, print_warning, print_error,
    )

    print_info("checking for /bin/sh string")
    try:
        content = run_strings(program)
        if _BINSH in content:
            print_success("/bin/sh string found in binary")
            return True
        else:
            print_warning("/bin/sh string not found in binary")
            return False
    except Exception as e:
        print_error(f"failed to check for /bin/sh string: {e}")
        return False


def _legacy_check_binsh(program: Path) -> bool:
    """[OBSOLETE — prefer :func:`check_binsh`] Verbatim port of v3.1's ``check_binsh``.

    Retained for spec parity; has 1 caller (``_legacy.py`` L3320).
    Returns the bool only — no ``print_*`` output (the
    ``autopwn_base.py``-compatible minimal API).

    Returns:
        ``True`` if ``/bin/sh`` is found, ``False`` otherwise.
    """
    return _BINSH in run_strings(program)


__all__ = [
    "check_binsh",
    "_legacy_check_binsh_string",
    "_legacy_check_binsh",
]
