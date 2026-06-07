"""AutoPwn report layer — Report package entry point.

See ``rebuild.md`` §3 分层依赖图 for this layer's role.

Adoption roadmap (see ``rebuild.md`` §4.4):
  * P3.1 (✅) — :class:`ExploitInfo` dataclass.
  * P3.2 (✅) — :func:`generate_docx` (moved from ``_legacy``).
  * P3.3 (✅) — :func:`generate_code` (moved from ``_legacy``).
  * P3.4 (✅) — :func:`record_success` (subscriber orchestrator).
  * P3.5 (this PR) — CLI ``--no-report`` / ``--report-dir`` flags; ctx
    threaded into :func:`record_success` via a module-level carrier.
  * P3.6 (✅) — ``try/except ImportError`` markdown fallback for docx.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from autopwn.context import ExploitContext
from autopwn.core.logging import print_critical
from autopwn.report.code import generate_code
from autopwn.report.docx import generate_docx
from autopwn.report.model import ExploitInfo

__all__: list[str] = [
    "ExploitInfo",
    "generate_code",
    "generate_docx",
    "record_success",
    "set_current_ctx",
]


# P3.5: module-level carrier for the current ExploitContext.  Set by
# main() at startup, read by record_success() at the success path.
# This is an intentional transitional measure: threading ``ctx`` through
# 14 caller signatures of ``_legacy.handle_exploitation_success`` is
# invasive (touches 10 strategy functions).  P8 will replace this with
# direct ctx plumbing once the strategies are refactored to P7's
# ExploitStrategy abstract class.
_current_ctx: Optional[ExploitContext] = None


def set_current_ctx(ctx: Optional[ExploitContext]) -> None:
    """Set the module-level ``_current_ctx`` used by :func:`record_success`.

    Called by ``_legacy.main()`` after ``ExploitContext.from_args(args)``.
    Pass ``None`` to clear (used in tests).

    P8.5 will delete this function along with the rest of the
    transitional carrier.
    """
    global _current_ctx
    _current_ctx = ctx


def record_success(info: ExploitInfo) -> None:
    """Subscriber orchestrator for a successful exploitation run.

    P3.4 introduced this as the canonical success-path entry point.
    P3.5 extends it to honor the new ``--no-report`` and
    ``--report-dir`` CLI flags by reading from
    :data:`_current_ctx` (set by :func:`set_current_ctx` from main()).

    Parameters
    ----------
    info : ExploitInfo
        Typed result of the exploitation.  All 8 fields are
        populated by the caller (``_legacy.handle_exploitation_success``).

    Side effects
    ------------
    * Prints the "EXPLOITATION SUCCESSFUL! Dropping to shell..." banner
      (always — this is a status message, not a report artifact).
    * If ``_current_ctx`` is set AND ``ctx.enable_report`` is True,
      calls :func:`generate_docx` to write the .docx (or .md fallback)
      to ``ctx.report_dir``.
    * If ``_current_ctx`` is None (defensive — should not happen in
      normal main() flow), falls back to cwd to preserve legacy
      behavior.
    * If ``ctx.enable_report`` is False (``--no-report``), prints an
      info line and skips report generation.

    P3.4 deviation #1 fix
    ---------------------
    P3.4 declared ``record_success(info)`` with a note that P3.5 would
    add a ``ctx`` parameter.  P3.5 implements that via the
    module-level :data:`_current_ctx` carrier instead of an explicit
    parameter, to avoid touching 14 caller signatures in
    ``handle_exploitation_success``.  The signature is still
    ``record_success(info)``; ``ctx`` is read from the module global.
    This is documented as transitional in
    ``autopwn._legacy.handle_exploitation_success`` and will be
    removed in P8.
    """
    # 1. Banner (unchanged from legacy L361 — always printed)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")

    # 2. Resolve ctx (from module-level carrier set by main())
    ctx = _current_ctx

    # 3. --no-report gate (P3.5)
    if ctx is not None and not ctx.enable_report:
        from autopwn.core.logging import print_info
        print_info("report generation skipped (--no-report)")
        return

    # 4. Dispatch to docx generator (P3.6 handles ImportError → markdown)
    out_dir = ctx.report_dir if ctx is not None else Path(".")
    generate_docx(info, out_dir)
