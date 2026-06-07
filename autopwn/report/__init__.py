"""AutoPwn report layer — Report package entry point.

See ``rebuild.md`` §3 分层依赖图 for this layer's role.

Adoption roadmap (see ``rebuild.md`` §4.4):
  * P3.1 (✅) — :class:`ExploitInfo` dataclass.
  * P3.2 (✅) — :func:`generate_docx` (moved from ``_legacy``).
  * P3.3 (✅) — :func:`generate_code` (moved from ``_legacy``).
  * P3.4 (this PR) — :func:`record_success` (subscriber orchestrator).
  * P3.5 — add ``ctx`` param + ``--no-report`` / ``--report-dir`` flags.
  * P3.6 (✅) — ``try/except ImportError`` markdown fallback for docx.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from autopwn.core.logging import print_critical
from autopwn.report.docx import generate_docx
from autopwn.report.model import ExploitInfo

__all__: list[str] = [
    "ExploitInfo",
    "generate_docx",
    "record_success",
]


def record_success(info: ExploitInfo) -> None:
    """Subscriber orchestrator for a successful exploitation run.

    P3.4 introduces this as the **canonical success-path entry point**
    in the ``report/`` layer.  It replaces the inline success-handling
    code in ``_legacy.handle_exploitation_success`` and consolidates
    the dispatch logic in one place.

    Parameters
    ----------
    info : ExploitInfo
        Typed result of the exploitation.  All 8 fields are
        populated by the caller (``_legacy.handle_exploitation_success``).

    Side effects
    ------------
    * Prints the "EXPLOITATION SUCCESSFUL! Dropping to shell..." banner.
    * Calls :func:`generate_docx` to write the .docx (or .md fallback).

    P3.5 will extend this signature to take an :class:`ExploitContext`
    so the function can honor ``--no-report`` (via
    ``ctx.enable_report``) and ``--report-dir`` (via ``ctx.report_dir``).
    For P3.4, the function always generates a report to ``Path('.')``,
    matching the legacy behavior.

    Subscriber architecture
    -----------------------
    This function is the **subscriber** for the success event.  When
    a strategy function (``_legacy.ret2_system_x64``, etc.) finishes
    exploitation, it calls ``_legacy.handle_exploitation_success``
    which in turn calls :func:`record_success` here.  The dispatch
    logic is centralized:

    * **Today (P3.4)**: docx generation only.
    * **P3.5**: add CLI flag gate (``--no-report``) and report dir
      override (``--report-dir``).  Optional: also write a
      ``{target}_wp.py`` artifact via ``report.code.generate_code``.
    * **P8.x (future)**: the dispatcher could become a generic
      pub/sub system where multiple subscribers (docx, code, metrics,
      remote upload) can register themselves.  P3.4 keeps it simple
      with an inline dispatch — the function body is the only
      "subscriber list".

    See ``refactor.md`` §3.2.2 (Strategy/Primitive) for the broader
    pattern that P7 will adopt for the actual exploit strategies.
    """
    # 1. Banner (unchanged from legacy L361)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")

    # 2. Dispatch to docx generator (P3.6 handles ImportError → markdown)
    #    out_dir is hard-coded to cwd for P3.4; P3.5 will thread ctx
    #    through and use ctx.report_dir.
    generate_docx(info, Path("."))
