"""Report layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role.

Adoption roadmap (see ``rebuild.md`` §4.4):
  * P3.1 (✅) — :class:`ExploitInfo` dataclass.
  * P3.2 (✅) — :func:`generate_docx` (moved from ``_legacy``).
  * P3.3 (this PR) — :func:`generate_code` (moved from ``_legacy``).
  * P3.4 — add :func:`record_success` (subscriber pattern).
  * P3.5 — ``--no-report`` / ``--report-dir`` CLI flags.
  * P3.6 — ``try/except ImportError`` markdown fallback for docx.
"""
from __future__ import annotations

from autopwn.report.model import ExploitInfo
from autopwn.report.docx import generate_docx
from autopwn.report.code import generate_code

__all__: list[str] = ["ExploitInfo", "generate_docx", "generate_code"]
