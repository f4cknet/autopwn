"""Report layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role.

Adoption roadmap (see ``rebuild.md`` §4.4):
  * P3.1 (this PR) — re-export :class:`ExploitInfo` only.
  * P3.2 — add ``docx.py`` (``generate_docx``); add to ``__all__``.
  * P3.3 — add ``code.py`` (``generate_code``); add to ``__all__``.
  * P3.4 — add ``record_success(ctx, info)`` orchestrator function.
"""
from __future__ import annotations

from autopwn.report.model import ExploitInfo

__all__: list[str] = ["ExploitInfo"]
