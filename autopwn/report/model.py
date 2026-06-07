"""AutoPwn report model layer — ``ExploitInfo`` dataclass.

Replaces the loose ``exploit_info`` dict that ``autopwn/_legacy.py`` v3.1
exposes at module scope (see ``AGENTS.md`` §1 铁律 1 + ``refactor.md`` §4.4 P3.1).

Design principles (enforced by §6.4 reviewer checklist):
  * ``@dataclass(slots=True)`` for performance + frozen-by-default semantics
    (consistent with ``autopwn/context.py`` dataclasses from P2.1).
  * All mutable defaults use ``field(default_factory=...)`` (no dict literal).
  * No upward imports — this module depends only on stdlib.
  * 6 required + 3 optional fields, mirroring ``_compat._legacy_info``
    1:1 (9 keys, minus ``success`` — see deviation note below).
  * ``extra`` is a forward-compatibility escape hatch for new fields
    that P3.4+ subscribers may need (e.g., libc base, canary value,
    fmtstr offset) without forcing a dataclass field on every PR.

Adoption roadmap (see ``rebuild.md`` §4.4):
  * P3.1 (this PR) — define the dataclass only; no behavior change.
  * P3.2 — move ``generate_docx_report`` to ``report/docx.py``; read
    from ``ExploitInfo``.
  * P3.3 — move ``generate_exploitation_code`` to ``report/code.py``.
  * P3.4 — refactor ``handle_exploitation_success`` into
    ``record_success(ctx, info)`` that emits to docx/code subscribers
    (Subscriber pattern, see ``refactor.md`` §3.2.2).
  * P3.5 — CLI ``--no-report`` / ``--report-dir`` flags; add
    ``ctx.enable_report: bool``.
  * P3.6 — ``python-docx`` ``try/except ImportError`` fallback to
    markdown (see ``refactor.md`` §10).

Deviation from ``rebuild.md`` §6.4 P3.1 spec example
=====================================================
The §6.4 spec example has a bare ``dict`` annotation on ``extra``
and ``addresses``.  This implementation tightens both to
``Dict[str, int]`` (addresses) and ``Dict[str, Any]`` (extra) — same
runtime behavior, but with type hints that survive ``mypy --strict``
and IDE autocomplete.  P2.1 took the same liberty (see
``autopwn/context.py`` ``Dict``/``Tuple``/``Optional`` annotations).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(slots=True)
class ExploitInfo:
    """Typed result of a successful exploitation run.

    Mirrors the 8 mutable fields of the legacy ``_compat._legacy_info``
    dict (see ``autopwn/_compat.py`` for the canonical default values).

    Construction site: ``P3.4 report.record_success(ctx, info)`` in
    the success path of each strategy.  Docx / code generators
    (``P3.2`` / ``P3.3``) read this dataclass instead of the loose
    dict.

    Why no ``success: bool`` field
    ------------------------------
    The legacy dict has a ``success`` key (L241 docx gate
    ``if not exploit_info['success']: return``).  We **omit** it
    here for two reasons:

    1. ``ExploitInfo`` is constructed only on the success path
       (P3.4 ``record_success``); a failed exploit never produces one.
       The "is success" question is replaced by "was an ``ExploitInfo``
       ever produced at all".
    2. P3.5 will add ``ctx.enable_report: bool`` for the user-facing
       "should we generate a report" toggle — that lives on the
       context, not on the info.

    If a future subscriber needs a "partial / failed" report, the
    right design is a separate ``FailedExploitInfo`` dataclass, not
    overloading this one with a ``success=False`` state.
    """

    # Required — populated by record_success (P3.4)
    exploit_type: str          # e.g., "ret2system - x64", "Format String - Local"
    payload: bytes             # the actual exploit payload (raw bytes)
    padding: int               # the padding (bytes) used to reach saved RIP
    addresses: Dict[str, int]  # e.g., {"system_addr": 0x..., "buf_addr": 0x...}
    vulnerability_type: str    # e.g., "Stack Buffer Overflow", "Format String"
    architecture: str          # "x32" | "x64"

    # Optional — populated at startup or by record_success
    target_binary: str = ""    # basename of target binary (no path, no extension)
    timestamp: str = ""        # ISO-format string, populated by main() at startup

    # Forward-compat: subscribers can stash extra facts here without
    # a dataclass field on every PR.  Example: P3.4 ret2libc record_success
    # could store libc base in info.extra["libc_base"].
    extra: Dict[str, Any] = field(default_factory=dict)


__all__ = ["ExploitInfo"]
