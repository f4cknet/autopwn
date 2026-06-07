"""Bridge between ExploitContext and the legacy ``exploit_info`` dict.

Adoption window: P2.3 (2026-06-07) — P8.5 (final cleanup).
Lifecycle:  see ``rebuild.md`` §4.3 P2.3 and §6.3 P2.3 spec.

Purpose
=======
``autopwn/_legacy.py`` v3.1 uses a module-level ``exploit_info`` dict that
~50 call sites read from (docx generation, code generation, success gate).
Refactoring every call site at once is too risky for a single PR.  The
bridge lets new code work with ``ExploitContext`` (typed, slots-validated)
while old code continues to read ``exploit_info`` (loose dict) unchanged.

Design
======
* ``_legacy_info`` is a single module-level dict.  ``_legacy.py`` imports
  it as ``exploit_info`` (alias), so all ~50 reads and ~7 writes in legacy
  code continue to operate on the same dict object.  No copy-on-sync;
  mutations are immediately visible to both APIs.
* ``sync_ctx_to_legacy(ctx)`` is called once from ``main()`` after
  ``ExploitContext.from_args(args)``.  It copies the ctx fields that are
  known *at startup* into the dict.  Legacy writes at L3305/L3306
  (basic info) and L354-360 (``handle_exploitation_success``) then
  overwrite as needed.
* P2.4 will replace the remaining legacy ``exploit_info[...] = ...``
  writes with bridge calls (or direct ``ctx`` access).  P2.5 adds a
  DeprecationWarning on the legacy ``update_exploit_info`` helper.
* P8.5 deletes this module entirely.

Deviations from the ``rebuild.md`` §6.3 P2.3 spec example
=========================================================
The spec example has three issues that would introduce behaviour drift;
P2.3 deviates as follows and documents each in the implementation record:

1. **No ``warnings.warn(...)`` in ``sync_ctx_to_legacy``**.
   The bridge is the main API until P8.5.  Warning on every call would
   flood stderr and break log-diff validation.  P2.5 will add the
   DeprecationWarning to the legacy ``update_exploit_info`` instead.

2. **``architecture`` is guarded by ``ctx.binary.bit != 0``**.
   P4.1 (``recon/checksec.py``) will populate ``BinaryInfo.bit`` with
   ``32`` or ``64``.  Until then, ``from_args`` writes a placeholder
   ``bit=0`` (see ``autopwn/context.py`` docstring).  The spec's
   ``f"x{ctx.binary.bit}"`` would produce ``"x0"`` and leak that into
   ``exploit_info['architecture']`` if any reader accesses it before
   ``handle_exploitation_success`` runs.

3. **``success`` is NOT set to ``True`` at startup**.
   Currently ``exploit_info['success']`` stays ``False`` until
   ``handle_exploitation_success`` flips it.  The docx generator gates
   on ``if not exploit_info['success']`` (L241).  Setting ``True`` at
   startup would always trigger the docx, even for failed exploits.
   P3.4 (``report/model.py:record_success``) is the place that should
   set ``True`` — for now P2.3 leaves the field untouched.
"""
from __future__ import annotations

from autopwn.context import ExploitContext


_legacy_info: dict = {
    'target_binary': '',
    'exploit_type': '',
    'payload': '',
    'padding': 0,
    'addresses': {},
    'vulnerability_type': '',
    'architecture': '',
    'success': False,
    'timestamp': '',
}


def sync_ctx_to_legacy(ctx: ExploitContext) -> None:
    """Copy known-stable fields from ``ctx`` into the legacy dict.

    Called once from ``main()`` after ``ExploitContext.from_args(args)``.

    Fields set:

    * ``target_binary`` — ``str(ctx.binary.path)`` (full path).
      L3305 immediately overwrites with ``os.path.basename(args.local)``.
    * ``padding`` — ``ctx.padding`` (from ``-f`` override or 0).
      L356 in ``handle_exploitation_success`` overwrites with the actual
      exploit padding.
    * ``architecture`` — ``"x{ctx.binary.bit}"`` only when
      ``ctx.binary.bit != 0`` (P4.1 placeholder guard; see module
      docstring deviation #2).  L359 in ``handle_exploitation_success``
      overwrites with the real value.

    Fields NOT set (and why):

    * ``success`` — P3.4 ``record_success()`` will set this to ``True``.
    * ``exploit_type`` / ``payload`` / ``addresses`` / ``vulnerability_type``
      — only known after exploitation; set by ``handle_exploitation_success``.
    * ``timestamp`` — set by legacy L3306 (kept as-is in P2.3).
    """
    _legacy_info['target_binary'] = str(ctx.binary.path)
    _legacy_info['padding'] = ctx.padding
    if ctx.binary.bit != 0:  # P4.1 placeholder guard
        _legacy_info['architecture'] = f"x{ctx.binary.bit}"


__all__ = ["_legacy_info", "sync_ctx_to_legacy"]
