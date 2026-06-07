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
   *(Superseded by P2.4: the ``update_exploit_info`` helper is deleted
   entirely since P2.4 converts its 7 callers to ``record_success()``.)*

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
   set ``True`` — for now P2.3 leaves the field untouched.  *P2.4 fixes
   this by introducing ``record_success()`` (below), which sets
   ``success=True`` only at exploit completion — preserving the legacy
   invariant.*
"""
from __future__ import annotations

from typing import Optional

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


def sync_ctx_to_legacy(
    ctx: ExploitContext,
    *,
    target_name: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> None:
    """Copy known-stable fields from ``ctx`` into the legacy dict.

    Called once from ``main()`` after ``ExploitContext.from_args(args)``.

    Parameters
    ----------
    ctx : ExploitContext
        The constructed context.  Fields read: ``binary.path``,
        ``binary.bit`` (with P4.1 placeholder guard), ``padding``.
    target_name : str, optional
        If given, used as ``_legacy_info['target_binary']``.  In P2.4 the
        caller passes ``os.path.basename(args.local)`` to preserve the
        legacy semantics (docx / code-generation read the basename, not
        the full path).  If ``None``, falls back to ``str(ctx.binary.path)``
        — the P2.3 default.
    timestamp : str, optional
        If given, used as ``_legacy_info['timestamp']``.  In P2.4 the
        caller passes ``datetime.now().strftime(...)`` to match the
        legacy L3306 string format.  If ``None``, leaves the field
        unchanged (P2.3 left it as the empty default).

    Fields set
    ----------
    * ``target_binary`` — ``target_name`` if provided, else
      ``str(ctx.binary.path)`` (full path).
    * ``timestamp`` — ``timestamp`` if provided, else unchanged.
    * ``padding`` — ``ctx.padding`` (from ``-f`` override or 0).
      ``record_success()`` overwrites with the actual exploit padding.
    * ``architecture`` — ``"x{ctx.binary.bit}"`` only when
      ``ctx.binary.bit != 0`` (P4.1 placeholder guard; see module
      docstring deviation #2).  ``record_success()`` overwrites with the
      real value.

    Fields NOT set (and why)
    -------------------------
    * ``success`` — stays ``False``; ``record_success()`` flips it to
      ``True`` at exploit completion.
    * ``exploit_type`` / ``payload`` / ``addresses`` /
      ``vulnerability_type`` — only known after exploitation; set by
      ``record_success()``.
    """
    if target_name is not None:
        _legacy_info['target_binary'] = target_name
    else:
        # P2.3 default: full path.  P2.4 callers should pass
        # target_name=basename to match the legacy 'target_binary'
        # field semantics (basename, not path).
        _legacy_info['target_binary'] = str(ctx.binary.path)
    if timestamp is not None:
        _legacy_info['timestamp'] = timestamp
    _legacy_info['padding'] = ctx.padding
    if ctx.binary.bit != 0:  # P4.1 placeholder guard
        _legacy_info['architecture'] = f"x{ctx.binary.bit}"


def record_success(
    *,
    exploit_type: str,
    payload,
    padding: int,
    addresses: dict,
    vulnerability_type: str,
    architecture: str,
) -> None:
    """Sync exploit-completion info into the legacy dict.

    P2.4: replaces the 7 ``update_exploit_info(...)`` calls in
    ``_legacy.handle_exploitation_success`` (L350-356, pre-P2.4) with a
    single bridge call.  Sets the same 7 fields the helper used to set,
    in the same order.  Also flips ``success`` to ``True`` (P2.3 spec
    deviation #3 — ``sync_ctx_to_legacy`` does *not* set ``True`` at
    startup; only ``record_success`` does, at the right moment).

    Parameters mirror the legacy ``handle_exploitation_success`` signature
    minus the leading ``program`` (which is now in ``ctx.binary.path``).
    P3.4 will refactor this into ``record_success(ctx, ExploitInfo)``
    that emits to docx / code subscribers; for P2.4 the simpler kwargs
    form is the minimum change that eliminates the 7 write sites.

    Parameters
    ----------
    exploit_type : str
        E.g. ``"ret2system"``, ``"ret2libc (write) - x64"``,
        ``"Format String - Local"``, ``"PIE Backdoor - Local"``.
    payload : bytes or str
        Exploit payload.  If bytes, hex-encoded; if str, kept as-is.
        Mirrors the legacy L351 ``payload.hex() if hasattr(payload, 'hex')``
        logic byte-for-byte.
    padding : int
        The actual padding used (from auto-detection or ``-f`` override).
    addresses : dict
        E.g. ``{"system_addr": 0x..., "buf_addr": 0x...}`` — consumed by
        the docx / code generators.
    vulnerability_type : str
        E.g. ``"Stack Buffer Overflow"``, ``"Format String"``.
    architecture : str
        E.g. ``"x32"``, ``"x64"``.
    """
    _legacy_info['exploit_type'] = exploit_type
    _legacy_info['payload'] = payload.hex() if hasattr(payload, 'hex') else str(payload)
    _legacy_info['padding'] = padding
    _legacy_info['addresses'] = addresses
    _legacy_info['vulnerability_type'] = vulnerability_type
    _legacy_info['architecture'] = architecture
    _legacy_info['success'] = True


__all__ = ["_legacy_info", "sync_ctx_to_legacy", "record_success"]
