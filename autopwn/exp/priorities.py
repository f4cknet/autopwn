"""P7.2: hardcoded priority constants for the strategy registry.

These values are the **single source of truth** for the
``ExploitStrategy.priority`` field on every P7.3+ strategy class.
They come from ``rebuild.md`` §11 附录 A, which Owner signed off
on 2026-06-08 (P7.2a / B-003).

Why a separate module
---------------------
Two reasons we don't inline the values in :mod:`autopwn.exp.registry`:

1. **Single source of truth**: P7.3+ strategy files
   (``exp/strategies/ret2system_x32.py`` etc.) import these
   constants by name (``from autopwn.exp.priorities import
   RET2SYSTEM``) so the priority value is grep-able from the
   strategy file.  Searching for ``priority = 150`` finds
   nothing; searching for ``priority = RET2SYSTEM`` finds the
   class + a link back to this file.

2. **Single audit point**: when the team wants to tweak
   priorities (e.g. to favor one technique over another
   in a new CTF), they update :data:`STRATEGY_PRIORITY_HUMAN`
   in this file + the 附录 A row in ``rebuild.md`` (both
   PRs are reviewed together).

Note: if a value here ever drifts from 附录 A, the P7.2
unit test ``test_priorities_match_appendix_a`` will catch
it (manually maintained; see ``tests/unit/test_exp_registry.py``).
"""
from __future__ import annotations


# --- canary branch (most specific; only viable path under canary) ---
# R3 mitigation: 7 canary_* strategy files (P7.10) all inherit
# priority from this constant so a single tweak here propagates.
CANARY: int = 200


# --- non-canary stack overflow branch (decisions tree order) ---
# 1. PIE + backdoor: brute-force the PIE base via a known
#    backdoor symbol (e.g. ``callsystem``) — works only when
#    PIE=1 AND backdoor function is present.  See P7.9.
PIE_BACKDOOR: int = 180

# 2. ret2system: ``system("/bin/sh")`` with both symbols
#    available — fastest path when libc's ``system`` and the
#    ``"/bin/sh"`` string are accessible.
RET2SYSTEM: int = 150

# 3. ret2libc (puts leak): 2-stage leak-then-return via
#    ``puts@GOT`` — broader compat than write leak (puts PLT
#    is in almost every glibc, write PLT was historically
#    rarer).  Put BEFORE write in the new spec; this is the
#    deliberate P7.2a change vs. the v3.1 write>put order.
RET2LIBC_PUT: int = 120

# 4. ret2libc (write leak): 2-stage leak-then-return via
#    ``write@GOT`` — fallback for binaries lacking ``puts``.
RET2LIBC_WRITE: int = 110

# 5. rwx shellcode: inject ``shellcraft.sh()`` into a BSS
#    segment with RWX permission — only works when
#    ``ctx.binary.rwx_segments`` is True.
RWX_SHELLCODE: int = 90

# 6. execve syscall chain: ``int 0x80`` syscall via 4 pop
#    gadgets — x32 only, no libc dependency.
EXECVE_SYSCALL: int = 80


# --- format string branch (fallback when no stack overflow) ---
# R5 mitigation: 1 fmtstr strategy handles all 3 sub-flavors
# (system write, string leak, address write) via ``requires``
# metadata; the single 50 priority reflects "兜底" semantics.
FMTSTR: int = 50


# Human-readable labels for the P8 orchestrator's
# "→ trying <human-name>" log lines.  Maps priority value
# → Chinese-friendly description (matches 附录 A 备注 column).
# Optional: callers can fall back to ``strat.name`` (English).
STRATEGY_PRIORITY_HUMAN: dict[int, str] = {
    CANARY:          "canary 泄漏 → 任意 ROP",
    PIE_BACKDOOR:    "PIE 爆破 + backdoor",
    RET2SYSTEM:      "ret2system (system+bin_sh)",
    RET2LIBC_PUT:    "ret2libc (puts 泄漏)",
    RET2LIBC_WRITE:  "ret2libc (write 泄漏)",
    RWX_SHELLCODE:   "rwx shellcode 注入",
    EXECVE_SYSCALL:  "execve syscall (int 0x80)",
    FMTSTR:          "format string 兜底",
}


__all__ = [
    "CANARY",
    "PIE_BACKDOOR",
    "RET2SYSTEM",
    "RET2LIBC_PUT",
    "RET2LIBC_WRITE",
    "RWX_SHELLCODE",
    "EXECVE_SYSCALL",
    "FMTSTR",
    "STRATEGY_PRIORITY_HUMAN",
]
