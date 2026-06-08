"""Exp layer of AutoPwn.

See rebuild.md §3 分层依赖图 for this layer's role in the
overall architecture.  The P7 layer holds the strategy
abstractions that the P8 orchestrator iterates.

Sub-modules
-----------
- :mod:`autopwn.exp.base` (P7.1) — ``ExploitStrategy`` ABC.
- :mod:`autopwn.exp.priorities` (P7.2) — hardcoded priority constants.
- :mod:`autopwn.exp.registry` (P7.2) — ``@register`` decorator + ``candidates``.
- :mod:`autopwn.exp.strategies.*` (P7.3-P7.10) — concrete strategy classes.

P7.11 will add explicit imports of all concrete strategy modules
to ``autopwn.exp.strategies.__init__`` to trigger their ``@register``
side effects.  P7.2 deliberately does NOT auto-import strategy
modules here — that would create an import cycle and break
``pip install -e .`` lint checks.
"""
from __future__ import annotations

from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import (
    CANARY,
    EXECVE_SYSCALL,
    FMTSTR,
    PIE_BACKDOOR,
    RET2LIBC_PUT,
    RET2LIBC_WRITE,
    RET2SYSTEM,
    RWX_SHELLCODE,
    STRATEGY_PRIORITY_HUMAN,
)
from autopwn.exp.registry import (
    all_strategies,
    candidates,
    register,
    reset,
)

__all__: list[str] = [
    # base (P7.1)
    "ExploitStrategy",
    # priorities (P7.2)
    "CANARY",
    "PIE_BACKDOOR",
    "RET2SYSTEM",
    "RET2LIBC_PUT",
    "RET2LIBC_WRITE",
    "RWX_SHELLCODE",
    "EXECVE_SYSCALL",
    "FMTSTR",
    "STRATEGY_PRIORITY_HUMAN",
    # registry (P7.2)
    "register",
    "candidates",
    "all_strategies",
    "reset",
]
