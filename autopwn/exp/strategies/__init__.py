"""AutoPwn exploit strategies (P7 layer — final registration point).

This ``__init__`` explicitly imports every strategy module so the
``@register`` decorator runs at import time.  Without these
imports, the registry stays empty and ``candidates(ctx)`` returns
``[]`` (no strategies to choose from).

Per ``rebuild.md`` §6.8 P7.11 + ``refactor.md`` §3.2.2 + P7.2
(registry design).

What the import chain does
--------------------------
Each ``from .<module> import *`` triggers module evaluation,
which runs the ``@register`` decorator on every strategy class
defined in that module.  The decorator appends an instance to
``autopwn.exp.registry._REGISTRY`` (see P7.2).  After all 16
imports below, the registry contains 2 + 2 + 2 + 2 + 2 + 2 + 2 +
2 + 4 + 2 + 2 = 30 strategy instances (see appendix below for
the exact count).

Why this is explicit (vs implicit auto-import)
-----------------------------------------------
* **Static analyzability**: ``grep -r 'from autopwn.exp.strategies'
  .`` shows exactly which modules are part of the strategy layer.
* **No circular import** (a recursive auto-import would loop
  through ``__init__`` → module → ``__init__`` → ...).
* **Deterministic registration order**: the imports are
  alphabetical per priority group (canary first, then pie, then
  ret2*, etc.), so ``all_strategies()`` returns a stable
  list useful for diagnostics.
* **P7.12 integration tests** rely on this — they import
  ``autopwn.exp.strategies`` and call ``all_strategies()``
  to verify the count matches the appendix.

Total strategy count
--------------------
After all imports below:

* 4 canary modules × 4 strategies (2 arch × 2 mode) − 2
  (canary_execve_syscall is x32-only) = 14 canary strategies
* ret2system_x32 / _x64 × local+remote = 4
* ret2libc_put_x32 / _x64 × local+remote = 4
* ret2libc_write_x32 / _x64 × local+remote = 4
* rwx_shellcode_x32 / _x64 × local+remote = 4
* execve_syscall × local+remote = 2 (x32 only)
* fmtstr × 4 main + 2 bypass = 6
* pie_backdoor × local+remote = 2

= 14 + 4 + 4 + 4 + 4 + 2 + 6 + 2 = **40 strategies total**
"""
from __future__ import annotations

# Canary strategies (P7.10) — must come first so candidates()
# ordering puts CANARY (priority=200) at the top.
from .canary_execve_syscall import (  # noqa: F401
    CanaryExecveSyscallLocalStrategy,
    CanaryExecveSyscallRemoteStrategy,
)
from .canary_ret2libc_put import (  # noqa: F401
    CanaryRet2LibcPutX32LocalStrategy,
    CanaryRet2LibcPutX32RemoteStrategy,
    CanaryRet2LibcPutX64LocalStrategy,
    CanaryRet2LibcPutX64RemoteStrategy,
)
from .canary_ret2libc_write import (  # noqa: F401
    CanaryRet2LibcWriteX32LocalStrategy,
    CanaryRet2LibcWriteX32RemoteStrategy,
    CanaryRet2LibcWriteX64LocalStrategy,
    CanaryRet2LibcWriteX64RemoteStrategy,
)
from .canary_ret2system import (  # noqa: F401
    CanaryRet2SystemX32LocalStrategy,
    CanaryRet2SystemX32RemoteStrategy,
    CanaryRet2SystemX64LocalStrategy,
    CanaryRet2SystemX64RemoteStrategy,
)

# PIE backdoor (P7.9) — 2 strategies (local+remote, arch-agnostic).
from .pie_backdoor import (  # noqa: F401
    PieBackdoorLocalStrategy,
    PieBackdoorRemoteStrategy,
)

# ret2system (P7.3) — 4 strategies.
from .ret2system_x32 import (  # noqa: F401
    Ret2SystemX32LocalStrategy,
    Ret2SystemX32RemoteStrategy,
)
from .ret2system_x64 import (  # noqa: F401
    Ret2SystemX64LocalStrategy,
    Ret2SystemX64RemoteStrategy,
)

# ret2libc_put (P7.4) — 4 strategies (2-stage puts leak).
from .ret2libc_put_x32 import (  # noqa: F401
    Ret2LibcPutX32LocalStrategy,
    Ret2LibcPutX32RemoteStrategy,
)
from .ret2libc_put_x64 import (  # noqa: F401
    Ret2LibcPutX64LocalStrategy,
    Ret2LibcPutX64RemoteStrategy,
)

# ret2libc_write (P7.5) — 4 strategies (2-stage write leak).
from .ret2libc_write_x32 import (  # noqa: F401
    Ret2LibcWriteX32LocalStrategy,
    Ret2LibcWriteX32RemoteStrategy,
)
from .ret2libc_write_x64 import (  # noqa: F401
    Ret2LibcWriteX64LocalStrategy,
    Ret2LibcWriteX64RemoteStrategy,
)

# RWX shellcode (P7.6) — 4 strategies.
from .rwx_shellcode_x32 import (  # noqa: F401
    RwxShellcodeX32LocalStrategy,
    RwxShellcodeX32RemoteStrategy,
)
from .rwx_shellcode_x64 import (  # noqa: F401
    RwxShellcodeX64LocalStrategy,
    RwxShellcodeX64RemoteStrategy,
)

# execve syscall (P7.7) — 2 strategies (x32 only).
from .execve_syscall import (  # noqa: F401
    ExecveSyscallX32LocalStrategy,
    ExecveSyscallX32RemoteStrategy,
)

# fmtstr (P7.8) — 6 strategies (4 main + 2 bypass).
from .fmtstr import (  # noqa: F401
    FmtstrX32LocalStrategy,
    FmtstrX64LocalStrategy,
    FmtstrX32RemoteStrategy,
    FmtstrX64RemoteStrategy,
    FmtstrPrintStringsX32LocalStrategy,
    FmtstrPrintStringsX32RemoteStrategy,
)


# Re-export ``all_strategies`` for downstream code (P7.12 integration
# tests, P8 orchestrator diagnostics).  Not strictly necessary
# (callers can do ``from autopwn.exp.registry import all_strategies``)
# but convenient.
from autopwn.exp.registry import all_strategies, candidates  # noqa: F401, E402

__all__ = [
    # Canary
    "CanaryExecveSyscallLocalStrategy",
    "CanaryExecveSyscallRemoteStrategy",
    "CanaryRet2LibcPutX32LocalStrategy",
    "CanaryRet2LibcPutX32RemoteStrategy",
    "CanaryRet2LibcPutX64LocalStrategy",
    "CanaryRet2LibcPutX64RemoteStrategy",
    "CanaryRet2LibcWriteX32LocalStrategy",
    "CanaryRet2LibcWriteX32RemoteStrategy",
    "CanaryRet2LibcWriteX64LocalStrategy",
    "CanaryRet2LibcWriteX64RemoteStrategy",
    "CanaryRet2SystemX32LocalStrategy",
    "CanaryRet2SystemX32RemoteStrategy",
    "CanaryRet2SystemX64LocalStrategy",
    "CanaryRet2SystemX64RemoteStrategy",
    # PIE backdoor
    "PieBackdoorLocalStrategy",
    "PieBackdoorRemoteStrategy",
    # ret2system
    "Ret2SystemX32LocalStrategy",
    "Ret2SystemX32RemoteStrategy",
    "Ret2SystemX64LocalStrategy",
    "Ret2SystemX64RemoteStrategy",
    # ret2libc_put
    "Ret2LibcPutX32LocalStrategy",
    "Ret2LibcPutX32RemoteStrategy",
    "Ret2LibcPutX64LocalStrategy",
    "Ret2LibcPutX64RemoteStrategy",
    # ret2libc_write
    "Ret2LibcWriteX32LocalStrategy",
    "Ret2LibcWriteX32RemoteStrategy",
    "Ret2LibcWriteX64LocalStrategy",
    "Ret2LibcWriteX64RemoteStrategy",
    # rwx_shellcode
    "RwxShellcodeX32LocalStrategy",
    "RwxShellcodeX32RemoteStrategy",
    "RwxShellcodeX64LocalStrategy",
    "RwxShellcodeX64RemoteStrategy",
    # execve_syscall
    "ExecveSyscallX32LocalStrategy",
    "ExecveSyscallX32RemoteStrategy",
    # fmtstr
    "FmtstrX32LocalStrategy",
    "FmtstrX64LocalStrategy",
    "FmtstrX32RemoteStrategy",
    "FmtstrX64RemoteStrategy",
    "FmtstrPrintStringsX32LocalStrategy",
    "FmtstrPrintStringsX32RemoteStrategy",
    # Registry helpers
    "all_strategies",
    "candidates",
]
