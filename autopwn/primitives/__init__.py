"""Primitives layer of AutoPwn.

See ``rebuild.md`` §3 分层依赖图 for this layer's role and
``refactor.md`` §3.2.2 for the primitives contract.

P6 modules in this layer (all follow the same pattern: one
or more subclasses of :class:`ExploitPrimitive`, each implementing
``build_payload(ctx) -> bytes`` as a pure function — no
file writes, no process spawns, no ``ctx`` mutation; read-only
ELF parsing for symbol lookup is allowed and expected):

  * **P6.1** (``base``) — :class:`ExploitPrimitive` ABC +
    :class:`ExploitResult` dataclass (foundation for P6.2-P6.8).
  * **P6.2** (``ret2system``) — :class:`Ret2SystemX32` and
    :class:`Ret2SystemX64` (single-stage ret2libc system).
  * **P6.3** (``ret2libc_put``) — :class:`Ret2LibcPutX32` and
    :class:`Ret2LibcPutX64` (2-stage; leak via ``puts(puts@GOT)``).
  * **P6.4** (``ret2libc_write``) — :class:`Ret2LibcWriteX32` and
    :class:`Ret2LibcWriteX64` (2-stage; leak via
    ``write(1, write@GOT, n)`` — useful when ``puts`` is
    absent, e.g. level3_x64).
  * **P6.5** (``execve_syscall``) — :class:`ExecveSyscallX32`
    (x32-only; ``int 0x80`` syscall chain — independent of
    libc symbols, used when libc is stripped / statically
    linked).
  * **P6.6** (``shellcode``) — :class:`RwxShellcodeX32` and
    :class:`RwxShellcodeX64` (single-stage; injects
    ``pwntools shellcraft.sh()`` into an RWX BSS buffer;
    only applicable when ``rwx_segments=True``).
"""
from __future__ import annotations

from autopwn.primitives.base import (
    ExploitPrimitive as ExploitPrimitive,
    ExploitResult as ExploitResult,
)
from autopwn.primitives.ret2system import (
    Ret2SystemX32 as Ret2SystemX32,
    Ret2SystemX64 as Ret2SystemX64,
)
from autopwn.primitives.ret2libc_put import (
    Ret2LibcPutX32 as Ret2LibcPutX32,
    Ret2LibcPutX64 as Ret2LibcPutX64,
)
from autopwn.primitives.ret2libc_write import (
    Ret2LibcWriteX32 as Ret2LibcWriteX32,
    Ret2LibcWriteX64 as Ret2LibcWriteX64,
)
from autopwn.primitives.execve_syscall import (
    ExecveSyscallX32 as ExecveSyscallX32,
)
from autopwn.primitives.shellcode import (
    RwxShellcodeX32 as RwxShellcodeX32,
    RwxShellcodeX64 as RwxShellcodeX64,
)

__all__: list[str] = [
    "ExploitPrimitive",
    "ExploitResult",
    "Ret2SystemX32",
    "Ret2SystemX64",
    "Ret2LibcPutX32",
    "Ret2LibcPutX64",
    "Ret2LibcWriteX32",
    "Ret2LibcWriteX64",
    "ExecveSyscallX32",
    "RwxShellcodeX32",
    "RwxShellcodeX64",
]
