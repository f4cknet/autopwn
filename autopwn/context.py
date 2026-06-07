"""AutoPwn model layer — ExploitContext and sub-dataclasses.

Replaces the global ``exploit_info`` dict and ``globals()['system']`` / ``globals()['puts']``
injection pattern used by the v3.1 monolith (see ``AGENTS.md`` §1 铁律 1 + ``refactor.md`` §3.2.1).

Design principles (enforced by §6.3 reviewer checklist):
  * ``@dataclass(slots=True)`` for performance + frozen-by-default semantics.
  * All mutable defaults use ``field(default_factory=...)`` (no list/dict/Path() literals).
  * No upward imports — this module depends only on stdlib.
  * ``LibcInfo.elf`` is typed as ``object`` to avoid pulling pwntools at import time.

Adoption roadmap (see ``rebuild.md`` §4.3):
  * P2.1 (this PR) — define the dataclasses only; no behavior change.
  * P2.2 — add ``ExploitContext.from_args(args)`` factory.
  * P2.3 — build ``ctx = ExploitContext.from_args(args)`` at the top of ``main()``
            and wire a bridge (``autopwn._compat.sync_ctx_to_legacy``) so old
            ``exploit_info[...] = ...`` call sites keep working.
  * P2.4 — replace the remaining ``exploit_info[]`` writes with bridge calls.
  * P2.5 — deprecation warning on ``update_exploit_info``.
  * P8.5 — delete the bridge entirely; only ``ctx`` remains.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple


@dataclass(slots=True)
class BinaryInfo:
    """Static properties of the target ELF, populated by ``recon/checksec.py`` (P4.1)."""

    path: Path
    bit: int                          # 32 / 64
    stack_canary: bool
    pie: bool
    nx: bool
    relro: str                        # "Full" / "Partial" / "No"
    rwx_segments: bool
    stripped: bool


@dataclass(slots=True)
class LibcInfo:
    """The libc the target is dynamically linked against.

    ``path`` is ``None`` when no libc is available locally and the strategy must
    fall back to ``LibcSearcher`` (see P4.2).
    ``elf`` is typed as ``object`` (instead of ``pwntools.ELF``) to keep this
    module pwntools-import-free and to avoid circular imports.
    """

    path: Optional[Path] = None
    elf: object = None                # pwntools.ELF — see module docstring
    base: int = 0


@dataclass(slots=True)
class RopGadgetsX64:
    """x86_64 ROP gadget addresses resolved by ``recon/rop.py`` (P4.4).

    ``extra_rdi`` / ``extra_rsi`` non-zero means the gadget also pops a trailing
    register (``pop rdi ; ret`` vs ``pop rdi ; pop r15 ; ret``), used by some
    glibc versions.
    """

    pop_rdi: int
    pop_rsi: int
    ret: int
    extra_rdi: int = 0
    extra_rsi: int = 0


@dataclass(slots=True)
class RopGadgetsX32:
    """x86 ROP gadget addresses for ``int 0x80`` syscall chains (P4.4 / P6.5).

    ``has_eax_ebx_ecx_edx`` collapses the four independent bools
    ``eax``/``ebx``/``ecx``/``edx`` that ``set_function_flags`` used to
    inject via ``globals()`` — see AGENTS.md §2.6 R8 mitigation.
    """

    pop_eax: int
    pop_ebx: int
    pop_ecx: int
    pop_edx: int
    pop_ecx_ebx: int
    ret: int
    int_0x80: int
    has_eax_ebx_ecx_edx: bool = False


@dataclass(slots=True)
class CanaryInfo:
    """The leaked stack canary value + padding diff to the saved return address.

    ``value`` is the 8-byte canary (little-endian as ``u64``).
    ``diff`` is the number of filler bytes between the canary and the saved RBP/RIP.
    """

    value: int
    diff: int


@dataclass(slots=True)
class ExploitContext:
    """The single source of truth for an exploitation run.

    Replaces both ``exploit_info`` (a dict) and the ``globals()['system']`` family
    of injected flags.  Every recon/detect/strategy function in P4–P7 takes a
    single ``ctx`` argument instead of the 9-position-argument list used by
    v3.1 (see ``refactor.md`` §1.3 架构气味 #2/#3).
    """

    # Target
    binary: BinaryInfo
    mode: str                                   # "local" | "remote"
    remote: Optional[Tuple[str, int]] = None    # (host, port) when mode == "remote"

    # Exploitation resources — populated by recon phase
    libc: LibcInfo = field(default_factory=LibcInfo)
    gadgets_x64: Optional[RopGadgetsX64] = None
    gadgets_x32: Optional[RopGadgetsX32] = None

    # Vulnerability facts — populated by detect phase
    padding: int = 0
    canary: Optional[CanaryInfo] = None
    has_system: bool = False
    has_puts: bool = False
    has_write: bool = False
    has_printf: bool = False
    has_backdoor: bool = False
    has_callsystem: bool = False
    binsh_in_binary: bool = False
    fmtstr_offset: Optional[int] = None
    fmtstr_buf: Optional[int] = None

    # Runtime
    verbose: bool = False
    report_dir: Path = field(default_factory=Path.cwd)

    def log(self, message: str, level: str = "info") -> None:
        """Convenience pass-through to ``core.logging.print_*``.

        Routed through here (not directly imported) so strategy code in P7
        doesn't need to know about Colors / print_* — it just calls
        ``ctx.log("...", level="warning")``.  P2.x keeps the shim minimal
        to avoid changing print output formats; P8 will align it with
        the orchestrator's own logging style.
        """
        # Local import to keep core/ as the only dependency direction
        # (context.py is the model layer, logging is the infra layer).
        from autopwn.core.logging import (
            print_debug, print_info, print_success,
            print_warning, print_error, print_critical,
        )

        router = {
            "debug":    print_debug,
            "info":     print_info,
            "success":  print_success,
            "warning":  print_warning,
            "error":    print_error,
            "critical": print_critical,
        }
        router.get(level, print_info)(message)


__all__ = [
    "BinaryInfo",
    "LibcInfo",
    "RopGadgetsX64",
    "RopGadgetsX32",
    "CanaryInfo",
    "ExploitContext",
]
