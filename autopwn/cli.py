"""AutoPwn CLI — modern entry point (P0.0 shim + P8.3 orchestrator dispatch).

v4 起所有命令行入口都走这里：
  - `python autopwn.py` (shim, deprecated per P8.6) → from autopwn.cli import main
  - `python -m autopwn`        → from autopwn.cli import main
  - `autopwn` (after pip install) → autopwn.cli:main (console_scripts)

P8.3 (this version): ``main()`` is reduced to a thin wrapper that
parses args, builds the typed :class:`ExploitContext`, and hands
control to :func:`autopwn.orchestrator.run`.  All decision-tree
logic (recon → detect → strategy selection) lives in
:mod:`autopwn.orchestrator`.

P8.5 (2026-06-09): ``_compat.sync_ctx_to_legacy`` bridge removed.
P8.6 (2026-06-09): ``autopwn.py`` shim deleted.

v4.1.8 (2026-06-13): Mirror ``sys.stdout`` / ``sys.stderr`` to
``logs/{challenge_name}/run.log`` via :class:`autopwn.core.tee.Tee`
(see ``upgraded.md`` §3.2 v4.1.8).  The banner + recon/detect/
strategy output (including pwntools tube output that uses
``sys.stdout``) is captured to disk for post-mortem analysis
without changing the on-terminal experience.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autopwn.context import ContextError, ExploitContext
from autopwn.core.logging import print_banner, print_error, set_verbose
from autopwn.core.tee import Tee
from autopwn.orchestrator import run as orchestrator_run
from autopwn.report import set_current_ctx


def _build_argparser() -> argparse.ArgumentParser:
    """Construct the 8-flag argparse parser.

    The flags are identical to v3.1's :func:`_legacy.main` parser
    (``autopwn/_legacy.py`` L3019-3050) so that the
    ``python autopwn.py -l X -v`` CLI surface is bit-for-bit the
    same; only the dispatcher changed (P8.3).  See
    ``rebuild.md`` §6.9 P8.3 for the spec.
    """
    parser = argparse.ArgumentParser(
        prog="autopwn",
        description="AutoPwn - Automated Binary Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python autopwn.py -l ./target_binary
  python autopwn.py -l ./target_binary -f 112
  python autopwn.py -l ./target_binary -libc ./libc-2.19.so
  python autopwn.py -l ./target_binary -ip 192.168.1.100 -p 9999
        """,
    )
    parser.add_argument("-l", "--local", type=str, required=True,
                        help="Target binary file (required)")
    parser.add_argument("-ip", "--ip", type=str,
                        help="Remote target IP address")
    parser.add_argument("-p", "--port", type=int,
                        help="Remote target port")
    parser.add_argument("-libc", "--libc", type=str,
                        help="Path to libc file")
    parser.add_argument("-f", "--fill", type=int,
                        help="Manual overflow padding size")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip DOCX report generation (exploit still runs)")
    parser.add_argument("--report-dir", type=str, default=None,
                        help="Directory to write the DOCX report into "
                             "(default: current working directory). "
                             "Auto-created if it does not exist.")
    # v4.1.11: SSL/TLS toggle for remote connections.  Many CTF
    # platforms (e.g. cyberstages, r3) wrap their remote binary
    # service in TLS via stunnel/nginx, so pwntools' plain ``remote()``
    # raises on handshake.  Pass ``-ssl`` to enable TLS on the socket.
    # Requires ``-ip`` + ``-p`` (local mode ignores this flag).
    parser.add_argument("-ssl", "--ssl", action="store_true",
                        help="Use SSL/TLS for the remote connection "
                             "(requires -ip + -p).  No effect in local mode.")
    return parser


def _resolve_log_path(args: argparse.Namespace) -> Path | None:
    """v4.1.8 — compute the per-run log file path from CLI args.

    Returns ``logs/{challenge_name}/run.log`` (cwd-relative) for
    local binaries, ``logs/remote_{ip}_{port}/run.log`` for remote
    targets, or ``None`` if no identifier is available (caller
    should skip log capture).

    The directory is auto-created.  The file is opened in **write**
    mode by the caller (overwrites any previous run log for the
    same challenge name — v4.1.8b may add a timestamp suffix if
    historical preservation is needed).
    """
    local = getattr(args, "local", None)
    if local:
        challenge_name = Path(local).stem
    else:
        ip = getattr(args, "ip", None)
        port = getattr(args, "port", None)
        if ip:
            challenge_name = f"remote_{ip}_{port or 0}"
        else:
            return None

    log_dir = Path("logs") / challenge_name
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "run.log"


def main() -> int:
    """CLI entry point: parse args → build ctx → dispatch to orchestrator.

    Returns the orchestrator's exit code (0 on successful
    exploitation, 1 on failure).  Does NOT call :func:`sys.exit`
    — the wrapper (``python -m autopwn``) does the
    ``raise SystemExit`` translation.  Per
    ``refactor.md`` §11 R1 + §6.8 Reviewer checklist.

    Side effects (in order):
      1. **v4.1.8** — resolve log path from args, open log file,
         wrap ``sys.stdout``/``sys.stderr`` with :class:`Tee`,
         and redirect pwntools' ``context.log_console`` to the
         same tee (pwntools captures the original stdout at
         ``pwn`` import time, so a plain ``sys.stdout`` swap is
         not enough — see :class:`autopwn.core.tee.Tee` for the
         full pwntools-compat story).
      2. ``print_banner()`` — startup banner (now also goes to log).
      3. ``set_verbose(args.verbose)`` — propagate ``-v`` to
         :mod:`autopwn.core.logging`.
      4. ``ExploitContext.from_args(args)`` — typed context with
         validation (binary exists, ip+port pair consistency,
         libc path exists).  Raises :class:`ContextError` on
         failure; we catch it and exit 1 with the legacy red
         error message.
      5. ``set_current_ctx(ctx)`` — wire the report carrier so
         ``autopwn.report.record_success`` (called from
         orchestrator) can find the ctx.
      6. ``orchestrator_run(ctx)`` — recon + detect + strategy.
      7. **v4.1.8** — in ``finally``: restore ``sys.stdout``/
         ``sys.stderr`` / ``pwnlib.context.context.log_console``
         and close the log file handle.
    """
    args = _build_argparser().parse_args()

    set_verbose(args.verbose)

    # v4.1.8: mirror stdout/stderr to logs/{challenge_name}/run.log
    log_path = _resolve_log_path(args)
    log_file = None
    old_stdout, old_stderr = sys.stdout, sys.stderr
    pwn_context = None
    old_pwn_log_console = None
    if log_path is not None:
        log_file = open(log_path, "w", encoding="utf-8")
        tee_stdout = Tee(sys.stdout, log_file)
        tee_stderr = Tee(sys.stderr, log_file)
        sys.stdout = tee_stdout
        sys.stderr = tee_stderr
        # pwntools' Handler.emit reads ``context.log_console`` at
        # emit time, but the value was captured at ``pwn`` import.
        # Override so pwntools' "[+] Starting local process" etc.
        # also land in the log file.  See pwnlib/log.py:521 and
        # pwnlib/context/__init__.py:367,1073.
        try:
            from pwnlib.context import context as _pwn_context
            pwn_context = _pwn_context
            old_pwn_log_console = _pwn_context.log_console
            _pwn_context.log_console = tee_stdout
        except ImportError:
            # pwntools not installed — nothing to do, our tee still
            # captures everything that uses sys.stdout/sys.stderr.
            pass

    try:
        print_banner()

        try:
            ctx = ExploitContext.from_args(args)
        except ContextError as e:
            print_error(str(e))
            return 1

        set_current_ctx(ctx)

        return orchestrator_run(ctx)
    finally:
        # v4.1.8: always restore streams + close log file, even on
        # exception / KeyboardInterrupt.
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        if pwn_context is not None and old_pwn_log_console is not None:
            try:
                pwn_context.log_console = old_pwn_log_console
            except Exception:
                pass
        if log_file is not None:
            try:
                log_file.flush()
                log_file.close()
            except Exception:
                pass


# Wire the legacy SystemExit translation for the `python autopwn.py`
# shim and `python -m autopwn` entry points — the orchestrator
# returns an int, but the conventional CLI contract is to exit
# with that code.  SystemExit also propagates cleanly through
# pytest (becomes a return code in the test runner).
if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main"]
