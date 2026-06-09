"""AutoPwn CLI — modern entry point (P0.0 shim + P8.3 orchestrator dispatch).

v4 起所有命令行入口都走这里：
  - `python autopwn.py` (shim) → from autopwn.cli import main
  - `python -m autopwn`        → from autopwn.cli import main
  - `autopwn` (after pip install) → autopwn.cli:main (console_scripts)

P8.3 (this version): ``main()`` is reduced to a thin wrapper that
parses args, builds the typed :class:`ExploitContext`, and hands
control to :func:`autopwn.orchestrator.run`.  All decision-tree
logic (recon → detect → strategy selection) lives in
:mod:`autopwn.orchestrator`; the legacy ``autopwn._legacy.main``
remains the v3.1 fallback for the ``autopwn.py`` shim until P8.6
deletes the shim entirely.
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys

from autopwn._compat import sync_ctx_to_legacy
from autopwn.context import ContextError, ExploitContext
from autopwn.core.logging import print_banner, print_error, set_verbose
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
    return parser


def main() -> int:
    """CLI entry point: parse args → build ctx → dispatch to orchestrator.

    Returns the orchestrator's exit code (0 on successful
    exploitation, 1 on failure).  Does NOT call :func:`sys.exit`
    — the wrapper (autopwn.py shim, ``python -m autopwn``) does
    the ``raise SystemExit`` translation.  Per
    ``refactor.md`` §11 R1 + §6.8 Reviewer checklist.

    Side effects (in order):
      1. ``print_banner()`` — startup banner.
      2. ``set_verbose(args.verbose)`` — propagate ``-v`` to
         :mod:`autopwn.core.logging`.
      3. ``ExploitContext.from_args(args)`` — typed context with
         validation (binary exists, ip+port pair consistency,
         libc path exists).  Raises :class:`ContextError` on
         failure; we catch it and exit 1 with the legacy red
         error message.
      4. ``set_current_ctx(ctx)`` + ``sync_ctx_to_legacy(...)`` —
         wire the bridge so the legacy ``_compat.record_success``
         and downstream report readers can find the ctx fields.
         Kept for P2.3/P2.4/P3.5 backward compatibility until
         P8.5 deletes ``_compat.py`` entirely.
      5. ``orchestrator_run(ctx)`` — recon + detect + strategy.
    """
    print_banner()

    args = _build_argparser().parse_args()

    set_verbose(args.verbose)

    try:
        ctx = ExploitContext.from_args(args)
    except ContextError as e:
        print_error(str(e))
        return 1

    set_current_ctx(ctx)
    sync_ctx_to_legacy(
        ctx,
        target_name=os.path.basename(args.local),
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    return orchestrator_run(ctx)


# Wire the legacy SystemExit translation for the `python autopwn.py`
# shim and `python -m autopwn` entry points — the orchestrator
# returns an int, but the conventional CLI contract is to exit
# with that code.  SystemExit also propagates cleanly through
# pytest (becomes a return code in the test runner).
if __name__ == "__main__":
    sys.exit(main())


__all__ = ["main"]
