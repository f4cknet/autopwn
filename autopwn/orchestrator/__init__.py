"""AutoPwn orchestrator — recon + detect + strategy phase scheduler (P8.1 + P8.2).

P11.5 (2026-06-10) refactored this module from a single 361-line
file into a 4-file subpackage:

  * ``orchestrator/recon.py``    — Phase 1: run_recon_phase
  * ``orchestrator/detect.py``   — Phase 2: run_detect_phase
  * ``orchestrator/strategy.py`` — Phase 3: run_strategy_phase
  * ``orchestrator/__init__.py`` — re-exports + top-level run()

The public API is **unchanged** — ``from autopwn.orchestrator
import run`` still works, as does importing the individual
phase functions.  Log markers and behaviour are preserved
bit-for-bit per the §2.6 baseline requirement.

Replaces the v3.1 monolith's ``main()`` decision tree
(``autopwn/_legacy.py`` L3016-3479) with a phase-separated,
strategy-driven exploitation flow.  Per ``rebuild.md`` §6.9
P8.1 / P8.2 + ``refactor.md`` §3.2.2 + §11 R1 mitigation:
**the orchestrator has no specific strategy names**; strategy
selection is driven entirely by
:func:`autopwn.exp.registry.candidates` which sorts by
:attr:`ExploitStrategy.priority`.

Public API
----------
* :func:`run` — top-level entry: takes a fully populated
  :class:`ExploitContext`, runs the three phases, returns ``0``
  on successful exploitation and ``1`` on failure.
* :func:`run_recon_phase` — Phase 1: ``recon/`` modules populate
  ``ctx.binary`` / ``ctx.libc`` / ``ctx.has_*`` / ``ctx.gadgets_*``.
* :func:`run_detect_phase` — Phase 2: ``detect/`` modules populate
  ``ctx.binsh_in_binary`` / ``ctx.canary`` / ``ctx.padding``.
* :func:`run_strategy_phase` — Phase 3: iterate
  :func:`autopwn.exp.registry.candidates` and call ``strat.run``
  on each; first ``True`` wins.

Design notes
------------
* **Phase separation matches refactor.md §3.2.1 dependency graph**:
  Phase 1 depends only on ``recon/`` (read-only binary probes);
  Phase 2 depends only on ``detect/`` (read+write ctx);
  Phase 3 depends only on ``exp/`` (read ctx, spawn exploit).
* **No ``sys.exit(0)`` in the orchestrator**: ``run()`` returns an
  int (0 or 1) and lets ``cli.py`` decide the process exit code.
* **Log marker preservation** (``rebuild.md`` §6.9 P8.4 acceptance):
  the orchestrator emits the same section headers that v3.1's
  main() does (BINARY ANALYSIS PHASE, FUNCTION ANALYSIS,
  ROP GADGET DISCOVERY, PADDING CALCULATION, STRING ANALYSIS,
  CANARY PROTECTION DETECTED, EXPLOITATION PHASE).
"""
from __future__ import annotations

from autopwn.context import ExploitContext

from autopwn.orchestrator.recon import run_recon_phase
from autopwn.orchestrator.detect import run_detect_phase
from autopwn.orchestrator.strategy import run_strategy_phase


def run(ctx: ExploitContext) -> int:
    """Top-level orchestrator entry point.

    Runs the three phases in order:

    1. :func:`run_recon_phase` — populate the binary's static profile.
    2. :func:`run_detect_phase` — populate the binary's vulnerability profile.
    3. :func:`run_strategy_phase` — try each priority-sorted candidate.

    Returns the strategy-phase exit code (``0`` on success, ``1``
    on failure).  Does NOT call :func:`sys.exit` — the caller
    (``cli.py``) decides the process exit code (per
    ``refactor.md`` §11 R1 + §6.9 P8.3 spec).

    Args:
        ctx: a fully populated :class:`ExploitContext` (typically
            built by ``ExploitContext.from_args(args)`` in cli.py).

    Returns:
        ``0`` on successful exploitation; ``1`` otherwise.
    """
    run_recon_phase(ctx)
    run_detect_phase(ctx)
    return run_strategy_phase(ctx)


__all__ = [
    "run",
    "run_recon_phase",
    "run_detect_phase",
    "run_strategy_phase",
]
