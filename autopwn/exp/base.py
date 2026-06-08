"""AutoPwn strategies layer: base abstract class (P7.1).

Replaces the v3.1 monolith's if/elif decision tree in
``autopwn/_legacy.py`` ``main()`` (L3316-3720 area) with a
:class:`ExploitStrategy` ABC + ``@register`` registry pattern
(see :mod:`autopwn.exp.registry`, P7.2).

Per ``rebuild.md`` §6.8 P7.1 + ``refactor.md`` §3.2.2,
:class:`ExploitStrategy` carries:

  * A human-readable ``name`` (used by orchestrator log lines
    and the P9 registry test).
  * A numeric ``priority`` — higher wins; the orchestrator
    iterates :func:`exp.registry.candidates` in priority order.
  * Declarative ``requires_*`` metadata — bit-width, mode,
    canary-presence, and a tuple of ctx-flag names — that the
    default :meth:`matches` implementation uses to filter
    strategies for a given :class:`ExploitContext`.  Subclasses
    **MUST** override at least the relevant subset (don't set
    ``requires_arch`` if the strategy works on both bitnesses).
  * An abstract :meth:`run` that takes a fully populated
    :class:`ExploitContext` and returns ``True`` on success
    (shell / flag / response received), ``False`` on
    non-fatal failure (move to the next candidate).

Design notes
------------
* **Pure-metadata contract** (no side effects on import): the
  ABC declares metadata only.  Subclasses hold pwntools
  imports (``from pwn import process, remote``) lazily inside
  :meth:`run` to keep :mod:`autopwn.exp` importable on
  environments without pwntools installed (e.g. CI lint).
* **Single-dependency direction**: strategies may import from
  :mod:`autopwn.context` and :mod:`autopwn.primitives` (and
  the pwntools family) but **NOT** from :mod:`autopwn.recon` /
  :mod:`autopwn.detect` — those layers are orchestrator-only.
  Enforced by §6.8 Reviewer checklist + refactor.md §3.1.
* **No pwntools import at module level**: the v3.1 spec
  snippet had a stray ``from pwntools import process, remote``
  line — that's a typo (``pwntools`` is a meta-package; the
  actual import is ``from pwn import process, remote``), and
  base.py has no need for it.  Strategies (P7.3+) import
  pwntools in their own ``run()`` method or at file top.
* **No interactive / no sys.exit in run()**: strategies
  return ``bool``; the orchestrator handles
  ``interactive()``, ``record_success``, and process exit
  codes.  Enforced by §6.8 Reviewer checklist + refactor.md
  §11 R1.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from autopwn.context import ExploitContext

if TYPE_CHECKING:
    # Imported only for type hints — the runtime class object
    # is a metadata slot; subclasses set ``primitive = Ret2SystemX32``
    # (or leave it ``None``).  TYPE_CHECKING avoids the runtime
    # import of primitives (which transitively imports pwntools).
    from autopwn.primitives.base import ExploitPrimitive


class ExploitStrategy(ABC):
    """Abstract base for every exploitation strategy in the P7 layer.

    Strategies are registered via the :func:`@register <autopwn.exp.registry.register>`
    decorator at import time.  The orchestrator (P8.2) calls
    :func:`autopwn.exp.registry.candidates` to get a
    priority-sorted list of strategies that match the current
    context, then iterates ``for strat in candidates(ctx): if
    strat.run(ctx): return 0``.

    The default :meth:`matches` implementation is a pure-function
    filter on the declarative ``requires_*`` class attributes —
    subclasses MAY override for non-declarative cases (e.g. a
    custom libc-version probe) but the default covers ~95% of
    v3.1's branching.

    Class attributes
    ----------------
    name : str
        Human-readable strategy name (e.g. ``"ret2system-x32"``).
        Used by the orchestrator's "trying <name>" log line
        and by the P9 registry test.  **MUST** be overridden
        by subclasses to a non-empty string.
    priority : int
        Higher = tried first.  See ``rebuild.md`` §11 附录 A
        (decision-tree priority table) for canonical values:
        canary=200, pie_backdoor=180, ret2system=150, ret2libc_put=120,
        ret2libc_write=110, rwx_shellcode=90, execve_syscall=80,
        fmtstr=50.  Subclasses MUST pick a value from this
        table (or justify a new one in the PR description).
    requires_canary : bool
        If ``True``, :meth:`matches` returns ``False`` when
        ``ctx.canary is None`` (i.e. the binary has no canary
        or it wasn't leaked).  Default ``False``.
    requires_remote : bool | None
        If ``True``, strategy only matches when ``ctx.mode ==
        "remote"``; if ``False``, only when ``ctx.mode ==
        "local"``; if ``None`` (default), both are accepted.
    requires_arch : int | None
        If set to 32 or 64, :meth:`matches` only returns
        ``True`` when ``ctx.binary.bit`` matches.  Default
        ``None`` (strategy is arch-agnostic — rare; almost
        all strategies are x32-only or x64-only).
    requires : tuple[str, ...]
        Tuple of :class:`ExploitContext` attribute names that
        MUST be truthy for the strategy to apply.  Example:
        ``requires = ("has_system", "binsh_in_binary")`` for
        ret2system.  Default empty tuple.  See
        ``rebuild.md`` §11 附录 A for canonical combinations.
    primitive : type[ExploitPrimitive] | None
        Optional link to a payload builder.  Used by the
        orchestrator (P8) to call ``primitive().build_payload(ctx)``
        when the strategy doesn't override :meth:`run`
        (degenerate case — most strategies will fully
        implement :meth:`run` themselves).  Default ``None``.

    Abstract methods
    ----------------
    run(ctx) -> bool
        Execute the exploitation.  Returns ``True`` on
        success (shell obtained / flag read / response
        received), ``False`` on non-fatal failure (the
        orchestrator moves to the next candidate).
    """

    name: str = ""
    priority: int = 0

    requires_canary: bool = False
    requires_remote: bool | None = None
    requires_arch: int | None = None
    requires: tuple[str, ...] = ()
    primitive: "type[ExploitPrimitive] | None" = None

    @abstractmethod
    def run(self, ctx: ExploitContext) -> bool:
        """Execute the exploitation strategy against ``ctx``.

        Args:
            ctx: a fully populated :class:`ExploitContext`
                (binary, libc, gadgets, padding, canary,
                PLT flags, etc.).  Strategies MAY mutate
                ``ctx.last_exploit`` (set by the
                orchestrator on success), but MUST NOT
                mutate recon / detect fields (those are
                orchestrator-managed).

        Returns:
            ``True`` if the exploitation succeeded (shell
            obtained, flag read, or response received).
            ``False`` if the strategy cannot exploit the
            target (e.g. a required ctx field changed since
            ``matches()`` was called, or the payload didn't
            trigger the expected behaviour).

        Notes:
            * Strategies MUST NOT call :func:`sys.exit` —
              return a bool and let the orchestrator decide
              the process exit code.  Enforced by §6.8
              Reviewer checklist.
            * Strategies MUST NOT call :meth:`io.interactive`
              unconditionally — only on success.  Enforced
              by the orchestrator's ``if strat.run(ctx):
              return 0`` flow.
            * Strategies SHOULD print status via
              :meth:`ExploitContext.log` (e.g. ``ctx.log("...``),
              not via :mod:`autopwn.core.logging` directly —
              keeps the strategy decoupled from output
              formatting.
        """
        raise NotImplementedError

    def matches(self, ctx: ExploitContext) -> bool:
        """Return ``True`` iff this strategy can exploit ``ctx``.

        Pure-function filter on the ``requires_*`` metadata:

          1. ``requires_arch`` — bit-width match (None = any).
          2. ``requires_remote`` — local / remote match
             (None = any).
          3. ``requires_canary`` — ctx.canary must be set.
          4. ``requires`` tuple — every named attribute of
             ``ctx`` MUST be truthy.

        Subclasses MAY override to add non-declarative checks
        (e.g. "libc version >= 2.27" for one_gadget).  When
        overriding, call ``super().matches(ctx)`` first to
        keep the declarative filter, then add custom
        boolean logic.

        Args:
            ctx: a fully populated :class:`ExploitContext`.

        Returns:
            ``True`` iff all declarative requirements are
            met.  Used by
            :func:`autopwn.exp.registry.candidates` to filter
            the strategy list before sorting by ``priority``.
        """
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        if self.requires_canary and ctx.canary is None:
            return False
        return all(getattr(ctx, key) for key in self.requires)

    def __repr__(self) -> str:
        """Canonical repr for log lines and P9 registry tests.

        Format: ``<ClassName>(name='<name>', priority=<n>, arch=<n|None>, remote=<T|F|None>)``
        — concise but includes the four metadata fields most
        useful for debugging the candidate order.
        """
        return (
            f"{type(self).__name__}("
            f"name={self.name!r}, "
            f"priority={self.priority}, "
            f"arch={self.requires_arch!r}, "
            f"remote={self.requires_remote!r})"
        )


__all__ = [
    "ExploitStrategy",
]
