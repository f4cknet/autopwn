"""AutoPwn primitives layer: base abstract class + result dataclass (P6.1).

Replaces the v3.1 monolith's ad-hoc "build payload" code blocks
embedded inside the 30+ exploitation functions (see
``autopwn/_legacy.py`` L1590-2280 area) with two typed
abstractions in ``primitives/base.py``:

  * :class:`ExploitPrimitive` — ABC every payload builder
    subclasses.  Carries a ``name`` class attribute
    (for P7 registry / log lines), an abstract
    ``build_payload(ctx)`` method, and a ``stage_count()``
    hook for the 2-stage ret2libc primitives
    (P6.3 / P6.4) that need a "leak first, then return"
    flow.
  * :class:`ExploitResult` — frozen dataclass holding the
    primitive's output: ``success`` (bool) + ``payload`` (bytes).
    P7 strategies consume ``ExploitResult`` and dispatch the
    payload to the target binary.

Per ``rebuild.md`` §6.7 P6.1 + ``refactor.md`` §3.2.2
primitives-contract, this is the foundation of the P6 layer
(M3 milestone).  P6.2-P6.8 will subclass :class:`ExploitPrimitive`
with concrete payload builders (``Ret2SystemX32`` /
``Ret2SystemX64`` / ``Ret2LibcPutX32`` / ...).

Design notes
------------
* **Pure-function contract** (no *side effects*): subclasses
  of :class:`ExploitPrimitive` MUST NOT spawn processes, write
  files, mutate :class:`ExploitContext`, or call
  ``interactive()``.  ``build_payload`` takes a fully populated
  :class:`ExploitContext` and returns ``bytes``.

  Read-only file access (e.g. ``ELF(path).symbols['system']``)
  is allowed and expected — pwntools' ``ELF`` class is the
  canonical way to look up symbol addresses inside a binary.
  P7 strategies handle process spawn, payload transmission,
  and response parsing.
* **Single-dependency direction**: primitives may import from
  ``autopwn.context`` (model layer) but **NOT** from
  ``autopwn.exp`` (strategies layer).  Enforced by §6.7
  Reviewer checklist.
* **Stage count is a method, not a class attribute**, so
  subclasses can override it dynamically if needed (e.g. a
  future primitive might stage based on ``ctx`` state).
  Default is 1; the ret2libc primitives (P6.3/P6.4) override
  to 2.
* :class:`ExploitResult` is a ``@dataclass(slots=True)`` per
  the P2.1 project convention (``context.py`` module
  docstring).  v3.1 used a hand-rolled ``__init__`` (see
  ``rebuild.md`` §6.7 P6.1 spec snippet) but the dataclass
  form is byte-equivalent at the API level and adds
  ``__repr__`` / ``__eq__`` for free.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from autopwn.context import ExploitContext


class ExploitPrimitive(ABC):
    """Abstract base for every payload builder in the P6 layer.

    Carries a human-readable ``name`` (used by P7 registry and
    log lines), an abstract :meth:`build_payload` method
    (subclasses implement this), and a :meth:`stage_count`
    hook (default 1; overridden by the 2-stage ret2libc
    primitives in P6.3 / P6.4).

    The ABC contract is intentionally minimal — subclasses
    are expected to read all needed state from the passed
    :class:`ExploitContext` and return ``bytes`` only.  No
    globals, no I/O, no file writes.

    Class attributes
    ---------------
    name : str
        Human-readable name (e.g. ``"ret2system-x32"``).
        P7's :func:`exp.registry.candidates` uses this to
        print "trying <name>" log lines.  Subclasses MUST
        set this to a non-empty string.
    """

    name: str = ""

    @abstractmethod
    def build_payload(self, ctx: ExploitContext) -> bytes:
        """Build the exploitation payload for the given run context.

        Args:
            ctx: a fully populated :class:`ExploitContext`
                (binary info, libc, gadgets, padding, etc.).
                The primitive reads fields from ``ctx`` but
                does **not** mutate it.

        Returns:
            The payload bytes (padding + return addresses +
            arguments + shellcode).  Empty bytes (``b""``)
            is a valid return when the primitive decides
            the target is not exploitable with its technique
            (e.g. ``has_system=False``); P7's strategy will
            then move on to the next candidate.

        Notes:
            This method MUST be pure: no subprocess, no file
            I/O, no ``interactive()``.  All I/O is the
            caller's responsibility.
        """
        raise NotImplementedError

    def stage_count(self) -> int:
        """Return the number of stages this primitive needs.

        Default 1 (single payload).  Override to 2 in
        primitives that need a "leak-then-return" flow
        (e.g. the ret2libc primitives in P6.3 / P6.4 that
        first leak a libc address via ``write``/``puts``,
        then return to a one-gadget / system + ``/bin/sh``).
        The P7 orchestrator uses this to allocate the
        right number of ``io.sendline`` calls.
        """
        return 1


@dataclass(slots=True)
class ExploitResult:
    """The output of a primitive + the strategy's verdict.

    ``success`` is ``True`` when the strategy's ``run(ctx)``
    finished without error and the binary produced a shell /
    flag / response.  ``payload`` is the bytes that were
    sent (empty for strategies that don't send anything, e.g.
    a pure format-string leak).

    The dataclass form (``@dataclass(slots=True)``) is byte-
    equivalent to v3.1's hand-rolled ``__init__`` (see
    ``rebuild.md`` §6.7 P6.1 spec) and adds ``__repr__`` /
    ``__eq__`` for free, which simplifies P7's registry
    log lines and P9's test assertions.
    """

    success: bool
    payload: bytes = b""


__all__ = [
    "ExploitPrimitive",
    "ExploitResult",
]
