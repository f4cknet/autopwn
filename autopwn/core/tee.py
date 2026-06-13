"""core.tee — file-like writer that mirrors output to multiple streams.

v4.1.8: Used by :mod:`autopwn.cli` to mirror ``sys.stdout`` /
``sys.stderr`` to both the terminal **and** a per-run log file at
``logs/{challenge_name}/run.log`` (see ``upgraded.md`` §3.2 v4.1.8).

Why a separate module
---------------------
:mod:`autopwn.core.logging` is imported throughout the project (CLI,
orchestrator, strategies).  Adding a ``Tee`` class there would couple
a low-level writer primitive to the print-style API surface.  A
dedicated module keeps the dependency direction clean: ``cli`` →
``core.tee`` → stdlib only.

Why not use :mod:`contextlib`'s ``redirect_stdout``
---------------------------------------------------
``contextlib.redirect_stdout`` swaps the stream for the duration of a
``with`` block and does **not** display in the terminal.  We need a
*tee* (write to BOTH terminal and file), not a redirect.  Hence the
explicit :class:`Tee` class below.

ANSI / color codes
------------------
v4.1.8 keeps ANSI escape codes in the log file (the user reads it
with ``cat`` / ``less -R`` to reproduce the terminal display).  Strip
colors only if a future task (``v4.1.8b``) needs machine-grep friendly
plain-text logs.

Layer: core (no upward dependency).
"""
from __future__ import annotations

from typing import IO, Iterable


class Tee:
    """File-like object that writes to multiple underlying streams.

    All ``write()`` calls are forwarded to each registered stream in
    order.  ``flush()`` is forwarded as well.  Attributes not handled
    explicitly (e.g. ``encoding``, ``newlines``) are transparently
    delegated to the first underlying stream so downstream code that
    introspects the stream (e.g. ``hasattr(sys.stdout, 'encoding')``)
    keeps working.

    Parameters
    ----------
    *streams : IO[str]
        Underlying streams to mirror writes to.  Must be writable
        text streams (``sys.stdout``, an open file handle, an
        :class:`io.StringIO`, etc.).

    Examples
    --------
    >>> import io, sys
    >>> buf = io.StringIO()
    >>> tee = Tee(sys.stdout, buf)
    >>> _ = tee.write("hello\\n")
    >>> "hello" in buf.getvalue()
    True

    v4.1.8 typical use (cli.py main())::

        log_file = open("logs/rip/run.log", "w", encoding="utf-8")
        sys.stdout = Tee(sys.stdout, log_file)
        sys.stderr = Tee(sys.stderr, log_file)
        try:
            ...  # run autopwn
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
            log_file.close()
    """

    def __init__(self, *streams: IO[str]) -> None:
        if not streams:
            raise ValueError("Tee requires at least one underlying stream")
        self._streams: tuple[IO[str], ...] = streams

    def write(self, data) -> int:
        """Write ``data`` to all streams.  Returns the length written.

        A failure in one underlying stream does not abort writes to
        the others (best-effort).  This matches the legacy
        ``print(*, file=...)`` semantics where the kernel will simply
        discard the write if the fd is closed.
        """
        if not isinstance(data, str):
            data = str(data)
        n = len(data)
        for s in self._streams:
            try:
                s.write(data)
            except Exception:
                # Don't let one stream's failure break the others
                # (e.g. file handle closed during shutdown).
                pass
        return n

    def flush(self) -> None:
        """Flush all underlying streams (best-effort)."""
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass

    def isatty(self) -> bool:
        """``True`` if **any** underlying stream is a TTY.

        Used by pwntools / argparse / click-style code that disables
        color / progress bars when not on a TTY.  Returning ``True``
        when at least one stream is interactive preserves the
        terminal's "live" feel.
        """
        for s in self._streams:
            isatty = getattr(s, "isatty", None)
            if isatty is not None:
                try:
                    if isatty():
                        return True
                except Exception:
                    continue
        return False

    def fileno(self) -> int:
        """File descriptor of the first stream that has ``fileno()``.

        Some libraries (e.g. subprocess, pwntools ``process``) need a
        real fd.  We delegate to the first underlying stream that
        exposes one.
        """
        for s in self._streams:
            fileno = getattr(s, "fileno", None)
            if fileno is None:
                continue
            try:
                return fileno()
            except Exception:
                continue
        raise OSError(9, "Tee: no underlying stream exposes fileno()")

    def __getattr__(self, name: str):
        """Delegate unknown attribute access to the first stream.

        This keeps ``sys.stdout.encoding`` / ``sys.stdout.newlines`` /
        etc. working transparently for introspection.
        """
        # __getattr__ is only called for attributes NOT found on the
        # instance — so we won't shadow write/flush/isatty/fileno
        # defined above.  Iterate streams in order, return the first
        # that has the attribute.
        for s in self._streams:
            if hasattr(s, name):
                return getattr(s, name)
        raise AttributeError(
            f"Tee has no attribute {name!r} (none of {len(self._streams)} "
            f"underlying streams expose it)"
        )


__all__ = ["Tee"]
