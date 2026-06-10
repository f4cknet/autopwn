"""AutoPwn shell verification helper (P11.6 / v4.0.1).

Per ``upgraded.md`` §3.1 v4.0.1: replace the v3.1 ``io.interactive()``
success signal with a real shell-availability probe.  The
prior behavior (still preserved as a banner) was::

    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()   # blocks waiting for stdin; in run_verify.sh
                       # (no stdin) this raises immediately

That made every primitive report SUCCESS even when the spawned
process died before ``system("/bin/sh")`` could run.  This
module replaces that signal with a 2-second ``id``-command probe:

    >>> io = process(program)
    >>> io.sendline(payload)
    >>> ok, id_output = verify_shell(io, timeout=2.0)
    >>> if ok:
    ...     print("real shell acquired: " + id_output.strip())
    ... else:
    ...     print("exploit failed; no id output")

Design notes
------------
* The function takes a pwntools tube (``io``) — it is agnostic to
  whether the tube is a local ``process`` or a ``remote``.  This
  keeps the helper usable from any strategy.
* The helper swallows all pwntools errors (EOFError, OSError) and
  returns ``(False, "")``.  Callers MUST check the boolean — never
  infer success from a non-empty ``id_output`` (an attacker can
  echo ``uid=0`` to a dead shell).
* The timeout default (2.0s) is intentionally short — successful
  ``system("/bin/sh")`` + ``id`` should complete in < 100ms; the
  extra headroom tolerates scheduler jitter.  Longer timeouts make
  ``run_verify.sh`` slow without adding real signal.
"""
from __future__ import annotations

from typing import Tuple


def verify_shell(io, timeout: float = 2.0) -> Tuple[bool, str]:
    """Probe whether ``io`` has a real shell by running ``id``.

    Sends ``id\\n`` and reads until the line containing ``uid=`` or
    the timeout elapses.  Returns ``(True, <line>)`` only when
    ``uid=`` appears in the captured output.

    Args:
        io: a pwntools tube (``pwn.process`` / ``pwn.remote`` / etc).
        timeout: seconds to wait for ``uid=``.  Default 2.0s.

    Returns:
        ``(True, "uid=0(root) gid=0(root) ..." )`` on success.
        ``(False, "")`` on any failure (EOF, timeout, OSError).

    Implementation note:
        We use ``recvuntil(b"uid=", timeout=timeout)`` rather than
        ``recvline(timeout=...)`` to tolerate the trailing prompt
        / banner that ``/bin/sh`` may print on the first call.
    """
    try:
        # Drain any banner the shell printed on connect (e.g. ``$``).
        try:
            io.recv(timeout=0.1)
        except Exception:
            pass

        # Send the probe command.
        io.sendline(b"id")

        # Wait for ``uid=`` in the output.
        try:
            io.recvuntil(b"uid=", timeout=timeout)
            line = io.recvline(timeout=timeout)
        except Exception:
            return (False, "")

        if not line:
            return (False, "")

        id_output = b"uid=" + line
        return (True, id_output.decode(errors="replace"))
    except Exception:
        return (False, "")
    finally:
        # Best-effort cleanup: close the tube so the test runner can
        # move on.  If the caller wants to keep the shell open for
        # manual interaction, it should not call this helper.
        try:
            io.close()
        except Exception:
            pass


__all__ = ["verify_shell"]
