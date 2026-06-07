"""Unit tests for ``autopwn.primitives.ret2system`` (P6.2).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.2: every primitive
needs ``build_payload(ctx) -> bytes`` asserted against a
fake address.  P6.2 has 2 primitives (x32 + x64) so we
cover both happy path and edge cases (no system, no
gadgets, etc.).

Test plan
---------
* :class:`Ret2SystemX32` — uses real ``Challenge/fmtstr1``
  + ``Challenge/rip`` binaries (both have system + /bin/sh).
  Asserts the payload is exactly ``padding + 12`` bytes
  (3 little-endian 32-bit addresses).
* :class:`Ret2SystemX64` — uses real ``Challenge/pie`` binary
  (has system + /bin/sh) with a fake gadget context.  Asserts
  the payload is exactly ``padding + 32`` bytes (4 LE 64-bit
  addresses including the ``ret`` alignment gadget).
* Edge cases:
    * no system symbol → ``b""``
    * no ``/bin/sh`` → ``b""``
    * no gadgets_x64 (x64) → ``b""``
    * pop_rdi == 0 (x64) → ``b""``
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


class TestRet2SystemX32:
    """``primitives.ret2system.Ret2SystemX32`` — 32-bit ret2libc system."""

    def test_name_is_set(self):
        """Class attribute ``name`` is the canonical P7 registry string."""
        from autopwn.primitives.ret2system import Ret2SystemX32

        assert Ret2SystemX32.name == "ret2system-x32"

    def test_payload_length_is_padding_plus_12(self, challenge_dir):
        """Payload is ``padding + 12`` bytes (3 p32 addresses)."""
        from autopwn.primitives.ret2system import Ret2SystemX32

        # fmtstr1 has system + /bin/sh + typical buffer overflow.
        # v3.1 main() reaches padding=112 (4-byte aligned).
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 112
        payload = Ret2SystemX32().build_payload(ctx)
        assert len(payload) == 112 + 12
        # First 112 bytes are the padding
        assert payload[:112] == b"A" * 112
        # Next 12 bytes are 3 little-endian 32-bit addresses
        import struct
        system_addr, fake_ret, binsh_addr = struct.unpack("<III", payload[112:124])
        assert fake_ret == 0  # system() doesn't return
        assert system_addr != 0
        assert binsh_addr != 0

    def test_returns_empty_when_no_system_symbol(self, challenge_dir):
        """``b""`` when the binary has no ``system`` symbol (e.g. canary)."""
        from autopwn.primitives.ret2system import Ret2SystemX32

        # canary has stack protection but no /bin/sh string
        # and (depending on the build) no system symbol.
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.padding = 80
        payload = Ret2SystemX32().build_payload(ctx)
        # Empty when the primitive decides it's not applicable.
        assert payload == b""

    def test_works_on_rip(self, challenge_dir):
        """rip is a 32-bit binary exploitable by ret2system."""
        from autopwn.primitives.ret2system import Ret2SystemX32

        ctx = ctx_for("rip", bit=32)
        ctx.padding = 24
        payload = Ret2SystemX32().build_payload(ctx)
        # rip has system + /bin/sh, so payload must be non-empty.
        assert len(payload) == 24 + 12


class TestRet2SystemX64:
    """``primitives.ret2system.Ret2SystemX64`` — 64-bit ret2libc system."""

    def test_name_is_set(self):
        from autopwn.primitives.ret2system import Ret2SystemX64

        assert Ret2SystemX64.name == "ret2system-x64"

    def test_payload_length_is_padding_plus_32(self, challenge_dir):
        """Payload is ``padding + 32`` bytes (4 p64 addresses)."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2system import Ret2SystemX64

        # pie has system + /bin/sh.  Fake gadget addresses for
        # pop_rdi + ret so we don't depend on ropper output.
        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 48
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0x1234, pop_rsi=0, ret=0x5678,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2SystemX64().build_payload(ctx)
        # 48 padding + 32 (4 * p64) = 80
        assert len(payload) == 48 + 32
        # First 48 bytes are padding
        assert payload[:48] == b"A" * 48

    def test_payload_uses_fake_gadgets(self, challenge_dir):
        """The pop_rdi and ret fields from ctx end up in the payload."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2system import Ret2SystemX64

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xDEAD, pop_rsi=0, ret=0xBEEF,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2SystemX64().build_payload(ctx)
        # After 8 bytes of padding: pop_rdi (8B) + binsh (8B) +
        # ret (8B) + system (8B)
        import struct
        pop_rdi, binsh, ret, system = struct.unpack("<4Q", payload[8:40])
        assert pop_rdi == 0xDEAD
        assert ret == 0xBEEF
        # binsh and system come from the binary — both non-zero
        # for pie (which has /bin/sh + imports system)
        assert binsh != 0
        assert system != 0

    def test_returns_empty_without_gadgets(self, challenge_dir):
        """``b""`` when ``ctx.gadgets_x64`` is ``None``."""
        from autopwn.primitives.ret2system import Ret2SystemX64

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 48
        ctx.gadgets_x64 = None  # default
        payload = Ret2SystemX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_with_zero_gadgets(self, challenge_dir):
        """``b""`` when ``pop_rdi`` or ``ret`` is 0."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2system import Ret2SystemX64

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 48
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0, pop_rsi=0, ret=0,  # all zero
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2SystemX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_for_canary(self, challenge_dir):
        """canary has no system + no /bin/sh → ``b""``."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2system import Ret2SystemX64

        ctx = ctx_for("canary", bit=32, stack_canary=True)  # canary is 32-bit
        ctx.padding = 80
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0x1234, pop_rsi=0, ret=0x5678,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2SystemX64().build_payload(ctx)
        # canary is 32-bit + has no system → empty
        assert payload == b""
