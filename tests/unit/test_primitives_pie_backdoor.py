"""Unit tests for ``autopwn.primitives.pie_backdoor`` (P6.8).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.8: every primitive needs
``build_payload(ctx) -> bytes`` asserted against a fake
address.  P6.8 has 1 primitive (``PieBackdoor``) that is
**bit-width-agnostic** (v3.1 uses p64 universally; the NUL-
stripping collapses x32/x64 PIE addresses to the same form).

The payload shape::

    [asm("nop") * padding] [cleaned_backdoor_bytes]

Where ``cleaned_backdoor_bytes`` is ``p64(backdoor_addr)`` with
embedded NUL bytes stripped.  For ``Challenge/pie``'s backdoor
at ``0x9c5`` (``symbols['backdoor'] + 0x04``), the cleaned
form is ``b'\\xc5\\x09'`` (2 bytes — the leading NULs are
stripped).

Test plan
---------
* :class:`PieBackdoor`:
    * ``name`` + ``stage_count()`` = 1 (single-stage; strategy
      handles the brute-force loop separately)
    * Subclass of :class:`ExploitPrimitive` + re-exported from
      ``autopwn.primitives``
    * Non-PIE binary → ``b""``
    * PIE but no ``has_backdoor`` / ``has_callsystem`` → ``b""``
    * ``padding == 0`` → ``b""``
    * ``padding < 0`` → ``b""``
    * Happy path (pie, has_backdoor, padding=80):
      - payload length = 80 + 2 (0xc5, 0x09) = 82
      - first 80 bytes are NOPs (0x90)
      - last 2 bytes are ``b'\\xc5\\x09'``
    * ``has_callsystem`` wins over ``has_backdoor`` (mirrors v3.1
      L1451-1452; callsystem check runs second, overwriting)
* :func:`_lookup_backdoor_addr`:
    * Neither flag → ``None``
    * has_backdoor only → returns ``symbols['backdoor'] + 4``
    * has_callsystem only → returns ``symbols['callsystem'] + 4``
    * Binary missing symbol → ``None``
* Real-binary smoke: 5 Challenge/ binaries
    * Only ``pie`` has the backdoor symbol; all others
      should return ``b""``
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Challenge/pie's backdoor symbol is at 0x9c1; legacy adds 0x04
# for the prologue skip, so the runtime backdoor address is
# 0x9c5.  p64(0x9c5) = b'\\xc5\\x09\\x00\\x00\\x00\\x00\\x00\\x00';
# after NUL-strip, b'\\xc5\\x09' (2 bytes).
_FAKE_PIE_PADDING = 80
_FAKE_PIE_BACKDOOR_TAIL = b"\xc5\x09"  # == 0x9c5 with NULs stripped
_FAKE_PIE_BACKDOOR_TAIL_LEN = len(_FAKE_PIE_BACKDOOR_TAIL)


class TestPieBackdoorMetadata:
    """Class-level invariants for ``PieBackdoor``."""

    def test_name_is_canonical(self):
        from autopwn.primitives.pie_backdoor import PieBackdoor

        assert PieBackdoor.name == "pie-backdoor"

    def test_stage_count_is_one(self):
        """PIE backdoor is single-stage — the strategy handles the
        brute-force loop separately, not the primitive."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        assert PieBackdoor().stage_count() == 1

    def test_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.pie_backdoor import PieBackdoor

        assert issubclass(PieBackdoor, ExploitPrimitive)

    def test_re_exported_from_primitives_package(self):
        from autopwn.primitives import PieBackdoor as Re

        from autopwn.primitives.pie_backdoor import PieBackdoor

        assert Re is PieBackdoor

    def test_in_primitives_all(self):
        from autopwn.primitives import __all__

        assert "PieBackdoor" in __all__


class TestPieBackdoorPayload:
    """``PieBackdoor.build_payload(ctx)`` happy-path and edge cases."""

    def test_happy_path_payload_shape(self, challenge_dir):
        """PIE + has_backdoor + padding=80 → 80 nops + 2 cleaned bytes = 82 bytes."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = _FAKE_PIE_PADDING
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert len(payload) == _FAKE_PIE_PADDING + _FAKE_PIE_BACKDOOR_TAIL_LEN
        assert len(payload) == 82
        # First 80 bytes are NOPs (asm("nop") == 0x90)
        assert payload[:_FAKE_PIE_PADDING] == b"\x90" * _FAKE_PIE_PADDING
        # Last 2 bytes are the cleaned backdoor address (0x9c5 → b'\\xc5\\x09')
        assert payload[_FAKE_PIE_PADDING:] == _FAKE_PIE_BACKDOOR_TAIL

    def test_returns_empty_for_non_pie_binary(self):
        """Non-PIE binary → ``b""`` (PIE is a hard gate)."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        # canary/fmtstr1/level3_x64/rip are all non-PIE; pick canary
        ctx = ctx_for("canary", bit=32, pie=False)
        ctx.padding = 80
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_neither_backdoor_nor_callsystem(self):
        """PIE but no has_backdoor/has_callsystem → ``b""``."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 80
        ctx.has_backdoor = False
        ctx.has_callsystem = False
        payload = PieBackdoor().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_padding_is_zero(self):
        """``padding == 0`` → ``b""`` (no BOF offset to slide nops into)."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 0
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_padding_is_negative(self):
        """``padding < 0`` → ``b""``."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = -10
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert payload == b""

    def test_padding_2(self):
        """Tiny padding=2 → 2 nops + 2 cleaned bytes = 4 bytes total."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 2
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert len(payload) == 4
        assert payload[:2] == b"\x90\x90"
        assert payload[2:] == _FAKE_PIE_BACKDOOR_TAIL

    def test_padding_200(self):
        """Large padding=200 → 200 nops + 2 cleaned bytes = 202 bytes total."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.padding = 200
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        assert len(payload) == 202
        assert payload[:200] == b"\x90" * 200
        assert payload[200:] == _FAKE_PIE_BACKDOOR_TAIL


class TestLookupBackdoorAddr:
    """``_lookup_backdoor_addr(ctx)`` returns the backdoor address."""

    def test_returns_none_when_neither_flag(self):
        from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.has_backdoor = False
        ctx.has_callsystem = False
        assert _lookup_backdoor_addr(ctx) is None

    def test_returns_backdoor_addr_when_has_backdoor(self):
        from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.has_backdoor = True
        ctx.has_callsystem = False
        addr = _lookup_backdoor_addr(ctx)
        # pie's backdoor is at 0x9c1; + 0x04 = 0x9c5
        assert addr == 0x9c1 + 0x04

    def test_callsystem_wins_over_backdoor(self):
        """``has_callsystem`` takes priority over ``has_backdoor`` (v3.1 behavior).

        When the binary doesn't have a ``callsystem`` symbol,
        ``_lookup_backdoor_addr`` returns ``None`` (matches v3.1's
        implicit KeyError fallback).  This is a quirk of v3.1's
        code where the second ``if`` overwrites the first; the
        primitive preserves it 1:1.
        """
        from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

        ctx = ctx_for("pie", bit=64, pie=True)
        ctx.has_backdoor = True
        ctx.has_callsystem = True
        # Challenge/pie has NO 'callsystem' symbol → KeyError
        # → _lookup_backdoor_addr returns None (consistent with v3.1)
        assert _lookup_backdoor_addr(ctx) is None

    def test_returns_none_when_binary_missing_symbol(self):
        """Non-pie binary has no backdoor symbol → ``None``."""
        from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

        ctx = ctx_for("canary", bit=32, pie=False)
        ctx.has_backdoor = True
        ctx.has_callsystem = False
        # canary has no 'backdoor' symbol → KeyError → None
        assert _lookup_backdoor_addr(ctx) is None


class TestPieBackdoorRealBinarySmoke:
    """Real-binary smoke: only ``pie`` should produce a non-empty payload.

    The other 4 binaries are all non-PIE → ``b""``.
    """

    @pytest.mark.parametrize("binary,bit,pie,expected_empty", [
        ("pie", 64, True, False),       # PIE + has backdoor symbol → real payload
        ("canary", 32, False, True),    # non-PIE
        ("fmtstr1", 32, False, True),   # non-PIE
        ("level3_x64", 64, False, True),  # non-PIE
        ("rip", 64, False, True),       # non-PIE
    ])
    def test_real_binary_default(self, binary, bit, pie, expected_empty):
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for(binary, bit=bit, pie=pie)
        ctx.padding = 80
        ctx.has_backdoor = True
        payload = PieBackdoor().build_payload(ctx)
        if expected_empty:
            assert payload == b""
        else:
            assert payload != b""
            # Verify tail is the pie backdoor bytes
            assert payload[-2:] == _FAKE_PIE_BACKDOOR_TAIL

    @pytest.mark.parametrize("binary,bit,pie", [
        ("pie", 64, True),
        ("canary", 32, False),
        ("fmtstr1", 32, False),
        ("level3_x64", 64, False),
        ("rip", 64, False),
    ])
    def test_real_binary_with_callsystem(self, binary, bit, pie):
        """When ``has_callsystem=True``, only binaries with that symbol
        produce a real payload.  None of the Challenge/ binaries have
        a ``callsystem`` symbol, so all return ``b""``."""
        from autopwn.primitives.pie_backdoor import PieBackdoor

        ctx = ctx_for(binary, bit=bit, pie=pie)
        ctx.padding = 80
        ctx.has_callsystem = True
        ctx.has_backdoor = False
        payload = PieBackdoor().build_payload(ctx)
        assert payload == b""
