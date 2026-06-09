"""P4.4b contract tests for ``autopwn.recon.rop``.

These tests guard the **B-006 contract fix** — that all address
fields in :class:`RopGadgetsX64` and :class:`RopGadgetsX32` are
``int`` (not ``str``), so downstream P6.x primitives can call
``p64(ctx.gadgets_x64.pop_rdi)`` directly.

Background: P4.4 (2026-06-07) returned ``str`` addresses (matching
v3.1 main() L3159's late conversion).  P8.1 §2.6 baseline
(2026-06-09) caught 2 regressions (level3_x64 + rip) via
``struct.error: required argument is not an integer``.  P4.4b
moved the ``int(..., 16)`` conversion into the parser so the
dataclass contract is now ``int`` end-to-end.

Per AGENTS.md §2.6.4 (small PRs ≤ 50 lines): this is a single
contract-test module guarding the B-006 fix.
"""
from __future__ import annotations

import pytest

from autopwn.context import RopGadgetsX64, RopGadgetsX32
from autopwn.recon.rop import _extract_x32_gadgets, _extract_x64_gadgets


# ---------------------------------------------------------------------------
# _extract_x64_gadgets: address fields are int
# ---------------------------------------------------------------------------


class TestExtractX64GadgetsIntContract:
    """P4.4b: address fields in x64 parser output MUST be int, not str."""

    def test_empty_input_returns_zero_ints(self):
        """All address fields default to ``0`` (int), not ``None``/``""``."""
        result = _extract_x64_gadgets("")
        assert result["pop_rdi"] == 0
        assert result["pop_rsi"] == 0
        assert result["ret"] == 0
        assert isinstance(result["pop_rdi"], int)
        assert isinstance(result["pop_rsi"], int)
        assert isinstance(result["ret"], int)

    def test_simple_pop_rdi_ret_is_int(self):
        """``0x4011fb: pop rdi; ret;`` → ``pop_rdi`` is int 0x4011fb."""
        ropper = "0x00000000004011fb: pop rdi; ret;\n"
        result = _extract_x64_gadgets(ropper)
        assert result["pop_rdi"] == 0x4011fb
        assert isinstance(result["pop_rdi"], int)
        assert result["extra_rdi"] == 0

    def test_multi_pop_rdi_is_int(self):
        """``0x4011fb: pop rdi; pop r15; ret;`` → ``pop_rdi`` is int, extra=1."""
        ropper = "0x00000000004011fb: pop rdi; pop r15; ret;\n"
        result = _extract_x64_gadgets(ropper)
        assert result["pop_rdi"] == 0x4011fb
        assert isinstance(result["pop_rdi"], int)
        assert result["extra_rdi"] == 1

    def test_pop_rsi_int(self):
        ropper = "0x0000000000401234: pop rsi; pop r15; ret;\n"
        result = _extract_x64_gadgets(ropper)
        assert result["pop_rsi"] == 0x401234
        assert isinstance(result["pop_rsi"], int)
        assert result["extra_rsi"] == 1

    def test_ret_only_int(self):
        ropper = "0x0000000000401567: ret;\n"
        result = _extract_x64_gadgets(ropper)
        assert result["ret"] == 0x401567
        assert isinstance(result["ret"], int)

    def test_p64_callable_directly(self):
        """B-006 根因：`p64(str)` raises struct.error.  Guard it works now."""
        from pwn import p64
        ropper = "0x00000000004011fb: pop rdi; ret;\n"
        result = _extract_x64_gadgets(ropper)
        # Pre-P4.4b this raised: struct.error: required argument is not an integer
        encoded = p64(result["pop_rdi"])
        assert encoded == b"\xfb\x11\x40\x00\x00\x00\x00\x00"

    def test_combined_output_all_int(self):
        """3-search concatenated output: all 3 address fields are int."""
        ropper = (
            "0x00000000004011fb: pop rdi; ret;\n"
            "0x0000000000401234: pop rsi; pop r15; ret;\n"
            "0x0000000000401567: ret;\n"
        )
        result = _extract_x64_gadgets(ropper)
        for key in ("pop_rdi", "pop_rsi", "ret"):
            assert isinstance(result[key], int), f"{key} must be int, got {type(result[key])}"


# ---------------------------------------------------------------------------
# _extract_x32_gadgets: address fields are int (symmetric fix)
# ---------------------------------------------------------------------------


class TestExtractX32GadgetsIntContract:
    """P4.4b: x32 path also converts to int (symmetric to x64)."""

    def test_empty_input_returns_zero_ints(self):
        result = _extract_x32_gadgets({})
        for key in ("pop_eax", "pop_ebx", "pop_ecx", "pop_edx",
                    "pop_ecx_ebx", "ret", "int_0x80"):
            assert result[key] == 0
            assert isinstance(result[key], int), f"{key} must be int, got {type(result[key])}"
        assert result["has_eax_ebx_ecx_edx"] is False

    def test_all_four_registers_int(self):
        ropper_outputs = {
            "pop eax;": "0x080490f6: pop eax; ret;\n",
            "pop ebx;": "0x080490f7: pop ebx; ret;\n",
            "pop ecx;": "0x080490f8: pop ecx; ret;\n",
            "pop edx;": "0x080490f9: pop edx; ret;\n",
            "ret;": "0x08049100: ret;\n",
            "int 0x80;": "0x08049101: int 0x80;\n",
        }
        result = _extract_x32_gadgets(ropper_outputs)
        assert result["pop_eax"] == 0x080490f6
        assert result["pop_ebx"] == 0x080490f7
        assert result["pop_ecx"] == 0x080490f8
        assert result["pop_edx"] == 0x080490f9
        assert result["ret"] == 0x08049100
        assert result["int_0x80"] == 0x08049101
        for key in ("pop_eax", "pop_ebx", "pop_ecx", "pop_edx", "ret", "int_0x80"):
            assert isinstance(result[key], int)
        assert result["has_eax_ebx_ecx_edx"] is True


# ---------------------------------------------------------------------------
# Dataclass-level contract: fields declared int, parser honors it
# ---------------------------------------------------------------------------


class TestRopGadgetsX64X32Contract:
    """Both dataclasses declare address fields as int (context.py P4.4b)."""

    def test_x64_defaults_are_int(self):
        g = RopGadgetsX64(pop_rdi=0, pop_rsi=0, ret=0)
        assert isinstance(g.pop_rdi, int)
        assert isinstance(g.pop_rsi, int)
        assert isinstance(g.ret, int)

    def test_x32_defaults_are_int(self):
        g = RopGadgetsX32(
            pop_eax=0, pop_ebx=0, pop_ecx=0, pop_edx=0,
            pop_ecx_ebx=0, ret=0, int_0x80=0,
        )
        for f in ("pop_eax", "pop_ebx", "pop_ecx", "pop_edx",
                  "pop_ecx_ebx", "ret", "int_0x80"):
            assert isinstance(getattr(g, f), int)

    @pytest.mark.parametrize("hex_addr", ["0x4011fb", "0x080490f6", "0x1234567890abcdef"])
    def test_p64_works_for_all_gadget_fields(self, hex_addr):
        """Regression guard: any hex-int stored in field can be p64'd."""
        from pwn import p64
        addr_int = int(hex_addr, 16)
        g = RopGadgetsX64(pop_rdi=addr_int, pop_rsi=0, ret=0)
        encoded = p64(g.pop_rdi)
        assert isinstance(encoded, bytes)
        assert len(encoded) == 8
