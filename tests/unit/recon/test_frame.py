"""Unit tests for ``autopwn.recon.frame`` (v4.0.5 / P4.7).

Per ``fix.md`` §3.1 v4.0.5: replaces the v4.0.2b magic-number
``include_ret = (padding < 32)`` heuristic with a typed
:class:`FrameContext` carrying the caller's frame structure and a
principled :func:`compute_required_ret_count` ABI-arithmetic
function.  These tests pin the three release gates:

1. ``compute_required_ret_count(lea_offset)`` returns the right
   ``0|1`` for every ``lea_offset`` boundary case:
   - 16-aligned (e.g. ``0x80``, ``0x100``, ``0x20``) → ``0`` (skip ret)
   - non-16-aligned (e.g. ``0xf``, ``0x8``, ``0x18``) → ``1`` (include ret)
   - ``0`` / negative (no frame info)               → ``1`` (conservative)
2. :class:`FrameContext` is a ``slots=True`` dataclass with 4
   fields, all with the correct defaults (the v3.x unsafe-dict
   pattern is gone).
3. :func:`extract_frame_context` returns the expected
   :class:`FrameContext` for the 3 anchor binaries from
   ``fix.md`` §3.1:
   - ``rip``        (x64, ``lea -0xf(%rbp)``)        → ``required_ret_count=1``
   - ``level3_x64`` (x64, ``lea -0x80(%rbp)``)        → ``required_ret_count=0``
   - 32-bit input (any binary)                        → conservative
     :class:`FrameContext` with ``required_ret_count=1``
     (the 32-bit alignment math is a v4.0.6+ concern; for
     v4.0.5 we only ship the 64-bit case).

Why these are *unit* tests, not *integration* tests
----------------------------------------------------
``recon.frame`` is a *pure* function library (no IO beyond
``run_objdump_disasm``, no globals, no state mutation) so
unit testing it is meaningful and fast.  Each test runs in
<1 second; the only subprocess calls are ``objdump`` parses
on the local Challenge/ binaries (which are tiny).  The
exploit-level integration tests live in
``tests/integration/test_*`` (P9.x).
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from tests.conftest import CHALLENGE_DIR, ctx_for


pytestmark = pytest.mark.recon


# ---------------------------------------------------------------------------
# compute_required_ret_count: pure-function table tests
# ---------------------------------------------------------------------------


class TestComputeRequiredRetCount:
    """``compute_required_ret_count(lea_offset)`` table tests.

    Pin the full decision table.  The empirical rule (validated on
    rip + level3_x64 by ctf-pwn 2026-06-11) is:

        lea_offset % 16 == 0  →  0  (skip alignment ret)
        lea_offset % 16 != 0  →  1  (include alignment ret)

    New ``lea_offset`` boundary cases must add a test here; do
    NOT silently expand the table without a corresponding test
    (per ``fix.md`` §6 "compute_required_ret_count 计算错误 →
    3 个 unit test 强制覆盖 rip/level3/canary 三种 frame size").
    """

    def test_lea_offset_0xf_rip_returns_1(self):
        """``rip`` main has ``lea -0xf(%rbp)`` → lea_offset = 0xf → 1 ret.

        0xf % 16 = 15 ≠ 0, so include the alignment ret.  This
        is the v4.0.2b's "include_ret=True" case.  Before the
        v4.0.2b fix, this binary would have gotten an
        unconditional ret and worked; the v4.0.2b magic
        threshold ``padding < 32`` happened to also pick the
        right value (padding=23 < 32 = True).  v4.0.5 encodes
        the same decision principled by lea_offset.
        """
        from autopwn.recon.frame import compute_required_ret_count

        assert compute_required_ret_count(lea_offset=0xf) == 1

    def test_lea_offset_0x80_level3_returns_0(self):
        """``level3_x64`` vuln_func has ``lea -0x80(%rbp)`` → 0x80 → 0 ret.

        0x80 % 16 = 0, so skip the alignment ret.  This is the
        v4.0.2b's "include_ret=False" case (the primitive's
        hardcoded chain would have included a ret gadget
        unnecessarily, advancing rsp by 16 bytes past the
        do_system movaps sweet spot).  v4.0.5 gets this
        correct where the magic threshold got it wrong
        (padding=136 ≥ 32 → False; happens to match the
        principled answer here, but is fragile for padding
        in [20, 31]).
        """
        from autopwn.recon.frame import compute_required_ret_count

        assert compute_required_ret_count(lea_offset=0x80) == 0

    def test_lea_offset_0_returns_1_conservative(self):
        """``lea_offset=0`` (no frame info) → conservative 1.

        Defensive: when static analysis fails to find a
        ``lea -N(%rbp)`` we should err on the side of including
        the alignment ret (mirrors v4.0.1's always-include
        behaviour).
        """
        from autopwn.recon.frame import compute_required_ret_count

        assert compute_required_ret_count(lea_offset=0) == 1

    def test_lea_offset_negative_returns_1_conservative(self):
        """Negative ``lea_offset`` (defensive guard) → 1."""
        from autopwn.recon.frame import compute_required_ret_count

        assert compute_required_ret_count(lea_offset=-1) == 1

    @pytest.mark.parametrize(
        "lea_offset,expected",
        [
            # 16-aligned (lea_offset % 16 == 0) → no ret needed
            (0x10, 0), (0x20, 0), (0x80, 0), (0x100, 0), (0x200, 0), (0x1000, 0),
            # non-16-aligned (lea_offset % 16 in {1..15}) → ret needed
            (0x01, 1), (0x08, 1), (0x0f, 1), (0x18, 1), (0x28, 1), (0x38, 1), (0x88, 1), (0x108, 1),
            # Other alignments (1..7, 9..15) → 1 (conservative)
            (0x12, 1), (0x14, 1), (0x1c, 1), (0x24, 1), (0x2c, 1), (0x34, 1),
        ],
    )
    def test_lea_offset_full_decision_table(self, lea_offset, expected):
        """Full parametrize table — every ``lea_offset % 16`` residue.

        Adding a new ``lea_offset`` boundary case to the function
        MUST be paired with adding a test row here (per
        ``fix.md`` §3.1 "compute_required_ret_count 计算错误 →
        3 个 unit test 强制覆盖").
        """
        from autopwn.recon.frame import compute_required_ret_count

        assert compute_required_ret_count(lea_offset=lea_offset) == expected

    def test_frame_size_is_diagnostic_only(self):
        """``frame_size`` parameter is accepted but does NOT affect result.

        The decision is on ``lea_offset`` alone.  The
        ``frame_size`` parameter is kept in the signature for
        backward compatibility and for diagnostic display in
        the FrameContext dataclass, but it MUST NOT influence
        the alignment decision (per the module docstring:
        "frame_size ... does not affect the result").
        """
        from autopwn.recon.frame import compute_required_ret_count

        # Same lea_offset, different frame_size → same result
        assert (
            compute_required_ret_count(lea_offset=0x80, frame_size=0x10)
            == compute_required_ret_count(lea_offset=0x80, frame_size=0x80)
            == 0
        )
        # Different lea_offset, same frame_size → different result
        assert (
            compute_required_ret_count(lea_offset=0xf, frame_size=0x80) == 1
        )

    def test_return_type_is_literal_0_or_1(self):
        """Return is typed ``Literal[0, 1]``; runtime check ensures int."""
        from autopwn.recon.frame import compute_required_ret_count

        result = compute_required_ret_count(lea_offset=0xf)
        assert isinstance(result, int)
        assert result in (0, 1)


# ---------------------------------------------------------------------------
# FrameContext dataclass
# ---------------------------------------------------------------------------


class TestFrameContextDataclass:
    """``FrameContext`` is a slots dataclass with 4 fields + sane defaults."""

    def test_has_all_four_fields(self):
        from autopwn.recon.frame import FrameContext

        fc = FrameContext()
        # 4 documented fields
        assert hasattr(fc, "vuln_func_addr")
        assert hasattr(fc, "lea_offset")
        assert hasattr(fc, "frame_size")
        assert hasattr(fc, "required_ret_count")

    def test_default_values(self):
        """Default: ``vuln_func_addr=0``, ``lea_offset=0``, ``frame_size=0``,
        ``required_ret_count=1`` (conservative)."""
        from autopwn.recon.frame import FrameContext

        fc = FrameContext()
        assert fc.vuln_func_addr == 0
        assert fc.lea_offset == 0
        assert fc.frame_size == 0
        assert fc.required_ret_count == 1

    def test_is_slots_dataclass(self):
        """``@dataclass(slots=True)`` — ``__slots__`` attribute present.

        Guards against accidental switch to ``slots=False`` (which
        would re-introduce the ``__dict__`` per-instance overhead
        the v4.0 refactor explicitly removed; per ``context.py``
        L7 "performance + frozen-by-default semantics").
        """
        from autopwn.recon.frame import FrameContext

        assert "__slots__" in dir(FrameContext)

    def test_equality_via_dataclasses(self):
        """Two FrameContexts with the same fields compare equal (dataclass Eq)."""
        from autopwn.recon.frame import FrameContext

        a = FrameContext(vuln_func_addr=0x4011fb, lea_offset=0x80,
                         frame_size=0x80, required_ret_count=0)
        b = FrameContext(vuln_func_addr=0x4011fb, lea_offset=0x80,
                         frame_size=0x80, required_ret_count=0)
        c = FrameContext(vuln_func_addr=0x4011fb, lea_offset=0x80,
                         frame_size=0x10, required_ret_count=1)
        assert a == b
        assert a != c

    def test_is_dataclass(self):
        """``dataclasses.is_dataclass`` returns True (subclasses dataclass)."""
        from autopwn.recon.frame import FrameContext

        assert dataclasses.is_dataclass(FrameContext)


# ---------------------------------------------------------------------------
# extract_frame_context: integration with Challenge/ binaries
# ---------------------------------------------------------------------------


class TestExtractFrameContext:
    """``extract_frame_context(program, bit)`` on real Challenge/ binaries.

    End-to-end test: each test invokes the actual ``objdump``
    pipeline (``run_objdump_disasm``) and asserts the extracted
    frame matches the v4.0.5 ABI math.
    """

    def test_32bit_returns_conservative_default(self):
        """32-bit input → ``FrameContext(required_ret_count=1)``.

        32-bit alignment math differs (system@plt ABI
        different); v4.0.5 only ships the 64-bit case so the
        32-bit path returns a conservative default.  The
        fallback ``required_ret_count=1`` preserves the v4.0.1
        always-align behaviour for 32-bit binaries.
        """
        from autopwn.recon.frame import extract_frame_context

        # canary is 32-bit
        result = extract_frame_context(CHALLENGE_DIR / "canary", bit=32)
        assert result is not None
        assert result.required_ret_count == 1

    def test_rip_64bit_lea_offset_0xf_required_ret_count_1(self):
        """``rip`` main: ``lea -0xf(%rbp)`` → lea_offset = 0xf → ret needed.

        0xf % 16 == 15 ≠ 0 → ``required_ret_count=1``.  This
        is the binary that v4.0.2b's magic threshold
        ``padding < 32`` got right (padding=23 < 32 = include
        ret), so the v4.0.5 principled result matches.
        """
        from autopwn.recon.frame import extract_frame_context

        result = extract_frame_context(CHALLENGE_DIR / "rip", bit=64)
        assert result is not None
        # rip's main has lea -0xf(%rbp) → 0xf, % 16 = 15 → 1 ret
        assert result.lea_offset == 0xf
        assert result.required_ret_count == 1

    def test_level3_x64_lea_offset_0x80_required_ret_count_0(self):
        """``level3_x64`` vuln_func: ``lea -0x80(%rbp)`` → 0 ret.

        0x80 % 16 == 0 → ``required_ret_count=0``.  This is
        the binary that v4.0.2b's magic threshold got WRONG
        (padding=136 ≥ 32, so v4.0.2b would have skipped the
        ret — but here the principled answer happens to
        agree, the issue is the *fragility* of the magic
        threshold for padding in [20, 31]).  v4.0.5's
        principled result is correct.
        """
        from autopwn.recon.frame import extract_frame_context

        result = extract_frame_context(CHALLENGE_DIR / "level3_x64", bit=64)
        assert result is not None
        # level3_x64's vuln_func has lea -0x80(%rbp) → 0x80, % 16 = 0 → 0 ret
        assert result.lea_offset == 0x80
        assert result.required_ret_count == 0

    def test_level3_x64_frame_size_0x80_via_add_signed_immediate(self):
        """``level3_x64`` vuln_func: ``add $0xffffffffffffff80, %rsp`` → frame_size = 0x80.

        The AT&T encoding for ``sub $0x80, %rsp`` may appear
        as ``add $0xffffffffffffff80, %rsp`` (sign-extended
        negative 32-bit immediate).  This test pins that
        ``extract_frame_context`` normalises the add form
        to the equivalent sub value.
        """
        from autopwn.recon.frame import extract_frame_context

        result = extract_frame_context(CHALLENGE_DIR / "level3_x64", bit=64)
        assert result is not None
        assert result.frame_size == 0x80

    def test_vuln_func_addr_is_nonzero(self):
        """``vuln_func_addr`` should be a non-zero address (function entry)."""
        from autopwn.recon.frame import extract_frame_context

        result = extract_frame_context(CHALLENGE_DIR / "rip", bit=64)
        assert result is not None
        assert result.vuln_func_addr != 0
        # Sanity: should look like a valid 64-bit address (low nibble
        # typically 0 or 6 for x86_64 function entries)
        assert result.vuln_func_addr > 0x400000

    def test_lea_offset_matches_frame_size_region(self):
        """``lea_offset`` is the buffer-to-rbp distance; should be a positive hex int."""
        from autopwn.recon.frame import extract_frame_context

        result = extract_frame_context(CHALLENGE_DIR / "rip", bit=64)
        assert result is not None
        assert result.lea_offset > 0
        # lea_offset is typically a small positive integer (0x10 to 0x400 range)
        assert result.lea_offset < 0x10000

    def test_exported_from_recon_package(self):
        """``FrameContext`` is exported from ``autopwn.recon`` package."""
        from autopwn.recon import FrameContext as FC1
        from autopwn.recon import compute_required_ret_count as crc
        from autopwn.recon import extract_frame_context as efc
        from autopwn.recon.frame import (
            FrameContext as FC2,
            compute_required_ret_count as crc2,
            extract_frame_context as efc2,
        )

        assert FC1 is FC2
        assert crc is crc2
        assert efc is efc2


# ---------------------------------------------------------------------------
# FrameContext consumed by primitives (end-to-end sanity)
# ---------------------------------------------------------------------------


class TestFrameContextWiredThroughExploitContext:
    """The new field on :class:`ExploitContext` is reachable + defaults to None."""

    def test_context_frame_context_field_default_none(self):
        """``ExploitContext.frame_context`` defaults to ``None`` (backward compat).

        The orchestrator (P4.7 wire-up) populates it during the
        recon phase, but the field is optional so existing
        strategy code that doesn't read it (17 of 17 strategies
        as of v4.0.1) keeps working.
        """
        from autopwn.recon.frame import FrameContext

        ctx = ctx_for("rip", bit=64)
        assert ctx.frame_context is None
        # Setting it manually works
        ctx.frame_context = FrameContext(
            vuln_func_addr=0x4011fb,
            lea_offset=0x10,
            frame_size=0x10,
            required_ret_count=1,
        )
        assert ctx.frame_context.required_ret_count == 1
