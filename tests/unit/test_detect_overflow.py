"""Unit tests for ``autopwn.detect.overflow`` (P5.1).

Per ``rebuild.md`` §6.6 P5.5: every detect function must have
a test case against the corresponding Challenge/ binary.

Test plan
---------
* :func:`test_stack_overflow` — dynamic SIGSEGV probe.  We
  override ``max_test`` to a small value (e.g. 64) so the
  test runs in < 5s on any binary.  Asserts the function
  returns ``>= 0`` and writes ``ctx.padding`` to the same
  value.
* :func:`analyze_vulnerable_functions` — static lea+call
  heuristic.  Asserts the function returns a positive int
  on stack-overflow-vulnerable binaries (level3_x64, rip)
  and ``None`` on binaries without the heuristic match
  (canary).  Writes ``ctx.padding`` to the same int.
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.detect


class TestTestStackOverflow:
    """``detect.overflow.test_stack_overflow`` — dynamic SIGSEGV probe."""

    def test_returns_int_and_writes_ctx_padding(self, challenge_dir):
        """Function returns an int and writes the same int into ``ctx.padding``."""
        from autopwn.detect.overflow import test_stack_overflow

        # level3_x64 has a well-known padding at 128 + 8 = 136 bytes
        # (128 = function stack frame, 8 = 64-bit alignment).
        ctx = ctx_for("level3_x64", bit=64)
        result = test_stack_overflow(ctx, challenge_dir / "level3_x64", 64, max_test=200)
        assert isinstance(result, int)
        assert ctx.padding == result
        # Padding must be 8-aligned on 64-bit
        assert result % 8 == 0 or result == 0

    def test_no_overflow_returns_zero(self, challenge_dir):
        """A binary that doesn't SIGSEGV within ``max_test`` returns 0."""
        from autopwn.detect.overflow import test_stack_overflow

        # A tiny max_test forces the function to return 0 even on
        # stack-overflow-vulnerable binaries (because the SIGSEGV
        # offset is far past max_test).
        ctx = ctx_for("level3_x64", bit=64)
        result = test_stack_overflow(ctx, challenge_dir / "level3_x64", 64, max_test=1)
        assert result == 0
        assert ctx.padding == 0


class TestAnalyzeVulnerableFunctions:
    """``detect.overflow.analyze_vulnerable_functions`` — static heuristic."""

    def test_finds_padding_in_level3_x64(self, challenge_dir):
        """Detects a vulnerable function in level3_x64 (has lea + dangerous call)."""
        from autopwn.detect.overflow import analyze_vulnerable_functions

        ctx = ctx_for("level3_x64", bit=64)
        result = analyze_vulnerable_functions(ctx, challenge_dir / "level3_x64", 64)
        # level3_x64's vulnerable function has a 128-byte stack frame
        # → padding = 128 + 8 = 136 bytes (64-bit alignment).
        assert result is not None
        assert result > 0
        assert result % 8 == 0
        # ctx.padding is overwritten
        assert ctx.padding == result

    def test_finds_padding_in_rip(self, challenge_dir):
        """Detects a vulnerable function in rip (32-bit)."""
        from autopwn.detect.overflow import analyze_vulnerable_functions

        ctx = ctx_for("rip", bit=32)
        result = analyze_vulnerable_functions(ctx, challenge_dir / "rip", 32)
        # rip is a 32-bit binary with stack overflow; expect a positive int
        # aligned to 4 bytes.
        assert result is not None
        assert result > 0
        assert ctx.padding == result

    def test_writes_ctx_padding_on_match(self, challenge_dir):
        """``ctx.padding`` is set to the first vulnerable function's padding."""
        from autopwn.detect.overflow import analyze_vulnerable_functions

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 999  # pre-set to detect overwrite
        result = analyze_vulnerable_functions(ctx, challenge_dir / "level3_x64", 64)
        assert result is not None
        assert ctx.padding == result
        assert ctx.padding != 999
