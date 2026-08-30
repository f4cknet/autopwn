"""Unit tests for ``autopwn.detect.hints`` (v4.1.19)."""
from __future__ import annotations

import pytest

from tests.conftest import CHALLENGE_DIR, ctx_for


pytestmark = pytest.mark.detect


class TestStaticHints:
    def test_canary_static_hints_include_second_sink_and_local_penalty(self):
        from autopwn.detect.hints import collect_static_hints

        ctx = ctx_for("canary", bit=32, stack_canary=True, pie=False, relro="Partial")
        hints = collect_static_hints(ctx, CHALLENGE_DIR / "canary")
        kinds = {hint.kind for hint in hints}

        assert "second_input_sink" in kinds
        assert "local_nonfork_canary_bruteforce_penalty" in kinds


class TestFmtstrHints:
    def test_canary_fmtstr_hints_capture_leak_then_bof_route(self):
        from autopwn.detect.hints import collect_fmtstr_hints

        ctx = ctx_for("canary", bit=32, stack_canary=True, pie=False, relro="Partial")
        hints = collect_fmtstr_hints(
            ctx,
            CHALLENGE_DIR / "canary",
            fmtstr_vulnerable=True,
        )
        kinds = {hint.kind for hint in hints}

        assert "fmtstr_sink" in kinds
        assert "fmt_then_bof" in kinds
        assert "canary_leakable" in kinds
        assert "got_writable_no_pie" in kinds

    def test_non_fmtstr_probe_yields_no_hints(self):
        from autopwn.detect.hints import collect_fmtstr_hints

        ctx = ctx_for("canary", bit=32, stack_canary=True, pie=False, relro="Partial")
        assert collect_fmtstr_hints(
            ctx,
            CHALLENGE_DIR / "canary",
            fmtstr_vulnerable=False,
        ) == []
