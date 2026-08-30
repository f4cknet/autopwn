"""Unit tests for ``autopwn.recon.targets`` (v4.1.19)."""
from __future__ import annotations

import pytest

from tests.conftest import CHALLENGE_DIR, ctx_for


pytestmark = pytest.mark.recon


class TestTargetCandidateScoring:
    """Candidate-function scoring should stay generic, not challenge-specific."""

    def test_canary_prefers_hacked_over_vuln(self):
        from autopwn.recon.targets import collect_target_candidates

        ctx = ctx_for("canary", bit=32, stack_canary=True)
        candidates = collect_target_candidates(ctx, CHALLENGE_DIR / "canary")
        by_name = {candidate.name: candidate for candidate in candidates}

        assert "hacked" in by_name
        assert "vuln" in by_name
        assert candidates[0].name == "hacked"
        assert by_name["hacked"].score > by_name["vuln"].score

    def test_name_bonus_caps_at_30(self):
        from autopwn.recon.targets import _name_bonus

        assert _name_bonus(
            "win_flag_getflag_print_flag_hacked_backdoor_secret_shell_pwn",
            stripped=False,
        ) == 30

    def test_vuln_and_vulnerable_are_weak_name_signals(self):
        from autopwn.recon.targets import _name_bonus

        assert _name_bonus("vuln", stripped=False) == 5
        assert _name_bonus("vulnerable", stripped=False) == 5

    def test_stripped_binary_zeroes_name_bonus_but_keeps_other_signals(self):
        from autopwn.recon.targets import collect_target_candidates

        normal_ctx = ctx_for("canary", bit=32, stack_canary=True, stripped=False)
        stripped_ctx = ctx_for("canary", bit=32, stack_canary=True, stripped=True)

        normal = next(
            candidate
            for candidate in collect_target_candidates(normal_ctx, CHALLENGE_DIR / "canary")
            if candidate.name == "hacked"
        )
        stripped = next(
            candidate
            for candidate in collect_target_candidates(stripped_ctx, CHALLENGE_DIR / "canary")
            if candidate.name == "hacked"
        )

        assert stripped.score > 0
        assert stripped.score < normal.score
        assert all("name bonus" not in reason for reason in stripped.reasons)
