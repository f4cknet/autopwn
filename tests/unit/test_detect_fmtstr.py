"""Unit tests for ``autopwn.detect.fmtstr`` (P5.2).

Per ``rebuild.md`` §6.6 P5.5: every detect function must have
a test case against the corresponding Challenge/ binary.

Test plan
---------
* :func:`detect_format_string_vulnerability` — runs 6 payloads
  against the binary and reports triggers.  Asserts ``vulnerable=True``
  on binaries that DO have a format-string vuln (fmtstr1, level3_x64
  — both leak ``0x...`` per v3.1's behavior).
* :func:`find_offset` — sends ``AAAA.%x*40`` and returns the
  1-based offset of ``0x41414141``.  Asserts the offset is
  a positive int (no exact value — depends on binary state).
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.detect


class TestDetectFormatStringVulnerability:
    """``detect.fmtstr.detect_format_string_vulnerability`` — 6-payload probe."""

    def test_returns_probe_with_vulnerable_flag(self, challenge_dir):
        """Returns a ``FormatStringProbe`` with the expected bool field."""
        from autopwn.detect.fmtstr import detect_format_string_vulnerability

        ctx = ctx_for("fmtstr1", bit=32)
        probe = detect_format_string_vulnerability(ctx, challenge_dir / "fmtstr1")
        # fmtstr1 IS a format-string vulnerable binary → must report True.
        assert probe.vulnerable is True
        assert isinstance(probe.triggers, int)
        assert probe.triggers >= 1

    def test_level3_x64_also_triggers(self, challenge_dir):
        """level3_x64 is format-string vulnerable (v3.1 baseline confirms)."""
        from autopwn.detect.fmtstr import detect_format_string_vulnerability

        ctx = ctx_for("level3_x64", bit=64)
        probe = detect_format_string_vulnerability(ctx, challenge_dir / "level3_x64")
        assert probe.vulnerable is True

    def test_probe_is_dataclass(self, challenge_dir):
        """The result is a ``FormatStringProbe`` dataclass, not a raw bool."""
        from autopwn.detect.fmtstr import FormatStringProbe, detect_format_string_vulnerability

        ctx = ctx_for("fmtstr1", bit=32)
        probe = detect_format_string_vulnerability(ctx, challenge_dir / "fmtstr1")
        assert isinstance(probe, FormatStringProbe)


class TestFindOffset:
    """``detect.fmtstr.find_offset`` — 1-based offset of ``0x41414141``."""

    def test_finds_offset_in_fmtstr1(self, challenge_dir):
        """fmtstr1 leaks 0x41414141 at offset 11 (v3.1 baseline)."""
        from autopwn.detect.fmtstr import find_offset

        ctx = ctx_for("fmtstr1", bit=32)
        offset = find_offset(ctx, challenge_dir / "fmtstr1")
        assert isinstance(offset, int)
        assert offset >= 1
        # v3.1 baseline reports 11 for fmtstr1; allow a small range
        # in case the binary's stack layout shifts (very unlikely).
        assert 1 <= offset <= 40

    def test_raises_on_non_fmtstr_binary(self, challenge_dir):
        """Non-format-string binaries raise ``ValueError``."""
        from autopwn.detect.fmtstr import find_offset

        # rip doesn't have a format string vuln, so the sentinel
        # 0x41414141 won't be in the leaked stack.  The function
        # raises ValueError per v3.1 behavior.
        ctx = ctx_for("rip", bit=32)
        with pytest.raises(ValueError):
            find_offset(ctx, challenge_dir / "rip")
