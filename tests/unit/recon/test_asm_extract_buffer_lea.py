"""Unit tests for ``autopwn.recon.asm._extract_buffer_lea_padding`` (v4.0.2c3).

Per upgraded.md §3.1 v4.0.2c3: the buffer-setup lea is the LAST
``lea -N(%ebp/%rbp)`` before the first dangerous call (not the
function's first lea, which can be the epilogue ``lea -0x8(%ebp),%esp``).

The helper is tested with synthetic function bodies to exercise
the edge cases (epilogue lea, no dangerous call, no lea, multiple
leas, etc.) and with the real Challenge/ binaries to confirm
zero regression on rip / level3_x64 / pie / fmtstr1.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from autopwn.recon.asm import _extract_buffer_lea_padding, asm_stack_overflow
from tests.conftest import CHALLENGE_DIR


# ---------------------------------------------------------------------------
# Synthetic function-body tests
# ---------------------------------------------------------------------------


class TestExtractBufferLeaSynthetic:
    """Synthetic function bodies — cover the edge cases."""

    def test_simple_buffer_lea_x64(self):
        """Buffer lea ``lea -0x10(%rbp),%rax`` before ``call read@plt``."""
        body = (
            "  push   %rbp\n"
            "  mov    %rsp,%rbp\n"
            "  sub    $0x20,%rsp\n"
            "  lea    -0x10(%rbp),%rax\n"   # buffer at rbp-0x10
            "  mov    %rax,%rdi\n"
            "  call   0x401234 <read@plt>\n"
            "  leave\n"
            "  ret\n"
        )
        # 0x10 + 8 (x64) = 24
        assert _extract_buffer_lea_padding(body, 64) == 24

    def test_simple_buffer_lea_x32(self):
        """Buffer lea ``lea -0xc(%ebp),%eax`` before ``call gets@plt``."""
        body = (
            "  push   %ebp\n"
            "  mov    %esp,%ebp\n"
            "  sub    $0x10,%esp\n"
            "  lea    -0xc(%ebp),%eax\n"
            "  mov    %eax,(%esp)\n"
            "  call   0x8048410 <gets@plt>\n"
            "  leave\n"
            "  ret\n"
        )
        # 0xc + 4 (x32) = 16
        assert _extract_buffer_lea_padding(body, 32) == 16

    def test_skips_epilogue_lea(self):
        """The epilogue ``lea -0x8(%ebp),%esp`` (restore esp) is AFTER
        the dangerous call and must NOT be picked up.  This is the
        fmtstr1 fix — without it, epilogue is misread as buffer."""
        body = (
            "  push   %ebp\n"
            "  mov    %esp,%ebp\n"
            "  sub    $0x28,%esp\n"
            "  call   0x8048410 <read@plt>\n"
            "  leave\n"
            "  lea    -0x8(%ebp),%esp\n"   # epilogue (non-standard)
            "  pop    %ebx\n"
            "  ret\n"
        )
        # No buffer lea before the read call → None
        assert _extract_buffer_lea_padding(body, 32) is None

    def test_picks_last_lea_before_dangerous_call(self):
        """If there are multiple leas (e.g. one for stack frame setup
        + one for buffer), pick the LAST one before the dangerous call."""
        body = (
            "  push   %rbp\n"
            "  mov    %rsp,%rbp\n"
            "  sub    $0x40,%rsp\n"
            "  lea    -0x30(%rbp),%rax\n"   # NOT the buffer (frame setup)
            "  mov    %rax,%rdi\n"
            "  lea    -0x10(%rbp),%rax\n"   # <-- actual buffer
            "  mov    %rax,%rsi\n"
            "  call   0x401234 <read@plt>\n"
            "  leave\n"
            "  ret\n"
        )
        # 0x10 + 8 (x64) = 24
        assert _extract_buffer_lea_padding(body, 64) == 24

    def test_no_dangerous_call_returns_none(self):
        """No ``call read/gets/fgets/scanf`` in the body → None."""
        body = (
            "  push   %rbp\n"
            "  mov    %rsp,%rbp\n"
            "  sub    $0x10,%rsp\n"
            "  lea    -0x4(%rbp),%rax\n"
            "  call   0x401234 <puts@plt>\n"   # not dangerous
            "  leave\n"
            "  ret\n"
        )
        assert _extract_buffer_lea_padding(body, 64) is None

    def test_no_lea_returns_none(self):
        """No ``lea -N(%ebp)`` at all → None (even if read is called)."""
        body = (
            "  push   %rbp\n"
            "  mov    %rsp,%rbp\n"
            "  sub    $0x10,%rsp\n"
            "  mov    $0x0,%eax\n"
            "  call   0x401234 <read@plt>\n"
            "  leave\n"
            "  ret\n"
        )
        assert _extract_buffer_lea_padding(body, 64) is None

    def test_getegid_does_not_match_gets(self):
        """``call getegid@plt`` must NOT be treated as a ``gets`` call
        (substring ``gets`` in ``getegid``).  This is the false-positive
        trap in the v3.1 substring-based dangerous call check."""
        body = (
            "  push   %ebp\n"
            "  mov    %esp,%ebp\n"
            "  sub    $0x28,%esp\n"
            "  call   0x8048410 <getegid@plt>\n"
            "  lea    -0x8(%ebp),%esp\n"
            "  pop    %ebx\n"
            "  leave\n"
            "  ret\n"
        )
        # No dangerous call (getegid != gets) → None
        assert _extract_buffer_lea_padding(body, 32) is None

    def test_negative_offset_in_lea(self):
        """Buffer lea with negative offset (``-0x80``) works correctly."""
        body = (
            "  push   %rbp\n"
            "  mov    %rsp,%rbp\n"
            "  sub    $0x90,%rsp\n"
            "  lea    -0x80(%rbp),%rax\n"
            "  mov    %rax,%rdi\n"
            "  call   0x401234 <read@plt>\n"
            "  leave\n"
            "  ret\n"
        )
        # 0x80 + 8 (x64) = 0x88 = 136
        assert _extract_buffer_lea_padding(body, 64) == 136


# ---------------------------------------------------------------------------
# Real Challenge/ binary tests (zero-regression)
# ---------------------------------------------------------------------------


class TestExtractBufferLeaChallengeBinaries:
    """Verify v4.0.2c3 doesn't regress the real Challenge/ binaries.

    Expected values (per the v4.0.2a/b/4.0.5/4.0.7 fix history):
    * rip (x64)        → 23
    * level3_x64 (x64) → 136
    * pie (x32)        → 36
    * fmtstr1 (x32)    → None (was 12; epilogue lea correctly excluded)
    * canary (x32)     → None (no lea+read combo)
    """

    @pytest.mark.parametrize(
        "binary,bit,expected",
        [
            ("rip", 64, 23),
            ("level3_x64", 64, 136),
            ("pie", 32, 36),
            # canary: vuln() has ``lea -0x4c(%ebp),%eax`` BEFORE
            # ``call gets@plt`` → buffer at ebp-0x4c, padding 0x4c+4=80
            ("canary", 32, 80),
        ],
    )
    def test_returns_expected_padding(self, binary: str, bit: int, expected: int):
        path = CHALLENGE_DIR / binary
        if not path.exists():
            pytest.skip(f"Challenge binary {binary} not present")
        assert asm_stack_overflow(path, bit) == expected

    def test_fmtstr1_returns_none(self):
        """fmtstr1: the only ``lea -N(%ebp)`` in main is the
        epilogue (AFTER ``call read@plt``).  The buffer lea uses
        %esp (not %ebp) and is missed by ``_LEA_RE`` (pre-existing
        limitation).  Result: None (was 12 pre-v4.0.2c3)."""
        path = CHALLENGE_DIR / "fmtstr1"
        if not path.exists():
            pytest.skip("Challenge binary fmtstr1 not present")
        assert asm_stack_overflow(path, 32) is None
