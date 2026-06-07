"""Unit tests for ``autopwn.detect.binsh`` (P5.4).

Per ``rebuild.md`` §6.6 P5.5: every detect function must have
a test case against the corresponding Challenge/ binary.

Test plan
---------
* :func:`check_binsh` — scans strings for ``/bin/sh``.
  Asserts:
    - ``True`` for binaries that contain ``/bin/sh`` (fmtstr1, pie, rip)
    - ``False`` for binaries that don't (canary, level3_x64)
    - ``ctx.binsh_in_binary`` is set to the same bool
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.detect


class TestCheckBinsh:
    """``detect.binsh.check_binsh`` — ``/bin/sh`` string detection."""

    @pytest.mark.parametrize(
        "binary,bit,expected",
        [
            ("canary", 32, False),
            ("fmtstr1", 32, True),
            ("level3_x64", 64, False),
            ("pie", 64, True),
            ("rip", 32, True),
        ],
    )
    def test_returns_bool(self, challenge_dir, binary, bit, expected):
        """Returns the correct bool for each Challenge/ binary."""
        from autopwn.detect.binsh import check_binsh

        ctx = ctx_for(binary, bit=bit)
        result = check_binsh(ctx, challenge_dir / binary)
        assert result is expected

    def test_writes_ctx_binsh_in_binary(self, challenge_dir):
        """``ctx.binsh_in_binary`` is set to the discovered bool."""
        from autopwn.detect.binsh import check_binsh

        ctx = ctx_for("fmtstr1", bit=32)
        assert ctx.binsh_in_binary is False  # default
        result = check_binsh(ctx, challenge_dir / "fmtstr1")
        assert result is True
        assert ctx.binsh_in_binary is True

        ctx2 = ctx_for("level3_x64", bit=64)
        check_binsh(ctx2, challenge_dir / "level3_x64")
        assert ctx2.binsh_in_binary is False
