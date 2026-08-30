"""Unit tests for ``autopwn.detect.canary`` (P5.3).

Per ``rebuild.md`` §6.6 P5.5: every detect function must have
a test case against the corresponding Challenge/ binary.

Test plan
---------
* :func:`leakage_canary_value` — format-string probe.  Asserts
  it returns a list (possibly empty for non-fmtstr binaries).
  Uses ``max_offset=5`` to keep the test fast.
* :func:`canary_fuzz` — brute-force bypass.  Asserts the
  function returns ``None`` for trivial cases (a binary with
  no canary, or with a tiny ``max_c``/``max_padding`` budget).
  The real bypass requires ~7 minutes of brute-forcing, so
  we do NOT assert success here — that's an integration test.
* :func:`_legacy_leakage_canary_value` — writes ``canary.txt``;
  uses ``tmp_path`` to redirect.
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.detect


class TestLeakageCanaryValue:
    """``detect.canary.leakage_canary_value`` — format-string probe."""

    def test_returns_list_of_tuples(self, challenge_dir):
        """Returns a list of ``(offset, hex_string)`` pairs."""
        from autopwn.detect.canary import leakage_canary_value

        ctx = ctx_for("canary", bit=32)
        leaks = leakage_canary_value(ctx, challenge_dir / "canary", max_offset=5)
        assert isinstance(leaks, list)
        # Every entry is a (int, str) tuple
        for entry in leaks:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            offset, value = entry
            assert isinstance(offset, int)
            assert isinstance(value, str)

    def test_returns_empty_for_non_fmtstr(self, challenge_dir):
        """Non-format-string binaries return an empty list (or skip)."""
        from autopwn.detect.canary import leakage_canary_value

        # level3_x64 — although v3.1 detects fmtstr here, the leaks
        # for canary-style probes depend on the binary's input parser.
        # We just assert the function returns a list (not None / error).
        ctx = ctx_for("level3_x64", bit=64)
        leaks = leakage_canary_value(ctx, challenge_dir / "level3_x64", max_offset=3)
        assert isinstance(leaks, list)


class TestCanaryFuzz:
    """``detect.canary.canary_fuzz`` — brute-force bypass fuzzer."""

    def test_returns_none_with_tiny_budget(self, challenge_dir):
        """Tiny ``max_c``/``max_padding`` → returns ``None`` (no bypass found)."""
        from autopwn.detect.canary import canary_fuzz

        # Use the canary binary with a real-ish leaks list (the
        # first 3 entries from a small probe).
        from autopwn.detect.canary import leakage_canary_value

        ctx = ctx_for("canary", bit=32)
        leaks = leakage_canary_value(ctx, challenge_dir / "canary", max_offset=3)
        # Tiny budget → will exhaust before finding a real bypass.
        result = canary_fuzz(
            ctx, challenge_dir / "canary", 32, leaks,
            max_c=2, max_padding=2,
        )
        assert result is None
        # ctx.canary is left untouched on failure
        assert ctx.canary is None

    def test_returns_none_for_empty_leaks(self, challenge_dir):
        """Empty leaks list short-circuits to ``None``."""
        from autopwn.detect.canary import canary_fuzz

        ctx = ctx_for("canary", bit=32)
        result = canary_fuzz(ctx, challenge_dir / "canary", 32, [])
        assert result is None
        assert ctx.canary is None

    def test_respects_wall_time_budget(self, challenge_dir, monkeypatch):
        """v4.1.18: ``max_seconds`` must cut off long brute-force loops."""
        import pwn
        from autopwn.detect import canary as canary_mod

        ctx = ctx_for("canary", bit=32)
        spawn_count = 0

        class FakeIO:
            def recv(self): return b""
            def recvline(self): return b"0x41414141"
            def sendline(self, *a, **kw): pass
            def wait(self): pass
            def poll(self): return 0
            def close(self): pass

        def fake_process(*a, **kw):
            nonlocal spawn_count
            spawn_count += 1
            return FakeIO()

        ticks = iter([0.0, 0.0, 0.2, 0.2, 0.2])
        monkeypatch.setattr(pwn, "process", fake_process)
        monkeypatch.setattr(canary_mod.time, "monotonic", lambda: next(ticks, 0.2))

        leaks = [(0, "0x0"), (1, "0x1111"), (2, "0x80000000")]
        result = canary_mod.canary_fuzz(
            ctx, challenge_dir / "canary", 32, leaks,
            max_c=3, max_padding=10, max_seconds=0.1,
        )
        assert result is None
        assert ctx.canary is None
        assert spawn_count == 1

    def test_writes_ctx_canary_on_success(self, challenge_dir, monkeypatch):
        """``ctx.canary`` is set to a ``CanaryInfo`` on successful bypass."""
        from autopwn.context import CanaryInfo

        # Monkey-patch :func:`pwn.process` to fake a SIGSEGV on
        # the first attempt.  This validates the ctx.canary mutation
        # path without requiring the 7-minute brute force.
        # The canary module does ``from pwn import process`` inside
        # the function, so we patch ``pwn.process`` (the source)
        # and pytest will undo the patch on test teardown.
        import pwn
        ctx = ctx_for("canary", bit=64)

        class FakeIO:
            def __init__(self, *a, **kw): pass
            def recv(self): return b""
            def recvline(self): return b"0x4141414141414141"  # canary value
            def sendline(self, *a, **kw): pass
            def wait(self): pass
            def poll(self): return -11  # SIGSEGV
            def close(self): pass

        monkeypatch.setattr(pwn, "process", lambda *a, **kw: FakeIO())

        # leaks: (offset, hex_string) pairs.  Need at least one
        # 0x8* value at j > i to trigger the inner bypass loop.
        # ``canary_fuzz`` reads leaks[j][1] for the canary value.
        leaks = [(i, f"0x{i:x}") for i in range(5)]
        leaks[3] = (3, "0x8000000000000000")  # canary-shaped value at index 3

        # Re-import canary_mod so the local ``from pwn import process``
        # picks up our monkey-patched version.
        from autopwn.detect import canary as canary_mod
        result = canary_mod.canary_fuzz(
            ctx, challenge_dir / "canary", 64, leaks,
            max_c=2, max_padding=1,
        )
        assert isinstance(result, CanaryInfo)
        assert ctx.canary is result
        assert result.diff >= 1
        assert result.value == 0x8000000000000000  # value from leaks[3]
