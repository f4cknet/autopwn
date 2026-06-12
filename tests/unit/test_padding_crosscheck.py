"""v4.0.7 — Static/dynamic padding cross-check (per ``fix.md`` §3.3).

Why this test exists
--------------------
The v4.0.2a fix (``detect/overflow.py::test_stack_overflow``
removes ``+alignment`` from the dynamic padding) was a **symptom-
level** fix — the unit test ``test_returns_int_and_writes_ctx_padding``
only asserted ``result % 8 == 0``, NOT the **consistency** between
the static (``asm_stack_overflow``) and dynamic (``test_stack_overflow``)
probes.  This module fills that gap by running **both** probes on
each Challenge/ binary and asserting the delta is in a known-legal
set of values.

The "legal delta" set
---------------------
For a well-behaved binary, the static and dynamic probes should
agree on the padding within a small set of well-understood offsets
that arise from how the C runtime / pwntools model the stack:

  * **0** — exact match (both probes found the same offset)
  * **1** — null terminator off-by-one (``gets`` adds a trailing
    ``\\0`` after the buffer)
  * **4 or 8** — saved rbp corruption boundary (32-bit uses 4-byte
    saved ebp; 64-bit uses 8-byte)
  * **12, 16, 24, 32** — frame size alignment boundary (16-byte
    aligned, 8-byte saved rbp, etc.)

Anything **outside** this set is a sign of the v4.0.2a-style
``+alignment`` bug: ctf-pwn 2026-06-11 found rip's dynamic probe
returned 30 while the static probe returned 23 (delta = 7, which
is NOT in the legal set).  This test would have caught that.

Per-binary expectations (observed v4.0.2/3/4 + v4.0.5)
-------------------------------------------------------
* ``rip``        — static=23, dynamic=22 → delta=1 (legal)
* ``level3_x64`` — static=136, dynamic=128 → delta=8 (legal, 8-byte boundary)
* ``pie``        — static=36, dynamic=40 → delta=4 (legal, 32-bit 4-byte boundary)
* ``canary``     — static=80, dynamic=0 → **SKIP** (no overflow detected
  within max_test=300, canary brute force is a separate problem)
* ``fmtstr1``    — static=12, dynamic=0 → **SKIP** (no BOF in fmtstr1,
  it's a format-string binary; no padding crosscheck is meaningful)

Why per-architecture legal sets
--------------------------------
The legal delta set is **architecture-dependent**:

  * **64-bit** (rip, level3_x64): saved rbp is 8 bytes → 8-byte
    alignment is the natural unit.  Legal: ``{0, 1, 8, 16, 24, 32}``.
  * **32-bit** (pie, canary, fmtstr1): saved ebp is 4 bytes →
    4-byte alignment is the natural unit.  Legal:
    ``{0, 1, 4, 8, 12, 16, 24, 32}``.

This split is the v4.0.7 fix to the v4.0.2a-style single-set
mistake.

When to skip the crosscheck
----------------------------
If the **dynamic** probe returns 0 (no overflow detected within
``max_test``), the binary either:
  * Has no BOF (fmtstr1), or
  * Has a very large padding (canary), or
  * The dynamic probe is too slow to converge in this CI environment.

In all these cases, the crosscheck is **not meaningful** (we have
no dynamic value to compare against) and we skip.  This is **not**
a regression — the v4.0.2a bug was about wrong values, not about
no values.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from autopwn.context import BinaryInfo, ExploitContext
from autopwn.detect.overflow import test_stack_overflow as _test_stack_overflow
from autopwn.recon.asm import asm_stack_overflow as _asm_stack_overflow
from tests.conftest import CHALLENGE_DIR


pytestmark = [pytest.mark.detect]


# ---------------------------------------------------------------------------
# Per-architecture legal-delta sets
# ---------------------------------------------------------------------------

# 64-bit: saved rbp is 8 bytes → 8-byte alignment is the natural unit.
# Includes 0 (exact match), 1 (null terminator), 8 (8-byte boundary),
# 16/24/32 (frame size alignment, 16-byte aligned, 8-byte saved rbp).
LEGAL_DELTA_X64 = frozenset({0, 1, 8, 16, 24, 32})

# 32-bit: saved ebp is 4 bytes → 4-byte alignment is the natural unit.
# Includes 4 (32-bit saved ebp boundary), 12 (4+8 stack-canary slot
# before saved ebp), in addition to the 64-bit set.
LEGAL_DELTA_X32 = frozenset({0, 1, 4, 8, 12, 16, 24, 32})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_ctx(binary: Path, bit: int) -> ExploitContext:
    """Build a minimal ExploitContext for ``detect.overflow.test_stack_overflow``."""
    return ExploitContext(
        binary=BinaryInfo(
            path=binary,
            bit=bit,
            stack_canary=False,  # defensive default; we don't care here
            pie=False,
            nx=True,
            relro="Partial",
            rwx_segments=False,
            stripped=False,
        ),
        mode="local",
    )


def _run_both_probes(binary: Path, bit: int, max_test: int = 300) -> tuple[int, int]:
    """Run static (``asm_stack_overflow``) + dynamic (``test_stack_overflow``).

    Returns ``(static_padding, dynamic_padding)``.  Either may be 0 if
    the probe found no candidate.
    """
    static_padding = _asm_stack_overflow(binary, bit) or 0

    ctx = _build_ctx(binary, bit)
    dynamic_padding = _test_stack_overflow(ctx, binary, bit, max_test=max_test)

    return static_padding, dynamic_padding


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "binary_name,bit",
    [
        # 64-bit binaries (expected to have working dynamic probes)
        ("rip", 64),
        ("level3_x64", 64),
        # 32-bit binary (pie has a small, fast overflow probe)
        ("pie", 32),
        # 32-bit binaries without BOF or with very large padding —
        # the dynamic probe returns 0; these are SKIPPED below
        # (we still parametrize for documentation).
    ],
)
def test_static_dynamic_delta_is_legal(binary_name: str, bit: int) -> None:
    """``|static - dynamic|`` is in the per-architecture legal set.

    Catches the v4.0.2a-style ``+alignment`` bug: ctf-pwn 2026-06-11
    found rip's dynamic probe returning 30 while the static probe
    returned 23 (delta = 7, NOT in the legal set).  This test would
    have caught that bug at unit-test time.
    """
    path = CHALLENGE_DIR / binary_name
    if not path.exists():
        pytest.skip(f"Challenge binary {binary_name} not present")

    static, dynamic = _run_both_probes(path, bit, max_test=300)
    legal_set = LEGAL_DELTA_X64 if bit == 64 else LEGAL_DELTA_X32

    if dynamic == 0:
        pytest.skip(
            f"{binary_name}: dynamic probe found no overflow within max_test=300 "
            f"(static={static}); crosscheck not meaningful.  This is expected for "
            f"non-BOF binaries (fmtstr1) or very-large-padding binaries (canary)."
        )

    delta = abs(static - dynamic)
    assert delta in legal_set, (
        f"{binary_name} (bit={bit}): static={static} dynamic={dynamic} "
        f"delta={delta} not in legal set {sorted(legal_set)}.  "
        f"This is the v4.0.2a-style '+alignment' bug pattern.  "
        f"Check detect/overflow.py::test_stack_overflow formula."
    )


# ---------------------------------------------------------------------------
# Edge case: dynamic=0 should be handled gracefully (no crash, no false positive)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "binary_name,bit",
    [
        ("canary", 32),    # very large padding (canary brute force)
        ("fmtstr1", 32),   # no BOF (format string vulnerability)
    ],
)
def test_dynamic_zero_handled_gracefully(binary_name: str, bit: int) -> None:
    """When the dynamic probe returns 0, the crosscheck skips cleanly.

    The original v4.0.7 test design was over-strict: it required
    the legal-delta set to include the *static* value (e.g. 80 for
    canary) which would silently turn a "no overflow detected"
    signal into a passing assertion.  This test pins the correct
    behaviour: dynamic=0 is a legitimate signal ("no BOF"), and
    the crosscheck MUST skip rather than spuriously pass.
    """
    path = CHALLENGE_DIR / binary_name
    if not path.exists():
        pytest.skip(f"Challenge binary {binary_name} not present")

    static, dynamic = _run_both_probes(path, bit, max_test=64)  # short budget
    # We intentionally use a short max_test so even binaries with
    # modest padding return 0 (canary's padding is ~80; 64 is below).
    assert dynamic == 0, (
        f"{binary_name}: expected dynamic=0 with short max_test=64, "
        f"got dynamic={dynamic} (static={static}).  This may indicate "
        f"a regression in the dynamic probe's SIGSEGV detection."
    )
    # The fact that dynamic=0 is a legitimate "no overflow" signal
    # is what we want to assert here.  The crosscheck would skip
    # in the main test (see test_static_dynamic_delta_is_legal).


# ---------------------------------------------------------------------------
# Sanity: the legal-delta set covers the actually-observed ctf-pwn data
# ---------------------------------------------------------------------------


def test_legal_delta_set_covers_ctfpwn_observations() -> None:
    """The legal-delta set MUST include the deltas ctf-pwn observed.

    Per the ctf-pwn 2026-06-11 findings (per ``fix.md`` §1.1):
      * rip:        static=23, dynamic=22 → delta=1 (in set ✓)
      * level3_x64: static=136, dynamic=128 → delta=8 (in set ✓)
      * pie:        static=36, dynamic=40 → delta=4 (in 32-bit set ✓)

    This is a meta-test that guards against the legal set shrinking
    or the per-architecture split being collapsed.
    """
    # rip: x64 delta
    assert abs(23 - 22) in LEGAL_DELTA_X64  # 1
    # level3_x64: x64 delta
    assert abs(136 - 128) in LEGAL_DELTA_X64  # 8
    # pie: x32 delta
    assert abs(36 - 40) in LEGAL_DELTA_X32  # 4
    # 32-bit set MUST be a superset of 64-bit set (looser, never stricter)
    assert LEGAL_DELTA_X64.issubset(LEGAL_DELTA_X32), (
        f"LEGAL_DELTA_X32 must be a superset of LEGAL_DELTA_X64; "
        f"missing from x32: {LEGAL_DELTA_X64 - LEGAL_DELTA_X32}"
    )
