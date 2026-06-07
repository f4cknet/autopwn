"""AutoPwn pytest configuration and shared fixtures.

Adds the project root to ``sys.path`` so ``import autopwn`` works
when tests are run from the project root (``pytest tests/``).
Also defines the :func:`ctx_for` factory used by every
``test_detect_*`` module to build an :class:`ExploitContext`
for a Challenge/ binary.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path so ``import autopwn.*`` works
# when pytest is invoked from the project root without ``pip install -e .``.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from autopwn.context import BinaryInfo, ExploitContext  # noqa: E402


# Path to the Challenge/ directory; tests resolve binaries by name
# relative to this.  Override with the ``AUTOPWN_CHALLENGE_DIR``
# env var to test on a different directory (e.g. CI artifact).
CHALLENGE_DIR = Path(
    __import__("os").environ.get(
        "AUTOPWN_CHALLENGE_DIR",
        str(_PROJECT_ROOT / "Challenge"),
    )
)


def ctx_for(binary_name: str, bit: int, **overrides) -> ExploitContext:
    """Build an :class:`ExploitContext` for ``Challenge/{binary_name}``.

    Args:
        binary_name: bare name (e.g. ``"canary"``); resolved
            relative to :data:`CHALLENGE_DIR`.
        bit: 32 or 64 — bit-width of the target binary.
        **overrides: keyword overrides for
            :class:`BinaryInfo` fields (``stack_canary``,
            ``pie``, ``nx``, ``relro``, ``rwx_segments``,
            ``stripped``).

    Returns:
        A new :class:`ExploitContext` with ``mode="local"`` and
        ``libc`` empty (the P5 unit tests don't exercise libc
        resolution).
    """
    path = CHALLENGE_DIR / binary_name
    info = BinaryInfo(
        path=path,
        bit=bit,
        stack_canary=overrides.get("stack_canary", False),
        pie=overrides.get("pie", False),
        nx=overrides.get("nx", True),
        relro=overrides.get("relro", "Partial"),
        rwx_segments=overrides.get("rwx_segments", False),
        stripped=overrides.get("stripped", False),
    )
    return ExploitContext(binary=info, mode="local")


@pytest.fixture
def challenge_dir() -> Path:
    """The Challenge/ directory (override via ``AUTOPWN_CHALLENGE_DIR``)."""
    return CHALLENGE_DIR
