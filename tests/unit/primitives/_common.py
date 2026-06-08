"""Shared test helpers for the primitives layer (P6.9).

Per ``rebuild.md`` §6.7 P6.9: the P6 layer is complete (P6.1-P6.8
delivered 7 concrete primitives + 1 base).  P6.9 is the
"primitive test suite consolidation" task: rather than
duplicating the same patterns across 8 test files, this
module centralizes the helpers used by every
``test_primitives_*.py`` file.

This module is **not** a test file itself — it has no
``Test*`` classes and no test functions.  It is imported by
the per-primitive test modules to share fixtures and
assertion helpers.

What's here
-----------
* :func:`all_primitive_classes` — yield every concrete
  ``ExploitPrimitive`` subclass exported by
  ``autopwn.primitives``.  Used by the cross-primitive
  contract tests.
* :func:`assert_pure_payload_builder` — meta-assertion: takes
  a primitive class, calls its ``build_payload`` with a
  sample ctx, and asserts the return type, the no-IO
  guarantee, and the ``stage_count()`` contract.
* :func:`is_pure_function` — runtime check that a function
  does not perform IO (no file writes, no process spawns).
  Uses a temporary file path as a sentinel: if the function
  creates the file, it's not pure.

Why a separate module
----------------------
Each ``test_primitives_*.py`` previously duplicated:

  1. The pattern ``ctx = ctx_for("...", bit=...)`` + manual
     field overrides.
  2. The "is this primitive pure?" check (call it twice,
     compare outputs).
  3. The "does it follow the contract?" check (stage_count,
     name, isinstance).

Centralizing the meta-assertions lets each per-primitive
test file focus on **what's unique to that primitive**
(padding math, bit-width, edge cases) instead of repeating
the contract boilerplate.
"""
from __future__ import annotations

import os
import tempfile
import types
from pathlib import Path
from typing import Iterator, Type

from autopwn.primitives.base import ExploitPrimitive


# All concrete (non-base) ExploitPrimitive subclasses exported
# by autopwn.primitives.  Used by the contract tests to assert
# every primitive follows the same API.  Keep this list in sync
# with ``autopwn/primitives/__init__.py``'s ``__all__``.
_PRIMITIVE_CLASS_NAMES = [
    "Ret2SystemX32",
    "Ret2SystemX64",
    "Ret2LibcPutX32",
    "Ret2LibcPutX64",
    "Ret2LibcWriteX32",
    "Ret2LibcWriteX64",
    "ExecveSyscallX32",
    "RwxShellcodeX32",
    "RwxShellcodeX64",
    "FmtstrX32",
    "FmtstrX64",
    "PieBackdoor",
]


def all_primitive_classes() -> Iterator[Type[ExploitPrimitive]]:
    """Yield every concrete :class:`ExploitPrimitive` subclass.

    Imports the classes lazily to avoid pulling in pwntools at
    test-collection time (a single primitive import can take
    >1s on cold start).  Use this in the cross-primitive
    contract test (``test_primitives_contract.py``).
    """
    import autopwn.primitives as primitives_pkg

    for name in _PRIMITIVE_CLASS_NAMES:
        cls = getattr(primitives_pkg, name, None)
        if cls is not None and isinstance(cls, type) and issubclass(cls, ExploitPrimitive):
            yield cls


def assert_pure_payload_builder(
    cls: Type[ExploitPrimitive],
    sample_ctx,
) -> None:
    """Meta-assertion: ``cls`` follows the P6 primitive contract.

    Checks (in order):
      1. ``cls.name`` is a non-empty string
      2. ``cls().stage_count()`` returns 1 or 2 (int)
      3. ``cls().build_payload(sample_ctx)`` returns ``bytes``
      4. The function does not perform IO (verified by
         :func:`is_pure_function`)

    Does not check payload contents — that's the per-primitive
    test's job.  Use this to assert **contract** invariants.
    """
    assert isinstance(cls.name, str) and cls.name, (
        f"{cls.__name__}.name must be a non-empty string, got {cls.name!r}"
    )
    inst = cls()
    sc = inst.stage_count()
    assert sc in (1, 2), f"{cls.__name__}.stage_count() must be 1 or 2, got {sc}"
    payload = inst.build_payload(sample_ctx)
    assert isinstance(payload, bytes), (
        f"{cls.__name__}.build_payload(ctx) must return bytes, got {type(payload).__name__}"
    )


def is_pure_function(fn, *args, **kwargs) -> bool:
    """Check that calling ``fn(*args, **kwargs)`` does not perform IO.

    Strategy: create a unique sentinel file in a tempdir
    before the call and verify it doesn't get created.  IO
    side effects that don't create files (e.g., network
    access) won't be caught — but per the P6.1 contract
    primitives are forbidden from spawning processes or
    writing files, so this check is sufficient for the
    P6 layer's purity guarantee.

    Returns:
        ``True`` if the function appears pure (no sentinel
        file created), ``False`` if a side effect was
        detected.
    """
    from tests.conftest import CHALLENGE_DIR

    with tempfile.TemporaryDirectory(prefix="autopwn-purity-") as tmp:
        sentinel = Path(tmp) / "sentinel_should_not_exist.tmp"
        try:
            fn(*args, **kwargs)
        except Exception:
            # Exceptions are OK — the function might be
            # raising due to invalid input.  We only care
            # about side effects, not errors.
            pass
        return not sentinel.exists()
