"""Unit tests for ``autopwn.primitives.base`` (P6.1).

Per ``rebuild.md`` §6.7 P6.1: the base class + result dataclass
are the foundation for P6.2-P6.8.  This module tests:

  * :class:`ExploitPrimitive` ABC contract (cannot be
    instantiated directly; subclasses must implement
    ``build_payload``).
  * :class:`ExploitPrimitive.stage_count` default = 1.
  * :class:`ExploitResult` dataclass shape (success, payload).
  * Subclass registration pattern that P6.2-P6.8 will use.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


class TestExploitPrimitiveABC:
    """``primitives.base.ExploitPrimitive`` — abstract base contract."""

    def test_cannot_instantiate_directly(self):
        """The ABC raises TypeError when instantiated without a ``build_payload`` impl."""
        from autopwn.primitives.base import ExploitPrimitive

        with pytest.raises(TypeError) as exc_info:
            ExploitPrimitive()  # noqa: B017  (intentional ABC violation)
        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_build_payload(self):
        """A subclass without ``build_payload`` is also non-instantiable."""
        from autopwn.primitives.base import ExploitPrimitive

        class Incomplete(ExploitPrimitive):
            name = "incomplete"
            # NOTE: no build_payload override — should be non-instantiable

        with pytest.raises(TypeError):
            Incomplete()  # noqa: B017

    def test_subclass_with_build_payload_is_instantiable(self):
        """A complete subclass instantiates and runs."""
        from autopwn.primitives.base import ExploitPrimitive

        class Complete(ExploitPrimitive):
            name = "complete"

            def build_payload(self, ctx):
                return b"X" * ctx.padding

        inst = Complete()
        assert inst.name == "complete"
        assert inst.stage_count() == 1

    def test_stage_count_default_is_one(self):
        """``stage_count()`` defaults to 1; subclasses can override."""
        from autopwn.primitives.base import ExploitPrimitive

        class TwoStage(ExploitPrimitive):
            name = "two-stage"

            def build_payload(self, ctx):
                return b""

            def stage_count(self) -> int:
                return 2

        assert TwoStage().stage_count() == 2

    def test_name_must_be_set(self):
        """Class attribute ``name`` defaults to ``""`` — subclasses MUST override."""
        from autopwn.primitives.base import ExploitPrimitive

        class Nameless(ExploitPrimitive):
            def build_payload(self, ctx):
                return b""

        assert Nameless().name == ""  # convention: subclasses override

    def test_build_payload_takes_ctx_and_returns_bytes(self, challenge_dir):
        """A subclass can read ``ctx.padding`` and return ``bytes``."""
        from autopwn.primitives.base import ExploitPrimitive

        class Padding(ExploitPrimitive):
            name = "padding"

            def build_payload(self, ctx):
                return b"P" * ctx.padding

        ctx = ctx_for("canary", bit=32)
        ctx.padding = 12
        result = Padding().build_payload(ctx)
        assert isinstance(result, bytes)
        assert result == b"P" * 12


class TestExploitResult:
    """``primitives.base.ExploitResult`` — frozen-ish dataclass."""

    def test_default_construction(self):
        """Default ``payload=b""`` lets callers pass just the bool."""
        from autopwn.primitives.base import ExploitResult

        r = ExploitResult(success=True)
        assert r.success is True
        assert r.payload == b""

    def test_full_construction(self):
        """Both fields are settable via the constructor."""
        from autopwn.primitives.base import ExploitResult

        r = ExploitResult(success=False, payload=b"AAAA")
        assert r.success is False
        assert r.payload == b"AAAA"

    def test_equality_via_dataclass(self):
        """Two results with the same fields compare equal (dataclass __eq__)."""
        from autopwn.primitives.base import ExploitResult

        a = ExploitResult(success=True, payload=b"\x00\x01")
        b = ExploitResult(success=True, payload=b"\x00\x01")
        assert a == b
        assert a is not b

    def test_repr_is_deterministic(self):
        """The dataclass repr is the canonical ``ExploitResult(success=..., payload=...)``."""
        from autopwn.primitives.base import ExploitResult

        r = ExploitResult(success=True, payload=b"hi")
        assert repr(r) == "ExploitResult(success=True, payload=b'hi')"
