"""Cross-primitive contract tests (P6.9).

Per ``rebuild.md`` §6.7 P6.9: every primitive in the P6 layer
must follow the same API contract, regardless of the specific
exploitation technique (ret2system, ret2libc, execve, shellcode,
fmtstr, pie-backdoor).  This test file verifies the
cross-cutting contract invariants using
:func:`autopwn.primitives._common.all_primitive_classes` and
:func:`autopwn.primitives._common.assert_pure_payload_builder`.

These tests don't replace the per-primitive tests in
``test_primitives_*.py`` — those still cover each primitive's
specific behavior (padding math, bit-width gates, edge cases).
This file is the **contract layer**: it asserts that
"every primitive behaves like a primitive" — a property that
would break if a future P6.x forgot to set ``name`` or made
``build_payload`` perform IO.

Test plan
---------
* Every primitive has a non-empty ``name`` class attribute
* Every primitive's ``stage_count()`` returns 1 or 2
* Every primitive's ``build_payload(ctx)`` returns ``bytes``
  for at least one (x32, x64) ctx
* No primitive writes a sentinel file (purity check)
* No primitive spawns a subprocess (verified by checking
  the primitive class has no ``process`` import in its
  source — the legacy ports ARE allowed to import
  ``pwntools.process``, but the public ``build_payload``
  method must not invoke it)
* The ``autopwn.primitives`` re-exports are all valid
  :class:`ExploitPrimitive` subclasses (catches typos in
  ``__init__.py``)
"""
from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from tests.conftest import ctx_for
from tests.unit.primitives._common import (
    all_primitive_classes,
    assert_pure_payload_builder,
    is_pure_function,
)


pytestmark = pytest.mark.primitive


class TestPrimitiveContract:
    """Cross-primitive contract: every P6 primitive follows the same API."""

    def test_all_primitives_have_non_empty_name(self):
        """``cls.name`` must be a non-empty string for every primitive."""
        for cls in all_primitive_classes():
            assert isinstance(cls.name, str) and cls.name, (
                f"{cls.__name__}.name must be a non-empty string, got {cls.name!r}"
            )

    def test_all_primitives_have_valid_stage_count(self):
        """``cls().stage_count()`` must return 1 or 2."""
        for cls in all_primitive_classes():
            sc = cls().stage_count()
            assert sc in (1, 2), (
                f"{cls.__name__}.stage_count() must be 1 or 2, got {sc}"
            )

    def test_all_primitives_have_docstring(self):
        """Every primitive class must have a docstring (P6.1 convention)."""
        for cls in all_primitive_classes():
            assert cls.__doc__, f"{cls.__name__} is missing a class docstring"

    def test_all_primitives_subclass_exploit_primitive(self):
        """Every primitive must subclass :class:`ExploitPrimitive`."""
        from autopwn.primitives.base import ExploitPrimitive

        for cls in all_primitive_classes():
            assert issubclass(cls, ExploitPrimitive)

    @pytest.mark.parametrize("arch,ctx_factory", [
        ("x32", lambda: ctx_for("fmtstr1", bit=32)),
        ("x64", lambda: ctx_for("level3_x64", bit=64)),
    ])
    def test_build_payload_returns_bytes(self, arch, ctx_factory):
        """``build_payload(ctx)`` returns ``bytes`` for at least one arch.

        For x32 we use ``fmtstr1`` (32-bit) and for x64 we use
        ``level3_x64`` (64-bit).  The payload may be ``b""`` if
        the primitive's gates aren't met (e.g., ret2system
        returns ``b""`` when there's no ``system`` symbol) —
        that's OK; we only assert the return TYPE is ``bytes``.
        """
        ctx = ctx_factory()
        ctx.fmtstr_offset = 11
        ctx.fmtstr_buf = 0x404060
        ctx.has_backdoor = True
        ctx.gadgets_x64 = None
        ctx.gadgets_x32 = None

        for cls in all_primitive_classes():
            inst = cls()
            payload = inst.build_payload(ctx)
            assert isinstance(payload, bytes), (
                f"{cls.__name__}.build_payload must return bytes, "
                f"got {type(payload).__name__}"
            )

    def test_all_primitive_class_names_unique(self):
        """Every primitive must have a unique ``name`` (registry identifier)."""
        names = [cls.name for cls in all_primitive_classes()]
        duplicates = [n for n in names if names.count(n) > 1]
        assert not duplicates, f"duplicate primitive names: {set(duplicates)}"

    def test_primitive_name_is_lowercase_with_dashes(self):
        """All primitive names follow the ``<tech>-<arch>`` convention.

        E.g., ``ret2system-x32``, ``fmtstr-x64``, ``pie-backdoor``.
        This is the format P7's strategy registry uses for
        "trying <name>" log lines.
        """
        name_pattern = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
        for cls in all_primitive_classes():
            assert name_pattern.match(cls.name), (
                f"{cls.__name__}.name={cls.name!r} doesn't match "
                f"the <tech>-<arch> convention"
            )


class TestPrimitivePurity:
    """Pure-function contract: primitives must not perform IO."""

    def test_build_payload_does_not_write_sentinel_file(self, tmp_path):
        """``build_payload(ctx)`` must not create any file.

        We use :func:`is_pure_function` which calls the
        function with a sentinel path setup; if the function
        creates the sentinel, it's impure.
        """
        from autopwn.primitives.base import ExploitPrimitive

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 80
        ctx.fmtstr_offset = 6
        ctx.fmtstr_buf = 0x404060
        ctx.has_backdoor = True

        for cls in all_primitive_classes():
            inst = cls()
            # is_pure_function calls the function and checks for
            # IO side effects.  Note: this does NOT test that
            # the function is deterministic — it only checks
            # that no files are created.  Determinism is
            # verified separately by the per-primitive tests.
            assert is_pure_function(inst.build_payload, ctx), (
                f"{cls.__name__}.build_payload wrote a sentinel file — "
                f"primitive must be pure (no file writes)"
            )

    def test_build_payload_source_does_not_import_pwn_process(self):
        """Public ``build_payload`` source must not reference ``pwn.process``.

        This is a static AST check: walk every
        ``ExploitPrimitive`` subclass's ``build_payload``
        method, get its source body (sans docstring), and
        assert it doesn't call ``process(`` or ``remote(``.
        Legacy ports (``_legacy_*`` functions) are allowed
        to import / call ``process`` because they're meant
        to mirror v3.1's IO-heavy code; only the public
        ``build_payload`` is forbidden from doing so.
        """
        import ast as ast_mod

        for cls in all_primitive_classes():
            # Get the source of build_payload
            try:
                src = inspect.getsource(cls.build_payload)
            except (OSError, TypeError):
                # Built-in / dynamically generated — skip
                continue

            # Strip the docstring (line-by-line) to avoid false
            # positives — the docstring often contains "no
            # process" or similar language describing the
            # contract.
            tree = ast_mod.parse(src.lstrip())
            method_def = tree.body[0]
            docstring = ast_mod.get_docstring(method_def)
            src_no_docstring = src
            if docstring:
                # Drop everything from the line containing the
                # docstring start to its end.  This is a
                # best-effort string substitution — accurate
                # enough for the assertion.
                lines = src.split("\n")
                start = method_def.lineno  # 1-based relative
                # docstring is the first stmt; find the closing
                # triple-quote line
                in_doc = False
                quote = '"""'
                doc_start = doc_end = None
                for i, line in enumerate(lines):
                    if quote in line and not in_doc:
                        in_doc = True
                        doc_start = i
                        # check for single-line docstring
                        if line.count(quote) >= 2:
                            doc_end = i
                            break
                    elif in_doc and quote in line:
                        doc_end = i
                        break
                if doc_start is not None and doc_end is not None:
                    src_no_docstring = "\n".join(
                        lines[:doc_start] + lines[doc_end + 1:]
                    )

            # Now assert: no process( or remote(
            assert "process(" not in src_no_docstring, (
                f"{cls.__name__}.build_payload references 'process(' — "
                f"primitives must be pure (no process spawns)"
            )
            assert "remote(" not in src_no_docstring, (
                f"{cls.__name__}.build_payload references 'remote(' — "
                f"primitives must be pure (no process spawns)"
            )


class TestPrimitiveRegistry:
    """Verify the ``autopwn.primitives`` re-exports are correct."""

    def test_all_exported_primitives_are_concrete(self):
        """Every name in ``autopwn.primitives.__all__`` must be a concrete class.

        Catches typos in ``__init__.py`` like accidentally
        exporting a helper function or re-exporting the
        abstract ``ExploitPrimitive`` (which IS in ``__all__``
        by design but is the base class, not a concrete
        primitive).
        """
        from autopwn.primitives import __all__ as primitives_all
        from autopwn.primitives import ExploitPrimitive, ExploitResult
        import autopwn.primitives as primitives_pkg

        base_classes = {ExploitPrimitive, ExploitResult}
        for name in primitives_all:
            obj = getattr(primitives_pkg, name)
            assert isinstance(obj, type), (
                f"autopwn.primitives.{name} is not a class"
            )
            if obj not in base_classes:
                # Must be a concrete ExploitPrimitive subclass
                assert issubclass(obj, ExploitPrimitive), (
                    f"autopwn.primitives.{name} is not a subclass of "
                    f"ExploitPrimitive"
                )

    def test_primitives_can_be_imported_from_package(self):
        """All primitives are accessible via ``from autopwn.primitives import X``.

        This is a sanity check that the re-export pattern
        works for every concrete primitive.
        """
        from autopwn.primitives import (
            Ret2SystemX32, Ret2SystemX64,
            Ret2LibcPutX32, Ret2LibcPutX64,
            Ret2LibcWriteX32, Ret2LibcWriteX64,
            ExecveSyscallX32,
            RwxShellcodeX32, RwxShellcodeX64,
            FmtstrX32, FmtstrX64,
            PieBackdoor,
        )

        # All 12 primitives
        for cls in [
            Ret2SystemX32, Ret2SystemX64,
            Ret2LibcPutX32, Ret2LibcPutX64,
            Ret2LibcWriteX32, Ret2LibcWriteX64,
            ExecveSyscallX32,
            RwxShellcodeX32, RwxShellcodeX64,
            FmtstrX32, FmtstrX64,
            PieBackdoor,
        ]:
            assert inspect.isclass(cls)
            assert hasattr(cls, "build_payload")
            assert hasattr(cls, "stage_count")
