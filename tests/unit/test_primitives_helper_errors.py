"""Targeted coverage tests for primitives helper error paths (P6.9).

Per ``rebuild.md`` §6.7 P6.9: the per-primitive tests cover the
happy path + gates (bit-width / fields-missing), but don't
exercise the ``try/except`` error paths inside the helper
functions (``_lookup_*``).  These error paths are uncovered
in the line coverage report and are exactly the kind of code
that breaks silently when refactored.

This file adds **focused** tests for those error paths using
``unittest.mock`` to simulate the failure conditions:

* :func:`_lookup_system_and_binsh` (ret2system) — ELF() failure,
  symbols lookup failure
* :func:`_lookup_puts_and_main` (ret2libc_put) — same
* :func:`_lookup_write_and_main` (ret2libc_write) — same
* :func:`_lookup_binsh` (execve_syscall) — ELF() failure
* :func:`_lookup_bss_addr` (shellcode) — recon.find_bss failure
* :func:`_lookup_backdoor_addr` (pie_backdoor) — ELF() failure
* :func:`_resolve_fmtstr_inputs` (fmtstr) — already covered
  in test_primitives_fmtstr.py

Each test verifies that the helper degrades gracefully
(returns ``None`` / empty) when the underlying lookup fails,
rather than raising an unhandled exception.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest


pytestmark = pytest.mark.primitive


class TestRet2systemHelperErrorPaths:
    """``_lookup_system_and_binsh`` returns ``(None, None)`` on failure."""

    def test_returns_none_when_elf_open_fails(self, tmp_path):
        """If ``ELF()`` raises, the helper returns ``(None, None)``."""
        from autopwn.primitives.ret2system import _lookup_system_and_binsh

        nonexistent = tmp_path / "does_not_exist"
        with patch("pwn.ELF", side_effect=OSError("not found")):
            result = _lookup_system_and_binsh(nonexistent)
        assert result == (None, None)

    def test_returns_none_when_system_symbol_missing(self, tmp_path):
        """If ``e.symbols['system']`` raises ``KeyError``, system_addr is None."""
        from autopwn.primitives.ret2system import _lookup_system_and_binsh

        # Use a real binary but mock ELF to simulate missing symbols
        real_binary = Path("Challenge/canary")
        mock_elf = type("MockELF", (), {
            "symbols": {},  # empty → KeyError on "system"
            "search": lambda self, x: iter([]),  # empty → StopIteration
        })()
        with patch("pwn.ELF", return_value=mock_elf):
            result = _lookup_system_and_binsh(real_binary)
        assert result == (None, None)


class TestRet2libcPutHelperErrorPaths:
    """``_lookup_puts_and_main`` returns ``(None, None, None)`` on failure."""

    def test_returns_none_tuple_when_elf_open_fails(self, tmp_path):
        from autopwn.primitives.ret2libc_put import _lookup_puts_and_main

        nonexistent = tmp_path / "does_not_exist"
        with patch("pwn.ELF", side_effect=OSError("not found")):
            result = _lookup_puts_and_main(nonexistent)
        assert result == (None, None, None)

    def test_returns_none_tuple_when_symbols_missing(self):
        from autopwn.primitives.ret2libc_put import _lookup_puts_and_main

        real_binary = Path("Challenge/canary")
        mock_elf = type("MockELF", (), {
            "plt": {},
            "got": {},
            "symbols": {},
        })()
        with patch("pwn.ELF", return_value=mock_elf):
            result = _lookup_puts_and_main(real_binary)
        assert result == (None, None, None)


class TestRet2libcWriteHelperErrorPaths:
    """``_lookup_write_and_main`` returns ``(None, None, None)`` on failure."""

    def test_returns_none_tuple_when_elf_open_fails(self, tmp_path):
        from autopwn.primitives.ret2libc_write import _lookup_write_and_main

        nonexistent = tmp_path / "does_not_exist"
        with patch("pwn.ELF", side_effect=OSError("not found")):
            result = _lookup_write_and_main(nonexistent)
        assert result == (None, None, None)

    def test_returns_none_tuple_when_symbols_missing(self):
        from autopwn.primitives.ret2libc_write import _lookup_write_and_main

        real_binary = Path("Challenge/canary")
        mock_elf = type("MockELF", (), {
            "plt": {},
            "got": {},
            "symbols": {},
        })()
        with patch("pwn.ELF", return_value=mock_elf):
            result = _lookup_write_and_main(real_binary)
        assert result == (None, None, None)


class TestExecveSyscallHelperErrorPaths:
    """``_lookup_binsh`` returns ``None`` on failure."""

    def test_returns_none_when_elf_open_fails(self, tmp_path):
        from autopwn.primitives.execve_syscall import _lookup_binsh

        nonexistent = tmp_path / "does_not_exist"
        with patch("pwn.ELF", side_effect=OSError("not found")):
            result = _lookup_binsh(nonexistent)
        assert result is None

    def test_returns_none_when_no_binsh_string(self):
        from autopwn.primitives.execve_syscall import _lookup_binsh

        real_binary = Path("Challenge/canary")
        mock_elf = type("MockELF", (), {
            "search": lambda self, x: iter([]),  # no /bin/sh
        })()
        with patch("pwn.ELF", return_value=mock_elf):
            result = _lookup_binsh(real_binary)
        assert result is None


class TestShellcodeHelperErrorPaths:
    """``_lookup_bss_addr`` returns ``None`` when ``find_bss`` returns empty."""

    def test_returns_none_when_find_bss_returns_empty(self):
        from autopwn.primitives.shellcode import _lookup_bss_addr

        real_binary = Path("Challenge/canary")
        # `_lookup_bss_addr` does `from autopwn.recon.bss import find_bss`
        # at call time — patch the source module, not the local binding.
        with patch("autopwn.recon.bss.find_bss", return_value=[]):
            result = _lookup_bss_addr(real_binary)
        assert result is None


class TestPieBackdoorHelperErrorPaths:
    """``_lookup_backdoor_addr`` returns ``None`` on ELF failure."""

    def test_returns_none_when_elf_open_fails(self, tmp_path):
        from autopwn.primitives.pie_backdoor import _lookup_backdoor_addr

        # ctx with has_backdoor=True (otherwise we'd short-circuit before ELF)
        from autopwn.context import BinaryInfo, ExploitContext

        ctx = ExploitContext(
            binary=BinaryInfo(
                path=tmp_path / "does_not_exist",
                bit=64, stack_canary=False, pie=True, nx=True,
                relro="Partial", rwx_segments=False, stripped=False,
            ),
            mode="local",
            has_backdoor=True,
        )
        with patch("pwn.ELF", side_effect=OSError("not found")):
            result = _lookup_backdoor_addr(ctx)
        assert result is None
