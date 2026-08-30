"""Unit tests for ``autopwn.core.runner`` toolchain compatibility shims.

Per ``upgraded.md`` §3.2 ``v4.1.14``: the standard ``ctf_env`` container
uses a slightly different external-tool contract than the historical dev
host, so the compatibility branch must stay pinned by unit tests.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from autopwn.core import runner


def _cp(*, stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a minimal ``subprocess.CompletedProcess`` test double."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_run_checksec_falls_back_to_file_flag(monkeypatch):
    """When bare ``checksec <file>`` fails, runner retries ``--file=``."""
    calls = []

    def fake_run(cmd, capture_output, text, check):
        calls.append(cmd)
        if len(calls) == 1:
            return _cp(stderr="usage: checksec --file=ELF", returncode=1)
        return _cp(stderr="RELRO: Full RELRO\n", returncode=0)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    out = runner.run_checksec(Path("Challenge") / "rip")

    assert "RELRO" in out
    assert calls[0][0] == "checksec"
    assert calls[0][1].endswith(str(Path("Challenge") / "rip"))
    assert calls[1] == ["checksec", f"--file={Path('Challenge') / 'rip'}"]


def test_run_checksec_raises_when_both_cli_forms_fail(monkeypatch):
    """Both checksec forms failing must still surface a ``ToolError``."""

    def fake_run(cmd, capture_output, text, check):
        return _cp(stderr=f"bad call: {' '.join(cmd)}", returncode=1)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    with pytest.raises(runner.ToolError, match="both CLI forms"):
        runner.run_checksec(Path("Challenge") / "rip")


def test_normalize_ropgadget_output_strips_headers_and_formats_lines():
    """ROPgadget headers/footers are dropped; gadget lines become ropper-like."""
    raw = "\n".join(
        [
            "Gadgets information",
            "============================================================",
            "0x00000000004011fb : pop rdi ; ret",
            "0x0000000000401016 : ret",
            "Unique gadgets found: 2",
        ]
    )

    assert runner._normalize_ropgadget_output(raw) == (
        "0x00000000004011fb: pop rdi; ret;",
        "0x0000000000401016: ret;",
    )


def test_run_ropper_fallback_uses_ropgadget_and_exact_ret_filter(monkeypatch):
    """Fallback keeps pure ``ret`` separate from ``pop ...; ret`` gadgets."""

    def fake_which(name):
        if name == "ropper":
            return None
        if name == "ROPgadget":
            return "/usr/bin/ROPgadget"
        return None

    monkeypatch.setattr(runner.shutil, "which", fake_which)
    monkeypatch.setattr(
        runner,
        "_ropgadget_scan_cached",
        lambda _program: (
            "0x1: pop rdi; ret;",
            "0x2: pop rsi; pop r15; ret;",
            "0x3: ret;",
        ),
    )

    assert runner.run_ropper(Path("Challenge") / "rip", "pop rdi") == "0x1: pop rdi; ret;\n"
    assert runner.run_ropper(Path("Challenge") / "rip", "ret;") == "0x3: ret;\n"


def test_run_cyclic_create_falls_back_to_pwn(monkeypatch):
    """Standalone ``cyclic`` missing -> use ``pwn cyclic``."""

    def fake_which(name):
        if name == "cyclic":
            return None
        if name == "pwn":
            return "/usr/bin/pwn"
        return None

    calls = []

    def fake_run(cmd, capture_output, text, check):
        calls.append(cmd)
        return _cp(stdout="aaaabaaacaaadaaa\n")

    monkeypatch.setattr(runner.shutil, "which", fake_which)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    out = runner.run_cyclic_create(16)

    assert out == "aaaabaaacaaadaaa"
    assert calls == [["pwn", "cyclic", "16"]]


def test_run_cyclic_find_falls_back_to_pwn(monkeypatch):
    """Standalone ``cyclic -l`` missing -> use ``pwn cyclic -l``."""

    def fake_which(name):
        if name == "cyclic":
            return None
        if name == "pwn":
            return "/usr/bin/pwn"
        return None

    calls = []

    def fake_run(cmd, capture_output, text, check):
        calls.append(cmd)
        return _cp(stdout="140\n")

    monkeypatch.setattr(runner.shutil, "which", fake_which)
    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    out = runner.run_cyclic_find("kaaa")

    assert out == "140"
    assert calls == [["pwn", "cyclic", "-l", "kaaa"]]
