"""Unit tests for ``autopwn.context.ExploitContext`` v4.1.11 SSL toggle.

Per ``upgraded.md`` §3.2 v4.1.11: the new ``-ssl`` CLI flag must
propagate to ``ExploitContext.ssl: bool`` and raise ``ContextError``
when combined with local mode (no ``-ip`` / ``-p``).
"""
from __future__ import annotations

import argparse

import pytest


def _ns(**kwargs):
    """Build a minimal argparse.Namespace matching what main() produces.

    Uses an **absolute** path for ``local`` so the tests are independent
    of the current working directory (per `from_args` semantics —
    `Path("Challenge/rip").exists()` resolves against cwd).
    """
    base = dict(
        local="/ctf/autopwn/Challenge/rip",  # absolute — exists in this repo
        ip=None,
        port=None,
        libc=None,
        fill=0,
        verbose=False,
        no_report=False,
        report_dir=None,
        ssl=False,
    )
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_from_args_default_ssl_is_false(tmp_path, monkeypatch):
    """Without ``-ssl`` flag, ``ctx.ssl`` is False (backward compat)."""
    monkeypatch.chdir(tmp_path)
    from autopwn.context import ExploitContext
    ctx = ExploitContext.from_args(_ns())
    assert ctx.ssl is False
    assert ctx.mode == "local"


def test_from_args_with_ssl_remote_sets_flag(tmp_path, monkeypatch):
    """``-ip 1.2.3.4 -p 31337 -ssl`` → ``ctx.ssl is True`` + remote mode."""
    monkeypatch.chdir(tmp_path)
    from autopwn.context import ExploitContext
    ctx = ExploitContext.from_args(_ns(ip="1.2.3.4", port=31337, ssl=True))
    assert ctx.ssl is True
    assert ctx.mode == "remote"
    assert ctx.remote == ("1.2.3.4", 31337)


def test_from_args_with_ssl_local_raises_context_error(tmp_path, monkeypatch):
    """``-ssl`` without ``-ip/-p`` is a user typo — must raise ContextError.

    Rationale: silently allowing it would let users think they have SSL
    while the local ``process()`` path ignores the flag.  Force them to
    add ``-ip`` + ``-p`` to make the SSL intent explicit.
    """
    monkeypatch.chdir(tmp_path)
    from autopwn.context import ContextError, ExploitContext
    with pytest.raises(ContextError, match="-ssl requires"):
        ExploitContext.from_args(_ns(ssl=True))


def test_from_args_remote_without_ssl_still_works(tmp_path, monkeypatch):
    """``-ip -p`` without ``-ssl`` → remote mode, ctx.ssl=False (legacy)."""
    monkeypatch.chdir(tmp_path)
    from autopwn.context import ExploitContext
    ctx = ExploitContext.from_args(_ns(ip="10.0.0.1", port=9999))
    assert ctx.ssl is False
    assert ctx.mode == "remote"


def test_cli_argparser_accepts_dash_ssl():
    """The CLI parser must register ``-ssl`` / ``--ssl`` as a flag.

    This guards against accidentally renaming the CLI surface (e.g.
    someone refactors _build_argparser and drops the flag).
    """
    from autopwn.cli import _build_argparser
    parser = _build_argparser()
    # Short form
    ns = parser.parse_args(["-l", "/tmp/x", "-ssl"])
    assert ns.ssl is True
    # Long form
    ns = parser.parse_args(["-l", "/tmp/x", "--ssl"])
    assert ns.ssl is True
    # No flag → False
    ns = parser.parse_args(["-l", "/tmp/x"])
    assert ns.ssl is False

