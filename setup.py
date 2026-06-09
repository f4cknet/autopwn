"""Minimal setup.py — delegates to pyproject.toml (PEP 517/518).

P10.2 (2026-06-09): replaced the 336-line legacy setup.py (v3.0 banner +
interactive dependency installer) with a minimal forwarder.  All real
metadata lives in ``pyproject.toml``; this file exists only for
environments that still require ``setup.py`` to exist (e.g. older
``pip`` versions without PEP 517 support).

Per ``AGENTS.md`` §1 铁律 + ``rebuild.md`` §6.11 spec:

  > P10.2 改为最小转发 (``from setuptools import setup; setup()``)

After this rewrite, ``pip install .`` reads from ``pyproject.toml``
exclusively; ``setup.py`` is a stub for backward compatibility.
"""
from setuptools import setup

setup()
