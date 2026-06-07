"""AutoPwn — Automated Binary Exploitation Framework.

Refactored from open-source pwnpasi (heimao-box/pwnpasi, MIT).
Maintained by qzdx_soc (衢州电信安全运营中心).
"""
from __future__ import annotations

__version__ = "4.0.dev0"
__author__ = "qzdx_soc"
__org__ = "衢州电信安全运营中心"
__github__ = "https://github.com/f4cknet/autopwn"

# Re-export CLI as a top-level attribute for convenience.
from autopwn import cli  # noqa: E402, F401

# P2.1: re-export the model-layer dataclasses.  Recon/detect/strategy
# modules in P4-P7 will import them as `from autopwn import BinaryInfo, ExploitContext, ...`.
from autopwn.context import (  # noqa: E402, F401
    BinaryInfo,
    CanaryInfo,
    ExploitContext,
    LibcInfo,
    RopGadgetsX64,
    RopGadgetsX32,
)

__all__ = [
    "__version__", "__author__", "__org__", "__github__", "cli",
    "BinaryInfo", "CanaryInfo", "ExploitContext",
    "LibcInfo", "RopGadgetsX64", "RopGadgetsX32",
]
