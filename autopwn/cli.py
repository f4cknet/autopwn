"""AutoPwn CLI — modern entry point.

v4 起所有命令行入口都走这里：
  - `python autopwn.py` (shim) → from autopwn.cli import main
  - `python -m autopwn`        → from autopwn.cli import main
  - `autopwn` (after pip install) → autopwn.cli:main (console_scripts)

P8 完成后本模块会替换 autopwn._legacy.main。
"""
from __future__ import annotations

# 临时：P0 阶段从 _legacy 桥接，P8 后改为 from autopwn.orchestrator import run
from autopwn._legacy import main

__all__ = ["main"]
