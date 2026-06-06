#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AutoPwn shim — delegates to autopwn.cli.main().

真正的实现在 autopwn/ 包里。本文件仅为兼容 `python autopwn.py` 的旧调用方式。

P8 orchestrator 落地后，本 shim 可保持现状，也可删除（统一走 `python -m autopwn`）。
"""
from autopwn.cli import main

if __name__ == "__main__":
    main()
