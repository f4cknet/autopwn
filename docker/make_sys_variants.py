#!/usr/bin/env python3
"""从 0CTF-2016-welcome 型二进制派生出「窗口 / 帧尺寸」变体，用来回归 syscall1 / syscall3。

用法（容器内）：
    python3 docker/make_sys_variants.py <原始二进制> bench_sys

派生逻辑（只改三个立即数，其余字节不动）：
    v_limXX  把 `mov dword ptr [esp+8], 0x34` 的 0x34 改掉 —— 窗口变宽后应走 syscall1
    v_frXX   把 `sub esp,0x30` / `add esp,0x30` 一起改 —— 帧变小后返回地址前移，也应走 syscall1

断言：每条原始字节必须唯一命中，避免改错位置还不报错。
"""
from __future__ import annotations

import os
import sys


def patch(data: bytes, pairs) -> bytes:
    b = bytearray(data)
    for old, new in pairs:
        assert len(old) == len(new)
        i = b.find(old)
        assert i > 0, f"pattern not found: {old.hex()}"
        assert b.find(old, i + 1) < 0, f"pattern not unique: {old.hex()}"
        b[i:i + len(old)] = new
    return bytes(b)


def main() -> int:
    src = sys.argv[1] if len(sys.argv) > 1 else \
        "/work/chellenges/7a4abf36c2cebe58ae6c7bff94737a8649589031480027275e3db85d636c9428"
    out = sys.argv[2] if len(sys.argv) > 2 else "/work/bench_sys"
    data = open(src, "rb").read()
    os.makedirs(out, exist_ok=True)

    jobs = {}
    # limit: c7 44 24 08 <imm32>
    for lim in (0x38, 0x3C):
        jobs[f"v_lim{lim:02x}"] = [
            (bytes([0xC7, 0x44, 0x24, 0x08, 0x34, 0, 0, 0]),
             bytes([0xC7, 0x44, 0x24, 0x08, lim, 0, 0, 0]))
        ]
    # frame: 83 ec 30 / 83 c4 30
    for fr in (0x28, 0x2C):
        jobs[f"v_fr{fr:02x}"] = [
            (bytes([0x83, 0xEC, 0x30]), bytes([0x83, 0xEC, fr])),
            (bytes([0x83, 0xC4, 0x30]), bytes([0x83, 0xC4, fr])),
        ]

    for name, pairs in jobs.items():
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        blob = patch(data, pairs)
        p = os.path.join(d, "bin")
        with open(p, "wb") as fh:
            fh.write(blob)
        os.chmod(p, 0o755)
        print(f"{name}: {len(blob)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
