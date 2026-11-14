"""远程 libc 识别：双符号 low12 指纹 → 自动匹配 libc → 返回关键符号偏移。

只做符号偏移查询，不下载 libc 文件。识别顺序：
  1) LibcSearcher（镜像内离线库，无网络）——多候选时取第一个（同 Ubuntu 系列
     关键符号一致，stage2 只用 system/binsh/puts 三个，候选间无差异）；
  2) libc.rip HTTP API（有网络时的回退，超时即放弃）。
识别失败返回 None —— 调用方按原样报 leak failed，不放宽判据。
"""
from __future__ import annotations

import json
import re
from typing import Optional

# LibcSearcher 的多候选交互会 input()；这里绕过它直接读内部结构
USE_RIP_FALLBACK = True
RIP_TIMEOUT = 10


def identify(low12: dict[str, int]) -> Optional[dict]:
    """用若干 {符号: 真实地址} 识别 libc，返回 {符号: 偏移} 映射（含 id）。

    双符号可靠；单符号允许「amd64 候选 ≤3」时放行（Ubuntu 系 amd64 候选的
    system/binsh 偏移一致）。失败返回 None。
    """
    if not low12:
        return None
    cand = _via_libcsearcher(low12)
    if cand:
        return cand
    if USE_RIP_FALLBACK:
        return _via_rip(low12)
    return None


def candidates(low12: dict[str, int]) -> list[dict]:
    """识别的所有可用候选（双符号通常 ≤2 个；单符号 amd64 全集）。

    每个 dict = {id, system, binsh, puts, ...}。按 libcsearch 排序返回。
    调用方对 base 页对齐校验后逐候选尝试。
    """
    if not low12:
        return []
    out = []
    try:
        from LibcSearcher import LibcSearcher
        names = list(low12)
        rs = LibcSearcher(names[0], low12[names[0]] & 0xFFF)
        for name in names[1:]:
            rs.add_condition(name, low12[name] & 0xFFF)
        cands = getattr(rs, "libc_list", None) or []
        if len(low12) < 2:
            cands = [c for c in cands if "_amd64" in c.get("id", "")
                     or "x86_64" in c.get("id", "")]
        for c in cands[:6]:
            syms = c.get("symbols") or {}
            if "system" not in syms or "str_bin_sh" not in syms:
                continue
            d = {"id": c.get("id", "?"), "candidates": len(cands)}
            for name in names:
                if name in syms:
                    d[name] = int(str(syms[name]), 0)
            d["system"] = int(str(syms["system"]), 0)
            d["binsh"] = int(str(syms["str_bin_sh"]), 0)
            out.append(d)
    except Exception:
        pass
    if not out and USE_RIP_FALLBACK:
        rip = _via_rip(low12)
        if rip:
            out.append(rip)
    return out


def _via_libcsearcher(low12: dict[str, int]) -> Optional[dict]:
    try:
        from LibcSearcher import LibcSearcher
    except Exception:
        return None
    try:
        names = list(low12)
        rs = LibcSearcher(names[0], low12[names[0]] & 0xFFF)
        for name in names[1:]:
            rs.add_condition(name, low12[name] & 0xFFF)
        cands = getattr(rs, "libc_list", None) or []
        if not cands:
            return None
        # 单符号时候选混杂 i386/其他发行版：只在「amd64 候选 ≤3」时放行
        if len(low12) < 2:
            amd64 = [c for c in cands if "_amd64" in c.get("id", "")
                     or "x86_64" in c.get("id", "")]
            if not amd64 or len(amd64) > 3:
                return None
            cands = amd64
        # 取第一个（同系列关键符号一致）
        first = cands[0]
        syms = first.get("symbols") or {}
        out = {"id": first.get("id", "?"), "candidates": len(cands)}
        for name in names:
            v = syms.get(name)
            if v is None:
                return None
            out[name] = int(v)
        # stage2 需要的三件套：system / /bin/sh / 泄漏基准
        if "system" in syms:
            out["system"] = int(syms["system"])
        if "str_bin_sh" in syms:
            out["binsh"] = int(syms["str_bin_sh"])
        return out if "system" in out and "binsh" in out else None
    except Exception:
        return None


def _via_rip(low12: dict[str, int]) -> Optional[dict]:
    """libc.rip /api/find 兜底：POST {symbols: {name: low12_hex}}。"""
    try:
        import urllib.request
    except Exception:
        return None
    body = json.dumps({"symbols": {k: format(v & 0xFFF, "x") for k, v in low12.items()}})
    req = urllib.request.Request(
        "https://libc.rip/api/find", data=body.encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        import contextlib
        with contextlib.closing(urllib.request.urlopen(req, timeout=RIP_TIMEOUT)) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    syms = first.get("symbols") or {}
    out = {"id": first.get("id", "?"), "candidates": len(data)}
    for name in low12:
        v = syms.get(name)
        if v is None:
            return None
        out[name] = int(str(v), 16)
    if "system" in syms:
        out["system"] = int(str(syms["system"]), 16)
    if "str_bin_sh" in syms:
        out["binsh"] = int(str(syms["str_bin_sh"]), 16)
    return out if "system" in out and "binsh" in out else None


def rebase(leak_addr: int, cand: dict, anchor: str) -> Optional[int]:
    """按识别出的锚符号偏移重算 base；页不对齐/越界 → None。"""
    off = cand.get(anchor)
    if not off:
        return None
    base = leak_addr - off
    if base <= 0 or base % 0x1000 != 0:
        return None
    if not (0x7F0000000000 <= base < 0x800000000000):
        return None
    return base
