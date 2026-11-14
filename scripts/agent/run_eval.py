#!/usr/bin/env python3
"""冻结评测器：跑 dev + 三套回归，输出 state/last.json。

设计约束（不要改）：
  * 本文件应放在 /srv/autopwn/eval/，root:root 755，impl 用户只读。
  * **不许调用 --allow-brute**（盲试恒为 0，这是判定前提）。
  * 只输出数字，不做任何"是否可以合入"的判断（判断在 supervisor.py）。

用法：
  python3 run_eval.py --root /srv/autopwn/impl --dev dev \
      --out /srv/autopwn/state/last.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

SUMMARY_RE = re.compile(r"===\s*(\d+)/(\d+)\s*shell,\s*(\d+)\s*flag-only\s*===")
MARK_RE = re.compile(r"^\s*([✓✗⚑])\s+(\S+)", re.M)


def sha256(path: str) -> str:
    if not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def run_target(root: str, target: str, timeout: int = 3600) -> dict:
    """在容器里跑一个目标，解析汇总行。"""
    cmd = ["bash", "docker/solve.sh", target, "-q"]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=root, capture_output=True, text=True,
                           timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + (exc.stderr or "")
        out = out if isinstance(out, str) else out.decode("utf-8", "replace")
        rc = -9
    m = None
    for m in SUMMARY_RE.finditer(out):
        pass
    if m is None:
        return {"target": target, "parsed": False, "rc": rc,
                "elapsed": round(time.time() - t0, 1),
                "raw_tail": out[-800:]}
    shell, total, flag = int(m.group(1)), int(m.group(2)), int(m.group(3))
    marks = {"pass": 0, "fail": 0, "flag": 0}
    for sym, _name in MARK_RE.findall(out):
        marks["pass" if sym == "✓" else ("flag" if sym == "⚑" else "fail")] += 1
    return {"target": target, "parsed": True, "rc": rc,
            "shell": shell, "total": total, "flag_only": flag,
            "marks": marks, "elapsed": round(time.time() - t0, 1)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="impl 仓库路径")
    ap.add_argument("--dev", default="dev", help="dev 题目录（相对仓库根）")
    ap.add_argument("--suites", default="bench,bench_extra,bench_sys")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    targets = [args.dev] + [s for s in args.suites.split(",") if s]
    res = {}
    ok = True
    for t in targets:
        r = run_target(args.root, t)
        res[t] = r
        if not r.get("parsed"):
            ok = False
        print(f"[eval] {t}: {r}", file=sys.stderr)

    # 盲试恒为 0：本脚本根本不传 --allow-brute，任何非 0 都是被外部篡改
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "git_head": subprocess.run(
            ["git", "-C", args.root, "rev-parse", "HEAD"],
            capture_output=True, text=True).stdout.strip(),
        "oracle_sha": sha256(os.path.join(args.root, "autopwn/engine/oracle.py")),
        "eval_sha": sha256(os.path.abspath(__file__)),
        "brute_allowed": False,
        "brute_attempts": 0,
        "dev_rate": (res[args.dev].get("shell", 0) / max(res[args.dev].get("total", 0), 1)
                     if res[args.dev].get("parsed") else 0.0),
        "suites": {k: v for k, v in res.items() if k != args.dev},
        "dev": res[args.dev],
        "parsed_all": ok,
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(json.dumps({"dev_rate": payload["dev_rate"], "parsed_all": ok}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
