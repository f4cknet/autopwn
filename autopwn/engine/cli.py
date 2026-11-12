"""命令行入口：

    python -m autopwn.engine.cli bench/            # 跑整个目录
    python -m autopwn.engine.cli bench/ch01_note   # 单题
    python -m autopwn.engine.cli bench/ch13 --libc path/to/libc.so.6
"""
from __future__ import annotations

import argparse
import os
import sys

from .model import Challenge
from .orchestrator import solve, solve_many


def _collect(target: str) -> list[str]:
    if os.path.isfile(target):
        return [target]
    if os.path.exists(os.path.join(target, "bin")):
        return [target]
    out = []
    for name in sorted(os.listdir(target)):
        if name.startswith("."):
            continue
        d = os.path.join(target, name)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "bin")):
            out.append(d)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="autopwn.engine")
    ap.add_argument("target", help="题目目录 / 二进制 / 含多题的父目录")
    ap.add_argument("--libc", default=None)
    ap.add_argument("--ld", default=None)
    ap.add_argument("--host", default=None, help="远程地址（配合 --port 使用）")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--max-attempts", type=int, default=80)
    ap.add_argument("--budget", type=float, default=240.0, help="单题时间预算（秒）")
    ap.add_argument("--facts-only", action="store_true", help="只打印静态事实，不执行利用")
    ap.add_argument("--out", default="results")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    targets = _collect(args.target)
    if not targets:
        print("no challenge found", file=sys.stderr)
        return 2

    only = targets[0]
    results = []
    for t in targets:
        ch = Challenge(t, libc=args.libc, ld=args.ld,
                       host=args.host, port=args.port)
        print(f"[*] {ch.name}: {ch.bin_src}")
        if args.facts_only:
            from .facts import analyse
            ch.prepare()
            f = analyse(ch)
            print(f"    prot   : {ch.prot}")
            print(f"    libc   : {ch.libc_path}")
            print(f"    vulns  : {[str(v) for v in f.vulns]}")
            print(f"    wins   : {[str(w) for w in f.wins]}")
            print(f"    binsh  : {hex(f.binsh) if f.binsh else None}")
            print(f"    gadgets: {{{', '.join(f'{k}: {hex(v)}' for k, v in f.gadgets.items())}}}")
            print(f"    csu    : {f.csu}")
            print(f"    mmapRX : {hex(f.mmap_rwx) if f.mmap_rwx else None}")
            print(f"    fmtbuf : {f.fmt_buf}")
            continue
        res = solve(ch, max_attempts=args.max_attempts,
                    budget=args.budget, verbose=not args.quiet)
        results.append(res)
        status = "SHELL" if (res.ok and not res.flag_only) else ("FLAG-ONLY" if res.ok else "FAILED")
        print(f"    => {status} {res.strategy} "
              f"{res.detail} ({res.elapsed:.1f}s / {len(res.attempts)} attempts)")
        os.makedirs(args.out, exist_ok=True)
        import json
        with open(os.path.join(args.out, f"{ch.name}.json"), "w", encoding="utf-8") as fh:
            json.dump(res.as_dict(), fh, ensure_ascii=False, indent=2)

    shell = sum(1 for r in results if r.ok and not r.flag_only)
    flag = sum(1 for r in results if r.ok and r.flag_only)
    if not results:
        return 0
    print(f"\n=== {shell}/{len(results)} shell, {flag} flag-only ===")
    for r in results:
        mark = "✓" if (r.ok and not r.flag_only) else ("⚑" if r.ok else "✗")
        print(f"  {mark} {r.name:<24} {r.strategy:<14} {r.detail[:70]}")
    return 0 if shell else 1


if __name__ == "__main__":
    raise SystemExit(main())
