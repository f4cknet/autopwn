#!/usr/bin/env python3
"""多 agent 迭代的裁决器：唯一有权决定「合入 / 回滚 / 停止」的地方。

设计约束（不要改）：
  * **纯 Python，不调用任何 LLM**。Agent 的话不是判据，只有 state/last.json 是。
  * 评测由本脚本调用冻结的 eval/run_eval.py 完成；Agent 不得参与打分。
  * 判据哈希（oracle.py / run_eval.py）每轮校验，变了立刻 abort。

一轮 = impl 改代码 → commit 到 dev → 本脚本跑评测 → 判定 → 合入或回滚。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

BASE = {"bench": 13, "bench_extra": 6, "bench_sys": 4, "bench_extra_flag": 1}


def sh(cmd, cwd=None, check=True):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {p.stderr[-500:]}")
    return p


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def run_agent(prompt_file: str, workdir: str, max_turns: int, tag: str):
    """跑一个 headless agent 轮次。返回 returncode。"""
    with open(prompt_file, encoding="utf-8") as fh:
        prompt = fh.read()
    log = os.path.join(workdir, "..", "logs", f"{tag}-{int(time.time())}.json")
    os.makedirs(os.path.dirname(log), exist_ok=True)
    with open(log, "w", encoding="utf-8") as fh:
        p = subprocess.run(
            ["claude", "-p", prompt,
             "--output-format", "json",
             "--max-turns", str(max_turns),
             "--dangerously-skip-permissions"],
            cwd=workdir, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return p.returncode


def guarantees_ok(cur: dict, best: dict) -> tuple[bool, str]:
    """四道锁。返回 (是否通过, 原因)。"""
    if cur.get("oracle_sha") != best.get("oracle_sha"):
        return False, "判据被改：oracle.py sha 变化"
    s = cur.get("suites", {})
    for k, need in (("bench", BASE["bench"]),
                    ("bench_extra", BASE["bench_extra"]),
                    ("bench_sys", BASE["bench_sys"])):
        got = s.get(k, {}).get("shell", -1)
        if got < need:
            return False, f"回归掉分：{k} {got} < {need}"
    if s.get("bench_extra", {}).get("flag_only", 0) < BASE["bench_extra_flag"]:
        return False, "回归掉分：bench_extra flag-only 减少"
    if cur.get("brute_attempts", 0) != 0:
        return False, "出现盲试：brute_attempts != 0"
    return True, "ok"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="impl 仓库")
    ap.add_argument("--state", required=True, help="state 目录")
    ap.add_argument("--eval", dest="eval_py", required=True, help="冻结的 run_eval.py")
    ap.add_argument("--prompt-impl", required=True)
    ap.add_argument("--prompt-verify", required=True)
    ap.add_argument("--dev", default="dev")
    ap.add_argument("--target", type=float, default=0.7)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--max-hours", type=float, default=8.0)
    ap.add_argument("--max-turns", type=int, default=80)
    args = ap.parse_args(argv)

    last_json = os.path.join(args.state, "last.json")
    best_json = os.path.join(args.state, "best.json")
    hist = os.path.join(args.state, "history.jsonl")
    t0 = time.time()
    no_gain = 0

    def evaluate(tag: str) -> dict:
        sh([sys.executable, args.eval_py, "--root", args.root,
            "--dev", args.dev, "--out", last_json], check=False)
        return load(last_json, {}) or {}

    best = load(best_json)
    if not best:
        sh(["git", "-C", args.root, "checkout", "dev"])
        best = evaluate("baseline")
        dump(best_json, best)
        print(f"[base] dev_rate={best.get('dev_rate')} suites={ {k: v.get('shell') for k, v in best.get('suites', {}).items()} }")

    for rnd in range(1, args.rounds + 1):
        if (time.time() - t0) / 3600 > args.max_hours:
            dump(os.path.join(args.state, "ALERT"),
                 {"reason": "MAX_HOURS", "round": rnd})
            break

        before = sh(["git", "-C", args.root, "rev-parse", "HEAD"]).stdout.strip()

        # 1) 实施
        rc = run_agent(args.prompt_impl, args.root, args.max_turns, f"impl-{rnd}")
        head = sh(["git", "-C", args.root, "rev-parse", "HEAD"]).stdout.strip()
        if head == before:
            print(f"[{rnd}] impl 无提交，停")
            break

        # 2) 评测（脚本执行，agent 不参与）
        cur = evaluate(f"round-{rnd}")

        # 3) 判定
        ok, why = guarantees_ok(cur, best)
        improved = cur.get("dev_rate", 0) > best.get("dev_rate", 0)

        # 4) verify 只写归因，不改数字
        run_agent(args.prompt_verify, args.root, 20, f"verify-{rnd}")

        record = {"round": rnd, "dev_rate": cur.get("dev_rate"),
                  "suites": {k: v.get("shell") for k, v in cur.get("suites", {}).items()},
                  "ok": ok, "why": why, "improved": improved, "head": head}
        with open(hist, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(json.dumps(record, ensure_ascii=False))

        if ok and improved:
            sh(["git", "-C", args.root, "checkout", "main"])
            sh(["git", "-C", args.root, "merge", "--no-ff", "-m",
                f"merge v-autoloop round {rnd}", "dev"])
            sh(["git", "-C", args.root, "checkout", "dev"])
            best = cur
            dump(best_json, best)
            no_gain = 0
        else:
            sh(["git", "-C", args.root, "reset", "--hard", before])
            no_gain += 1
            if no_gain >= 2:
                dump(os.path.join(args.state, "ALERT"),
                     {"reason": "2 rounds no gain", "round": rnd, "why": why})
                break

        if cur.get("dev_rate", 0) >= args.target:
            dump(os.path.join(args.state, "DONE"),
                 {"round": rnd, "dev_rate": cur["dev_rate"]})
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
