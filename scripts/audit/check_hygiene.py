#!/usr/bin/env python3
"""仓库卫生检查 —— 把「主目录清洁」从口头约定变成可执行门禁。

用法（在仓库根目录或任意位置运行均可）：

    py -3 scripts/audit/check_hygiene.py      # Windows 本机（python 是 pyenv shim）
    python3 scripts/audit/check_hygiene.py    # 容器内

退出码：
    0 = 干净
    1 = 有问题（详见输出）

检查项：
    1. 根目录白名单：出现白名单外的条目
    2. 临时文件残留：dbg_*/bf*/probe_*/*.tmp/*.bak/*~/*.log 等
    3. 运行产物误入库：results/ 下除 remote/FLAGS.md 外被 git 跟踪
    4. 构建产物：build/、*.egg-info/、__pycache__/、.pytest_cache/
    5. 大文件：单文件 > 8 MB 且被 git 跟踪（防止再塞反汇编导出）

设计原则：只报「确定是垃圾」的东西，不猜。误报比漏报更烦人。
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# 根目录允许出现的条目（目录以 / 结尾便于阅读，比较时去掉）
ALLOWED_ROOT = {
    # 代码
    "autopwn", "docker", "scripts", "tests",
    # 题库
    "bench", "bench_extra", "bench_sys", "chellenges", "Challenge", "holdout",
    # 资料
    "bugs", "upgraded", "archive", "writeups", "results", "_target",
    # Windows 入口
    "solve.bat", "target.bat", "build_pwn.bat", "shell.bat",
    # 文档
    "README.md", "CLAUDE.md", "AGENTS.md", "HANDOVER.md",
    "ARCHITECTURE.md", "PROGRESS.md", "CHEATSHEET.md", "DOC_MAP.md", "upgraded.md",
    # 工程文件
    "LICENSE", "pyproject.toml", "requirements.txt", "setup.py",
    ".gitignore", ".gitattributes", ".venv", ".github", ".coveragerc",
    ".python-version", ".git",
    # Claude Code 本地配置（settings.local.json 已在 .gitignore，不入库）
    ".claude",
    # Agent 工作区记忆（本项目数据，非临时缓存；已在 .gitignore，不入库）
    ".workbuddy",
}

# 根目录里出现即算违规的临时文件特征
TEMP_PATTERNS = (
    "dbg_", "bf_", "probe_", "tmp_", "_t.", "batout", "run_all.log", "run_verify.out",
)
TEMP_SUFFIX = (".tmp", ".bak", "~", ".log", ".orig", ".rej", ".swp", ".docx.tmp")

BUILD_DIRS = ("build", "dist", ".pytest_cache", "__pycache__", "autopwn.egg-info")
MAX_TRACKED_BYTES = 8 * 1024 * 1024


def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=60
        ).stdout
    except Exception:
        return ""


def _allowed(name: str) -> bool:
    """白名单匹配：固定名 + 引擎运行时目录（.run / .<name>.run）。"""
    if name in ALLOWED_ROOT:
        return True
    # 引擎为裸二进制创建的运行副本目录：.run/ 或 .note.run/
    if name == ".run" or (name.startswith(".") and name.endswith(".run")):
        return True
    return False


def check_root() -> list[str]:
    bad = []
    for entry in sorted(ROOT.iterdir()):
        name = entry.name
        if _allowed(name):
            continue
        hint = "（看起来是测试/调试脚本 → 移到 scripts/test/）" if name.endswith(".py") else ""
        bad.append(f"根目录多余条目：{name}{hint}")
    return bad


def check_temp() -> list[str]:
    bad = []
    for entry in sorted(ROOT.iterdir()):
        n = entry.name
        if _allowed(n):
            continue
        low = n.lower()
        if any(p in low for p in TEMP_PATTERNS) or low.endswith(TEMP_SUFFIX):
            bad.append(f"临时文件残留：{n}（用完应删除）")
    # 子目录里的调试脚本（排除 archive / .venv / tests）
    for pat in ("docker/dbg_*.py", "docker/bf*.py", "docker/probe_*.py", "scripts/dbg_*.py"):
        for p in ROOT.glob(pat):
            bad.append(f"调试脚本未清理：{p.relative_to(ROOT)}（提交前删除或移入 scripts/audit/）")
    return bad


def check_results() -> list[str]:
    tracked = [f for f in git("ls-files", "results").splitlines() if f.strip()]
    bad = [f"运行产物误入库：{f}" for f in tracked if not f.endswith("remote/FLAGS.md")]
    return bad


def check_build() -> list[str]:
    bad = []
    for d in BUILD_DIRS:
        p = ROOT / d
        if p.exists():
            bad.append(f"构建产物存在：{d}/（应由 .gitignore 覆盖，删除即可）")
    return bad


def check_big_tracked() -> list[str]:
    bad = []
    for f in git("ls-files").splitlines():
        if not f.strip():
            continue
        p = ROOT / f
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size > MAX_TRACKED_BYTES:
            bad.append(f"版本库内大文件：{f} ({size / 1024 / 1024:.1f} MB) —— 确认是否该入库")
    return bad


def main() -> int:
    groups = [
        ("1. 根目录白名单", check_root()),
        ("2. 临时文件", check_temp()),
        ("3. 运行产物", check_results()),
        ("4. 构建产物", check_build()),
        ("5. 大文件", check_big_tracked()),
    ]
    problems = sum((g[1] for g in groups), [])
    for title, items in groups:
        mark = "OK " if not items else "FAIL"
        print(f"[{mark}] {title}")
        for it in items:
            print(f"        - {it}")
    print()
    if problems:
        print(f"共 {len(problems)} 个问题。修完再提交（规则见 CLAUDE.md「工作纪律」）。")
        return 1
    print("仓库干净。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
