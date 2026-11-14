"""L3 判定层：成功与否只有这一份实现。

判据铁律（CLAUDE.md / HANDOVER.md）：
  SHELL = 目标进程里真执行了命令（PWNED_42 回显 / uid= 出现）；
  FLAG  = 输出里出现 flag{...} / CTF{...}；
  FILE  = 打到了 win 但本地没有 flag 文件（No such file 等）——链路成立的证据，如实标注。

判定函数是纯函数（不读 tube、不做 I/O）：喂它累积输出，返回 Verdict。
读多少、何时停的时序仍在 run.py。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SHELL_MARKER = b"PWNED_42"

FLAG_RE = re.compile(rb"(?:flag|ctf|FLAG|CTF)[A-Za-z0-9_]{0,20}\{[^}\n]{4,}\}")
# 打到 win 但本地没 flag 文件：system("cat flag") 的报错就是「链路通了」的证据
NO_FILE_RE = re.compile(rb"No such file|Permission denied|unavailable|cat: ")

UID_RE = re.compile(rb"uid=\d+\([^)]*\)")


@dataclass
class Verdict:
    ok: bool
    kind: str          # "shell" | "flag" | "file" | "gate" | "win" | "none"
    cause: str         # marker | uid | flag_re | no_flag_file | gate_passed | win_executed | no_match
    detail: str = ""   # 命中的 flag / uid 串（拼接进 note 用）


def judge_shell(out: bytes) -> Verdict:
    """对累积输出判「拿到 shell」。"""
    if SHELL_MARKER in out:
        return Verdict(True, "shell", "marker", SHELL_MARKER.decode())
    m = UID_RE.search(out)
    if m:
        return Verdict(True, "shell", "uid", m.group(0).decode("latin-1", "replace"))
    return Verdict(False, "none", "no_match")


def judge_gate(out: bytes, marker: bytes = b"") -> Verdict:
    """门控通过：**证据态，不是成功**（`ok=False`，不参与 shell/flag 记账）。

    只认调用方从静态事实里拿到的门控串（如 434c 的 `good job!!`）；
    程序随机输出/提示语不算。门控通过后是否真执行了命令，由调用方
    继续交给 judge_shell 判（A3）。
    """
    if marker and marker in out:
        return Verdict(False, "gate", "gate_passed",
                       "gate passed: " + marker.decode("latin-1", "replace").strip())
    return Verdict(False, "none", "no_match")


def judge_win_executed(out: bytes, marker: bytes = b"") -> Verdict:
    """诱饵 win 真的被执行：**证据态，不是成功**（`ok=False`）。

    只证明控制流到达 win（如 `system("echo flag")` 的回显），不产出 flag；
    不参与 shell/flag 记账。
    """
    if marker and marker in out:
        return Verdict(False, "win", "win_executed",
                       "win executed: " + marker.decode("latin-1", "replace").strip())
    return Verdict(False, "none", "no_match")


def judge_flag(out: bytes) -> Verdict:
    """对累积输出判「拿到 flag」；真 flag 优先于 win reached。"""
    m = FLAG_RE.search(out)
    if m:
        return Verdict(True, "flag", "flag_re",
                       "flag:" + m.group(0).decode("latin-1", "replace"))
    if NO_FILE_RE.search(out):
        return Verdict(True, "file", "no_flag_file", "win reached (no flag file)")
    return Verdict(False, "none", "no_match")
