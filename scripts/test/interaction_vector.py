#!/usr/bin/env python3
"""v7.0.1 交互层回归向量：Send / Wait / Interaction。

在容器内运行（导入 autopwn.engine 会拉 pwntools）：

    python3 scripts/test/interaction_vector.py

覆盖：
  1) FakeTube 单元检查（跨 chunk、重复 prompt、静默屏障、超时、EOF、Send 失败）
  2) Send→Wait 不自动读 / Send→Send 仍同步
  3) Plan 兼容（steps 归一化、sends / last_send）
  4) run.execute 的错误路径（Wait 超时不抛、只发前置 Send、Send 死亡不抛）
  5) 真实 C 菜单程序：Wait(prompt) 驱动三段交互，断言 PWNED_42
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    import pwn  # noqa: F401
except Exception as exc:                      # 宿主机通常没有 pwntools
    print(f"SKIP: pwntools unavailable ({exc}); run inside autopwn:pwn22")
    raise SystemExit(0)

from autopwn.engine import run as R
from autopwn.engine import strategies as S
from autopwn.engine.interact import (
    Interaction, Send, Wait, StepError, WaitTimeout, normalize_steps,
)
from autopwn.engine.oracle import judge_shell, judge_flag, SHELL_MARKER

FAILS: list[str] = []


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILS.append(name)
        print(f"[FAIL] {name}")
        traceback.print_exc()
    else:
        print(f"[PASS] {name}")


class FakeTube:
    """按队列吐 chunk 的最小 tube；recvrepeat 不等待（超时由 deadline 控制）。"""

    def __init__(self, chunks=(), alive=True, send_error=None):
        self.chunks = list(chunks)
        self.alive = alive
        self.send_error = send_error
        self.sent: list[bytes] = []
        self.reads = 0

    def send(self, data):
        if self.send_error:
            raise self.send_error
        self.sent.append(data)

    def recvrepeat(self, timeout):
        self.reads += 1
        return self.chunks.pop(0) if self.chunks else b""

    def connected(self):
        return self.alive


class FakeCh:
    host = None


# --------------------------------------------------------------------- 单元
def t_cross_chunk():
    tube = FakeTube([b"hel", b"lo cmd", b"> rest"])
    it = Interaction(tube, needle_timeout=1.0)
    it.wait_for(b"cmd> ")
    assert it.buf == b"hello cmd> rest", it.buf


def t_two_prompts_cursor():
    tube = FakeTube([b"cmd> cmd> "])
    it = Interaction(tube, needle_timeout=1.0)
    assert it.wait_for(b"cmd> ") == b"cmd> "
    assert it.wait_for(b"cmd> ") == b"cmd> "   # 第二个不再匹配第一个
    assert it.pos == len(b"cmd> cmd> ")


def t_silence_barrier():
    tube = FakeTube([b"old cmd> ", b"", b"new cmd> "])
    it = Interaction(tube, silence_timeout=0.2, needle_timeout=1.0)
    it.wait_for(b"")                           # 静默屏障：旧输出视为已消费
    it.wait_for(b"new cmd> ")
    assert it.buf == b"old cmd> new cmd> "


def t_wait_timeout_partial():
    tube = FakeTube([b"banner"], alive=True)
    it = Interaction(tube, needle_timeout=0.2)
    it.read(0.01)
    t0 = time.time()
    try:
        it.wait_for(b"never> ")
    except WaitTimeout as exc:
        assert exc.partial == b"banner", exc.partial
        assert time.time() - t0 < 1.0
    else:
        raise AssertionError("expected WaitTimeout")


def t_eof_fast_fail():
    it = Interaction(FakeTube([], alive=False), needle_timeout=5.0)
    t0 = time.time()
    try:
        it.wait_for(b"x")
    except WaitTimeout:
        assert time.time() - t0 < 0.5, time.time() - t0
    else:
        raise AssertionError("expected WaitTimeout")


def t_wait_owns_boundary():
    tube = FakeTube([b"x", b""])
    it = Interaction(tube, needle_timeout=1.0)
    it.run_steps([Send(b"A"), Wait(b"x")], final_sleep=0, final_read=0)
    assert tube.sent == [b"A"]
    # 若 Wait 前先做隐式 sync，会多消费一个 b"" → reads == 2
    assert tube.reads == 1, tube.reads


def t_send_send_sync():
    tube = FakeTube([b"x", b""])
    it = Interaction(tube)
    it.run_steps([Send(b"A"), Send(b"B")], final_sleep=0, final_read=0)
    assert tube.sent == [b"A", b"B"]
    assert tube.reads == 2, tube.reads


def t_send_error():
    it = Interaction(FakeTube(send_error=BrokenPipeError("gone")))
    try:
        it.run_steps([Send(b"A")], final_sleep=0, final_read=0)
    except StepError as exc:
        assert "send failed" in str(exc)
    else:
        raise AssertionError("expected StepError")


# --------------------------------------------------------------------- Oracle
def t_judge_shell():
    v = judge_shell(b"banner\n" + b"PWNED_42\nuid=0(root)\n")
    assert v.ok and v.kind == "shell" and v.cause == "marker", v
    v2 = judge_shell(b"uid=1000(ctf) gid=1000")
    assert v2.ok and v2.cause == "uid" and "ctf" in v2.detail, v2
    v3 = judge_shell(b"no shell here")
    assert not v3.ok and v3.cause == "no_match"


def t_judge_flag_priority():
    # 真 flag 优先于 win reached
    v = judge_flag(b"cat: /flag: No such file\nflag{real_one_42}\n")
    assert v.ok and v.cause == "flag_re" and "flag{real_one_42}" in v.detail, v
    # 只有报错 → win reached（链路成立）
    v2 = judge_flag(b"cat: /flag: No such file or directory")
    assert v2.ok and v2.cause == "no_flag_file" and "win reached" in v2.detail, v2
    # 累积输出里早到的 flag（最后一段没有）也必须判到
    v3 = judge_flag(b"flag{early_arrival}" + b"\nmenu> " * 5)
    assert v3.ok and "flag{early_arrival}" in v3.detail, v3
    # 普通 {} 文本不是 flag
    v4 = judge_flag(b"set {a,b,c} done")
    assert not v4.ok, v4
    # 大小写变体
    assert judge_flag(b"CTF2{docker-local-target}").ok
    assert judge_flag(b"FLAG{UpperCase}").ok


# --------------------------------------------------------------------- Plan
def t_plan_normalize():
    p = S.Plan("x", [b"", b"a", Send(b"b"), Wait()])
    assert len(p.steps) == 3, p.steps
    assert p.sends == [b"a", b"b"], p.sends
    assert p.last_send == b"b"
    p2 = S.Plan("x", [b""])
    assert p2.steps == [] and p2.sends == [] and p2.last_send == b""


def t_normalize_rejects_bad_type():
    try:
        normalize_steps([b"a", 123])
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")


# --------------------------------------------------------------------- 引擎
def t_execute_wait_timeout():
    tube = FakeTube([], alive=True)
    old = R.spawn
    R.spawn = lambda ch: tube
    try:
        r = R.execute(FakeCh(), [Send(b"A"), Wait(b"never> ", timeout=0.2)],
                      verify=False)
    finally:
        R.spawn = old
    assert r.ok is False
    assert "timeout" in r.error, r.error
    assert tube.sent == [b"A"], tube.sent


def t_execute_send_death():
    tube = FakeTube(send_error=BrokenPipeError("closed"))
    old = R.spawn
    R.spawn = lambda ch: tube
    try:
        r = R.execute(FakeCh(), [Send(b"A")], verify=False)
    finally:
        R.spawn = old
    assert r.ok is False
    assert "send failed" in r.error, r.error


# --------------------------------------------------------------------- 真实进程
C_SOURCE = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char eaten[8], choice[8], data[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    write(1, "menu> ", 6);
    read(0, eaten, sizeof(eaten));          /* 吞掉提前发送的输入 */
    write(1, "choice> ", 8);
    read(0, choice, sizeof(choice));
    if (choice[0] != 'w') {
        write(1, "bye\n", 4);
        return 0;
    }
    write(1, "data> ", 6);
    read(0, data, sizeof(data));
    if (strncmp(data, "PWNED", 5) == 0)
        write(1, "PWNED_42\n", 9);
    else
        write(1, "nope\n", 5);
    return 0;
}
"""


def t_real_menu_program():
    if not shutil.which("gcc"):
        print("  [SKIP] gcc missing, real-process check skipped")
        return
    tmp = tempfile.mkdtemp(prefix="autopwn-vec-")
    src = os.path.join(tmp, "menu.c")
    exe = os.path.join(tmp, "menu")
    try:
        with open(src, "w", encoding="utf-8") as fh:
            fh.write(C_SOURCE)
        subprocess.run(["gcc", "-O0", "-o", exe, src], check=True)

        from pwn import context, process
        context.log_level = "error"
        env = dict(os.environ)
        env.setdefault("TERM", "xterm")
        env["PWNLIB_NOTERM"] = "1"
        p = process([exe], env=env)
        try:
            it = Interaction(p, needle_timeout=3.0)
            it.run_steps([
                Wait(b"menu> "), Send(b"w\n"),
                Wait(b"choice> "), Send(b"w\n"),
                Wait(b"data> "), Send(b"PWNED\n"),
            ], final_sleep=0.2, final_read=0.2)
            assert b"PWNED_42" in it.buf, it.buf
        finally:
            p.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


TESTS = [
    ("judge_shell marker/uid/no-match", t_judge_shell),
    ("judge_flag priority & cumulative", t_judge_flag_priority),
    ("cross-chunk Wait", t_cross_chunk),
    ("repeated prompt cursor", t_two_prompts_cursor),
    ("silence barrier consumes old output", t_silence_barrier),
    ("Wait timeout carries partial output", t_wait_timeout_partial),
    ("EOF fails fast", t_eof_fast_fail),
    ("Send->Wait does not auto-read", t_wait_owns_boundary),
    ("Send->Send still syncs", t_send_send_sync),
    ("Send failure becomes StepError", t_send_error),
    ("Plan steps normalization", t_plan_normalize),
    ("normalize_steps rejects bad type", t_normalize_rejects_bad_type),
    ("run.execute Wait timeout -> Result", t_execute_wait_timeout),
    ("run.execute Send death -> Result", t_execute_send_death),
    ("real C menu program", t_real_menu_program),
]


def main() -> int:
    for name, fn in TESTS:
        check(name, fn)
    print()
    if FAILS:
        print(f"FAILED {len(FAILS)}/{len(TESTS)}: {', '.join(FAILS)}")
        return 1
    print(f"OK {len(TESTS)}/{len(TESTS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
