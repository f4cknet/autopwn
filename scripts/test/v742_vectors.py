#!/usr/bin/env python3
"""v7.4.2 合成向量（A 数字菜单 / B 全局写→win / C1 静态事实 / D shell 判据）。

在容器内运行，用 x64 gcc 现场编译小程序到临时目录（不落库、不新增 bench 题）。
本镜像没有 32 位 crt 与 i386 libc.a，**不使用 -m32**；C1 的 32 位样本用
`solve.bat bench/ch10_static32 --facts-only` 兜底（见 bench/RESULTS.md §18）。

    docker run --rm -v "$PWD:/work" -w /work autopwn:pwn22 \
        python3 scripts/test/v742_vectors.py

A 的真样本命中由验证方下轮盲测确认；本脚本只证明判据在合成形态上成立。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from autopwn.engine.facts import (  # noqa: E402
    Dis, _func_entries, _static_sym, _static_vulns, _win_kind, analyse,
)
from autopwn.engine.model import Challenge  # noqa: E402
from autopwn.engine.orchestrator import solve  # noqa: E402
from autopwn.engine.strategies import s_global_write_win  # noqa: E402

# -no-pie 让 win 地址在 facts 里是绝对地址；容器内 x64 gcc 可用。
GCC = ["gcc", "-O0", "-fno-stack-protector", "-no-pie", "-Wl,-z,norelro"]

_pass = 0
_fail = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _pass, _fail
    if cond:
        _pass += 1
        print(f"  ok   {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f"\n       {detail}" if detail else ""))


def build(tmp: str, name: str, src: str, extra: tuple = ()) -> Challenge:
    d = os.path.join(tmp, name)
    os.makedirs(d, exist_ok=True)
    cpath = os.path.join(d, "t.c")
    with open(cpath, "w", encoding="utf-8") as fh:
        fh.write(src)
    exe = os.path.join(d, "chall")
    cmd = GCC + list(extra) + ["-o", exe, cpath]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"gcc failed: {' '.join(cmd)}\n{proc.stderr[-800:]}")
    ch = Challenge(exe)
    ch.prepare()
    return ch


# --------------------------------------------------------------------------- D
def test_win_kind() -> None:
    print("[D] shell 路径合法性（_win_kind）")
    pos = ("sh", "/bin/sh", "/bin//sh", "/usr/bin/sh")
    for t in pos:
        check(f"D shell  {t!r}", _win_kind(t) == "shell", f"got {_win_kind(t)!r}")
    for t in ("fish", "push", "C:\\foo\\sh", "/bbbb?/sh"):
        check(f"D reject {t!r}", _win_kind(t) is None, f"got {_win_kind(t)!r}")
    check("D /bin/sh -c id 不算 shell",
          _win_kind("/bin/sh -c id") != "shell", f"got {_win_kind('/bin/sh -c id')!r}")
    check("D cat /flag 仍算 flag", _win_kind("cat /flag") == "flag")
    check("D echo flag 仍算诱饵", _win_kind("echo flag") == "decoy")


# --------------------------------------------------------------------------- A
A_INLINE = r"""
#include <stdio.h>
#include <stdlib.h>
void secret(void) { puts("PWNED_42"); }
int main(void) {
    int c = 0;
    puts("1.Encrypt\n2.Decrypt\n3.Exit");
    scanf("%d", &c);
    if (c == 1) secret();
    else if (c == 2) puts("decrypt");
    return 0;
}
"""

A_HELPER = r"""
#include <stdio.h>
#include <stdlib.h>
void secret(void) { puts("PWNED_42"); }
static void menu(void) {
    int c = 0;
    puts("1.Add\n2.Delete\n3.Quit");
    scanf("%d", &c);
    switch (c) { case 1: secret(); break; case 2: puts("del"); break; }
}
int main(void) { menu(); return 0; }
"""

A_READ_ATOI = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void secret(void) { puts("PWNED_42"); }
int main(void) {
    char b[16];
    puts("1.Encrypt\n2.Decrypt\n3.Exit");
    read(0, b, sizeof(b));
    int c = atoi(b);
    if (c == 1) secret();
    else if (c == 2) puts("decrypt");
    return 0;
}
"""

A_NEG_LEN = r"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int n = 0;
    printf("Length: ");
    scanf("%d", &n);
    if (n > 100) puts("too long");
    else if (n < 50) puts("too short");
    return 0;
}
"""

A_NEG_BANNER = r"""
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int n = 0;
    puts("1.Encrypt\n2.Decrypt\n3.Exit");
    scanf("%d", &n);              /* 编号横幅 + 输入，但输入是长度不是分派 */
    if (n > 100) puts("too long");
    else if (n < 50) puts("too short");
    return 0;
}
"""


def _menu_hit(ch: Challenge) -> tuple:
    f = analyse(ch)
    cands = [c for v in f.interact.values() for c in v]
    return f, (b"1\n" in cands), f.interact


def test_menu(tmp: str) -> None:
    print("[A] 数字菜单判据")
    cases = (
        ("a_inline", A_INLINE, "内联 scanf(%d) 菜单"),
        ("a_helper", A_HELPER, "helper 读选择 + 分派"),
        ("a_read_atoi", A_READ_ATOI, "read + atoi 菜单"),
    )
    for name, src, label in cases:
        ch = build(tmp, name, src)
        f, hit, interact = _menu_hit(ch)
        check(f"A hit  {label}", hit,
              f"interact={ {hex(k): v for k, v in interact.items()} } "
              f"unknowns={f.unknowns}")
    for name, src, label in (
        ("a_neg_len", A_NEG_LEN, "长度输入无横幅"),
        ("a_neg_banner", A_NEG_BANNER, "有横幅但无小常数分派"),
    ):
        ch = build(tmp, name, src)
        f, _hit, interact = _menu_hit(ch)
        check(f"A miss {label}", not interact,
              f"interact={ {hex(k): v for k, v in interact.items()} }")


# --------------------------------------------------------------------------- B
B_GLOBAL = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct state { char buf[64]; void (*fn)(void); } g;
void hello(void) { puts("hello"); }
void win(void) { system("/bin/sh"); }
int main(void) {
    g.fn = hello;
    puts("1.Hello\n2.Exit");
    fgets(g.buf, 128, stdin);
    g.fn();
    return 0;
}
"""


def test_global_write(tmp: str) -> None:
    print("[B] 全局写 -> 覆盖全局函数指针 -> win")
    ch = build(tmp, "b_global", B_GLOBAL)
    f = analyse(ch)
    check("B global_writes 非空", bool(f.global_writes), repr(f.global_writes))
    check("B global_calls 非空", bool(f.global_calls), repr(f.global_calls))
    win = f.shell_win
    check("B shell win 识别", win is not None and win.kind == "shell",
          f"wins={[str(w) for w in f.wins]}")
    plans = list(s_global_write_win(ch, f))
    check("B 策略产出计划", bool(plans), f"writes={f.global_writes} calls={f.global_calls}")
    if plans and win is not None:
        raw = win.addr.to_bytes(ch.wordsize, "little")
        payload = plans[0].steps[-1].data
        check("B payload 末字 = win.addr", payload.endswith(raw + b"\n"),
              f"payload_tail={payload[-16:]!r} raw={raw!r}")
    else:
        raw = b""
    res = solve(ch, max_attempts=12, budget=40.0, verbose=False)
    out = b"".join(a.output for a in res.attempts)
    check("B 端到端 PWNED_42", res.ok and b"PWNED_42" in out,
          f"ok={res.ok} strategy={res.strategy} detail={res.detail} "
          f"tail={out[-200:]!r}")
    check("B 成功来自 global_write_win", res.strategy == "global_write_win",
          f"strategy={res.strategy} raw={raw!r}")


# --------------------------------------------------------------------------- C1
C_STATIC = r"""
#include <stdio.h>
#include <stdlib.h>
void win(void) { system("/bin/sh"); }
int main(void) {
    char buf[64];
    puts("input:");
    fgets(buf, 200, stdin);
    if (buf[0] == 'x') win();
    return 0;
}
"""


def test_static(tmp: str) -> None:
    print("[C1] 静态事实（x64 -static；32 位样本用 ch10_static32 兜底）")
    ch = build(tmp, "c1_static", C_STATIC, extra=("-static",))
    check("C1 识别 static", bool(ch.prot.static), str(ch.prot))
    check("C1 无 PLT", not ch.plt_map, f"plt={list(ch.plt_map)[:5]}")
    f = analyse(ch)
    sink_unknown = f.unknowns.get("sink", "")
    check("C1 不再报 PLT 映射为空", "PLT 映射为空" not in sink_unknown,
          f"unknowns={f.unknowns}")
    check("C1 analyse 有 vuln", bool(f.vulns), f"unknowns={f.unknowns}")
    d = Dis(ch)
    entries = _func_entries(ch, d)
    vs = _static_vulns(ch, d, entries)
    check("C1 _static_vulns 符号直呼命中",
          any(v.sink == "fgets" and v.offset is not None for v in vs),
          f"vulns={[str(v) for v in vs]}")
    if _static_sym(ch, "system"):
        check("C1 静态 shell win 识别",
              any(w.kind == "shell" for w in f.wins),
              f"wins={[str(w) for w in f.wins]}")
    else:
        print("  info 静态镜像无 system 符号，跳过静态 win 断言")


# --------------------------------------------------------------------------- main
def main() -> int:
    if not shutil.which("gcc"):
        print("SKIP: gcc not found (run inside the autopwn container)")
        return 0
    tmp = tempfile.mkdtemp(prefix="v742_")
    try:
        test_win_kind()
        test_menu(tmp)
        test_global_write(tmp)
        test_static(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n=== v7.4.2 vectors: {_pass} passed, {_fail} failed ===")
    return 1 if _fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
