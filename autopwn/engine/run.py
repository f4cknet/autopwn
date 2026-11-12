"""进程交互与 shell 验证。

成功判据只有一条：payload 之后能在目标进程里执行 `whoami` 并看到用户名
（或 `echo PWNED_$((6*7))` 回显 PWNED_42）。任何「看起来没报错」都不算成功。
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from pwn import context, process

from .model import Challenge

MARKER = b"PWNED_42"
PROBE = (b"echo PWNED_$((6*7))", b"whoami", b"id")


@dataclass
class Result:
    ok: bool
    output: bytes = b""
    note: str = ""
    error: str = ""


def _env(ch: Challenge) -> dict:
    env = dict(os.environ)
    env.setdefault("TERM", "xterm")
    env["PWNLIB_NOTERM"] = "1"
    return env


def spawn(ch: Challenge):
    context.log_level = "error"
    if ch.host:
        from pwn import remote
        return remote(ch.host, ch.port, timeout=5)
    # 不显式传 stdin/stdout/stderr：pwnlib 默认给三者共用同一个 PTY，
    # 显式传 -1 会把子进程 stdout 接到父进程，tube 里读不到任何输出。
    return process([ch.run_bin], cwd=ch.dir, env=_env(ch))


def run_capture(ch: Challenge, stdin_data: bytes = b"", timeout: float = 2.0) -> bytes:
    """跑一次拿输出（用于探测提示语/程序行为），不管它死活。"""
    try:
        p = spawn(ch)
    except Exception:
        return b""
    try:
        if stdin_data:
            p.send(stdin_data)
        out = p.recvrepeat(timeout)
        return out or b""
    except Exception:
        return b""
    finally:
        try:
            p.close()
        except Exception:
            pass


def verify_shell(p, wait: float = 0.45) -> Result:
    """在有 shell 的前提下探测；返回是否拿到 shell 与回显。"""
    out = b""
    try:
        # PTY 规范模式下 read() 可能还在等换行，先补一个空行把缓冲区冲出来
        p.send(b"\n")
        out += p.recvrepeat(0.06)
    except Exception:
        pass
    try:
        for line in PROBE:
            p.sendline(line)
    except Exception as exc:
        return Result(False, out, error=str(exc))
    deadline = time.time() + 1.6
    while time.time() < deadline:
        try:
            chunk = p.recvrepeat(wait)
        except EOFError:
            break
        except Exception:
            break
        if not chunk:
            break
        out += chunk
        if MARKER in out or b"uid=" in out:
            break
    if MARKER in out or re.search(rb"uid=\d+", out):
        return Result(True, out)
    return Result(False, out)


def execute(ch: Challenge, sends: list[bytes], pre_wait: float = 0.0,
            post_wait: float = 0.0, verify: bool = True,
            keep_open: float = 0.0) -> Result:
    """按顺序发送 sends，然后验证 shell。"""
    try:
        p = spawn(ch)
    except Exception as exc:
        return Result(False, b"", error=f"spawn failed: {exc}")
    out = b""
    try:
        if pre_wait:
            time.sleep(pre_wait)
        try:
            out += p.recvrepeat(0.12)
        except Exception:
            pass
        total = len(sends)
        for idx, blob in enumerate(sends):
            if not blob:
                continue
            try:
                p.send(blob)
            except (EOFError, BrokenPipeError, OSError):
                # 进程已退出：这次尝试失败，但不要中断整轮
                return Result(False, out, error="process died before payload")
            # 分阶段读写的题目（scanf 之后 read）需要给足时间让上一段先被消费
            time.sleep(0.12 if idx < total - 1 else 0.18)
            try:
                out += p.recvrepeat(0.03)
            except Exception:
                pass
        if post_wait:
            time.sleep(post_wait)
        if not verify:
            out += p.recvrepeat(0.4)
            return Result(False, out, note="no-verify")
        res = verify_shell(p)
        res.output = out + res.output
        return res
    finally:
        if keep_open:
            time.sleep(keep_open)
        try:
            p.close()
        except Exception:
            pass


FLAG_RE = re.compile(rb"(?:flag|ctf|FLAG|CTF)[A-Za-z0-9_]{0,20}\{[^}\n]{4,}\}")


def probe_flag(p, wait: float = 0.5) -> Result:
    """题目只打印 flag（不落地 shell）时的二次判定。

    只认形如 flag{...} / CTF{...} 的输出，避免把普通大括号文本当成 flag。
    """
    out = b""
    deadline = time.time() + 1.2
    while time.time() < deadline:
        try:
            chunk = p.recvrepeat(wait)
        except Exception:
            break
        if not chunk:
            break
        out += chunk
        if FLAG_RE.search(out):
            break
    m = FLAG_RE.search(out)
    if m:
        return Result(True, out, note="flag:" + m.group(0).decode("latin-1", "replace"))
    return Result(False, out)


def execute_flag(ch: Challenge, sends: list[bytes]) -> Result:
    """发 payload 后用 flag 正则判定（题目只打 flag 不落 shell 时用）。"""
    try:
        p = spawn(ch)
    except Exception as exc:
        return Result(False, b"", error=f"spawn failed: {exc}")
    out = b""
    try:
        time.sleep(0.1)
        out += p.recvrepeat(0.08)
        for blob in sends:
            if not blob:
                continue
            try:
                p.send(blob)
            except Exception:
                return Result(False, out, error="process died")
            time.sleep(0.15)
            out += p.recvrepeat(0.05)
        r = probe_flag(p)
        r.output = out + r.output
        return r
    finally:
        try:
            p.close()
        except Exception:
            pass
