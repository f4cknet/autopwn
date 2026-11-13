"""静态事实提取：漏洞调用点、偏移推导、win 函数、gadget、RWX、格式化字符串。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM

from .model import Challenge

SINKS = {"gets", "read", "scanf", "__isoc99_scanf", "fgets",
         "strcpy", "strcat", "sprintf", "memcpy", "fread"}
SHELL_STRINGS = ("/bin/sh", "/bin//sh", "sh\x00")
NON_SHELL_CMD = ("echo", "cat ", "ls ", "id", "whoami", "pwd", "date", "ps ")


# --------------------------------------------------------------------------- 反汇编
class Dis:
    def __init__(self, ch: Challenge):
        self.ch = ch
        self.elf = ch.elf
        self.bits = ch.elf.bits
        md = Cs(CS_ARCH_X86, CS_MODE_64 if self.bits == 64 else CS_MODE_32)
        md.detail = True
        sec = self.elf.get_section_by_name(".text")
        self.insns = list(md.disasm(sec.data(), sec.header.sh_addr))
        self.by_addr = {i.address: n for n, i in enumerate(self.insns)}

    def window(self, idx: int, back: int = 25) -> list:
        return self.insns[max(0, idx - back):idx + 1]

    def call_targets(self) -> dict:
        """sink 名 -> [call 指令下标]"""
        out: dict[str, list[int]] = {}
        for n, ins in enumerate(self.insns):
            if ins.mnemonic != "call" or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != X86_OP_IMM:  # X86_OP_IMM
                continue
            name = self.ch.plt_map.get(op.imm)
            if name in SINKS:
                out.setdefault(name, []).append(n)
        return out


@dataclass
class Vuln:
    sink: str
    call_addr: int
    buf_disp: Optional[int]
    offset: Optional[int]
    size_limit: Optional[int] = None
    target: int = 0          # 被调用函数的实际地址（静态链接时很有用）
    func_entry: int = 0      # 该调用所在的函数入口

    def __str__(self) -> str:
        lim = f" limit={self.size_limit}" if self.size_limit else ""
        return f"{self.sink}@{hex(self.call_addr)} disp={self.buf_disp} off={self.offset}{lim}"


@dataclass
class Win:
    addr: int
    kind: str            # shell | flag
    evidence: str
    alt: int = 0         # 跳过 push rbp / mov rbp,rsp 后的入口（ret 进来栈对齐差 8 时用它）

    def __str__(self) -> str:
        return f"{self.kind}@{hex(self.addr)}({self.evidence})"


@dataclass
class Facts:
    vulns: list[Vuln] = field(default_factory=list)
    wins: list[Win] = field(default_factory=list)
    binsh: Optional[int] = None
    binsh_text: Optional[str] = None
    gadgets: dict = field(default_factory=dict)
    csu: Optional[tuple] = None          # (gadgetA, gadgetB)
    rwx: list = field(default_factory=list)
    mmap_rwx: Optional[int] = None
    fmt_buf: Optional[int] = None        # printf(user_buf) 的缓冲位移
    static_binsh: bool = False
    callers: dict = field(default_factory=dict)   # 函数入口 -> [调用点之后的下一条地址]
    gadget_alts: dict = field(default_factory=dict)  # gadget 名 -> 全部可用地址（用于挑无坏字节的）
    gates: list = field(default_factory=list)   # [(rbp 相对位移, 值)] 溢出后必须满足的 cmp 校验
    sys_read: Optional[int] = None       # read 包装入口（mov eax,3 处）；无 libc 的题只有这个
    sys_load: Optional[int] = None       # 「mov ebx,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]; int 0x80」入口
    sys_wrappers: dict = field(default_factory=dict)   # syscall 号 -> (entry, load, int80)
    data_addr: Optional[int] = None      # 可写数据段起始地址
    entry_sub: int = 0                   # _start 开头的 sub esp,imm（重入时帧下移的量）

    @property
    def shell_win(self) -> Optional[Win]:
        for w in self.wins:
            if w.kind == "shell":
                return w
        return None


# --------------------------------------------------------------------------- 工具
def read_cstr(ch: Challenge, addr: int, maxlen: int = 96) -> Optional[str]:
    """按虚拟地址从 ELF 段里读 C 字符串。"""
    for seg in ch.elf.segments:
        start = seg.header.p_vaddr
        if start <= addr < start + seg.header.p_filesz:
            data = seg.data()
            off = addr - start
            raw = data[off:off + maxlen]
            if not raw:
                return None
            raw = raw.split(b"\x00")[0]
            try:
                return raw.decode("latin-1")
            except Exception:
                return None
    return None


def _imm(tok: str) -> int:
    """capstone 的小位移/小立即数会打印成十进制，这里统一解析。"""
    tok = tok.strip()
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok, 10)


def _lea_disp(ins) -> Optional[tuple]:
    """解析 `lea reg, [rbp - X]` / `[esp + X]`，返回 (base, disp, dest)。"""
    m = re.match(r"^(r[a-z0-9]+|e[a-z]{2}), \[(rbp|ebp|rsp|esp)( ?[-+] ?(?:0x[0-9a-f]+|\d+))?\]$",
                 ins.op_str)
    if not m:
        return None
    dest, base, delta = m.group(1), m.group(2), m.group(3)
    disp = 0
    if delta:
        s = delta.replace(" ", "")
        if s.startswith("-"):
            disp = -_imm(s[1:])
        else:
            disp = _imm(s[1:])
    return base, disp, dest


def _mov_imm(ins) -> Optional[tuple]:
    m = re.match(r"^(r[a-z0-9]+|e[a-z]{2}), (0x[0-9a-f]+|\d+)$", ins.op_str)
    if not m:
        return None
    return m.group(1), _imm(m.group(2))


def _frame_size(win: list) -> Optional[int]:
    for ins in reversed(win):
        if ins.mnemonic == "sub" and ins.op_str.startswith(("rsp, ", "esp, ")):
            try:
                return _imm(ins.op_str.split(", ")[1])
            except Exception:
                return None
    return None


# --------------------------------------------------------------------------- 主入口
def analyse(ch: Challenge) -> Facts:
    f = Facts()
    d = Dis(ch)
    ptr = ch.wordsize

    # ---- /bin/sh 字符串
    for s in ch.elf.search(b"/bin/sh"):
        f.binsh = s
        f.binsh_text = read_cstr(ch, s) or "/bin/sh"
        break

    # ---- 漏洞调用点 + 偏移推导
    calls = d.call_targets()
    for sink, idxs in calls.items():
        for n in idxs:
            ins = d.insns[n]
            win = d.window(n, 25)
            offset, disp, limit = _derive_offset(ch, win, sink)
            tgt = ins.operands[0].imm if ins.operands else 0
            f.vulns.append(Vuln(sink, ins.address, disp, offset, limit, int(tgt)))

    # ---- 无 libc 的手写汇编题：call 的是自写的 int 0x80 包装，PLT 里什么都没有
    f.sys_wrappers = _find_sys_wrappers(d)
    rd = f.sys_wrappers.get(3)
    if rd:
        f.sys_read = rd[0]
        f.sys_load = rd[1] or None
    wr = f.sys_wrappers.get(4)
    if wr and not f.sys_load:
        f.sys_load = wr[1] or None
    f.data_addr = _writable_start(ch)
    f.entry_sub = _entry_sub(ch, d)

    if not f.vulns:
        v = _find_sys_vuln(ch, d, f)
        if v:
            f.vulns.append(v)

    if not f.vulns and ch.prot.static:
        v = _static_vuln(ch, d)
        if v:
            f.vulns.append(v)

    # ---- 调用关系（PIE 局部覆盖 ret 时要用）
    entries = _func_entries(ch, d)
    f.callers = _collect_callers(d, entries)
    for v in f.vulns:
        v.func_entry = _entry_of(v.call_addr, entries)

    # ---- win 函数
    f.wins = _find_wins(ch, d)

    # ---- gadget
    f.gadgets = _find_gadgets(ch)
    f.gadget_alts = _scan_gadget_alts(ch)
    f.csu = _find_csu(ch, d)

    # ---- RWX / mmap RWX
    try:
        for seg in ch.elf.segments:
            if (seg.header.p_flags & 7) == 7 and seg.header.p_memsz > 0x100:
                f.rwx.append(seg.header.p_vaddr)
    except Exception:
        pass
    f.mmap_rwx = _find_mmap_rwx(ch, d)
    f.gates = _find_gates(d)

    # ---- printf(user_buf)
    f.fmt_buf = _find_fmt(ch, d)
    return f


# --------------------------------------------------------------------------- 无 libc：int 0x80 包装
def _find_sys_wrappers(d: Dis) -> dict:
    """识别「mov eax,NR ... int 0x80」这种自写 syscall 包装。

    返回 {NR: (entry, load, int80)}：
      entry = mov eax,NR 的地址（从这进就是完整包装）
      load  = 装载 ebx/ecx/edx 的第一条 mov 的地址（从这进可保留 eax，用于 execve）
      int80 = int 0x80 的地址
    """
    out: dict[int, tuple] = {}
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "int" or not ins.op_str.startswith("0x80"):
            continue
        nr, entry = None, 0
        for k in range(n - 1, max(-1, n - 24), -1):
            p = d.insns[k]
            if p.mnemonic == "mov" and p.op_str.startswith("eax, "):
                try:
                    nr = _imm(p.op_str.split(", ", 1)[1])
                except Exception:
                    nr = None
                entry = int(p.address)
                break
            if p.mnemonic in ("call", "ret", "int"):
                break
        load = 0
        for k in range(n - 1, max(-1, n - 16), -1):
            p = d.insns[k]
            if p.mnemonic == "mov" and p.op_str.startswith("ebx, dword ptr [esp + 4]"):
                load = int(p.address)
                break
            if p.mnemonic == "int":
                break
        if nr is not None:
            out.setdefault(int(nr), (entry, load, int(ins.address)))
    return out


def _writable_start(ch: Challenge) -> Optional[int]:
    best = None
    for sec in ch.elf.sections:
        if not (sec.header.sh_flags & 0x1) or not (sec.header.sh_flags & 0x2):
            continue
        if sec.header.sh_size == 0:
            continue
        if best is None or sec.header.sh_addr < best:
            best = int(sec.header.sh_addr)
    return best


def _find_gates(d: Dis) -> list:
    """`cmp dword ptr [rbp-X], imm` —— 溢出后要写进去的「暗号」。

    只认后面紧跟条件跳转的，避免把普通比较也当门槛。
    """
    out = []
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "cmp":
            continue
        m = re.match(r"^dword ptr \[rbp - (0x[0-9a-f]+|\d+)\], (0x[0-9a-f]+|\d+)$", ins.op_str)
        if not m:
            continue
        nxt = d.insns[n + 1] if n + 1 < len(d.insns) else None
        if nxt is None or not nxt.mnemonic.startswith("j"):
            continue
        out.append((-_imm(m.group(1)), _imm(m.group(2))))
    return out


def _zero_addr(ch: Challenge, data: Optional[int]) -> Optional[int]:
    """数据段 memsz 之后、同一页内的零填充区。

    用作 execve 的 argv 数组（内容为 NULL），免得依赖「我们刚写过 0」。
    """
    if not data:
        return None
    for seg in ch.elf.segments:
        v = int(seg.header.p_vaddr)
        m = int(seg.header.p_memsz)
        if v <= data < v + max(m, 1):
            end = v + m
            z = (end + 3) & ~3
            if z + 4 <= ((end | 0xFFF) + 1):
                return z
            return None
    return None


def _entry_sub(ch: Challenge, d: Dis) -> int:
    """_start 开头的 sub esp,imm —— 重入 _start 时整个帧会下移这么多。"""
    if not d.insns:
        return 0
    for ins in d.insns[:6]:
        m = re.match(r"^esp, (0x[0-9a-f]+|\d+)$", ins.op_str) if ins.mnemonic == "sub" else None
        if m:
            return _imm(m.group(1))
    return 0


def _find_sys_vuln(ch: Challenge, d: Dis, f: Facts) -> Optional[Vuln]:
    """call 的是自写 read 包装时，从 lea/mov 的立即数推缓冲位移、从 sub esp 推帧大小。"""
    rd = f.sys_wrappers.get(3)
    if not rd:
        return None
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        if ins.operands[0].type != X86_OP_IMM or ins.operands[0].imm != rd[0]:
            continue
        win = d.window(n, 20)
        buf_disp, count, frame = None, None, None
        for p in win:
            if p.mnemonic == "lea":
                m = re.match(r"^eax, \[esp \+ (0x[0-9a-f]+|\d+)\]$", p.op_str)
                if m:
                    buf_disp = _imm(m.group(1))
            elif p.mnemonic == "mov":
                m = re.match(r"^dword ptr \[esp \+ 8\], (0x[0-9a-f]+|\d+)$", p.op_str)
                if m:
                    count = _imm(m.group(1))
        for p in reversed(win):
            m = re.match(r"^esp, (0x[0-9a-f]+|\d+)$", p.op_str) if p.mnemonic == "sub" else None
            if m:
                frame = _imm(m.group(1))
                break
        if buf_disp is None or not frame:
            continue
        off = frame - buf_disp
        if 0 < off < 0x400:
            return Vuln("read", ins.address, buf_disp, off, count, int(rd[0]))
    return None


def _static_vuln(ch: Challenge, d: Dis) -> Optional[Vuln]:
    """静态链接（无 PLT）时，从 _start -> __libc_start_main 的 push 定位 main，
    再从 main 的 `sub esp,F` + `lea reg,[esp+X]` + call 推导栈溢出偏移。"""
    text = ch.elf.get_section_by_name(".text")
    lo, hi = text.header.sh_addr, text.header.sh_addr + text.header.sh_size
    start = d.by_addr.get(int(ch.elf.entry))
    if start is None:
        return None
    main = None
    last_push = None
    for ins in d.insns[start:start + 40]:
        if ins.mnemonic == "push":
            try:
                last_push = _imm(ins.op_str)
            except Exception:
                last_push = None
        elif ins.mnemonic == "call" and last_push and lo <= last_push < hi:
            main = last_push
            break
    if main is None:
        return None
    mi = d.by_addr.get(main)
    if mi is None:
        return None
    body = d.insns[mi:mi + 80]
    frame = None
    for ins in body[:12]:
        if ins.mnemonic == "sub" and ins.op_str.startswith(("esp, ", "rsp, ")):
            try:
                frame = _imm(ins.op_str.split(", ")[1])
            except Exception:
                frame = None
            break
    if frame is None:
        return None
    for n, ins in enumerate(body):
        if ins.mnemonic == "lea":
            info = _lea_disp(ins)
            if not info or info[0] not in ("esp", "rsp"):
                continue
            for nxt in body[n + 1:n + 4]:
                if nxt.mnemonic == "call":
                    off = frame - info[1]
                    if 0 < off < 0x400:
                        tgt = nxt.operands[0].imm if nxt.operands else 0
                        return Vuln("gets", nxt.address, info[1], off, None, int(tgt))
    return None


def _derive_offset(ch: Challenge, win: list, sink: str):
    """从一个 sink 调用点回溯，推导 缓冲区→返回地址 的距离。"""
    ptr = ch.wordsize
    cands = []
    for k in range(len(win) - 2, max(-1, len(win) - 22), -1):
        ins = win[k]
        if ins.mnemonic == "lea":
            info = _lea_disp(ins)
            if info:
                base, disp, dest = info
                if base in ("rbp", "ebp"):
                    cands.append((-disp + ptr, disp))
                elif base in ("rsp", "esp"):
                    fs = _frame_size(win[:k + 1])
                    if fs is not None:
                        # 返回地址在 sub 之前的 rsp 处：offset = frame - disp
                        cands.append((fs - disp, disp))
        elif ins.mnemonic in ("mov", "push") and sink != "gets":
            info = _mov_imm(ins)
            if info and info[1] > 0x1000 and _looks_writable(ch, info[1]):
                pass  # 全局缓冲区，不做栈偏移
    # read 的 size 参数（rdx / push 立即数）
    limit = None
    if sink in ("read", "memcpy", "fread"):
        for ins in reversed(win):
            if ins.mnemonic == "mov" and ins.op_str.startswith(("edx, ", "rdx, ")):
                try:
                    limit = _imm(ins.op_str.split(", ")[1])
                except Exception:
                    limit = None
                break
            if ins.mnemonic == "push":
                # 32 位调用序列是 push count / push buf / push fd，
                # 倒着扫时先遇到的是 fd(0)，要跳过继续往前找 count
                try:
                    val = _imm(ins.op_str)
                except Exception:
                    continue
                if val > 1:
                    limit = val
                    break
    if limit == 0:
        limit = None
    if sink == "fgets":
        for ins in reversed(win):
            if ins.mnemonic == "mov" and ins.op_str.startswith(("esi, ", "rsi, ")):
                try:
                    limit = _imm(ins.op_str.split(", ")[1])
                except Exception:
                    limit = None
                break
    if not cands:
        return None, None, limit
    return cands[0][0], cands[0][1], limit


def _looks_writable(ch: Challenge, addr: int) -> bool:
    for seg in ch.elf.segments:
        if seg.header.p_vaddr <= addr < seg.header.p_vaddr + seg.header.p_memsz:
            return bool(seg.header.p_flags & 2)
    return False


def _func_entries(ch: Challenge, d: Dis) -> list[int]:
    """枚举函数入口：符号表 ∪ 所有 call 的直接目标 ∪ entrypoint。"""
    entries = set()
    try:
        for name, addr in ch.elf.functions.items():
            if addr:
                entries.add(int(addr))
    except Exception:
        pass
    for name, addr in ch.elf.symbols.items():
        if addr and ch.elf.get_section_by_name(".text") and \
                ch.elf.get_section_by_name(".text").header.sh_addr <= addr < \
                ch.elf.get_section_by_name(".text").header.sh_addr + ch.elf.get_section_by_name(".text").header.sh_size:
            entries.add(int(addr))
    text = ch.elf.get_section_by_name(".text")
    lo, hi = text.header.sh_addr, text.header.sh_addr + text.header.sh_size
    for ins in d.insns:
        # endbr64/endbr32 是编译器插在函数首地址的 CET 标记，stripped 时它是唯一可靠的入口线索
        if ins.mnemonic in ("endbr64", "endbr32"):
            entries.add(int(ins.address))
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X86_OP_IMM:
            t = ins.operands[0].imm
            if lo <= t < hi:
                entries.add(t)
    entries.add(int(ch.elf.entry))
    return sorted(entries)


def _entry_of(addr: int, entries: list[int]) -> int:
    cur = 0
    for e in entries:
        if e <= addr:
            cur = e
        else:
            break
    return cur


def _collect_callers(d: Dis, entries: list[int]) -> dict:
    out: dict[int, list[int]] = {}
    eset = set(entries)
    for ins in d.insns:
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X86_OP_IMM:
            t = ins.operands[0].imm
            if t in eset:
                out.setdefault(t, []).append(ins.address + ins.size)
    return out


def _find_wins(ch: Challenge, d: Dis) -> list[Win]:
    """找「函数体里直接 system/execve 一个 shell 字符串」的函数。"""
    wins: list[Win] = []
    targets = {}
    for addr, name in ch.plt_map.items():
        if name in ("system", "execve", "execl", "execv", "execvp", "popen"):
            targets[addr] = name
    if not targets:
        return wins
    entries = _func_entries(ch, d)
    bounds = list(zip(entries, entries[1:] + [ch.elf.entry + 0x100000]))
    for lo, hi in bounds:
        start = d.by_addr.get(lo)
        if start is None:
            continue
        body = []
        for ins in d.insns[start:start + 400]:
            if ins.address >= hi:
                break
            body.append(ins)
        for n, ins in enumerate(body):
            if ins.mnemonic != "call" or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != X86_OP_IMM or op.imm not in targets:
                continue
            arg = _first_arg_string(ch, body[max(0, n - 12):n + 1])
            if not arg:
                continue
            text, addr = arg
            low = text.lower()
            if any(low.startswith(x) or x in low for x in NON_SHELL_CMD):
                kind = "flag"
            elif "/bin/sh" in text or text.strip().endswith("sh"):
                kind = "shell"
            else:
                continue
            alt = lo
            for q in body[:8]:
                if (q.mnemonic in ("endbr64", "endbr32", "nop")
                        or (q.mnemonic == "push" and q.op_str == "rbp")
                        or (q.mnemonic == "mov" and q.op_str.replace(" ", "") == "rbp,rsp")):
                    alt = int(q.address) + int(q.size)
                else:
                    break
            wins.append(Win(lo, kind, f"{targets[op.imm]}(\"{text}\")",
                            alt if alt != lo else 0))
    # 去重：同一地址只留一条（优先 shell）
    uniq: dict[int, Win] = {}
    for w in wins:
        if w.addr not in uniq or (uniq[w.addr].kind != "shell" and w.kind == "shell"):
            uniq[w.addr] = w
    return list(uniq.values())


def _first_arg_string(ch: Challenge, win: list):
    """在调用前找第一个参数指向的字符串（兼容 lea rdi,[rip+x] / mov edi,imm / lea rax+mov rdi,rax）。"""
    reg_rip: dict[str, int] = {}
    for ins in win:
        if ins.mnemonic == "lea":
            m = re.match(r"^(r[a-z0-9]+|e[a-z]{2}), \[rip \+ (0x[0-9a-f]+)\]$", ins.op_str)
            if m:
                reg_rip[m.group(1)] = ins.address + ins.size + _imm(m.group(2))
                continue
        if ins.mnemonic == "mov":
            m = re.match(r"^(r[a-z0-9]+|e[a-z]{2}), (0x[0-9a-f]+)$", ins.op_str)
            if m:
                reg_rip[m.group(1)] = _imm(m.group(2))
    for ins in reversed(win):
        if ins.mnemonic == "mov":
            m = re.match(r"^(rdi|edi), (0x[0-9a-f]+)$", ins.op_str)
            if m:
                txt = read_cstr(ch, _imm(m.group(2)))
                if txt:
                    return txt, _imm(m.group(2))
            m = re.match(r"^(rdi|edi), (r[a-z0-9]+|e[a-z]{2})$", ins.op_str)
            if m and m.group(2) in reg_rip:
                txt = read_cstr(ch, reg_rip[m.group(2)])
                if txt:
                    return txt, reg_rip[m.group(2)]
        if ins.mnemonic == "lea":
            m = re.match(r"^(rdi|edi), \[rip \+ (0x[0-9a-f]+)\]$", ins.op_str)
            if m:
                addr = ins.address + ins.size + _imm(m.group(2))
                txt = read_cstr(ch, addr)
                if txt:
                    return txt, addr
        if ins.mnemonic == "push":
            try:
                addr = _imm(ins.op_str)
            except Exception:
                continue
            txt = read_cstr(ch, addr)
            if txt:
                return txt, addr
    return None


GADGET_BYTES = {
    "pop_eax": b"\x58\xc3",
    "pop_ebx": b"\x5b\xc3",
    "pop_ecx": b"\x59\xc3",
    "pop_edx": b"\x5a\xc3",
    "pop_esi": b"\x5e\xc3",
    "pop_edi": b"\x5f\xc3",
    "pop_ecx_ebx": b"\x59\x5b\xc3",
    "pop_ebx_edx": b"\x5b\x5a\xc3",
    "pop_edx_ecx": b"\x5a\x59\xc3",
    "int80": b"\xcd\x80",
}


def _scan_gadget_alts(ch: Challenge) -> dict:
    """字节级扫 gadget 的所有出现位置。

    `gets` 会在 0x0a 处截断、`scanf("%s")` 会在空白处截断，
    所以同一个 gadget 往往不能只用 pwntools 返回的那一个地址。
    """
    text = ch.elf.get_section_by_name(".text")
    if text is None:
        return {}
    data = text.data()
    base = text.header.sh_addr
    out: dict[str, list[int]] = {}
    for name, seq in GADGET_BYTES.items():
        hits = []
        start = 0
        while True:
            i = data.find(seq, start)
            if i < 0:
                break
            hits.append(base + i)
            start = i + 1
        if hits:
            out[name] = hits
    return out


def _find_gadgets(ch: Challenge) -> dict:
    """用 pwntools ROP 找常用 gadget。"""
    from pwn import ROP
    out = {}
    try:
        rop = ROP(ch.elf)
    except Exception:
        return out
    want = {
        "pop_rdi": ["pop rdi", "ret"],
        "pop_rsi": ["pop rsi", "ret"],
        "pop_rdx": ["pop rdx", "ret"],
        "pop_rax": ["pop rax", "ret"],
        "pop_rbp": ["pop rbp", "ret"],
        "syscall": ["syscall"],
        "int80": ["int 0x80"],
        "ret": ["ret"],
        "leave": ["leave", "ret"],
    }
    if ch.elf.bits == 32:
        want.update({
            "pop_ebx": ["pop ebx", "ret"],
            "pop_ecx": ["pop ecx", "ret"],
            "pop_edx": ["pop edx", "ret"],
            "pop_eax": ["pop eax", "ret"],
            # 组合 gadget：pop ecx 缺失时用来同时设置 ecx/ebx
            "pop_ecx_ebx": ["pop ecx", "pop ebx", "ret"],
            "pop_ebx_ecx": ["pop ebx", "pop ecx", "ret"],
            "pop_ecx_edx": ["pop ecx", "pop edx", "ret"],
            "pop_edx_ecx": ["pop edx", "pop ecx", "ret"],
        })
    for key, seq in want.items():
        try:
            g = rop.find_gadget(seq)
        except Exception:
            g = None
        if g:
            out[key] = g.address
    # int 0x80 / syscall 最好带 ret
    for key, seq in (("int80", ["int 0x80", "ret"]), ("syscall", ["syscall", "ret"])):
        try:
            g = rop.find_gadget(seq)
        except Exception:
            g = None
        if g:
            out[key] = g.address
    return out


def _find_csu(ch: Challenge, d: Dis) -> Optional[tuple]:
    """定位 __libc_csu_init 的 pop 链（gadget A）与 call 链（gadget B）。

    返回 (A, B, mapping)：mapping 描述 rdi/rsi/rdx 分别由 r13/r14/r15 里哪个提供，
    不同 gcc 版本编译出来的顺序并不一致，必须按实际指令解析。
    """
    if ch.elf.bits != 64:
        return None
    pops = ["pop rbx", "pop rbp", "pop r12", "pop r13", "pop r14", "pop r15", "ret"]
    for n in range(len(d.insns) - len(pops)):
        seq = d.insns[n:n + len(pops)]
        if [i.mnemonic + (" " + i.op_str if i.op_str else "") for i in seq] == pops:
            a = seq[0].address
            for k in range(n - 1, max(-1, n - 40), -1):
                ins = d.insns[k]
                if ins.mnemonic == "call" and "r12 + rbx*8" in ins.op_str:
                    mapping = {}
                    start = None
                    for prev in d.insns[max(0, k - 6):k]:
                        m = re.match(r"^(rdi|edi|rsi|esi|rdx|edx), (r\d+d?|e[a-z]{2})$",
                                     prev.op_str)
                        if prev.mnemonic == "mov" and m:
                            dst = {"edi": "rdi", "esi": "rsi", "edx": "rdx"}.get(
                                m.group(1), m.group(1))
                            src = m.group(2).rstrip("d")
                            mapping[dst] = src
                            start = prev.address if start is None else start
                    if start is None or "r12" in mapping.values():
                        continue
                    if set(mapping) >= {"rdi", "rsi", "rdx"}:
                        return a, start, mapping
    return None


def _find_mmap_rwx(ch: Challenge, d: Dis) -> Optional[int]:
    p = ch.plt("mmap")
    if not p:
        return None
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type == X86_OP_IMM and op.imm == p:
            addr = None
            for prev in reversed(d.insns[max(0, n - 10):n]):
                m = _mov_imm(prev)
                if m and m[0] in ("edi", "rdi"):
                    addr = m[1]
                    break
            if addr:
                return addr
    return None


def _find_fmt(ch: Challenge, d: Dis) -> Optional[int]:
    """检测 printf(用户缓冲区) —— 返回缓冲区相对 rbp 的位移。"""
    p = ch.plt("printf")
    if not p:
        return None
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM or op.imm != p:
            continue
        # 参数寄存器来自 lea [rbp-X] / mov [esp], lea-result
        for prev in reversed(d.insns[max(0, n - 8):n]):
            if prev.mnemonic == "lea":
                info = _lea_disp(prev)
                if info and info[0] in ("rbp", "ebp"):
                    return -info[1]
            if prev.mnemonic in ("mov", "push") and "[esp" in prev.op_str:
                break
    return None
