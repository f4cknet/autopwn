"""静态事实提取：漏洞调用点、偏移推导、win 函数、gadget、RWX、格式化字符串。"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .model import Challenge

SINKS = {"gets", "read", "scanf", "__isoc99_scanf", "fgets",
         "strcpy", "strcat", "sprintf", "memcpy", "fread"}
SHELL_STRINGS = ("/bin/sh", "/bin//sh", "sh\x00")
NON_SHELL_CMD = ("echo", "cat ", "ls ", "id", "whoami", "pwd", "date", "ps ")
# v7.3.1：只有真正读文件的命令才算「打印 flag」；echo/ls 这类只输出常量 → 诱饵
FILE_READ_CMD = ("cat ", "cat\t", "head ", "tail ", "grep ", "strings ",
                 "xxd ", "more ", "less ", "awk ", "sed ", "tac ")


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
    kind: str            # shell | flag | decoy（decoy = 打中了也拿不到 flag，如 system("echo flag")）
    evidence: str
    alt: int = 0         # 跳过 push rbp / mov rbp,rsp 后的入口（ret 进来栈对齐差 8 时用它）
    arg_addr: int = 0    # v7.4.2：常量实参字符串地址（参数化 win / 证据用）

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
    fmt_sites: list = field(default_factory=list)  # [(基址, 位移, rbp相对位移|None, call)] 全部 fmt 站点
    static_binsh: bool = False
    callers: dict = field(default_factory=dict)   # 函数入口 -> [调用点之后的下一条地址]
    gadget_alts: dict = field(default_factory=dict)  # gadget 名 -> 全部可用地址（用于挑无坏字节的）
    gates: list = field(default_factory=list)   # [(rbp 相对位移, 值)] 溢出后必须满足的 cmp 校验
    interact: dict = field(default_factory=dict)  # 函数入口 -> [b"w\n"] 菜单式题的前置选择字符
    sys_read: Optional[int] = None       # read 包装入口（mov eax,3 处）；无 libc 的题只有这个
    sys_load: Optional[int] = None       # 「mov ebx,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]; int 0x80」入口
    sys_wrappers: dict = field(default_factory=dict)   # syscall 号 -> (entry, load, int80)
    data_addr: Optional[int] = None      # 可写数据段起始地址
    entry_sub: int = 0                   # _start 开头的 sub esp,imm（重入时帧下移的量）
    echo_leak: Optional[tuple] = None    # (vuln_idx, buf_size)：read 溢出 + puts(buf) 回显结构（canary-echo 泄漏用）
    prompts: dict = field(default_factory=dict)   # 函数入口 -> [常量提示串]（Wait(prompt) 用）
    # ---- v7.3.0 事实三态：Known 有值 / Absent 确认不存在（不登记）/ Unknown 登记原因
    unknowns: dict = field(default_factory=dict)    # 事实名 -> 无法判定的原因
    unreachable: list = field(default_factory=list)  # [{sink, call, offset, limit}] 明确不可达的溢出点
    # ---- v7.4.0 守卫层：输入 → win 的判定条件（逻辑校验题）
    guards: list = field(default_factory=list)      # [guard.Guard]
    backfills: list = field(default_factory=list)   # [guard.Backfill]
    # ---- v7.4.2 全局写 → 跳 win（缺口 B）
    global_writes: list = field(default_factory=list)  # [(buf, sink, call, limit)]
    global_calls: list = field(default_factory=list)   # [(slot, call)]

    @property
    def shell_win(self) -> Optional[Win]:
        for w in self.wins:
            if w.kind == "shell":
                return w
        return None


# --------------------------------------------------------------------------- 工具
def _find_echo_vuln(f: "Facts", ch: Challenge, d: Dis) -> Optional[tuple]:
    """找「read(0, buf, N) 溢出 + 紧随 puts(buf) 回显」的结构（canary-echo 泄漏用）。

    返回 (vuln 在 f.vulns 里的下标, buf_size=-disp)；不满足返回 None。
    repeater 型：read 之后 puts 同一个 buf——发 buf_size+1 字节盖掉 canary LSB，
    回显就能把 canary 高 7 字节带出来。
    """
    for i, v in enumerate(f.vulns):
        if v.sink != "read" or not v.buf_disp or not v.offset or not v.size_limit:
            continue
        n = next((j for j, ins in enumerate(d.insns) if ins.address == v.call_addr), None)
        if n is None:
            continue
        # read 调用点之后 10 条内：call puts 且参数是同一个 [rbp+disp]
        # （i386 下 puts 前可能隔着 add esp / sub esp 等栈清理，窗口放宽）
        for k in range(n + 1, min(n + 11, len(d.insns))):
            ins = d.insns[k]
            if ins.mnemonic == "call":
                target = ins.operands[0].imm if ins.operands and \
                    ins.operands[0].type == X86_OP_IMM else 0
                if target in _puts_plts(ch):
                    # 参数必须是 read 的同一个 buf：call 前最近的 lea/取址
                    for b in range(k - 1, max(k - 6, n), -1):
                        pv = d.insns[b]
                        if pv.mnemonic == "lea":
                            info = _lea_disp(pv)
                            if info and info[0] in ("rbp", "ebp") and info[1] == v.buf_disp:
                                return (i, -v.buf_disp)
                        if pv.mnemonic == "call":
                            break
                break
    return None


def _find_prompts(ch: Challenge, f: "Facts", d: Dis) -> dict:
    """提取交互提示串：puts/printf/write 的常量串实参 → 归组到其后最近的输入函数入口。

    启发式过滤（铁律 5：宁缺勿滥，误报会让 Wait 烧死）：
      * 只认第一实参是只读段常量地址（lea reg,[imm] / mov reg,imm）；
      * 4~64 字节、可打印（允许 \\n）、含 `:` / `?` / `!` / `>` 之一；
      * ASCII art banner（无标点）自然落选。
    归组：该 call 之后 25 条内最近的 read/gets/scanf/fgets —— 它们同属一个函数帧。
    """
    out: dict[int, list] = {}
    io_out = _puts_plts(ch)
    printf_plt = ch.plt("printf")
    write_plt = ch.plt("write")
    sinks = set()
    for name in ("read", "gets", "fgets"):
        p = ch.plt(name)
        if p:
            sinks.add(p)
    scanf = ch.plt("__isoc99_scanf") or ch.plt("scanf")
    if scanf:
        sinks.add(scanf)
    if not sinks:
        return out

    def _const_str_arg(ins) -> Optional[int]:
        """call 前的实参装载是否为只读段常量地址；是则返回地址。"""
        return None  # 在调用点处统一回看，见主循环

    rodata = []
    for sec in (".rodata", ".data.rel.ro"):
        s = ch.elf.get_section_by_name(sec)
        if s:
            rodata.append((s.header.sh_addr, s.header.sh_addr + s.header.sh_size))

    def _in_rodata(addr: int) -> bool:
        for lo, hi in rodata:
            if lo <= addr < hi:
                return True
        return False

    n_ins = len(d.insns)
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM:
            continue
        if op.imm not in io_out and op.imm not in (printf_plt, write_plt):
            continue
        if op.imm == printf_plt:
            # printf 第一参是 fmt：只有「fmt 是常量且像提示语」才算（printf("...:")）
            pass  # 与 puts 同路径处理
        # 回看 8 条找第一实参装载：amd64 rdi / edi，i386 push
        # note 型：lea rax,[rip+…] → mov rdi,rax → call puts（rip 相对，要算绝对地址）
        arg_addr = None
        rip = None
        dest_reg = ""
        for k in range(n - 1, max(-1, n - 9), -1):
            p = d.insns[k]
            if p.mnemonic == "call":
                break
            if p.mnemonic == "lea":
                ops = p.operands
                dest_reg = p.op_str.split(",")[0].strip()
                if ops and ops[1].type == X86_OP_MEM:
                    mem = ops[1].mem
                    if mem.base == 0 and mem.index == 0:        # 绝对 disp
                        arg_addr = mem.disp & (2 ** 64 - 1 if ch.elf.bits == 64
                                               else 2 ** 32 - 1)
                    elif d.insns[k + 1].mnemonic == "mov" if k + 1 < n else False:
                        pass
                    else:
                        arg_addr = None
                    if mem.base != 0 and "rip" in p.op_str:
                        # rip 相对：下一条指令地址 + disp
                        arg_addr = int(p.address) + p.size + mem.disp
                elif ops and ops[1].type == X86_OP_IMM:
                    arg_addr = int(ops[1].imm)
                if arg_addr is not None and dest_reg in ("rdi", "edi"):
                    break
                if arg_addr is not None:
                    rip = arg_addr          # 暂存，等 mov rdi,dest 确认
                    continue
            if p.mnemonic == "mov" and p.op_str.startswith(("rdi, ", "edi, ")) \
                    and rip is not None:
                if p.op_str.split(", ", 1)[1] == dest_reg:
                    arg_addr = rip
                    break
            if p.mnemonic == "mov" and len(p.operands) >= 2 and \
                    p.operands[1].type == X86_OP_IMM and \
                    p.op_str.startswith(("rdi, ", "edi, ")):
                # amd64: mov edi, 0x400a70（常量串直接进 rdi）—— repeater 型
                # 注意 capstone 的 operands[0] 是 REG、operands[1] 才是 IMM
                v = int(p.operands[1].imm)
                if _in_rodata(v):
                    arg_addr = v
                    break
            if p.mnemonic == "push" and p.operands and \
                    p.operands[0].type == X86_OP_IMM:
                v = int(p.operands[0].imm)
                if _in_rodata(v):
                    arg_addr = v
                    break
            if p.mnemonic in ("mov",) and p.op_str.split(",")[0].strip() == dest_reg \
                    and dest_reg and dest_reg not in ("rdi", "edi"):
                break                        # dest 被覆盖：lea 的值死了
        if arg_addr is None or not _in_rodata(arg_addr):
            continue
        text = read_cstr(ch, arg_addr, 80)
        if not text or not (4 <= len(text.rstrip()) <= 64):
            continue
        if not all(32 <= ord(c) < 127 or c == "\n" for c in text):
            continue
        if not any(mark in text for mark in (":", "?", "!", ">")):
            continue
        # 归组：call 之后 25 条内最近的输入函数
        entry = None
        for j in range(n + 1, min(n + 26, n_ins)):
            nxt = d.insns[j]
            if nxt.mnemonic == "call" and nxt.operands and \
                    nxt.operands[0].type == X86_OP_IMM:
                if nxt.operands[0].imm in sinks:
                    entry = _entry_of(nxt.address, f.callers and list(f.callers.keys())
                                      or [])
                    break
                if nxt.operands[0].imm in io_out:
                    break               # 又一个输出：提示串属于下一个输入，不追
        if entry is None:
            continue
        b = text.encode("latin-1", "replace")
        if b not in out.setdefault(entry, []):
            out[entry].append(b)
    return out


def _puts_plts(ch: Challenge) -> set:
    """puts 的 PLT 地址集合（含 pwntools 映射的所有别名入口）。"""
    out = set()
    for addr, name in getattr(ch, "plt_map", {}).items():
        if name == "puts":
            out.add(addr)
    return out


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
    """当前函数的栈帧调整量（`sub esp,N` 或等价的 `add esp,-N`）。

    v7.3.1 两处修正：
      * 只往回看到**最近一次 ret** 为止——旧实现从 .text 起点扫，
        会抓到上一个函数的 `sub`（题七把 0x80 的帧算成 40）；
      * `add esp, -0x80` / `add esp, 0xffffff80` 与 `sub esp, 0x80` 等价，
        旧实现只认 sub，直接放弃。
    """
    for ins in reversed(win):
        if ins.mnemonic == "ret":
            return None
        if ins.mnemonic not in ("sub", "add"):
            continue
        op = ins.op_str
        if not op.startswith(("rsp, ", "esp, ")):
            continue
        raw = op.split(", ", 1)[1].strip()
        neg = raw.startswith("-")
        try:
            v = _imm(raw.lstrip("-+"))
        except Exception:
            continue
        if ins.mnemonic == "sub":
            return v
        if neg:
            return v
        if v >= 0x80000000:           # 未加负号的补码写法：0xffffff80 == -0x80
            return 0x100000000 - v
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

    # ---- 调用关系（PIE 局部覆盖 ret 时要用）；静态事实提取也要 entries
    entries = _func_entries(ch, d)

    if not f.vulns and ch.prot.static:
        v = _static_vuln(ch, d)
        if v:
            f.vulns.append(v)

    # v7.4.2c1：旧 fallback 没找到时，从 main（及一层直接被调函数）找 sink 符号直呼
    if not f.vulns and ch.prot.static:
        f.vulns = _static_vulns(ch, d, entries)

    f.callers = _collect_callers(d, entries)
    for v in f.vulns:
        v.func_entry = _entry_of(v.call_addr, entries)

    # ---- win 函数
    f.wins = _find_wins(ch, d)

    # ---- 菜单式前置交互（先发 'w\n' 才进 write_note 这类）
    f.interact = _find_interact(d)
    # 数字菜单（1.Encrypt 2.Decrypt 3.Exit + scanf("%d")）——v7.3.1
    for _entry, _cands in _find_numeric_menu(
            ch, d, entries, {v.func_entry for v in f.vulns}).items():
        bucket = f.interact.setdefault(_entry, [])
        for _c in _cands:
            if _c not in bucket:
                bucket.append(_c)

    # print_flag 自己 open()+read(fd,buf,n) 不是漏洞点，从 vulns 里剔掉。
    # v7.3.0：旧规则「函数入口是 win 就整批剔除」把「同一函数既收输入又有 win」的题
    # 也误杀了（题三 / ch04 / ch09）——这类题本来该靠正常偏移打，去掉盲猜兜底后会直接归零。
    # 新规则：只有该函数**自己 open/fopen 了文件**时，函数内的 read 才算「读 flag 自身」。
    win_addrs = {w.addr for w in f.wins}
    file_open_funcs = _funcs_with_file_open(ch, d, entries)
    kept, dropped = [], []
    for v in f.vulns:
        in_win = v.func_entry in win_addrs
        # 「win 自己读文件」的两种形态：函数内有 open；或 read 的 fd 明显不是 stdin
        file_read = in_win and v.func_entry in file_open_funcs
        if in_win and v.sink == "read":
            fd = _read_fd(ch, d, v.call_addr)
            if fd is not None and fd > 2:
                file_read = True
        (dropped if file_read else kept).append(v)
    f.vulns = kept

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
    f.fmt_sites = _find_fmt_sites(ch, d)
    f.fmt_buf = next((v for (_b, _d, v, _c) in f.fmt_sites if v is not None), None)
    f.echo_leak = _find_echo_vuln(f, ch, d)
    f.prompts = _find_prompts(ch, f, d)
    # ---- v7.4.2 全局写 → 跳 win（缺口 B）：事实先行，策略只消费
    f.global_writes = _find_global_writes(ch, d, f)
    f.global_calls = _find_global_calls(ch, d)
    _audit_facts(ch, d, f, dropped)

    # ---- v7.4.0 守卫层（放在 audit 之后：可扩展 unknowns；异常不影响已有事实）
    from .guard import find_backfills, find_guards
    try:
        f.guards = find_guards(ch, d, f)
    except Exception as exc:
        f.unknowns["guard"] = f"守卫分析异常：{type(exc).__name__}: {exc}"
    try:
        f.backfills = find_backfills(ch, d, f)
    except Exception as exc:
        f.unknowns["backfill"] = f"回填分析异常：{type(exc).__name__}: {exc}"
    for g in f.guards:
        if g.status not in ("solved", "fmt", "none"):
            f.unknowns[f"guard@{g.call:#x}"] = f"{g.status}: {g.reason}"
    for b in f.backfills:
        if b.status != "backfill":
            f.unknowns[f"backfill@{b.call:#x}"] = f"{b.status}: {b.reason}"
    return f


def _read_fd(ch: Challenge, d: "Dis", call_addr: int) -> Optional[int]:
    """`read(fd, …)` 的第一个参数；None = 判定不了。

    v7.3.1：win 剔除规则改成「自己 open 才剔除」之后，
    「win 里只有 read 没有 open」的形态会重新变成漏洞候选。
    若该 read 的 fd 明显不是 0（stdin），说明读的是文件/管道，仍应剔除。
    """
    n = d.by_addr.get(call_addr)
    if n is None:
        return None
    if ch.elf.bits == 64:
        for k in range(n - 1, max(-1, n - 10), -1):
            ins = d.insns[k]
            if ins.mnemonic == "xor" and ins.op_str in ("edi, edi", "rdi, rdi"):
                return 0
            if ins.mnemonic == "mov":
                m = re.match(r"^(?:edi|rdi), (0x[0-9a-f]+|\d+)$", ins.op_str)
                if m:
                    return _imm(m.group(1))
    else:
        for k in range(n - 1, max(-1, n - 10), -1):
            ins = d.insns[k]
            if ins.mnemonic != "push":
                continue
            try:
                return _imm(ins.op_str)      # cdecl 倒序 push：最近的 push 就是 fd
            except Exception:
                return None
    return None


def _scanf_format(ch: Challenge, d: "Dis", call_idx: int) -> Optional[bytes]:
    """scanf 调用点的格式串（用于区分 `%s` 与数字菜单 `%d`）。"""
    for k in range(call_idx - 1, max(-1, call_idx - 9), -1):
        ins = d.insns[k]
        addr = None
        if ins.mnemonic == "lea":
            m = re.match(r"^(?:rsi|esi), \[rip \+ (0x[0-9a-f]+|\d+)\]$", ins.op_str)
            if m:
                addr = ins.address + ins.size + _imm(m.group(1))
        elif ins.mnemonic in ("mov", "push"):
            info = _mov_imm(ins)
            if info:
                addr = info[1]
            elif ins.mnemonic == "push":
                try:
                    addr = _imm(ins.op_str)
                except Exception:
                    addr = None
        if not addr:
            continue
        s = read_cstr(ch, addr, 32)
        if s:
            return s.encode("latin-1", "ignore")
    return None


INPUT_CALLS = {"read", "gets", "fgets", "scanf", "__isoc99_scanf",
               "getchar", "getline"}


def _scanf_addrs(ch: Challenge) -> set:
    """scanf 的桩/符号地址集合（动态 = PLT；静态 = .text 符号）。

    v7.4.2：`.plt` 与 `.plt.sec` 常同时映射同一符号（两个地址），
    调用点可能落在任意一个；必须收全 plt_map，不能只取 `ch.plt(name)`。
    """
    out = {int(a) for a, n in ch.plt_map.items() if n in ("__isoc99_scanf", "scanf")}
    for name in ("__isoc99_scanf", "scanf"):
        s = _static_sym(ch, name)
        if s:
            out.add(int(s))
    return out


def _input_call_addrs(ch: Challenge) -> set:
    """输入函数地址集合（read/gets/fgets/scanf/getchar/getline）。"""
    out = {int(a) for a, n in ch.plt_map.items() if n in INPUT_CALLS}
    for name in INPUT_CALLS:
        s = _static_sym(ch, name)
        if s:
            out.add(int(s))
    return out


def _body_range(d: "Dis", lo: int, hi: int, max_len: int = 400) -> list:
    """[lo, hi) 内的指令（最多 max_len 条）；lo 不在反汇编里返回空。"""
    start = d.by_addr.get(lo)
    if start is None:
        return []
    out = []
    for ins in d.insns[start:start + max_len]:
        if ins.address >= hi:
            break
        out.append(ins)
    return out


_MENU_ITEM = re.compile(r"^\s*[\[(]?([1-9])[.)\]:]\s*(\S.*)$")


def _scan_menu_banners(ch: Challenge) -> dict:
    """常量段里的编号菜单项 {编号: 标签}（v7.4.2 缺口 A）。

    先按 NUL、再按换行切分，覆盖「1.Encrypt\\n2.Decrypt\\n3.Exit」单串多行菜单；
    标签必须含字母或非 ASCII 字节，排除 `1.0` / `1.2.3` 版本串。
    """
    out: dict[int, str] = {}
    for secname in (".rodata", ".data.rel.ro", ".data"):
        sec = ch.elf.get_section_by_name(secname)
        if sec is None or sec.header.sh_size == 0:
            continue
        try:
            data = sec.data()
        except Exception:
            continue
        for chunk in data.split(b"\x00"):
            for line in chunk.split(b"\n"):
                text = line.decode("latin-1", "ignore")
                m = _MENU_ITEM.match(text)
                if not m:
                    continue
                label = m.group(2).strip()
                if not label:
                    continue
                if not (any(c.isalpha() for c in label)
                        or any(ord(c) >= 0x80 for c in label)):
                    continue
                out.setdefault(int(m.group(1)), label)
    return out


def _menu_exit_label(label: str) -> bool:
    low = label.lower()
    return any(k in low for k in ("exit", "quit", "bye"))


def _dispatch_evidence(body: list, after: int) -> bool:
    """输入调用之后 60 条内出现「≥2 个不同的小常数 cmp/sub」或「计算跳转」。

    这是「输入值被拿去分派」的证据：单看输入调用会把长度输入误当菜单，
    所以横幅与分派证据缺一不可。
    """
    consts = set()
    for ins in body[after + 1:after + 61]:
        if ins.mnemonic in ("cmp", "sub"):
            m = re.search(r",\s*(0x[0-9a-f]+|\d+)\s*$", ins.op_str)
            if not m:
                continue
            try:
                val = _imm(m.group(1))
            except Exception:
                continue
            if 1 <= val <= 9:
                consts.add(val)
        if ins.mnemonic == "jmp" and re.search(r"\[[^\]]*\*[1248][^\]]*\]", ins.op_str):
            return True
    return len(consts) >= 2


def _find_numeric_menu(ch: Challenge, d: "Dis", entries: list,
                       vuln_funcs: set) -> dict:
    """数字菜单：返回 {菜单函数入口: [b"1\\n", b"2\\n", b""]}。

    两条路径（结果合并；末尾永远保留空前缀，避免封死「不需要菜单」的尝试）：

    1. **v7.3.1 旧路径**：`scanf("%d")` 所在函数直接 call 进含 sink 的函数。
    2. **v7.4.2 新路径**（缺口 A）：同一函数同时满足
       任意输入调用（覆盖 `read + atoi`、helper 读选择）
       + 常量段有 ≥2 个编号横幅
       + 输入调用后 60 条内有 ≥2 个 [1..9] 小常数比较或跳表；
       候选由横幅编号导出（跳过 exit/quit/bye，最多 4 个）。
    """
    out: dict[int, list] = {}

    # ---- 路径 1：scanf("%d") + 直接 dispatch 进含 sink 的函数
    scanf_addrs = _scanf_addrs(ch)
    vuln_funcs = {e for e in (vuln_funcs or set()) if e}
    if scanf_addrs and vuln_funcs:
        dispatchers: dict[int, list[int]] = {}
        for n, ins in enumerate(d.insns):
            if ins.mnemonic != "call" or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != X86_OP_IMM or int(op.imm) not in vuln_funcs:
                continue
            dispatchers.setdefault(_entry_of(ins.address, entries), []).append(n)
        for entry in dispatchers:
            body = _body_range(d, entry, entry + 0x100000, 400)
            for n, ins in enumerate(body):
                if ins.mnemonic != "call" or not ins.operands:
                    continue
                op = ins.operands[0]
                if op.type != X86_OP_IMM or int(op.imm) not in scanf_addrs:
                    continue
                fmt = _scanf_format(ch, d, d.by_addr.get(ins.address, 0))
                if fmt and b"%d" in fmt:
                    bucket = out.setdefault(entry, [])
                    for c in (b"1\n", b"2\n", b""):
                        if c not in bucket:
                            bucket.append(c)
                    break

    # ---- 路径 2：任意输入调用 + 编号横幅 + 小常数分派/跳表
    inputs = _input_call_addrs(ch)
    banners = _scan_menu_banners(ch)
    if not inputs or len(banners) < 2:
        return out
    picked = [i for i in sorted(banners) if not _menu_exit_label(banners[i])]
    if not picked:
        return out
    cands = [f"{i}\n".encode() for i in picked[:4]] + [b""]
    for pos, entry in enumerate(entries):
        hi = entries[pos + 1] if pos + 1 < len(entries) else entry + 0x100000
        body = _body_range(d, entry, hi)
        if not body:
            continue
        hit = None
        for n, ins in enumerate(body):
            if ins.mnemonic == "call" and ins.operands \
                    and ins.operands[0].type == X86_OP_IMM \
                    and int(ins.operands[0].imm) in inputs:
                hit = n
                break
        if hit is None or not _dispatch_evidence(body, hit):
            continue
        bucket = out.setdefault(entry, [])
        for c in cands:
            if c not in bucket:
                bucket.append(c)
    return out


def _buf_is_global(ch: Challenge, d: "Dis", call_addr: int) -> Optional[int]:
    """调用点附近的写入目标是否为可写段的全局缓冲区（v7.3.1）。

    用于把「算不出栈偏移」拆成两种完全不同的原因：
      * 写入目标本来就是全局变量（题三 `scanf("%s", 0x6010c0)`）→ 无栈溢出可谈；
      * 真的没看懂帧布局 → 才叫 Unknown。
    """
    n = d.by_addr.get(call_addr)
    if n is None:
        return None
    for k in range(n - 1, max(-1, n - 12), -1):
        ins = d.insns[k]
        if ins.mnemonic == "mov":
            info = _mov_imm(ins)
            if info and _looks_writable(ch, info[1]):
                return info[1]
        elif ins.mnemonic == "lea":
            # x64 PIE / -no-pie 的全局地址常以 `lea rdi, [rip+disp]` 传入
            m = re.match(r"^(r[a-z0-9]+|e[a-z]{2}), \[rip \+ (0x[0-9a-f]+|\d+)\]$",
                         ins.op_str)
            if m:
                val = int(ins.address) + int(ins.size) + _imm(m.group(2))
                if _looks_writable(ch, val):
                    return val
        elif ins.mnemonic == "push":
            try:
                val = _imm(ins.op_str)
            except Exception:
                continue
            if _looks_writable(ch, val):
                return val
    return None


def _find_global_writes(ch: Challenge, d: "Dis", f: "Facts") -> list:
    """(buf, sink, call, limit)：写全局缓冲区的 sink（v7.4.2 缺口 B）。

    只收 `offset is None` 的写入点——能推出栈偏移的按栈溢出处理，
    归到全局写会让「本来能打的题」多出无效计划。
    """
    out = []
    for v in f.vulns:
        if v.offset is not None:
            continue
        buf = _buf_is_global(ch, d, v.call_addr)
        if buf:
            out.append((int(buf), v.sink, int(v.call_addr), v.size_limit))
    return out


def _mem_slot_addr(ins) -> Optional[int]:
    """指令操作数里的内存槽地址（i386 绝对 / x64 rip 相对）；不是内存槽返回 None。"""
    m = re.search(r"\[rip ([+-]) (0x[0-9a-f]+|\d+)\]", ins.op_str)
    if m:
        delta = _imm(m.group(2))
        return int(ins.address) + int(ins.size) + (delta if m.group(1) == "+" else -delta)
    m = re.search(r"\[(0x[0-9a-f]+)\]", ins.op_str)
    if m:
        return int(m.group(1), 16)
    return None


def _same_reg(a: str, b: str) -> bool:
    """rax/eax、rdi/edi 这类同一寄存器的不同位宽写法。"""
    if a == b:
        return True
    return len(a) >= 3 and len(b) >= 3 and a[1:] == b[1:]


def _call_slot(d: "Dis", n: int) -> Optional[int]:
    """第 n 条 call/jmp 的间接调用槽地址（v7.4.2）。"""
    ins = d.insns[n]
    if ins.mnemonic not in ("call", "jmp") or not ins.operands:
        return None
    op = ins.operands[0]
    if op.type == X86_OP_MEM:
        return _mem_slot_addr(ins)
    if op.type != X86_OP_REG:
        return None
    reg = ins.reg_name(op.reg)
    for k in range(n - 1, max(-1, n - 6), -1):
        prev = d.insns[k]
        if prev.mnemonic != "mov" or len(prev.operands) < 2:
            continue
        dst = prev.operands[0]
        if dst.type != X86_OP_REG or not _same_reg(prev.reg_name(dst.reg), reg):
            continue
        if prev.operands[1].type != X86_OP_MEM:
            continue
        return _mem_slot_addr(prev)
    return None


def _find_global_calls(ch: Challenge, d: "Dis") -> list:
    """(slot, call)：可写全局槽上的间接调用（v7.4.2 缺口 B）。

    覆盖 `call/jmp [0x…]`、`call/jmp [rip+disp]`、`call/jmp reg`
    （回看 5 条内 `mov reg,[…]`）；槽必须是可写段。
    """
    out, seen = [], set()
    for n, ins in enumerate(d.insns):
        if ins.mnemonic not in ("call", "jmp"):
            continue
        slot = _call_slot(d, n)
        if slot is None or slot in seen or not _looks_writable(ch, slot):
            continue
        seen.add(slot)
        out.append((int(slot), int(ins.address)))
    return out


def _global_win_pairs(f: "Facts") -> list:
    """可用的 (gap, buf, sink, slot) 对；距离超过可写窗口的不算证据。"""
    out = []
    for buf, sink, _call, limit in getattr(f, "global_writes", []) or []:
        span = min(limit or 0x400, 0x400)
        for slot, _icall in getattr(f, "global_calls", []) or []:
            gap = slot - buf
            if 0 < gap <= span:
                out.append((gap, buf, sink, slot))
    return out


def _funcs_with_file_open(ch: Challenge, d: "Dis", entries: list) -> set:
    """含 open/fopen/openat 调用的函数入口集合（用于判定「win 自己读文件」）。"""
    tgts = {a for a, n in ch.plt_map.items()
            if n in ("open", "fopen", "openat", "fopen64", "open64")}
    if not tgts:
        return set()
    out = set()
    for ins in d.insns:
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM or int(op.imm) not in tgts:
            continue
        out.add(_entry_of(ins.address, entries))
    return out


def _fmt_suspect(d: "Dis", ch: Challenge) -> bool:
    """printf 前 8 条内有栈缓冲区 lea —— 可能漏判的 fmt 点（只用于登记 Unknown）。"""
    p = ch.plt("printf")
    if not p:
        return False
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM or int(op.imm) != p:
            continue
        for k in range(n - 1, max(-1, n - 9), -1):
            prev = d.insns[k]
            if prev.mnemonic == "lea" and any(
                    b in prev.op_str for b in ("[rbp", "[ebp", "[rsp", "[esp")):
                return True
    return False


def _audit_facts(ch: Challenge, d: "Dis", f: Facts, dropped: list) -> None:
    """事实自检（v7.3.0）：把「我没算出来」与「确认不存在」分开。

    三态：Known 有值即结束 / Absent 确认不存在则静默 / Unknown 登记到 f.unknowns。
    登记的 Unknown 会由 orchestrator 在零计划时拼成 UNRESOLVED 原因，
    下游策略**不得**据此盲猜（_offsets 的无证据兜底已默认关闭）。
    """
    if not ch.plt_map:
        if ch.prot.static:
            # v7.4.2 缺陷 C1：静态链接本来就没有 PLT，不能当「桩形态未识别」误诊
            if not f.vulns:
                f.unknowns["sink"] = (
                    "静态链接：无 PLT（正常）；symbol 直呼未定位到可溢出调用点")
        else:
            f.unknowns["sink"] = "PLT 映射为空：桩形态未识别（如 32 位 PIC 的 jmp [ebx+N]）"
    elif not f.vulns:
        if dropped:
            f.unknowns["sink"] = "sink 命中但被 win 规则整批剔除：" + \
                ", ".join(f"{v.sink}@{hex(v.call_addr)}" for v in dropped[:3])
        else:
            f.unknowns["sink"] = "PLT 已解析但无 sink 调用点命中"

    for v in f.vulns:
        if v.offset is None:
            g = _buf_is_global(ch, d, v.call_addr)
            if g:
                f.unknowns[f"offset@{hex(v.call_addr)}"] = (
                    f"{v.sink} 写入目标是全局缓冲区 {hex(g)}"
                    "（不存在栈溢出，需覆写全局/走逻辑分支）")
            else:
                f.unknowns[f"offset@{hex(v.call_addr)}"] = \
                    f"{v.sink} 的缓冲区→返回址距离未识别（帧布局）"
        if v.offset and v.size_limit and v.size_limit <= v.offset:
            f.unreachable.append({
                "sink": v.sink, "call": v.call_addr,
                "offset": v.offset, "limit": v.size_limit,
            })

    decoys = [w for w in f.wins if w.kind == "decoy"]
    if decoys and not any(w.kind in ("shell", "flag") for w in f.wins):
        f.unknowns["win"] = "仅存在诱饵 win（打中也不产出 flag）：" + \
            ", ".join(w.evidence for w in decoys[:2])

    # v7.4.2 缺口 B：全局写存在且有 shell win，但没有可用的 (buf, slot) 对 —— 归因
    if f.global_writes and f.shell_win and not _global_win_pairs(f):
        buf = f.global_writes[0][0]
        if not f.global_calls:
            f.unknowns["global_win"] = (
                f"有全局写 {hex(buf)} 且有 shell win，但未找到可写的全局间接调用槽")
        else:
            nearest = min((slot - buf for slot, _c in f.global_calls
                           if slot > buf), default=None)
            f.unknowns["global_win"] = (
                f"全局写 {hex(buf)} 到最近间接槽的距离 "
                f"{hex(nearest) if nearest is not None else 'n/a'} 超出 0x400 可写窗口")

    if f.fmt_buf is None and _fmt_suspect(d, ch):
        f.unknowns["fmt"] = "printf 前有栈缓冲区 lea，但未确认该缓冲来自用户输入"



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


def _find_interact(d: Dis) -> dict:
    """菜单式程序：`cmp al,'w'; jne <跳过 call>; call write_note` —— 必须发 'w' 才进得去。

    返回 {被调用函数入口: [b"w\n"]}。只认「相等则落进 call」的方向（jne/jnz 向前跳）。
    """
    out: dict[int, list] = {}
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        if ins.operands[0].type != X86_OP_IMM:
            continue
        target = int(ins.operands[0].imm)
        for k in range(n - 1, max(-1, n - 14), -1):
            p = d.insns[k]
            if p.mnemonic != "cmp":
                continue
            m = re.match(r"^(?:al|eax|byte ptr \[rbp [-+] (?:0x[0-9a-f]+|\d+)\]), (0x[0-9a-f]+|\d+)$",
                         p.op_str)
            if not m:
                break
            try:
                val = _imm(m.group(1))
            except Exception:
                break
            if not (0x20 <= val < 0x7F):
                break
            nxt = d.insns[k + 1] if k + 1 < len(d.insns) else None
            if nxt is None or nxt.mnemonic not in ("jne", "jnz", "je", "jz"):
                break
            fwd = True
            try:
                fwd = int(nxt.operands[0].imm) > int(ins.address)
            except Exception:
                pass
            # jne 向前跳 => 相等就落进 call；je 向前跳 => 不等才落进 call（这种没有确定的字符）
            if (nxt.mnemonic in ("jne", "jnz")) and fwd:
                out.setdefault(target, []).append(bytes([val]) + b"\n")
            break
    return out


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


def _static_sym(ch: Challenge, name: str) -> Optional[int]:
    """静态二进制里的函数符号地址（只认 .text）；动态/未定义符号返回 None。"""
    addr = ch.var(name)
    if addr and _in_text(ch, int(addr)):
        return int(addr)
    return None


_SINK_ALIASES = {
    "gets": ("gets", "_IO_gets"),
    "fgets": ("fgets", "_IO_fgets"),
    "scanf": ("__isoc99_scanf", "scanf"),
    "__isoc99_scanf": ("__isoc99_scanf", "scanf"),
    "read": ("read", "__libc_read"),
}

_STATIC_LIB_STOP = set(SINKS) | {
    "printf", "puts", "fwrite", "write", "system", "malloc", "free",
    "strlen", "strcmp", "strncmp", "strcpy", "strcat", "sprintf",
    "memcpy", "memmove", "atoi", "exit", "abort", "fprintf", "snprintf",
    "__libc_start_main", "open", "fopen", "fread", "fputs",
}


def _static_reachable(d: "Dis", entries: list, root: int, depth: int = 2) -> set:
    """从 main 出发 depth 层直接 call 可达的函数入口（静态 win 扫描范围）。

    静态链接的 .text 里包含整个 libc；不限范围会把 `do_system` 这类内部函数
    误当 win，因此只扫用户代码邻近的两层调用图。
    """
    idx = {e: i for i, e in enumerate(entries)}
    if root not in idx:
        return {root}
    eset = set(entries)
    seen, frontier = {root}, {root}
    for _ in range(depth):
        nxt = set()
        for e in frontier:
            i = idx[e]
            hi = entries[i + 1] if i + 1 < len(entries) else e + 0x100000
            for ins in _body_range(d, e, hi):
                if ins.mnemonic == "call" and ins.operands \
                        and ins.operands[0].type == X86_OP_IMM:
                    t = int(ins.operands[0].imm)
                    if t in eset and t not in seen:
                        nxt.add(t)
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return seen


def _static_vulns(ch: Challenge, d: "Dis", entries: list) -> list:
    """静态链接：main 及一层直接被调函数里对 sink 符号的直呼（v7.4.2c1）。

    只在既有 `_static_vuln`（_start→main 的窄 fallback）没找到 vuln 时调用，
    ch10_static32 的现有路径优先级不变。不进入库函数体（按符号名停表），
    否则 `gets` 内部的 `read` 会被误当成用户漏洞点。
    """
    sink_addrs: dict[int, str] = {}
    for sink in SINKS:
        for alias in _SINK_ALIASES.get(sink, (sink,)):
            a = _static_sym(ch, alias)
            if a:
                sink_addrs.setdefault(a, sink)
                break
    if not sink_addrs:
        return []
    root = ch.var("main") or _derive_main(ch, d)
    if not root:
        return []
    idx = {e: i for i, e in enumerate(entries)}
    if root not in idx:
        return []
    stop = set(sink_addrs)
    for name, addr in ch.elf.symbols.items():
        if name in _STATIC_LIB_STOP and addr:
            stop.add(int(addr))

    def body_of(e: int) -> list:
        i = idx[e]
        hi = entries[i + 1] if i + 1 < len(entries) else e + 0x100000
        return _body_range(d, e, hi)

    scan = {root}
    for ins in body_of(root):
        if ins.mnemonic == "call" and ins.operands \
                and ins.operands[0].type == X86_OP_IMM:
            t = int(ins.operands[0].imm)
            if t in idx and t not in stop:
                scan.add(t)

    out = []
    for e in sorted(scan):
        body = body_of(e)
        for n, ins in enumerate(body):
            if ins.mnemonic != "call" or not ins.operands:
                continue
            op = ins.operands[0]
            if op.type != X86_OP_IMM:
                continue
            t = int(op.imm)
            sink = sink_addrs.get(t)
            if sink is None:
                continue
            win = body[max(0, n - 25):n + 1]
            offset, disp, limit = _derive_offset(ch, win, sink)
            out.append(Vuln(sink, ins.address, disp, offset, limit, t))
    return out


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


def _derive_main(ch: Challenge, d: Dis) -> Optional[int]:
    """stripped 题从 _start 推导 main：`lea rdi,[imm]`（或 mov edi,imm）→
    call __libc_start_main@plt，imm 即 main。

    repeater 实测：entry=0x4006a0，`lea rdi,[0x4007d9]; call __libc_start_main`
    → main=0x4007d9。推不出来返回 None（不要瞎猜，铁律 5）。
    """
    lsm = ch.plt("__libc_start_main")
    if not lsm:
        return None
    entry = ch.elf.entry
    n0 = next((i for i, ins in enumerate(d.insns) if ins.address >= entry), None)
    if n0 is None:
        return None
    for i in range(n0, min(n0 + 20, len(d.insns))):
        ins = d.insns[i]
        if ins.mnemonic == "call" and ins.operands and \
                ins.operands[0].type == X86_OP_IMM and ins.operands[0].imm == lsm:
            # 回看这条 call 之前 10 条，找喂 rdi 的 lea/mov
            for k in range(i - 1, max(-1, i - 11), -1):
                prev = d.insns[k]
                if prev.mnemonic == "lea":
                    info = _lea_disp(prev)
                    if info and info[2] in ("rdi", "edi"):
                        return info[1] if info[1] > 0 else None
                if prev.mnemonic == "mov" and \
                        prev.op_str.startswith(("rdi, ", "edi, ")):
                    op = prev.operands[1] if len(prev.operands) > 1 else None
                    if op is not None and op.type == X86_OP_IMM:
                        return int(op.imm)
        # 走出 _start（遇到 ret）就停
        if ins.mnemonic == "ret":
            break
    return None


def _func_entries(ch: Challenge, d: Dis) -> list[int]:
    """枚举函数入口：符号表 ∪ 所有 call 的直接目标 ∪ entrypoint ∪ 推导的 main。"""
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
    # stripped 时 main 不在符号表里：从 _start 推导，并注入 symbols 让 ch.var("main") 生效
    if ch.var("main") == 0:
        m = _derive_main(ch, d)
        if m and lo <= m < hi:
            entries.add(m)
            ch.elf.symbols["main"] = m
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


def _alt_entry(body: list, lo: int) -> int:
    """跳过 endbr64/push rbp/mov rbp,rsp/nop 后的入口。

    ret 进入函数时 rsp 比 call 进入高 8 字节，`system` 里的 movaps 会崩；
    从 alt 进去就对齐了。
    """
    alt = lo
    for q in body[:8]:
        if (q.mnemonic in ("endbr64", "endbr32", "nop")
                or (q.mnemonic == "push" and q.op_str == "rbp")
                or (q.mnemonic == "mov" and q.op_str.replace(" ", "") == "rbp,rsp")):
            alt = int(q.address) + int(q.size)
        else:
            break
    return alt if alt != lo else 0


def _win_kind(text: str) -> Optional[str]:
    """win 实参的语义分类（v7.4.2 缺陷 D）：shell / flag / decoy / None。

    旧判据 `endswith("sh")` 会把 `fish`、`push`、`/bbbb…?/sh` 判成 shell。
    新判据只认路径合法且可执行的 sh：
      * 精确白名单：`sh` / `/bin/sh` / `/bin//sh` / `/usr/bin/sh`；
      * 或 basename == `sh` 且 dirname 在当前镜像里真实存在。
    不匹配时按 flag / decoy 命令词继续判，仍不匹配则丢弃（不往假地址跳）。
    """
    t = text.strip()
    low = text.lower()
    shell = t in ("sh", "/bin/sh", "/bin//sh", "/usr/bin/sh")
    if not shell and "/" in t:
        head, _sep, base = t.rpartition("/")
        shell = base == "sh" and bool(head) and os.path.isdir(head)
    if shell:
        return "shell"
    if any(low.startswith(x) or x in low for x in FILE_READ_CMD):
        return "flag"      # system("cat /flag")：真读文件
    if any(low.startswith(x) or x in low for x in NON_SHELL_CMD):
        # v7.3.1：system("echo flag") 只打印常量，不读文件 —— 是诱饵不是 win。
        return "decoy"
    return None


def _find_wins(ch: Challenge, d: Dis) -> list[Win]:
    """找「函数体里直接 system/execve 一个 shell 字符串」的函数。"""
    wins: list[Win] = []
    targets = {}
    for addr, name in ch.plt_map.items():
        if name in ("system", "execve", "execl", "execv", "execvp", "popen"):
            targets[addr] = name
    # 没有 system/execve 也不能直接放弃：还有一种 win 是自己 open+puts 打印 flag
    _io_in = {a for a, n in ch.plt_map.items() if n in ("open", "fopen", "fread", "read")}
    _io_out = {a for a, n in ch.plt_map.items() if n in ("puts", "printf", "write", "fwrite", "fputs")}
    entries = _func_entries(ch, d)
    static_scan = None
    if ch.prot.static:
        # v7.4.2c1：静态题没有 PLT，只能按符号地址识别直呼。
        # 扫描范围限 main 两层内可达的用户函数，避免把静态 libc 内部
        # （如 do_system）误当 win；拿不到 main 就不扫（宁缺勿滥）。
        for name in ("system", "execve", "execl", "execv", "execvp", "popen"):
            a = _static_sym(ch, name)
            if a:
                targets.setdefault(a, name)
        for name in ("open", "fopen", "openat", "read", "fread"):
            a = _static_sym(ch, name)
            if a:
                _io_in.add(a)
        for name in ("puts", "printf", "write", "fwrite", "fputs"):
            a = _static_sym(ch, name)
            if a:
                _io_out.add(a)
        root = ch.var("main") or _derive_main(ch, d)
        static_scan = _static_reachable(d, entries, root) if root else set()
    if not targets and not (_io_in and _io_out):
        return wins
    bounds = list(zip(entries, entries[1:] + [ch.elf.entry + 0x100000]))
    for lo, hi in bounds:
        if static_scan is not None and lo not in static_scan:
            continue
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
            kind = _win_kind(text)
            if kind is None:
                continue
            wins.append(Win(lo, kind, f"{targets[op.imm]}(\"{text}\")",
                            _alt_entry(body, lo), arg_addr=addr))
    # ---- 还有一种 win：程序自己 open()/fopen() 读文件再 puts()/write() 打出来
    io_in, io_out = _io_in, _io_out
    if io_in and io_out:
        for lo, hi in bounds:
            start = d.by_addr.get(lo)
            if start is None:
                continue
            body = []
            for ins in d.insns[start:start + 400]:
                if ins.address >= hi:
                    break
                body.append(ins)
            has_in = has_out = has_flag = False
            for ins in body:
                if ins.mnemonic != "call" or not ins.operands:
                    continue
                if ins.operands[0].type != X86_OP_IMM:
                    continue
                t = int(ins.operands[0].imm)
                if t in io_in:
                    has_in = True
                if t in io_out:
                    has_out = True
            for ins in body:
                if ins.mnemonic != "lea":
                    continue
                m = re.match(r"^[re][a-z0-9]*, \[rip \+ (0x[0-9a-f]+|\d+)\]$", ins.op_str)
                if not m:
                    continue
                addr = ins.address + ins.size + _imm(m.group(1))
                txt = read_cstr(ch, addr) or ""
                if "flag" in txt.lower():
                    has_flag = True
                    break
            if has_in and has_out and has_flag and not any(w.addr == lo for w in wins):
                wins.append(Win(lo, "flag", "open+print flag (self-read)", _alt_entry(body, lo)))
                continue
            # 门槛形态： `mov [rip+X], imm` 紧跟着 call 到上面那个 win
            for n, ins in enumerate(body):
                if ins.mnemonic != "mov" or not ins.op_str.startswith(("qword ptr [rip", "dword ptr [rip")):
                    continue
                for q in body[n + 1:n + 10]:
                    if q.mnemonic != "call" or not q.operands:
                        continue
                    if q.operands[0].type == X86_OP_IMM and int(q.operands[0].imm) in {w.addr for w in wins}:
                        # 真正能跳的入口是「把值装进寄存器」那条：mov eax,imm; mov [rip+X],rax
                        entry = int(ins.address)
                        prev = body[n - 1] if n > 0 else None
                        if prev is not None and prev.mnemonic == "mov":
                            p_reg = prev.op_str.split(",")[0].strip()
                            d_reg = ins.op_str.split(",")[-1].strip()
                            if p_reg[-2:] == d_reg[-2:]:
                                entry = int(prev.address)
                        if not any(w.addr == entry for w in wins):
                            wins.append(Win(entry, "flag",
                                            f"set global + call win({hex(int(q.operands[0].imm))})"))
                        break

    # 去重：同一地址只留一条（优先 shell）
    uniq: dict[int, Win] = {}
    for w in wins:
        if w.addr not in uniq or (uniq[w.addr].kind != "shell" and w.kind == "shell"):
            uniq[w.addr] = w
    # 排序：shell 优先；同为 flag 时「先设全局再 call」比裸 win 函数更好用
    # （裸函数可能被全局校验挡住，进去只会打印 "lock closed" 之类）
    # hints 命中（符号名像 win）的入口插队（v7.2.0：只做排序证据，不做判定）
    hint_addrs = set()
    for name, addr in getattr(ch, "elf").symbols.items():
        low = name.lower()
        if any(k in low for k in ("getflag", "backdoor", "shell", "win", "flag")) \
                and addr and _in_text(ch, int(addr)):
            hint_addrs.add(int(addr))
    def _rank(w: Win):
        return (0 if w.kind == "shell" else 1,
                0 if "set global" in w.evidence else 1,
                0 if w.addr in hint_addrs else 1,
                w.addr)
    return sorted(uniq.values(), key=_rank)


def _in_text(ch: Challenge, addr: int) -> bool:
    text = ch.elf.get_section_by_name(".text")
    if not text:
        return False
    return text.header.sh_addr <= addr < text.header.sh_addr + text.header.sh_size


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


def _find_fmt_sites(ch: Challenge, d: Dis) -> list:
    """检测所有 printf(用户缓冲区) 调用点 —— [(基址, 位移, rbp 相对位移|None, call)]。

    判据与 v7.3.1 的 `_find_fmt` 相同（只认栈参真的来自用户缓冲的 printf；
    直接 push 常量串地址的调用不算）。差别是本函数收集**全部**站点：
    v7.4.0 守卫层按「缓冲基址+位移」匹配 printf 站点（题七 buf=esp+0x2c
    → printf 在 0x80485ad），旧逻辑只返回第一个站点的 rbp 相对位移。
    """
    p = ch.plt("printf")
    sites: list = []
    if not p:
        return sites
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM or op.imm != p:
            continue
        hit = None
        for k in range(n - 1, max(-1, n - 9), -1):
            prev = d.insns[k]
            if prev.mnemonic == "lea":
                info = _lea_disp(prev)
                if info:
                    base, disp = info[0], info[1]
                    dest = info[2] if len(info) > 2 else ""
                    val = None
                    if base in ("rbp", "ebp"):
                        val = -disp
                    else:
                        # v7.3.1：esp 相对帧（`and esp,0xfffffff0` 之后 buf 在 [esp+X]）
                        # 换算成「相对 rbp 的距离」= 帧大小 + 字长 - disp；
                        # 帧大小推定不出来时仍记录站点（守卫匹配只需要基址+位移）
                        fs = _frame_size(d.insns[max(0, k - 40):k + 1])
                        if fs is not None:
                            val = fs + ch.wordsize - disp
                    if val is not None and val <= 0:
                        continue
                    if dest in ("rdi", "edi") or \
                            _flows_to_rdi(d, k, n, dest) or \
                            _pushed_for_call(d, k, n, dest):
                        hit = (base, disp, val, int(ins.address))
                        break
                continue
            if prev.mnemonic == "push":
                # i386：printf 最近一次 push 若是立即数（常量串地址）→ 不是用户 buf
                if prev.operands and prev.operands[0].type == X86_OP_IMM:
                    break
        if hit is not None:
            sites.append(hit)
    return sites


def _flows_to_rdi(d: Dis, lea_idx: int, call_idx: int, dest: str) -> bool:
    """lea dest 之后、call printf 之前，dest 是否被搬进 rdi（amd64）。

    两个约束（last-write-wins：printf 真正吃到的 rdi 是**最后一次**写入的值）：
      * ret2win：`lea rax,[rbp-0x40]; lea rax,[rip+…]; mov rdi,rax; call printf`
        最后一次写 rdi 的 rax 是常量串 → 否；
      * repeater：`lea rax,[rbp-0x30]; mov rdi,rax; call puts; mov edi,常量; call printf`
        最后一次写 rdi 的是常量（且中间隔着 call puts）→ 否。
    """
    if not dest:
        return False
    flows = False      # rdi 当前的值是否来自用户 buf
    alive = True       # dest 是否仍持有 lea 写入的那个值
    for j in range(lea_idx + 1, call_idx):
        ins = d.insns[j]
        if ins.mnemonic == "call":
            flows = False         # call 用掉/破坏 rdi，之前的赋值不算数
            continue
        if ins.mnemonic == "mov" and ins.op_str.startswith(("rdi, ", "edi, ")):
            src = ins.op_str.split(", ", 1)[1]
            flows = alive and src == dest   # last write wins
            continue
        if ins.mnemonic in ("mov", "lea") and \
                ins.op_str.split(",")[0].strip() == dest:
            alive = False         # dest 被重写 → lea 的值已死
    return flows


def _pushed_for_call(d: Dis, lea_idx: int, call_idx: int, dest: str) -> bool:
    """lea dest 之后、call printf 之前，dest 是否被当成栈参传给 printf（i386）。

    两种写法都算：
      * `push eax`                        —— gcc 默认；
      * `mov dword ptr [esp], eax`        —— v7.3.1 补：`and esp,0xfffffff0` 之后
        编译器改用预留槽位写参（题七 `lea eax,[esp+0x2c]; mov [esp],eax; call printf`）。
    """
    if not dest:
        return False
    slot = re.compile(r"^dword ptr \[esp(?: ?\+ ?(?:0x[0-9a-f]+|\d+))?\], %s$" % re.escape(dest))
    for j in range(lea_idx + 1, call_idx):
        ins = d.insns[j]
        if ins.mnemonic == "push" and ins.op_str == dest:
            return True
        if ins.mnemonic == "mov" and slot.match(ins.op_str):
            return True
    return False
