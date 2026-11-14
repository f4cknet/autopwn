"""题目模型：准备可运行副本、解析保护、定位 libc。"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from pwn import ELF, context

# 32 位运行所需的 i386 库路径由容器提供；这里只做存在性检查
LIBC64 = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC32 = "/lib/i386-linux-gnu/libc.so.6"


@dataclass
class Protections:
    arch: str
    bits: int
    endian: str
    pie: bool
    canary: bool
    nx: bool
    relro: str
    static: bool

    def as_dict(self) -> dict:
        return {
            "arch": f"{self.arch}/{self.bits}",
            "pie": self.pie,
            "canary": self.canary,
            "nx": self.nx,
            "relro": self.relro,
            "static": self.static,
        }

    def __str__(self) -> str:
        return (f"{self.arch}{self.bits} pie={self.pie} canary={self.canary} "
                f"nx={self.nx} relro={self.relro} static={self.static}")


class Challenge:
    """一道 pwn 题目。

    目录约定（bench/<name>/）:
        bin            目标二进制
        libc/          可选，题目自带 libc.so.6 / ld-*.so
        .run/          运行时副本（自动生成，patchelf 处理过的 bin）
    """

    def __init__(self, path: str, libc: Optional[str] = None,
                 ld: Optional[str] = None, workdir: Optional[str] = None,
                 host: Optional[str] = None, port: Optional[int] = None,
                 ssl: bool = False, sni: Optional[str] = None):
        self.src = os.path.abspath(path)
        if os.path.isdir(self.src):
            self.dir = self.src
            self.bin_src = os.path.join(self.dir, "bin")
            self.name = os.path.basename(self.dir.rstrip("/\\")) or "challenge"
            self.run_dir = workdir or os.path.join(self.dir, ".run")
        else:
            # 裸二进制：名字取文件名，运行副本放 <name>.run/，不要污染父目录
            self.dir = os.path.dirname(self.src)
            self.bin_src = self.src
            self.name = os.path.splitext(os.path.basename(self.src))[0] or "challenge"
            self.run_dir = workdir or os.path.join(self.dir, f".{self.name}.run")

        self.libc_path = libc or self._auto_libc()
        self.ld_path = ld or self._auto_ld()
        self.run_bin = os.path.join(self.run_dir, "bin")
        self.host = host
        self.port = port
        self.ssl = bool(ssl)
        self.sni = sni or (host if ssl else None)
        self._prepared = False

        self.elf: ELF = None          # type: ignore
        self.libc_elf: Optional[ELF] = None
        self.prot: Protections = None  # type: ignore
        self.notes: list[str] = []
        # v7.3.0：无证据时的盲枚举偏移，默认关闭；由 CLI --allow-brute 打开并计入盲试占比
        self.allow_brute: bool = False

    # ------------------------------------------------------------------ 发现
    def _auto_libc(self) -> Optional[str]:
        for cand in ("libc.so.6", "libc-2.31.so", "libc-2.27.so", "libc-2.23.so"):
            for base in (os.path.join(self.dir, "libc"), self.dir):
                p = os.path.join(base, cand)
                if os.path.exists(p):
                    return p
        return None

    def _auto_ld(self) -> Optional[str]:
        base = os.path.join(self.dir, "libc")
        if os.path.isdir(base):
            for f in sorted(os.listdir(base)):
                if f.startswith("ld-") and f.endswith(".so"):
                    return os.path.join(base, f)
        return None

    # ------------------------------------------------------------------ 准备
    def prepare(self) -> "Challenge":
        if self._prepared:
            return self
        os.makedirs(self.run_dir, exist_ok=True)
        shutil.copy2(self.bin_src, self.run_bin)
        os.chmod(self.run_bin, 0o755)

        if self.libc_path and self.ld_path:
            libc_dir = os.path.join(self.run_dir, "lib")
            os.makedirs(libc_dir, exist_ok=True)
            shutil.copy2(self.libc_path, os.path.join(libc_dir, "libc.so.6"))
            shutil.copy2(self.ld_path, os.path.join(libc_dir, "ld.so"))
            os.chmod(os.path.join(libc_dir, "ld.so"), 0o755)
            for cmd in (
                ["patchelf", "--set-interpreter", os.path.join(libc_dir, "ld.so"), self.run_bin],
                ["patchelf", "--set-rpath", libc_dir, self.run_bin],
            ):
                try:
                    subprocess.run(cmd, capture_output=True, timeout=30)
                except Exception as exc:  # pragma: no cover
                    self.notes.append(f"patchelf failed: {exc}")
            self.libc_path = os.path.join(libc_dir, "libc.so.6")
            self.notes.append("patched interpreter -> 题目自带 libc")

        self.elf = ELF(self.run_bin, checksec=False)
        if self.libc_path:
            try:
                self.libc_elf = ELF(self.libc_path, checksec=False)
            except Exception:
                self.libc_elf = None
        if self.libc_elf is None:
            default = LIBC32 if self.elf.bits == 32 else LIBC64
            try:
                self.libc_elf = ELF(default, checksec=False)
            except Exception:
                self.libc_elf = None

        self.prot = Protections(
            arch=self.elf.arch,
            bits=self.elf.bits,
            endian=self.elf.endian,
            pie=bool(self.elf.pie),
            canary=bool(self.elf.canary),
            nx=bool(self.elf.nx) if self.elf.nx is not None else True,
            relro=str(self.elf.relro),
            static=self.elf.get_section_by_name(".interp") is None,
        )
        context.binary = self.elf
        context.log_level = "error"
        self.plt_map, self.name2plt = _build_plt_map(self.elf)
        self._prepared = True
        return self

    # ------------------------------------------------------------------ 工具
    @property
    def wordsize(self) -> int:
        return self.elf.bits // 8

    def p64(self, v: int) -> bytes:
        return (v & 0xFFFFFFFF if self.elf.bits == 32 else v).to_bytes(self.wordsize, "little")

    def p32(self, v: int) -> bytes:
        return (v & 0xFFFFFFFF).to_bytes(4, "little")

    def var(self, name: str, default: int = 0) -> int:
        """符号地址，缺失时返回 default（PIE 下为偏移）。"""
        return int(self.elf.symbols.get(name, default) or default)

    def plt(self, name: str) -> Optional[int]:
        """PLT 桩地址（自建映射，规避 pwntools 在某些 IBT 二进制上 +4 的偏移）。"""
        v = self.name2plt.get(name)
        if v:
            return int(v)
        addr = self.elf.plt.get(name)
        return int(addr) if addr else None

    def got(self, name: str) -> Optional[int]:
        addr = self.elf.got.get(name)
        return int(addr) if addr else None

    @property
    def base(self) -> int:
        """非 PIE 的加载基址；PIE 返回 0（偏移即地址）。"""
        return 0 if self.elf.pie else (self.elf.address or 0x400000)

    def e(self, off: int) -> int:
        """把 ELF 偏移转成运行时地址（非 PIE 才有意义）。"""
        return (self.elf.address or 0) + off

    def __repr__(self) -> str:
        return f"<Challenge {self.name} {self.prot}>"


def _build_plt_map(elf: ELF) -> tuple[dict[int, str], dict[str, int]]:
    """从 .plt/.plt.sec/.plt.got 反查每个桩对应哪个导入符号。

    不依赖 pwntools 的 ELF.plt（不同二进制上会差 4 字节），
    而是看桩里的 `jmp [got]` 指向哪个 GOT 项，再用 GOT 反查符号名。
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    import re

    rev_got = {int(v): k for k, v in elf.got.items() if v}
    md = Cs(CS_ARCH_X86, CS_MODE_64 if elf.bits == 64 else CS_MODE_32)
    addr2name: dict[int, str] = {}
    name2addr: dict[str, int] = {}
    for secname in (".plt", ".plt.sec", ".plt.got", ".plt.bnd"):
        sec = elf.get_section_by_name(secname)
        if sec is None or sec.header.sh_size == 0:
            continue
        try:
            data = sec.data()
        except Exception:
            continue
        for ins in md.disasm(data, sec.header.sh_addr):
            if "jmp" not in ins.mnemonic:
                continue
            target = None
            m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", ins.op_str)
            if m:
                target = ins.address + ins.size + int(m.group(1), 16)
            else:
                m = re.search(r"\[(?:e[a-z]{2} \+ )?(0x[0-9a-f]+)\]", ins.op_str)
                if m:
                    target = int(m.group(1), 16)
            if target is None:
                continue
            name = rev_got.get(target)
            if not name:
                continue
            addr2name[ins.address] = name
            name2addr.setdefault(name, ins.address)
            # .plt.sec 的桩以 endbr64 开头，真实入口在 jmp 前 4 字节
            try:
                if elf.read(ins.address - 4, 4) == b"\xf3\x0f\x1e\xfa":
                    addr2name[ins.address - 4] = name
                    name2addr[name] = ins.address - 4
            except Exception:
                pass
    return addr2name, name2addr
