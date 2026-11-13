# 远程实打记录（dasctf 平台）

> 判定：拿到远端进程的 shell，并在其中执行 `id` / `cat /flag` 有真实回显。
> 每条都附「反向对照」结论，避免把「连上了」当成「打通了」。

## 1. `090d11f4…`（ret2win, amd64, Partial RELRO）

- 目标：`498ad229bce7d5be4c6bb2d0.tcp-ctf2.dasctf.com:9999`（TLS + SNI）
- 策略：`ret2win` → `system("/bin/sh") @ 0x401186`，off=23
- 耗时：2 次尝试（第 1 次是未对齐变体，被服务端 `timeout` 收掉）
- 远端回显：

```
PWNED_42
ctf
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

- `cat /flag` → `CTF2{fc1e9971-7d2f-4210-ae51-87c48c4aab20}`
- 反向对照：拿错误附件 `58a4f498…` 打同一端口 → 10 次尝试全 FAILED（无假成功）

## 2. `f5b5ad3d…`（i386 静态, NX, Partial RELRO）

- 目标：`dc35bb7af89126d01c70fe49.tcp-ctf2.dasctf.com:9999`（TLS）
- 策略：`ret2sys_write` — `gets(bss)` 写入 `/bin/sh` → 回 main → `int 0x80` execve，off=56
- 本地：`SHELL ret2sys_write uid=0(root)`
- 远端：`SHELL ret2sys_write uid=1000(ctf)`
- 远端回显：

```
$ id
  uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -la /
  lrwxrwxrwx 1 root root 5 Oct 14 2019 flag.txt -> /flag
  ... drwxr-xr-x 1 root root 4096 Dec  8  2019 pwn
$ cat /flag
  CTF2{6b390e76-76ec-4f60-aaa0-77bbfa2c3dc0}
```

- 备注：首次打成功后该实例被平台回收，再次连接返回
  `This address has no running target. Return to the challenge page, start or renew it, then reconnect.`
  —— 属于平台侧实例生命周期，不是利用失败（引擎已能识别并提示）。


## 3. `7a4abf36…`（0CTF 2016 "welcome" 型：724B 手写汇编 / 只有 int 0x80）

- 目标：`db7f604154c9c7a6971c7aa6.tcp-ctf2.dasctf.com:9999`（TLS）
- 二进制：i386、stripped、静态、**无 libc**、`.data` 与栈都不可执行
  流程：`alarm(10)` → `write("Welcome to 0CTF 2016!")` → `read(0, esp+0x10, 0x34)` → 全寄存器
  写成 `0xdeadbeaf` → `ret`
- 为什么常规链全废：
  - 没有 PLT，`gets/read@plt` 一个都没有 → 引擎原来的 `vulns=0`，0 次尝试
  - 只有 `read(3)/write(4)/exit(1)/alarm(27)` 四个包装，代码里没有 `mov eax, 11`
  - 窗口 52 字节，返回地址在 offset 32，之后只剩 4 个 dword；
    而「用 read 返回 11 设 eax」会让栈帧整体右移 4 字节，`envp` 槽位正好掉出窗口一个 dword
  - `.data`（RW）和栈（`GNU_STACK RW`）都不可执行，shellcode 无路
- 解法（三段，引擎已内置 `syscall3`）：
  1. `read(0, .data, 0x34)` 写入 `"/bin/sh\0"` + 0 填充，回漏洞函数
  2. 把 0 种在 `anchor+4`（下一段窗口外一格），再 `ret` 到 `_start` 让帧下移 `0x10`
     → 下一段里 `execve` 的 `envp` 槽位读到的正好是这个 0
  3. `read(0, .data, argv_ptr)` 只喂 **11 字节** → 返回 11 → `eax=11`；
     紧跟 `0x804813a`（`mov ebx,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]; int 0x80`）
     → `execve("/bin/sh", {NULL}, NULL)`
- 远端回显：

```
$ id
  uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat /flag
  CTF2{e95e6c3a-94ce-423a-be7e-0ac805f14294}
```

- 引擎结果：`=> SHELL syscall3 uid=1000(ctf) (4.5s / 1 attempts)`
- 稳定性：同一版本连打 **6 轮 6/6**（迭代前后各 3 轮），每轮均 1 次尝试、约 3.7–4.5s
- 迭代补充：新增 `syscall1`（窗口够宽时一次 read 搞定），并用 `bench_sys/` 的 4 个变体验证
  （帧 0x28/0x2c、窗口 0x38/0x3c 全部一次打通）；原始题仍走 `syscall3`
- 踩坑：数据段尾部**不是**零区（整页与文件映射，读到的是 `.shstrtab`），
  所以 argv 只能用「我们自己写过 0 的 `data+8`」，不能用「段尾页内空白」

## 4. 已验证 / 未验证的边界

| 链路 | 远程验证 |
|---|---|
| ret2win（amd64） | ✓ 真实远程 |
| ret2sys_write（i386 静态，无 `/bin/sh`） | ✓ 真实远程 |
| ret2libc | 未验证（需远程同版本 libc 才能算 system） |
| 纯 int 0x80 三段式（`syscall3`） | ✓ 真实远程 |
| ret2csu / shellcode / canary+fmt / fmtstr GOT | 未验证 |

不把「本地 14/16」等价成「远程 14/16」。
