# 早上好用这个（pwn 速用卡 · Windows 版）

> ⚠️ 不要在 CMD 里敲 `bash xxx.sh`：这台机器的 `bash` 指向 **WSL**，而 WSL 没装发行版，
> 会报 `execvpe(/bin/bash) failed`。**用下面的 `.bat`**，或在 Git Bash（MINGW64）里跑 `.sh`。

工作目录：`D:\ctf\ctf-env\autopwn`

## 1. 拿到题目后三步（CMD / 双击都行）

```bat
:: ① 把题目放成 bench\<题名>\bin（自带 libc 就放 bench\<题名>\libc\）
::    也可以直接用裸文件：solve.bat 你的binary

:: ② 先看静态事实（1 秒，不执行利用）
solve.bat bench\ch01_note --facts-only

:: ③ 直接打，看到 => SHELL 就是拿到了
solve.bat bench\ch01_note
```

判成功只看一行：`=> SHELL ...`，且 `results\<题名>.json` 里 `ok: true`。

| 输出 | 含义 |
|---|---|
| `=> SHELL` | 拿到 shell（已用 whoami/id 验证） |
| `=> FLAG-ONLY` | 只打出 flag，没落 shell |
| `=> FAILED` | 没打通 |

## 2. 一次打一批

```bat
solve.bat bench
```

## 3. 打远程（比赛现场）

```bat
:: 明文
solve.bat pwn --host 1.2.3.4 --port 31337

:: 平台套了 TLS（dasctf 这类 tcp-ctf2 域名基本都要）
solve.bat pwn --host xxxx.tcp-ctf2.dasctf.com --port 9999 --ssl --sni xxxx.tcp-ctf2.dasctf.com

:: ret2libc 必须给远程同版本 libc
solve.bat pwn --host 1.2.3.4 --port 31337 --libc libc.so.6
```

成功时会直接打印证据：`=> SHELL ret2win uid=1000(ctf)`。

### 拿到 shell 后跑自己的命令

```bat
:: 一个 --cmd 一条命令，可重复
solve.bat pwn --host 1.2.3.4 --port 31337 --ssl ^
  --cmd "id" --cmd "ls -la /" --cmd "cat /flag" --cmd "find / -maxdepth 3 -name *flag* 2>/dev/null"
```

输出会把命令和回显单独列出来（同时写进 `results\<题>.json` 的 `cmds` 字段）：

```
    $ cat /flag
      CTF2{...}
```

### 打不通先看这一张表（按报错对号入座）

| 你看到的报错 | 真实原因 | 怎么办 |
|---|---|---|
| `Could not resolve hostname` / `Name or service not known` | 域名拼错 | 常见是 `.dasctf.com` 写成 `.dasctf.comm`；复制时多/少一个字母 |
| `This address has no running target` | 平台实例已回收/未启动 | 回题目页点「启动 / 续期」，拿新地址再连 |
| `Connection refused` | 端口错或实例没起来 | 核对端口号，确认实例 running |
| `FAILED` 但没有任何报错 | 真的没打进去 | 先 `--facts-only` 看保护/偏移，再单题跑 |

> 前三种引擎现在都会**只跑 1 次就中止**，并打印中文原因，不会把 20 次尝试白烧掉。

### 远程 ≠ 本地的三个坑（引擎已处理 / 需你注意）

| 坑 | 表现 | 处理 |
|---|---|---|
| stdout 全缓冲 | 本地能看到的提示语/泄漏，远程一条都不来 | 引擎在远程模式优先用 `write(1,got,8)` 泄漏（系统调用，不经 stdio 缓冲）；只在本地才用 `puts` |
| libc 版本不同 | ret2libc 算出的 system 地址非法，直接崩 | **必须** `--libc` 给远程同版本；没有就别用 ret2libc 这条路 |
| 每次尝试是新连接 | 平台限速/超时杀连接 | 远程模式每次尝试间隔 0.25s；单题预算内不狂刷 |

## 4. 其他入口

| 脚本 | 用途 |
|---|---|
| `solve.bat <目标> [参数]` | 主入口（内部起 docker，参数原样透传给引擎） |
| `build_pwn.bat` | 重建 `autopwn:pwn22` 镜像（约 8–12 分钟） |
| `shell.bat` | 进容器交互 shell（pwntools/gdb/one_gadget 都在），挂载 `/work` = 本目录 |

如果你想用 Git Bash 而不是 CMD，`bash docker/solve.sh bench` 也可以（Git Bash 的 bash 才可用）。

## 5. 打不通怎么办

1. `--facts-only` 看 `vulns` 是否为空：
   - 空 → 不是栈溢出（堆/逻辑漏洞），本工具覆盖有限
   - 有 → 看 `off=` 是否合理，可手动试相邻值
2. `results\<题名>.json` 的 `attempts` 有每次尝试的输出尾部，能看出卡在格式串/堆/长度限制
3. 已知不支持：菜单式堆（tcache/fastbin）、SROP、纯 PIE 无泄漏、超短输入 fmt

## 6. 本次离线评测成绩（可复核）

- `chellenges/` 15 个唯一二进制：**13 题拿到 shell（86.7%）**，三连跑稳定
- 未解：`ch07_acae`、`ch14_easyheap`（菜单式堆，glibc 2.35 下未实现堆策略）
- 仓库自带 `Challenge/` 8 题：4 题拿到 shell（含 canary+fmt 组合）
- 明细：`bench/RESULTS.md`；逐题证据：`results\*.json`
