# ARCHITECTURE — autopwn.engine（v7.0.2 现状）

> 本文只描述**现在能跑的代码**（`autopwn/engine/`，约 3200 行）。
> v4/v5 遗留链路（`autopwn/cli.py` 等）见 `README.md` 的「遗留入口」与 `v5_architecture.md`。
> 下一版设计提案见 [`upgraded/v7.0.0.md`](./upgraded/v7.0.0.md)。

## 1. 设计目标与唯一判据

| 项 | 约定 |
|---|---|
| 成功判据 | **目标进程里真的执行了命令**：`echo PWNED_$((6*7))` 回显 `PWNED_42`，或 `id` 回显 `uid=` |
| flag 类判据 | 输出里出现 `flag{...}` / `CTF2{...}` 这类正则；打到 win 但本地无 flag 文件时记 `reached` |
| 反例判据 | 「策略跑完没报错」**不算成功**；「连上了」不算成功（有反向对照用例） |
| 记账口径 | `SHELL`（真 shell）与 `FLAG-ONLY`（只出 flag）分开统计，不合并成「成功率」 |

## 2. 分层与数据流

```
                    ┌──────────────┐
   命令参数 ───────► │  cli.py      │  收集题目(原始目录/zip/平铺目录)、md5 去重、路径归一化
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  model.py    │  Challenge.prepare()：复制到 .run/bin，patchelf(libc/ld)，加载 ELF
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  facts.py    │  analyse()：静态事实（漏洞点/win/校验/交互/gadget/syscall 包装…）
                    │  guard.py    │  L0.5 守卫层：输入 → win 路径条件（find_guards/find_backfills，v7.4.0）
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ strategies.py│  16 个策略：facts → Plan 候选（纯函数，不产生副作用）
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │orchestrator  │  按顺序尝试、单题预算、按 tag 分派特殊流程、留痕
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ interact.py  │  Send/Wait 步骤、累积缓冲与游标、唯一一份收发时序
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  run.py      │  spawn(本地/远程)、按步骤收发、后置命令
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │  oracle.py   │  判定唯一实现：judge_shell / judge_flag / Verdict(cause)
                    └──────────────┘
```

关键约束：**facts 与 strategies 不 import wails / 不碰网络**；一切副作用集中在 `run.py` 与 `interact.py`。
（与另一仓库 `ctfbox` 的「services 层是唯一能 import wails 的层」是同一个思路。）

## 3. 核心数据结构

### `model.Challenge`
| 字段 | 说明 |
|---|---|
| `dir` / `bin_src` / `run_dir` / `run_bin` | 题目目录、原始二进制、`.run/` 运行副本 |
| `elf` | pwntools ELF（`checksec=False`，另算 `prot`） |
| `prot` | `Protections(arch,bits,endian,pie,canary,nx,relro,static)` |
| `libc_path` / `ld_path` | 题目自带 libc/ld（`libc/` 子目录自动发现） |
| `host`/`port`/`ssl`/`sni` | 远程模式；`ssl` 走 stunnel 类平台，`sni` 默认等于 host |

### `facts.Facts`（静态事实，纯数据）
| 字段 | 含义 |
|---|---|
| `vulns: [Vuln]` | 漏洞点：`sink`(read/gets/scanf/fgets)、`call_addr`、`buf_disp`(相对 rbp)、`offset`(到返回地址)、`size_limit`、`func_entry` |
| `wins: [Win]` | 可直接跳的「赢」函数：`addr`、`kind`(**shell / flag / decoy**)、`evidence`、`alt`(跳过 prologue 的入口，修栈对齐)。`decoy` = 打中也拿不到 flag（`system("echo flag")` 这类），不生成计划 |
| `gadgets` / `gadget_alts` | 常用 gadget；`alts` 是同类全部地址（用于绕 `\n` 等坏字节） |
| `csu` | `__libc_csu_init` 的 (pop 链, call 链)，寄存器映射随编译器变 |
| `mmap_rwx` | `mmap(PROT_EXEC)` 得到的固定 RWX 地址 |
| `fmt_buf` | `printf(用户缓冲区)` 的探测结果（第一个站点的 rbp 相对位移） |
| `fmt_sites: [(base, disp, rbp_disp, call)]` | **v7.4.0** 全部 `printf(用户缓冲区)` 站点；守卫层按「缓冲基址+位移」匹配（C4，不重复解析） |
| `guards: [Guard]` | **v7.4.0** 输入 → win 的路径条件：`buf_kind/buf_addr/buf_disp`、`length`、`conds`（byte/dword/global/len）、`ones`、`status`（solved/fmt/unsupported/unsat/unknown）、`reason`、`marker`。只登记不执行 |
| `backfills: [Backfill]` | **v7.4.0** `strncmp(input, 运行时串, n)` 的可回填点：`n`、成功 `marker`、`status`（backfill/unsupported/unprinted/unknown） |
| `gates: [(disp, val)]` | `cmp dword [rbp-X], imm` 的「暗号」，溢出时必须写回 |
| `interact: {func: [b"w\n"]}` | 菜单式题：进该函数前必须发的选择字符。**v7.3.1** 起也包含数字菜单（`scanf("%d")` + dispatch 进含 sink 的函数）候选 `b"1\n" / b"2\n" / b""` |
| `sys_wrappers` / `sys_read` / `sys_load` | 无 libc 时的 `mov eax,NR … int 0x80` 包装（read=3） |
| `data_addr` / `entry_sub` | 可写数据段起始；`_start` 的 `sub esp,imm`（重帧下移量） |
| `callers` | 函数入口 → 调用点之后的下一条地址（PIE 部分覆盖要用） |
| `unknowns: {name: reason}` | **v7.3.0** 事实三态登记：`Known` 有值 / `Absent` 不登记 / `Unknown` 记原因（`sink` / `offset@0x…` / `fmt`）。零计划时拼成 `UNRESOLVED` 输出 |
| `unreachable: [{sink,call,offset,limit}]` | **v7.3.0** 明确不可达的溢出点（`size_limit <= offset`）。不再静默丢弃，也不再据此盲枚举 |

> **v7.3.0 起的不变量**：`Facts` 的 `Optional` 字段为 `None` 时**不代表「随便试试」**。
> 「确认不存在」与「没算出来」必须由 `unknowns` 区分；`_offsets` 的无证据兜底默认关闭，
> 需要时用 `--allow-brute` 显式开启（并计入盲试占比指标）。

### `strategies.Plan`
```python
Plan(strategy: str, steps: list, desc: str = "", tag: str = "")
```
`steps` 的元素是 `interact.Send(data)` / `interact.Wait(needle=b"", timeout=None)`；
旧的裸 `bytes` 写法继续可用（`__post_init__` 自动归一化并丢弃空 blob）。
只读兼容属性：`plan.sends` / `plan.last_send`。

`tag` 决定 orchestrator 走哪条特殊流程：

| tag | 含义 | 处理函数 |
|---|---|---|
| `""` | 普通单进程链 | `execute()` |
| `flag` | 只跳 flag win | `execute_flag()` |
| `stage1:<leak>:<off>:<sink>` | 两阶段 ret2libc（**必须同进程**） | `_try_ret2libc()` |
| `canary:<off>:<sink>` | 三阶段 canary+fmt | `_try_canary_fmt()` |
| `pie:<tgt>:<nib>:<kind>` | PIE 部分覆盖 | `_try_pie_partial()` |

### `run.Result` / `orchestrator.SolveResult`
`Result(ok, output, note, error, cause, cmds)`；`cause` 来自 oracle（`marker` / `uid` / `flag_re` /
`no_flag_file` / `no_match`），落到 `attempts[].cause` 供归因。
`SolveResult` 额外含 `strategy/detail/elapsed/attempts/facts/flag_only`，
整体序列化到 `results/<题名>.json`（含每次尝试的 tail，复盘用）。

## 4. 策略清单（`STRATEGIES` 的顺序 = 尝试顺序）

| # | 策略 | 适用 | 关键点 |
|---|---|---|---|
| 1 | `pie_partial_win` | PIE + 无泄漏 + 有 win | 只覆盖返回地址低 2 字节；本地读 `/proc/pid/maps` 拿基址，远程枚举 16 个 nib |
| 2 | `syscall_direct` | 无 libc，窗口 `limit >= off+0x18` | 一次 `read` 喂满 execve 三参 |
| 3 | `syscall_execve` | 无 libc，窗口 `limit == off+0x14` | 种 0 到窗口外一格 + 重入 `_start` 下移帧 |
| 4 | `ret2win_pie` | PIE + shell win，同 0x100 页 | 1 字节部分覆盖 |
| 5 | `ret2win` | 非 PIE + shell win | 含 `ret` 对齐变体、菜单前缀 |
| 6 | `ret2plt` | 有 `pop rdi` + `system@plt` + `/bin/sh` | — |
| 7 | `ret2gets` | 有 `gets`/`read` + `system@plt` | 先写 `/bin/sh` 到 bss 再 system |
| 8 | `ret2csu` | 无 `pop rdi`，有 `__libc_csu_init` | 按实际寄存器映射现拼 |
| 9 | `canary_fmt` | canary + `printf(buf)` | 泄漏 canary → 泄漏 GOT → 回 main → system |
| 10 | `ret2libc_write` | 只有 `write` 没有 `puts` | `write(1,got,8)` 泄漏，远程优先（无 stdio 缓冲） |
| 11 | `ret2libc` | 有 `puts`/`write` + 给了 libc | 同进程两阶段 |
| 12 | `shellcode` | 有 RWX `mmap` | 两段：shellcode → 跳 RWX |
| 13 | `ret2syscall` | i386 + `int 0x80` 全套 gadget | 组合搜索 gadget 绕坏字节 |
| 14 | `ret2syscall_write` | i386 静态无 `/bin/sh` | 先写 bss，再回 main，再 execve |
| 15 | `fmtstr` | `printf(buf)` + 可写 GOT | `fmtstr_payload` 改 GOT |
| 16 | `ret2win_flag` | 只出 flag 的题（兜底） | 不算 shell，记 `FLAG-ONLY` |

## 5. 判定链（`run.py`）

```
spawn(ch)
  ├── 本地：process(...)  # 不显式传 stdin/stdout：让 pwnlib 共用同一个 PTY
  └── 远程：remote(host, port, ssl=, sni=)   # 每次尝试间隔 0.25s，防限速

send 分阶段（`interact.Interaction.run_steps`，唯一实现）：
  ├── Send → Send：execute / ret2libc 用「读到静默」同步；flag 路径用固定 0.15 + 0.05
  ├── Send → Wait：不自动读，Wait 独占边界
  ├── Wait(needle)：在累积缓冲中从游标查找，支持跨 chunk / 重复 prompt
  ├── Wait(b"")：读到静默，并把游标推到缓冲末尾（旧输出视为已消费）
  └── 远程额外把验证 / Wait 超时 2.2s → 6s

判定（`oracle.py`，唯一实现）：
  ├── judge_shell(out): PWNED_42 回显（marker）或 uid=…（uid）→ ok；cause 记来源
  ├── judge_flag(out):  FLAG_RE 真 flag 优先，其次 No such file → win reached（no_flag_file）
  └── 判定函数是纯函数：喂累积输出，返回 Verdict；I/O 时序留在 run.py
```

**铁律（都是踩过的坑）**：
1. `process(stdin=-1, stdout=-1, stderr=-1)` 会把子进程 stdout 接到父进程 → tube 读不到任何东西
2. 判定必须看**累积输出**，不能只看最后一段 `recvrepeat`（flag 早到就会被判负）
3. 「打到 win 但没 flag 文件」要和「没打到」区分：`No such file` 是**通了**的证据
4. 远程 stdout 全缓冲：`puts` 的泄漏会卡在缓冲区，ret2libc 远程优先用 `write`
5. 远程每次尝试都是新连接：DNS/端口/实例类错误要**立刻中止**，不要烧完 attempts

## 6. 环境与运行形态

| 形态 | 入口 | 说明 |
|---|---|---|
| 本地直跑 | `solve.bat <题>` → `docker run --rm -v %CD%:/work autopwn:pwn22 python3 -m autopwn.engine.cli` | 题目在容器内执行 |
| 远程 | `solve.bat <题> --host H --port P [--ssl]` | `127.0.0.1` 自动 `--network host`；其它地址走 `host.docker.internal` |
| 自建靶机 | `target.bat <题> <端口> [noaslr]` | `socat TCP-LISTEN,fork`，每连接新进程（ASLR 每次变），同目录放 `flag` |

镜像 `autopwn:pwn22`（ubuntu 22.04，1.43GB）：pwntools 4.14 / capstone 6 / gdb / ROPgadget / ropper /
one_gadget / seccomp-tools / patchelf / **i386 多架构库**。
GitHub 直连受限，`pwndbg` / `pwninit` / `libc-database` 三项构建时跳过（不影响当前题型）。

## 7. 已知边界（不要假装覆盖）

| 类别 | 状态 | 原因 |
|---|---|---|
| 菜单式堆（tcache/FSOP） | ✗ | glibc 2.35 无 `__free_hook`，且无堆地址泄漏；堆策略完全没实现 |
| SROP（`rax=15`） | ✗ | `bench_extra/chall` 只有 syscall gadget |
| 20 字节极限 fmt | ✗ | `bench_extra/fmtstr1` 输入太短，写不动 |
| ORW 型（无现成 win） | ✗ | 需要自拼 open/read/write，等同普通 ROP，属人工范畴 |
| 多轮交互（prompt 驱动） | △ | `Wait(prompt)` 已能表达；但 `facts.py` 还不提取 prompt，策略目前只自动插静默 Wait |
| 运行时地址占位的多阶段 | △ | `_try_canary_fmt` / `_try_pie_partial` 仍用专用流程（payload 含运行时 canary / PIE base） |

## 8. 与 v7 提案的差距

v7（[`upgraded/v7.0.0.md`](./upgraded/v7.0.0.md)）提的是四层：目标模型 / 交互规划 / 能力注册 / 判定与归因。
当前代码在「事实」这一层已经接近 L0（`gates`/`interact`/`alt` 就是 trigger 与 gate 的雏形），
**L1 交互层已在 v7.0.1 落地**（[`upgraded/v7.0.1.md`](./upgraded/v7.0.1.md)）。
下一步是 **L3 判定统一**（v7.0.2）、facts 提取 prompt（v7.1）与 L2 能力注册。
