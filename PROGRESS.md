# PROGRESS — 开发进度与实测基线

> 口径：所有「已解出」都必须有**可复现证据**（`results/*.json` 里有真实回显）。
> 「策略跑完没报错」不算完成。`SHELL` 与 `FLAG-ONLY` 分开统计。

最后更新：2026-11-14（v7.2.0）

## 1. 版本演进

| 版本 | 内容 | 关键产出 |
|---|---|---|
| `v5.0.x` | 遗留链路（planner/verifier/report），以「出报告」为导向 | 见 `archive/v5/`，**不是当前主线** |
| `v6.0.0` | 新建 `autopwn/engine/`：facts → strategies → orchestrator → run，判据改为「真执行 whoami」 | 15 题 13 解 |
| `v6.0.1` | 加 `canary_fmt` / `ret2libc_write` / PIE 局部覆盖 / `ret2flag`；修 PTY 交互 | — |
| `v6.0.3` | Windows `.bat` 入口（本机 `bash` 指向未安装的 WSL） | `solve.bat` |
| `v6.0.4` | 原始目录直跑（ELF/zip/平铺目录 + md5 去重）；gadget 坏字节规避；用「输出静默」做阶段同步 | 解决 ch08 偶发失败 |
| `v6.1.0` | 远程 TLS/SNI；远程优先无缓冲泄漏；超时与限速适配 | 首次真远程拿 shell |
| `v6.1.1` | `--cmd`：getshell 后执行自定义命令并留痕迹 | 取 flag |
| `v6.1.2` | 连接类失败（DNS/实例/端口）立即中止 + 中文原因 | 不再白烧 attempts |
| `v6.2.0` | 纯 `int 0x80` 手写汇编题：识别自写 syscall 包装 + `syscall3` 三段式 execve | 0CTF-welcome 型 |
| `v6.2.1` | `syscall1`（宽窗口一次到位）+ 变体回归矩阵（`bench_sys`） | 泛化验证 |
| `v6.3.0` | PIE 无泄漏部分覆盖：`endbr64` 认入口、gate 校验、栈对齐 `alt` 入口、nib 爆破 | `chellenges/pwn` |
| `v6.3.1` | `target.bat`：把附件挂成容器内 TCP 靶机；`127.0.0.1` 走 host 网络 | 远程形态可复现 |
| `v6.4.0` | 「自读 flag」型 win（`open`+`puts`）、门槛入口回溯、flag 判定覆盖累积输出 | `bench_extra/ret2win` |
| `v6.4.1` | 菜单式前置交互（`interact`）自动探测；剔除 win 内部 read 的假漏洞 | `chellenges/note` |
| `v6.5.0` | 交付文档：README / ARCHITECTURE / PROGRESS / HANDOVER / CLAUDE / DOC_MAP | 可移交 |
| `v6.5.1` | 文档与目录整理：v5 归档 `archive/v5/`；`AGENTS`/`upgraded` 瘦身；脚本聚合 `scripts/`；`results/` 移出版本库 | 根目录 30+ → 22 项 |
| `v6.5.2` | 删除 `bench/*/{disasm,strings}.txt`（7.6 MB）；新增卫生门禁 `scripts/audit/check_hygiene.py`；仓库纪律写入 §铁律 5 | 主目录清洁可执行化 |
| `v6.5.3` | 文档与卫生清理：`.claude` 白名单、`py -3` 命令、路径/章节引用修正 | 收尾清单可在本机原样执行 |
| `v6.5.4` | 新建 `ctf-pwn-local` Skill：本地镜像/容器/工具链/环境坑速查 | Agent 可自动加载本机 pwn 环境说明 |
| `v7.0.1` | L1 交互层：`Plan.steps`（`Send`/`Wait`）、统一收发时序、修复 `_try_ret2libc` 丢弃前缀 | 菜单/多轮题可表达；独立向量 13/13；基线不变 |
| `v7.0.2` | L3 判定统一：`oracle.py`（`judge_shell`/`judge_flag`/`Verdict`）+ 唯一 `FLAG_RE` + attempts 带 `cause` | 4 份判定收成 1 份；向量 15/15；基线不变 |
| `v7.0.3` | repeater 解锁：`_find_fmt` 误报修复、`_start` 推 main、新策略 `canary_echo`（canary-echo 泄漏 + 对齐重入 ret2libc） | **chellenges 首次 1/3**（repeater 真拿 shell 3/3）；基线不变 |
| `v7.0.4` | 远程 libc 识别：`libcsearch.py` 双符号 low12 指纹 + 候选轮换；ret2libc/canary_echo 接入 | repeater 远程真取 flag（2.23 自动识别）；基线不变 |
| `v7.1.0` | prompt 驱动交互：`Facts.prompts` 提取 + 菜单题自动 `Wait(prompt)` | note 1 attempts 取 flag（desc 带提示串归因）；向量 17/17；基线不变 |
| `v7.2.0` | canary_fmt 五 bug 修复 + hints 排序 + ret2libc_write 远程识别（csu 双块链修复 + write 型双段解析） | **cannary/ae3f 本地远程全解**；cc7e 判定能力边界；基线不变 |
| `v7.3.0` | 失败可见化：`Facts.unknowns/unreachable` 三态 + `_offsets` 盲枚举兜底默认关闭（`--allow-brute` 显式开启）+ 零计划报 `UNRESOLVED` + win 剔除改判 `open` 语义 | 10 题样本外：盲试 **231 → 0**，attempts **461 → 195**，5 题从静默 FAILED 变可归因；基线不变（13/15、5+1、4/4） |
| `v7.3.1` | 事实层形态补全：32 位 PIC 桩多数票解 ebx 基址 / `_frame_size` 认 `add esp,-N` 且不跨函数 / fmt 支持 esp 缓冲与 `mov [esp],reg` 传参 / `echo` 类诱饵 win / 数字菜单 `scanf("%d")` / 全局缓冲区措辞 | 题一 plt_map **0→8**、题七 `fmt_buf` **None→88** 且 `off` **None→84**、题三报出 `0x6010c0`；基线不变 |

## 2. 当前基线（2026-11-14 v7.3.1 实测，`--max-attempts 80`，盲试默认关闭）

| 题库 | 规模 | shell | flag-only | 未解 |
|---|---|---|---|---|
| `bench/` | 15 | **13** | 0 | `ch07_acae`、`ch14_easyheap`（菜单式堆） |
| `bench_extra/` | 8 | **5** | 1 | `chall`（SROP）、`fmtstr1`（20 字节 fmt） |
| `bench_sys/` | 4 | **4** | 0 | — |
| `chellenges/`（原始赛题，**样本外**） | 33 | **0** | 0 | 见下 |

> **`chellenges/` 自 v7.0.3 起是样本外题目，不是验收集。**
> 2026-11-14 抽 10 题实测 **0 shell / 0 flag**，逐题归因见
> [`upgraded/v7.3.0.md`](./upgraded/v7.3.0.md) §1.1 与 [`v7.3.1`](./upgraded/v7.3.1.md) §7.2。
> 现存已知可解项：`repeater`（v7.0.3 `canary_echo`）、`note`/`pwn`（flag-only）。

逐题明细：`bench/RESULTS.md`（含每题的策略、偏移、关键参数）；远程实打记录：`results/remote/FLAGS.md`。

> `chellenges/note` 与 `chellenges/pwn` 显示 `win reached (no local flag file)`：
> 容器内没有 `/flag`，但**链路已打通**（放一个 flag 文件或挂 `target.bat` 就能真取到）。
> 这两题都已在容器靶机上验证过 1 次尝试出 flag。

## 3. 能力矩阵

| 题型 | 覆盖 | 策略 | 代表题目 |
|---|---|---|---|
| ret2win（含对齐变体） | ✅ | `ret2win` | ch01/ch03/ch05/ch08/ch11/ch12 |
| ret2win + PIE 局部覆盖 | ✅ | `ret2win_pie` | `bench_extra/pie` |
| PIE + 零泄漏 + win | ✅ | `pie_partial_win` | `chellenges/pwn` |
| ret2system@plt | ✅ | `ret2plt` | ch09 |
| gets/read → bss → system | ✅ | `ret2gets` | ch04/ch06 |
| ret2csu（按实际寄存器映射） | ✅ | `ret2csu` | `bench_extra/level3_x64` |
| ret2libc（puts 泄漏，同进程） | ✅ | `ret2libc` | ch13、`bench_extra/ret2libc` |
| ret2libc（只有 write） | ✅ | `ret2libc_write` | `bench_extra/level3_x64` |
| canary + fmt 三阶段 | ✅ | `canary_fmt` | `bench_extra/canary` |
| RWX mmap shellcode | ✅ | `shellcode` | ch15 |
| i386 `int 0x80` execve | ✅ | `ret2syscall` / `_write` | ch10、`f5b5…` |
| fmt 改 GOT | ✅ | `fmtstr` | ch02 |
| 只出 flag（`system("cat flag")`） | ✅ | `ret2win_flag` | ch04 备用路径 |
| 只出 flag（自读 `open`+`puts`） | ✅ | `ret2win_flag` | `bench_extra/ret2win` |
| 菜单式（需前置 `'w'`） | ✅ | `interact` + `ret2win_flag` | `chellenges/note` |
| 交互层（`Send` / `Wait`） | ✅ | `interact.Interaction` | `scripts/test/interaction_vector.py`；菜单题 `note` |
| canary + 回显泄漏（无 fmt） | ✅ | `canary_echo` | `chellenges/repeater` |
| stripped（无 main 符号） | ✅ | `_start` 推 main | `chellenges/repeater` |
| prompt 驱动（facts 提取 prompt） | ✅ | `Facts.prompts` + `Wait(prompt)` | `chellenges/note`（v7.1.0） |
| 无 libc 纯 syscall 三段式 | ✅ | `syscall_execve` | `7a4abf36…` |
| **菜单式堆（tcache/FSOP）** | ❌ | — | ch07、ch14 |
| **坏字节封死 pop rdi + 泄漏需 resolver** | ❌ | — | `cc7e9c60`：scanf(%s) 坏字节封死唯一 pop rdi；假 rbp 迁栈可写 GOT，但泄漏走 printf@plt→resolver 的 xsave 区需 rsp≥0x601110，bss 段尾 0x6010b0 物理不可达（GDB 逐级实证）；brute 不适用（写 8 字节完整地址，20-bit 熵） |
| **SROP** | ❌ | — | `bench_extra/chall` |
| **20 字节极限 fmt** | ❌ | — | `bench_extra/fmtstr1` |
| **ORW（无现成 win）** | ❌ | — | 需人工 |
| **无 libc + 需 ret2libc** | ✅ | `libcsearch`（v7.0.4） | `chellenges/repeater`（本地 + 远程均解） |

## 4. 已知边界（逐条原因）

| 项 | 原因 |
|---|---|
| 菜单式堆 `ch07_acae` / `ch14_easyheap` | glibc 2.35 移除了 `__free_hook`/`__malloc_hook`；程序不打印堆内容，safe-linking 下无堆地址泄漏。堆策略完全没实现 |
| `bench_extra/chall` | 只有 syscall gadget，需要 `rax=15` 的 SROP；未实现 |
| `bench_extra/fmtstr1` | 输入限制 20 字节，写不动 GOT |
| `chellenges/repeater` | ✅ v7.0.3 已解（`canary_echo`）；远程形态 v7.0.4 已解（`libcsearch` 自动识别 2.23，dasctf TLS 实例真取 flag）。复盘结论：①stripped 无 main 符号 → `_start` 推导；②`fmt=48` 是误报（`_find_fmt` 已修）；③canary 在 buf+40 → 盖 LSB 后 puts 回显带出高 7 字节；④远程 libc≠本地 → 双符号 low12 指纹 + 候选轮换 |
| ORW 型 | 需要自拼 open/read/write，属人工范畴（见 v7 文档 §5「明确不做的事」） |

## 5. 下一步（按投入产出）

| 优先级 | 任务 | 理由 |
|---|---|---|
| P1 | prompt→read 绑定校验（同函数多 prompt 时选对） | v7.1.0 遗留；先取最外层入口提示的启发式已可用 |
| P1 | L2 能力声明式注册（`requires`/`forbids`/`evidence`） | 去掉「策略顺序 + 各自 early-return」的隐式耦合（`_find_wins` 曾因此埋掉一整类题） |
| P1 | 补 libc-database / 或支持「按泄漏找 libc」 | 解锁 `repeater` 这类题 |
| P2 | L4 失败归因（tail 分类驱动换分支） | 减少人工看 tail |
| P2 | 堆题（tcache dup / FSOP） | 覆盖面大但成本高，且当前 2.35 环境限制多 |

## 6. 验收标准（改完必须跑）

```bat
solve.bat bench            :: 期望 13/15 shell（失败项只能是 ch07_acae、ch14_easyheap）
solve.bat bench_extra      :: 期望 5/8 shell + 1 flag-only（失败项只能 chall、fmtstr1）
solve.bat bench_sys        :: 期望 4/4 shell
```

任何一项低于上述数字 = 回归，不允许提交。
新增能力要同时补一条**可复现的向量**（放在 `bench/`、`bench_extra/` 或 `bench_sys/`），
并在 `bench/RESULTS.md` 里登记。
