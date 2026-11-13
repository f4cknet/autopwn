# AutoPwn

离线 pwn 自动利用引擎：给它一个题目的二进制，它给你「目标进程里真的执行了命令」的证据。

- **判据**：payload 之后在目标进程里执行 `echo PWNED_$((6*7))` / `whoami` / `id` 有正确回显；
  只出 flag 的题记 `FLAG-ONLY`，与 shell 成功率**分开统计**。
- **不依赖 AI、不依赖人工**：静态推导 → 逐策略尝试 → 真实执行验证。
- **可复盘**：每次尝试的回显都落在 `results/<题名>.json`。

> 仓库里还保留一套 v4/v5 历史链路（`autopwn/cli.py`，输出 docx 报告）。
> **对外一律以 `autopwn/engine/` 为准**；历史文档去向见 [`DOC_MAP.md`](./DOC_MAP.md)。

## 当前状态

| 题库 | 规模 | shell | flag-only |
|---|---|---|---|
| `bench/`（比赛原题） | 15 | **13** | 0 |
| `bench_extra/`（经典题型泛化） | 8 | **5** | 1 |
| `bench_sys/`（syscall 策略变体） | 4 | **4** | 0 |
| `chellenges/`（当前赛题） | 3 | 0 | 2（容器内无 `/flag`，链路已验证） |

明细与已知边界见 [`PROGRESS.md`](./PROGRESS.md)；逐题参数见 [`bench/RESULTS.md`](./bench/RESULTS.md)。

## 快速开始

环境：Windows + Docker Desktop。镜像构建一次即可。

```bat
cd /d D:\hacktools\10-pwn\autopwn

:: 0) 首次或镜像丢失时（8~12 分钟）
build_pwn.bat

:: 1) 先看静态事实：保护、漏洞点、可用 win、偏移、菜单字符
solve.bat chellenges\note --facts-only

:: 2) 打本地
solve.bat chellenges\note

:: 3) 整个目录（自动识别 ELF / zip / 已解压的平铺目录，按 md5 去重）
solve.bat bench
```

### 打远程

```bat
:: 明文
solve.bat pwn --host 1.2.3.4 --port 31337

:: 平台套了 TLS（dasctf 这类 tcp-ctf2 域名基本都要）
solve.bat pwn --host xxxx.tcp-ctf2.dasctf.com --port 9999 --ssl --sni xxxx.tcp-ctf2.dasctf.com

:: ret2libc 必须给远程同版本 libc
solve.bat pwn --host 1.2.3.4 --port 31337 --libc libc.so.6

:: 拿到 shell 后跑自己的命令（可重复）
solve.bat pwn --host 1.2.3.4 --port 31337 --cmd "id" --cmd "cat /flag"
```

### 没有远程地址时：自建容器靶机

```bat
target.bat chellenges\note 4444          :: socat fork，每连接新进程（ASLR 每次变）
solve.bat chellenges\note --host 127.0.0.1 --port 4444
target.bat stop
```

`solve.bat` 检测到 `--host 127.0.0.1` 会自动给攻击容器加 `--network host`；其它地址走
`host.docker.internal`。这是**唯一**能复现「远程形态」的方式 —— 本地直跑会读 `/proc/<pid>/maps`
走捷径（PIE 题尤其明显）。

## 文档索引

| 文档 | 给谁看 | 内容 |
|---|---|---|
| [`HANDOVER.md`](./HANDOVER.md) | 接手开发者 | 上手、铁律、环境坑、如何加策略、验收清单 |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | 接手开发者 | 分层、数据结构、16 个策略、判定链、边界 |
| [`PROGRESS.md`](./PROGRESS.md) | 所有人 | 版本演进、实测基线、能力矩阵、下一步 |
| [`CHEATSHEET.md`](./CHEATSHEET.md) | 比赛现场 | 一页命令速查 + 排错对照表 |
| [`bench/RESULTS.md`](./bench/RESULTS.md) | 复盘 | 逐题策略/偏移/关键参数/踩坑 |
| [`DOC_MAP.md`](./DOC_MAP.md) | 维护者 | 哪份文档是活的、哪些是历史、清理清单 |
| [`CLAUDE.md`](./CLAUDE.md) | Claude Code | 入口指针与最容易违反的规则 |
| [`AGENTS.md`](./AGENTS.md) | AI Agent | 治理与铁律（项目级约定） |
| [`upgraded.md`](./upgraded.md) | 维护者 | 任务板（版本 → 状态 → 详情） |
| [`upgraded/v7.0.0.md`](./upgraded/v7.0.0.md) | 架构 | 四层管线提案（下一步方向） |

## 目录结构

```
autopwn/
├── autopwn/engine/        引擎主线（facts / strategies / orchestrator / run / model / cli）
├── docker/                Dockerfile、serve.sh（靶机）、make_sys_variants.py、评测入口
├── bench/                 15 道比赛原题（<题名>/bin [+ libc/]）
├── bench_extra/           8 道经典题型（泛化验证用）
├── bench_sys/             4 个「窗口/帧尺寸」变体（syscall 策略回归）
├── chellenges/            当前比赛附件（原始 ELF / zip / 平铺目录，可直接跑）
├── Challenge/             仓库自带经典题（pytest 依赖，勿移动）
├── scripts/
│   ├── test/              评测与回归脚本
│   └── audit/             一次性审计脚本
├── bugs/                  修复记录（fix.md 索引 + 单条 fix_<name>.md）
├── upgraded/              任务详情（v6.0.0、v7.0.0）
├── results/               证据 json（本地 + chellenges / extra / remote / docker）
├── archive/               历史归档（v4、v5）
├── writeups/              解题报告（docx）
└── *.bat                  solve / target / build_pwn / shell（Windows 入口）
```

> 文档职责分工见 [`DOC_MAP.md`](./DOC_MAP.md)：每份文档只负责一件事，避免同一数字写在三处。

## 覆盖的题型

ret2win（含栈对齐变体）· PIE 局部覆盖（含零泄漏 nib 爆破）· ret2system@plt ·
gets/read→bss→system · ret2csu（按实际寄存器映射）· ret2libc（`puts` 或 `write(1,got,8)` 泄漏，
同进程两阶段）· canary+fmt 三阶段 · RWX mmap shellcode · i386 `int 0x80` execve ·
无 libc 纯 syscall 三段式（0CTF-welcome 型）· fmt 改 GOT · 只出 flag（`system("cat flag")` /
自读 `open`+`puts` / 带全局门槛）· 菜单式前置交互。

**未覆盖**：菜单式堆（tcache/FSOP）、SROP、20 字节极限 fmt、ORW、无 libc 的 ret2libc。
原因逐条列在 [`PROGRESS.md §4`](./PROGRESS.md)。

## 容器镜像

`autopwn:pwn22`（ubuntu 22.04，1.43 GB）：pwntools 4.14 / capstone 6 / gdb / ROPgadget / ropper /
one_gadget / seccomp-tools / patchelf / i386 多架构库。

GitHub 直连受限，构建时跳过 `pwndbg` / `pwninit` / `libc-database`。前者不影响解题；
最后一项缺失会限制「无 libc 时按泄漏找 libc」，见 [`PROGRESS.md §4`](./PROGRESS.md)。

## 许可

见 [`LICENSE`](./LICENSE)。
