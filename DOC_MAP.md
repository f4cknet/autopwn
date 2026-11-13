# DOC_MAP — 文档地图与清理清单

> 目的：让接手的人 30 秒内知道「哪份文档是活的、哪份是历史、哪些是垃圾」。
> **本文件只做分类，不执行删除。** 删除/移动的命令在 §5，需要人工确认后执行。

盘于 2026-11-13 22:20。已排除 `.venv/`（虚拟环境，已 gitignore）。

## 1. 结论

| 类别 | 数量 | 处理 |
|---|---|---|
| **活跃文档**（日常要看/要写） | 9 | 留在根目录 |
| **历史文档**（v4/v5 时代，仅存档） | 21 | 移到 `archive/v5/` + `archive/bugs/` |
| **派生产物**（可随时重生成） | 30 个文件 / **7.5 MB** | 删除并 gitignore |
| **运行产物**（每次跑都变） | `results/`、`_target/`、`.*.run/` | gitignore，本地留 |

## 2. 活跃文档（保留）

| 文件 | 大小 | 作用 | 备注 |
|---|---|---|---|
| `README.md` | 11 KB | 项目入口：定位、快速开始、文档索引 | 待重写（现在混了 v4 用法） |
| `ARCHITECTURE.md` | 9.9 KB | 现状架构：分层/数据结构/策略清单/判定链/边界 | 新增 |
| `PROGRESS.md` | 6.5 KB | 版本演进、实测基线、能力矩阵、下一步 | 新增 |
| `HANDOVER.md` | — | 交接说明（环境/铁律/坑/如何扩展） | 新增 |
| `CLAUDE.md` | — | 给 Claude Code 的入口指针 | 新增 |
| `CHEATSHEET.md` | 6.6 KB | 赛前速用卡（本地/远程/靶机/排错表） | 面向使用者 |
| `AGENTS.md` | 18.5 KB | 治理与铁律（AI Agent 必须遵守） | **需更新**：里面「以 `v5_architecture.md` 为准」已过期 |
| `upgraded.md` | 8.7 KB | 任务板（版本 → 状态 → 详情链接） | 活跃 |
| `bench/RESULTS.md` | 13.8 KB | 逐题实测明细（策略/偏移/参数/踩坑） | 活跃，每次改能力都要补 |
| `results_remote/FLAGS.md` | 4.3 KB | 远程实打记录 + flag 证据 | 证据文件，保留 |

`upgraded/` 里保留 **`v6.0.0.md`**（v6 起点）与 **`v7.0.0.md`**（架构提案）。

## 3. 历史文档（建议归档到 `archive/v5/`）

| 文件 | 大小 | 为什么归档 |
|---|---|---|
| `v5_architecture.md` | 6.6 KB | v5 时代架构，已被 `ARCHITECTURE.md` 取代 |
| `v5_prd.md` | 6.5 KB | v5 需求书，已过期 |
| `v5_todo.md` | 1.5 KB | 内容已并入 `upgraded.md` |
| `upgraded/v5.0.1.md` ~ `v5.0.9.md` | 共 9 个 | v5 各切片记录 |
| `upgraded/appendix.md` | 5.6 KB | v5 附录 |
| `bugs/fix*.md` | 5 个 / 38 KB | 08-26~08-30 的历史缺陷记录 |
| `logs/comparison/summary.md` | 4.5 KB | 一次性的性能对比日志 |
| `autopwn/pwntools.md` | 301 B | 早期笔记（pwntools 用法） |

> `archive/v4/` 已经存在且结构正确，保持不动；v5 按同样方式归档即可。

## 4. 派生产物与运行产物（这是「乱」的主因）

### 4.1 派生产物：`bench/*/disasm.txt` + `bench/*/strings.txt`

| 项 | 值 |
|---|---|
| 文件数 | 30（15 题 × 2） |
| 体积 | **7.5 MB**（`ch10_static32/disasm.txt` 单个就 7.6 MB 之一） |
| 来源 | v6.0 早期我用 `objdump`/`strings` 导出的侦察中间件 |
| 代码依赖 | **无**（`grep -rn "disasm.txt\|strings.txt" autopwn/ docker/` 为空） |
| 处理 | 删除 + gitignore；需要时用一行命令重生成 |

重生成方式：
```bat
solve.bat bench\ch10_static32 --facts-only   :: 引擎自己会反汇编，不需要人工导出
:: 或容器内临时导出
docker run --rm -v "%CD%:/work" -w /work autopwn:pwn22 sh -c "for d in bench/ch*; do objdump -d -M intel $d/bin > $d/disasm.txt; strings -a $d/bin > $d/strings.txt; done"
```

### 4.2 运行产物

| 路径 | 现状 | 处理 |
|---|---|---|
| `results/*.json` | 34 个、79 KB，**每次跑都会变**（`git status` 里常年一片 M） | `git rm --cached` + gitignore，本地保留 |
| `results_remote/*.json` | 同上 | 同上（`FLAGS.md` 保留跟踪） |
| `_target/` | `target.bat` 生成的靶机目录 | 已 gitignore |
| `.*.run/` | 每题的运行副本 | 已 gitignore |
| `rsys_dbg/`、`results_docker/` | 临时调试输出 | 删除或 gitignore |
| `Challenge/` | 上话题库（`chall`/`ret2win`/`libc.so.6`），未跟踪 | 加进 gitignore，别误提交 |

## 5. 执行命令（**未执行，等确认**）

### 5.1 低风险：只删派生产物（7.5 MB，随时可重生成）

```bat
cd /d D:\ctf\ctf-env\autopwn
git rm -r --cached bench --quiet
git add bench
del /s /q bench\ch*\disasm.txt bench\ch*\strings.txt
```
然后 `.gitignore` 追加：
```
bench/*/disasm.txt
bench/*/strings.txt
```

### 5.2 中风险：历史文档归档（移动，不删除）

```bat
mkdir archive\v5\upgraded archive\bugs
move v5_architecture.md v5_prd.md v5_todo.md archive\v5\
move upgraded\v5.0.*.md upgraded\appendix.md archive\v5\upgraded\
move bugs\fix*.md archive\bugs\
move logs\comparison\summary.md archive\v5\
move autopwn\pwntools.md archive\v5\
git add -A archive v5_architecture.md v5_prd.md v5_todo.md upgraded bugs logs autopwn
```
> 归档后 `upgraded.md` 的任务板里 v5 行的链接会失效，需要一起改指向 `archive/v5/upgraded/`。

### 5.3 低风险：运行产物移出版本库

```bat
git rm -r --cached results results_remote --quiet
```
`.gitignore` 追加：
```
results/
results_remote/*.json
rsys_dbg/
results_docker/
Challenge/
```
> `results_remote/FLAGS.md` 要保留跟踪（证据），所以只忽略 `*.json`。

## 6. 清理后的目标结构

```
autopwn/
├── README.md              入口
├── ARCHITECTURE.md        现状架构
├── PROGRESS.md            进度与基线
├── HANDOVER.md            交接说明
├── CLAUDE.md              给 Claude 的指针
├── DOC_MAP.md             本文件
├── CHEATSHEET.md          赛前速用卡
├── AGENTS.md              治理铁律
├── upgraded.md            任务板（只留 v6+ 行）
├── autopwn/engine/        引擎源码（2960 行）
├── docker/                Dockerfile、serve.sh、变体生成器、评测脚本
├── bench/                 15 题 + RESULTS.md（不再有 disasm.txt）
├── bench_extra/           8 题（经典题型泛化）
├── bench_sys/             4 个变体（syscall 策略回归）
├── chellenges/            当前比赛附件（3 题）
├── upgraded/              v6.0.0.md、v7.0.0.md
└── archive/               v4/（已存在）、v5/（本次归档）
```
