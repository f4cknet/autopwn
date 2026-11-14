# DOC_MAP — 文档地图

> 目的：让接手的人 30 秒内知道「哪份文档是活的、哪份是历史」。
>
> **2026-11-13 清理已执行**（详见 §4）。根目录现只保留 7 份活跃文档。

## 1. 活跃文档（根目录，7 份）

| 文件 | 给谁 | 职责（**唯一来源**） | 不该写什么 |
|---|---|---|---|
| [`README.md`](./README.md) | 所有人 | 项目定位、成功判据、快速开始、覆盖题型 | 不写详细架构与基线数字 |
| [`CLAUDE.md`](./CLAUDE.md) | Claude Code | 读文档顺序、必跑命令、最易违反的 5 条 | 不重复铁律全文（指向 AGENTS） |
| [`AGENTS.md`](./AGENTS.md) | 所有 AI Agent | 治理规则：5 条铁律、违规升级、高危区 | 不写架构、不写任务状态 |
| [`HANDOVER.md`](./HANDOVER.md) | 接手开发者 | 上手步骤、环境坑、加策略 recipe、验收清单 | 不写完整的 API 表（指向 ARCHITECTURE） |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | 接手开发者 | 分层数据流、数据结构、策略清单、判定链 | 不写版本演进与基线数字 |
| [`PROGRESS.md`](./PROGRESS.md) | 所有人 | **唯一**基线数字来源：版本演进、能力矩阵、已知边界 | 不写架构细节 |
| [`CHEATSHEET.md`](./CHEATSHEET.md) | 比赛现场 | 一页命令速查 + 排错对照表 | 不写开发流程 |

## 2. 附属文档（子目录）

| 文件 | 职责 |
|---|---|
| [`upgraded.md`](./upgraded.md) | 任务看板（v7 待办 + v6 已完成）；只做「任务 → 状态 → 详情」索引 |
| [`upgraded/v7.0.0.md`](./upgraded/v7.0.0.md) | 四层管线架构提案（下一步方向） |
| [`upgraded/v7.0.1.md`](./upgraded/v7.0.1.md) | L1 交互层（`Send`/`Wait`）设计与实施记录 |
| [`upgraded/v7.0.2.md`](./upgraded/v7.0.2.md) | L3 判定统一（`oracle.py`）设计与实施记录 |
| [`upgraded/v7.0.3.md`](./upgraded/v7.0.3.md) | repeater 解锁（fmt 误报修复 / 推 main / canary_echo）设计与实施记录 |
| [`upgraded/v7.0.4.md`](./upgraded/v7.0.4.md) | 远程 libc 识别（low12 指纹 / 候选轮换）设计与实施记录 |
| [`upgraded/v6.0.0.md`](./upgraded/v6.0.0.md) | v6 引擎的首版设计与实施记录 |
| [`bench/RESULTS.md`](./bench/RESULTS.md) | 逐题策略 / 偏移 / 关键参数 / 踩坑（复盘与回归依据） |
| [`bugs/fix.md`](./bugs/fix.md) | Bug 修复索引（单条记录 `bugs/fix_<name>.md`） |
| [`archive/v4/`](./archive/v4/) | v4 历史（已完成，仅审计用） |
| [`archive/v5/`](./archive/v5/) | v5 历史（架构 / PRD / TODO / 迭代详情 / 日志） |

## 3. 历史文档（已归档，**不要在这里新增**）

| 原路径 | 现路径 | 归档原因 |
|---|---|---|
| `v5_architecture.md` | `archive/v5/` | v5 分层设计（verifier / capability / planner），v6 已用 `autopwn/engine` 另一套实现取代 |
| `v5_prd.md` | `archive/v5/` | v5 需求文档，v6 的能力边界改由 `PROGRESS.md §3` 描述 |
| `v5_todo.md` | `archive/v5/` | v5 路线图，已被 `upgraded/v7.0.0.md` 取代 |
| `upgraded/v5.0.*.md` + `appendix.md` | `archive/v5/upgraded/` | v5 迭代详情（9 份） |
| `logs/` | `archive/v5/logs/` | v4/v5 调试日志 |
| `tools/*.py` | `scripts/audit/` | v3/v4 时代的一次性校验脚本 |

## 4. 已执行的清理（2026-11-13）

| 动作 | 对象 | 结果 |
|---|---|---|
| 归档 | `v5_*.md` 3 份 + `upgraded/v5.0.*` 9 份 + `logs/` | → `archive/v5/` |
| 重写瘦身 | `AGENTS.md`（273 → ~150 行）、`upgraded.md`（188 → ~90 行） | 删掉 v4 治理细节与 08-30 旧基线，修掉 3 处断链 |
| 聚合 | `scripts/test/`（`baseline_lock.sh`、`run_verify.sh`）、`scripts/audit/`（3 个 `check_*.py` / `verify_*.py`） | 脚本集中在 `scripts/` |
| 收敛结果目录 | `results_chellenges/` `results_extra/` `results_remote/` `results_docker/` | → `results/{chellenges,extra,remote,docker}/` |
| 删除生成物 | `build/`、`autopwn.egg-info/`、`.pytest_cache/`、`rsys_dbg/` | 均在 .gitignore 内，可重建 |
| 删除派生产物 | `bench/*/disasm.txt` + `strings.txt`（30 文件 / **7.6 MB**） | 已删除并 gitignore；`objdump`/`strings` 可随时重生成 |
| 新增门禁 | `scripts/audit/check_hygiene.py` | 根目录白名单 / 临时文件 / results 误入库 / 构建产物 / 大文件，非 0 退出则不许提交 |

## 5. 剩余可选清理

| 项 | 体积 | 建议 | 风险 |
|---|---|---|---|
| `Challenge/` | 10 项 | **保留** | 不可删：`tests/conftest.py` 硬依赖它（可用 `AUTOPWN_CHALLENGE_DIR` 覆盖） |
| `writeups/*.docx` | 5 份 | 保留 | 解题报告，属内容资产，不是噪音 |
| `results/*`、`_target/`、`.*.run/` | — | 已在 .gitignore，本地保留 | 无 |

## 6. 目录约定

```
autopwn/
├── autopwn/engine/     引擎源码（facts / strategies / interact / oracle / libcsearch / orchestrator / run / model / cli）
├── docker/             镜像、靶机（serve.sh）、评测入口（solve.sh / bench_all.sh）
├── bench/              15 道比赛原题（回归主基准）
├── bench_extra/        8 道经典题型（泛化验证）
├── bench_sys/          4 个尺寸变体（syscall 策略回归）
├── chellenges/         当前比赛附件（原始 ELF / zip / 平铺目录，可直接跑）
├── Challenge/          仓库自带经典题（pytest 依赖，勿移动）
├── scripts/
│   ├── test/           评测与回归脚本
│   └── audit/          审计脚本（含 `check_hygiene.py` 仓库卫生门禁）
├── bugs/               修复记录（fix.md 索引 + 单条 fix_<name>.md）
├── upgraded/           任务详情（v6.0.0、v7.0.0~v7.0.4）
├── results/            每次尝试的证据（本地 / chellenges / extra / remote / docker）
├── archive/            v4、v5 历史归档
├── writeups/           解题报告（docx）
└── *.bat               solve / target / build_pwn / shell（Windows 入口）
```
