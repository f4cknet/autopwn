# AutoPwn 重构实施历史（rebuild.md · v4.0 历史）

> **角色**：v3.1 → v4.0.dev0 重构的**实施历史档案**
> **状态**：重构 **已完成**（6/6 里程碑 + M6 全部 ✅ 2026-06-10）
> **未来开发规范**：见 [`upgraded.md`](./upgraded.md)
> **核心治理规则**：见 [`AGENTS.md`](./AGENTS.md) §1 四条铁律
> **架构演进史**：见 [`refactor.md`](./refactor.md) §1 / §3 / §9 / §13
> **本文件保留内容**：P0-P11 阶段总结表 + 重构期约定（§2 状态图例、§9.4 分支策略历史、§11 附录）
> **本文件删除内容**：§4 详细任务看板 + §6 4000 行详细任务步骤 + §5 阶段依赖图 + §7 Review checklist 详细 + §8 风险（已 Mitigated）+ §10 阻塞表（已 Resolved）

---

## 0. 阅读指引

| 你是谁 | 先看哪一节 |
|---|---|
| **找当前任务 / 准备开发** | **必读 [`upgraded.md`](./upgraded.md)**（v4.0+ 迭代流程）|
| **理解 v4.0 架构** | [`refactor.md`](./refactor.md) §1（重构起点）+ §3（已落地架构）|
| **理解 v3.1 → v4.0 演进** | [`refactor.md`](./refactor.md) §13 + 本文件 §3 阶段总结 |
| **AI Agent session 启动** | [`AGENTS.md`](./AGENTS.md) §5（5 步启动）+ 本文件 §2 状态图例 |
| **重构期历史追溯** | `git log --oneline` + 本文件 §3 阶段总结 |

---

## 2. 状态图例与命名约定

### 2.1 任务状态

| 图标 | 状态 | 含义 |
|---|---|---|
| ⏳ | Pending | 已规划，未开始 |
| 🔄 | In Progress | 正在做 |
| 👀 | In Review | PR 已开，等 Review |
| ✅ | Done | 已合并到主分支 |
| ⚠️ | Blocked | 阻塞中 |
| ❌ | Cancelled | 不再需要 |

### 2.2 任务 ID（重构期 P 阶段）

- 格式：`P{阶段}.{子任务序号}`，例如 `P0.3`
- 同一子任务被拆分时，追加字母：`P7.2a`、`P7.2b`
- v4.0+ 迭代任务改用 `upgraded.md` 中 `v{X}.{Y}.{Z}` 格式

### 2.3 优先级（重构期）

- 🔴 P0：阻塞后续阶段
- 🟡 P1：当前 sprint 必做
- 🟢 P2：排进 backlog

### 2.4 预估工时

单位：人时（h）或人天（d）。每人每天 ≤ 6h 有效编码时间。

---

## 3. 总体里程碑（全部完成 · 2026-06-10）

| # | 里程碑 | 阶段 | 状态 | 关键产物 |
|---|---|---|---|---|
| **M0** | 项目骨架就位 | P0 + P1 | ✅ | `autopwn/` 包 + `pyproject.toml` |
| **M1** | 状态显式化 | P2 + P3 | ✅ | `ExploitContext` + `report/` 模块 + `_legacy.py` 删 |
| **M2** | 收集与检测层化 | P4 + P5 | ✅ | `recon/` + `detect/` 完整 + 95% public API coverage |
| **M3** | 利用层抽象 | P6 + P7 | ✅ | `primitives/` + `exp/strategies/`（12 类 40 strategies）|
| **M4** | 编排重写 | P8 | ✅ | `orchestrator.py` + 4/5 SUCCESS 持平 v3.1 |
| **M5** | 工程化 | P9 + P10 | ✅ | 626 unit tests + CI + pip install |
| **M6** | v4.0.dev0 内部打磨 | P11 | ✅ | docs 清理 + 6 关验证 + coverage 44% + orchestrator 拆分 |

**整体进度**：7/7 里程碑完成（6 核心 + 1 内部打磨期）

### 3.1 P 阶段任务总结表（替换原 §4 详细任务看板）

> 完整 P 阶段任务看板见 `git log --oneline --grep="P[0-9]" | head -100` 或 `git show <commit>`。

| 阶段 | 任务数 | 关键任务 | Owner 拍板数 | 完成日期 |
|---|---|---|---|---|
| **P0** | 9 (P0.0-P0.8) | 改名 pwnpasi→autopwn + 验证基础设施 + v3.1 vs v4.0 对比 | 4 (B-001 团队 + B-002 验证 + R10 改名 + R12 品牌) | 2026-06-07 |
| **P1** | 8 (P1.1-P1.6 + P1.3a-d) | `core/` 层（logging + fs + runner + 14 工具）| 0 (走 spec) | 2026-06-07 |
| **P2** | 4 (P2.1-P2.4) | `ExploitContext` 落地 + 桥函数 | 0 (走 spec) | 2026-06-07 |
| **P3** | 6 (P3.1-P3.6) | `report/` 层（model + docx + code + fallback）| 0 (走 spec) | 2026-06-08 |
| **P4** | 9 (P4.1-P4.8 + P4.4b) | `recon/` 层（checksec + libc + plt + rop + asm + bss）| 1 (P4.4b B-006 fix) | 2026-06-08 |
| **P5** | 5 (P5.1-P5.5) | `detect/` 层（canary + overflow + fmtstr + binsh）| 0 (走 spec) | 2026-06-08 |
| **P6** | 10 (P6.1-P6.9 + P6.3b + P6.4b) | `primitives/` 层（9 个 primitive + 单元测试）| 1 (P6.4b B-007 fix) | 2026-06-09 |
| **P7** | 12 (P7.1-P7.12) | `exp/strategies/`（12 strategy 类，40 strategies）| 1 (B-003 优先级) | 2026-06-09 |
| **P8** | 6 (P8.1-P8.6) | `orchestrator.py` + cli 调度 + 4/5 SUCCESS | 2 (B-006 + B-007) | 2026-06-09 |
| **P9** | 6 (P9.1-P9.6) | 单元测试 + CI（604 tests）| 0 (走 spec) | 2026-06-09 |
| **P10** | 4 (P10.1-P10.4) | 打包升级（pyproject.toml + setup.py + pip install）| 0 (走 spec) | 2026-06-09 |
| **P11** | 6 (P11.0-P11.5) | M6 内部打磨（docs + 6 关 + coverage + baseline + orchestrator）| 0 (走 spec) | 2026-06-10 |

**总计**：85 个 P 阶段子任务，9 次 Owner 拍板决策，4 次阻塞登记（全部 Resolved），7 次 git tag（无 — 0 个 tag，per 治理变更 1.5 删 dev 角色后 main 是唯一分支）。

### 3.2 §6 详细任务步骤（替换原 4088 行）

> 完整实施记录见 `git log --oneline --grep="P[0-9]" --format="%H %s"` 每个 commit message 含任务 ID + 实施要点。
> 详细实施记录（4000+ 行）保留在 `git reflog` + git history 中（永不删除），不重复放在本文档。

每阶段关键要点：

- **P0 (项目骨架)**：项目改名 pwnpasi→autopwn (P0.0 临时需求 #1) + 验证基础设施 (P0.7 临时需求 #2) + v3.1 vs v4.0 严格对比 96% PASS (P0.8)
- **P1 (`core/`)**：Colors + print_* + set_permission + 14 个 binutils/ropper/qemu 工具包装
- **P2 (`ExploitContext`)**：6 个 dataclass + from_args 工厂 + _compat.py 桥
- **P3 (`report/`)**：ExploitInfo model + generate_docx + generate_code + markdown fallback
- **P4 (`recon/`)**：checksec + libc + plt + rop（gadget 解析含 P4.4b 修复 hex→int 契约）
- **P5 (`detect/`)**：canary 5-byte fuzz + overflow + fmtstr probe + binsh
- **P6 (`primitives/`)**：9 个 primitive（ret2system/ret2libc-put/ret2libc-write/rwx-shellcode/execve-syscall/fmtstr/pie-backdoor/...）+ P6.4b 修 3 变体 cascade
- **P7 (`exp/strategies/`)**：12 strategy 类（40 strategies），按 priority 排序（CANARY 200 → PIE_BACKDOOR 180 → RET2SYSTEM 150 → RET2LIBC_PUT 120 → ...）
- **P8 (`orchestrator`)**：recon+detect+strategy 三阶段调度 + 4/5 SUCCESS 持平 v3.1
- **P9 (CI)**：GitHub Actions 2 jobs (test+lint) + 604 unit tests
- **P10 (打包)**：`pyproject.toml` 完整 + `setup.py` 最小转发 + `pip install -e .`
- **P11 (M6 打磨)**：docs 清理 + 6 关 4/5 SUCCESS 验证 + coverage 43.5%→44% (4 个 error-path tests) + sha256sum baseline lockfile + orchestrator.py 拆 4 文件子包 (361→92)

### 3.3 §5 阶段依赖图（替换原依赖图）

> 阶段依赖图简化为线性：P0 → P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8 → P9 → P10 → P11
> 实际可并行（如 P4 + P5 部分并行 P6），但单 Owner 项目按顺序推进。
> 详见 [`refactor.md §7`](./refactor.md)（拆分阶段表）。

### 3.4 §7 Review 检查清单（替换原详细 checklist）

> 完整 Review 清单见 [`AGENTS.md §3`](./AGENTS.md) 违规分级 L1/L2/L3。
> 简单版：
> 1. PR 标题引用任务 ID
> 2. 6 关验收全过（pytest unit + integration + 关键日志 + Owner 自审 + 文档同步）
> 3. 不跨层 / 不跨阶段
> 4. 单 PR ≤ 400 行 diff

### 3.5 §8 风险（已 Mitigated，替换原 17 行风险表）

| 风险 | 状态 |
|---|---|
| R8 set_function_flags 标志位拆分 | ✅ Resolved via P3 收尾 |
| R13 race condition (Information_Collection.txt 共享污染) | ✅ Resolved via P0.7 串行 runner + P1 `core/fs.py` tempfile |
| R14 runner 工具接口漂移 | ✅ Resolved via P1.3a-d 范式基线 |
| R15 Owner handle 变更 (@Ba1_Ma0 → @Minzhi_Zhou) | ✅ Resolved via 1.3 changelog 50 处全替换 |
| R16 P4.4/P6.4 契约错位 (B-006) | ✅ Resolved via P4.4b (P4.4b commit 8c3bc7c) |
| R17 P6.4/P6.3 漏读 extra_rdi/extra_rsi (B-007) | ✅ Resolved via P6.3b + P6.4b (commit 1df463c) |

### 3.6 §10 阻塞登记表（全部 Resolved，0 open）

> **当前 open 阻塞 = 0**（2026-06-10 M6 启动时状态）。v3.1 → v4.0.dev0 重构周期所有阻塞已 Resolved。
> **已 Resolved 历史阻塞**（审计追踪保留）：B-001 / B-002 / B-003 / B-004 / B-005 / B-006 / B-007 — 全部 `git log --grep="B-0"` 可查。
> **新迭代流程**（v4.0+）走 [`upgraded.md`](./upgraded.md) §10 阻塞表（替代 §10）。

---

## 9. 同步与协作机制（v4.0 仍是规范）

### 9.4 分支策略（v4.0 + 2026-06-10 简化后）

> **2026-06-10 简化**（Owner 决策）：单 Owner 项目，删 `dev` 角色，`main` 是唯一长期分支。所有 PR target=`main`，主干开发模式。

| 分支 | 角色 | 保护 | 来源 / 流向 |
|---|---|---|---|
| `main` | **唯一长期分支**，CI 必绿 | 推荐: 禁止 force-push | 来源：feature/* / docs/* / fix/* 短期分支 PR；发布时打 tag `vN.M.P` |
| `docs/*` `fix/*` `feature/*` | **单任务短期分支** | 无 | fork 自 `main`；完成后 PR 回 `main`（单 Owner 项目 Owner 自审） |

**Inaugural（2026-06-08 B-005 / 2026-06-10 简化）**：
- v3.1 → v4.0.dev0 重构 6/6 里程碑 + M6 全部完成；`dev` 角色废除
- 单 Owner 项目简化：从 `main` 拉个人分支 `git checkout main && git pull && git checkout -b {docs|fix|feature}/{P{X}.{Y}|short-desc}`

**Feature 分支清理**（2026-06-10 Owner 特批）：
- 触发条件：分支内容已合 `main` 且 30 天内无未合 commit（`git rev-list --count main..branch` = 0）
- 清理动作：`git branch -D <branch>`（本地）+ `git push origin --delete <branch>`（远程）
- 安全网：git reflog 30 天可恢复
- 首次批量清理：2026-06-10 删 36 个本地 + 10 个远程 feature/*

### 9.5 提交信息规范

格式：`[P{阶段}.{子任务}] {动词} {对象}` 或 `[docs]` / `[fix]` 简短描述。
**v4.0+ 迭代任务**改用 `[v{X}.{Y}.{Z}] {动词} {对象}` 格式（per AGENTS.md §1 铁律 2）。

---

## 11. 附录

### 附录 A：决策树优先级（重构期 P7.2 拍板）

| 优先级 | Strategy |
|---|---|
| 200 | CANARY (canary binary 专用) |
| 180 | PIE_BACKDOOR (pie binary 专用) |
| 150 | RET2SYSTEM (32/64) |
| 120 | RET2LIBC_PUT (32/64) |
| 110 | RET2LIBC_WRITE (32/64) |
| 90 | RWX_SHELLCODE (32/64) |
| 80 | EXECVE_SYSCALL (32 only) |
| 50 | FMTSTR (兜底) |

### 附录 B：文件路径速查

| 旧 (v3.1 `autopwn.py`) | 新 (v4.0) |
|---|---|
| 顶层 `Colors` / `print_*` | `autopwn/core/logging.py` |
| 顶层 `set_permission` / 临时目录 | `autopwn/core/fs.py` |
| 顶层 `os.system('checksec ... > ...')` | `autopwn/core/runner.py:run_checksec()` |
| `exploit_info` dict | `autopwn/context.py:ExploitContext` |
| `handle_exploitation_success` | `autopwn/report/record_success()` |
| `generate_docx_report` | `autopwn/report/docx.py:generate_docx()` |
| `generate_exploitation_code` | `autopwn/report/code.py:generate_code()` |
| `ret2_system_x32` / `ret2_system_x64` | `autopwn/exp/strategies/ret2system_x32.py` / `_x64.py` |
| `main()` 决策树 (400 行 if) | `autopwn/orchestrator/run_recon_phase` + `run_detect_phase` + `run_strategy_phase` |

### 附录 C：维护铁律（精简版）

- 文档先行，新需求走铁律 2
- 任务必须有状态（⏳🔄👀✅⚠️❌）
- 未经验证 = 未完成（铁律 4 6 关）
- 重构期 P 阶段 ID：P{X}.{Y}（已废，改用 v{X}.{Y}.{Z}）
- v4.0+ 任务 ID：v{X}.{Y}.{Z}（per upgraded.md §3）

---

> **最后一条**：
> 重构已完成，所有 v3.1 → v4.0.dev0 演进历史归档在 `git log` + `refactor.md §13` + 本文件。
> **未来开发走**：[`upgraded.md`](./upgraded.md) — v4.0+ 迭代流程的单一事实来源。
