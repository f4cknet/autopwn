# upgraded.md — AutoPwn v5 迭代索引

> **角色**：v5 的**主索引与流程入口**
> **状态**：`5.0.dev0` 文档基线已建立（当前活动任务：无；最近完成：`v5.0.4`，2026-08-30）
> **配套文档**：
> - [`AGENTS.md`](./AGENTS.md) — 项目治理与 AI Agent 约束
> - [`v5_prd.md`](./v5_prd.md) — v5 当前需求
> - [`v5_architecture.md`](./v5_architecture.md) — v5 当前架构
> - [`upgraded/appendix.md`](./upgraded/appendix.md) — 文件路径 / 工具 / 模板速查
> - [`archive/v4/README.md`](./archive/v4/README.md) — v4 历史归档入口
>
> **治理变更 1.14 · 2026-08-30**：v4 文档已归档到 `archive/v4/`，本文件切换为 v5 当前任务索引。

---

## 0. 阅读指引

| 你是谁 | 先看什么 |
|---|---|
| **第一次接触本项目** | `AGENTS.md` → 本文件 → `v5_prd.md` → `v5_architecture.md §3` |
| **正在做当前任务** | 本文件 §3.1 → 对应 `upgraded/vX.Y.Z.md` → `v5_architecture.md` |
| **要续做历史 backlog** | `archive/v4/upgraded/backlog.md` 对应条目 → **先回填** 本文件 §3 + 新建 `upgraded/vX.Y.Z.md` → 再实施 |
| **只想找文件路径 / 工具脚本** | `upgraded/appendix.md` |
| **要追溯旧状态 / 历史决策** | `archive/v4/README.md` / `archive/v4/upgraded.md` / `archive/v4/rebuild.md` |

---

## 1. 当前状态

### 1.1 现状快照

- 当前开发主线：`v5`
- 当前行为基线：**5/5 SUCCESS**；`v4.1.22` 已为本地 x32 `fmt leak -> second input BOF` 题型补齐 same-session canary 路线，`canary_fuzz()` 仍保留 **20s fail-fast budget** 作为回退
- 当前治理模式：**单 Owner / 单目录 / 直接 `commit + push` 到 `main`**
- 主工作目录固定为 `D:\ctf\ctf-env\autopwn`（容器内 `/data/autopwn`）
- v4 详细状态、旧 backlog 与历史任务已统一归档到 [`archive/v4/`](./archive/v4/)

### 1.2 当前主线

- **当前活动任务**：_无_
- **最近完成**：`v5.0.4` 已建立能力层基础层，并把 same-session canary 与 2-stage ret2libc-write 路线映射为 capability 链
- **当前非目标**：尚未进入 planner / unified verifier 主体迁移

---

## 2. 迭代流程

### 2.1 任务来源

| 来源 | 要求 |
|---|---|
| Owner 新需求 | 在 §3 增加任务索引行 + 创建 `upgraded/vX.Y.Z.md` |
| 续做历史 backlog | 先从 `archive/v4/upgraded/backlog.md` 找来源，再**回填到 §3** 并新建 `upgraded/vX.Y.Z.md` |
| AI Agent 发现 | 不直接实施；先走需求澄清 / 立项 |
| 历史追溯 | 默认读 archive；非追溯场景不主动进入 |

### 2.2 单任务工作流

1. **立项**：在 §3 加任务索引行，写状态 / 预估 / 链接；详情写入 `upgraded/vX.Y.Z.md`
2. **实施**：在主目录 `D:\ctf\ctf-env\autopwn` / `/data/autopwn` 完成改动，并跑对应验收
3. **收尾**：`commit + push` 后，同提交更新 §3 索引行与详情文件完成记录

### 2.3 详情文件规则

- **当前活动 / 待收尾任务**：必须有专属 `upgraded/vX.Y.Z.md`，或有明确的 backlog 长记录可追溯
- **历史 backlog**：默认留在 `archive/v4/upgraded/backlog.md`，但**重新开工前必须拆出专属详情文件并回填主索引**
- 详情文件至少包含：背景、目标、范围、实施方向、风险、6 关验收
- `commit body` 若存在，需同时引用 `upgraded.md §3` 与对应详情文件

### 2.4 任务粒度

- 单个任务 ≤ 400 行 diff（不含 lock 文件）
- 同一批次 `commit/push` 不跨多个任务 ID
- 纯治理 / 文档任务也必须有索引行与状态

---

## 3. 任务看板

> **现行规则**：主索引只保留**v5 当前活动任务**；v4 历史任务与 backlog 统一放在 `archive/v4/`。

### 3.1 当前活动任务

_（无 — 2026-08-30）_

### 3.2 待收尾 / 待自审

_（无 — 已归档到 `archive/v4/`）_

### 3.3 最近完成

| ID | 摘要 | 状态 | 实际 | 详情 |
|---|---|---|---|---|
| `v5.0.4` | 建立能力层基础层，把 facts + interaction 映射为可解释 exploit capability | ✅ | 3h | [`v5.0.4`](./upgraded/v5.0.4.md) |
| `v5.0.3` | 建立交互图基础层，并接入 same-session canary 与 2-stage ret2libc 路线 | ✅ | 3h | [`v5.0.3`](./upgraded/v5.0.3.md) |
| `v5.0.2` | 建立事实作用域 / 生命周期基础层，并接入首批 detect / strategy producer | ✅ | 3h | [`v5.0.2`](./upgraded/v5.0.2.md) |
| `v5.0.1` | 治理变更实施 + 文档落盘 | ✅ | 1h | [`v5.0.1`](./upgraded/v5.0.1.md) |
| `v4 archive` | 历史完成任务与 backlog 已统一迁入 `archive/v4/` | ✅ | - | [`archive/v4/README.md`](./archive/v4/README.md) |

### 3.4 历史入口

- v4 归档入口：[`archive/v4/README.md`](./archive/v4/README.md)
- v4 历史索引：[`archive/v4/upgraded.md`](./archive/v4/upgraded.md)
- v4 任务详情 / backlog / 状态：[`archive/v4/upgraded/`](./archive/v4/upgraded/)

### 3.5 open 阻塞

_（无 — 2026-08-30）_

---

## 4. 当前架构（精简）

详细当前架构：见 [`v5_architecture.md §3`](./v5_architecture.md)

```text
CLI / Orchestrator
        ↓
Planner
        ↓
Executor / Legacy Strategy Adapter
        ↓
Capability IR
        ↓
Interaction Graph
        ↓
Scope / Lifetime Facts
        ↓
Recon / Detect Producers
        ↓
Core
```

常用入口：
- CLI：`autopwn/cli.py`
- 编排：`autopwn/orchestrator/*`
- 上下文：`autopwn/context.py`
- 策略注册：`autopwn/exp/registry.py`

完整文件路径、工具脚本与模板已迁到 [`upgraded/appendix.md`](./upgraded/appendix.md)。

---

## 5. 验证方法（6 关验收）

1. **关 1**：代码已 push 到 `main`
2. **关 2**：`pytest tests/unit -m "not integration" -q` 全过
3. **关 3**：若涉及行为变化，跑对应 integration / `Challenge/` 验证
4. **关 4**：若涉及 `autopwn` 行为，至少复测 1 个 `Challenge/`；当前 5-binary 基线以 **5/5 SUCCESS** 为准
5. **关 5**：Owner 自审
6. **关 6**：同提交同步索引行、详情文件、必要归档

### 5.1 近期参考基线（2026-08-30）

- 单元测试：`763 passed`
- 相关 integration 子集：`5 passed, 1 skipped`
- 手工 `Challenge/canary`：detect 阶段会产出 `same-session canary plan`（`stack_index=55 / buffer_to_canary=64 / post_canary_padding=12`），strategy 通过 `whoami` 验证拿到 `root`
- 手工 `Challenge/level3_x64`：2-stage ret2libc-write 路线可稳定完成，验证输出为 `ID_OUTPUT='PWNED\n'`

---

## 6. 速查入口

- 当前需求：[`v5_prd.md`](./v5_prd.md)
- 当前架构：[`v5_architecture.md`](./v5_architecture.md)
- 文件路径 / 工具 / 模板：[`upgraded/appendix.md`](./upgraded/appendix.md)
- v4 归档入口：[`archive/v4/README.md`](./archive/v4/README.md)
- 修复记录索引：[`bugs/fix.md`](./bugs/fix.md)

---

> **最后一条**：
> `upgraded.md` 现在只负责“把你带到正确的当前信息”；历史长记录与速查内容按需进入 `upgraded/*.md`。
