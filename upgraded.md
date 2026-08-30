# upgraded.md — AutoPwn v4.0+ 迭代索引

> **角色**：v4.0+ 迭代的**主索引与流程入口**——“今天起怎么开发 autopwn”
> **状态**：`4.0.dev0` 准备 GA（最近治理变更：1.13，2026-08-30）
> **配套文档**：
> - [`AGENTS.md`](./AGENTS.md) — 项目治理与 AI Agent 约束
> - [`refactor.md`](./refactor.md) — v4.0 架构演进史（WHY）
> - [`rebuild.md`](./rebuild.md) — v3.1 → v4.0 重构实施历史
> - [`upgraded/appendix.md`](./upgraded/appendix.md) — 文件路径 / 工具 / 模板速查
> - [`upgraded/backlog.md`](./upgraded/backlog.md) — 休眠 backlog 与历史未完成任务归档
> - [`upgraded/archive_completed.md`](./upgraded/archive_completed.md) — 历史已完成任务归档
> - [`upgraded/archive_state.md`](./upgraded/archive_state.md) — v4.1.21 前的详细状态快照
>
> **治理变更 1.12 / 1.13 · 2026-08-30**：`upgraded.md` 现在只保留阅读入口、流程、当前活动任务、待收尾任务、最近完成任务与验证基线；休眠 backlog、详细状态说明、附录速查统一下沉到 `upgraded/*.md`。

---

## 0. 阅读指引

| 你是谁 | 先看什么 |
|---|---|
| **第一次接触本项目** | `AGENTS.md` §1 → 本文件 §1 / §2 / §5 → `refactor.md §3` |
| **正在做当前任务** | 本文件 §3.1 / §3.2 → 对应 `upgraded/vX.Y.Z.md` → 本文件 §5 |
| **要续做历史 backlog** | `upgraded/backlog.md` 对应条目 → **先回填** 本文件 §3 + 新建 `upgraded/vX.Y.Z.md` → 再实施 |
| **只想找文件路径 / 工具脚本** | `upgraded/appendix.md` |
| **要追溯旧状态 / 历史决策** | `upgraded/archive_state.md` / `upgraded/archive_completed.md` / `rebuild.md` |

---

## 1. 当前状态

### 1.1 现状快照

- 当前开发版本：`4.0.dev0`，GA 收尾任务仍未完成
- 当前行为基线：**4/5 SUCCESS + canary PARTIAL**；`v4.1.18` 起，`canary_fuzz()` 默认带 **20s fail-fast budget**
- 当前治理模式：**单 Owner / 单目录 / 直接 `commit + push` 到 `main`**
- 主工作目录固定为 `D:\ctf\ctf-env\autopwn`（容器内 `/data/autopwn`）
- v4.1.21 前的详细状态长说明已迁到 [`upgraded/archive_state.md`](./upgraded/archive_state.md)

### 1.2 当前主线

- **当前活动任务**：`v4.1.19` 候选目标打分 + 利用链排序
- **待收尾任务**：`v4.1.14` / `v4.1.15` 仍处于 `👀`
- **最近治理完成**：`v4.1.21` 第二轮瘦身 `upgraded.md` 已落地
- **休眠 backlog**：其余历史未完成任务已下沉到 [`upgraded/backlog.md`](./upgraded/backlog.md)，默认不在主索引逐条展开

---

## 2. 迭代流程

### 2.1 任务来源

| 来源 | 要求 |
|---|---|
| Owner 新需求 | 在 §3 增加任务索引行 + 创建 `upgraded/vX.Y.Z.md` |
| 续做历史 backlog | 先从 `upgraded/backlog.md` 拆出 `upgraded/vX.Y.Z.md`，并**回填到 §3**，再写代码 |
| AI Agent 发现 | 不直接实施；先走需求澄清 / 立项 |
| 历史追溯 | 默认读 archive；非追溯场景不主动进入 |

### 2.2 单任务工作流

1. **立项**：在 §3 加任务索引行，写状态 / 预估 / 链接；详情写入 `upgraded/vX.Y.Z.md`
2. **实施**：在主目录 `D:\ctf\ctf-env\autopwn` / `/data/autopwn` 完成改动，并跑对应验收
3. **收尾**：`commit + push` 后，同提交更新 §3 索引行与详情文件完成记录

### 2.3 详情文件规则

- **当前活动 / 待收尾任务**：必须有专属 `upgraded/vX.Y.Z.md`，或有明确的 backlog 长记录可追溯
- **休眠 backlog**：允许先留在 `upgraded/backlog.md`，但**重新开工前必须拆出专属详情文件并回填主索引**
- 详情文件至少包含：背景、目标、范围、实施方向、风险、6 关验收
- `commit body` 若存在，需同时引用 `upgraded.md §3` 与对应详情文件

### 2.4 任务粒度

- 单个任务 ≤ 400 行 diff（不含 lock 文件）
- 同一批次 `commit/push` 不跨多个任务 ID
- 纯治理 / 文档任务也必须有索引行与状态

---

## 3. 任务看板

> **现行规则**：主索引只保留**当前活动任务**、**待收尾任务**与**最近完成任务**。休眠 backlog 与更早历史统一放在 `upgraded/*.md`；若某个历史 backlog 要续做，必须先回填到本节。

### 3.1 当前活动任务

| ID | 摘要 | 状态 | 预估 | 详情 |
|---|---|---|---|---|
| `v4.1.19` | 候选目标打分 + 利用链排序（含 `vuln/vulnerable` 弱信号） | ⏳ | 2h | [`v4.1.19`](./upgraded/v4.1.19.md) |

### 3.2 待收尾 / 待自审

| ID | 摘要 | 状态 | 预估 | 详情 |
|---|---|---|---|---|
| `v4.1.14` | `ctf_env` 工具链兼容层 | 👀 | 1h | [`backlog`](./upgraded/backlog.md#v4_1_14) |
| `v4.1.15` | x64 三参 write leak primitive 缺第三参数控制 | 👀 | 1.5h | [`backlog`](./upgraded/backlog.md#v4_1_15) |

### 3.3 最近完成

| ID | 摘要 | 状态 | 实际 | 详情 |
|---|---|---|---|---|
| `v4.1.21` | 第二轮瘦身 `upgraded.md` | ✅ | 0.5h | [`v4.1.21`](./upgraded/v4.1.21.md) |
| `v4.1.20` | `upgraded.md` 第一阶段索引化 | ✅ | 0.5h | [`v4.1.20`](./upgraded/v4.1.20.md) / `c261d49`, `63d4103` |
| `v4.1.18` | canary 检测 fail-fast 预算阈值 | ✅ | 1h | [`v4.1.18`](./upgraded/v4.1.18.md) / `e19d33f`, `aa46ad9` |

### 3.4 历史入口

- 休眠 backlog（当前收纳 14 条历史未完成任务）：[`upgraded/backlog.md`](./upgraded/backlog.md)
- 历史已完成任务快照：[`upgraded/archive_completed.md`](./upgraded/archive_completed.md)
- v4.1.21 前的详细状态说明：[`upgraded/archive_state.md`](./upgraded/archive_state.md)

### 3.5 open 阻塞

_（无 — 2026-08-30）_

---

## 4. 当前架构（精简）

详细 WHY 与分层演进：见 [`refactor.md §3`](./refactor.md)

```text
CLI / Orchestrator
        ↓
Strategies
        ↓
Primitives
        ↓
Detect
        ↓
Recon
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
4. **关 4**：若涉及 `autopwn` 行为，至少复测 1 个 `Challenge/`；5-binary 基线仍以 **4/5 SUCCESS + canary PARTIAL** 为准
5. **关 5**：Owner 自审
6. **关 6**：同提交同步索引行、详情文件、必要归档

### 5.1 近期参考基线（2026-08-30）

- 单元测试：`740 passed, 2 warnings`
- 相关 integration 子集：`4 passed, 1 skipped, 1 xfailed`
- 手工 `Challenge/canary`：默认可在 detect 阶段 **20s fail-fast**，不再无界刷 `Starting local process`

---

## 6. 速查入口

- 文件路径 / 工具 / 模板：[`upgraded/appendix.md`](./upgraded/appendix.md)
- 休眠 backlog：[`upgraded/backlog.md`](./upgraded/backlog.md)
- 历史已完成任务：[`upgraded/archive_completed.md`](./upgraded/archive_completed.md)
- 详细状态长说明：[`upgraded/archive_state.md`](./upgraded/archive_state.md)
- 修复记录索引：[`bugs/fix.md`](./bugs/fix.md)

---

> **最后一条**：
> `upgraded.md` 现在只负责“把你带到正确的当前信息”；历史长记录与速查内容按需进入 `upgraded/*.md`。