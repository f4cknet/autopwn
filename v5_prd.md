# AutoPwn v5 PRD

> **角色**：v5 当前需求文档与迭代总纲。
> **用途**：定义要做什么、为什么做、做到什么程度算完成。
> **状态**：生效中（2026-08-30）

## 1. 定义

AutoPwn v5 面向 CTF / 离线训练场景，目标是把自动化 pwn 从“strategy 枚举”推进到“事实 → 交互 → 能力 → 计划 → 验证”的可解释路线。

## 2. 当前目标

1. 保留已验证运行基线
2. 显式建模事实作用域（binary / process / session / attempt）
3. 显式建模多阶段交互
4. 把 leak / write / control / exec / verify 抽象成可组合能力
5. 让 exploit 路线选择可解释、可验证

## 3. 非目标

- 一次性重写全部 runtime
- 只为单题成功率继续堆特判
- 删除 v4 历史记录

## 4. 当前成功标准

- v5 文档主线已生效
- v4 继承基线不回退
- 后续 `v5.0.x` 按“文档 → 实施 → 验证”推进

## 5. 继承基线（2026-08-30）

- unit：`763 passed`
- integration 子集：`5 passed, 1 skipped`
- 手工：`Challenge/canary` 可通过 `whoami` 拿到 `root`
- 手工：`Challenge/level3_x64` 可稳定完成 2-stage ret2libc-write，并返回 `ID_OUTPUT='PWNED\n'`

## 6. 近期路线

- `v5.0.1`：文档重置
- `v5.0.2`：事实作用域 / 生命周期（FactScope / FactStore / 首批 producer 接入）
- `v5.0.3`：交互图（same-session / multi-stage route 显式化）
- `v5.0.4`：能力层（Capability IR / route 可执行性表达）
- `v5.0.5+`：planner / verifier

### 6.1 `v5.0.2` 完成标准

- 在 `autopwn/context.py` 建立最小可用的事实存储层
- 显式区分 `binary / process / session / attempt` 四类作用域
- 至少让一批现有 producer 把关键检测结果同步进 fact store
- 保留现有 `ctx.padding` / `ctx.canary` / `ctx.canary_plan` 等兼容视图，避免一次性重写全部 runtime

### 6.2 `v5.0.3` 完成标准

- 在 runtime 中建立最小可用的 `InteractionGraph`
- 能显式表达多阶段 leak → reentry → execute → verify 顺序
- 至少接入 1 条 same-session 链路和 1 条普通 2-stage ret2libc 链路
- 与 `v5.0.2` 的 fact store 协同，不破坏当前 5/5 SUCCESS 基线

### 6.3 `v5.0.4` 完成标准

- 在 runtime 中建立最小可用的 `Capability` 建模层
- capability 必须绑定 `FactScope`、`InteractionGraph` 与首批 `leak / control / exec / verify` 能力表达
- 至少接入 1 条 same-session canary 路线和 1 条普通 2-stage ret2libc 路线，并保持当前 5/5 SUCCESS 基线

## 7. 需求 / 架构 / 迭代 / 进度 分工

- `v5_prd.md`：定义为什么做、做什么、做到什么程度算完成
- `v5_architecture.md`：定义怎么做、模块怎么拆、依赖怎么流
- `upgraded.md`：定义当前做到哪一步、谁在做、最近完成了什么
- `upgraded/vX.Y.Z.md`：定义单次迭代的背景、范围、风险、验收

## 8. 迭代计划（高层）

| 阶段 | 状态 | 目标 | 主要产出 |
|---|---|---|---|
| v5.0.1 | 完成 | 文档重置与基线归档 | `upgraded.md` / `v5_prd.md` / `v5_architecture.md` / `archive/v4/` |
| v5.0.2 | 完成 | Facts / Scope | `FactStore` / 作用域事实 |
| v5.0.3 | 完成 | InteractionGraph | 多阶段交互显式化 |
| v5.0.4 | 完成 | Capability IR | `Capability` 建模 |
| v5.0.5 | 完成 | Planner 入口 | plan 生成与 legacy adapter 并存 |
| 下一步候选 | 待立项 | Unified verifier | 统一成功判定与回归口径 |
| 后续候选 | 待立项 | Legacy adapter 收敛 | fallback 逐步缩小 |

### 8.1 进度口径

1. `upgraded.md` 负责“当前做什么 / 最近完成什么”
2. `v5_prd.md` 负责“为什么做 / 做到什么算完”
3. `v5_architecture.md` 负责“怎么做 / 模块怎么拆”
4. 每个新需求都必须先立任务，再写实现

## 9. 需求清单（详细）

> 说明：本节只定义“需求与验收”，不承载执行状态；执行状态统一以 `upgraded.md` 为准。

| ID | 需求 | 优先级 | 验收标准 | 架构映射 |
|---|---|---:|---|---|
| RQ-01 | 事实层标准化 | P0 | binary / process / session / attempt 四类作用域稳定存在，且兼容旧字段视图 | `v5_architecture.md §3.3` / `§5.4` |
| RQ-02 | 交互图显式化 | P0 | 能描述 leak → reentry → execute → verify 的多阶段路径 | `v5_architecture.md §3.5` / `§5.4` |
| RQ-03 | 能力层抽象 | P0 | leak / write / control / exec / verify 可组合、可追溯、可解释 | `v5_architecture.md §3.7` / `§5.4` |
| RQ-04 | Planner 入口 | P0 | 能基于前提、风险、作用域兼容性生成并排序候选 plan | `v5_architecture.md §3.1` / `§5.4` |
| RQ-05 | Legacy 兼容执行 | P0 | 旧 strategy 在迁移期仍可作为 adapter / fallback 正常运行 | `v5_architecture.md §3.2` / `§5.4` |
| RQ-06 | 统一验证口径 | P0 | success verdict 可由统一 verifier 输出，而非分散判定 | `v5_architecture.md §3.1` / `§5.4` |
| RQ-07 | 可解释性与可追溯 | P1 | 每次选择 plan 都能回溯到事实、交互、能力、评分 | `v5_architecture.md §5.4` |
| RQ-08 | 回归与验证基线 | P0 | 所有验证仍只在 `ctf_env` 容器内完成，且不回退现有基线 | `AGENTS.md` / `upgraded.md §5` |
| RQ-09 | 文档/治理一致性 | P0 | 需求、架构、执行状态三者引用一致，不出现双份状态漂移 | `AGENTS.md` / `upgraded.md` |
| RQ-10 | 增量迁移 | P0 | 新层可逐步接管，旧层保持可用，禁止一次性重写 | `v5_architecture.md §4` |

### 9.1 非功能需求

- 可维护：模块边界清晰，禁止互相反向依赖
- 可验证：每个阶段都能在真实 `Challenge/` 上验收
- 可回退：迁移失败时能落回 legacy adapter
- 可解释：plan、capability、verifier 都能输出原因
- 可移植：默认只在 `ctf_env` 容器内验证

## 10. Todo 管理原则

- **只保留一个可变状态源**：`upgraded.md`
- `v5_prd.md` 只放“需求清单 + 验收标准”
- `v5_architecture.md` 只放“模块拆分 + 需求映射”
- 不建议在 PRD 和 architecture 里各放一份独立可编辑的 TODO 状态；那样容易漂移
- 若必须展示进度，只在文档中引用 `upgraded.md` 的任务 ID 和状态
