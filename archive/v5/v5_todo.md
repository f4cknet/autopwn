# AutoPwn v5 Todo

> **角色**：v5 独立待办 / 路线图文档
> **用途**：记录长期待办、优先级、依赖关系与下一步规划
> **状态**：生效中（2026-09-01）

## 1. 文档关系

- `v5_prd.md`：定义需求与验收
- `v5_architecture.md`：定义模块与数据流
- `v5_todo.md`：定义下一步做什么、先做什么
- `upgraded.md`：定义当前执行到哪一步

## 2. 当前基线

- `RQ-01`~`RQ-05` 已完成：Facts / Scope / InteractionGraph / Capability IR / Planner 入口
- 当前待推进：`RQ-06`~`RQ-10`

## 3. 长期待办

| ID | 事项 | 优先级 | 状态 | 依赖 | 验收 |
|---|---|---|---|---|---|
| TD-01 | 统一 verifier 主体 | P0 | ⏳ | `RQ-06` | 成功判定可由统一 verifier policy 输出 |
| TD-02 | 计划解释链路 | P1 | ⏳ | `RQ-07` | 每个 plan 可回溯到事实 / 能力 / 评分 |
| TD-03 | 回归门禁硬化 | P0 | ⏳ | `RQ-08` | 容器验证与回归样本矩阵稳定可复现 |
| TD-04 | 文档/治理同步 | P0 | ⏳ | `RQ-09` | PRD / architecture / todo / upgraded 不漂移 |
| TD-05 | legacy adapter 收敛 | P1 | ⏳ | `RQ-05`, `RQ-10` | fallback 面收窄，旧 strategy 逐步退场 |
| TD-06 | planner scoring refinement | P1 | ⏳ | `RQ-04`, `RQ-07` | plan 排序更稳定，可解释性更强 |
| TD-07 | 样本覆盖扩展 | P2 | ⏳ | `RQ-08` | 代表性 Challenge 样本覆盖继续扩充 |

## 4. 推荐顺序

1. `TD-01`
2. `TD-03`
3. `TD-04`
4. `TD-05`
5. `TD-02`
6. `TD-06`
7. `TD-07`
