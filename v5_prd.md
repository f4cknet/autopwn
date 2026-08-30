# AutoPwn v5 PRD

> **角色**：v5 当前需求文档。
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

- unit：`757 passed`
- integration 子集：`5 passed, 1 skipped`
- 手工：`Challenge/canary` 可通过 `whoami` 拿到 `root`

## 6. 近期路线

- `v5.0.1`：文档重置
- `v5.0.2`：事实作用域 / 生命周期（FactScope / FactStore / 首批 producer 接入）
- `v5.0.3`：交互图
- `v5.0.4+`：能力层 / planner / verifier

### 6.1 `v5.0.2` 完成标准

- 在 `autopwn/context.py` 建立最小可用的事实存储层
- 显式区分 `binary / process / session / attempt` 四类作用域
- 至少让一批现有 producer 把关键检测结果同步进 fact store
- 保留现有 `ctx.padding` / `ctx.canary` / `ctx.canary_plan` 等兼容视图，避免一次性重写全部 runtime
