# AutoPwn v5 Architecture

> **角色**：v5 当前架构规范。
> **状态**：生效中（2026-08-30）

## 1. 原则

1. 先事实，后决策
2. 先建模，后模板
3. 先增量迁移，后回收兼容层
4. 每一步都必须绑定真实 `Challenge/` 验证

## 2. 目标

v5 要解决的问题不是“再加几个 strategy”，而是让系统能稳定表达：
- 哪些事实存在
- 这些事实属于哪个作用域
- 交互怎样推进
- 当前具备哪些 exploit 能力
- 为什么选择这条 plan
- 用什么 verifier 判定成功

## 3. 目标架构

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

### 3.1 关键层职责

- **Facts**：收集并存储结构化事实
- **Scope**：定义 binary / process / session / attempt 生命周期
- **Interaction Graph**：表达多输入、多轮返回、同会话约束
- **Capability IR**：表达 leak / write / control / exec / verify 能力
- **Planner**：按前提、成本、风险、作用域兼容性排序 exploit plan
- **Executor**：执行 plan；旧 strategy 在迁移期只做 adapter / fallback
- **Verifier**：统一 `echo PWNED`、`whoami`、`cat flag` 等成功判定协议

### 3.2 与现有代码的迁移方向

- `autopwn/context.py` → fact store / plan state
- `autopwn/recon/*`、`autopwn/detect/*` → facts / evidence producers
- `autopwn/exp/registry.py` → planner 入口或 legacy adapter 路由
- `autopwn/exp/strategies/*` → fallback / 模板执行器
- `autopwn/core/shell_verify.py` → verifier policy 实现

## 4. 迁移约束

- 保持单向依赖，禁止反向 import
- 迁移期间维持当前 5/5 SUCCESS 基线
- 禁止 challenge-name 特判回潮
