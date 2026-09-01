# AutoPwn v5 Architecture

> **角色**：v5 当前架构规范与迁移路线图。
> **用途**：定义模块边界、数据流与迁移顺序。
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

### 3.3 作用域模型（`v5.0.2` 首个落地切片）

| Scope | 含义 | 典型事实 | 失效时机 |
|---|---|---|---|
| `binary` | 静态目标属性，可跨本次运行复用 | `padding`、`fmtstr.offset`、`canary.plan` | 目标二进制 / 对应 libc 变化 |
| `process` | 绑定某个本地进程实例 | 本地单次 spawn 中泄露的 canary / puts 地址 | 进程退出、重启、崩溃 |
| `session` | 绑定某个远端连接或持久交互会话 | 同连接内 menu 状态、认证状态、远端泄露值 | 连接关闭、服务端重置会话 |
| `attempt` | 单次 detect / execute 尝试的短生命周期诊断 | fuzz budget 耗尽记录、一次性 probe 结果 | 切换下一次尝试 |

### 3.4 `v5.0.2` 迁移约束

- 先建立 `FactStore`，再逐步把 producer 接入
- 旧字段继续保留为兼容视图，不在本阶段一次性删除
- 首批接入聚焦 detect/runtime 的高价值事实：`padding`、`binsh`、`fmtstr` 元数据、`canary` 相关事实

### 3.5 交互图模型（`v5.0.3` 首个落地切片）

- **InteractionGraph**：描述一条 exploit 路线需要经过的交互步骤与依赖边
- **InteractionStep**：描述单步动作，如 `leak` / `execute` / `reentry` / `verify`
- **InteractionEdge**：表达“必须先完成哪一步，才能进入下一步”
- **InteractionEvent**：记录运行时实际走过的步骤与关键结果

本阶段先覆盖两类高价值交互：

1. **same-session canary 链**：`fmt leak canary → bof leak puts → reentry → bof shell → whoami verify`
2. **普通 2-stage ret2libc 链**：`leak libc addr → stage2 shell → shell verify`

### 3.6 `v5.0.3` 迁移约束

- binary scope 可存交互模板，runtime scope 存实际执行轨迹
- 不在本阶段引入完整 planner，只做可执行路线的显式表达
- 不把 challenge 特判塞进 interaction graph；图只描述交互结构，不描述题名

### 3.7 能力模型（`v5.0.4` 首个落地切片）

- `Capability / CapabilityKind / CapabilityPrereq / CapabilityBinding / CapabilityEvidence` 共同表达能力、事实前提、作用域兼容性、绑定 strategy / graph step 与 evidence
- 首批接入两条已验证路线：same-session canary 链、2-stage ret2libc-write 链

### 3.8 `v5.0.4` 迁移约束

- capability 只表达“能做什么 / 需要什么 / 依赖什么”，排序与搜索留给后续 planner
- capability 必须可回溯到 `InteractionGraph` 或 `FactStore`，并保留 legacy strategy 作为 adapter / fallback；禁止 challenge-name 特判

## 4. 迁移约束

- 保持单向依赖，禁止反向 import
- 迁移期间维持当前 5/5 SUCCESS 基线
- 禁止 challenge-name 特判回潮

## 5. 迭代落地顺序与当前状态

### 5.1 模块边界

| 层 | 职责 | 输入 | 输出 |
|---|---|---|---|
| Core | 基础事实与检测原语 | target / runtime signal | facts / evidence |
| Scope / Lifetime | 生命周期控制 | facts / events | scoped facts |
| Interaction Graph | 交互路径建模 | facts / runtime steps | graph / route events |
| Capability IR | 将事实与交互抽象为能力 | facts + graph | capability set |
| Planner | 计划排序与选择 | capability set | ordered plan |
| Executor / Legacy Adapter | 执行与兼容 | selected plan | runtime events |
| Verifier | 成功判定 | runtime output | verdict |

### 5.2 迁移顺序

1. 先事实与作用域
2. 再交互图
3. 再能力层
4. 再 planner
5. 最后统一 verifier 和收敛 legacy adapter

### 5.3 当前状态

- Facts / Scope：已落地
- InteractionGraph：已落地
- Capability IR：已落地
- Planner：最小入口已落地
- Verifier：仍以 legacy / 分散实现为主
