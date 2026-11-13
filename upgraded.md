# upgraded.md — 任务看板与迭代索引

> **职责**：只做「任务 → 状态 → 详情」的索引。
> 架构看 [`ARCHITECTURE.md`](./ARCHITECTURE.md)，基线数字看 [`PROGRESS.md`](./PROGRESS.md)，
> 上手看 [`HANDOVER.md`](./HANDOVER.md)，规则看 [`AGENTS.md`](./AGENTS.md)。
>
> 本文件**不再重复**架构描述与验证方法（v5 时代的 §4/§5 已删，避免与上面三份文档打架）。

## 0. 阅读指引

| 你想干什么 | 去哪 |
|---|---|
| 领任务 / 看进度 | 本文件 §2 |
| 看某个任务的具体方案 | `upgraded/vX.Y.Z.md` |
| 看下一步架构方向 | [`upgraded/v7.0.0.md`](./upgraded/v7.0.0.md) |
| 看当前实测能力 | [`PROGRESS.md §2`](./PROGRESS.md) |
| 看 v4 / v5 历史 | `archive/v4/`、`archive/v5/` |

## 1. 迭代流程

### 1.1 任务来源

1. Owner 直接指定
2. 回归中发现的缺口（`bench/*` 有新题型打不动）
3. `upgraded/v7.0.0.md` 的四层管线路线

### 1.2 单任务工作流

```
立项（§2 加行 + 建 upgraded/vX.Y.Z.md）
  → 实施
  → 回归（bench / bench_extra / bench_sys 不低于基线）
  → 更新 §2 状态 + 详情文件「实施记录」
  → 一次提交（代码 + 文档）
```

### 1.3 详情文件要求

必须含：背景 / 目标 / 范围（做什么、不做什么）/ 风险 / 验收标准 / 实施记录。

### 1.4 任务粒度

单任务 ≤ 400 行 diff；过大就拆 `a` / `b`。

## 2. 任务看板

### 2.1 进行中 / 待办

| ID | 摘要 | 状态 | 预估 | Owner | 详情 |
|---|---|---|---|---|---|
| `v7.0.0` | 架构提案：四层管线（目标模型 / 交互规划 / 能力注册 / 判定归因） | 📝 | 3h | @Minzhi_Zhou | [`v7.0.0`](./upgraded/v7.0.0.md) |
| `v7.0.1` | **P0**：`Plan.sends` → `Plan.steps`（交互层，解菜单题与多轮题） | ⏳ | 4h | @Minzhi_Zhou | 待建详情 |
| `v7.0.2` | **P0**：三处判定合并为统一 `Oracle`（`verify_shell` / `probe_flag` / `_try_pie_partial`） | ⏳ | 3h | @Minzhi_Zhou | 待建详情 |

> 这两项是 `HANDOVER.md §8` 指定的接手起点，均**不需要改 `facts.py`**，风险可控。

### 2.2 已完成（v6 系列）

| ID | 摘要 | 状态 | 实际 | 详情 |
|---|---|---|---|---|
| `v6.5.0` | 交付文档：README / ARCHITECTURE / PROGRESS / HANDOVER / CLAUDE / DOC_MAP | ✅ | 2h | 本仓库根目录 |
| `v6.4.1` | 菜单式前置交互（`interact`）自动探测；剔除 win 内部 read 的假漏洞 | ✅ | 1h | [`PROGRESS.md`](./PROGRESS.md) §1 |
| `v6.4.0` | 自读 flag 型 win：`open+puts` 识别、门槛入口回溯、flag 判定覆盖累积输出 | ✅ | 1.5h | 同上 |
| `v6.3.x` | PIE 无泄漏部分覆盖（`endbr64` 认函数入口 / `Win.alt` 栈对齐 / nib 爆破）+ 容器靶机 | ✅ | 4h | 同上 |
| `v6.2.x` | 纯 `int 0x80` 手写汇编：`syscall1` / `syscall3` 三段式 + 变体回归矩阵 | ✅ | 3h | 同上 |
| `v6.1.x` | 远程 TLS/SNI、远程优先无缓冲泄漏、连接类失败立即中止、`--cmd` | ✅ | 2h | 同上 |
| `v6.0.x` | 离线自动利用引擎（`autopwn.engine`）+ pwn 容器 + 15 题回归 | ✅ | 6h | [`v6.0.0`](./upgraded/v6.0.0.md) |

### 2.3 已取消

| ID | 摘要 | 状态 | 原因 |
|---|---|---|---|
| `v5.0.9` | 统一 verifier 主体切片（probe/spec 抽象） | ❌ | v6 重构后 `autopwn/engine` 已用另一套实现达成目的；v5 骨架不再演进 |

### 2.4 历史入口

- v5 归档（架构 / PRD / TODO / 迭代详情）：[`archive/v5/`](./archive/v5/)
- v4 归档（README / upgraded / 任务详情 / backlog）：[`archive/v4/README.md`](./archive/v4/README.md)
