# fix.md — v4.0+ 修复索引

> **角色**：所有 `fix_<bug_name>.md` 的入口（**不承载 fix 本身内容**）。
> **配套文档**：
> - [`AGENTS.md`](./AGENTS.md) §6.1 — 修复记录文件结构（命名约定 / 新增流程 / 删除规则 / 模板）
> - [`upgraded.md §3`](./upgraded.md) — 任务看板（每个 fix 关联一个任务行 `v4.0.X.Y`）
> - [`refactor.md §3`](./refactor.md) — v4.0 已落地的目标架构
> - [`rebuild.md §3`](./rebuild.md) — v3.1 → v4.0.dev0 重构历史（v3.1 fix 不回填本文件）
>
> **本文件章节**：
> - §0 阅读指引
> - §1 已 merge 修复索引（表格，**只**列已 merge 的 fix）
> - §2 治理变更历史（fix.md 本身的结构变化）

---

## 0. 阅读指引

| 你是谁 | 先看哪节 |
|---|---|
| **想看某个 fix 的细节** | §1 表格找 fix ID → 点开对应 `fix_<bug_name>.md` |
| **想看任务看板的 fix 候选** | `upgraded.md §3`（**未做**的 fix 不进本文件） |
| **理解 "为什么这样组织 fix 记录"** | `AGENTS.md §6.1` |
| **v3.1 时代 fix 的位置** | `rebuild.md §3`（不回填本文件） |

---

## 1. 已 merge 修复索引

| Fix ID | 关联任务 | 文件 | 状态 | 一句话描述 |
|---|---|---|---|---|
| `fix_fmtstr1_routing` | v4.0.2c1 | [fix_fmtstr1_routing.md](./fix_fmtstr1_routing.md) | ✅ | fmtstr1 ret2libc_put hang 修复 + fmtstr strategy 路由到 canary+fmtstr 二进制 |
| `fix_asm_and_add_padding` | v4.0.2c3 | [fix_asm_and_add_padding.md](./fix_asm_and_add_padding.md) | ✅ | `recon/asm.py::asm_stack_overflow` 误把函数 epilogue 的 `lea -0x8(%ebp),%esp` 当 buffer offset |
| `fix_x64_recv_timeout` | v4.0.2c4 | [fix_x64_recv_timeout.md](./fix_x64_recv_timeout.md) | ✅ | x64 ret2libc strategies (`io.recv()` + `io.recvuntil(b"\x7f")` / `io.recv(8)`) 无 timeout hang（mirror v4.0.2c1 x32 fix） |

> **未做 / TODO** → 走 `upgraded.md §3` 任务看板，**不进**本文件。

---

## 2. 治理变更历史（本文件本身结构变化）

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-06-12 | 1.0 | 初版：`fix.md` 331 行承载 3 个 fix 内容（v4.0.5 FrameContext 立项 + 背景 / 复盘 / 计划） |
| 2026-06-12 | 1.7 | **结构化拆分**（AGENTS.md 治理变更 1.7）：`fix.md` 331 → ~50 行变**纯索引**；3 个 v4.0+ 修复拆为 `fix_<bug_name>.md` 单文件；新增流程见 `AGENTS.md §6.1` |
