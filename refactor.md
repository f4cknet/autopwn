# AutoPwn 架构演进史（refactor.md · v4.0 历史）

> **角色**：系统架构演进档案
> **状态**：v3.1 → v4.0.dev0 重构 **已完成**（6/6 里程碑 + M6 全部 ✅）。本文档作为 v4.0 演进史保留，**不是未来开发规范**。
> **未来开发规范**：见 `upgraded.md`（v4.0+ 迭代流程）。
> **本文件保留内容**：
> 1. **§1 现状盘点**（重构起点）— 让你理解 v3.1 单体的问题（为什么重构）
> 2. **§3 目标架构**（v4.0 已落地的当前架构）— AI Agent 必读 + 任何架构变更前必查
> 3. **§9 测试策略**（仍是规范）— pytest 单元 + 集成 + 不变量
> 4. **§13 过渡期临时文件**（v4.0 历史）— `_legacy.py` / `_compat.py` / `autopwn.py` shim 已删
> **本文件删除内容**：
> - §2 设计目标（已落地）
> - §4 目录结构（已落地，见 `upgraded.md §4`）
> - §5 拆分映射表（已落地，函数位置见代码）
> - §6 编排层（已落地）
> - §7 拆分阶段（已全部完成）
> - §4 临时需求 #4（已落地）
> - §8 兼容性与迁移策略（已落地，_legacy.py 已删）
> - §10 风险与权衡（已 Mitigated）
> - §11 后续扩展点（重构期特定，多数已落地）
> - §12 立即可执行的下一步（已完成）

---

## 1. 现状盘点（v3.1 重构起点）

### 1.1 量化数据
- `autopwn.py` 3720 行单体（v3.1）
- 30+ 利用函数（`ret2_system_x32` / `ret2_system_x64` / `ret2libc_write_x32` / ...）
- 79 个顶层函数
- 12 阶段 + 12 个子决策（main() 的 if 树）
- 利用覆盖率 60-70%（canary / PIE / fmtstr 都覆盖，但部分 binary 仍失败）

### 1.2 核心架构气味
1. **函数级全局变量滥用**：43 处 `exploit_info[...] = ...` + 4 处 `globals().get(...)` 隐式注入
2. **决策树耦合**：30+ 利用函数由 `main()` 一个 400 行 if-else 树调度
3. **重复代码**：x32 / x64 双胞胎函数多份（参数差异仅 `p32` / `p64`）
4. **IO + 业务逻辑耦合**：所有 `subprocess.run` 直接调 `os.system('ropper ... > out.txt')`
5. **单测不可行**：无依赖注入，所有函数读 globals

### 1.3 拆分目标（v4.0 已落地）
- ✅ 把 `autopwn.py` 拆为 7 层（CLI / Strategies / Primitives / Detect / Recon / Core / Report）
- ✅ 30+ 利用函数收敛为 12 个 strategy 类（按 `priority` 排序而非 if 链）
- ✅ `ExploitContext` dataclass 替代 `exploit_info` dict + `globals()`
- ✅ `core/runner.py` 包装 14 个 binutils / ropper / qemu 工具
- ✅ 引入 5 个 fixture（Context / Recon / Detect / Strategy / Integration）

---

## 3. 目标架构（v4.0 已落地 · AI Agent 必读）

### 3.1 分层模型（自下而上，单向依赖）

```
┌─────────────────────────────────────────────────────────┐
│  CLI / Orchestrator  (cli.py, orchestrator/{__init__,recon,detect,strategy}.py)  │   ← 输入解析 + 决策调度
├─────────────────────────────────────────────────────────┤
│  Strategies  (exp/strategies/*.py, exp/strategies/canary_*.py)                 │   ← 一次完整利用流程
├─────────────────────────────────────────────────────────┤
│  Primitives  (primitives/*.py)                                                 │   ← 可复用的 payload 构造
├─────────────────────────────────────────────────────────┤
│  Detect  (detect/*.py)                                                         │   ← 漏洞存在性判定
├─────────────────────────────────────────────────────────┤
│  Recon  (recon/*.py)                                                           │   ← 二进制静态 / 动态信息收集
├─────────────────────────────────────────────────────────┤
│  Core  (core/*.py)                                                             │   ← logging, IO, subprocess 包装
└─────────────────────────────────────────────────────────┘
```

依赖方向严格自上而下，**禁止反向 import**。

### 3.2 关键抽象

#### 3.2.1 `ExploitContext`（v4.0 落地）
- `autopwn/context.py` 定义 6 个 dataclass：`BinaryInfo` / `LibcInfo` / `RopGadgetsX64` / `RopGadgetsX32` / `CanaryInfo` / `ExploitContext`
- `@dataclass(slots=True)` + `field(default_factory=...)` 防 mutable default 泄漏
- `ExploitContext.from_args(args)` 工厂映射 argparse
- 替代 v3.1 的 `exploit_info` dict + `globals()` 注入

#### 3.2.2 `ExploitStrategy` + `@register`（v4.0 落地）
- `autopwn/exp/base.py` 定义 `ExploitStrategy` 抽象类
- 字段：`name: str` / `priority: int` / `requires_*: bool` / `requires_arch: int | None` / `requires_canary: bool` / `requires_remote: bool`
- 方法：`matches(ctx) -> bool` / `run(ctx) -> bool`
- `autopwn/exp/registry.py` `@register` 装饰器 + `candidates(ctx)` 排序
- 12 个 strategy 类（40 strategies）注册，按 priority 排序而非 if 链

#### 3.2.3 `report.model.ExploitInfo`（v4.0 落地）
- 9 字段（6 required + 3 optional）的 dataclass
- 替代 v3.1 的 `exploit_info['x']` dict 读

### 3.3 命名约定（v4.0 落地）
- 项目名：`pwnpasi` (v3.1) → `autopwn` (v4.0)
- 团队：`@Ba1_Ma0` (v3.1) → `@Minzhi_Zhou` (v4.0, 2026-06-07 rename)
- 仓库：`f4cknet/autopwn`
- 版本：`4.0.dev0` (当前) → `4.0` (GA 目标)

---

## 9. 测试策略（v4.0 仍是规范）

### 9.1 单元测试（无副作用）
- 所有 `primitives/*.py` 的 `build_payload` 接受 fake address 输入返回纯 bytes
- `exp/registry.candidates(ctx)` 的过滤逻辑可被 monkeypatch 测
- `report/code.py` 的代码生成可对比 snapshot
- 当前规模：626 unit tests（per `pytest tests/unit/`），0 回归

### 9.2 集成测试（跑 `Challenge/` 下的真实二进制）
- `tests/integration/test_challenge_*.py`
- pytest fixture 启动 binary（timeout 5s），喂 payload，断言 `io.recvline()` 含 `'$ '` 或 `'/bin/sh'` 等标志
- CI 中若二进制缺失则 `pytest.mark.skip`
- 当前规模：17/18 + 1 SKIP integration tests

### 9.3 不变量测试
- `Challenge/level3_x64` / `Challenge/canary` / `Challenge/fmtstr1` / `Challenge/pie` / `Challenge/rip` 各跑一次完整利用
- 5 binary 串行 60s/binary baseline：4/5 SUCCESS + canary PARTIAL（pre-existing v3.1 限制，非 v4.0 regression）
- 跑 600s timeout：canary 仍 PARTIAL（strategies 阶段 > 10min 持续触发 timeout）
- 5/5 SUCCESS 是 pre-existing 限制（v3.1 也 4/5），不阻塞 v4.0 GA

---

## 13. 过渡期临时文件（v4.0 历史 — 文件已删 · 2026-06-09 P8.5/P8.6 落地）

> **本节是 v3.1 → v4.0.dev0 重构的过渡期历史档案**（**v4.0 已不再相关**）。
> 重构 P0.4–P8.5 阶段存在 2 个临时脚手架文件，**已于 2026-06-09 在 P8.5 / P8.6 commit 4fb00b3 中删除**：
> - `autopwn/_legacy.py`（3479 行 dead code，`git rm` — 0 live caller）
> - `autopwn/_compat.py`（194 行桥模块，`git rm` — 0 live caller）
> - 根目录 `autopwn.py` 5 行 shim（同 PR 删除，入口改 `python -m autopwn`）
>
> 本节作为 v4.0 演进史保留，**不再是开发期阅读材料**——如果你在 v4.0+ 看到本节引用文件位置，可直接跳过；引用目的仅供 git blame / v3.1 → v4.0 审计追溯。**v4.0+ 新增代码禁止 `from autopwn._legacy import ...` / `from autopwn._compat import ...`**（grep 验证 0 行）。

---

## v4.0 演进时间线（一次性总结）

| 日期 | 阶段 | 内容 |
|---|---|---|
| 2026-06-06 | P0.0 | 项目改名 `pwnpasi` → `autopwn` |
| 2026-06-07 | P0.7-P0.8 | 验证基础设施 + v3.1 vs v4.0 严格对比 (96% 一致 PASS) |
| 2026-06-07 | P1.1-P1.6 | `core/` 层（logging / fs / runner / 14 工具）|
| 2026-06-07 | P2.1-P2.4 | `ExploitContext` 落地 + 桥函数 |
| 2026-06-08 | P3.1-P3.6 | `report/` 层（model / docx / code / markdown fallback）|
| 2026-06-08 | P4.1-P4.8 | `recon/` 层（checksec / libc / plt / rop / asm / bss）|
| 2026-06-08 | P5.1-P5.5 | `detect/` 层（canary / overflow / fmtstr / binsh）|
| 2026-06-08 | P6.1-P6.9 | `primitives/` 层（9 个 primitive + 单元测试）|
| 2026-06-08 | P7.1-P7.12 | `exp/strategies/`（12 strategy 类，40 strategies）|
| 2026-06-09 | P8.1-P8.6 | `orchestrator.py` + cli 调度 + 4/5 SUCCESS 持平 v3.1 |
| 2026-06-09 | P9.1-P9.6 | 单元测试 + CI（604 tests + GitHub Actions）|
| 2026-06-09 | P10.1-P10.4 | 打包升级（pyproject.toml + setup.py + pip install）|
| 2026-06-09 | P4.4b + P6.3b + P6.4b | B-006 + B-007 根因修复（rop int 契约 / extra_rdi-rsi 3 变体）|
| 2026-06-09 | M1 + M2 收尾 | 删 `_legacy.py` 3479 行 + recon 单元测试 16 + coverage gate |
| 2026-06-10 | P11.0-P11.5 | M6 内部打磨（6 任务：docs 清理 / 6 关验证 / coverage / baseline / orchestrator 拆分）|
| 2026-06-10 | 治理变更 1.5 | 删 §2.6 + 主干开发 + 删 dev 角色 |
| 2026-06-10 | 治理变更 1.6 | 文档瘦身（AGENTS / refactor / rebuild + 新建 upgraded.md）|

> 详细 git log 见 `git log --oneline --graph`。
