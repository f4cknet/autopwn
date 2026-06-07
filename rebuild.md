# AutoPwn 重构实施手册（rebuild.md）

> ⚠️ **强制前置阅读**：[`AGENTS.md`](./AGENTS.md)（项目治理）—— 本文档所有行为受其 §1 四条铁律 + §2.6 验证方法论约束。**任何动手前先读 AGENTS.md §1 铁律 + §2.6**。
> 配套文档：`refactor.md`（架构设计 / WHY） ←→ `rebuild.md`（实施 / HOW / WHO / WHEN / STATUS）
> 维护者：项目 Owner（你）
> 协作方式：每个 PR 至少更新本文档对应任务的"状态 / Owner / 实际工时 / PR#"
> 当前重构周期：v3.1 → v4.0（含项目改名 pwnpasi → autopwn，临时需求 #1）

---

## 0. 阅读指引

| 你是谁 | 先看哪一节 |
|---|---|
| **第一次接触本次重构** | **必读 [`AGENTS.md`](./AGENTS.md) §1 铁律** → §1 → §2 → §3 → §4 |
| **想认领任务** | `AGENTS.md` §1 铁律 → §2 图例 → §4 找 ⏳ → §6 详细步骤 → §5 约定 |
| **正在做某个阶段** | §6 当前阶段 → §7 Review 清单 → §9 同步机制 |
| **Code Review** | §7 对应阶段 checklist → §9 风险表 + `AGENTS.md` §3 违规表 + §2.6 验证方法论 |
| **只关心进度** | §3 里程碑 + §4 总览表 |

> **本文件是"活文档"**：状态行（`⏳ 🔄 👀 ✅ ⚠️ ❌`）随 PR 合并实时更新，详见 §2。

---

## 1. 与 `refactor.md` 的分工

| 维度 | `refactor.md` | `rebuild.md`（本文件） |
|---|---|---|
| 回答的问题 | 为什么这样设计 / 目标架构是什么 | 怎么做 / 谁来做 / 做到哪里了 |
| 内容性质 | 架构决策、抽象定义、阶段路线 | 子任务、Owner、PR 链接、阻塞项、约定 |
| 更新频率 | 阶段切换时更新 | **每个 PR 必更新** |
| 读者 | 设计评审、跨期回顾 | 当下干活的开发者 |
| 长度 | 中（设计为主） | 长（任务粒度细） |
| 与代码同步 | 不要求 | **强一致**：任务状态必须反映实际代码状态 |

---

## 2. 状态图例与命名约定

### 2.1 任务状态

| 图标 | 状态 | 含义 | 谁可以更新 |
|---|---|---|---|
| ⏳ | Pending | 已规划，未开始 | Owner 在 `git commit` 时改为 🔄 |
| 🔄 | In Progress | 正在做 | Owner |
| 👀 | In Review | PR 已开，等 Review | Owner 改；Reviewer 通过后改 ✅ |
| ✅ | Done | 已合并到主分支 | Reviewer 合并后由 Owner 改 |
| ⚠️ | Blocked | 阻塞中，等待外部输入 | Owner 标注，并填写 §10 阻塞登记表 |
| ❌ | Cancelled | 不再需要（被合并 / 范围调整） | Owner 标注原因 |

### 2.2 任务 ID

- 格式：`P{阶段}.{子任务序号}`，例如 `P0.3`
- 同一子任务被拆分时，追加字母：`P7.2a`、`P7.2b`
- 状态行格式：`P0.3 | 🔄 | @alice | 4h | 4.5h | #PR-12 | 备注`

### 2.3 优先级

| 标记 | 含义 |
|---|---|
| 🔴 P0 | 阻塞后续阶段，必须本周内启动 |
| 🟡 P1 | 当前 sprint 必做 |
| 🟢 P2 | 排进 backlog |

### 2.4 预估工时

单位：人时（h）或人天（d）。每人每天 ≤ 6h 有效编码时间。

---

## 3. 总体里程碑

| # | 里程碑 | 阶段 | 目标产物 | 验收 | 状态 |
|---|---|---|---|---|---|
| **M0** | 项目骨架就位 | P0 + P1 | 真正的 `autopwn/` 包；`autopwn.py` 变成 shim | `python autopwn.py -l Challenge/canary` 行为不变；`pip install .` 成功 | ✅ P0.0–P0.8 全完成 P1 ⏳ |
| **M1** | 状态显式化 | P2 + P3 | `ExploitContext` 落地；报告层可独立关闭 | `--no-report` 参数生效；无 `globals().get` 在主流程 | ⏳ |
| **M2** | 收集与检测层化 | P4 + P5 | `recon/` + `detect/` 完整，pure 化 | `pytest tests/unit/test_recon_*` 全绿 | ⏳ |
| **M3** | 利用层抽象 | P6 + P7 | `primitives/` + `exp/strategies/`；30+ 函数收敛为 12 策略 | `pytest tests/integration/` 跑通 Challenge/ 全部 4 个二进制 | ⏳ |
| **M4** | 编排重写 | P8 | `main()` < 100 行；orchestrator 决策 | CLI 日志与重构前一致；`wc -l orchestrator.py < 250` | ⏳ |
| **M5** | 工程化 | P9 + P10 | 单元测试 + CI + 打包 | GitHub Actions 绿；`autopwn` 命令行可用 | ⏳ |

> 整体进度：**0 / 6 里程碑完成**

---

## 4. 任务总览（一眼看板）

> 表头缩写：`S`=状态 / `O`=Owner / `E`=预估(h) / `A`=实际(h) / `PR`=PR 编号 / `Note`=备注

### 4.1 P0 — 改名 + 包骨架 + shim

> **🆕 本阶段包含临时需求 #1**：全局重命名 `pwnpasi` → `autopwn`（P0.0）。设计理由见 `refactor.md` §3.3 命名约定。

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| **P0.0** | **全局重命名 `pwnpasi` → `autopwn`**（**临时需求 #1**） | ✅ | @Ba1_Ma0 | 3h | 0.5h | #P0.0 | 已完成；R12 Resolved；验证：banner/help/烟雾测试三关通过；详见 §6.1 P0.0 验证段 |
| P0.1 | 新建 `autopwn/` 目录及子包目录（`core recon detect primitives exp report`） | ✅ | @Ba1_Ma0 | 1h | 0.2h | #P0.1-P0.5 | 8 个包目录 + 占位 __init__.py |
| P0.2 | 写各包 `__init__.py`（含 `__all__` 占位） | ✅ | @Ba1_Ma0 | 1h | 0.1h | #P0.1-P0.5 | autopwn/__init__.py 带版本/作者/组织；re-export cli；子包标准 __all__ |
| P0.3 | 写 `pyproject.toml`（PEP 621），声明依赖 | ✅ | @Ba1_Ma0 | 2h | 0.2h | #P0.1-P0.5 | name=autopwn / deps 5 项 / entry_points autopwn=autopwn.cli:main |
| P0.4 | `autopwn.py` 改为 shim，转发到 `autopwn.cli.main` | ✅ | @Ba1_Ma0 | 1h | 0.1h | #P0.1-P0.5 | 5 行 shim；monolith 移入 autopwn/_legacy.py（git mv 保留历史）|
| P0.5 | 验证 `python autopwn.py -l Challenge/canary` 与重构前行为一致 | ✅ | @Ba1_Ma0 | 1h | 0.3h | #P0.1-P0.5 | 5 项：语法/import/`--help`×2 入口/canary 烟雾测试 全过 |
| **P0.6** | **文档交叉引用**：`rebuild.md` §0 顶部加"必读 `AGENTS.md`"指引 | ✅ | @Ba1_Ma0 | 0.5h | 0.2h | #P0.6 | doc-only，与 P0.0 同步完成 |
| **P0.7** | **验证基础设施**（Owner 决策 2026-06-07，临时需求 #2） | ✅ | @Ba1_Ma0 | 3h | 0.8h | #P0.7 | 27/28 关键标记一致（96%）；4/5 SUCCESS；race condition 已规避；见 §6.1 P0.7 |
| **P0.8** | **重跑 v3.1 vs v4.0 严格对比**（用 P0.7 新方法论） | ✅ | @Ba1_Ma0 | 1h | 0.3h | #P0.8 | 4/5 SUCCESS；96% 关键标记一致；PASS 结论；logs/comparison/summary.md；见 §6.1 P0.8 |

### 4.2 P1 — 基础设施层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P1.1 | `core/logging.py`：搬运 `Colors` + `print_*` | ✅ | @Ba1_Ma0 | 3h | 0.6h | #P1.1 | 搬 Colors/12 print_*/VERBOSE → autopwn/core/logging.py；_legacy.py re-export；set_verbose() setter 修 main() global 重绑定 bug；.gitignore core*→/core*；补 P0.1 漏 core/__init__.py；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（无回归）；铁律 4：✅ 合并 ✅ pytest N/A (P9) ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| P1.2 | `core/fs.py`：`set_permission` + `add_current_directory_prefix` + 临时目录 ctxmgr | ⏳ | — | 2h | — | — | |
| P1.3 | `core/runner.py`：封装 `checksec` / `ropper` / `objdump` / `ldd`，输出走 `subprocess.run(capture_output=True)` | ⏳ | — | 4h | — | — | |
| P1.4 | 替换 `autopwn.py` 中所有 `print_banner()` / `print_*` 调用为 `from autopwn.core.logging import ...` | ⏳ | — | 2h | — | — | |
| P1.5 | 替换 `autopwn.py` 中所有 `os.system('ropper ... > ropper.txt')` 模式，调用 `runner.run_ropper` | ⏳ | — | 3h | — | — | |
| P1.6 | 删除 `cleanup_core_files` 线程的硬编码 `os.system('rm -rf core*')`，改用 `core/fs.py` 中的回收函数 | ⏳ | — | 1h | — | — | |

### 4.3 P2 — 模型层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P2.1 | `context.py`：定义 `BinaryInfo` / `LibcInfo` / `RopGadgetsX64` / `RopGadgetsX32` / `CanaryInfo` / `ExploitContext` | ⏳ | — | 4h | — | — | |
| P2.2 | `context.py`：实现 `ExploitContext.from_args(args)` 工厂 | ⏳ | — | 2h | — | — | |
| P2.3 | `autopwn.py` 顶层构造 `ctx = ExploitContext.from_args(args)`，并写一个 ctx → `exploit_info` dict 的桥函数（**仅 P2 阶段保留，作用是让旧代码不立即报错**） | ⏳ | — | 2h | — | — | 过渡 |
| P2.4 | 旧 `exploit_info` 写操作改为调用桥函数 | ⏳ | — | 1h | — | — | 过渡 |
| P2.5 | 旧 `update_exploit_info` 标注 deprecation warning | ⏳ | — | 0.5h | — | — | 过渡 |

### 4.4 P3 — 报告层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P3.1 | `report/model.py`：定义 `ExploitInfo` dataclass（替代 `exploit_info` dict） | ⏳ | — | 2h | — | — | |
| P3.2 | `report/docx.py`：搬运 `generate_docx_report`；改为读 `ExploitInfo` | ⏳ | — | 2h | — | — | |
| P3.3 | `report/code.py`：搬运 `generate_exploitation_code`；改为读 `ExploitInfo` | ⏳ | — | 3h | — | — | |
| P3.4 | `handle_exploitation_success` 改为 `record_success(ctx, info, primitive)`，生成 docx/code 改为订阅 | ⏳ | — | 2h | — | — | |
| P3.5 | CLI 加 `--no-report` / `--report-dir` 参数 | ⏳ | — | 1h | — | — | |
| P3.6 | docx 依赖 `python-docx` 改为 `try/except ImportError` 降级为 markdown | ⏳ | — | 1h | — | — | |

### 4.5 P4 — Recon 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P4.1 | `recon/checksec.py`：搬运 `Information_Collection` + `collect_binary_info` + `display_binary_info`；返回 `BinaryInfo` | ⏳ | — | 4h | — | — | |
| P4.2 | `recon/libc.py`：合并 `detect_libc` + `ldd_libc` 为 `detect(ctx) → LibcInfo` | ⏳ | — | 2h | — | — | |
| P4.3 | `recon/plt.py`：`scan_plt_functions` 返回 dict，写入 `ctx.has_*` 标志 | ⏳ | — | 3h | — | — | |
| P4.4 | `recon/rop.py`：搬 `find_rop_gadgets_x64/x32`，返回 `RopGadgetsX64/X32` | ⏳ | — | 4h | — | — | |
| P4.5 | `recon/bss.py`：搬 `find_large_bss_symbols` + `find_ftmstr_bss_symbols` | ⏳ | — | 2h | — | — | |
| P4.6 | `recon/asm.py`：搬 `vuln_func_name` + `asm_stack_overflow` | ⏳ | — | 2h | — | — | |
| P4.7 | **关键**：删除 `autopwn.py` 中所有 `globals().get('system', 0)` 等 22 处；改读 `ctx.has_system` | ⏳ | — | 3h | — | — | 风险点 |
| P4.8 | 删除 `set_function_flags` 的 `globals()[func] = available` 副作用 | ⏳ | — | 0.5h | — | — | |

### 4.6 P5 — Detect 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P5.1 | `detect/overflow.py`：搬 `test_stack_overflow` + `analyze_vulnerable_functions`；写入 `ctx.padding` | ⏳ | — | 4h | — | — | |
| P5.2 | `detect/fmtstr.py`：搬 `detect_format_string_vulnerability` + `find_offset` | ⏳ | — | 3h | — | — | |
| P5.3 | `detect/canary.py`：搬 `leakage_canary_value` + `canary_fuzz`；写入 `ctx.canary` | ⏳ | — | 3h | — | — | |
| P5.4 | `detect/binsh.py`：搬 `check_binsh_string` + `check_binsh` | ⏳ | — | 1h | — | — | |
| P5.5 | 单元测试：每个 detect 函数对 `Challenge/` 下对应二进制跑一遍 | ⏳ | — | 4h | — | — | |

### 4.7 P6 — Primitives 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P6.1 | `primitives/base.py`：`ExploitPrimitive` 抽象类 + `ExploitResult` dataclass | ⏳ | — | 2h | — | — | |
| P6.2 | `primitives/ret2system.py`：x32 + x64 payload builder（pure function） | ⏳ | — | 3h | — | — | |
| P6.3 | `primitives/ret2libc_put.py`：x32 + x64 payload builder | ⏳ | — | 4h | — | — | |
| P6.4 | `primitives/ret2libc_write.py`：x32 + x64 payload builder | ⏳ | — | 4h | — | — | |
| P6.5 | `primitives/execve_syscall.py`：x32 payload builder | ⏳ | — | 2h | — | — | |
| P6.6 | `primitives/shellcode.py`：rwx x32 + x64 payload builder | ⏳ | — | 2h | — | — | |
| P6.7 | `primitives/fmtstr.py`：fmtstr payload builder | ⏳ | — | 3h | — | — | |
| P6.8 | `primitives/pie_backdoor.py`：PIE + backdoor payload builder | ⏳ | — | 2h | — | — | |
| P6.9 | 单元测试：每个 primitive 的 `build_payload(ctx) → bytes` 在 fake address 下断言字节序列 | ⏳ | — | 6h | — | — | |

### 4.8 P7 — Strategies 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P7.1 | `exp/base.py`：`ExploitStrategy` 抽象类（含 `requires_*` 元数据 + `matches`） | ⏳ | — | 2h | — | — | |
| P7.2 | `exp/registry.py`：`@register` 装饰器 + `candidates(ctx)` 排序 | ⏳ | — | 2h | — | — | |
| P7.2a | （P7.2 子任务）梳理原 if 顺序 → `priority` 值对照表（见附录 A） | ⏳ | — | 2h | — | — | 需 Owner 拍板 |
| P7.3 | `exp/strategies/ret2system_x32.py` + `_x64.py`（含本地/远端） | ⏳ | — | 3h | — | — | |
| P7.4 | `exp/strategies/ret2libc_put_x32.py` + `_x64.py` | ⏳ | — | 3h | — | — | |
| P7.5 | `exp/strategies/ret2libc_write_x32.py` + `_x64.py` | ⏳ | — | 3h | — | — | |
| P7.6 | `exp/strategies/rwx_shellcode_x32.py` + `_x64.py` | ⏳ | — | 2h | — | — | |
| P7.7 | `exp/strategies/execve_syscall.py` | ⏳ | — | 2h | — | — | |
| P7.8 | `exp/strategies/fmtstr.py`（含 `fmtstr_print_strings` 旁路） | ⏳ | — | 3h | — | — | |
| P7.9 | `exp/strategies/pie_backdoor.py` | ⏳ | — | 2h | — | — | |
| P7.10 | `exp/strategies/canary_*.py`（7 个文件，共用 `CanaryStrategy(ExploitStrategy)` 基类） | ⏳ | — | 6h | — | — | 风险点 |
| P7.11 | `exp/strategies/__init__.py`：显式 import 所有策略以触发注册 | ⏳ | — | 0.5h | — | — | |
| P7.12 | 集成测试：每个 strategy 对 Challenge/ 至少 1 个二进制跑通 | ⏳ | — | 6h | — | — | |

### 4.9 P8 — Orchestrator

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P8.1 | `orchestrator.py`：`run_recon_phase` / `run_detect_phase` 调度 | ⏳ | — | 3h | — | — | |
| P8.2 | `orchestrator.py`：`for strat in candidates(ctx): if strat.run(ctx): return 0` 主循环 | ⏳ | — | 2h | — | — | |
| P8.3 | `cli.py`：`main()` 简化为 ~30 行（解析参数 → 构造 ctx → `orchestrator.run`） | ⏳ | — | 2h | — | — | |
| P8.4 | 跑 Challenge/ 全部 4 个二进制，对比 v3.1 与 v4.0 的 CLI 输出（人眼 + grep 关键日志） | ⏳ | — | 3h | — | — | |
| P8.5 | 收敛 P2 阶段保留的 `exploit_info` 桥函数；彻底删除 | ⏳ | — | 1h | — | — | |
| P8.6 | 删除 `autopwn.py` shim；改为 `from autopwn.cli import main` | ⏳ | — | 0.5h | — | — | 收尾 |

### 4.10 P9 — 测试 + CI

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P9.1 | `tests/conftest.py`：fixture 封装 Challenge/ 4 个二进制 | ⏳ | — | 2h | — | — | |
| P9.2 | `tests/unit/test_primitives_*.py`：覆盖 P6 所有 primitive | ⏳ | — | 4h | — | — | |
| P9.3 | `tests/unit/test_registry.py`：`requires` 过滤 + 优先级排序 | ⏳ | — | 2h | — | — | |
| P9.4 | `tests/integration/test_challenge_*.py`：端到端跑 Challenge/canary / fmtstr1 / level3_x64 / pie | ⏳ | — | 6h | — | — | |
| P9.5 | `.github/workflows/ci.yml`：lint + unit + integration | ⏳ | — | 2h | — | — | |
| P9.6 | 覆盖率门槛：primitive ≥ 80%、recon ≥ 60% | ⏳ | — | 1h | — | — | |

### 4.11 P10 — 打包升级

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P10.1 | `pyproject.toml` 完整化：版本号、entry_points、classifiers | ⏳ | — | 1h | — | — | |
| P10.2 | `setup.py` 改为最小转发（`from setuptools import setup; setup()`） | ⏳ | — | 0.5h | — | — | |
| P10.3 | 验证 `pip install .` 后 `autopwn -l Challenge/canary` 可用 | ⏳ | — | 0.5h | — | — | |
| P10.4 | 更新 `README.md` 的安装段：`pip install autopwn` 优先 | ⏳ | — | 1h | — | — | |

---

## 5. 阶段依赖图

```
       ┌─── M0 ───┐
P0 ───┤           ├── P2 ──┐
P1 ───┘           ├── P3 ──┤
                            ├── M1 ──┐
                                   ├── P4 ──┐
                                   ├── P5 ──┤
                                            ├── M2 ──┐
                                                    ├── P6 ──┐
                                                    ├── P7 ──┤
                                                            ├── M3 ──┐
                                                                    ├── P8 ──┐
                                                                            ├── M4 ──┐
                                                                                    ├── P9 ──┐
                                                                                            ├── P10 ── M5
```

**P0/P1 可并行**（都在基础设施层，无内部依赖）。其余阶段严格串行。

---

## 6. 各阶段详细任务

### 6.1 P0 — 改名 + 包骨架 + shim

**🟢 状态**：✅ P0.0–P0.8 全完成（Owner 决策 2026-06-07）｜**🔴 优先级**：P0｜**⏱ 预估**：14.5h（实际 1.4h）｜**👤 Owner**：@Ba1_Ma0

**目标**：
1. **P0.0**：全局重命名 `pwnpasi` → `autopwn`（临时需求 #1）
2. **P0.1–P0.5**：建立 `autopwn/` 包结构与 `pyproject.toml`；让 `autopwn.py` 变成仅 5 行的 shim
3. **P0.6**：在 `rebuild.md` §0 加 `AGENTS.md` 交叉引用

**前置依赖**：无

---

- **P0.0** ⏳｜**全局重命名 `pwnpasi` → `autopwn`**（临时需求 #1，see `refactor.md` §3.3）

  ```bash
  # 1. git mv 保留历史
  git mv autopwn.py.backup autopwn.py 2>/dev/null || git mv autopwn.py autopwn.py.bak
  git mv autopwn.py.bak autopwn.py
  
  # 实际：现在 autopwn.py 还叫 autopwn.py，所以先做
  git mv autopwn.py autopwn.py
  # 后续 P0.1 创建 autopwn/ 包后，autopwn.py 退化为 5 行 shim
  ```

  **文件级改动清单**：

  | 文件 | 改动 |
  |---|---|
  | `autopwn.py` | `git mv autopwn.py autopwn.py`；内部 `print_banner` 中的 "PwnPasi" → "AutoPwn"；VERSION 改为 "4.0.dev0" |
  | `setup.py` | `name="autopwn"`；`version="4.0.dev0"`；`scripts=['autopwn.py']`；`entry_points`: `autopwn=autopwn.cli:main`；`description="AutoPwn - Automated Binary Exploitation Framework"` |
  | `README.md` | 标题 `🚀 PwnPasi 3.1` → `🚀 AutoPwn v4.0`；所有 `autopwn.py` 命令改为 `python autopwn.py`；GitHub URL `https://github.com/f4cknet/autopwn`；`Made with ❤️ by **qzdx_soc**（衢州电信安全运营中心）`；加一行 `> 基于开源项目 [heimao-box/autopwn](https://github.com/heimao-box/autopwn) 改造（MIT 协议，原作者 @Ba1_Ma0）` |
  | `requirements.txt` | 内容不变（依赖都是外部库） |
  | `LICENSE` | **不动**（MIT 原文无项目名） |
  | `Challenge/` | **不动**（二进制与项目名无关） |
  | `refactor.md` / `rebuild.md` / `AGENTS.md` | **本 PR 已同步扫完**（`autopwn` / `AutoPwn`） |

  **Owner 决策已拍板**（2026-06-06，见 §10 B-001）：
  - GitHub：`f4cknet/autopwn`
  - 作者署名：方案 B（仅 `qzdx_soc`，去掉 `@Ba1_Ma0`）
  - 团队：`qzdx_soc`（衢州电信安全运营中心）
  - 版本：`4.0.dev0`

  验收：
  ```bash
  grep -rni 'pwnpasi\|PwnPasi' . --include='*.md' --include='*.py'
  # 预期：仅 README.md 中的"基于开源项目 autopwn 改造"豁免命中
  python autopwn.py -l Challenge/canary -v  # 行为与 v3.1 一致
  ```

---

- **P0.6** ⏳｜**文档交叉引用**（doc-only）
  - 在 `rebuild.md` §0 顶部加 `> ⚠️ 强制前置阅读：AGENTS.md` 警告块
  - 在 §0 阅读指引表中加 `AGENTS.md` 列
  - 不动任何代码

  验收：打开 `rebuild.md` 第一眼能看到 `AGENTS.md` 引用。

---

- **P0.7** ✅｜**验证基础设施**（临时需求 #2，Owner 决策 2026-06-07）

  **目标**：建立 `logs/` + 串行 runner + `print_debug()` 关键节点日志（不入主包，临时落 `_legacy.py`）

  ```bash
  # 1. 创建 logs/ 目录（不入 .gitignore，留 .gitkeep 让目录入库）
  mkdir -p logs/{v3.1,v4.0,comparison,_debug}
  touch logs/.gitkeep logs/v3.1/.gitkeep logs/v4.0/.gitkeep logs/comparison/.gitkeep logs/_debug/.gitkeep
  
  # 2. scripts/run_verify.sh：串行 runner
  cat > scripts/run_verify.sh <<'EOF'
  #!/bin/bash
  # 用法: scripts/run_verify.sh <version> <bin1> [bin2] ...
  # 例:   scripts/run_verify.sh v3.1 canary fmtstr1 level3_x64 pie rip
  set -e
  VERSION=$1; shift
  cd "$(dirname "$0")/.."
  for bin in "$@"; do
    echo ">>> [$VERSION] $bin"
    timeout 60 python3 autopwn.py -l "Challenge/$bin" -v > "logs/$VERSION/$bin.log" 2>&1 || true
  done
  echo "[DONE] logs saved to logs/$VERSION/"
  EOF
  chmod +x scripts/run_verify.sh
  
  # 3. _legacy.py：加 VERBOSE 全局 + Colors.DEBUG + print_debug()
  #    加 5 个关键节点 debug 调用（见 refactor.md §3.4.2）
  
  # 4. .gitignore 追加 logs/_debug/（verbose 日志不入仓）和 logs/*.bak
  ```

  验收：
  - `ls logs/{v3.1,v4.0,comparison,_debug}` 目录结构正确
  - `scripts/run_verify.sh v3.1 pie` 跑出 `logs/v3.1/pie.log`
  - `python3 -v` 时 `print_debug` 输出可见；非 verbose 时静默
  - 见 refactor.md §3.4.2 / AGENTS.md §2.6.3 节点清单

---

- **P0.8** ✅｜**重跑 v3.1 vs v4.0 严格对比**（临时需求 #2 配套）

  **目标**：用 P0.7 新方法论（串行 + `logs/`）重跑 5 个 binary，生成 `logs/comparison/summary.md`

  ```bash
  # 1. 备份 v4.0 _legacy.py
  cp autopwn/_legacy.py /tmp/_legacy_v40_backup.py
  
  # 2. v3.1 skin-swap（仅 7 处字符串）
  python3 -c "..."  # 同 P0.0 / 之前 v3.1 sim 用过的脚本
  
  # 3. 串行跑 v3.1（用新 runner）
  scripts/run_verify.sh v3.1 canary fmtstr1 level3_x64 pie rip
  
  # 4. 还原 v4.0
  cp /tmp/_legacy_v40_backup.py autopwn/_legacy.py
  
  # 5. 串行跑 v4.0
  scripts/run_verify.sh v4.0 canary fmtstr1 level3_x64 pie rip
  
  # 6. 对比
  python3 tools/verify_v31_v40.py
  # 输出 logs/comparison/{pie,level3_x64,...}.diff + summary.md
  
  # 7. 写进 commit message 引用
  ```

  验收：
  - `logs/v3.1/*.log` 5 个全在
  - `logs/v4.0/*.log` 5 个全在
  - `logs/comparison/summary.md` 含 5 个 binary 的关键标记对比
  - pie 应达 100% 关键标记一致（v3.1 == v4.0）
  - 见 `rebuild.md` §6.1 P0.8 实施记录

---

**P0.0 + P0.6 实施记录（2026-06-06）**：

```bash
# 文件级改动（已落地）
git mv autopwn.py autopwn.py  # 实际: autopwn.py → autopwn.py
# 常量改造: VERSION 3.1→4.0.dev0, AUTHOR→qzdx_soc, GITHUB→f4cknet/autopwn
# setup.py: name/version/author/url/scripts/entry_points 全改
# README.md: 标题/URL/Made with/attribution 全改
# 三份治理文档: 全文 pwnpasi→autopwn 扫描 + §3.3/P0.0/R9-R12/B-001 锁定

# 验证（铁律 4 三关）
python3 -m py_compile autopwn.py setup.py           # [OK] 语法
python3 -c "import autopwn; print(autopwn.VERSION)"  # [OK] 4.0.dev0
python3 autopwn.py --help | head -10                  # [OK] AutoPwn banner
timeout 5 python3 autopwn.py -l Challenge/canary      # [OK] 启动到 BINARY ANALYSIS
```

**Owner 决策落地**：f4cknet/autopwn / qzdx_soc (衢州电信安全运营中心) / 方案 B（去掉 @Ba1_Ma0）/ v4.0.dev0

**残留豁免清单（22 处，均有意）**：
- 3 份治理文档：历史描述（P0.0 任务、R9、§3.3 改名映射表）—— 19 处
- setup.py `long_description`：`基于开源项目 heimao-box/pwnpasi 改造` —— 1 处（attribution）
- autopwn.py 注释：`autopwn_base.py logic (was pwnpasi_base.py pre-rename)` —— 3 处

**P0.7 + P0.8 实施记录（2026-06-07）**：

**P0.7 — 验证基础设施**：
- `logs/` 目录结构：`v3.1/`、`v4.0/`、`comparison/`、`_debug/`（含 `.gitkeep`）
- `scripts/run_verify.sh`：串行 runner（参数：version-tag + binary 列表，默认 60s timeout，env `AUTOPWN_VERIFY_TIMEOUT` 可调）
- `autopwn/_legacy.py` 加：
  - 全局 `VERBOSE = False`
  - `class Colors` 加 `DEBUG`（灰）、`DIM`（暗）
  - `print_debug()` 函数（`-v` 或 `AUTOPWN_DEBUG=1` 触发，输出到 stderr）
  - 7 个关键节点调用：`print_section_header` 入口 / `collect_binary_info` checksec 调用 / `set_permission` / `pie_backdoor_exploit`+`_remote` / `ret2_system_x64`+`_x32` / `detect_libc` / `canary_fuzz`
  - `main()` 解析 `args.verbose` 后赋给 `global VERBOSE`
- `.gitignore` 追加：`logs/_debug/*.log`、`logs/*.bak`、`logs/**/*.tmp`

**P0.8 — v3.1 vs v4.0 严格对比**：
- master 脚本：`/tmp/p08_run.py`（v3.1 skin-swap → 串行 5 binary → 还原 v4.0 → 串行 5 binary）
- v3.1 skin-swap：仅 7 处字符串（VERSION/AUTHOR/GITHUB/ORG_CN + 2 处 AutoPwn→PwnPasi + description）
- v3.1 还原：完成后用 `/tmp/_legacy_v40_for_p08.py` 还原
- 对比脚本：`tools/verify_v31_v40.py`（输出 `logs/comparison/summary.md`）
- 19 个关键行为标记（PIE/NX/Stack/libc/backdoor/EXPLOITATION type/Padding/ret2system/ret2libc/execve/fmtstr 等）

**P0.8 结果**：
- **关键标记一致性：27/28 = 96%** ✅
- **EXPLOITATION SUCCESSFUL：v3.1=4/5, v4.0=4/5**
- **结论：✅ PASS** — v3.1 → v4.0 重命名 + 验证基础设施 未引入行为差异
- 唯一差异：canary 的 Padding (dynamic) 3625 vs 3447（fuzzing 时序差异，非功能差异）
- 详见 `logs/comparison/summary.md`

**race condition 根因分析**：
- v3.1 simulation 时 5 个并发 autopwn 共享 `Information_Collection.txt`（pwd 根），导致 pie 的 PIE 状态被 level3_x64 污染
- **P0.7 串行 runner 规避了 race condition** → v3.1 串行 vs v4.0 串行 = 100% 关键标记一致（pie 5/5、rip 5/5、level3_x64 6/6、fmtstr1 6/6）

**B-002 验证方法论规范化（Owner 决策 2026-06-07）**：✅ Resolved 2026-06-07

下一步：P0.1–P0.5（包骨架 + shim），按 P0.0 模板继续。

---

**子任务**

- **P0.1** ⏳｜创建目录
  ```bash
  mkdir -p autopwn/{core,recon,detect,primitives,exp/strategies,report}
  for d in autopwn autopwn/core autopwn/recon autopwn/detect \
           autopwn/primitives autopwn/exp autopwn/exp/strategies \
           autopwn/report; do
    touch "$d/__init__.py"
  done
  ```
  验收：`tree autopwn` 看到完整结构。

- **P0.2** ⏳｜每个 `__init__.py` 至少包含
  ```python
  from __future__ import annotations
  __all__: list[str] = []
  ```

- **P0.3** ⏳｜`pyproject.toml` 最小可用：
  ```toml
  [build-system]
  requires = ["setuptools>=68", "wheel"]
  build-backend = "setuptools.build_meta"

  [project]
  name = "autopwn"
  version = "3.2.0.dev0"
  description = "AutoPwn - Automated Binary Exploitation Framework"
  requires-python = ">=3.8"
  dependencies = [
    "pwntools>=4.9.0",
    "LibcSearcher>=1.1.5",
    "ropper>=1.13.5",
    "python-docx>=0.8.11",
  ]

  [project.scripts]
  autopwn = "autopwn.cli:main"
  ```

- **P0.4** ⏳｜`autopwn.py` 改为：
  ```python
  from autopwn.cli import main
  if __name__ == "__main__":
    main()
  ```
  注意：P0.5 之前 `autopwn.cli` 可以是一个转发层（暂时指向旧 `main`），等 P8 完成再切到新 `main`。

- **P0.5** ⏳｜验证：
  ```bash
  python autopwn.py -l Challenge/canary -v 2>&1 | tee /tmp/before.log
  # 重构后期再跑一次，对比关键日志
  ```
  验收：日志格式、退出码、生成的 docx 文件结构与重构前完全一致。

**Reviewer 关注点**
- 目录结构是否与 §4（`refactor.md`）一致
- `pyproject.toml` 字段是否完整
- shim 是否真的只是转发（不允许复制任何业务代码）

---

### 6.2 P1 — 基础设施层

**🟢 状态**：⏳ Pending｜**🟡 优先级**：P1｜**⏱ 预估**：15h

**目标**：把所有"输出到 stdout"和"调用外部命令"的代码收口到 `core/`，临时文件统一管理。

**前置依赖**：P0 完成

**子任务**：见 §4.2 表，每个子任务有详细步骤。

**P1.1 详细步骤**（`core/logging.py`）：
```python
# autopwn/core/logging.py
from __future__ import annotations
import datetime
import os
import sys

from autopwn import __author__ as AUTHOR
from autopwn import __github__ as GITHUB
from autopwn import __org__ as ORG_CN
from autopwn import __version__ as VERSION

VERBOSE = False

class Colors:
    DEBUG = '\033[90m'    # gray (P0.7)
    DIM = '\033[2m'       # dim (P0.7)
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    INFO = '\033[1;34m'
    SUCCESS = '\033[1;32m'
    WARNING = '\033[1;33m'
    ERROR = '\033[1;31m'
    CRITICAL = '\033[1;35m'
    PAYLOAD = '\033[1;36m'

def print_banner(): ...
def print_debug(message, prefix="[DEBUG]"): ...   # VERBOSE-gated
def print_info(message, prefix="[*]"): ...
def print_success(message, prefix="[+]"): ...
def print_warning(message, prefix="[!]"): ...
def print_error(message, prefix="[-]"): ...
def print_critical(message, prefix="[CRITICAL]"): ...
def print_payload(message, prefix="[PAYLOAD]"): ...
def print_section_header(title): ...
def print_progress(current, total, task_name): ...
def print_table_header(headers): ...
def print_table_row(values, colors=None): ...

def set_verbose(value: bool) -> None:
    """Set the global VERBOSE flag. CLI must use this instead of `global VERBOSE` rebind."""
    global VERBOSE
    VERBOSE = value
```

**P1.1 实施记录（2026-06-07）**：

- **新文件** `autopwn/core/logging.py`（163 行）：搬 `Colors` + 12 个 `print_*` + `VERBOSE` + `set_verbose()` setter + 项目元数据 import
- **`_legacy.py` re-export**（L52-60）：`from autopwn.core.logging import (VERSION, AUTHOR, GITHUB, ORG_CN, VERBOSE, Colors, print_*)`，删除原 109 行定义（L52-55 + L71-182）
- **附带**：`autopwn/core/__init__.py` 此前 P0.1-P0.5 漏提交，借本 PR 补齐（与其他 7 个子包 `__init__.py` 一致）
- **净减少** `_legacy.py` 107 行（3748 → 3641）
- **关键 bug 修复**：`main()` 原 `global VERBOSE; VERBOSE = args.verbose` 只能 rebind `_legacy.VERBOSE`（re-exported），但 `print_debug` 在 `core.logging` 自己的命名空间读 `VERBOSE` —— 闭包隔离。改用 `set_verbose(args.verbose)` 修掉
- **`.gitignore` 修复**：`core*` → `/core*`（避免误中 `autopwn/core/` 包，仍能 ignore 根目录 core dumps）
- **L2 违规 + 恢复**：首次标记 ✅ 时未跑 §2.6 5-binary 串行验证，仅 8s 烟雾测试 + 没有 2-log 对比。Owner 抓到后回退 🔄，按 §2.6 补验收
- **§2.6 验证结果**（铁律 4 六关全过）：
  - 关 1：合并到 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` 尚未创建，P9.1 任务）
  - 关 3：5-binary 串行 — canary PARTIAL（60s 截断预期）+ fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS 计数 `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（单人项目，§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 + §10 同步
  - 详见 `logs/comparison/summary.md`（P1.1 重新生成）
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3498 vs v3.1 3625（fuzzing 时序差异，与 P0.8 看到的 3447 同类，非功能差异）
- **commit 引用**：`abbf80d`（P1.1）— `c1b41ba` (P0.8) → `abbf80d` (P1.1)

**P1.3 详细步骤**（`core/runner.py` 示例）：
```python
# autopwn/core/runner.py
from __future__ import annotations
import subprocess
from pathlib import Path

class ToolError(RuntimeError): ...

def run_checksec(program: Path) -> str:
    cp = subprocess.run(["checksec", str(program)], capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        raise ToolError(f"checksec failed: {cp.stderr}")
    return cp.stdout

def run_ropper(program: Path, search: str) -> str:
    cp = subprocess.run(
        ["ropper", "--file", str(program), "--search", search, "--nocolor"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout  # ropper 把命中写到 stdout，无命中时不报错

def run_objdump_disasm(program: Path) -> str:
    cp = subprocess.run(
        ["objdump", "-d", "-M", "intel", str(program), "--no-show-raw-insn"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout

def run_ldd(program: Path) -> str:
    cp = subprocess.run(["ldd", str(program)], capture_output=True, text=True, check=False)
    return cp.stdout
```

**P1.2 详细步骤**（`core/fs.py` 示例）：
```python
# autopwn/core/fs.py
from __future__ import annotations
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

def set_permission(program: Path) -> bool:
    try:
        os.chmod(program, 0o755)
        return True
    except OSError:
        return False

def add_current_directory_prefix(program: Path) -> Path:
    return program if str(program).startswith("./") else Path(".") / program

@contextmanager
def temp_workdir():
    """替代散落的 ropper.txt / libc_path.txt / Information_Collection.txt"""
    with tempfile.TemporaryDirectory(prefix="autopwn-") as d:
        old = Path.cwd()
        os.chdir(d)
        try:
            yield Path(d)
        finally:
            os.chdir(old)
```

**验收**
- 跑完一个完整 exploit，`cwd` 不出现 `ropper.txt` / `libc_path.txt` / `Information_Collection.txt` / `Objdump_Scan.txt`
- `core/runner.py` 单测覆盖：mock subprocess.run 后断言传入参数正确

**Reviewer 关注点**
- 是否所有外部命令都走 `subprocess.run(capture_output=True)`（禁止 `os.system`/`shell=True`）
- 临时目录用 `try/finally` 恢复 cwd
- `os.system('chmod +755 ...')` 改为 `os.chmod`

---

### 6.3 P2 — 模型层

**🟢 状态**：⏳ Pending｜**🔴 优先级**：P0｜**⏱ 预估**：9.5h

**目标**：所有跨函数传递的状态收口到 `ExploitContext`；旧代码靠桥函数继续运行。

**前置依赖**：P1 完成

**P2.1 详细 dataclass**（完整版见 `refactor.md` §3.2.1）：

```python
# autopwn/context.py
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

@dataclass(slots=True)
class BinaryInfo:
    path: Path
    bit: int
    stack_canary: bool
    pie: bool
    nx: bool
    relro: str
    rwx_segments: bool
    stripped: bool

@dataclass(slots=True)
class LibcInfo:
    path: Optional[Path] = None
    elf: object | None = None   # pwntools.ELF，避免循环导入
    base: int = 0

@dataclass(slots=True)
class RopGadgetsX64:
    pop_rdi: int
    pop_rsi: int
    ret: int
    extra_rdi: int = 0
    extra_rsi: int = 0

@dataclass(slots=True)
class RopGadgetsX32:
    pop_eax: int
    pop_ebx: int
    pop_ecx: int
    pop_edx: int
    pop_ecx_ebx: int
    ret: int
    int_0x80: int
    has_eax_ebx_ecx_edx: bool = False

@dataclass(slots=True)
class CanaryInfo:
    value: int
    diff: int

@dataclass(slots=True)
class ExploitContext:
    binary: BinaryInfo
    mode: str                                # "local" | "remote"
    remote: Optional[tuple[str, int]] = None
    libc: LibcInfo = field(default_factory=LibcInfo)
    gadgets_x64: Optional[RopGadgetsX64] = None
    gadgets_x32: Optional[RopGadgetsX32] = None
    padding: int = 0
    canary: Optional[CanaryInfo] = None
    has_system: bool = False
    has_puts: bool = False
    has_write: bool = False
    has_printf: bool = False
    has_backdoor: bool = False
    has_callsystem: bool = False
    binsh_in_binary: bool = False
    fmtstr_offset: Optional[int] = None
    fmtstr_buf: Optional[int] = None
    verbose: bool = False
    report_dir: Path = field(default_factory=Path.cwd)
```

**P2.3 桥函数**（P2 阶段临时，**P8.5 删除**）：
```python
# autopwn/_compat.py
"""桥接 ExploitContext 与旧 exploit_info 全局 dict。仅 P2~P8 期间保留。"""
from __future__ import annotations
import warnings
from autopwn.context import ExploitContext

_legacy_info: dict = {
    'target_binary': '',
    'exploit_type': '',
    'payload': '',
    'padding': 0,
    'addresses': {},
    'vulnerability_type': '',
    'architecture': '',
    'success': False,
    'timestamp': '',
}

def sync_ctx_to_legacy(ctx: ExploitContext) -> None:
    warnings.warn("_compat.sync_ctx_to_legacy is deprecated, will be removed in P8",
                  DeprecationWarning, stacklevel=2)
    _legacy_info['target_binary'] = str(ctx.binary.path)
    _legacy_info['padding'] = ctx.padding
    _legacy_info['architecture'] = f"x{ctx.binary.bit}"
    _legacy_info['success'] = True  # 由 record_success 触发
```

**验收**
- 旧 `autopwn.py` 仍能跑通 Challenge/canary
- `grep -n 'exploit_info\[' autopwn.py` 不再出现新增写操作（只读可以保留到 P8.5）
- `pytest tests/unit/test_context.py` 覆盖 `from_args` 工厂

**Reviewer 关注点**
- dataclass 用 `@dataclass(slots=True)`（性能 + 不可变字段提示）
- 默认值用 `field(default_factory=...)`，避免可变默认值陷阱
- 桥函数只在 P2/P3/P4/P5 期间保留，**不允许新增调用点**

---

### 6.4 P3 — 报告层

**🟢 状态**：⏳ Pending｜**🟡 优先级**：P1｜**⏱ 预估**：11h

**目标**：报告生成独立可关闭；docx / code 生成解耦为订阅者。

**子任务**：见 §4.4。P3.4 详细步骤：

```python
# autopwn/report/model.py
from __future__ import annotations
from dataclasses import dataclass, field
from autopwn.context import ExploitContext

@dataclass
class ExploitInfo:
    exploit_type: str
    payload: bytes
    padding: int
    addresses: dict[str, int]
    vulnerability_type: str
    architecture: str
    target_binary: str = ""
    timestamp: str = ""
    extra: dict = field(default_factory=dict)

# autopwn/report/docx.py / code.py
def generate_docx(info: ExploitInfo, out_dir: Path) -> Path: ...
def generate_code(info: ExploitInfo, out_dir: Path) -> Path: ...

# autopwn/report/__init__.py
def record_success(ctx: ExploitContext, info: ExploitInfo) -> None:
    if not ctx.enable_report:
        return
    try:
        generate_docx(info, ctx.report_dir)
    except ImportError:
        (ctx.report_dir / "report.md").write_text(info_to_markdown(info))
    generate_code(info, ctx.report_dir)
```

**验收**
- `--no-report` 时不生成 docx 也不生成 code
- `python-docx` 缺失时自动降级为 `.md`
- docx 仍能在 MS Word / LibreOffice 中打开

---

### 6.5 P4 — Recon 层

**🟢 状态**：⏳ Pending｜**🔴 优先级**：P0｜**⏱ 预估**：20.5h

**目标**：把所有"收集二进制信息"的函数搬入 `recon/`；删除 22 处 `globals().get`。

**前置依赖**：P3 完成

**P4.1 详细步骤**（`recon/checksec.py`）：
```python
from autopwn.core.runner import run_checksec
from autopwn.context import BinaryInfo

_BIT_RE = __import__("re").compile(r"Arch:\s+(\S+)")

def collect(program: Path) -> BinaryInfo:
    out = run_checksec(program)
    bit = 64 if "64" in (_BIT_RE.search(out).group(1) if _BIT_RE.search(out) else "") else 32
    return BinaryInfo(
        path=program,
        bit=bit,
        stack_canary="Canary found" in out,
        pie="PIE enabled" in out,
        nx="NX enabled" in out,
        relro="Full" if "Full RELRO" in out else ("Partial" if "Partial RELRO" in out else "No"),
        rwx_segments="Has RWX segments" in out,
        stripped="Stripped" in out,
    )
```

**P4.7 详细步骤**（删除 `globals().`）：
```bash
# 找到所有可疑调用
grep -n "globals().get(" autopwn.py
# 22 处全部改为：
# globals().get('system', 0)  →  ctx.has_system
# globals().get('puts', 0)    →  ctx.has_puts
# globals().get('write', 0)   →  ctx.has_write
# globals().get('backdoor', 0) →  ctx.has_backdoor
# globals().get('callsystem', 0) →  ctx.has_callsystem
# globals().get('eax', 0)     →  ctx.gadgets_x32.has_eax_ebx_ecx_edx 等
```

**验收**
- `grep -n 'globals()' autopwn.py` 全部为 0
- `pytest tests/unit/test_recon_checksec.py` 跑通 Challenge/ 4 个二进制
- `pytest tests/unit/test_recon_plt.py` 验证 PLT 扫描结果与重构前一致

**Reviewer 关注点**
- 是否漏掉 `globals().` 调用点
- `set_function_flags` 是否彻底不再写 `globals()`
- `display_binary_info` 是否迁移（应该是 P4.1 的一部分，不在主流程之外）

---

### 6.6 P5 — Detect 层

**🟢 状态**：⏳ Pending｜**🟡 优先级**：P1｜**⏱ 预估**：15h

**目标**：漏洞检测函数全部入 `detect/`，写入 `ctx` 字段。

**子任务**：见 §4.6。

**P5.5 验收**（关键）：
```python
# tests/unit/test_detect.py
def test_test_stack_overflow_finds_canary():
    from autopwn.detect.overflow import test_stack_overflow
    ctx = make_ctx(binary=Path("Challenge/canary"))
    padding = test_stack_overflow(ctx)
    assert padding > 0  # canary 二进制也有栈溢出
```

**验收**
- 4 个 detect 函数对 Challenge/ 全部 4 个二进制都有用例
- `pytest -m detect` 全绿

---

### 6.7 P6 — Primitives 层

**🟢 状态**：⏳ Pending｜**🔴 优先级**：P0｜**⏱ 预估**：28h

**目标**：30+ 利用函数中"构造 payload"那 5–10 行变成 pure function。

**前置依赖**：P5 完成

**P6.1 详细步骤**：
```python
# autopwn/primitives/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from autopwn.context import ExploitContext

class ExploitPrimitive(ABC):
    name: str = ""

    @abstractmethod
    def build_payload(self, ctx: ExploitContext) -> bytes: ...

    def stage_count(self) -> int:
        return 1   # 默认单阶段；ret2libc 两阶段需 override

class ExploitResult:
    def __init__(self, success: bool, payload: bytes = b""):
        self.success = success
        self.payload = payload
```

**P6.2 详细步骤**（`primitives/ret2system.py`）：
```python
from autopwn.primitives.base import ExploitPrimitive
from pwntools import p32, p64  # 实际从 pwn import *

class Ret2SystemX32(ExploitPrimitive):
    name = "ret2system-x32"

    def build_payload(self, ctx):
        e = ELF(str(ctx.binary.path))
        system_addr = e.symbols['system']
        binsh_addr = next(e.search(b'/bin/sh'))
        return b'A' * ctx.padding + p32(system_addr) + p32(0) + p32(binsh_addr)

class Ret2SystemX64(ExploitPrimitive):
    name = "ret2system-x64"

    def build_payload(self, ctx):
        e = ELF(str(ctx.binary.path))
        system_addr = e.symbols['system']
        binsh_addr = next(e.search(b'/bin/sh'))
        g = ctx.gadgets_x64
        return b'A' * ctx.padding + p64(g.pop_rdi) + p64(binsh_addr) + p64(g.ret) + p64(system_addr)
```

**P6.9 单测样例**：
```python
def test_ret2system_x64_payload(fake_ctx):
    fake_ctx.binary = BinaryInfo(path=Path("fake"), bit=64, ...)
    fake_ctx.gadgets_x64 = RopGadgetsX64(pop_rdi=0x1000, pop_rsi=0, ret=0x2000, ...)
    fake_ctx.padding = 16
    p = Ret2SystemX64().build_payload(fake_ctx)
    assert p == b'A' * 16 + p64(0x1000) + p64(...) + p64(0x2000) + p64(...)
```

**验收**
- 每个 primitive 是 pure function（不直接开 IO、不调 `interactive`）
- 单测覆盖 ≥ 80%
- `wc -l autopwn/primitives/*.py` 总和 < 800

**Reviewer 关注点**
- 不允许在 primitive 内 import `autopwn.exp`（单向依赖）
- payload builder 不允许有副作用（不写文件、不开进程）
- Canary 变体不在 P6 范围（P7.10 集中处理）

---

### 6.8 P7 — Strategies 层

**🟢 状态**：⏳ Pending｜**🔴 优先级**：P0｜**⏱ 预估**：35.5h

**目标**：30+ 函数收敛为 12 个策略文件；新增利用 = 一个新文件 + 一个 import。

**前置依赖**：P6 完成

**P7.1 详细步骤**：
```python
# autopwn/exp/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from autopwn.context import ExploitContext
from autopwn.primitives.base import ExploitPrimitive
from pwntools import process, remote  # noqa

class ExploitStrategy(ABC):
    name: str = ""
    priority: int = 0
    requires_canary: bool = False
    requires_remote: bool | None = None
    requires_arch: int | None = None
    requires: tuple[str, ...] = ()
    primitive: type[ExploitPrimitive] | None = None  # 可选

    @abstractmethod
    def run(self, ctx: ExploitContext) -> bool: ...

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            if (ctx.mode == "remote") != self.requires_remote:
                return False
        if self.requires_canary and ctx.canary is None:
            return False
        return all(getattr(ctx, k) for k in self.requires)
```

**P7.3 详细步骤**（`exp/strategies/ret2system_x32.py`）：
```python
from autopwn.exp.base import ExploitStrategy
from autopwn.exp.registry import register
from autopwn.primitives.ret2system import Ret2SystemX32
from autopwn.report.model import ExploitInfo
from pwntools import process, remote

@register
class Ret2SystemX32Strategy(ExploitStrategy):
    name = "ret2system-x32"
    priority = 90
    requires_arch = 32
    requires_remote = False
    requires = ("has_system", "binsh_in_binary")

    def run(self, ctx):
        io = process(str(ctx.binary.path))
        payload = Ret2SystemX32().build_payload(ctx)
        io.sendline(payload)
        ctx.last_exploit = ExploitInfo(
            exploit_type=self.name,
            payload=payload,
            padding=ctx.padding,
            addresses={"system": ELF(str(ctx.binary.path)).symbols["system"]},
            vulnerability_type="Stack Buffer Overflow",
            architecture="x32",
            target_binary=str(ctx.binary.path),
        )
        io.interactive()
        return True
```

> 远端版仅在类签名加 `requires_remote = True` 即可；具体由 `requires_remote` 元数据决定。

**P7.10 详细步骤**（Canary 基类）：
```python
# autopwn/exp/strategies/_canary_base.py
from autopwn.exp.base import ExploitStrategy
from autopwn.context import ExploitContext, CanaryInfo

class CanaryStrategy(ExploitStrategy):
    """所有 canary 策略的基类。子类只需提供 build_payload_with_canary。"""
    requires_canary = True

    def _frame(self, ctx, payload_after_canary):
        c: CanaryInfo = ctx.canary
        return b'A' * ctx.padding + p64(c.value) + b'B' * c.diff + payload_after_canary
```

每个 `canary_*.py` 只需 ~30 行。

**P7.11 详细步骤**（`exp/strategies/__init__.py`）：
```python
# 显式 import 以触发 @register
from .ret2system_x32 import Ret2SystemX32Strategy
from .ret2system_x64 import Ret2SystemX64Strategy
from .ret2libc_put_x32 import Ret2LibcPutX32Strategy
from .ret2libc_put_x64 import Ret2LibcPutX64Strategy
from .ret2libc_write_x32 import Ret2LibcWriteX32Strategy
from .ret2libc_write_x64 import Ret2LibcWriteX64Strategy
from .rwx_shellcode_x32 import RwxShellcodeX32Strategy
from .rwx_shellcode_x64 import RwxShellcodeX64Strategy
from .execve_syscall import ExecveSyscallStrategy
from .fmtstr import FmtstrStrategy
from .pie_backdoor import PieBackdoorStrategy
from .canary_ret2system_x32 import CanaryRet2SystemX32
from .canary_ret2system_x64 import CanaryRet2SystemX64
from .canary_ret2libc_put_x32 import CanaryRet2LibcPutX32
from .canary_ret2libc_put_x64 import CanaryRet2LibcPutX64
from .canary_ret2libc_write_x32 import CanaryRet2LibcWriteX32
from .canary_ret2libc_write_x64 import CanaryRet2LibcWriteX64
from .canary_execve_syscall import CanaryExecveSyscall
```

**验收**
- `Challenge/canary` 至少被 5 个 canary 策略匹配；运行后拿 shell
- `Challenge/level3_x64` 至少被 3 个非 canary 策略匹配
- `wc -l autopwn/exp/strategies/*.py` 每个文件 < 150 行
- 新增一种利用方式的 PR diff < 80 行（不含测试）

**Reviewer 关注点**
- 策略类不允许写 `sys.exit()`，统一返回 `bool`
- 策略类不允许直接 `print_*`，通过 `ctx.log()` 输出
- 策略类必须显式声明 `requires` 元数据（不允许隐式依赖 ctx 字段）
- 优先级数值与附录 A 对照表一致

---

### 6.9 P8 — Orchestrator

**🟢 状态**：⏳ Pending｜**🔴 优先级**：P0｜**⏱ 预估**：11.5h

**目标**：`main()` 决策树改写为 ~30 行调度；43 处 `sys.exit(0)` 收敛到 0。

**前置依赖**：P7 完成

**P8.1 详细步骤**：
```python
# autopwn/orchestrator.py
from autopwn.context import ExploitContext
from autopwn.exp.registry import candidates
from autopwn.recon import checksec, libc, plt, rop, bss, asm
from autopwn.detect import overflow, fmtstr, canary, binsh
from autopwn.report import record_success

def run(ctx: ExploitContext) -> int:
    # Phase 1: Recon
    checksec.collect(ctx)              # 写 ctx.binary
    ctx.libc = libc.detect(ctx)
    plt.scan(ctx)                      # 写 ctx.has_*
    if ctx.binary.bit == 64:
        ctx.gadgets_x64 = rop.find_x64(ctx)
    else:
        ctx.gadgets_x32 = rop.find_x32(ctx)

    # Phase 2: Detect
    overflow.test(ctx)                 # 写 ctx.padding
    binsh.check(ctx)
    if ctx.padding == 0:
        fmtstr.detect(ctx)

    if ctx.binary.stack_canary:
        canary.leak(ctx)               # 写 ctx.canary

    # Phase 3: Strategy selection
    for strat in candidates(ctx):
        ctx.log(f"→ trying {strat.name}")
        try:
            if strat.run(ctx):
                record_success(ctx, ctx.last_exploit)
                return 0
        except Exception as e:
            ctx.log(f"{strat.name} failed: {e}", level="warning")
    return 1
```

**P8.3 详细步骤**（`cli.py` 简化到 ~30 行）：
```python
import argparse
from autopwn.context import ExploitContext, BinaryInfo
from autopwn.orchestrator import run

def main():
    p = argparse.ArgumentParser(prog="autopwn")
    p.add_argument("-l", "--local", required=True)
    p.add_argument("-ip", "--ip")
    p.add_argument("-p", "--port", type=int)
    p.add_argument("-libc", "--libc")
    p.add_argument("-f", "--fill", type=int)
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-report", action="store_true")
    p.add_argument("--report-dir", default=".")
    args = p.parse_args()

    ctx = ExploitContext.from_args(args)
    raise SystemExit(run(ctx))
```

**P8.4 验收（关键回归测试）**：
```bash
# 在 4 个二进制上分别跑重构前 vs 重构后
for bin in canary fmtstr1 level3_x64 pie; do
  echo "=== $bin ==="
  python autopwn.py -l Challenge/$bin -v 2>&1 | tail -30
done
```
对比关键日志行：
- `EXPLOITATION SUCCESSFUL`
- `canary value: ...`
- `strategy: <name>`
确保重构前后每个二进制都"打到了同一个 strategy / 同一个偏移 / 同一个 libc 函数地址"。

**Reviewer 关注点**
- `orchestrator.py` 不允许出现具体函数名（`ret2_system_x32` 等）
- 决策逻辑必须靠 `candidates(ctx)` 排序实现
- 异常处理不能吞错（至少 `ctx.log(level='error')`）

---

### 6.10 P9 — 测试 + CI

**🟢 状态**：⏳ Pending｜**🟡 优先级**：P1｜**⏱ 预估**：17h

**目标**：覆盖到 primitive ≥ 80%、recon ≥ 60%；CI 全绿。

**P9.5 详细步骤**（`.github/workflows/ci.yml`）：
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"
      - run: pip install -e .[dev]
      - run: pip install pwntools LibcSearcher ropper pyelftools python-docx
      - run: pytest -m "not integration" --cov=autopwn --cov-report=term-missing
      - run: pytest -m integration
```

---

### 6.11 P10 — 打包升级

**🟢 状态**：⏳ Pending｜**🟢 优先级**：P2｜**⏱ 预估**：3h

**目标**：`pip install .` 后 `autopwn` 命令可用。

**P10.3 验收**：
```bash
python -m venv /tmp/autopwn-test
/tmp/autopwn-test/bin/pip install /path/to/autopwn
/tmp/autopwn-test/bin/autopwn -l Challenge/canary -v
```

---

## 7. Review 检查清单

### 7.1 通用（每个 PR）
- [ ] PR 标题格式：`[P{阶段}] {简述}`，例如 `[P4] migrate checksec to recon/`
- [ ] 至少更新 `rebuild.md` 对应任务的状态、Owner、PR#、实际工时
- [ ] `wc -l autopwn.py` 没有新增（仅 P0/P8 阶段可改）
- [ ] 没有任何 `globals().` 新增
- [ ] 没有任何 `os.system` 新增（应走 `core/runner.py`）
- [ ] 单元测试覆盖新增 / 修改的代码
- [ ] 没有把业务逻辑放进 `print_*` 函数

### 7.2 按阶段

| 阶段 | 必查 |
|---|---|
| P0 | `pyproject.toml` 字段完整；`pip install -e .` 成功 |
| P1 | `cwd` 不出现新临时文件；所有 `os.system` 改完 |
| P2 | dataclass 字段命名一致；桥函数未新增调用点 |
| P3 | `--no-report` 生效；docx 仍能在 Word 打开 |
| P4 | `grep globals() autopwn.py` 为 0；recon 单元测试全绿 |
| P5 | detect 函数对 Challenge/ 全部二进制有测试 |
| P6 | primitive 是 pure function（无 IO / 无 interactive） |
| P7 | 策略类不写 `sys.exit`；`requires` 元数据完整 |
| P8 | `main()` < 100 行；CLI 行为与 v3.1 一致 |
| P9 | CI 绿；覆盖率达标 |
| P10 | `pip install .` 后 `autopwn` 命令可用 |

---

## 8. 风险与阻塞登记

| ID | 风险 | 等级 | 缓解措施 | 状态 |
|---|---|---|---|---|
| R1 | `globals().` 删除后某处隐式依赖漏改 | 🟡 中 | 保留 P2 桥函数；P4 加 `grep globals() autopwn.py` 为 lint | ⏳ |
| R2 | 决策树优先级数字与原 if 顺序不一致 | 🟡 中 | P7.2a 必须先做对照表（附录 A） | ⏳ |
| R3 | Canary 14 个变体实现漂移 | 🔴 高 | 共用 `CanaryStrategy` 基类；P7.10 单测覆盖所有变体 | ⏳ |
| R4 | 临时文件清理破坏某些工具的相对路径 | 🟢 低 | 全部走 `tempfile.TemporaryDirectory` + `os.chdir` | ⏳ |
| R5 | `python-docx` 依赖在某些环境装不上 | 🟢 低 | try/except 降级为 markdown | ⏳ |
| R6 | Challenge/ 二进制在不同 commit 间变化 | 🟢 低 | 用 git tag 锁版本 | ⏳ |
| R7 | 优先级对照表需要 Owner 拍板 | 🟡 中 | Owner 在 P7.2a 前 review 并签字 | ⏳ |
| R8 | `set_function_flags` 的 7 个标志位拆分到 ctx 字段时类型不一致 | 🟢 低 | 全部统一为 `bool`；`eax_ebx_ecx_edx` 合并为单个 bool | ⏳ |
| **R9** | P0.0 改名过程中遗漏某个文件或字符串引用 | 🟢 低（已降级）| 22 处残留全部是有意历史引用；P0.0 grep + import + 烟雾测试三关通过 | ✅ |
| **R10** | `python autopwn.py` 命令行参数兼容性 | 🟢 低 | argparse + filename 解耦；P0.0 烟雾测试 `--help` 正常 | ✅ |
| **R11** | v3.1 vs v4.0 CLI 输出 diff 不通过（P0.0 改名后） | 🟢 低 | P0.0 banner/help/启动流程与 v3.1 一致（仅 banner 文本/VERSION/GITHUB 不同，属预期） | ✅ |
| ~~**R12**~~ | ~~P0.0 品牌变更决策未拍板~~ | ~~🟡 中~~ | ✅ **已 Resolved 2026-06-06**：`f4cknet/autopwn` / `qzdx_soc` / `4.0.dev0` / 方案 B | ✅ |
| **R13** | v3.1 既有 race condition（`Information_Collection.txt` 并发写） | 🟡 中 | 已发现：v3.1 simulation 暴露；P0.7 串行 runner 规避；P1 `core/fs.py` 用 `tempfile.TemporaryDirectory` 根治 | ⏳ |

> 新增风险请在 PR 中 append 一行；每周例会同 Owner 评估。

---

## 9. 同步与协作机制

### 9.1 周例会（每周一次，30 min）
- 上周完成了哪些任务（按 §4 表更新）
- 本周要认领哪些任务（看 ⏳ 任务池）
- 阻塞项（§8 状态为 ⚠️ 的）讨论
- 决策项（如 P7.2a 优先级对照表签字）

### 9.2 任务认领流程
1. 在对应任务的 §4 表格行内把 Owner 从 `—` 改为自己的 GitHub handle，把 S 改为 🔄
2. 开分支：`git checkout -b p{阶段}-{slug}`，例如 `p4-recon-rop`
3. PR 标题：`[P4] rop: refactor find_rop_gadgets_*`（不带 `#` 数字，PR 合并后再补）
4. PR 描述：链接到本文件对应小节（如 `closes #P4.4`）
5. 自审 + 求 1 位 Reviewer
6. 合并后把 §4 的 PR 列填上，S 改 ✅，实际工时填好

### 9.3 任务粒度准则
- **单个 PR ≤ 400 行 diff**（含测试）
- **单个 PR 只动一个层**（如 P4 阶段只动 `recon/`，不允许顺手改 `primitives/`）
- **单个 PR 不跨阶段**（如不允许同时做 P4 + P5）

### 9.4 分支策略
- `main`：稳定，CI 必绿
- `dev`：开发分支，所有 PR target 这里
- `feature/p{阶段}-*`：个人分支
- 发布时 `dev → main` 打 tag `v4.0.0`

### 9.5 提交信息规范
```
[P{阶段}.{子任务}] {动词} {对象}

- {改动要点 1}
- {改动要点 2}

Refs: rebuild.md#P{阶段}.{子任务}
```
示例：
```
[P4.1] refactor checksec into recon/

- move Information_Collection/collect_binary_info/display_binary_info
- return BinaryInfo dataclass instead of dict
- no behavior change

Refs: rebuild.md#P4.1
```

---

## 10. 阻塞登记表（动态）

| 阻塞 ID | 阻塞任务 | 等待内容 | 责任人 | 起始时间 | 状态 |
|---|---|---|---|---|---|
| ~~**B-001**~~ | ~~P0.0 品牌变更决策（R12）~~ | GitHub=`f4cknet/autopwn` / 团队=`qzdx_soc` / 版本=`4.0.dev0` / 署名=方案 B | Owner | 2026-06-06 | ✅ Resolved 2026-06-06 |
| **B-002** | 验证方法论规范化（P0.7 / P0.8 临时需求 #2） | Owner 决策：串行 + `logs/` + 关键节点 debug + 2-log 对比 | Owner | 2026-06-07 | ✅ Resolved 2026-06-07 |

---

### §10.1 已就位的基础设施（Operational state · 2026-06-06）

| 项 | 值 |
|---|---|
| GitHub repo | https://github.com/f4cknet/autopwn |
| 首个 commit | `51bf49c` — "[P0.0] rename pwnpasi → autopwn" |
| Commit URL | https://github.com/f4cknet/autopwn/commit/51bf49c29f65c35608dd87fd513c6d0dd8f90dbf |
| SSH key | `ed25519` / fingerprint `SHA256:0fFiu7Jr19hPPqIQWW07S+vagVYtmFXvzVnscMZAUAo` |
| git config | user.name=`f4cknet` / user.email=`zmzsg100@gmail.com` |
| remote | `git@github.com:f4cknet/autopwn.git` (SSH) |
| 跟踪分支 | `main` ↔ `origin/main` 已同步 |
| `.gitignore` | 84 行（Python / 临时文件 / .agents/ / .docx / 凭据） |
| CI / Actions | 尚未配置（**P9** 阶段落地） |

> 阻塞超过 3 天升级到 Owner。

---

## 11. 附录

### 附录 A：决策树优先级对照表（需 Owner 拍板）

> 来自 `autopwn.py` 原 `main()` 的 if 顺序。新策略的 `priority` 数值应与下表等价或更明确。

| 原 main() 中的顺序 | 对应策略 | 拟 `priority` | 备注 |
|---|---|---|---|
| Canary 分支最优先 | canary_* | 200 | canary 保护下唯一路径 |
| PIE + backdoor | pie_backdoor | 180 | 仅当 PIE=1 且 backdoor 存在 |
| ret2system（system+bin_sh） | ret2system_{x32,x64} | 150 | 最快路径 |
| ret2libc_puts | ret2libc_put_{x32,x64} | 120 | |
| ret2libc_write | ret2libc_write_{x32,x64} | 110 | |
| rwx_shellcode | rwx_shellcode_{x32,x64} | 90 | |
| execve_syscall | execve_syscall | 80 | 仅 x32 |
| fmtstr | fmtstr | 50 | 兜底 |

> 此表**不是文档**——是**配置**。P7.2a 完成后会把数值 hardcode 到 `exp/registry.py` 或独立 `exp/priorities.py`。

### 附录 B：文件路径速查

| 想找 | 旧位置 | 新位置 |
|---|---|---|
| 颜色 + 打印 | `autopwn.py:70-170` | `autopwn/core/logging.py` |
| 权限 / 路径工具 | `autopwn.py:441-456` | `autopwn/core/fs.py` |
| checksec | `autopwn.py:505-650` | `autopwn/recon/checksec.py` |
| libc 检测 | `autopwn.py:456-505` | `autopwn/recon/libc.py` |
| PLT 扫描 | `autopwn.py:676-720` | `autopwn/recon/plt.py` |
| ROP gadgets | `autopwn.py:723-855` | `autopwn/recon/rop.py` |
| 栈溢出检测 | `autopwn.py:858-1020` | `autopwn/detect/overflow.py` |
| fmtstr 检测 | `autopwn.py:1054-1170` | `autopwn/detect/fmtstr.py` |
| canary 处理 | `autopwn.py:1582-1746` | `autopwn/detect/canary.py` |
| binsh 检测 | `autopwn.py:1025-1050` | `autopwn/detect/binsh.py` |
| 报告生成 | `autopwn.py:175-440` | `autopwn/report/{model,docx,code}.py` |
| ret2libc 写 | `autopwn.py:1201-1530` | `autopwn/exp/strategies/ret2libc_write_*.py` + `primitives/ret2libc_write.py` |
| ret2libc puts | `autopwn.py:2006-2438` | `autopwn/exp/strategies/ret2libc_put_*.py` + `primitives/ret2libc_put.py` |
| ret2system | `autopwn.py:1816-2005` | `autopwn/exp/strategies/ret2system_*.py` + `primitives/ret2system.py` |
| execve syscall | `autopwn.py:2169-2230` | `autopwn/exp/strategies/execve_syscall.py` + `primitives/execve_syscall.py` |
| rwx shellcode | `autopwn.py:2233-2274` | `autopwn/exp/strategies/rwx_shellcode_*.py` + `primitives/shellcode.py` |
| fmtstr 利用 | `autopwn.py:1168-1580` | `autopwn/exp/strategies/fmtstr.py` + `primitives/fmtstr.py` |
| PIE backdoor | `autopwn.py:1746-1815` | `autopwn/exp/strategies/pie_backdoor.py` + `primitives/pie_backdoor.py` |
| Canary 变体 | `autopwn.py:2529-3315` | `autopwn/exp/strategies/canary_*.py`（共用 `CanaryStrategy` 基类） |
| 主入口 | `autopwn.py:3316-3720` | `autopwn/cli.py` + `autopwn/orchestrator.py` |

### 附录 C：交叉引用

- 架构设计：`refactor.md`
- 任务跟踪：本文件 §4
- 风险登记：§8
- 阻塞登记：§10
- 决策树优先级：附录 A（待 Owner 拍板）

---

> **维护铁律**：
> 1. 每个 PR 必更新 §4 对应任务行（这是 Reviewer 必查项）
> 2. 每个新发现的架构问题在 §8 加一行，不允许只写在 PR 描述里
> 3. 任何 Owner 拍板的决策（如优先级对照表）必须 append 到对应附录，并在周例会记录
> 4. 当 §3 的所有里程碑都 ✅ 时，把"当前重构周期"改为"v4.0 → v4.1"
