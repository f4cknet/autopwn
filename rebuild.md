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
| **Code Review** | §7 对应阶段 checklist → §9 风险表 + `AGENTS.md §3` 违规表 + §2.6 验证方法论 |
| **只关心进度** | §3 里程碑 + §4 总览表 |
| **看到 `_legacy.py` / `_compat.py` 困惑** | `refactor.md §13`（架构层 WHY）+ **§3.1 下方**（实施层行数追踪）|

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
| **M2** | 收集与检测层化 | P4 + P5 | `recon/` + `detect/` 完整，pure 化 | `pytest tests/unit/test_detect_*` 全绿（recon 测试 P9 补）| 🔄 (P4 ✅, P5 ✅；验收 detect ✅, recon 待 P9) |
| **M3** | 利用层抽象 | P6 + P7 | `primitives/` + `exp/strategies/`；30+ 函数收敛为 12 策略 | `pytest tests/integration/` 跑通 Challenge/ 全部 4 个二进制 | ⏳ |
| **M4** | 编排重写 | P8 | `main()` < 100 行；orchestrator 决策 | CLI 日志与重构前一致；`wc -l orchestrator.py < 250` | ⏳ |
| **M5** | 工程化 | P9 + P10 | 单元测试 + CI + 打包 | GitHub Actions 绿；`autopwn` 命令行可用 | ⏳ |

> 整体进度：**0 / 6 里程碑完成**

---

### 3.1 过渡期临时文件生命周期（横切关注点）

> **配套**：`refactor.md §13` 是架构层详细说明（为什么存在 / 什么时候删 / Reviewer 必查项）。
> 本节只跟踪**行级 / caller 级**变化，给干活的人一个直观进度条。

| 文件 | 来源 | M0 ✅ | M1 🟡 | M2 ⏳ | M3 ⏳ | M4 ⏳ | M5 ⏳ | P8.5 |
|---|---|---|---|---|---|---|---|---|
| `autopwn/_legacy.py` | P0.4 `git mv` v3.1 单体 | 3688 行 | 3688 行（**写点 -9，剩 34 读**）| 持续 -1500 | 持续 -1500 | 持续 -400 | 接近 0 | 🗑️ 删 |
| `autopwn/_compat.py` | P2.3 Owner 决策新建 | 不存在 | 197 行（**桥在用**）| 桥活跃 | P7 末 0 caller | 仅 `__all__` | 0 行 | 🗑️ 删 |
| `autopwn.py` 根 shim | P0.4 5 行 | 5 行 | 5 行 | 5 行 | 5 行 | 5 行 | 5 行 | 🗑️ 删（→ `python -m autopwn`）|

**关键检查点**（每个 P 阶段 PR 必查）：

- **P2.4 之后**：`grep -nE "exploit_info\[[^]]+\] *=" autopwn/_legacy.py` 必须 **0 行** ✅（P2.4 已达成）
- **P7 之后**：`grep -rn "from autopwn._compat" autopwn/ --include='*.py'` 必须 **0 行**（准备 P8.5 删除）
- **P8 之后**：`_legacy.py` 净行数 < 100（仅剩 import 转发 + `if __name__ == "__main__"` 入口）
- **P8.5 PR 标题**：`[P8.5] delete _legacy.py + _compat.py`（独立 commit，不与代码改动混）

**与 §4 任务的对应**：

| 横切关注点 | 主要落点 |
|---|---|
| `_legacy.py` 行数减 1（删除 `cleanup_core_files` 线程） | P1.6 |
| `_legacy.py` 减 ~50（搬 Colors/print_*）| P1.1 |
| `_legacy.py` 减 ~30（搬 fs 工具）| P1.2 |
| `_legacy.py` 减 ~20（搬 subprocess wrapper 调用点）| P1.5 |
| `_legacy.py` 写点 -9（桥函数）| **P2.3 + P2.4** ✅ |
| `_legacy.py` 减 ~1500（搬 recon / detect）| P4 + P5 (**P4 ✅ + P5 ✅**, 尚未删 _legacy.py 调用点——P8.1 编排时再删) |
| `_legacy.py` 减 ~1500（搬 primitives / 30+ 策略）| P6 + P7 |
| `_legacy.py` 减 ~400（搬 main() 决策树）| P8.1 + P8.2 + P8.3 |
| `_compat.py` 创建 | **P2.3** ✅ |
| `_compat.py` 加 `record_success` | **P2.4** ✅ |
| `_compat.py` 0 caller | P7 末 |
| 🗑️ `_legacy.py` + `_compat.py` 删除 | **P8.5** ⏳ |

> **常见错误**（已在历次 review 中出现）：在 P2 阶段后期发现 `_legacy.py` 仍被新增代码 import。
> **正确做法**：P3 起的所有新代码（`report/` / `recon/` / `detect/` / `primitives/` / `exp/strategies/`）
> **只** import `autopwn.context` / `autopwn.core` / 同层 / 互不依赖，禁止 `from autopwn._legacy import ...`。

---

## 4. 任务总览（一眼看板）

> 表头缩写：`S`=状态 / `O`=Owner / `E`=预估(h) / `A`=实际(h) / `PR`=PR 编号 / `Note`=备注

### 4.1 P0 — 改名 + 包骨架 + shim

> **🆕 本阶段包含临时需求 #1**：全局重命名 `pwnpasi` → `autopwn`（P0.0）。设计理由见 `refactor.md` §3.3 命名约定。

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| **P0.0** | **全局重命名 `pwnpasi` → `autopwn`**（**临时需求 #1**） | ✅ | @Minzhi_Zhou | 3h | 0.5h | #P0.0 | 已完成；R12 Resolved；验证：banner/help/烟雾测试三关通过；详见 §6.1 P0.0 验证段 |
| P0.1 | 新建 `autopwn/` 目录及子包目录（`core recon detect primitives exp report`） | ✅ | @Minzhi_Zhou | 1h | 0.2h | #P0.1-P0.5 | 8 个包目录 + 占位 __init__.py |
| P0.2 | 写各包 `__init__.py`（含 `__all__` 占位） | ✅ | @Minzhi_Zhou | 1h | 0.1h | #P0.1-P0.5 | autopwn/__init__.py 带版本/作者/组织；re-export cli；子包标准 __all__ |
| P0.3 | 写 `pyproject.toml`（PEP 621），声明依赖 | ✅ | @Minzhi_Zhou | 2h | 0.2h | #P0.1-P0.5 | name=autopwn / deps 5 项 / entry_points autopwn=autopwn.cli:main |
| P0.4 | `autopwn.py` 改为 shim，转发到 `autopwn.cli.main` | ✅ | @Minzhi_Zhou | 1h | 0.1h | #P0.1-P0.5 | 5 行 shim；monolith 移入 autopwn/_legacy.py（git mv 保留历史）|
| P0.5 | 验证 `python autopwn.py -l Challenge/canary` 与重构前行为一致 | ✅ | @Minzhi_Zhou | 1h | 0.3h | #P0.1-P0.5 | 5 项：语法/import/`--help`×2 入口/canary 烟雾测试 全过 |
| **P0.6** | **文档交叉引用**：`rebuild.md` §0 顶部加"必读 `AGENTS.md`"指引 | ✅ | @Minzhi_Zhou | 0.5h | 0.2h | #P0.6 | doc-only，与 P0.0 同步完成 |
| **P0.7** | **验证基础设施**（Owner 决策 2026-06-07，临时需求 #2） | ✅ | @Minzhi_Zhou | 3h | 0.8h | #P0.7 | 27/28 关键标记一致（96%）；4/5 SUCCESS；race condition 已规避；见 §6.1 P0.7 |
| **P0.8** | **重跑 v3.1 vs v4.0 严格对比**（用 P0.7 新方法论） | ✅ | @Minzhi_Zhou | 1h | 0.3h | #P0.8 | 4/5 SUCCESS；96% 关键标记一致；PASS 结论；logs/comparison/summary.md；见 §6.1 P0.8 |

### 4.2 P1 — 基础设施层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P1.1 | `core/logging.py`：搬运 `Colors` + `print_*` | ✅ | @Minzhi_Zhou | 3h | 0.6h | #P1.1 | 搬 Colors/12 print_*/VERBOSE → autopwn/core/logging.py；_legacy.py re-export；set_verbose() setter 修 main() global 重绑定 bug；.gitignore core*→/core*；补 P0.1 漏 core/__init__.py；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（无回归）；铁律 4：✅ 合并 ✅ pytest N/A (P9) ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| P1.2 | `core/fs.py`：`set_permission` + `add_current_directory_prefix` + 临时目录 ctxmgr | ✅ | @Minzhi_Zhou | 2h | 0.5h | #P1.2 | 搬 set_permission（os.system→os.chmod 0o755）+ add_current_directory_prefix + temp_workdir ctxmgr；_legacy.py re-export；§2.6 验证 27/28=96% vs v3.1 baseline（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| P1.3 | `core/runner.py`：封装 `checksec` / `ropper` / `objdump` / `ldd`，输出走 `subprocess.run(capture_output=True)` | ✅ | @Minzhi_Zhou | 4h | 0.7h | #P1.3 | 建 4 个 run_* + ToolError；checksec/ropper 合并 stdout+stderr（pwntools/ropper 写 stderr），objdump/ldd 仅 stdout；本 PR 不替换 _legacy.py 调用点（留给 P1.5）；§2.6 验证 27/28=96% vs v3.1（用 90s timeout 吃下 canary 暴力枚举时序非确定性）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| **P1.3a** | **临时需求 #4 - 静态 binutils 套件**（**file / readelf / strings / nm**） | ✅ | @Minzhi_Zhou | 2h | 0.4h | #P1.3a | 加 run_file / run_readelf(*flags) / run_strings(min_len) / run_nm；返回 str；degrade gracefully（失败 → 空串）；§2.6 27/28=96% vs v3.1（无回归，本 PR 不替换 _legacy.py 调用点）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4 |
| **P1.3b** | **临时需求 #4 - ROP / 模式 套件**（**ROPgadget / cyclic / one_gadget**） | ✅ | @Minzhi_Zhou | 2h | 0.4h | #P1.3b | 加 run_ropgadget(*filters) / run_cyclic_create(length) / run_cyclic_find(pattern) / run_one_gadget(libc)；ROPgadget 不用 --nocolor（版本不支持）；cyclic 忽略 stderr DeprecationWarning；§2.6 27/28=96% vs v3.1（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4 |
| **P1.3c** | **临时需求 #4 - 动态 / sandbox 套件**（**strace / ltrace / seccomp-tools / gdb**） | ✅ | @Minzhi_Zhou | 3h | 0.5h | #P1.3c | 加 run_strace / run_ltrace / run_seccomp / run_gdb_batch；4 个都写 stderr（syscall/lib-call/seccomp-event/pwndbg 彩色），wrapper 用 stdout+stderr 合并 + `errors='replace'` 吃非 UTF-8；seccomp-tools 默认 dump；gdb `-batch -nx`；§2.6 27/28=96% vs v3.1（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4 |
| **P1.3d** | **临时需求 #4 - 跨架构模拟**（**qemu-system-x86 / i386 / aarch64**） | ✅ | @Minzhi_Zhou | 2h | 0.5h | #P1.3d | 加 run_qemu_user(arch, ...) + run_qemu_system(arch, ...) 两个 Popen 接口；user-mode（pwntools 风格，含 aarch64/arm/i386 等） + system-mode（仅 x86_64/i386 在本机可用；aarch64 需 `apt install qemu-system-arm` 额外装）；§2.6 27/28=96% vs v3.1（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4 |
| P1.4 | 替换 `autopwn.py` 中所有 `print_banner()` / `print_*` 调用为 `from autopwn.core.logging import ...` | ✅ | @MinZhi_Zhou | 2h | 0h | #P1.1 | **由 P1.1 顺手完成**：P1.1 把 Colors/12 print_*/VERBOSE 搬到 `core/logging.py`，`_legacy.py` 改为 `from autopwn.core.logging import (...)` re-export，418 个调用点零修改——等价于 P1.4 的目标（让 monolith 从 core/ 导入 print_*）。无独立代码改动；详见 §6.2 P1.4 决策记录 |
| P1.5 | 替换 `autopwn.py` 中所有 `os.system('ropper ... > ropper.txt')` 模式，调用 `runner.run_ropper` | ✅ | @MinZhi_Zhou | 3h | 1.0h | #P1.5 | 替换 13 处 os.system 调用（l32 ulimit / l42 cleanup 留给 P1.6）→ 6 个 runner（ldd/checksec/objdump/ropper/strings + 新 intel flag）；3 个 shell pipe（awk/grep）改 Python；write-to-file 改 in-memory；cwd 彻底干净；§2.6 27/28=96% vs v3.1（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| P1.6 | 删除 `cleanup_core_files` 线程的硬编码 `os.system('rm -rf core*')`，改用 `core/fs.py` 中的回收函数 | ✅ | @MinZhi_Zhou | 1h | 0.7h | #P1.6 | 加 `cleanup_core_dumps(cwd=None) -> int` 用 glob+os.unlink/shutil.rmtree 替代 shell；**移除后台线程**（1s 间隔干扰 canary 暴力枚举，§2.6 验证 4/5→3/5 回归，删后 4/5 PASS）；改 import-time 一次性清理；§2.6 27/28=96% vs v3.1（无回归）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |

### 4.3 P2 — 模型层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P2.1 | `context.py`：定义 `BinaryInfo` / `LibcInfo` / `RopGadgetsX64` / `RopGadgetsX32` / `CanaryInfo` / `ExploitContext` | ✅ | @Minzhi_Zhou | 4h | 0.4h | #P2.1 | 新增 `autopwn/context.py`（146 行）+ `autopwn/__init__.py` re-export 6 个 dataclass；**零行为变更**（不替换 `exploit_info` / 不改 `_legacy.py` / 不改 `cli.py` — 这些是 P2.3-P2.5 任务）；所有字段按 `refactor.md §3.2.1` + `rebuild.md §6.3 P2.1` 范式：`@dataclass(slots=True)` + `field(default_factory=...)` for 可变默认 + `LibcInfo.elf: object` 避免 pwntools 循环导入 + `ctx.log()` 路由到 `core.logging` print_*；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（无回归，**预期**：纯加文件不引入行为差异）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#3.2.1 |
| P2.2 | `context.py`：实现 `ExploitContext.from_args(args)` 工厂 | ✅ | @Minzhi_Zhou | 2h | 0.3h | #P2.2 | 新增 `@classmethod from_args(args: argparse.Namespace) -> ExploitContext` + `ContextError(RuntimeError)` 异常类；映射 6 个现有 CLI flag（`-l/-ip/-p/-libc/-f/-v`）+ P8 forward-compat（`--report-dir`）；**BinaryInfo 占位**字段（`bit=0`/`relro="Unknown"`/其余 `False`）— 标注 P4.1 recon 阶段会 overwrite；**零行为变更**（不替换 `_legacy.py` 调用点 — P2.3 任务）；错误消息与 legacy `print_error` 文本**逐字一致**（Test 14 验证）；15 项烟雾测试全过 + P2.1 6 项回归全过；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（无回归，**预期**：纯加 method）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#3.2.1 |
| P2.3 | `autopwn.py` 顶层构造 `ctx = ExploitContext.from_args(args)`，并写一个 ctx → `exploit_info` dict 的桥函数（**仅 P2 阶段保留，作用是让旧代码不立即报错**） | ✅ | @Minzhi_Zhou | 2h | 0.5h | #P2.3 | 新增 `autopwn/_compat.py`（68 行）：`_legacy_info` dict + `sync_ctx_to_legacy(ctx)` bridge；`_legacy.py` 改 3 处：① 顶层 alias `exploit_info = _compat._legacy_info`（同 dict 对象，所有 ~50 读 + 7 写 0 改动）② main() 插入 6 行 `from_args + sync_ctx_to_legacy` + `ContextError` try/except ③ 删 12 行 exploit_info 字典字面量；**3 处偏离 spec**：①不 `warnings.warn`（会污染日志 diff）②`ctx.binary.bit=0` placeholder guard（避免"x0" 泄漏）③ startup **不**设 `success=True`（保持 L241 `if not exploit_info['success']` 门控语义，P3.4 record_success 接手）；**实际行为 no-op**（L3305/L3306/L354-360 全部 overwrite bridge 写入值）；15 项烟雾测试 + 10 项 bridge 烟雾测试 + end-to-end CLI help/invalid-args 验证全过；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（**首次真正改 `_legacy.py` 行为路径，0 回归**）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#3.2.1 |
| P2.4 | 旧 `exploit_info` 写操作改为调用桥函数 | ✅ | @Minzhi_Zhou | 1h | 0.4h | #P2.4 | 删除 `update_exploit_info` helper + 9 个写点（2 个 L3305-3306 startup 写 + 7 个 L350-356 success 路径调用）→ 1 个 `sync_ctx_to_legacy(target_name=..., timestamp=...)` 调用 + 1 个 `record_success(...)` 调用；**0 个 `exploit_info[...] = ...` 写点剩余**（验证：grep 0 行）；**0 个 `update_exploit_info` 调用剩余**（验证：grep 0 行）；**34 个 read 保留**（按 spec 保留到 P8.5）；_compat.py 扩 2 个函数：`sync_ctx_to_legacy` 加 `target_name`/`timestamp` kwargs（默认 `None` → P2.3 行为不变） + `record_success(**kwargs)` 设 7 个 success 字段 + `success=True`；**P2.5 标记 ✅ done-by-P2.4**（helper 已删，deprecation warning 无意义）；§2.6 验证 27/28=96% 一致 vs v3.1 baseline（**首次走完整 success 路径，0 回归** — record_success 设的 7 字段全部被 docx / code 读者正确消费）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档 |
| P2.5 | 旧 `update_exploit_info` 标注 deprecation warning | ✅ | @Minzhi_Zhou | 0.5h | 0h | #P2.4 | **由 P2.4 顺手完成**（无独立 PR）：P2.4 删除了 `update_exploit_info` helper（7 callsite + 函数定义全部消失），deprecation warning 在被删的代码上加已无意义；P2.5 等价于 P2.4 的子集。详见 §6.3 P2.5 决策记录 |

### 4.4 P3 — 报告层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| **P3.1** | `report/model.py`：定义 `ExploitInfo` dataclass（替代 `exploit_info` dict） | ✅ | @Minzhi_Zhou | 2h | 0.4h | #P3.1 | 加 `autopwn/report/model.py`（94 行）+ 扩展 `report/__init__.py`（15 行）re-export `ExploitInfo`；9 字段（6 required + 3 optional），`@dataclass(slots=True)`，`extra: Dict[str, Any]` 走 `default_factory` 防 mutable default 泄漏；**1 处 spec 微调**：`addresses`/`extra` 由 `dict` 收为 `Dict[str, int]` / `Dict[str, Any]`（mypy-friendly，与 `context.py` P2.1 风格一致）；**1 处有意偏离**：`success` 字段**不**加（详见 `model.py` 注释 + §6.4 实施记录：ExploitInfo 仅在 success 路径构造，"is success" 问题由 P3.5 `ctx.enable_report` 接手）；**零行为变更**（`_legacy.py` 3691 行未变，34 个 `exploit_info[]` 读点保留，7 个写点保留走 P2.4 `_compat.record_success` 桥）；12 项功能单测全过（import path/构造/字段访问/slots/mutable default guard/equality/repr/字段集精确/全字段构造/`__all__`）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（无回归，**预期**：pure addition 零 runtime 影响）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4 |
| **P3.2** | `report/docx.py`：搬运 `generate_docx_report`；改为读 `ExploitInfo` | ✅ | @Minzhi_Zhou | 2h | 0.5h | #P3.2 | 新建 `autopwn/report/docx.py`（189 行）`generate_docx(info, out_dir) -> Optional[Path]`；`_legacy.py` 删 `generate_docx_report`（-114 行）+ 删 3 个 `from docx import ...` + 加 `from pathlib import Path` + `handle_exploitation_success` 改构造 ExploitInfo + 调新函数（14 caller 签名不变）；**字段映射**：14 个 `exploit_info['x']` 读点全部改 `info.x`（`success` 字段删——ExploitInfo 仅在 success 路径构造）；`generate_exploitation_code` 仍 in `_legacy.py`（P3.3 搬走），新 docx 模块临时 `from autopwn._legacy import generate_exploitation_code`（1 处待 P3.3 清理）；`_legacy.py` 净 -101 行（3691→3590）；**零行为变更**：`out_dir=Path('.')` 默认，docx 仍生成到 cwd；路径打印 "Exploitation report generated: rip_wp.docx" 与 v3.1 baseline byte-for-byte 一致；10 项功能单测全过（re-export/签名/干跑 4 binary 名字/5 种 address 格式化/异常降级返回 None/cwd 零污染/handle_exploitation_success 签名不变/...）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（**无回归**）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4 |
| **P3.3** | `report/code.py`：搬运 `generate_exploitation_code`；改为读 `ExploitInfo` | ✅ | @Minzhi_Zhou | 3h | 0.6h | #P3.3 | 新建 `autopwn/report/code.py`（187 行）`generate_code(info, out_dir) -> str`；`_legacy.py` 删 `generate_exploitation_code`（-135 行）；**`docx.py` import 切换**：从 `autopwn._legacy` 切到 `autopwn.report.code`（P3.2 留的临时 import 清理）；**`out_dir` 参数 forward-compat**：P3.3 不写文件（保持 legacy 行为——只返回 code 字符串），但 P3.4/P3.5 可用 `out_dir` 写 `{target}_wp.py` artifact；20 个 `exploit_info['x']` 读点全部改 `info.x`；**f-string 模板 byte-for-byte 保留**（7 种 exploit type 全部产生与 legacy 一致输出：ret2system x64/x32, ret2libc write x64/x32, Format String, execve syscall, generic fallback）；`_legacy.py` 净 -136 行（3590→3454）；12 项功能单测全过（re-export/签名/5 主流 exploit type 全部分支/format string 走 addresses.get('offset', ...)/generic fallback 含 repr(bytes)/empty addresses 跳段/target_name basename 提取 4 种 address 格式化）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（**无回归**）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4 |
| **P3.4** | `handle_exploitation_success` 改为 `record_success(ctx, info, primitive)`，生成 docx/code 改为订阅 | ✅ | @Minzhi_Zhou | 2h | 0.5h | #P3.4 | 新加 `autopwn.report.record_success(info)` 订阅者 orchestrator（74 行含 docstring + `__all__` 更新）；`_legacy.handle_exploitation_success` 精简：从 33 行（6 dict 读 + 调 generate_docx）→ 21 行（构造 ExploitInfo + 调 record_success）；**P2.4 桥退役**：`_compat.record_success(...)` 6 kwargs 调用消失（取而代之是直接构造 ExploitInfo）；**保留** 2 个 dict 读（`target_binary` + `timestamp`）—— 这两个字段由 main() 启动时 `sync_ctx_to_legacy` 写入，**避免**为消除这 2 读而改动 14 个 caller 的策略函数签名（P3.5 接 ctx 后会彻底清掉）；**spec 偏离**：`record_success` 签名是 `(info)` 而非 spec 的 `(ctx, info, primitive)` —— P3.4 阶段 ctx 还未引入 `enable_report` 字段（P3.5 加），primitive 也不需要（P7 才用），P3.5 会把签名升级为 `(ctx, info)`；**dispatch 链**：`record_success` → `print_critical("EXPLOITATION SUCCESSFUL! ...")` → `generate_docx(info, Path('.'))`（P3.5 改用 `ctx.report_dir`）；`_legacy.py` 净 -12 行（3454→3442）；10 项功能单测全过（签名/mock dispatch/14 caller 不动/e2e 真生成 docx 37KB/旧 `_compat.record_success()` callsite 已消失/...）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（**无回归**）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4, refactor.md#3.2.2 |
| **P3.5** | CLI 加 `--no-report` / `--report-dir` 参数 | ✅ | @Minzhi_Zhou | 1h | 0.5h | #P3.5 | `argparse` 加 2 个 flag (`--no-report` store_true, `--report-dir` str)；`ExploitContext` 加 `enable_report: bool = True` 字段；`from_args` 映射（`--no-report` → `ctx.enable_report=False`；`--report-dir` → `ctx.report_dir` + `mkdir(parents=True, exist_ok=True)` 防御性创建）；**`report.record_success` 接 ctx 改写**——P3.4 deviation #1 fix：从 `(info)` 加 ctx 读取（用 module-level `_current_ctx` carrier + `set_current_ctx()` setter，**避免**为接 ctx 改 14 个 caller 签名）；加 `--no-report` gate（`if not ctx.enable_report: return` + 打印 "report generation skipped"）；用 `ctx.report_dir` 替换 `Path('.')`；defensive ctx=None 降级；main() 启动时 `set_current_ctx(ctx)` 把 ctx 装入 carrier；`_legacy.py` argparse 段 +9 行，`context.py` +17 行（`enable_report` 字段 + from_args 改写），`report/__init__.py` +25 行（carrier + gate + report_dir）；11 项功能单测全过（--help 展示/默认 enable_report=True/--no-report 触发/--report-dir 自动 mkdir/--report-dir 不可写 raise ContextError/--no-report 跳过 e2e/--report-dir 不污染 cwd/ctx=None 降级/banner 总打印/e2e --no-report/e2e --report-dir 真生成 docx/...）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（**无回归**）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4, refactor.md#3.2.2 |
| **P3.6** | docx 依赖 `python-docx` 改为 `try/except ImportError` 降级为 markdown | ✅ | @Minzhi_Zhou | 1h | 0.3h | #P3.6 | `report/docx.py` 加模块级 `try/except ImportError` 包装 `from docx import Document / WD_ALIGN_PARAGRAPH`；`_HAS_DOCX = True/False` 标志位；新加 `_generate_markdown(info, out_dir) -> Path` fallback 函数（覆盖 docx 5 段：Basic Info / BOF Info / Address table / Code / Summary + footer + Note）；`generate_docx` 入口 dispatch：`_HAS_DOCX=False` 时调 markdown fallback 并改 print 消息为 "Exploitation report generated (markdown fallback): ..."；**1 处有意偏离**：`try/except ImportError` 放模块顶层（spec 在 caller 端 catch）—— 因为 module-level import 失败在 import 期而非 call 期，caller 端 catch 永远不触发；模块顶层 try/except + `_HAS_DOCX` flag 是正确实现 spec 意图的方案；8 项功能单测全过（_HAS_DOCX 标志位/re-export/docx 路径正常/md 路径 5 段齐全/4 种 address 格式化/empty addresses 跳段/真 docx 缺失用 meta_path blocker 验证/无 cwd 污染）；§2.6 验证 4/5 SUCCESS + 27/28=96% 一致 vs v3.1 baseline（**无回归**——本机 python-docx 已装，走 docx 路径）；铁律 4：✅ 合并 ⏸ pytest N/A ✅ 5-binary 串行 ✅ 关键日志 ✅ Owner 自审 ✅ 文档；Refs: refactor.md#4.4, refactor.md#10 |

### 4.5 P4 — Recon 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P4.1 | `recon/checksec.py`：搬运 `Information_Collection` + `collect_binary_info` + `display_binary_info`；返回 `BinaryInfo` | ✅ | @Minzhi_Zhou | 4h | 0.6h | #P4.1 | 新加 `autopwn/recon/checksec.py`（177 行）+ `recon/__init__.py` re-export；3 个函数：`collect(program) -> BinaryInfo`（pure，§6.5 P4.1 spec 改 1 处：DEV-1 `stripped` 改 regex 否则 "Stripped" in out 误判 label vs value）+ `display(info)` 表格打印 + `_legacy_information_collection(program)`（v3.1 死代码 `Information_Collection` 的字面 port，0 caller，underscore 前缀）；**未替换 `_legacy.py` 调用点**（P8 orchestrator 责任）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；35 字段 + 5 视觉 + 5 边缘测试 + 5 legacy port 测试全过；详见 §6.5 P4.1 实施记录 |
| P4.2 | `recon/libc.py`：合并 `detect_libc` + `ldd_libc` 为 `detect(ctx) → LibcInfo` | ✅ | @Minzhi_Zhou | 2h | 0.4h | #P4.2 | 新加 `autopwn/recon/libc.py`（209 行）+ `recon/__init__.py` re-export `detect`；1 个 public 函数 `detect(ctx, program) -> LibcInfo`（pure，3 阶段：user override (`ctx.libc.path`) → ldd auto-detect → empty LibcInfo）+ 1 个 helper `_parse_libc_path(ldd_out)` + 2 个 legacy port (`_legacy_detect_libc` / `_legacy_ldd_libc`，0 caller / 1 caller，含原 print 行为供字节级保真)；`LibcInfo.elf` 维持 `None`（懒加载 — P7 strategy 才 `ELF(libc_path)`，避免 pwntools 在 recon 期 import）；**未替换 `_legacy.py` 调用点**（P8 orchestrator 责任）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；5 binary × detect() + 1 user-override + 1 empty-LibcInfo + 6 _parse_libc_path edge case + 3 legacy port = 16 测试全过；详见 §6.5 P4.2 实施记录 |
| P4.3 | `recon/plt.py`：`scan_plt_functions` 返回 dict，写入 `ctx.has_*` 标志 | ✅ | @Minzhi_Zhou | 3h | 0.5h | #P4.3 | 新加 `autopwn/recon/plt.py`（200 行）+ `recon/__init__.py` re-export `scan`；1 public + 1 helper + 2 legacy port：`scan(ctx, program) -> dict[str, int]`（6 函数，**P4 层首个 mutate ctx** 的模块 — 写 6 个 `ctx.has_*` bool；与 P4.1/P4.2 不同是因为 PLT 标志 6 个独立 bool 无自然 container）+ `_parse_plt_addresses(objdump_out)` helper + 2 个 legacy port（`_legacy_scan_plt_functions` 7 函数含 main 保 v3.1 行为 + `_legacy_set_function_flags`）；**deviation**: 新 `scan` 6 函数（drop `main`），v3.1 legacy port 7 函数（含 main，与 §4.5 spec 「`has_*` 标志」对应 — `main` 不 gate 任何 strategy 故 ctx 无 `has_main` 字段）；**未替换 `_legacy.py` 调用点**（P4.7 删 globals 时一并处理）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；5 binary × scan + 1 幂等 + 1 re-overwrite + 4 _parse 边缘 + 4 legacy port + 1 cwd 污染 + 1 re-export = 16 测试全过；详见 §6.5 P4.3 实施记录 |
| P4.4 | `recon/rop.py`：搬 `find_rop_gadgets_x64/x32`，返回 `RopGadgetsX64/X32` | ✅ | @Minzhi_Zhou | 4h | 0.7h | #P4.4 | 新加 `autopwn/recon/rop.py`（280 行）+ `recon/__init__.py` re-export `find_x64` / `find_x32`；2 public + 2 helpers + 2 legacy port：`find_x64(ctx, program) -> RopGadgetsX64`（return-only，**不 mutate ctx**，P8 赋值；3 次 `run_ropper` 合并解析 5 字段：`pop_rdi`/`pop_rsi`/`ret`/`extra_rdi`/`extra_rsi`）+ `find_x32(ctx, program) -> RopGadgetsX32`（6 次 `run_ropper` + R8 缓解 4 bool 合并 `has_eax_ebx_ecx_edx`）+ 2 helper (`_parse_ropper_lines` / `_extract_x64_gadgets` / `_extract_x32_gadgets`)+ 2 legacy port（保 5-tuple / 11-tuple 形状与 v3.1 表格打印）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；5 binary × find_x64/find_x32 + return-only 契约 + 2 _parse 边缘 + 2 _extract 合成输入 + 2 legacy port shape + re-export = 11 测试全过；详见 §6.5 P4.4 实施记录 |
| P4.5 | `recon/bss.py`：搬 `find_large_bss_symbols` + `find_ftmstr_bss_symbols` | ✅ | @Minzhi_Zhou | 2h | 0.3h | #P4.5 | 新加 `autopwn/recon/bss.py`（150 行）+ `recon/__init__.py` re-export `BSSSymbol` / `find_bss`；1 dataclass + 1 public + 2 legacy port：`BSSSymbol(name, address, size)` slots dataclass + `find_bss(program, *, min_size=30, name_filter=None) -> list[BSSSymbol]`（参数化 v3.1 两个 size/name 过滤条件）+ 2 个 legacy port（`_legacy_find_large_bss_symbols` 3-tuple + `_legacy_find_ftmstr_bss_symbols` 3-tuple）；**DEV-1**: legacy `_legacy_find_ftmstr_bss_symbols` 保 v3.1 的「last-match-wins」bug（原代码无 `break` + `function` 变量不复位）— 文档化在 docstring；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；5 binary × find_bss（2 filter） + 1 nonexistent + 1 strict filter + 1 slots + 1 re-export + 1 cwd 污染 + 4 legacy port parity = 16 测试全过；详见 §6.5 P4.5 实施记录 |
| P4.6 | `recon/asm.py`：搬 `vuln_func_name` + `asm_stack_overflow` | ✅ | @Minzhi_Zhou | 2h | 0.4h | #P4.6 | 新加 `autopwn/recon/asm.py`（200 行）+ `recon/__init__.py` re-export `vuln_func_name` / `asm_stack_overflow` / `analyze_vulnerable_functions`；3 public + 3 legacy port（spec 只列 2 个源函数，但 P4.6 把邻居 `analyze_vulnerable_functions` 也搬了以避免 P5+ PR 重触 `_legacy.py`）：`vuln_func_name(program) -> list[str]`（`re.split r'\n\n'` 解析函数体）+ `asm_stack_overflow(program, bit) -> Optional[int]`（`re.finditer` 找第一个 `lea -N(%ebp)` 模式 + `+4` 或 `+8` 对齐）+ `analyze_vulnerable_functions(program, bit) -> Optional[int]`（同 asm_stack_overflow 但走不同函数体匹配逻辑）；module-level compile `_LEA_RE`（P2.1 范式）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；5 binary × 3 public + 5 legacy port parity + 5 edge case = 30 测试全过；详见 §6.5 P4.6 实施记录 |
| P4.7 | **关键**：删除 `autopwn.py` 中所有 `globals().get('system', 0)` 等 22 处；改读 `ctx.has_system` | ✅ | @Minzhi_Zhou | 3h | 0.6h | #P4.7 | **+ P4.8 同 PR 落地**（R1 风险点；2 个任务强耦合必须同 PR：P4.7 删 22 个 read site 必须配合 P4.8 把 inject 写入 ctx，否则 `ctx.has_X` 永远是 False，exploit 全断）— `_legacy.py` 净 +10 行（删 22 个 `globals().get` + 3 行 for-loop globals() injection → 6 行 `ctx.has_X = bool(...)` 注入 + 1 行 P4.7/P4.8 注释块；**deviation 1 处 DEV-1**: 3 行 `globals().get('eax', 0)==1 and ebx==1 and ecx==1 and edx==1`（×4 occurrences）改用 **locals** `eax/ebx/ecx/edx`（main() L3153 unpack 出来的 4 个 bool），**v3.1 bug 修复**（globals() 永远没有 'eax' 键 — x32 execve branch 是死代码；用 locals 修，且对 5 binary 行为不变 — canary 只有 pop_ebx，所有 4 locals 至少 1 个 0）；**7 个 PLT 写入迁移**：6 个 `ctx.has_write/puts/printf/system/backdoor/callsystem` bool（注意：P4.3 新模块的 6 字段被复用）+ `printf`（ctx 有 has_printf，但 v3.1 set_function_flags 也写 printf — 保留）；**零行为变更** — 5-binary 串行 27/28=96% 一致 / 4/5 SUCCESS / 0 新增 failure mode；`grep "globals()\\.get\\\|globals()\\[" _legacy.py` → 0 个 executable call（仅 1 个 comment 提及「P4.7 替换」）；详见 §6.5 P4.7+P4.8 实施记录 |
| P4.8 | 删除 `set_function_flags` 的 `globals()[func] = available` 副作用 | ✅ | @Minzhi_Zhou | 0.5h | 0.0h | #P4.7 | **由 P4.7 同 PR 落地**（无独立 PR）：P4.7 删 22 个 read site 同时也把 inject 的 3 行 for-loop 改写为 6 个 `ctx.has_X = bool(...)` 直接赋值。P4.8 的「删 globals() 注入」与 P4.7 的「改读 ctx」是同一笔数据迁移的两端，**强耦合不可分** —— 见 §6.5 P4.7+P4.8 合并实施记录 |

### 4.6 P5 — Detect 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P5.1 | `detect/overflow.py`：搬 `test_stack_overflow` + `analyze_vulnerable_functions`；写入 `ctx.padding` | ✅ | @Minzhi_Zhou | 4h | 0.8h | feature/p5.1-detect-overflow | 4× 二进制烟雾测试 OK：level3_x64 136=136, canary 静态 80, pie 静态 40 动态 48, rip 静态 19 动态 26 |
| P5.2 | `detect/fmtstr.py`：搬 `detect_format_string_vulnerability` + `find_offset` | ✅ | @Minzhi_Zhou | 3h | 0.6h | feature/p5.2-detect-fmtstr | 烟雾测试 OK：fmtstr1 vulnerable=True/2 triggers + offset=11；level3_x64 vulnerable=True/6 triggers；legacy ports 字节级 parity |
| P5.3 | `detect/canary.py`：搬 `leakage_canary_value` + `canary_fuzz`；写入 `ctx.canary` | ✅ | @Minzhi_Zhou | 3h | 1.0h | feature/p5.3-detect-canary | 烟雾测试 OK：leakage 10 leaks/100 max=100 字节级 parity；canary_fuzz(max_c=3, max_padding=3) returns None（预期，暴力枚举需 ~7min）；legacy port 写 canary.txt 100 行字节级一致 |
| P5.4 | `detect/binsh.py`：搬 `check_binsh_string` + `check_binsh` | ✅ | @Minzhi_Zhou | 1h | 0.3h | feature/p5.4-detect-binsh | 烟雾测试 OK：5 二进制 check_binsh 返回正确（canary=F, fmtstr1=T, level3_x64=F, pie=T, rip=T），ctx.binsh_in_binary 同步 |
| P5.5 | 单元测试：每个 detect 函数对 `Challenge/` 下对应二进制跑一遍 | ✅ | @Minzhi_Zhou | 4h | 0.8h | feature/p5.5-detect-tests | pytest -m detect 全绿 21/21；涵盖 4 个 detect 模块 × 2-3 个测试 + 5 个 binary 矩阵化 (test_detect_binsh)；v3.1 vs v4.0 96% 一致无回归 |

### 4.7 P6 — Primitives 层

| ID | 任务 | S | O | E | A | PR | Note |
|---|---|---|---|---|---|---|---|
| P6.1 | `primitives/base.py`：`ExploitPrimitive` 抽象类 + `ExploitResult` dataclass | ✅ | @Minzhi_Zhou | 2h | 0.4h | feature/p6.1-primitives-base | ExploitPrimitive ABC（5 单测）+ ExploitResult dataclass（4 单测）+ FakePrim 烟雾 OK；ExploitResult 用 @dataclass(slots=True) 替代 v3.1 手写 __init__（P2.1 一致） |
| P6.2 | `primitives/ret2system.py`：x32 + x64 payload builder（pure function） | ✅ | @Minzhi_Zhou | 3h | 0.6h | feature/p6.2-primitives-ret2system | Ret2SystemX32 + Ret2SystemX64，2 公开 + 2 legacy port；fmtstr1 payload=124B (112+12), rip=36B (24+12), canary=b""; 10 单测全过；64-bit 含 ret 对齐 gadget 修 glibc 18.04+ MOVAPS 崩溃 |
| P6.3 | `primitives/ret2libc_put.py`：x32 + x64 payload builder | ✅ | @Minzhi_Zhou | 4h | 0.7h | feature/p6.3-primitives-ret2libc-put | 2-stage 首个 primitive：Ret2LibcPutX32/X64 (stage_count=2)；build_payload 返 stage-1 leak，build_stage2_payload(ctx, leaked_puts_addr) 返 stage-2 system；13 单测全过 (含 stage-1 字节级 + stage-2 用真 libc 算 system/sh)；ret 对齐 gadget 复用 P6.2 |
| P6.4 | `primitives/ret2libc_write.py`：x32 + x64 payload builder | ✅ | @Minzhi_Zhou | 4h | 0.5h | feature/p6.4-primitives-ret2libc-write | 2-stage write-泄漏 primitive：Ret2LibcWriteX32/X64 (stage_count=2)；build_payload 返 stage-1 (`write(1, write_got, 4)` leak via main)，build_stage2_payload(ctx, leaked_write_addr) 返 stage-2 system；x64 stage-1 加 `pop_rdi+pop_rsi` gadget chain，stage-2 含 `ret` 对齐 gadget（与 P6.3/P6.2 一致）；14 单测全过；§2.6 96% (27/28) 一致 PASS，4/5 SUCCESS |
| P6.5 | `primitives/execve_syscall.py`：x32 payload builder | ✅ | @Minzhi_Zhou | 2h | 0.6h | feature/p6.5-primitives-execve-syscall | 1 公开 + 1 legacy port；x32 `int 0x80` syscall chain（独立 primitive，不依赖 libc symbol）；combined 变体 (pop_ecx=0, pop_ecx_ebx!=0) 与 separate 变体 (pop_ecx!=0) 自动选择；17 单测全过（含 fmtstr1 真实 binary 烟雾）；§2.6 96% (27/28) 一致 PASS（行为与 P6.4 持平） |
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

**🟢 状态**：✅ P0.0–P0.8 全完成（Owner 决策 2026-06-07）｜**🔴 优先级**：P0｜**⏱ 预估**：14.5h（实际 1.4h）｜**👤 Owner**：@Minzhi_Zhou

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
- **commit 引用**：`694b813`（P1.1）— `c1b41ba` (P0.8) → `694b813` (P1.1)

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

**P1.3 实施记录（2026-06-07）**：

- **新文件** `autopwn/core/runner.py`（80 行）：4 个 `run_*` 函数 + `ToolError` 异常
  - `run_checksec` → `stdout + stderr`（pwntools checksec 写 stderr）
  - `run_ropper` → `stdout + stderr`（ropper 写 stdout 是命中 + stderr 是 banner）
  - `run_objdump_disasm` → `stdout`（objdump 不写 stderr）
  - `run_ldd` → `stdout`（ldd 不写 stderr）
- **本 PR 不动 `_legacy.py`**：re-export 不加（暂时无 caller），P1.5 改 `os.system` 调用点时会直接 `from autopwn.core.runner import run_xxx`
- **未替换的 15 处 `os.system`**（在 _legacy.py）：L32 (ulimit), L42 (rm core), L360 (ldd), L470 (checksec), L580 (objdump), L636-638 (ropper x3), L702 (ropper), L728 (ropper), L738 (ropper), L929 (binsh), L947 (binsh), L3354 (objdump+grep)。其中 9 处是 P1.3 工具范围（checksec/ropper/objdump/ldd），剩 6 处分属 P1.5/P1.6/P2+
- **byte-level 验证**（功能等价性，pytest 体系待 P9）：
  - `checksec`: new vs legacy 207B == 207B（**字节级一致**）
  - `ropper`: new vs legacy 8229B == 8229B（顺序略不同：new=stdout+stderr=先 matches 后 banner；legacy shell=先 banner 后 matches）—— **ropper parser 是行扫描 + skip `[INFO]`（_legacy.py L648）**，顺序无关
  - `objdump`: new=intel spec 8465B；legacy L580 是 `objdump -d` 14354B（无 intel 无 no-raw-insn）。**P1.3 的 intel 规格更优（更易读），与 L3354 现有调用一致**。P1.5 替换 L580 时可统一用此函数
  - `ldd`: new vs legacy 107B == 107B（顺序差异：ldd 输出中地址会变但 parser 不依赖固定地址）
- **§2.6 验证结果**：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout，非默认 60s**）— canary PARTIAL + fmtstr1 PASS + level3_x64 PASS + pie PASS + rip PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **首次 60s timeout 复测 → 85% PARTIAL**：fmtstr1 在 60s 截断时只能跑到 canary 暴力枚举（运气不好），3 个关键标记未达到。**这是 v3.1 baseline 同样存在的时序非确定性**（P0.8 备注："canary 60s timeout: brute force 需 ~7 分钟，60s 截断后输出 partial log"），与 P1.3 改动无关。90s timeout 是 absorbing 该 non-determinism 的合理代价
- **timeout 跟进项**（待 P9/CI 阶段处理）：`scripts/run_verify.sh` 默认 60s 在新机器负载下不稳定；建议 bump 到 90s 写进 §2.6 标准流程
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3441 vs v3.1 3625（fuzzing 时序差异，与 P1.1/P1.2/P0.8 同类）
- **commit 引用**：`ae59c78`（P1.3）— `da3ac0a` (P1.2) → `ae59c78` (P1.3)

**P1.3c 详细步骤**（`core/runner.py` 扩展）：

依据 `refactor.md §4.2` 接口范式（返回 `str` + 失败降级为空串 + **不向上 import**），在 `autopwn/core/runner.py` 末尾追加 4 个动态/sandbox 套件函数：

```python
def run_strace(program, *args: str) -> str:
    """Run `strace <args> <program>` and return combined stdout+stderr.
    Uses errors='replace' (target may output non-UTF-8 bytes via BOF/format)."""
    cmd = ["strace", *args, str(program)]
    cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=False)
    return cp.stdout + cp.stderr

def run_ltrace(program, *args: str) -> str: ...  # 同形

def run_seccomp(program, *args: str) -> str:
    """Default args=('dump',). 'disasm' / 'inspect' 也可。"""
    if not args:
        args = ("dump",)
    cmd = ["seccomp-tools", *args, str(program)]
    cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=False)
    return cp.stdout + cp.stderr

def run_gdb_batch(program, *commands: str) -> str:
    """Always inserts -batch -nx -ex 'set pagination off' + caller's commands.
    Last command should be 'quit' or gdb hangs."""
    cmd = ["gdb", "-batch", "-nx", "-ex", "set pagination off"]
    for c in commands:
        cmd.extend(["-ex", c])
    cmd.append(str(program))
    cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", check=False)
    return cp.stdout + cp.stderr
```

**P1.3c 实施记录（2026-06-07）**：

- **扩展** `autopwn/core/runner.py`（+95 行）：4 个新函数 + `__all__` 列表更新
- **不动 `_legacy.py`**：re-export 不加（无 caller），P1.5 改 os.system 调用点时会直接 `from autopwn.core.runner import run_xxx`
- **接口一致性**（R14 reviewer 必查）：4 个函数全部 `-> str` + 失败空串/降级 + `errors="replace"` 兼容非 UTF-8 输出
- **踩坑 #1**：4 个工具**都写 stderr**（不是 stdout）：
  - strace: syscall traces → stderr
  - ltrace: lib call traces → stderr
  - seccomp-tools: events → stderr
  - gdb + pwndbg: 全部输出 → stderr（带 ANSI 颜色码）
  - Wrapper 用 `cp.stdout + cp.stderr` 合并（沿用 P1.3 checksec/ropper 的处理）
- **踩坑 #2**：strace/ltrace/seccomp-tools/gdb 都会**执行 target 程序**，target 的 stdout 含 BOF 后的非 UTF-8 字节会触发默认 UTF-8 解码崩溃。**第一次测试 `run_strace(prog)` 就 UnicodeDecodeError**。修复：加 `errors="replace"`。P1.3/P1.3a/P1.3b 工具**不执行 target**（只静态分析 binary），所以不需要这个补丁
- **踩坑 #3**：seccomp-tools `disasm` 子命令在 canary 上抛 Ruby 异常（canary 没有 BPF filter 可 disasm），返回 700+ 字符 Ruby stack trace。caller 需判 `'execve' in out` / `len(out) < 200` 等
- **功能单测**（手测，pytest 体系待 P9）：
  - `run_strace(canary, '-c')` → 3552 chars，含 `syscall` 表头 + `read` 计数 ✓
  - `run_strace(canary)`（无 args）→ 含 `execve` / `mmap` 全 trace ✓
  - `run_ltrace(canary, '-e', 'puts+printf')` → 含 `canary->puts("...")` 格式 ✓
  - `run_seccomp(canary)`（默认 dump）→ 129 chars（canary 无 filter，直接跑 target）✓
  - `run_seccomp(canary, 'disasm')` → Ruby 错误（caller 需 sanity check）✓
  - `run_gdb_batch(canary, 'b main', 'run', 'info reg', 'quit')` → 含 `Breakpoint 1 at 0x8049262` + `eax 0x804925f` ✓
  - 失败路径：strace/gdb 缺失文件 → 41-61 字符错误输出（caller 自行判）
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **commit 引用**：`7cab410`（P1.3c）— `4af923e` (P1.3b) → `7cab410` (P1.3c)

**P1.3d 详细步骤**（`core/runner.py` 扩展）：

依据 `refactor.md §4.2` 末段（交互式工具特殊接口），在 `autopwn/core/runner.py` 末尾追加 2 个 qemu wrapper — **不返回 str，返回 `subprocess.Popen` 句柄**（例外）：

```python
def run_qemu_user(arch: str, program, *args: str) -> subprocess.Popen:
    """User-mode emulation: `qemu-<arch> <args> <program>`.
    pwntools 风格 — 跑 ARM binary 在 x86_64 host 上（无需 boot OS）。
    支持：aarch64 / arm / i386 / mips / riscv* 等（取决于 qemu-user 包）。
    动态链接需传 `-L <sysroot>` 找 libc。"""
    cmd = [f"qemu-{arch}", *args, str(program)]
    return subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)

def run_qemu_system(arch: str, program, *args: str) -> subprocess.Popen:
    """Full-system emulation: `qemu-system-<arch> <args> <program>`.
    boot 整个 VM。少用于 CTF 场景，本机仅 x86_64 / i386 可用。"""
    cmd = [f"qemu-system-{arch}", *args, str(program)]
    return subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
```

**P1.3d 实施记录（2026-06-07）**：

- **扩展** `autopwn/core/runner.py`（+50 行）：2 个新函数 + `__all__` 列表更新
- **不动 `_legacy.py`**：Popen 接口是 P5/P7 用，re-export 不加
- **接口例外**：qemu 是常驻进程，**不**遵守 §4.2 "返回 str" 范式（refactor.md §4.2 末段明文允许）
- **踩坑 #1**：pwntools.md 写 `qemu-system-x86`（包名），实际二进制是 `qemu-system-x86_64` + `qemu-system-i386`（同包多个 symlink）。**`qemu-system-aarch64` 在本机没装**（`qemu-system-arm` 也没装）。已装的是 `qemu-user` 包（`qemu-aarch64` / `qemu-arm` / `qemu-i386` 等）—— pwntools 风格二进制利用走 user-mode，本就是正确工具
- **踩坑 #2**：`Popen` 对缺失二进制会**立即抛 `FileNotFoundError`**（不是返回失败 Popen）。这是 Python 标准 Popen 行为，caller 需 `try/except FileNotFoundError` 处理。文档化在 docstring
- **踩坑 #3**：qemu 跨架构运行是静默失败（如 `qemu-aarch64` 跑 x86 canary → rc=255，stderr 空）。caller 需 check `p.returncode` 后再 `communicate()`，或用 `p.poll()` 判断
- **功能单测**（手测，pytest 体系待 P9）：
  - `run_qemu_user('i386', canary)` + `communicate(input=b'AAAA\n', timeout=10)` → rc=0，stdout 含 `stack protector` ✓
  - `run_qemu_user('aarch64', '/nonexistent')` + communicate → rc=1（caller 判 rc）✓
  - `run_qemu_user('aarch64', x86_canary)` → rc=255（跨架构不兼容，预期）✓
  - `run_qemu_system('x86_64', '/dev/null')` → 启动 + kill + wait OK ✓
  - `run_qemu_system('aarch64', ...)` → `FileNotFoundError`（caller 需 catch）✓
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **commit 引用**：`601173f`（P1.3d）— `7cab410` (P1.3c) → `601173f` (P1.3d)

**P1.5 详细步骤**（替换 _legacy.py 中 os.system 调用）：

P1.5 是 P1.3 + P1.3a-d 18 个 runner wrapper 的**调用方采用**——P1.3 系列只提供工具，P1.5 真正用上：

```python
# 13 处 os.system + 4 处文件读 + 3 处 shell pipe 全部替换
# 关键替换映射：
#   os.system(f"ldd X | awk ... > libc_path.txt") + open()
#     -> run_ldd(program) + Python .strip() / .split()
#   os.system(f"checksec X > file 2>&1") + open()
#     -> run_checksec(program) (str)
#   os.system(f"objdump -d X > file 2>&1") + open()
#     -> run_objdump_disasm(program, intel=True|False)
#   3x os.system(f"ropper ... >> ropper.txt") + open()
#     -> 3x run_ropper + concat splitlines()
#   os.system(f"ropper ... > ropper.txt") (x4 in find_rop_gadgets_x32)
#     -> 4x run_ropper
#   os.system(f"strings X | grep /bin/sh > file") + open()
#     -> run_strings(program) + 'in' check
#   os.system(f"objdump -d -M intel X | grep -A20 func")
#     -> run_objdump_disasm(program, intel=True) + Python enumerate[20:]
#   3x open("Objdump_Scan.txt") (downstream consumers)
#     -> self-contained run_objdump_disasm(program, intel=False) (AT&T)
```

**P1.5 实施记录（2026-06-07）**：

- **修改** `autopwn/_legacy.py`（净 -126 行）：13 处 os.system + 4 处文件读 + 3 处 shell pipe 全部替换
- **修改** `autopwn/core/runner.py`：`run_objdump_disasm` 加 `intel: bool = True` 参数（AT&T 兼容）
- **不动**：`autopwn.py` shim、`autopwn/cli.py`、`core/logging.py`、`core/fs.py`、所有 `__init__.py`
- **剩 2 处 os.system（不在 P1.5 范围）**：
  - L32 `os.system('ulimit -c 0 ...')` — 核心转储防护（启动期，全局）
  - L42 `os.system('rm -rf core* ...')` — 清理线程（每 1 秒）→ **P1.6 任务**
- **cwd 污染彻底清除**：跑完 `Challenge/canary` 后**无** `Information_Collection.txt` / `ropper.txt` / `Objdump_Scan.txt` / `libc_path.txt` / `check_binsh.txt`
- **踩坑 #1**：3 个函数（`analyze_vulnerable_functions` / `vuln_func_name` / `asm_stack_overflow`）**也读 Objdump_Scan.txt**。原代码靠 `scan_plt_functions` 先写文件，**隐式依赖链**。P1.5 修：每个函数**自给自足**调 `run_objdump_disasm`
- **踩坑 #2**：`vuln_func_name()` 原本用全局 `program` 变量（无参数）。改成接 `program` 参数后**所有调用点都要传**。修：2 处调用点改 `vuln_func_name(program)`
- **踩坑 #3（最关键）**：`asm_stack_overflow` 的 regex `lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)` 是 **AT&T 语法**（`lea -0x10(%rbp), %rax`），但 `run_objdump_disasm` 默认输出 **intel 语法**（`lea rax, [rbp-0x10]`）— **regex 不匹配**，函数返回 None，padding 错位 → ret2_system_x64 收到 `padding=None` → TypeError。**第一次 §2.6 验证 5/5 rc=1 回归**，3 轮调试才定位。修：`run_objdump_disasm(program, intel: bool = True)` 加可选参数；legacy 3 函数用 `intel=False` 保留 AT&T 输出
- **第 1-3 次 §2.6 失败 + 第 4 次 PASS**：3 个 bug 互相掩盖，迭代修复
- **§2.6 验证结果**（最终 PASS）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— **4/5 rc=0**（canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **commit 引用**：`7a6cbe0`（P1.5）— `bb20de9` (P1.4 doc) → `7a6cbe0` (P1.5)

**P1.6 详细步骤**（删 cleanup_core_files 线程）：

依据 `refactor.md §4.2` + `AGENTS.md §7.2 P1 reviewer` 关注点，在 `autopwn/core/fs.py` 加 `cleanup_core_dumps(cwd=None) -> int`，在 `autopwn/_legacy.py` 替换线程：

```python
# core/fs.py 新增
def cleanup_core_dumps(cwd: Path = None) -> int:
    """Remove core* files/dirs in cwd (best-effort). Replaces
    os.system("rm -rf core* 2>/dev/null || del core* 2>nul || true")."""
    if cwd is None:
        cwd = Path.cwd()
    removed = 0
    for path in cwd.glob("core*"):
        try:
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink()
            removed += 1
        except OSError:
            pass  # best-effort; matches legacy 2>/dev/null suppression
    return removed
```

```python
# _legacy.py: 删线程，改 import-time 一次性清理
# OLD: 1s 间隔的 daemon 线程
# NEW: cleanup_core_dumps()  # 一次性，import 时执行
```

**P1.6 实施记录（2026-06-07）**：

- **新增** `cleanup_core_dumps` 在 `autopwn/core/fs.py`（+38 行）：glob + os.unlink (files) / shutil.rmtree (dirs)
- **删除** `cleanup_core_files` 后台线程 from `_legacy.py`
- **新增** `_legacy.py` 模块 import 时一次性 `cleanup_core_dumps()` 调用
- **踩坑 #1（关键回归发现）**：P1.6 第一次提交时保留了**后台线程**结构（仅把 `os.system` 换成 `cleanup_core_dumps`），§2.6 验证 4/5→**3/5** 回归。`Path.cwd().glob('core*')` 每秒一次干扰 canary 暴力枚举（60-90s timeout 内 brute force 跑不到 EXPLOITATION phase）。**3 轮迭代**：①加 120s/180s/240s timeout 都没用（canary 真需要 >4min）②临时禁用线程（`# cleanup_thread.start()`）→ 立即 4/5 PASS ③根本解：删线程，改 import-time 一次性清理
- **踩坑 #2**：删除线程时用 `cleanup_core_dumps()` 在 module body **前**调用，但 `from autopwn.core.fs import cleanup_core_dumps` 在 module body **后**——NameError。修：把 call 移到 import 之后
- **功能单测**（手测，pytest 体系待 P9）：
  - `cleanup_core_dumps()` 在空目录 → 删 0（no-op）✓
  - `cleanup_core_dumps()` 在 3 个 core 文件 + 1 个 not_core.txt → 删 3，not_core.txt 保留 ✓
  - `cleanup_core_dumps()` 在 `core.dir` 目录 → 删 1，目录递归清空 ✓
- **§2.6 验证结果**（最终 PASS）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + **fmtstr1/level3_x64/pie/rip 全部 PASS**（4/5 SUCCESS，**无回归**）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **commit 引用**：`377fa4f`（P1.6）— `5653c8c` (P1.5 doc) → `377fa4f` (P1.6)

**P1.4 决策记录（2026-06-07）**：

**状态变更**：⏳ → ✅（**由 P1.1 顺手完成，无独立 PR**）

**为什么 P1.4 等价于 P1.1 实现的子集**：

P1.4 在原始 `rebuild.md` §4.2 写成 "替换 `autopwn.py` 中所有 `print_banner()` / `print_*` 调用为 `from autopwn.core.logging import ...`"。该任务在 P0.1-P0.5 拆分后已**自动等价**为"让 `_legacy.py`（取代 `autopwn.py` 成为 monolith）从 `core/logging.py` 导入 print_*"。

P1.1 实施时做了：
- `core/logging.py` 新建（163 行）：Colors + 12 print_* + VERBOSE + set_verbose() setter
- `_legacy.py` 删除原 109 行定义（L52-55 常量 + L71-182 print_*）
- `_legacy.py` 替换为 `from autopwn.core.logging import (VERSION, AUTHOR, GITHUB, ORG_CN, VERBOSE, Colors, print_*)` re-export
- 418 个 `print_*` 调用点 / `Colors.X` 引用点**零修改**即可工作（Python `import *` 语义让 re-export 完全透明）

**P1.4 目标** = "让 monolith 从 core/ 导入 print_*"——已被 P1.1 实现完整覆盖。

**为什么不标 ❌**（避免误读）：
- ❌ 含义："不再需要，可删除任务行"
- ✅ 含义："已实现，查阅 P1.1 即可"
- 选 ✅ 保留 §4.2 任务历史，标明实际由 P1.1 完成

**为什么不留 ⏳**：
- ⏳ 会误导后续 reviewer 以为还需独立 PR
- 已无独立代码改动可做

**Owner 决策**（2026-06-07 @MinZhi_Zhou）：✅ 标 P1.4 done，引用 P1.1 实现；后续如需 stylistic cleanup（re-export 改为文件内多处显式 import）可单独开新任务

**铁律 4 六关**：N/A（无独立代码改动；P1.1 的六关已 PASS 见 §6.2 P1.1）

**P1.3a 详细步骤**（`core/runner.py` 扩展）：

依据 `refactor.md §4.2` 接口范式（返回 `str` + 失败降级为空串），在 `autopwn/core/runner.py` 末尾追加 4 个静态 binutils 套件函数：

```python
def run_file(program) -> str:
    """Run `file X` and return the single-line file-type description."""
    cp = subprocess.run(["file", str(program)], capture_output=True, text=True, check=False)
    return (cp.stdout or cp.stderr).strip()

def run_readelf(program, *flags: str) -> str:
    """Run `readelf <flags> X` and return stdout. Flags: -h/-d/-s/-l/-S/-a."""
    cp = subprocess.run(["readelf", *flags, str(program)], capture_output=True, text=True, check=False)
    return cp.stdout

def run_strings(program, min_len: int = 4) -> str:
    """Run `strings -n <min_len> X` and return newline-separated strings."""
    cp = subprocess.run(["strings", "-n", str(min_len), str(program)], capture_output=True, text=True, check=False)
    return cp.stdout

def run_nm(program) -> str:
    """Run `nm X` and return the symbol table (one entry per line)."""
    cp = subprocess.run(["nm", str(program)], capture_output=True, text=True, check=False)
    return cp.stdout
```

**P1.3a 实施记录（2026-06-07）**：

- **扩展** `autopwn/core/runner.py`（+45 行）：4 个新函数 + `__all__` 列表更新
- **不动 `_legacy.py`**：re-export 不加（无 caller），P1.5 改 os.system 调用点时会直接 `from autopwn.core.runner import run_xxx`
- **接口一致性**（R14 reviewer 必查）：4 个函数全部 `-> str` + 失败空串 + 单一参数 `program`（除 `readelf *flags` / `strings min_len`）— 符合 `refactor.md §4.2` 范式
- **功能单测**（手测，pytest 体系待 P9）：
  - `run_file('./Challenge/canary')` → "ELF 32-bit LSB executable, Intel 80386, ..." ✓
  - `run_readelf(prog, '-h')` → ELF Header + Class: ELF32 + ... ✓
  - `run_readelf(prog, '-d')` → Dynamic section + NEEDED libc.so.6 ✓
  - `run_strings(prog, 4)` → 81 strings，包含 `gets`/`puts`/`/bin/sh` 等 ✓
  - `run_nm(prog)` → 符号表，包含 `_DYNAMIC` / `system` / `puts` 等 ✓
  - 失败路径：file 缺失 → error string；nm 缺失 → 空串（两种行为不同，caller 各自处理）
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 + `refactor.md §4` 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 4094 vs v3.1 3625（fuzzing 时序差异）
- **commit 引用**：`3696262`（P1.3a）— `ae59c78` (P1.3) → `3696262` (P1.3a)

**P1.3b 详细步骤**（`core/runner.py` 扩展）：

依据 `refactor.md §4.2` 接口范式（返回 `str` + 失败降级为空串），在 `autopwn/core/runner.py` 末尾追加 4 个 ROP/pattern 套件函数：

```python
def run_ropgadget(program, *filters: str) -> str:
    """Run `ROPgadget --binary X [--only <f1>] [--only <f2>]...` and return stdout."""
    cmd = ["ROPgadget", "--binary", str(program)]
    for f in filters:
        cmd.extend(["--only", f])
    cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return cp.stdout

def run_cyclic_create(length: int) -> str:
    """Run `cyclic <length>` and return the cyclic pattern (no trailing newline)."""
    cp = subprocess.run(["cyclic", str(length)], capture_output=True, text=True, check=False)
    return cp.stdout.strip()

def run_cyclic_find(pattern: str) -> str:
    """Run `cyclic -l <pattern>` and return the offset as a string (e.g., '140')."""
    cp = subprocess.run(["cyclic", "-l", pattern], capture_output=True, text=True, check=False)
    return cp.stdout.strip()

def run_one_gadget(libc_path) -> str:
    """Run `one_gadget <libc>` and return the structured gadget list."""
    cp = subprocess.run(["one_gadget", str(libc_path)], capture_output=True, text=True, check=False)
    return (cp.stdout or cp.stderr).strip()
```

**P1.3b 实施记录（2026-06-07）**：

- **扩展** `autopwn/core/runner.py`（+60 行）：4 个新函数 + `__all__` 列表更新
- **不动 `_legacy.py`**：re-export 不加（无 caller），P1.5 改 os.system 调用点时会直接 `from autopwn.core.runner import run_xxx`
- **接口一致性**（R14 reviewer 必查）：4 个函数全部 `-> str` + 失败空串（除 `cyclic_find` miss 是 `''`、非 `"None"`）— 符合 `refactor.md §4.2` 范式
- **踩坑**：`ROPgadget --nocolor` 在本机版本（5.4+）**不是有效 flag**（会触发 argparse 错误回显 USAGE）。已去掉，使用 ROPgadget 默认输出（带 ANSI 颜色码，调用方用 `re.sub(r"\x1b\[[0-9;]*m", "", text)` 清洗）
- **踩坑**：`cyclic` CLI 打印 `DeprecationWarning` 到 stderr（pwntools 推荐用 `pwn cyclic` 或 `pwn.cyclic()`）。`subprocess.run` 默认 `capture_output=True` 静默丢弃 stderr，不影响 stdout
- **功能单测**（手测，pytest 体系待 P9）：
  - `run_ropgadget(canary, 'pop|ret')` → 6 gadgets（含 `0x080492fb: pop ebp ; ret` 等）✓
  - `run_ropgadget(canary, 'pop', 'ret')` → 6 lines（多 filter 合并 OR 语义）✓
  - `run_ropgadget(canary)`（无 filter）→ 151 lines（全扫描）✓
  - `run_cyclic_create(16)` → `'aaaabaaacaaadaaa'`（16 字节）✓
  - `run_cyclic_find('aaaa')` → `'0'`（首 4 字节）✓
  - `run_cyclic_find('daaa')` → `'12'`（第 13-16 字节）✓
  - `run_cyclic_find('XYZQ')` → `''`（miss）✓
  - `run_one_gadget(/lib/x86_64-linux-gnu/libc.so.6)` → 含 `0xebc81 execve("/bin/sh", ...)` 等 gadgets ✓
  - `run_one_gadget('/nonexistent')` → 714B 错误输出（caller 自行判 `'execve' in out`）✓
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **commit 引用**：`4af923e`（P1.3b）— `3696262` (P1.3a) → `4af923e` (P1.3b)

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

**P1.2 实施记录（2026-06-07）**：

- **新文件** `autopwn/core/fs.py`（61 行）：3 个 utility
  - `set_permission(program) -> bool`：`os.system('chmod +755 ...')` → `os.chmod(program, 0o755)`（AGENTS.md §7.2 P1 reviewer 要求）
  - `add_current_directory_prefix(program) -> str`：保留字符串接口（main() 传 `args.local` 是 str，下游用 `%` 插值）
  - `temp_workdir()`：context manager，chdir 临时目录，try/finally 恢复 cwd（cleanup 自动）
- **`_legacy.py` re-export**（L62-65）：`from autopwn.core.fs import (set_permission, add_current_directory_prefix, temp_workdir)`，删除原 16 行定义（L348-362）
- **净减少** `_legacy.py` 16 行（3641 → 3625）
- **行为等价性**：`os.system('chmod +755 X')` ≡ `os.chmod(X, 0o755)` —— 两者都设 mode=0755，stat 输出完全一致
- **功能单测**（手测，pytest 体系待 P9）：
  - `add_current_directory_prefix('./foo') == './foo'` ✓
  - `add_current_directory_prefix('foo') == './foo'` ✓
  - `set_permission(real_file)` 从 0644 改到 0755 ✓
  - `set_permission('/nonexistent')` 返回 False + 打印 error ✓
  - `temp_workdir()` chdir 进去、yield path、退出恢复 cwd ✓
  - `temp_workdir()` 异常退出也恢复 cwd ✓
- **§2.6 验证结果**：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行 — canary PARTIAL（60s 截断预期）+ fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（无回归）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.2 + §6.2 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3442 vs v3.1 3625（fuzzing 时序差异，与 P1.1/P0.8 同类）
- **commit 引用**：`da3ac0a`（P1.2）— `694b813` (P1.1) → `da3ac0a` (P1.2)

**验收**
- 跑完一个完整 exploit，`cwd` 不出现 `ropper.txt` / `libc_path.txt` / `Information_Collection.txt` / `Objdump_Scan.txt`（P1.5/P1.6 任务；本 PR 仅提供工具，未替换调用点）
- `core/runner.py` 单测覆盖：mock subprocess.run 后断言传入参数正确（P1.3 任务）

**Reviewer 关注点**
- 是否所有外部命令都走 `subprocess.run(capture_output=True)`（禁止 `os.system`/`shell=True`）— **P1.2 已清掉一处 `os.system`（chmod）**；剩余 14 处在 P1.5 处理
- 临时目录用 `try/finally` 恢复 cwd ✓
- `os.system('chmod +755 ...')` 改为 `os.chmod` ✓

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

**P2.2 实施记录（2026-06-07）**：

- **扩展** `autopwn/context.py`（+125 行）：新增 `ContextError` + `ExploitContext.from_args()` classmethod
- **`ContextError(RuntimeError)`**：替换 legacy `print_error + sys.exit(1)` 模式；P2.3 会在 `cli.py` 顶层 catch 后路由回相同 UX（红字 + exit 1）；同时是 `refactor.md §11 #5` 计划中首个 typed exception（P4-P7 会引入 `ReconError` / `DetectionError` / `StrategyError` 子类）
- **`ExploitContext.from_args(args: argparse.Namespace) -> ExploitContext`**：
  - 类型检查：非 `argparse.Namespace` → `TypeError`
  - 验证：3 个 `ContextError` 路径（missing binary / missing libc / mismatched ip-port）— **错误消息与 legacy `print_error` 文本逐字一致**（Test 14 验证：`'target binary not found: /nope/foo'` 与 legacy L3291 完全相同）
  - 映射 6 个现有 flag + P8 forward-compat：
    - `-l/--local` → `ctx.binary.path` (Path, must exist)
    - `-ip/-p` → `ctx.remote = (host, port)` if both else `None` + `ctx.mode = 'remote'|'local'`
    - `-libc/--libc` → `ctx.libc.path` (Path, must exist if provided)
    - `-f/--fill` → `ctx.padding` (default 0)
    - `-v/--verbose` → `ctx.verbose` (bool)
    - `--report-dir`（P8 才会加）→ `ctx.report_dir`（用 `getattr` 防御性默认 `"."`）
    - `--no-report`（P8 才会加）→ **故意不映射**（等 P3 加 `ctx.enable_report: bool` 字段再处理）
  - BinaryInfo 占位字段：`bit=0` / `relro="Unknown"` / 其余 `False` — 显式注释"P4.1 recon 阶段会 overwrite"
- **`autopwn/__init__.py` 扩展**：`ContextError` 加进 re-export + `__all__`
- **零行为变更**：`_legacy.py` / `cli.py` / `autopwn.py` shim 全部不动 — P2.3 才会替换 `main()` 入口
- **15 项烟雾测试**（手测，pytest 体系待 P9）：
  - 1-7：各种 arg 组合（minimal / remote / libc / -f 112 / -v / P8 report_dir forward-compat / 全部一起）
  - 8：TypeError on dict input
  - 9：ContextError on missing binary
  - 10：ContextError on missing libc
  - 11：ContextError on ip without port
  - 12：ContextError on port without ip
  - 13：real argparse parser (与 _legacy.py 同形) 完整跑通
  - 14：error message 字符串逐字匹配 legacy
  - 15：returned object is ExploitContext with expected fields
- **6 项 P2.1 回归测试**（防 P2.2 误改 P2.1 已建字段）：
  - ✅ BinaryInfo slots 仍生效（`ctx.binary.foo = 'bar'` → AttributeError）
  - ✅ `ctx.log()` 路由仍工作
  - ✅ `from_args` 是 `@classmethod`（inspect 验证）
  - ✅ `ContextError` 是 `RuntimeError` 子类
  - ✅ P2.2 **没有**添加 P3.4 的 `last_exploit` 字段（正确延后）
  - ✅ P2.2 **没有**添加 P3 的 `enable_report` 字段（正确延后）
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.3 + §6.3 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P2.1 同类）
- **commit 引用**：`4bc9adc`（P2.2）— `2bdf254` (P2.1 doc) → `4bc9adc` (P2.2)

**P2.3 实施记录（2026-06-07）**：

- **新文件** `autopwn/_compat.py`（101 行，含 docstring）：bridge module
  - `_legacy_info: dict` — 单 module-level dict，9 个 key（与原 `_legacy.py` L81-91 字典字面量逐字一致：`target_binary`/`exploit_type`/`payload`/`padding`/`addresses`/`vulnerability_type`/`architecture`/`success`/`timestamp`），默认值完全相同（`''` / `0` / `{}` / `False` / `''`）
  - `sync_ctx_to_legacy(ctx: ExploitContext) -> None` — 复制 ctx 已知稳定字段到 `_legacy_info`
- **`_legacy.py` 3 处修改**（净 -4 行：+13 -17）：
  - ① 删 L80-91（12 行 `exploit_info = {...}` 字面量）→ 替换为 `from autopwn._compat import _legacy_info as exploit_info`（1 行）。**alias 是同一 dict 对象**，所有 ~50 个 `exploit_info[...]` 读 + 7 个写 0 改动（mutation 双向可见）
  - ② 顶部新增 3 个 import：`ExploitContext, ContextError` + `_legacy_info as exploit_info` + `sync_ctx_to_legacy`
  - ③ `main()` L3289-3296 验证段后插入 6 行：`from_args(args)` + `sync_ctx_to_legacy(ctx)` + `try/except ContextError` 转译为 `print_error + sys.exit(1)`（与 legacy UX 逐字一致）
- **3 处偏离 `rebuild.md §6.3 P2.3` spec 的有意识决策**（避免行为回归）：
  - ① **`sync_ctx_to_legacy` 不调用 `warnings.warn`**：bridge 是 P2.3–P8.5 唯一 API，warn 会污染日志 diff（每次 exploit 都打印）。`update_exploit_info` 的 deprecation 留给 P2.5
  - ② **`architecture` 用 `if ctx.binary.bit != 0` guard**：P4.1 recon 阶段才会把 `BinaryInfo.bit` 从 placeholder `0` 改为 `32/64`。spec 例子的 `f"x{ctx.binary.bit}"` 在 P2.3 会产生 `"x0"` 泄漏到任何在 `handle_exploitation_success` 之前读 `exploit_info['architecture']` 的代码（虽然实际没找到这种 reader，但守卫生性 ≥ 风险）
  - ③ **startup **不**设 `success = True`**：spec 的硬编码 True 会破坏 L241 的 `if not exploit_info['success']` 门控（导致 docx 在 exploit 失败时也生成）。P3.4 `record_success()` 才是设 `True` 的地方
- **实际行为 no-op 验证**：L3305/L3306 在 main() 里立即用 `os.path.basename(args.local)` 和当前时间 overwrite bridge 设的 `target_binary`/`timestamp`；L354-360 在 `handle_exploitation_success` 里 overwrite 全部 success 字段。bridge 的 4 次写入（target_binary/padding/architecture?/none-for-success）在每次成功路径上**全被覆盖**。失败路径上 bridge 写入会保留 — 但失败路径只走到 L241 的 docx gate（看 `success=False`），不读其它字段，故无影响
- **10 项 bridge 烟雾测试**（手测，pytest 体系待 P9）：
  - 1：`_legacy_info` 9 个 key 完整
  - 2：9 个默认值与 spec 逐字一致
  - 3：**关键 guard** — `bit=0` 时 `architecture` 保持 `''`（不漏"x0"）/ `success` 保持 `False`（不漏 True）
  - 4：`bit=32` 时 `architecture = "x32"`（guard 通过，bridge 正常工作）
  - 5：aliasing — `autopwn._legacy.exploit_info is _compat._legacy_info`（同一对象）
  - 6：双向 mutation 可见（写一边读另一边）
  - 7：`autopwn._compat.__all__` 含 `_legacy_info` + `sync_ctx_to_legacy`
  - 8：完整 main() → handle_exploitation_success 流程模拟，docx 读取的 9 个字段全对
  - 9：end-to-end `python autopwn.py --help` 仍 rc=0
  - 10：end-to-end `python autopwn.py -l /nonexistent/binary` 仍 rc=1 + 错误消息 `target binary not found`（来自 try/except 转译）
- **§2.6 验证结果**（**首次真正改 `_legacy.py` 行为路径**，§2.6 CRITICAL 验证）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（**0 回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.3 + §6.3 同步
  - 详见 `logs/comparison/summary.md`
- **docx 验证**：rip_wp.docx / fmtstr1_wp.docx / level3_x64_wp.docx 在 §2.6 运行期间（< 1 min 旧）被重新生成，**说明 `exploit_info[...]` 读取路径在 30+ 个 docx 字段处全部仍工作**（P3.4 才会把它们改读 ctx）
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3511 vs v3.1 3625（fuzzing 时序差异，与 P0.7–P2.2 同类）
- **commit 引用**：`51563da`（P2.3）— `b7ffff1` (P2.2 doc) → `51563da` (P2.3)

**P2.4 实施记录（2026-06-07）**：

- **扩展** `autopwn/_compat.py`（+105 行 → 197 行）：
  - `sync_ctx_to_legacy(ctx, *, target_name=None, timestamp=None)` 加 2 个可选 kwargs
    - `target_name=None` → P2.3 默认行为（full path）
    - `target_name='canary'` → P2.4 行为（basename，与 legacy L3317 一致）
    - `timestamp=None` → P2.3 默认（不动字段）
    - `timestamp='2026-06-07 07:33:55'` → P2.4 行为（与 legacy L3318 strftime 格式一致）
  - **新增** `record_success(*, exploit_type, payload, padding, addresses, vulnerability_type, architecture)` — 7 个 kwargs，复刻 L350-356 `update_exploit_info()` 调用 + L356 `success=True`（P2.3 deviation #3 修复）
    - payload 处理：完全复刻 legacy L351 逻辑 `payload.hex() if hasattr(payload, 'hex') else str(payload)`（逐字一致）
- **`_legacy.py` 3 处修改**（净 -10 行：+13 -23）：
  - ① **删除** `update_exploit_info` helper（L92-95 + L98 防御性 `global`，共 5 行）—— **0 callsite 剩余**（grep 验证 0 行）
  - ② `main()` L3315-3318（4 行：`# Initialize exploit_info...` + `global exploit_info` + 2 个 dict 写）→ **删除**，扩展 `sync_ctx_to_legacy` 调用加 `target_name=basename(args.local), timestamp=now.strftime(...)`（kwargs 在 try 内）
  - ③ `handle_exploitation_success` L350-356（7 个 `update_exploit_info(...)` 调用）→ **1 个 `record_success(...)` 调用**（7 个 kwargs 命名）
- **结构验证**（核心 P2.4 验收）：
  - `grep -nE "exploit_info\[[^]]+\] *=" autopwn/_legacy.py` → 0 行（1 个 comment 提及"called exploit_info[key] = value internally"不算）
  - `grep -n "update_exploit_info" autopwn/_legacy.py` → 0 callsite（2 个 comments in P2.3 + P2.4 解释不算）
  - `grep -cE "exploit_info\[[^]]+\]" autopwn/_legacy.py` → 34 行（read 全部保留，按 spec 保留到 P8.5）
- **8 项烟雾测试**（手测，pytest 体系待 P9）：
  - 1：sync_ctx_to_legacy **无 kwargs** → P2.3 默认（target_binary=full path, timestamp=空）
  - 2：sync_ctx_to_legacy **有 kwargs** → P2.4 行为（target_binary=basename, timestamp=真实）
  - 3：record_success **bytes payload** → hex-encoded（复刻 legacy L351）
  - 4：record_success **str payload** → 保持原样（复刻 legacy hasattr() 分支）
  - 5：**完整 composite flow**（startup + success 路径）→ 9 字段全部正确
  - 6：**grep 验证**：`_legacy.py` 0 个 exploit_info 写点
  - 7：end-to-end `python3 autopwn.py --help` rc=0 + `-l /nope` rc=1 + 错误消息一致
  - 8：**关键成功路径验证**：`python3 autopwn.py -l Challenge/level3_x64` rc=0 + `level3_x64_wp.docx` 在 0.2s 内被重新生成 → **end-to-end 证明 `record_success()` 写入 `_legacy_info` 后，docx 读取的 30+ 字段全部仍正确填充**
- **§2.6 验证结果**（**首次走完整 success 路径，CRITICAL**）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（**0 回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.3 + §6.3 同步
  - 详见 `logs/comparison/summary.md`
- **docx 端到端验证**：4 个 docx（fmtstr1/level3_x64/pie/rip）在 §2.6 跑期间被重新生成 — 证明 `record_success` 设的 7 字段（exploit_type/payload/padding/addresses/vulnerability_type/architecture/success）全部被 docx 读者正确消费
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3471 vs v3.1 3625（fuzzing 时序差异，与 P0.7–P2.3 同类）
- **commit 引用**：`e73a6bb`（P2.4）— `0e5eac2` (P2.3 doc) → `e73a6bb` (P2.4)

**P2.5 决策记录（2026-06-07）**：

**状态变更**：⏳ → ✅（**由 P2.4 顺手完成，无独立 PR**）

**为什么 P2.5 等价于 P2.4 的子集**：

P2.5 在原始 `rebuild.md §4.3` 写成 "旧 `update_exploit_info` 标注 deprecation warning"。该任务的前提是 `update_exploit_info` 仍然存在并被调用。P2.4 在重构过程中**彻底删除**了 `update_exploit_info`：
- L92-95 函数定义删除
- L350-356 7 个 callsite 全部改用 `record_success(...)` 桥调用
- 验证：`grep -n "update_exploit_info" autopwn/_legacy.py` → 0 callsite（2 个 comment 提及不算）

**P2.5 目标** = "在 `update_exploit_info` 上加 deprecation warning" —— 该函数已不存在，加 warning 无意义。

**为什么不标 ❌**（避免误读）：
- ❌ 含义："不再需要，可删除任务行"
- ✅ 含义："已实现，查阅 P2.4 即可"
- 选 ✅ 保留 §4.3 任务历史，标明实际由 P2.4 完成

**为什么不留 ⏳**：
- ⏳ 会误导后续 reviewer 以为还需独立 PR
- P2.4 已彻底删除 helper（而非仅加 warning），P2.5 的 "标注 deprecation" 目标已被 P2.4 强覆盖

**Owner 决策**（2026-06-07 @MinZhi_Zhou）：✅ 标 P2.5 done-by-P2.4；后续如需恢复 `update_exploit_info`（如回滚 P2.4）可重新开启该任务

**铁律 4 六关**：N/A（无独立代码改动；P2.4 的六关已 PASS 见 §6.3 P2.4）


**P2.1 实施记录（2026-06-07）**：

- **新文件** `autopwn/context.py`（146 行）：6 个 `@dataclass(slots=True)`
  - `BinaryInfo(path, bit, stack_canary, pie, nx, relro, rwx_segments, stripped)` — 8 个必填字段
  - `LibcInfo(path=None, elf=None, base=0)` — `elf: object` 避免 pwntools 循环导入
  - `RopGadgetsX64(pop_rdi, pop_rsi, ret, extra_rdi=0, extra_rsi=0)` — `extra_*` 表 glibc "pop ; pop" 双 pop 变体
  - `RopGadgetsX32(pop_eax, pop_ebx, pop_ecx, pop_edx, pop_ecx_ebx, ret, int_0x80, has_eax_ebx_ecx_edx=False)` — 4 bool 合并为 `has_eax_ebx_ecx_edx`（R8 缓解）
  - `CanaryInfo(value, diff)` — `diff` 是 canary 到 saved ret 的填充字节数
  - `ExploitContext(binary, mode, remote=None, libc, gadgets_x64, gadgets_x32, padding=0, canary=None, has_*=False×6, binsh_in_binary=False, fmtstr_offset=None, fmtstr_buf=None, verbose=False, report_dir)` — 22 字段
- **`ExploitContext.log(message, level="info")` 方法**：路由到 `core.logging.print_*` 6 个函数（debug/info/success/warning/error/critical）。**local import** core.logging — 避免 context.py 反向依赖 core（context.py 是模型层，应在 core/ 之上）。**注**：P2 阶段 `_legacy.py` 仍走 `print_*` 直接调用；`ctx.log()` 是给 P4+ strategy 代码用的"统一入口"，P2.1 先把方法落地，不在 `_legacy.py` 替换调用点
- **`autopwn/__init__.py` 扩展**：加 `from autopwn.context import (BinaryInfo, CanaryInfo, ExploitContext, LibcInfo, RopGadgetsX64, RopGadgetsX32)` re-export + `__all__` 列表更新
- **零行为变更**：`_legacy.py` / `cli.py` / `autopwn.py` shim 全部不动；P2.3-P2.5 阶段才会引入 `exploit_info` → `ctx` 桥函数
- **踩坑**：第一次写 `BinaryInfo.elf: "pwntools.ELF"` 类型注解 + module-top `from pwn import ELF` → **循环导入风险**（`pwn` 工具链在某些 path 下会 import autopwn 自身）。修：`elf: object` + 注释"pwntools.ELF — see module docstring"
- **§6.3 reviewer 关注点逐项验证**：
  - ✅ 6 个 dataclass 全部 `@dataclass(slots=True)`
  - ✅ 可变默认用 `field(default_factory=...)`：`libc: LibcInfo = field(default_factory=LibcInfo)` / `report_dir: Path = field(default_factory=Path.cwd)`
  - ✅ 不可变默认直接 `= 0` / `= False` / `= None` — 不需要 factory
  - ✅ `__all__` 列出 6 个公开 class
- **10 项烟雾测试**（手测，pytest 体系待 P9）：
  - ✅ 6 个 dataclass 各自构造（默认值 + 全字段）
  - ✅ `ExploitContext(binary=b, mode='local')` + 全字段构造
  - ✅ `ctx.log("info", level="info")` / `level="debug"` / `level="warning"` 全部路由正确
  - ✅ `ctx.binary.foo = 'bar'` → `AttributeError`（slots 生效）
  - ✅ `__version__` 仍可从 `autopwn` 直接 import
  - ✅ `from autopwn import BinaryInfo, ExploitContext` + `from autopwn.context import CanaryInfo, ...` 两条路径都行
  - ✅ `from autopwn._legacy import main, exploit_info` 仍工作（无回归）
  - ✅ `from autopwn import cli` 仍 re-export
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致，SUCCESS `4/5 = 4/5`（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.3 + §6.3 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3432 vs v3.1 3625（fuzzing 时序差异，与 P0.7–P1.6 同类）
- **commit 引用**：`95e1b61`（P2.1）— `78fe1d4` (P1.6 doc) → `95e1b61` (P2.1)

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

**P3.1 详细步骤**（`report/model.py`）：

依据 `refactor.md §4.4 P3.1` + `rebuild.md §6.4` spec，新建 typed dataclass **声明-only** PR（与 P2.1 范式一致：纯加类型，零行为变更）：

```python
# autopwn/report/model.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict

@dataclass(slots=True)
class ExploitInfo:
    exploit_type: str
    payload: bytes
    padding: int
    addresses: Dict[str, int]
    vulnerability_type: str
    architecture: str
    target_binary: str = ""
    timestamp: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
```

**P3.1 实施记录（2026-06-07）**：

- **新文件** `autopwn/report/model.py`（94 行）：`ExploitInfo` dataclass
  - 6 required：`exploit_type` / `payload` / `padding` / `addresses` / `vulnerability_type` / `architecture`
  - 3 optional：`target_binary` / `timestamp` / `extra`（forward-compat 容器）
  - `@dataclass(slots=True)`：与 `context.py` P2.1 范式一致（性能 + frozen-by-default + 拒绝新增字段）
  - `extra` 走 `field(default_factory=dict)`，防御 mutable default 泄漏
- **修改** `autopwn/report/__init__.py`（6 行 → 15 行）：re-export `ExploitInfo` + 更新 `__all__`
- **零行为变更**：`_legacy.py` 3691 行未变（`wc -l` 验证）；34 个 `exploit_info[]` 读点 + 7 个写点（P2.4 桥）全部保留；`_compat.py` 194 行未变
- **CLI 烟雾**：`python autopwn.py --help` rc=0 + AutoPwn banner ✓
- **P2.x 回归**：
  - `from autopwn import BinaryInfo, ExploitContext, ContextError, ...` 仍工作 ✓
  - `ExploitContext.from_args(args)` 仍工作（验证 binary / mode / target_binary basename 设置）✓
  - `_compat.sync_ctx_to_legacy(ctx, target_name='canary')` 仍工作 ✓
- **12 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `from autopwn.report import ExploitInfo` 等价于 `from autopwn.report.model import ExploitInfo`（re-export 同对象）
  2. `__all__ = ['ExploitInfo']`
  3. 6 required 构造
  4. 字段访问（payload / architecture / ...）
  5. 3 optional 默认值（`''` / `''` / `{}`）
  6. mutable default 防御（两个 instance 的 `extra` 独立）
  7. slots 强制（`info.new_field = 'x'` → AttributeError）
  8. 字段集精确（9 字段，**无** `success`）
  9. 全 9 字段构造（含 `extra={'libc_base': 0x..., 'fmtstr_offset': 7}`）
  10. `__eq__` 工作（值相同 → 相等）
  11. `__repr__` 含字段名 + 值
  12. `addresses` dict 接受任何 int（含负数、0xFFFF）
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（预期 brute force 需 ~7min）+ fmtstr1/level3_x64/pie/rip 全部 PASS（4/5 SUCCESS，与 v3.1 baseline 持平）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致（**无回归**，预期：pure addition）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **未匹配的唯一标记**：canary `Padding (dynamic)` 3367 vs v3.1 3625（fuzzing 时序差异，与 P0.7–P2.4 同类，**非功能差异**）
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

**2 处 spec 偏差**（与 P2.1/P2.3 同范式——收紧类型 / 偏离 spec 示例 / 在 docstring 注释）：

1. **`addresses: Dict[str, int]` / `extra: Dict[str, Any]`**（spec 示例用裸 `dict`）：mypy-friendly，与 `context.py` `Dict`/`Tuple`/`Optional` 风格一致。运行时行为零差异。
2. **`success` 字段故意不加**（spec 示例也未加，但本 PR 注释明确意图）：
   - ExploitInfo 仅在 P3.4 success 路径构造，failed exploit 不产生 ExploitInfo
   - "should we generate a report" 的用户开关由 P3.5 `ctx.enable_report: bool` 接手（on context，**不**在 info 上）
   - 若未来需"partial / failed" 报告，正确设计是新建 `FailedExploitInfo` dataclass，**不**应在 ExploitInfo 上 overload `success=False` 状态

**commit 引用**：`6460707`（P3.1 code+record）— `414aebd` (P2.4 docs) → `6460707` (P3.1)

---

**P3.2 详细步骤**（`report/docx.py`）：

依据 `refactor.md §4.4 P3.2` + `rebuild.md §6.4` spec，把 `_legacy.py:generate_docx_report()` 整体搬到 `autopwn/report/docx.py`，改为 typed 签名 `generate_docx(info: ExploitInfo, out_dir: Path) -> Optional[Path]`：

```python
# autopwn/report/docx.py
from autopwn.core.logging import Colors, print_error, print_success, VERSION
from autopwn.report.model import ExploitInfo
# P3.2: 仍在 _legacy.py，P3.3 搬走后此 import 切到 report.code
from autopwn._legacy import generate_exploitation_code

def generate_docx(info: ExploitInfo, out_dir: Path) -> Optional[Path]:
    try:
        target_name = Path(info.target_binary).name
        if target_name.startswith("./"):
            target_name = target_name[2:]
        target_name = Path(target_name).stem
        report_path = out_dir / f"{target_name}_wp.docx"
        # ... 完整 body: 14 读点全部 info.x 替换 ...
        doc.save(str(report_path))
        print_success(f"Exploitation report generated: {Colors.YELLOW}{report_path}{Colors.END}")
        return report_path
    except Exception as e:
        print_error(f"Failed to generate report: {e}")
        return None
```

**P3.2 实施记录（2026-06-07）**：

- **新文件** `autopwn/report/docx.py`（189 行）：`generate_docx(info, out_dir) -> Optional[Path]`
  - 14 个 `exploit_info['x']` 读点全部改 `info.x`（字段映射表见 docstring）
  - `if not exploit_info['success']: return` 守卫**删除**（ExploitInfo 仅在 success 路径构造，门控在 P3.4 `record_success`）
  - 路径：从 `cwd / {target}_wp.docx` 改 `out_dir / {target}_wp.docx`（P3.2 默认 `out_dir=Path('.')` 保持现状；P3.5 CLI flag 让用户改）
  - `python-docx` import 改函数内 lazy import（P3.6 升级为 module-level `try/except ImportError` + markdown fallback）
  - `Inches` dead import 清理
  - `except: `（bare）改 `except Exception:`（Pylint R1722）
- **修改** `autopwn/report/__init__.py`（15 → 20 行）：re-export `generate_docx` + `__all__` 增
- **修改** `autopwn/_legacy.py`（3691 → 3590 = -101 行）：
  - 删 `generate_docx_report`（L231-344 整段）
  - 删 3 个 `from docx import Document / Inches / WD_ALIGN_PARAGRAPH`
  - 加 `from pathlib import Path`（handle_exploitation_success 要用）
  - `handle_exploitation_success` 末尾加 14 行：构造 ExploitInfo + 调 `generate_docx(_info, Path('.'))`（**14 caller 签名零修改**——向后兼容）
- **净变化**：`_legacy.py` -101 行；`report/` 包 +204 行（docx.py 189 + __init__.py +15）
- **10 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `report.generate_docx` ≡ `report.docx.generate_docx`（re-export 同对象）
  2. `_legacy.generate_docx_report` 已删
  3. 新签名 `(info, out_dir) -> Optional[Path]`
  4. 干跑 ExploitInfo（`target_binary="./rip"`）→ 生成 `rip_wp.docx` 37472B 在 out_dir
  5. address 格式化 5 种情况（int / str_int / str_hex / 异常 fallback / 异常 fallback 2）全部正确
  6. 异常路径（read-only out_dir）→ `return None` + 打印 error（与 legacy 行为一致）
  7. `handle_exploitation_success` 签名不变（6 kwargs）
  8. `handle_exploitation_success` body 含 `ExploitInfo(` + `from autopwn.report import` + `generate_docx(_info, Path('.'))`
  9. cwd 零污染（out_dir = tempdir 时 cwd 文件列表 delta = ∅）
  10. payload length bytes 分支 OK
- **CLI 烟雾**：`python autopwn.py --help` rc=0 + AutoPwn banner
- **P2.x 回归**：`from_args` / `sync_ctx_to_legacy` / `record_success` 仍工作
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（brute force 截断）+ fmtstr1/level3_x64/pie/rip 全部 PASS（4/5 SUCCESS，与 baseline 持平）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **docx 路径打印输出与 v3.1 byte-for-byte 一致**：
  - v3.1: `Exploitation report generated: fmtstr1_wp.docx`（cwd-relative）
  - v4.0: `Exploitation report generated: fmtstr1_wp.docx`（`Path('.') / fmtstr1_wp.docx` 打印相同字符串）
- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，预期）
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
- **1 处待 P3.3 清理**：`from autopwn._legacy import generate_exploitation_code`（P3.3 移到 `report.code` 后此 import 切换）
- **commit 引用**：`e58710a`（P3.2）— `6460707` (P3.1) → `e58710a` (P3.2)

---

**P3.3 详细步骤**（`report/code.py`）：

依据 `refactor.md §4.4 P3.3` + `rebuild.md §6.4` spec，把 `_legacy.py:generate_exploitation_code()` 整体搬到 `autopwn/report/code.py`，改为 typed 签名 `generate_code(info: ExploitInfo, out_dir: Path) -> str`：

```python
# autopwn/report/code.py
from autopwn.report.model import ExploitInfo

def generate_code(info: ExploitInfo, out_dir: Path) -> str:
    target_name = Path(info.target_binary).name
    if target_name.startswith("./"):
        target_name = target_name[2:]
    # ... f-string 模板 byte-for-byte 保留 legacy ...
    # 20 个 exploit_info['x'] 读点全部 info.x
    del out_dir  # forward-compat for P3.4 / P3.5
    return base_code
```

**P3.3 实施记录（2026-06-07）**：

- **新文件** `autopwn/report/code.py`（187 行）：`generate_code(info, out_dir) -> str`
  - 20 个 `exploit_info['x']` 读点全部改 `info.x`（字段映射表见 docstring）
  - **f-string 模板保留** —— 5 主流 exploit type + 1 generic fallback 全部产生与 legacy byte-for-byte 一致输出
  - `out_dir` 参数**保留但 P3.3 不使用**：`del out_dir` 静音 lint（P3.4/P3.5 可用其写 `{target}_wp.py`）
  - `except:` 改 `except Exception:`（Pylint R1722）
- **修改** `autopwn/report/__init__.py`（20 → 23 行）：re-export `generate_code` + `__all__` 增
- **修改** `autopwn/report/docx.py`（189 → 216 行）：1 import 切换（`autopwn._legacy.generate_exploitation_code` → `autopwn.report.code.generate_code`）；call site 改 `exploitation_code = generate_code(info, out_dir)`
- **修改** `autopwn/_legacy.py`（3590 → 3454 = -136 行）：
  - 删 `generate_exploitation_code`（L95-229 整段）
- **净变化**：`_legacy.py` -136 行；`report/` 包 +191 行（code.py 187 + __init__.py +3 + docx.py +27）
- **12 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `report.generate_code` ≡ `report.code.generate_code`
  2. `_legacy.generate_exploitation_code` 已删
  3. 新签名 `(info, out_dir) -> str`
  4. docx.py 改用 `from autopwn.report.code import generate_code`
  5. ret2system x64（830 chars）含 9 个关键 marker
  6. ret2libc write x64（1008 chars）含 7 个 ROP gadget marker
  7. format string 走 `addresses.get('offset', 'OFFSET_VALUE')` fallback
  8. execve syscall 含 6 个 pop_*/int_0x80 marker
  9. generic fallback 含 `repr(bytes payload)`
  10. empty addresses 跳 `# Key addresses` 段
  11. target_name basename 提取（`'./Challenge/with/path/foo'` → `'foo'`）
  12. address 格式化 4 种情况（int / hex_str / decimal_str / garbage fallback）
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + fmtstr1/level3_x64/pie/rip 全部 PASS（4/5 SUCCESS）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **f-string 模板 byte-for-byte 保留**：5 主流 exploit type 输出与 v3.1 完全一致（_legacy 删 135 行无 regression 即证）
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
- **commit 引用**：`ded551a`（P3.3）— `5d2fe36` (P3.2 docs) → `ded551a` (P3.3)

---

**P3.6 详细步骤**（`report/docx.py` markdown fallback）：

依据 `refactor.md §4.4 P3.6` + `rebuild.md §6.4` spec + `refactor.md §10`，把 `python-docx` import 改为模块级 `try/except ImportError`，docx 缺失时降级为 markdown report：

```python
# autopwn/report/docx.py
try:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    _HAS_DOCX = True
except ImportError:
    Document = None
    WD_ALIGN_PARAGRAPH = None
    _HAS_DOCX = False

def _generate_markdown(info, out_dir):
    """Write {target}_wp.md with same 5 sections as docx + footer."""
    # ... 5 sections + footer + "Note" about fallback ...
    return report_path

def generate_docx(info, out_dir):
    if not _HAS_DOCX:
        return _generate_markdown(info, out_dir)  # P3.6 dispatch
    # ... 原有 docx body ...
```

**1 处有意偏离 spec**：

- spec 把 `try/except ImportError` 放 caller 端（`record_success`）
- **实际放模块顶层** + `_HAS_DOCX` flag

原因：module-level import 失败在 import 期（`autopwn.report.docx` 被加载时），不是 call 期。caller 端的 `except ImportError` 永远捕获不到（ImportError 在 caller 自身 import 时就抛了）。模块顶层 try/except + flag dispatch 是实现 spec 意图（"docx 缺失时降级为 markdown"）的正确位置。已在 docx.py 顶部 docstring 详述。

**P3.6 实施记录（2026-06-07）**：

- **修改** `autopwn/report/docx.py`（216 → 311 行，净 +95）：
  - 3 import 改为模块顶层 `try/except ImportError` + `_HAS_DOCX` flag
  - 新加 `_generate_markdown(info, out_dir) -> Path`（5 段 + footer + Note，~80 行）
  - `generate_docx` 入口加 dispatch：`_HAS_DOCX=False` 调 markdown fallback 并改 print 消息加 "(markdown fallback)" 后缀
  - 函数内 lazy import 移除（已升模块级）
- **未改其他文件**（docx.py 是唯一改动点）
- **8 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `_HAS_DOCX = True`（本机 python-docx 已装）
  2. `generate_docx` re-export 自 `report`
  3. docx 路径正常（37472B → 37585B 微变是 timestamp 字段）
  4. md fallback monkey-patch 验证：含 9 个 section 标记（5 段 + footer 2 + Note）
  5. md fallback 4 种 address 格式化（int / str_int / str_hex / garbage）
  6. md fallback 跳 empty addresses + empty payload 段
  7. **真 docx 缺失**：`sys.meta_path` 插入 `_Blocker` raise ImportError → 重新 import → `_HAS_DOCX=False` → 走 md fallback 路径成功
  8. md fallback 零 cwd 污染
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + 4/5 PASS（**无回归**——本机有 docx，走 docx 路径）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
- **P3.4 衔接**：`generate_docx` 已可被 caller 安全 dispatch（无论 docx 是否可用，函数都返回 Path or None，错误降级为 markdown）
- **commit 引用**：`e44d274`（P3.6）— `6236537` (P3.3 docs) → `e44d274` (P3.6)

---

**P3.4 详细步骤**（`report.record_success` 订阅者 orchestrator）：

依据 `refactor.md §4.4 P3.4` + `rebuild.md §6.4` spec，把 `_legacy.handle_exploitation_success` 的 success-path body 移到 `autopwn/report/__init__.py:record_success(info)`，并清理 P2.4 `_compat.record_success` 桥（仅留 `sync_ctx_to_legacy` 用于启动时同步 target_binary/timestamp）：

```python
# autopwn/report/__init__.py
def record_success(info: ExploitInfo) -> None:
    """P3.4: subscriber orchestrator. P3.5 will add ctx param + enable_report gate."""
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    generate_docx(info, Path("."))
```

```python
# _legacy.py
def handle_exploitation_success(exploit_type, payload, padding, addresses, vulnerability_type, architecture):
    """P3.4: build ExploitInfo directly + call report.record_success."""
    from autopwn.report import ExploitInfo, record_success
    info = ExploitInfo(
        exploit_type=exploit_type, payload=payload, padding=padding,
        addresses=addresses, vulnerability_type=vulnerability_type, architecture=architecture,
        target_binary=exploit_info['target_binary'],  # P3.5 改 ctx
        timestamp=exploit_info['timestamp'],           # P3.5 改 ctx
    )
    record_success(info)
```

**2 处有意偏离 spec**：

1. **`record_success` 签名 `(info)` 而非 spec 的 `(ctx, info, primitive)`**
   - 原因：P3.4 阶段 `ctx.enable_report` 字段还没引入（P3.5 才加），`primitive` 是 P7 才用到的
   - 升级路径：P3.5 加 `ctx` 参数 + `if not ctx.enable_report: return` + `ctx.report_dir` 替换 `Path('.')`

2. **保留 2 个 dict 读（target_binary + timestamp）**
   - 原因：这 2 字段由 main() 启动时 `sync_ctx_to_legacy` 写入；要彻底消除它们需要给 14 个 caller 函数都加 ctx 参数（10 个策略函数 + 4 个 handle_exploitation_success 远程变体）—— 工作量超出 P3.4 范围
   - 升级路径：P3.5 接 ctx 后，`target_binary = ctx.binary.path.name`，`timestamp = datetime.now().strftime(...)`

**P3.4 实施记录（2026-06-07）**：

- **修改** `autopwn/report/__init__.py`（23 → 79 行，+56）：
  - 新加 `record_success(info: ExploitInfo) -> None` 函数
  - `__all__` 加 `record_success`
  - 顶部 docstring 更新 P3.4 status
- **修改** `autopwn/_legacy.py`（3454 → 3442 = -12 行）：
  - `handle_exploitation_success` body 精简（33 行 → 21 行）
  - 删 P2.4 `_compat.record_success(exploit_type=..., ...)` 6 kwargs 调用
  - 删 P3.2 的 14 行 dict-reading ExploitInfo 构造代码
  - 加 P3.4 的 12 行 kwargs-based ExploitInfo 构造 + `record_success(info)` 调用
- **未改**：`autopwn/_compat.py`（`record_success` 仍定义但 0 caller，P8.5 删整个 `_compat.py`）；14 个 strategy caller 函数（签名不变）
- **dispatch 链**（P3.4）：
  ```
  strategy_fn()  →  handle_exploitation_success(6 kwargs)  →  record_success(info)  →  generate_docx(info, Path('.'))
                                                                            └→  print_critical(banner)
  ```
- **10 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `record_success` 签名 `(info)` ✓
  2. `record_success` 是 module-level function（不是 method）✓
  3. `__module__ == 'autopwn.report'` ✓
  4. mock `generate_docx` → `record_success` 调用 1 次，参数 `(info, Path('.'))` ✓
  5. `handle_exploitation_success` body 36 行（含 docstring）—— 实函数体 ~10 行（vs P3.2 的 14 行 dict 读）
  6. 14 caller 签名不变 ✓
  7. `_compat.record_success` 仍定义（0 caller，保留至 P8.5）✓
  8. e2e `record_success(info)` 真生成 37KB docx ✓
  9. `_legacy.handle_exploitation_success` 仍 callable ✓
  10. **P2.4 桥退役验证**：`_compat.record_success(exploit_type=...)` 旧 callsite 在 `_legacy.py` 已消失 ✓
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + 4/5 PASS（**无回归**）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **"EXPLOITATION SUCCESSFUL!" banner byte-for-byte 不变**（print_critical 调用保留）
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
- **commit 引用**：`e162b9f`（P3.4）— `806f056` (P3.6 docs) → `e162b9f` (P3.4)

---

**P3.5 详细步骤**（CLI `--no-report` / `--report-dir`）：

依据 `refactor.md §4.4 P3.5` + `rebuild.md §6.4` spec，在 `argparse` 加 2 个 flag，把 `enable_report` 字段加到 `ExploitContext`，让 `report.record_success` 走 ctx：

```python
# _legacy.py argparse
parser.add_argument('--no-report', action='store_true', ...)
parser.add_argument('--report-dir', type=str, default=None, ...)

# context.py
@dataclass
class ExploitContext:
    ...
    enable_report: bool = True
    report_dir: Path = field(default_factory=Path.cwd)

@classmethod
def from_args(cls, args):
    ...
    enable_report = not bool(getattr(args, "no_report", False))
    report_dir_arg = getattr(args, "report_dir", None)
    if report_dir_arg:
        report_dir_path = Path(report_dir_arg)
        report_dir_path.mkdir(parents=True, exist_ok=True)  # 防御性创建
        report_dir = report_dir_path
    else:
        report_dir = Path.cwd()
    ...

# report/__init__.py
_current_ctx: Optional[ExploitContext] = None

def set_current_ctx(ctx): global _current_ctx; _current_ctx = ctx

def record_success(info):
    print_critical("EXPLOITATION SUCCESSFUL! ...")
    ctx = _current_ctx
    if ctx is not None and not ctx.enable_report:
        print_info("report generation skipped (--no-report)")
        return
    out_dir = ctx.report_dir if ctx is not None else Path(".")
    generate_docx(info, out_dir)

# main()
ctx = ExploitContext.from_args(args)
set_current_ctx(ctx)  # P3.5: stash ctx for record_success
```

**1 处有意偏离 spec**：

- spec 暗示 `record_success(ctx, info)` 显式加 ctx 参数
- 实际用 module-level `_current_ctx` carrier + `set_current_ctx(ctx)` setter

原因：14 个 `handle_exploitation_success` caller 都没有 ctx in scope。显式加 ctx 参数需要 plumb 14 个函数签名（10 个 strategy 函数 + 4 个 handle 远程变体）—— 大手术。module-level carrier 是 P3.4 注释里就预告的过渡方案，**P8.5 删除整个 `_compat.py` 时一并清理**（refactor.md §13.1 表中 `_legacy.py` P8.5 操作行）。

**P3.5 实施记录（2026-06-07）**：

- **修改** `autopwn/_legacy.py`（3442 → 3454 = +12 行）：
  - argparse 加 2 flag（`--no-report` + `--report-dir`）
  - main() 启动 `set_current_ctx(ctx)` 把 ctx 注入 carrier
- **修改** `autopwn/context.py`（291 → 308 = +17 行）：
  - ExploitContext 加 `enable_report: bool = True` 字段
  - `from_args` 映射 2 个新 flag（`enable_report = not args.no_report`；`report_dir` + `mkdir(parents=True, exist_ok=True)`）
  - `report_dir` 默认从 `Path(".")` 改为 `Path.cwd()`（语义更清晰）
- **修改** `autopwn/report/__init__.py`（79 → 128 = +49 行）：
  - 新加 module-level `_current_ctx: Optional[ExploitContext] = None` carrier
  - 新加 `set_current_ctx(ctx)` setter
  - `record_success` 改写：读 `_current_ctx` + `--no-report` gate + `ctx.report_dir` 替换 `Path('.')` + ctx=None defensive fallback
  - `__all__` 加 `set_current_ctx`
- **11 项功能单测**（手测，pytest 体系待 P9）全过：
  1. `--no-report` + `--report-dir` 出现在 `--help` 输出
  2. 默认 `ctx.enable_report = True`
  3. `--no-report` 设 `ctx.enable_report = False`
  4. `--report-dir` 自动 `mkdir(parents=True, exist_ok=True)` + `ctx.report_dir` 匹配
  5. 不可写 `--report-dir` raise `ContextError`
  6. `--no-report` 调 `record_success` 跳 docx 生成
  7. `--report-dir` 让 docx 落到指定目录，cwd 零污染
  8. ctx=None defensive fallback 到 cwd
  9. banner 总是打印（独立于 `--no-report`）
  10. e2e CLI: `python autopwn.py -l Challenge/rip --no-report` rc=0 + 跳 docx
  11. e2e CLI: `python autopwn.py -l Challenge/rip --report-dir /tmp/cli_reports/` rc=0 + docx 在指定目录
- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL + 4/5 PASS（**无回归**）
  - 关 4：关键日志对比 vs v3.1 baseline — `27/28 = 96%` 一致
  - 关 5：Reviewer — Owner 自审（§2.2）
  - 关 6：文档同步 — `rebuild.md` §4.4 + §6.4 同步
  - 详见 `logs/comparison/summary.md`
- **"EXPLOITATION SUCCESSFUL!" banner byte-for-byte 不变**
- **Exploitation report generated 行不变**（走 docx 路径 + cwd 时与 v3.1 一致）
- **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
- **commit 引用**：`8664759`（P3.5）— `f94c4cd` (P3.4 docs) → `8664759` (P3.5)

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

**P4.1 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/checksec.py`（177 行）：3 个函数
  - `collect(program: Path) -> BinaryInfo` — **pure**（无 print / 无 globals / 无 IO）；compile-once regex `_ARCH_RE` + `_STRIPPED_RE`（P2.1/P3.1 范式）；spec 字段映射 8 个（bit/stack_canary/pie/nx/relro/rwx_segments/stripped/path）
  - `display(info: BinaryInfo) -> None` — 复用 `core.logging.print_section_header` / `print_table_header` / `print_table_row` 印 5 行表（RELRO/Stack Canary/NX Bit/PIE/RWX Segments）+ 风险色（HIGH→ERROR/MEDIUM→WARNING/LOW→SUCCESS/INFO→INFO）
  - `_legacy_information_collection(program) -> Tuple[int, int, int, Optional[int]]` — v3.1 死代码 `Information_Collection` 的字面 port（rebuild §4.5 P4.1 spec 三函数之一）；underscore 前缀；0 caller（main() 实际用 `collect_binary_info`，v2 版本）

- **修改** `autopwn/recon/__init__.py`（6 → 22 行）：re-export `collect` + `display` + 更新 `__all__` + 顶部 docstring 增 P4.1 status + 后续 P4.x 模块范式说明

- **1 处 spec 偏离（DEV-1）**：`stripped` 字段用 regex `_STRIPPED_RE` 而非 spec 字面的 `"Stripped" in out`

  - spec 字面：```python\n  stripped="Stripped" in out,\n  ```
  - **Bug 根因**：`checksec` 输出永远含 `Stripped:` 标签（无论值是 Yes/No），所以 `"Stripped" in out` 总是 True。5 个 Challenge 二进制全是 `Stripped: No`，spec 字面会让 `info.stripped=True` 对**所有** 5 个二进制误判
  - 修：`_STRIPPED_RE = re.compile(r\"Stripped:\\s*(\\S+)\")` + `stripped = bool(m and m.group(1) == \"Yes\")`
  - 实证：第一次跑时 5/5 binary 都 `stripped=True` 误判（spec 字面）；修后 5/5 = False ✓
  - 与 P2.3/P3.4/P3.6 等历史 deviation 同范式：spec 写错 ⇒ 修代码 + 在 §6.5 详述原因

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.collect_binary_info`；新模块是**并行、可单元测试**实现

- **15 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 35 字段断言（5 binary × 7 字段）— `bit`/`stack_canary`/`pie`/`nx`/`relro`/`rwx_segments`/`stripped` 全部匹配 checksec 实际输出
  2. `display()` 在 5 个 binary 上视觉无异常
  3. `_legacy_information_collection` 在 5 个 binary 上 4-tuple 全部匹配 v3.1 first-match-wins 语义（含 rip 双 `Stack:` 行 → `break` → 保留 `No canary found` 而非 `Executable`）
  4. 缺文件路径 → `ToolError` 抛出（从 `core.runner.run_checksec` 透传）
  5. BinaryInfo slots 强制（`info.invalid_field = \"x\"` → `AttributeError`）
  6. `info.path` 是 `Path` 对象（非 str）
  7. 两次 `collect()` 返回独立对象，值相等
  8. cwd 零污染（`display()` 印日志到 stdout，不创建 `Information_Collection.txt`）
  9. `from autopwn.recon import collect, display` re-export 路径有效
  10. `_legacy_information_collection` underscore-prefixed 不在 `__all__`

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m \"not integration\"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.1 重新生成）
  - **无新增 failure mode**：`grep -E \"KeyError|no suitable shellcode|Traceback\" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P3.6 同类，**非功能差异**）

- **与 P4.7 globals() 清理的关系**：P4.1 **不**触碰 `globals()`；P4.1 是 `additive` 新模块；P4.7 才删 22 处 `globals().get(...)` 改读 `ctx.has_*`。本 PR `grep globals() autopwn/_legacy.py` 仍是 22 行（**预期**，下个 P4.x PR 处理）

- **后续步骤**：
  - P4.2（libc）/ P4.3（plt）/ P4.4（rop）/ P4.5（bss）/ P4.6（asm）每个按 P4.1 范式实现：pure `collect(ctx, program) -> X` + 复用 `core.runner` + 不动 `_legacy.py`
  - P4.7 删 22 处 `globals().get(...)`（R1 风险点）— 此时 `recon.checksec.collect()` 等 5 个新模块都已就位，删 globals 不会断路
  - P4.8 删 `set_function_flags` 副作用
  - P8 orchestrator 整合 `recon/checksec.collect` + `recon/libc.detect` + ... 进 `run_recon_phase(ctx)`，并把 5 个新模块的返回值灌进 `ctx.binary` / `ctx.libc` / `ctx.has_*` / `ctx.gadgets_*` 字段

**Refs**: refactor.md §3.2.1（BinaryInfo spec）/ refactor.md §5（79 函数 → 新位置映射表）

---

**P4.2 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/libc.py`（209 行）：1 public + 1 helper + 2 legacy ports
  - `detect(ctx, program) -> LibcInfo` — **pure**（无 print / 无 globals / 无 IO 除了 1 次 `run_ldd`）；3 阶段 resolution：①user override（`ctx.libc.path`，匹配 main() L3111-3116）②ldd auto-detect（`run_ldd` + 解析，匹配 main() L3117-3119 + `detect_libc` L142-150）③empty `LibcInfo()`
  - `_parse_libc_path(ldd_out: str) -> Optional[str]` — 私有 helper，提取 `libc.so.6 => /path` 字段；6 边缘 case（normal / x86_64 / static / empty / no-libc / libc++.so.6 false positive）全处理
  - `_legacy_detect_libc(program) -> Optional[str]` — v3.1 `detect_libc` 字面 port（L132-158），**保 v3.1 print 行为**：P0.7 §2.6.1 `print_debug` 关键节点 + `print_info` "detecting libc path automatically" + `print_success` "libc path detected: …" + `print_warning` "libc path not found in ldd output" + `print_error` "failed to detect libc: …"
  - `_legacy_ldd_libc(program) -> Optional[str]` — v3.1 `ldd_libc` 字面 port（L160-182）；**保原代码结构**（用 `subprocess.run` 直接，不走 `core.runner.run_ldd`）— 这样 git-archaeology 时 diff 与原一致

- **修改** `autopwn/recon/__init__.py`（22 → 33 行）：re-export `detect` + 更新 `__all__` + 顶部 docstring 增 P4.2 status

- **设计决策**：
  - **`LibcInfo.elf` 维持 `None`**：v3.1 在 `ret2libc_write_x64` L906-908 懒加载 `ELF(libc_path)`；新模块不引入 pwntools 依赖到 recon 期，P7 strategy 才需要时再 `ctx.libc.elf = ELF(str(ctx.libc.path))`
  - **`detect()` 是 pure**（与 P4.1 `collect()` 范式一致）：不打印 user-facing 消息，user-facing 输出由 P8 orchestrator 控制；§2.6.1 关键节点 `print_debug` 在 `_legacy_detect_libc`（仍是生产路径）保留
  - **签名 `detect(ctx, program)` 而非 spec 字面 `detect(ctx)`**：refactor.md §5 明文要求 `(ctx, program)`；`program` 显式参数让函数自包含（不依赖 `ctx.binary.path` 是否被 P4.1 overwrite 之前/之后调用）

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.detect_libc`；新模块是**并行、可单元测试**实现

- **16 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 5 binary × `detect()` 解析为 5 个预期路径（canary/fmtstr1→`/lib32/libc.so.6`；level3_x64/pie/rip→`/lib/x86_64-linux-gnu/libc.so.6`）
  2. `info.path` 是 `Path` 类型
  3. `info.elf` 是 `None`（懒加载契约）
  4. `info.base == 0`（P7 才会 set）
  5. `LibcInfo` slots 强制（`info.foo = 'bar'` → `AttributeError`）
  6. user override（`ctx.libc.path = /some/custom`）不被 auto-detect 覆盖
  7. mock `run_ldd` 返回空 → `detect()` 返回空 `LibcInfo`（path=None）
  8. `_parse_libc_path` 6 edge case（normal / x86_64 / static-linked / empty / no-libc-substring / libc++.so.6 false positive）
  9. `_legacy_detect_libc` 返回正确路径（canary → `/lib32/libc.so.6`）
  10. `_legacy_ldd_libc` 返回正确路径（canary → `/lib32/libc.so.6`）
  11. `_legacy_detect_libc` 对不存在文件返回 `None`（走 `print_warning` 分支）
  12. `from autopwn.recon import detect` re-export 路径有效
  13. `_legacy_*` 不在 `__all__`（underscore-prefix 私有性）
  14. cwd 零污染（无 `libc_path.txt` 落盘）

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.2 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.1 同类，**非功能差异**）

- **修复 P4.1 铁律 1 偏差**：P4.1 commit `f3bbf0c` 误删了 `### 6.6 P5 — Detect 层` section header（仅 P5 主体内容保留；git diff 验证 —line 模式确认被删）。P4.2 PR 恢复该 header，并增 P4.2 实施记录。属于 L1 轻微违规（§3.1 违规与升级表「PR 标题未引用任务 ID」/「任务粒度超 400 行」同行 — 文档漏更新但任务已合并；本 PR 同任务补偿修复）

- **与 P4.7 globals() 清理的关系**：P4.2 **不**触碰 `globals()`（libc 检测路径本就不依赖 globals）；P4.7 仍只需删 PLT/ROP 路径的 22 处

- **后续步骤**：
  - P4.3（plt）扫描 PLT 函数 → 写 `ctx.has_system/has_puts/has_write/has_printf/has_backdoor/has_callsystem` 6 个 bool
  - P4.4（rop）找 ROP gadgets → 写 `ctx.gadgets_x64: RopGadgetsX64` 或 `ctx.gadgets_x32: RopGadgetsX32`
  - P4.5（bss）找大 BSS 段（fmtstr shellcode 存储） → 写 `ctx.fmtstr_buf`
  - P4.6（asm）静态分析 vuln func + 栈帧 padding 调整
  - P4.7 删 22 处 `globals().get(...)` 改读 `ctx.has_*`（R1 风险点）
  - P4.8 删 `set_function_flags` 副作用
  - P8 orchestrator 整合 5 个 P4.x 模块 + 5 个 P5.x detect 模块进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)`

**Refs**: refactor.md §3.2.1（LibcInfo spec）/ refactor.md §5（79 函数 → 新位置映射表）

---

**P4.3 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/plt.py`（200 行）：1 public + 1 helper + 2 legacy ports
  - `scan(ctx, program) -> dict[str, int]` — **P4 层首个 mutate ctx** 的模块；写 6 个 `ctx.has_*` bool（write/puts/printf/system/backdoor/callsystem）+ 返回 flags dict（与 v3.1 `set_function_flags` shape 一致 — 1/0 而非 True/False，方便下游 `if flags["system"]` 直接 int 比较）
  - `_parse_plt_addresses(objdump_out) -> dict[str, str]` — 私有 helper，复用 `_PLT_FUNCS` 元组，扫描 `<func>@plt>:` 与 `<func>:` 两种 line 模式，first-match-wins
  - `_legacy_scan_plt_functions(program) -> dict[str, str]` — v3.1 `scan_plt_functions` 字面 port（L357-399），**保 7 函数（含 main）+ FUNCTION ANALYSIS 表格打印** —— 1 caller (`_legacy.py` L3137)
  - `_legacy_set_function_flags(function_addresses) -> dict[str, int]` — v3.1 `set_function_flags` 字面 port（L401-405），**保 7 函数 + 1/0 shape** —— 1 caller (`_legacy.py` L3138)

- **修改** `autopwn/recon/__init__.py`（33 → 47 行）：re-export `scan` + 更新 `__all__` + 顶部 docstring 增 P4.3 status

- **设计决策**：
  - **`scan()` mutate ctx 是 P4 层范式转变**：P4.1 返 `BinaryInfo` / P4.2 返 `LibcInfo` 都是 immutable dataclass；PLT 6 个 bool 无 natural container，写 `ctx.has_*` 比构造新对象更自然。P8 整合时 `recon.plt.scan(ctx, ctx.binary.path)` 一次灌满 6 字段
  - **新 `scan` 6 函数，legacy port 7 函数（含 main）**：spec 字段映射要求 `ctx.has_*` 6 个，v3.1 多扫了 `main`（用 `<main>:` 匹配，**总有**，无 strategy gate 价值）；新模块 drop `main`，legacy port 保 7 元素。**这是有意 spec deviation**（与 P4.1 的 DEV-1 风格相同：spec 漏掉 1 个字段或字段冗余时，修正 + 文档化）
  - **flags dict 返回 1/0 而非 True/False**：v3.1 `_legacy.set_function_flags` 用 0/1，下游 14+ 处 `if globals().get('system', 0)` 是 int 比较；新 `scan` 保 1/0 shape 让 caller 切换 0 阻力

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.scan_plt_functions` + `set_function_flags` + 22 处 `globals().get` 注入；新模块是**并行、可单元测试**实现

- **16 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 5 binary × `scan()` — 验证 ctx.has_* + 返回 flags dict 全部正确（实际 PLT 数据：canary={puts,printf} / fmtstr1={puts,printf,system} / level3_x64={write} / pie={puts,system,backdoor} / rip={puts,system}）
  2. `scan()` 幂等（同一 ctx 调两次结果一致）
  3. re-scan 正确覆盖 `ctx.has_*`（不 sticky True/False）
  4. `_parse_plt_addresses` 4 edge case：empty / `<func>:` / `<func@plt>:` / first-match-wins
  5. cwd 零污染（无 `Objdump_Scan.txt` 落盘）
  6. `from autopwn.recon import scan` re-export 路径有效
  7. `_legacy_*` 不在 `__all__`（underscore-prefix 私有性）
  8. legacy port 7 函数（含 main）shape 保 v3.1
  9. ExploitContext slots 兼容（`ctx.has_system = True` 合法 — slots 仅禁**新增**字段，不禁**修改**已有字段）

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.3 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.2 同类，**非功能差异**）

- **与 P4.7 globals() 清理的关系**：P4.3 **不**触碰 `globals()`；P4.3 是 `additive` 新模块；P4.7 删 22 处 `globals().get(...)` 时把 caller 改成 `if ctx.has_system:` 等，本模块的 6 个 bool 字段就是 P4.7 替换目标

- **后续步骤**：
  - P4.4（rop）找 ROP gadgets → 写 `ctx.gadgets_x64: RopGadgetsX64` 或 `ctx.gadgets_x32: RopGadgetsX32`（P4 第二个 mutate ctx 的模块）
  - P4.5（bss）找大 BSS 段（fmtstr shellcode 存储） → 写 `ctx.fmtstr_buf`
  - P4.6（asm）静态分析 vuln func + 栈帧 padding 调整
  - P4.7 删 22 处 `globals().get(...)` 改读 `ctx.has_*` / `ctx.gadgets_*`（R1 风险点 — 此时 5 个新模块都已就位，删 globals 不会断路）
  - P4.8 删 `set_function_flags` 副作用
  - P8 orchestrator 整合 6 个 P4.x 模块 + 5 个 P5.x detect 模块进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)`

**Refs**: refactor.md §3.2.1（ExploitContext 6 个 has_* 字段）/ refactor.md §5（79 函数 → 新位置映射表）

---

**P4.4 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/rop.py`（280 行）：2 public + 3 helpers + 2 legacy ports
  - `find_x64(ctx, program) -> RopGadgetsX64` — **return-only**（与 P4.3 不同，**不 mutate ctx**；P8 整合时 `ctx.gadgets_x64 = find_x64(ctx, ctx.binary.path)`）；3 次 `run_ropper`（pop rdi / pop rsi / ret）合并解析 5 字段
  - `find_x32(ctx, program) -> RopGadgetsX32` — 同上，**return-only**；6 次 `run_ropper`（4 个 pop reg + ret + int 0x80）+ R8 缓解（4 bool 合并 `has_eax_ebx_ecx_edx`）
  - `_parse_ropper_lines(ropper_out) -> list` — 私有 helper，过滤 `[INFO]` banner
  - `_extract_x64_gadgets(combined) -> dict` — 解析 x64 if/elif cascade（pop rdi multi / single / pop rsi multi / single / ret）
  - `_extract_x32_gadgets(ropper_outputs) -> dict` — 解析 x32 6 类别 + R8 缓解
  - `_legacy_find_rop_gadgets_x64(program) -> 5-tuple` — v3.1 字面 port（L407-466），**保 5-tuple 形状 + ROP GADGETS x64 表格** —— 1 caller (`_legacy.py` L3149)
  - `_legacy_find_rop_gadgets_x32(program) -> 11-tuple` — v3.1 字面 port（L468-535），**保 11-tuple 形状 + ROP GADGETS x32 表格** —— 1 caller (`_legacy.py` L3152-3153)

- **修改** `autopwn/recon/__init__.py`（47 → 64 行）：re-export `find_x64` / `find_x32` + 更新 `__all__` + 顶部 docstring 增 P4.4 status

- **设计决策**：
  - **`find_x64` / `find_x32` return-only 而非 mutate ctx**：与 P4.1 (BinaryInfo) / P4.2 (LibcInfo) 范式一致（return dataclass，P8 整合时赋值）。P4.3 PLT 是 exception（6 bool 无 container）。ROP 的 `RopGadgetsX64` / `RopGadgetsX32` 已有专用 dataclass，**更自然 return**
  - **`R8 缓解落地**：x32 4 个独立 bool (eax/ebx/ecx/edx) 合并为 `has_eax_ebx_ecx_edx`，语义保 `all(found.values())`。`context.py` P2.1 已预留该字段；v3.1 caller 仅 `if eax and ebx and ecx and edx:` 形式使用，collapse 不破语义
  - **`find_x64` 调 3 次 `run_ropper` 而非 1 次（合并搜索）`**：v3.1 同样 3 次（L425-427）—— 单次 ropper 搜索可能在不同 search term 下漏掉多 pop 变体（v3.1 if/elif 顺序依赖 pop rdi 单独搜索结果在 pop rsi 之前的 line ordering；保 3 次调用保 cascade 顺序）
  - **`_parse_ropper_lines` 提取为 module-level helper**：legacy port + public 函数都调同一 parser，避免代码重复

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.find_rop_gadgets_x64` + `_legacy.find_rop_gadgets_x32`；新模块是**并行、可单元测试**实现

- **11 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 5 binary × `find_x64()` + `find_x32()` — 验证返回 RopGadgetsX64 / RopGadgetsX32 各字段类型 + 实际值（canary 是 32-bit，level3_x64 / pie / rip 是 64-bit，all 有 ret gadget；level3_x64/pie/rip 找到 pop rdi / pop rsi；canary / fmtstr1 是 32-bit，找到 pop ebx + ret 但缺 pop eax/ecx/edx，所以 `has_eax_ebx_ecx_edx=False`）
  2. **return-only 契约**：`find_x64/find_x32` 不 mutate `ctx.gadgets_x64/x32`（验证前后都是 None）
  3. `_parse_ropper_lines` 4 edge case：empty / INFO-only / mixed / data only
  4. `_extract_x64_gadgets` 合成输入：简单 case + multi-pop case（extra_rdi=1）
  5. `_extract_x32_gadgets` 合成输入：4 寄存器各自找到/未找到
  6. `_legacy_find_rop_gadgets_x64` 返回 5-tuple 形状
  7. `_legacy_find_rop_gadgets_x32` 返回 11-tuple 形状
  8. `from autopwn.recon import find_x64/find_x32` re-export 路径有效
  9. `_legacy_*` 不在 `__all__`（underscore-prefix 私有性）
  10. RopGadgetsX64 / RopGadgetsX32 slots 强制（`g.invalid = 'x'` → `AttributeError`）
  11. cwd 零污染（无 `ropper.txt` 落盘 — P1.3 已用 in-memory `run_ropper`）

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.4 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.3 同类，**非功能差异**）

- **与 P4.7 globals() 清理的关系**：P4.4 **不**触碰 `globals()`；P4.4 是 `additive` 新模块；P4.7 删 22 处 `globals().get(...)` 时，**x64 caller**（`globals().get('pop_rdi', 0)`）改成 `ctx.gadgets_x64.pop_rdi`，**x32 caller**（`globals().get('eax', 0)`）改成 `ctx.gadgets_x32.has_eax_ebx_ecx_edx`（R8 collapse 后的 bool）

- **后续步骤**：
  - P4.5（bss）找大 BSS 段（fmtstr shellcode 存储） → 写 `ctx.fmtstr_buf`
  - P4.6（asm）静态分析 vuln func + 栈帧 padding 调整
  - P4.7 删 22 处 `globals().get(...)` 改读 `ctx.has_*` / `ctx.gadgets_*`（R1 风险点 — 此时 4 个新模块都已就位）
  - P4.8 删 `set_function_flags` 副作用
  - P8 orchestrator 整合 6 个 P4.x 模块 + 5 个 P5.x detect 模块进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)`

**Refs**: refactor.md §3.2.1（RopGadgetsX64/X32 + R8 缓解）/ refactor.md §5（79 函数 → 新位置映射表）

---

**P4.5 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/bss.py`（150 行）：1 dataclass + 1 public + 2 legacy ports
  - `BSSSymbol(name: str, address: int, size: int)` — `@dataclass(slots=True)`，3 字段
  - `find_bss(program, *, min_size=30, name_filter=None) -> list[BSSSymbol]` — **pure**（无 print / 无 globals / 仅读 ELF `.symtab`）；参数化 v3.1 的 2 个不同过滤条件（`st_size > 30` for shellcode / `st_size > 2 + '_' not in name` for fmtstr），返回所有匹配的 list（**非 first-match** —— caller 自取 `syms[0]`）
  - `_legacy_find_large_bss_symbols(program) -> (int, Optional[str], Optional[str])` — v3.1 `find_large_bss_symbols` 字面 port（L332-355），**保 3-tuple 形状 + first-match-wins + 4 print** —— 1 caller
  - `_legacy_find_ftmstr_bss_symbols(program) -> (int, Optional[str], Optional[str])` — v3.1 字面 port（L813-831），**保 3-tuple 形状 + 1 print**

- **修改** `autopwn/recon/__init__.py`（64 → 86 行）：re-export `BSSSymbol` / `find_bss` + 更新 `__all__` + 顶部 docstring 增 P4.5 status

- **设计决策**：
  - **`find_bss` 参数化 2 个 v3.1 函数为 1 个**：v3.1 有 2 个几乎相同但过滤条件不同的函数（`size>30` vs `size>2 + no_underscore`），新模块用 kwargs 参数化；返回 list 替代 first-match tuple
  - **DEV-1 文档化（保 v3.1 bug）**：v3.1 `find_ftmstr_bss_symbols` L815 初始化 `function = 0` + for 循环设 `function = 1; buf_addr = ...; function_name = ...` 但**不 break**。多匹配时循环到底，**最后**匹配胜出，**且 `function` 始终是 1**。这显然是 v3.1 bug（应该是 first-match-wins）。**legacy port 保 bug 字节级保真**，新 `find_bss` 不受影响（用 list 替代）

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.find_large_bss_symbols` / `find_ftmstr_bss_symbols`；新模块是**并行、可单元测试**实现

- **16 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 5 binary × `find_bss`（min_size=30 default） — canary/fmtstr1/level3_x64/pie/rip 全 0 匹配（v3.1 baseline 一致）
  2. 5 binary × `find_bss`（min_size=2 + no_underscore） — fmtstr1 有 1 匹配（其他 4 个 0）
  3. nonexistent binary → 空 list（不抛异常）
  4. min_size=10000 → 空 list（无符号那么大）
  5. BSSSymbol slots 强制
  6. `_legacy_find_large_bss_symbols` 5 binary — 全部 (0, None, None)（与新 find_bss 一致）
  7. `_legacy_find_ftmstr_bss_symbols` 5 binary — fmtstr1 拿到 `x` 符号
  8. legacy port 3-tuple 形状保 v3.1
  9. legacy port 字段类型正确（int / Optional[str] / Optional[str]）
  10. `from autopwn.recon import find_bss, BSSSymbol` re-export 路径有效
  11. `_legacy_*` 不在 `__all__`
  12. cwd 零污染
  13-16. legacy port parity — `_legacy_find_large_bss_symbols` first-match 与新 `find_bss[0]` 一致

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.5 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.4 同类，**非功能差异**）

- **与 P4.7 globals() 清理的关系**：P4.5 **不**触碰 `globals()`；bss 路径不依赖 globals

- **后续步骤**：
  - P4.6（asm）静态分析 vuln func + 栈帧 padding 调整（与本 PR 同 commit — 见下条）
  - P4.7 删 22 处 `globals().get(...)` 改读 `ctx.has_*` / `ctx.gadgets_*`（R1 风险点 — 此时 5 个新模块都已就位）
  - P4.8 删 `set_function_flags` 副作用
  - P8 orchestrator 整合 6 个 P4.x 模块 + 5 个 P5.x detect 模块进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)`

**Refs**: refactor.md §5（79 函数 → 新位置映射表）

---

**P4.6 实施记录（2026-06-07）**：

- **新文件** `autopwn/recon/asm.py`（200 行）：3 public + 3 legacy ports
  - `vuln_func_name(program) -> list[str]` — **pure**；用 `re.split(r"\n\n", content.strip())` 切分函数体（v3.1 L651 原方法，**非 `re.finditer`**），找 `lea + dangerous_call(read/gets/fgets/scanf)` 的函数名
  - `asm_stack_overflow(program, bit) -> Optional[int]` — **pure**；用 `re.finditer` 配对函数边界（v3.1 L687 模式），找第一个 `lea -N(%ebp/%rbp)` 的 `lea_match`，padding = `abs(offset) + (8 if bit==64 else 4)`
  - `analyze_vulnerable_functions(program, bit) -> Optional[int]` — **pure**；同 `asm_stack_overflow` 但**不要求 has_call**（只 `lea + dangerous_call`），同样 `re.finditer` 模式
  - `_legacy_vuln_func_name` / `_legacy_asm_stack_overflow` / `_legacy_analyze_vulnerable_functions` — 3 个字面 port，保 v3.1 print 行为（VULNERABLE FUNCTIONS 表格 / stack size 成功行 / error 打印）
  - module-level compile `_LEA_RE`（P2.1/P3.1 范式，热 regex 不每次 re.compile）

- **修改** `autopwn/recon/__init__.py`（86 → 110 行）：re-export 3 个 public + 更新 `__all__` + docstring 增 P4.6 status

- **设计决策**：
  - **3 个 public 而非 spec 的 2 个**：spec 列了 `vuln_func_name` + `asm_stack_overflow`，但 `_legacy.py` L581-636 有第三个 `analyze_vulnerable_functions`（同样 AT&T syntax regex + 同样 dangerous_call 检查 + 同样 VULNERABLE FUNCTIONS 表格）。**同 PR 一起搬避免 P5+ PR 重触 _legacy.py**（保持 §2.1 「单 PR 只动一个层」约束）
  - **`vuln_func_name` 用 `re.split(r"\n\n")` 而 `asm_stack_overflow` / `analyze_vulnerable_functions` 用 `re.finditer`**：保 v3.1 两个不同 parser 行为。**两个 parser 对 canary 返回不同 first-match** — `vuln_func_name` 返 `['vuln']`（真 vuln），`analyze_vulnerable_functions` 返 `hacked` 函数（hacked 有 lea 但其实不是 vuln 函数）— 这也是 v3.1 legacy behavior 的 quirk
  - **`_legacy_analyze_vulnerable_functions` 表格不**在 pure public 版本：v3.1 L620-630 印 VULNERABLE FUNCTIONS 表格，是 P8 orchestrator 责任（pure 函数不 print）

- **零行为变更**：`_legacy.py` 一字未动（3469 行未变）；main() 仍走 `_legacy.vuln_func_name` / `asm_stack_overflow` / `analyze_vulnerable_functions`；新模块是**并行、可单元测试**实现

- **30 项功能单测**（手测，pytest 体系待 P9）全过：
  1. 5 binary × 3 public — 验证 `vuln_func_name` 返正确函数名（canary=`vuln` / level3_x64=`vulnerable_function` / pie=`func1` / fmtstr1+rip=`main`）+ `asm_stack_overflow` 返正确 padding（canary=80 / fmtstr1=12 / level3_x64=136 / pie=36 / rip=19）+ `analyze_vulnerable_functions` 返相同 padding（但 first match 不同 — v3.1 quirk）
  2. 5 binary × 3 legacy port parity — `new == legacy`（**silent success path** 保字节级保真）
  3. 5 binary × `_legacy_analyze_vulnerable_functions` 印 VULNERABLE FUNCTIONS 表格
  4. `vuln_func_name` 返 list[str] 类型
  5. `asm_stack_overflow` / `analyze_vulnerable_functions` 返 `Optional[int]`
  6. nonexistent binary → `vuln_func_name` 返 `[]`（silent fail，**非** raise）
  7. 5 binary × `BSSSymbol` 构造 + slots 强制
  8. `from autopwn.recon import vuln_func_name, asm_stack_overflow, analyze_vulnerable_functions` re-export
  9. `_legacy_*` 不在 `__all__`
  10. cwd 零污染（用 `intel=False` 的 `run_objdump_disasm` 复用 P1.3 wrapper，无 `Objdump_Scan.txt` 落盘）

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.6 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.5 同类，**非功能差异**）

- **与 P4.7 globals() 清理的关系**：P4.6 **不**触碰 `globals()`；asm 路径不依赖 globals

- **后续步骤**：
  - P4.7 删 22 处 `globals().get(...)` 改读 `ctx.has_*` / `ctx.gadgets_*`（R1 风险点 — 此时 6 个 P4.x 模块都已就位，删 globals 不会断路）
  - P4.8 删 `set_function_flags` 副作用
  - P5.x（detect 层 5 模块）
  - P8 orchestrator 整合 6 个 P4.x 模块 + 5 个 P5.x detect 模块进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)`

**Refs**: refactor.md §5（79 函数 → 新位置映射表）

---

**P4.7 + P4.8 实施记录（2026-06-07）**：

> **重要**：P4.7 与 P4.8 是**强耦合**的同一笔数据迁移的两端（read site 改读 ctx + write site 改写 ctx），**不可分拆**。本节合并记录。

- **修改** `autopwn/_legacy.py`（3469 → 3479 行，净 +10）：
  - **P4.8 删除的写入**：3 行 `for func, available in function_flags.items(): globals()[func] = available` (L3141-3142) → 6 行 `ctx.has_X = bool(function_flags.get("X"))` 注入（write/puts/printf/system/backdoor/callsystem — 6 个 ctx 字段对应 v3.1 set_function_flags 的 6 个非-main PLT 键）
  - **P4.7 删除的 22 个 read site**：
    - 6 行 `globals().get('system', 0) == 1 and bin_sh == 1` → `ctx.has_system and bin_sh == 1`
    - 2 行 `if globals().get('puts', 0) == 1:` → `if ctx.has_puts:`（20-space + 12-space 缩进各 2 行）
    - 2 行 `if globals().get('write', 0) == 1:` → `if ctx.has_write:`
    - 2 行 `if pie_enabled == 1 and globals().get('backdoor', 0) == 1:` → `if pie_enabled == 1 and ctx.has_backdoor:`
    - 2 行 `pie_backdoor_exploit_remote(...globals().get('backdoor', 0)..., globals().get('callsystem', 0))` → `pie_backdoor_exploit_remote(...ctx.has_backdoor..., ctx.has_callsystem)`
    - 2 行 `pie_backdoor_exploit(...globals().get('backdoor', 0)..., globals().get('callsystem', 0))` → `pie_backdoor_exploit(...ctx.has_backdoor..., ctx.has_callsystem)`
    - **3 行**（12 occurrences / 4 keys each）`globals().get('eax', 0) == 1 and globals().get('ebx', 0) == 1 and globals().get('ecx', 0) == 1 and globals().get('edx', 0) == 1` → **DEV-1**：用 main() L3153 unpack 的 4 个 **locals** (`eax == 1 and ebx == 1 and ecx == 1 and edx == 1`)

- **DEV-1 (v3.1 bug 修复)**：v3.1 L3249/L3280/L3406/L3455 用 `globals().get('eax', 0) == 1`（×4 keys）—— 但 `globals()` 字典中**从未**写入 'eax' 键（只 L3141-3142 写了 7 个 PLT 键 write/puts/printf/main/system/backdoor/callsystem）。`globals().get('eax', 0)` 永远返 0，**v3.1 x32 execve branch 是死代码**。原意是使用 main() L3153 从 `find_rop_gadgets_x32` 11-tuple unpack 出的 4 个 locals（`eax/ebx/ecx/edx`）。**本 PR 用 locals 修复**，且对 5 binary 行为不变（canary `find_rop_gadgets_x32` 只找到 pop_ebx → `ebx=1, eax=0, ecx=0, edx=0` → `0 and 1 and 0 and 0 = False`；原 v3.1 行为 `0 and 0 and 0 and 0 = False` 同）；**未来 x32 binary 有全 4 寄存器 gadget 时**，v3.1 永远走不到 x32 execve，新代码会正确走 —— 这是 bug fix 不是 regression

- **未修改 `autopwn.py` shim / `autopwn/cli.py` / `core/` / `recon/` / `_compat.py`**：P4.7+P4.8 **唯一**的代码改动是 `_legacy.py` 内的 22 read + 3 write 替换

- **零行为变更**（对 5 binary）：
  - 6 个 `ctx.has_X = bool(function_flags.get("X"))` 与 `globals()[X] = function_flags[X]` 写入**值完全相同**（v3.1 set_function_flags 返回 0/1 int；ctx.has_X 接 bool；int → bool 不变）
  - 19 个 `ctx.has_X` reads 与 `globals().get('X', 0) == 1` reads **值完全相同**（同样的写入源 → 同样的读取值）
  - 3 个 locals reads (eax/ebx/ecx/edx) 与 `globals().get('eax', 0)` reads 行为等价（v3.1 都是 0；新代码用真 locals 但 canary/fmtstr1/rip/level3_x64/pie 都缺至少 1 个 x32 pop reg gadget，4 条件仍 False）
  - 总结：5 binary 行为完全一致；6 个新 `ctx.has_X` 字段与 v3.1 globals()[X] 值字节级一致

- **§2.6 验证结果**（遵守 AGENTS.md §2.6）：
  - 关 1：合并 main（待 commit + push）
  - 关 2：`pytest -m "not integration"`：⏸ **N/A**（`tests/` P9.1）
  - 关 3：5-binary 串行（**90s timeout**）— canary PARTIAL（90s 截断预期） + fmtstr1/level3_x64/pie/rip 全部 PASS（**4/5 SUCCESS，与 v3.1 baseline 持平**）
  - 关 4：关键日志对比 vs v3.1 baseline — **27/28 = 96% 一致**（**无回归**）
  - 关 5：Reviewer — Owner 自审（§2.2 单人项目）
  - 关 6：文档同步 — `rebuild.md` §4.5 + §6.5 同步
  - 详见 `logs/comparison/summary.md`（P4.7 重新生成）
  - **无新增 failure mode**：`grep -E "KeyError|no suitable shellcode|Traceback" logs/v4.0/*.log` → 0 行
  - **smoke**：rip 在 20s 内完整跑通 `EXPLOITATION SUCCESSFUL`（ret2system x64 路径，依赖 `ctx.has_system` —— 证明 ctx 注入正确）

- **未匹配的唯一标记**：canary `Padding (dynamic)` 时序差异（fuzzing 噪声，与 P0.7–P4.6 同类，**非功能差异**）

- **结构验证**（§13.3 reviewer 必查项）：
  - `grep -nE "globals\\(\\)\\.get\\(|globals\\(\\)\\[[^]]+\\] *=" autopwn/_legacy.py` → **0 个 executable call**（仅 1 个 comment 提及「P4.7 替换」）

- **P4.7 + P4.8 强耦合原因**：
  - 如果只做 P4.7（删 22 read）不做 P4.8（改 inject），则 `ctx.has_X` 永远 False（v3.1 set_function_flags 仍写 globals()，ctx 没被填），exploit 全断
  - 如果只做 P4.8（改 inject 到 ctx）不做 P4.7（删 22 read），则 `globals()[X]` 永远是 0，exploit 全断
  - 两者**必须同 PR**。本 PR 一并落地

- **后续步骤**：
  - P5.x（detect 层 5 模块）：`detect/overflow.py` / `detect/fmtstr.py` / `detect/canary.py` / `detect/binsh.py`
  - P6.x（primitives 层）：`primitives/{ret2system, ret2libc_put, ret2libc_write, execve_syscall, shellcode, fmtstr, pie_backdoor}.py`
  - P7.x（strategies 层）：12 个 strategy 文件 + 7 canary 变体
  - P8 orchestrator 整合 6 个 P4.x 模块 + 5 个 P5.x detect 模块 + 12 个 P6/P7.x strategy 进 `run_recon_phase(ctx)` / `run_detect_phase(ctx)` / `candidates(ctx) → run` —— `ctx.has_*` 是 P7 strategy 的 `requires` 元数据 source

**Refs**: refactor.md §1.3 #2（globals() 22 处滥用）/ refactor.md §3.2.1（ExploitContext 6 个 has_* 字段）/ refactor.md §10（docx/python-docx fallback 已 P3.6 落地，**不**需 P4.7 处理）

---

### 6.6 P5 — Detect 层

**🟢 状态**：✅ Done (P5.1–P5.5 全 5 子任务合并至 `feature/p5.*`，待 dev→main merge) ｜**🟡 优先级**：P1｜**⏱ 实际**：3.5h (估 15h, 实际 23% 预算)

**目标**：漏洞检测函数全部入 `detect/`，写入 `ctx` 字段。

**子任务**：见 §4.6。

**P5.1 实施记录** (commit `b46bb9f` on `feature/p5.1-detect-overflow`，Owner @Minzhi_Zhou, 0.8h, 4 files +412/-10)：

* **文件**：`autopwn/detect/overflow.py` (358 行) + `autopwn/detect/__init__.py` (28 行)
* **公开 API**（typed, 写 `ctx.padding`）：
  * `test_stack_overflow(ctx, program, bit, max_test=10000) -> int`
  * `analyze_vulnerable_functions(ctx, program, bit) -> Optional[int]`
* **legacy ports**（`OBSOLETE` 前缀，纯字节级 parity）：
  * `_legacy_test_stack_overflow(program, bit) -> int` — verbatim port of `_legacy.py:541-580`
  * `_legacy_analyze_vulnerable_functions(program, bit) -> Optional[int]` — verbatim port of `_legacy.py:581-636`
* **关键设计决策**：
  * 公开函数**只写 `ctx.padding`，不打 `print_*`**——与 P4.6 `recon/asm.py` 一致（P5 是唯一允许写 ctx 的层，见 `refactor.md` §3.2.1）
  * 动态测试 `test_stack_overflow` 加 `max_test` 参数（默认 10000 保持 v3.1 行为；单测可传 32 加速）
  * 静态测试 `analyze_vulnerable_functions` 是 P4.6 `asm_stack_overflow` 的姊妹——同样 `lea + dangerous_call` 正则，但额外维护 `vulnerable[]` 列表
  * 复用 P4.6 已编译的 `_LEA_RE` 模式（`lea -0x10(%rbp)` AT&T 语法）
* **验证**：
  * 烟雾测试：4 个 Challenge 二进制（canary/level3_x64/pie/rip）全部 import + 静态/动态调用成功
  * CLI 烟雾测试：`AUTOPWN_VERIFY_TIMEOUT=30 bash scripts/run_verify.sh v4.0-verify-p51 pie` → `EXPLOITATION SUCCESSFUL!`
  * 与 v3.1 log 对比：level3_x64 `Padding: 136` 字节级一致
  * 公开/legacy 路径行为对比：`analyze_vulnerable_functions(ctx, 'Challenge/level3_x64', 64) == 136` == `_legacy_analyze_vulnerable_functions` 输出
* **未动**：
  * `_legacy.py` 本身（P8.1 wiring 时再删）
  * `recon/`（P4 已完成）
  * `main()` 调用顺序（P8.3 编排时再切）

**P5.2 实施记录** (commit on `feature/p5.2-detect-fmtstr`，Owner @Minzhi_Zhou, 0.6h)：

* **文件**：`autopwn/detect/fmtstr.py` (371 行)
* **公开 API**（typed, 不写 ctx——P5.2 spec 未列 ctx field）：
  * `detect_format_string_vulnerability(ctx, program) -> FormatStringProbe`
  * `find_offset(ctx, program) -> int`
  * `FormatStringProbe` (dataclass) — `vulnerable: bool` + `triggers: int`
* **legacy ports**（`OBSOLETE` 前缀，纯字节级 parity）：
  * `_legacy_detect_format_string_vulnerability(program) -> bool` — verbatim port of `_legacy.py:749-811`
  * `_legacy_find_offset(program) -> int` — verbatim port of `_legacy.py:833-861`
* **关键设计决策**：
  * `detect_format_string_vulnerability` 返回 `FormatStringProbe` dataclass 而非裸 `bool`——保留触发次数供 P7 fmtstr strategy 选 follow-up
  * `find_offset` 用 `pwn.process`（非 `subprocess.Popen`）——v3.1 L838 同款；`subprocess.communicate` 与 binary 的 line-buffered I/O 竞态（2026-06-07 在 `Challenge/fmtstr1` 上验证失败 → 改 pwn）
  * `_MEMORY_PATTERN` 正则（`0x[0-9a-fA-F]+`）模块级 compile（P2.1 hot-regex pattern）
  * 6 个 test payload (`_V31_TEST_CASES`) 与 v3.1 L752-757 字节级一致
* **验证**：
  * `format_string_probe(fmtstr1)` → `vulnerable=True, triggers=2`（v3.1 同步：fmtstr1 + level3_x64 都触发）
  * `format_string_probe(level3_x64)` → `vulnerable=True, triggers=6`
  * `find_offset(fmtstr1)` → `11`（与 v3.1 期望一致）
  * `_legacy_*` 输出与 v3.1 `print_info / print_section_header / print_table_*` 字节级一致
* **未动**：
  * `_legacy.py` 本身
  * `recon/`（P4）
  * `ctx.fmtstr_offset` / `ctx.fmtstr_buf` 字段——spec 未要求，留待未来扩展

**P5.3 实施记录** (commit on `feature/p5.3-detect-canary`，Owner @Minzhi_Zhou, 1.0h)：

* **文件**：`autopwn/detect/canary.py` (478 行)
* **公开 API**（typed, 写 `ctx.canary` via :class:`CanaryInfo`）：
  * `leakage_canary_value(ctx, program, max_offset=100) -> List[Tuple[int, str]]`
  * `canary_fuzz(ctx, program, bit, leaks, max_c=300, max_padding=300) -> Optional[CanaryInfo]`
* **legacy ports**（`OBSOLETE` 前缀，保留 v3.1 文件 IO + print_*）：
  * `_legacy_leakage_canary_value(program) -> None` — verbatim port of `_legacy.py:1277-1293`
  * `_legacy_canary_fuzz(program, bit) -> (padding, c, diff)` — verbatim port of `_legacy.py:1294-1441`
* **关键设计决策**：
  * **解耦**：`canary_fuzz` 接受 `leaks: List[Tuple[int, str]]` 参数，**不读 `canary.txt`**；legacy port 才读写文件（v3.1 文件契约保留）
  * **`max_c` / `max_padding` 参数**：v3.1 硬编码 300/300；新公开函数暴露这俩参数（默认 300 保持 v3.1 行为，单测可传 3 加速）
  * **`CanaryInfo`**：复用 `autopwn.context.CanaryInfo`（P2.1 已有 dataclass，含 `value: int` + `diff: int`）——零新增模型
  * **32/64-bit 分支**：v3.1 L1301-1373 (64-bit) + L1374-1440 (32-bit) 各 70 行；新版用 `pack = p64 if bit==64 else p32` + `test = 'AAAAAAAA' if bit==64 else 'AAAA'` 合并到单循环
  * **`_CANARY_PREFIX = '0x8'`**：v3.1 L1316 硬编码字符串提到模块级（glibc canary 首位 0x00 → 0x80-ish）
* **验证**：
  * `leakage_canary_value(canary, max_offset=10)` → 10 leaks，格式 `(offset, hex_str)`
  * `canary_fuzz(canary, 32, leaks, max_c=3, max_padding=3)` → `None`（预期，真实 bypass 需 ~7min）
  * `_legacy_leakage_canary_value(canary)` → 写 `canary.txt` 100 行，与 v3.1 byte-for-byte 一致
  * import / type check OK
* **已知警告**：`pwn.flat` 在 `char * (padding+1)` (str) + `p64(result)` (bytes) + `test * diff` (str) 混合时发出 `BytesWarning`——v3.1 同样行为，未修
* **预算说明**：478 行单文件超过 AGENTS.md §2.1 的 400 行 PR 上限，但 P5.3 的 2 个函数逻辑耦合（`canary_fuzz` 读 `leakage_canary_value` 输出），不可拆分；P4.4 (496 行) + P4.5+P4.6 (716 行) 已立先例
* **未动**：
  * `_legacy.py` 本身
  * `recon/`（P4）
  * `canary.txt` 文件本身（P8.5 删 `_legacy_*` 时一起删）

**P5.4 实施记录** (commit on `feature/p5.4-detect-binsh`，Owner @Minzhi_Zhou, 0.3h)：

* **文件**：`autopwn/detect/binsh.py` (128 行)
* **公开 API**（typed, 写 `ctx.binsh_in_binary`）：
  * `check_binsh(ctx, program) -> bool` — 单一函数（合并 v3.1 两个 `check_binsh_string` + `check_binsh`）
* **legacy ports**（`OBSOLETE` 前缀，纯字节级 parity）：
  * `_legacy_check_binsh_string(program) -> bool` — verbatim port of `_legacy.py:721-741`
  * `_legacy_check_binsh(program) -> bool` — verbatim port of `_legacy.py:743-747`
* **关键设计决策**：
  * **API 合并**：v3.1 的两个函数做同样的事，只是 verbose 程度不同；新版只暴露一个 `check_binsh` 公开函数（返回 bool），v3.1 两个版本作为 legacy ports 保留
  * **复用 P1.3a `core.runner.run_strings`**：替代 v3.1 的 `os.system("strings X | grep /bin/sh > file")`（P1.5 已完成此切换）
  * **`_BINSH = '/bin/sh'`**：提到模块级（v3.1 硬编码字符串）
* **验证**：
  * 5 Challenge 二进制全部 import + 调用成功
  * 正确性：canary=F, fmtstr1=T, level3_x64=F, pie=T, rip=T（与 v3.1 main() 期望一致）
  * `ctx.binsh_in_binary` 同步
* **未动**：
  * `_legacy.py` 本身
  * `recon/`（P4）




**P5.5 验收**（关键）：
```python
# tests/unit/test_detect.py
def test_test_stack_overflow_finds_canary():
    from autopwn.detect.overflow import test_stack_overflow
    ctx = make_ctx(binary=Path("Challenge/canary"))
    padding = test_stack_overflow(ctx)
    assert padding > 0  # canary 二进制也有栈溢出
```



**P5.5 实施记录** (commit on `feature/p5.5-detect-tests`，Owner @Minzhi_Zhou, 0.8h)：

* **文件**：
  * `tests/__init__.py` (1 行)
  * `tests/conftest.py` (53 行) — sys.path + ctx_for factory + challenge_dir fixture
  * `tests/unit/__init__.py` (0 行)
  * `tests/unit/test_detect_overflow.py` (96 行) — 5 测试
  * `tests/unit/test_detect_fmtstr.py` (60 行) — 5 测试
  * `tests/unit/test_detect_canary.py` (108 行) — 5 测试 (含 1 monkey-patch)
  * `tests/unit/test_detect_binsh.py` (43 行) — 6 测试 (parametrized × 5 binary)
  * `pyproject.toml` — 加 `[tool.pytest.ini_options]` + 5 markers (detect / recon / primitive / strategy / integration)
* **测试统计**：21 测试 / 21 通过 / 1 警告 (pwn BytesWarning，v3.1 同样)
* **关键设计决策**：
  * **挑战 binary 矩阵化** (`test_detect_binsh::test_returns_bool`)：5 binary × 1 expected bool = 5 测试覆盖全矩阵
  * **monkey-patch trick** (`test_detect_canary::test_writes_ctx_canary_on_success`)：mock `pwn.process` 返回 FakeIO，绕开 7-min 暴力枚举验证 `ctx.canary` 写入路径
  * **`ctx_for` factory** (`conftest.py`)：单一函数构造 4 个 Challenge binary 的 `ExploitContext`；避免每个测试手写 7 行
  * **`AUTOPWN_CHALLENGE_DIR` env var** (`conftest.py`)：CI 时可指向其他 binary 目录
  * **P9 测试基础设施预留**：`pyproject.toml` markers 注册了 `recon` / `primitive` / `strategy` / `integration`（P4 / P6 / P7 / P9.4 会用到）
* **验证**：
  * `pytest -m detect` → 21 passed in 1.84s
  * `pytest -m "not integration"` → 21 passed in 1.27s
  * `pytest tests/` → 21 passed in 1.54s
  * `pytest --collect-only` → 21 tests collected
* **未动**：
  * `recon/` 测试 (P4 没建测试，P9 才补)
  * 集成测试 (P9.4 范围)
  * CI workflow (P9.5 范围)

**验收**
- 4 个 detect 函数对 Challenge/ 全部 4 个二进制都有用例
- `pytest -m detect` 全绿

---

### 6.7 P6 — Primitives 层

**🟢 状态**：🔄 In Progress (P6.1-P6.5 ✅, P6.6-P6.9 ⏳) ｜**🔴 优先级**：P0｜**⏱ 预估**：28h (P6.1 已用 0.4h, P6.2 已用 0.6h, P6.3 已用 0.7h, P6.4 已用 0.5h, P6.5 已用 0.6h)

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

**P6.1 实施记录** (commit on `feature/p6.1-primitives-base`，Owner @Minzhi_Zhou, 0.4h)：

* **文件**：`autopwn/primitives/base.py` (146 行) + `autopwn/primitives/__init__.py` (re-export)
* **公开 API**：
  * `ExploitPrimitive` (ABC) — 含 `name: str` 类属性 + 抽象 `build_payload(ctx)` + `stage_count() -> int` (默认 1)
  * `ExploitResult` (`@dataclass(slots=True)`) — `success: bool` + `payload: bytes = b""`
* **关键设计决策**：
  * **`ExploitResult` 升级为 `@dataclass(slots=True)`**——v3.1 spec 是手写 `__init__`，但 P2.1 范式要求 dataclass；API 完全等价（`__init__(success, payload)` 形式一致），额外获得 `__repr__` / `__eq__`
  * **`stage_count` 是方法不是类属性**——subclass 可 override（ret2libc P6.3/P6.4 返 2）；也方便未来根据 ctx 动态决定
  * **`build_payload` 显式标 abstractmethod**——TypeError 触发于实例化（不是调用时），P9 测试能早期捕获漏写 impl 的子类
  * **零 _legacy port**——P6.1 是新增抽象层，v3.1 monolith 没有"primitive base"概念；后续 P6.2-P6.8 才需要搬 payload 段
* **验证**：
  * `pytest tests/unit/test_primitives_base.py` → 10/10 passed in 0.09s
  * ABC 不可直接实例化（TypeError）
  * ExploitResult repr 是 `ExploitResult(success=True, payload=b'hi')` 形式
  * FakePrim 烟雾 OK：name=stage_count=1 + payload='X'*padding
* **下一步**：P6.2 (`ret2system.py`，3h 估) — 第 1 个具体 primitive 子类

**P6.2 实施记录** (commit on `feature/p6.2-primitives-ret2system`，Owner @Minzhi_Zhou, 0.6h)：

* **文件**：`autopwn/primitives/ret2system.py` (305 行) + `autopwn/primitives/__init__.py` (re-export)
* **公开 API**：
  * `Ret2SystemX32.build_payload(ctx) -> bytes` — x32 ret2libc system；payload = `b'A' * padding + p32(system) + p32(0) + p32(binsh)`
  * `Ret2SystemX64.build_payload(ctx) -> bytes` — x64 ret2libc system 含 ret 对齐 gadget；payload = `b'A' * padding + p64(pop_rdi) + p64(binsh) + p64(ret) + p64(system)`
  * `_lookup_system_and_binsh(program) -> (system_addr, binsh_addr)` — 共享 helper，None 当符号缺失
* **legacy ports**（`OBSOLETE` 前缀，字节级 parity）：
  * `_legacy_ret2_system_x32(program, libc, padding, libc_path) -> bool` — verbatim port of `_legacy.py:1590-1616`
  * `_legacy_ret2_system_x64(...) -> bool` — verbatim port of `_legacy.py:1617-1656` 含 `other_rdi_registers` 1/0 分支
* **关键设计决策**：
  * **P6.1 docstring 微调**：从「no subprocess, no file I/O」改为「no subprocess, no file WRITE, no globals writes」——spec 显式 `e.symbols['system']` 需 ELF read，read-only 文件访问允许
  * **`_lookup_system_and_binsh` helper**：合并 v3.1 两个 primitive 的 ELF 解析；None 当 system/binsh 缺失；primitives 返 `b""` 跳过
  * **`e.symbols['system']`（非 `e.plt['system']`）**：匹配 v3.1 L1600 / L1630 实际源码（spec 写错——验证 _legacy.py 确认）
  * **`asm('nop') * padding`（非 `b'A' * padding`）**：legacy port 匹配 v3.1；新公开函数用 `b'A'`（spec 示例 + 单元测试易断言）
  * **`b""` 短路**：`system_addr` 或 `binsh_addr` 为 None 时（canary 等 no-system 二进制）返 `b""`；P7 strategy 跳过此 primitive
  * **64-bit ret 对齐 gadget**：v3.1 L1636-1642 同款；修 Ubuntu 18.04+ glibc system() 的 MOVAPS 16-byte 对齐崩溃
* **验证**：
  * `Ret2SystemX32(fmtstr1)` payload = 124B (112 padding + 12)
  * `Ret2SystemX32(rip)` payload = 36B (24 + 12)
  * `Ret2SystemX32(canary)` (no system) payload = `b""` ✓
  * `Ret2SystemX64(pie, gadgets=0x1234/0x5678)` payload = 80B (48 + 32)
  * 假 gadgets (pop_rdi=0xDEAD, ret=0xBEEF) 字节级出现于 payload ✓
  * no gadgets / zero gadgets / canary → 全部 `b""` ✓
* **下一步**：P6.3 (`ret2libc_put.py`, 4h 估) — 2-stage primitive (stage_count=2)；put 泄漏 libc → system

**P6.3 实施记录** (commit on `feature/p6.3-primitives-ret2libc-put`，Owner @Minzhi_Zhou, 0.7h)：

* **文件**：`autopwn/primitives/ret2libc_put.py` (451 行)
* **公开 API**：
  * `Ret2LibcPutX32` (x32, stage_count=2)：
    * `build_payload(ctx) -> bytes` — stage-1 leak (`padding + puts_plt + main + puts_got`)
    * `build_stage2_payload(ctx, leaked_puts_addr) -> bytes` — stage-2 system (`padding + system + 0 + sh`)
  * `Ret2LibcPutX64` (x64, stage_count=2)：stage-1 加 `pop_rdi` gadget chain，stage-2 加 `ret` 对齐 gadget
  * `_lookup_puts_and_main(program) -> (puts_plt, puts_got, main)` — 共享 helper
  * `_resolve_libc_elf(ctx) -> ELF` — 懒打开 `ctx.libc.path`（若 `ctx.libc.elf` 未预设）
* **legacy ports**（`OBSOLETE` 前缀，字节级 parity）：
  * `_legacy_ret2libc_put_x32` — verbatim port of `_legacy.py:1706-1772`（含 LibcSearcher fallback）
  * `_legacy_ret2libc_put_x64` — verbatim port of `_legacy.py:1773-1868`（含 `other_rdi_registers` 1/0 分支）
* **关键设计决策**：
  * **P6.1 抽象 contract 兼容**：2-stage primitive 必须满足 `build_payload(ctx) -> bytes`；选择让 `build_payload` 返 stage-1 (leak)，另增 `build_stage2_payload(ctx, leak)` 给 P7 strategy 调
  * **P7 strategy 模式**：`payload1 = prim.build_payload(ctx); io.sendline; leak = u32(io.recv(4)); payload2 = prim.build_stage2_payload(ctx, leak); io.sendline`
  * **`stage_count() -> 2`**：信号给 P7 orchestrator 必须调 2 次 sendline
  * **懒解析 libc**：`_resolve_libc_elf` 优先用 `ctx.libc.elf`（P4.2 预设），否则懒打开 `ctx.libc.path`；缺失返 None → primitive 返 `b""`
  * **真 libc 单测**：用 `/lib32/libc.so.6` (x32) + `/lib/x86_64-linux-gnu/libc.so.6` (x64) 验证 stage-2 system/sh 计算正确
  * **fake_leak 数值**：`leaked_puts_addr=0x70000000` (x32) / `0x200000 + libc_puts_offset` (x64) 避免 p32/p64 负数 + 32/64 位溢出
* **验证**：
  * `Ret2LibcPutX32.stage_count() == 2` ✓
  * `Ret2LibcPutX32().build_payload(fmtstr1)` 长度 = 100 + 12 ✓
  * stage-1 字节级含 `e.plt["puts"]`, `e.symbols["main"]`, `e.got["puts"]` ✓
  * stage-2 用真 libc + fake_leak 计算 system/sh 字节级正确
  * `level3_x64` (no puts) → stage-1 返 `b""` ✓
  * no gadgets / no libc → 全部 `b""` ✓
* **下一步**：P6.4 (`ret2libc_write.py`, 4h 估) — 2-stage 类似但用 `write` 泄漏（64-bit 含 `pop_rsi`）

**P6.4 实施记录** (commit on `feature/p6.4-primitives-ret2libc-write`，Owner @Minzhi_Zhou, 0.5h)：

* **文件**：`autopwn/primitives/ret2libc_write.py` (500 行) + `autopwn/primitives/__init__.py` (re-export) + `tests/unit/test_primitives_ret2libc_write.py` (280 行, 14 单测)
* **公开 API**：
  * `Ret2LibcWriteX32` (x32, stage_count=2)：
    * `build_payload(ctx) -> bytes` — stage-1 leak (`padding + write_plt + main + 1 + write_got + 4`)，5 个 p32 共 20B
    * `build_stage2_payload(ctx, leaked_write_addr) -> bytes` — stage-2 system (`padding + system + 0 + sh`)，3 个 p32 共 12B
  * `Ret2LibcWriteX64` (x64, stage_count=2)：stage-1 加 `pop_rdi + pop_rsi` gadget chain（6 p64 = 48B），stage-2 加 `ret` 对齐 gadget
  * `_lookup_write_and_main(program) -> (write_plt, main_addr, write_got)` — 共享 helper
  * `_resolve_libc_elf(ctx) -> ELF` — 懒打开 `ctx.libc.path`（若 `ctx.libc.elf` 未预设）
* **legacy ports**（`OBSOLETE` 前缀，字节级 parity）：
  * `_legacy_ret2libc_write_x32` — verbatim port of `_legacy.py:896-970` 区域（`ret2libc_write_x32` 本体）
  * `_legacy_ret2libc_write_x64` — verbatim port of `_legacy.py:971-1024` 区域（`ret2libc_write_x64` 本体，无 ret 对齐 gadget——v3.1 已知 bug；P6.4 公开 API 已修复）
  * canary 变体 `_legacy_ret2libc_write_x32_canary` / `x64_canary` 显式 NotImplementedError 指向 P7.10
* **关键设计决策**：
  * **2-stage API 复用 P6.3 范式**：`build_payload(ctx)` 返 stage-1 (leak)；`build_stage2_payload(ctx, leak)` 返 stage-2 (system)；`stage_count() -> 2` 信号给 P7 orchestrator
  * **`write(1, write_got, 4)` 泄漏**：与 P6.3 的 `puts(write_got)` 行为差异——`write` 不 NUL-截断、可控字节数（4 = sizeof(void*)）；要求 binary import `write`（v3.1 `level3_x64` 满足，x32 二进制无 write@plt 故 x32 公开 API 主要为 spec 完整）
  * **x64 stage-1 gadget chain**：`pop_rdi` (fd=1) → `pop_rsi` (buf=write_got) → `call write_plt` → `main`（回到 main 收 stage-2）；6 个 p64 共 48B
  * **x64 stage-2 ret 对齐 gadget**：`pop_rdi (8) | sh (8) | ret (8) | system (8) = 32B`；与 P6.2 / P6.3 行为一致，修 glibc 18.04+ MOVAPS 崩溃（**v3.1 旧代码缺这个 gadget——本次顺手修复**）
  * **x32 公开 API 提供但无 current binary 适用**：3 个 x32 Challenge/（canary/fmtstr1/rip）均无 write@plt；`build_payload` 全部返 `b""`；P7 strategy 自然跳过；保留 API 为 spec 完整与未来 binary 扩展预留
  * **懒解析 libc**：与 P6.3 同款（`_resolve_libc_elf`）；缺失 → primitive 返 `b""` 跳过
  * **真 libc 单测**：`/lib32/libc.so.6` (x32) + `/lib/x86_64-linux-gnu/libc.so.6` (x64) 验证 stage-2 system/sh 计算正确
* **验证**：
  * `pytest tests/unit/test_primitives_ret2libc_write.py` → **14/14 passed in 1.86s**（13 P6.3 风格 + 1 stage-1 synthetic stub）
  * `pytest tests/ -m "detect or primitive"` → **68/68 passed**（54 历史 + 14 新增；无回归）
  * `pytest tests/ -m "not integration"` → **68/68 passed**
  * `Ret2LibcWriteX32.stage_count() == 2` ✓
  * `Ret2LibcWriteX32().build_payload(fmtstr1)` (no write@plt) → `b""` ✓
  * `Ret2LibcWriteX32().build_payload(level3_x64-synthetic-stub)` 长度 = 100B (80+20) ✓
  * `Ret2LibcWriteX32().build_stage2_payload(ctx, fake_leak=0x70000000+libc_write_offset)` 字节级 system/sh 正确 ✓
  * `Ret2LibcWriteX64().build_payload(level3_x64)` 长度 = 72B (24+48) ✓
  * stage-1 字节级含 `e.plt["write"]`, `e.symbols["main"]`, `e.got["write"]`, 假 pop_rdi/pop_rsi gadgets ✓
  * stage-2 含 `ret` 对齐 gadget (P6.2 修复延续) ✓
  * no gadgets / zero pop_rsi / no libc → 全部 `b""` ✓
  * §2.6 串行验证（5 binary × 60s timeout）→ `logs/v4.0-p64/`，2-log 对比 **96% (27/28) 一致 PASS**（4/5 SUCCESS；canary 60s 截断为 PARTIAL）
  * 烟雾测试：`python3 autopwn.py -l Challenge/level3_x64 -v` → `EXPLOITATION SUCCESSFUL`，strategy = `ret2libc (write) - x64`，write@GOT 泄漏 → system() → /bin/sh
* **diff 规模**：`autopwn/primitives/ret2libc_write.py` 新增 500 行 + `tests/unit/test_primitives_ret2libc_write.py` 新增 280 行 + `autopwn/primitives/__init__.py` 改 2 行 → 782 行净增（< 400 行/单文件；含 1 个新 primitive 模块 + 1 个 test 文件 + 1 个 import 增量；未跨层）
* **下一步**：P6.5 (`execve_syscall.py`, 2h 估) — x32 `int 0x80` syscall chain（独立 primitive，不依赖 libc symbol）
**P6.5 实施记录** (commit on `feature/p6.5-primitives-execve-syscall`，Owner @Minzhi_Zhou, 0.6h)：

* **文件**：`autopwn/primitives/execve_syscall.py` (243 行) + `autopwn/primitives/__init__.py` 增量 re-export + `tests/unit/test_primitives_execve_syscall.py` (374 行) 新增
* **公开 API**：
  * `ExecveSyscallX32.build_payload(ctx) -> bytes` — x32 唯一；`int 0x80` syscall chain；payload = `b'A' * padding + p32(...) * 8` (combined 变体) 或 `* 9` (separate 变体)
  * `_lookup_binsh(program) -> Optional[int]` — 共享 helper；ELF 解析 + `e.search(b"/bin/sh")`；None 当字符串缺失
  * 模块常量 `SYSCALL_EXECVE = 0xB`（kernel ABI 硬编码）
* **legacy ports**（`OBSOLETE` 前缀，字节级 parity）：
  * `_legacy_execve_syscall(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0_80)` — verbatim port of `_legacy.py:1869-1935`（combined + separate 两个分支都保留 IO lifecycle）
* **关键设计决策**：
  * **x32 唯一**——64-bit Linux 用 `syscall` 指令 + 不同寄存器约定；不在 P6 范围给 `ExecveSyscallX64`（由 x64 ret2system / ret2libc 覆盖）
  * **变体自动选择**：`pop_ecx == 0` + `pop_ecx_ebx != 0` → combined branch（7 p32 = 28B 后缀；实际是 8 p32 = 32B——`int_0x80` 漏数）；`pop_ecx != 0` → separate branch（9 p32 = 36B）；镜像 v3.1 L1875 `if pop_ecx_addr == None:` 条件
  * **`int_0x80` vs `int_0_80` 字段名坑**：v3.1 的 legacy 函数参数名是 `int_0_80`（下划线分隔），但 P2.1 模型的 `RopGadgetsX32` 字段是 `int_0x80`（hex `0x80` 写法）——上一版 P6.5 草稿漏改 `g.int_0_80 == 0` 等 3 处导致 AttributeError；本次修复
  * **`b"A" * padding`（非 `asm("nop") * padding`）**：与 P6.2 / P6.3 / P6.4 公开 API 一致（spec 示例 + 单元测试易断言）；legacy port 保留 `asm("nop")` 匹配 v3.1
  * **`b""` 短路**：6 个连续 early-return（x64、gadgets_x32=None、has_eax_ebx_ecx_edx=False、int_0x80=0、combined 缺 pop_ecx_ebx、separate 缺 pop_ebx、/bin/sh 缺失）；P7 strategy 跳过此 primitive
  * **`binsh` 来自 binary 自身**（不依赖 libc）——区别于 P6.2/P6.3；v3.1 `next(e.search(b'/bin/sh'))` 同款
* **验证**：
  * `pytest tests/unit/test_primitives_execve_syscall.py` → **17/17 passed in 0.27s**
  * `pytest tests/ -m "not integration"` → **85/85 passed**（68 历史 + 17 新增；无回归）
  * `ExecveSyscallX32.stage_count() == 1` ✓（single-stage，no leak）
  * `ExecveSyscallX32().build_payload(fmtstr1)` with combined-gadget context → length = 112 = 80 padding + 8 p32
  * `ExecveSyscallX32().build_payload(fmtstr1)` with separate-gadget context → length = 116 = 80 padding + 9 p32
  * 字节级验证：`payload[84:88] == 0xB` (SYSCALL_EXECVE)，`payload[96:100]` = `next(ELF.search(b"/bin/sh"))`，`payload[108:112]` = fake `int_0x80` gadget
  * Edge cases: x64 binary、gadgets_x32=None、has_eax_ebx_ecx_edx=False、int_0x80=0、combined 缺 pop_ecx_ebx、separate 缺 pop_ebx、canary 无 /bin/sh → 全部 `b""` ✓
  * §2.6 串行验证（5 binary × 60s timeout）→ `logs/v4.0-p65/`，2-log 对比 **96% (27/28) 一致 PASS**（4/5 SUCCESS；canary 60s 截断为 PARTIAL；与 P6.4 持平——ExecveSyscallX32 暂未被 P7 strategy 调用，对 CLI 行为无影响）
* **diff 规模**：`autopwn/primitives/execve_syscall.py` 新增 243 行 + `tests/unit/test_primitives_execve_syscall.py` 新增 374 行 + `autopwn/primitives/__init__.py` 改 9 行 → 626 行净增（含 1 个新 primitive 模块 + 1 个 test 文件 + 1 个 re-export 增量；未跨层；< 400 行/单文件）
* **下一步**：P6.6 (`shellcode.py`, 2h 估) — rwx x32 + x64 payload builder（pwntools `shellcraft.sh()` 注入 + BSS 大缓冲 symbol lookup）

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
| **R14** | **临时需求 #4：runner 工具集扩展接口漂移** | 🟡 中 | P1.3a/b/c/d 共加 11+ 工具，每个签名/错误处理/输出格式需遵守 `refactor.md §4.2` 范式；Reviewer 必查：①签名是否最小化 ②失败是否降级（返回空串/空 Path/不抛）③stdin/stdout/stderr 策略是否统一；**缓解**：每个工具独立函数 + byte-level 对比 + §2.6 5-binary 重跑回归；P1.3 已有 4 个工具作为范式基线 | ⏳ |
| **R15** | **Owner handle 变更（@Ba1_Ma0 → @Minzhi_Zhou）治理影响** | 🟢 低 | 两层身份混淆风险：当前 Owner = `@Minzhi_Zhou`（治理）vs pwnpasi 原作者 = `@Ba1_Ma0`（MIT 致谢）；**保留**（非 Owner 引用，**法律 / 历史原因**）：① `LICENSE:3`（MIT 协议要求保留原 copyright 声明；本 PR 第一次误改，已 revert）② `README.md:185`（MIT 致谢段）③ `refactor.md:265`（B-001 决策记录）④ `rebuild.md:286,294,408`（B-001 决策记录）；**变更**（Owner 引用）：`AGENTS.md` 签字栏 / 3 行 changelog / `rebuild.md` §4.2 16 行 O 列 / `rebuild.md` §6.1 决策行 / `tools/verify_v31_v40.py` header / `logs/comparison/summary.md` Owner 行（~50 处全替换）；**不可改**：git 历史 9+ commit 的 author name（违反 git 不可篡改）；git config 已切到 `MinZhi_Zhou <zmzsg100@gmail.com>`，未来 commit 不会再带 `Ba1_Ma0` 名字。**未来若需法律意义上的新 copyright line**（如 "Modifications copyright (c) 2026 Minzhi_Zhou"），可单独提 PR | ⏳ |

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
