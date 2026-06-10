# upgraded.md — AutoPwn v4.0+ 迭代流程

> **角色**：v4.0+ 迭代的**单一事实来源**（替代者）—— "今天起怎么开发 autopwn"
> **状态**：v4.0.dev0 准备 GA（2026-06-10）
> **配套文档**：
> - [`AGENTS.md`](./AGENTS.md) — 项目治理（4 条铁律 + 违规分级 + 紧急通道 + AI Agent 条款）
> - [`refactor.md`](./refactor.md) — v4.0 架构演进史（v3.1 → v4.0.dev0 WHY）
> - [`rebuild.md`](./rebuild.md) — v3.1 → v4.0.dev0 重构实施历史（P0-P11 阶段总结）
>
> **本文档章节**：
> - §0 阅读指引
> - §1 当前状态（v4.0 GA 准备 + v4.1 候选）
> - §2 迭代流程（sprint / issue-driven）
> - §3 任务看板（v4.0 GA / v4.1 候选任务）
> - §4 当前架构（v4.0 已落地 + AI Agent 必读）
> - §5 验证方法（铁律 4 6 关验收）
> - §6 附录（文件路径 / 决策树 / 工具 / 模板）

---

## 0. 阅读指引

| 你是谁 | 先看哪一节 |
|---|---|
| **第一次接触本项目** | **必读 [`AGENTS.md`](./AGENTS.md) §1 铁律** → 本文件 §0 → §1 → §4 → §5 |
| **想认领任务** | §1 当前状态 → §3 任务看板 → §2 流程 → §5 验证 |
| **正在做某个任务** | §3 当前任务 → §5 验证（6 关）|
| **理解 v4.0 架构** | §4 当前架构 + [`refactor.md §3`](./refactor.md) |
| **AI Agent session 启动** | [`AGENTS.md §5`](./AGENTS.md) 5 步启动 → 本文件 §0-§5 |
| **重构期历史追溯** | [`rebuild.md`](./rebuild.md) §3 阶段总结 + `git log` |

---

## 1. 当前状态

### 1.1 v4.0 GA 准备

**版本**：`4.0.dev0`（开发中）→ 目标 `4.0`（GA）

**已完成**：
- ✅ 6/6 重构里程碑（M0-M5）+ M6 内部打磨期
- ✅ 85 个 P 阶段子任务全部 ✅
- ✅ 9 次 Owner 拍板决策全部 Resolved
- ✅ 0 open 阻塞
- ✅ 626 unit tests + 17+1 integration tests（0 回归）
- ✅ 5 binary 串行 baseline 4/5 SUCCESS（per P11.2 实测 2026-06-10）
- ✅ 文档瘦身完成（AGENTS 174 + refactor 155 + rebuild 214 + 本文件）
- ✅ 主干开发模式（main 唯一长期分支）

**v4.0 GA 待做**（per §3 任务看板）：
- 切版本号 4.0.dev0 → 4.0
- 打 tag `v4.0.0` + GitHub Release
- 写 CHANGELOG.md（v3.1 → v4.0 重大变更摘要）
- README v4.0 更新（从 `4.0.dev0` → `4.0`）

### 1.2 v4.0 已知限制

- **🚨 当前 4/5 SUCCESS 是"假阳性"**（2026-06-10 诊断）：runner 环境无 stdin，`io.interactive()` 立即 EOF，但 "EXPLOITATION SUCCESSFUL" banner 已在 io.interactive() 之前 print → record_success 误触发。**v4.0+ 判定**：必须 `io.sendline(b"id") + io.recvuntil(b"uid=")` 真拿到 shell 才算 SUCCESS（per 任务 v4.0.1 / v4.0.2）
- **5/5 SUCCESS 不可达**：canary 暴力枚举需 > 10min，60s/600s timeout 都 PARTIAL；pre-existing v3.1 限制
- **覆盖率 44%**（行覆盖）：剩 56% 主要是 `_legacy_*` 函数（已 obsolete，按 `check_recon_coverage.py` 原则不测）；public API 覆盖率 95%
- **单一 Owner**：所有 PR 走 Owner 自审（per `AGENTS.md §2.2`）

### 1.3 v4.1 候选方向

- **HEAP 利用**：当前 strategies 全部栈 / ROP / PIE，缺 `malloc` / `free` / `tcache` 漏洞利用
- **多 binary 批处理**：当前 CLI 单 binary；`-l <dir>` 多 binary 批跑
- **Web UI / RPC**：`orchestrator.run` 暴露为 HTTP/JSON（per `refactor.md §11` 旧扩展点）
- **类型化异常**：`except Exception as e` 收敛为 `ReconError` / `DetectionError` / `StrategyError`
- **LLM 辅助决策**：`candidates(ctx)` 优先级交给 LLM 微调（与 `mmx-cli` 技能联动）
- **canary 暴力优化**（v4.1.3）：现 v4.0.3 "5/5 SUCCESS" 已被 v4.0.2 占位；如未来需要，可重写为并行爆破 + smarter padding

---

## 2. 迭代流程

### 2.1 任务来源

| 来源 | 流程 |
|---|---|
| **Owner 主动规划** | §3 任务看板加一行 + 状态 ⏳ |
| **Issue tracker** | Owner review 后转 §3 任务行 |
| **AI Agent 发现** | **不直接实施**（per `AGENTS.md §1` 铁律 2）→ 走"需求澄清"提问给 Owner |
| **重构期任务迁移** | 从 `rebuild.md §3` 提取 ✅ 任务作为新迭代的"已实现功能"基础 |

### 2.2 单任务工作流（4 步）

```
[⏳ Pending] → Owner 决策拍板 → [🔄 In Progress] → 实施 + 6 关验收 → [👀 Review] → [✅ Done]
                                       ↓
                                   [⚠️ Blocked] / [❌ Cancelled]
```

**详细步骤**：

1. **⏳ Pending → 🔄 In Progress**
   - 在 §3 任务行改状态 + 加 Owner + 实际工时
   - 拉分支：`git checkout main && git pull && git checkout -b fix/v{X}.{Y}.{Z}-{slug}`
   - 实施前先在 PR 描述引用任务 ID（per `AGENTS.md §5`）

2. **🔄 In Progress → 👀 Review**
   - 代码完成 + `pytest -m "not integration"` 全过
   - 写 PR 描述：`[v{X}.{Y}.{Z}] {动词} {对象}` + 实施要点 + Refs:`upgraded.md §3`
   - push + 创 PR（per Owner 自审）

3. **👀 Review → ✅ Done**
   - Owner 自审通过（单 Owner 项目）
   - 合并到 main
   - **同一 PR** 更新 §3 任务行状态 = ✅ + 加实际工时 + 加 commit SHA
   - **同一 PR** 更新 `CHANGELOG.md`（如适用）

### 2.3 任务 ID 格式（v4.0+）

格式：`v{X}.{Y}.{Z}` — 例如 `v4.0.1` / `v4.1.0`
- `X` 主版本（不兼容变更）
- `Y` 次版本（新功能，向后兼容）
- `Z` 修订版本（bug 修复）

> **与重构期 P 阶段 ID 区别**：`P{X}.{Y}` 是重构期 P 阶段任务（如 `P4.4b` = P4 阶段第 4 个子任务第 2 次修订）；`v{X}.{Y}.{Z}` 是 v4.0+ 迭代版本号任务（如 `v4.0.1` = v4.0 第 1 个修订）。

### 2.4 任务粒度

per `AGENTS.md §2.1`：
- 单 PR ≤ 400 行 diff
- 单 PR 不跨多个任务 ID
- 单 PR 只动一层（如 `recon/` 不允许顺手改 `primitives/`）

---

## 3. 任务看板

### 3.1 v4.0 GA 准备（高优先级 · 修复后才发 GA）

| ID | 任务 | 状态 | 预估 | 备注 |
|---|---|---|---|---|
| `v4.0.0` | **v4.0 GA 收尾**：切版本号 4.0.dev0 → 4.0 + tag `v4.0.0` + GitHub Release + CHANGELOG.md + README v4.0 更新 | ⏳ | 1.5h | **阻塞**：等 v4.0.1 / v4.0.2 修复后再做（per 2026-06-10 诊断） |
| `v4.0.1` | **修复 SUCCESS 判定 = 真 shell (id)**（v3.1 历史问题）：`autopwn/exp/strategies/*.py` + `autopwn/primitives/*.py` 把 `io.interactive()` 替换为 `io.sendline(b"id") + io.recvuntil(b"uid=", timeout=2)` 验证；orchestrator 接 "id_verified" 布尔信号；record_success 加 `id_output` 字段 | ⏳ | 4h | **高优先级**：当前 4/5 SUCCESS 是"假阳性"——runner 环境无 stdin，io.interactive() 立即 EOF，但 "EXPLOITATION SUCCESSFUL" banner 已在 io.interactive() 之前 print，造成 record_success 误触发。详见 /tmp/diagnosis.md（2026-06-10 诊断）|
| `v4.0.2` | **5 binary 实测修 padding / leak 路径**：fmtstr1 (canary 需先 fmtstr leak) / rip (padding 0x20 修复) / level3_x64 (ret2libc write leak 路径) / pie (PIE brute force 验证) — 4 binary 真实测 `id` 命令能拿到 `uid=` 后才算 SUCCESS | ⏳ | 2.5h | **依赖 v4.0.1**：先改判定逻辑，再修各 binary 实测 padding/leak。canary binary 仍 PARTIAL（v3.1 pre-existing 限制）|

### 3.2 v4.1 sprint 候选（按优先级排）

| ID | 任务 | 状态 | 预估 | 备注 |
|---|---|---|---|---|
| `v4.1.0` | **HEAP 利用层**：`primitives/heap.py` + `exp/strategies/heap_*.py` 至少 3 个新 strategy（malloc_hook / tcache / unsorted bin）| ⏳ | 12h | 大需求，Owner review 时机 |
| `v4.1.1` | **类型化异常**：`ReconError` / `DetectionError` / `StrategyError` 替代 `except Exception` | ⏳ | 1.5h | 重构期遗留，含 `orchestrator.run_strategy_phase` 等 |
| `v4.1.2` | **多 binary 批处理**：CLI `-L <dir>` 跑 `Challenge/*.bin` 全集，输出 `logs/batch/` summary | ⏳ | 3h | 跑 5 binary 当前要 5 次 `python -m autopwn` |
| `v4.1.4` | **Web UI / RPC**：`orchestrator.run` 暴露为 FastAPI，POST `/exploit` 返回 JSON | ⏳ | 6h | per `refactor.md §11` 旧扩展点 |
| `v4.1.5` | **LLM 辅助决策**：`candidates(ctx)` 接受外部 LLM override（与 `mmx-cli` 技能联动）| ⏳ | 4h | 实验性 |
| `v4.1.6` | **canary 暴力优化**（如 v4.0.2 未达标）：优化 canary 策略让 canary 60s timeout 内可解（parallel / smarter padding）| ⏳ | 8h | 需算法层重设计；可放弃走 ❌ |

### 3.3 open 阻塞（当前 = 0）

_（无 — 2026-06-10 v4.0+ 启动时无新阻塞）_

历史阻塞 B-001 ~ B-007 见 [`rebuild.md §3.6`](./rebuild.md)（已 Resolved，0 open）。

---

## 4. 当前架构（v4.0 已落地 · AI Agent 必读）

> 详细架构 WHY 见 [`refactor.md §3`](./refactor.md)。本节只列 v4.0 实际代码位置（"代码在哪"）。

### 4.1 分层依赖（自下而上单向）

```
CLI / Orchestrator  (cli.py, orchestrator/{__init__,recon,detect,strategy}.py)
        ↓
Strategies  (exp/strategies/*.py)
        ↓
Primitives  (primitives/*.py)
        ↓
Detect  (detect/*.py)
        ↓
Recon  (recon/*.py)
        ↓
Core  (core/*.py)
```

**禁止反向 import**（per `AGENTS.md §5`）。AI Agent 输出代码前必须问"这个改动对应哪一层？"

### 4.2 关键文件位置

| 用途 | 文件 | 关键 API |
|---|---|---|
| CLI 入口 | `autopwn/cli.py` | `main()` 解析 argparse + dispatch orchestrator |
| 编排调度 | `autopwn/orchestrator/{__init__,recon,detect,strategy}.py` | `run(ctx)` / `run_recon_phase(ctx)` / `run_detect_phase(ctx)` / `run_strategy_phase(ctx)` |
| 状态上下文 | `autopwn/context.py` | `ExploitContext` / `BinaryInfo` / `LibcInfo` / `RopGadgetsX64/32` / `CanaryInfo` |
| 二进制信息收集 | `autopwn/recon/{checksec,libc,plt,rop,asm,bss}.py` | `checksec.collect()` / `libc.detect()` / `rop.find_x64/32()` 等 |
| 漏洞探测 | `autopwn/detect/{binsh,canary,fmtstr,overflow}.py` | `binsh.check_binsh()` / `canary.canary_fuzz()` 等 |
| Payload 构造 | `autopwn/primitives/{ret2system,ret2libc_put,ret2libc_write,execve_syscall,fmtstr,pie_backdoor,shellcode}.py` | `build_payload(ctx) -> bytes` |
| 完整利用 | `autopwn/exp/strategies/*.py`（17 个文件 40 strategies）| `ExploitStrategy` 子类 + `@register` 装饰器 |
| 策略注册 | `autopwn/exp/registry.py` | `candidates(ctx) -> List[ExploitStrategy]`（按 priority 排序）|
| 报告生成 | `autopwn/report/{model,docx,code,__init__}.py` | `ExploitInfo` / `generate_docx()` / `generate_code()` |
| 核心工具 | `autopwn/core/{logging,fs,runner}.py` | `Colors` / `print_*` / `set_permission()` / `run_checksec()` 等 14 工具 |

### 4.3 Challenge 二进制（5 个）

| Binary | 架构 | 漏洞 | 关键策略 |
|---|---|---|---|
| `canary` | x32 | 栈溢出 + canary | CANARY strategies (priority 200) |
| `fmtstr1` | x32 | 格式串 | ret2system x32 (priority 150) |
| `level3_x64` | x64 | 栈溢出 + 64-bit libc | ret2libc write x64 (priority 110) |
| `pie` | x64 | PIE + backdoor | PIE Backdoor (priority 180) |
| `rip` | x64 | RIP 覆盖 | ret2system x64 (priority 150) |

---

## 5. 验证方法（铁律 4 6 关验收）

> **6 关验收（必跑）**：每条都 ✅ 才能把状态从 🔄/👀 改 ✅。

### 5.1 关 1: 代码已合并到 main

- PR target = main
- 合并后 working tree clean
- `git log main --oneline -1` 显示当前 commit

### 5.2 关 2: pytest unit 全过

```bash
pytest tests/unit/ -m "not integration" -q
```

**当前基准**：626 passed（per 2026-06-10 实测）

### 5.3 关 3: pytest integration（若涉及行为变化）

```bash
pytest tests/integration/ -q
```

**当前基准**：17/18 + 1 SKIP

### 5.4 关 4: 5-binary smoke（若涉及 autopwn 行为）

```bash
# 60s timeout 5 binary 串行
AUTOPWN_VERIFY_TIMEOUT=60 bash scripts/run_verify.sh v<X>.<Y>-smoke canary fmtstr1 level3_x64 pie rip

# 5 binary 应 4/5 SUCCESS（canary pre-existing PARTIAL）
# log 输出到 logs/v<X>.<Y>-smoke/
```

**当前基准**：4/5 SUCCESS（fmtstr1 / level3_x64 / pie / rip 全部 EXPLOITATION SUCCESSFUL，canary PARTIAL）

### 5.5 关 5: Owner 自审

- 单 Owner 项目（per `AGENTS.md §2.2`），Owner 自审 = Reviewer
- PR 描述含：任务 ID / 实施要点 / Refs:`upgraded.md §3` 任务行

### 5.6 关 6: 文档同步

- **同一 PR** 更新 §3 任务行（状态 + 实际工时 + commit SHA）
- **同一 PR** 更新 `CHANGELOG.md`（如适用）
- **同一 PR** 更新 `refactor.md` / `rebuild.md`（如涉及架构变更）

### 5.7 工具脚本

- `scripts/run_verify.sh <version-tag> <bin1> [bin2] ...` — 串行跑 binary（env `AUTOPWN_VERIFY_TIMEOUT` 控制 timeout）
- `scripts/baseline_lock.sh lock/verify/list <dir>` — sha256sum baseline 锁（v4.0+ 治理用）
- `tools/check_recon_coverage.py` — recon public API 覆盖率 gate（95% 阈值）
- `tools/check_public_api_coverage.py` — primitive public API 覆盖率 gate（80% 阈值）

---

## 6. 附录

### 6.1 文件路径速查（v4.0 完整）

```
autopwn/
├── __init__.py          # __version__ = "4.0.dev0"
├── __main__.py          # python -m autopwn 入口
├── cli.py               # argparse + dispatch orchestrator
├── context.py           # 6 个 dataclass
├── core/
│   ├── logging.py       # Colors + 12 print_* + VERBOSE
│   ├── fs.py            # set_permission + temp_workdir
│   └── runner.py        # 14 个 run_* 工具包装
├── recon/
│   ├── checksec.py      # collect() / display()
│   ├── libc.py          # detect()
│   ├── plt.py           # scan()
│   ├── rop.py           # find_x64/32()
│   ├── asm.py           # vuln_func_name / asm_stack_overflow
│   └── bss.py           # BSSSymbol / find_bss()
├── detect/
│   ├── binsh.py         # check_binsh()
│   ├── canary.py        # canary_fuzz() / leakage_canary_value()
│   ├── fmtstr.py        # detect_format_string_vulnerability()
│   └── overflow.py      # test_stack_overflow()
├── primitives/
│   ├── ret2system.py    # Ret2SystemX32 / X64
│   ├── ret2libc_put.py  # Ret2LibcPutX32 / X64
│   ├── ret2libc_write.py # Ret2LibcWriteX32 / X64
│   ├── execve_syscall.py # ExecveSyscall x32
│   ├── fmtstr.py        # FmtStr
│   ├── pie_backdoor.py  # PieBackdoor
│   └── shellcode.py     # RWX shellcode 通用
├── exp/
│   ├── base.py          # ExploitStrategy 抽象类
│   ├── registry.py      # @register / candidates(ctx)
│   └── strategies/      # 17 文件 40 strategies
├── orchestrator/        # 三阶段调度（拆子包）
│   ├── __init__.py      # run() 入口 + re-exports
│   ├── recon.py         # run_recon_phase
│   ├── detect.py        # run_detect_phase
│   └── strategy.py      # run_strategy_phase
├── report/
│   ├── model.py         # ExploitInfo
│   ├── docx.py          # generate_docx()
│   ├── code.py          # generate_code()
│   └── __init__.py      # record_success()
└── pwntools.md          # pwntools 笔记

tests/
├── conftest.py          # 共享 fixture (ctx_for, CHALLENGE_DIR)
├── unit/                # 626 tests（无 IO 副作用）
└── integration/         # 17+1 tests（真跑 Challenge 二进制）

scripts/
├── run_verify.sh        # 串行 5-binary 验证 runner
└── baseline_lock.sh     # sha256sum baseline 锁

tools/
├── check_recon_coverage.py    # recon 95% public API 覆盖 gate
├── check_public_api_coverage.py # primitive 80% public API 覆盖 gate
└── verify_v31_v40.py          # v3.1 vs v4.0 历史审计工具（仅保留）

Challenge/
├── canary               # x32 + canary
├── fmtstr1              # x32 + 格式串
├── level3_x64           # x64 + 64-bit libc
├── pie                  # x64 + PIE
└── rip                  # x64 + ret2system
```

### 6.2 决策树优先级（v4.0 现状）

| Priority | Strategy | 适用 binary |
|---|---|---|
| 200 | CANARY (canary_*.py) | canary |
| 180 | PIE_BACKDOOR (pie_backdoor.py) | pie |
| 150 | RET2SYSTEM (ret2system_*.py) | fmtstr1, rip |
| 120 | RET2LIBC_PUT (ret2libc_put_*.py) | level3_x64 (fallback) |
| 110 | RET2LIBC_WRITE (ret2libc_write_*.py) | level3_x64 |
| 90 | RWX_SHELLCODE (rwx_shellcode_*.py) | future RWX binaries |
| 80 | EXECVE_SYSCALL (execve_syscall.py) | canary (x32 fallback) |
| 50 | FMTSTR (fmtstr.py) | canary (兜底) |

### 6.3 工具脚本

| 工具 | 用途 | 何时用 |
|---|---|---|
| `pytest tests/unit/ -m "not integration"` | 单元测试 | 每次改代码后必跑（关 2）|
| `pytest tests/integration/` | 集成测试 | 改 orchestrator / strategy 时必跑（关 3）|
| `AUTOPWN_VERIFY_TIMEOUT=60 bash scripts/run_verify.sh <tag> canary fmtstr1 level3_x64 pie rip` | 5-binary 串行 smoke | 改 autopwn 行为时必跑（关 4）|
| `bash scripts/baseline_lock.sh lock logs/v<X>-smoke` | 锁 baseline log 文件 hash | 发布前 / 长期 baseline 保留时 |
| `python3 tools/check_recon_coverage.py` | recon 95% 覆盖 gate | CI 跑（关 2 增强）|
| `python3 tools/check_public_api_coverage.py` | primitive 80% 覆盖 gate | CI 跑（关 2 增强）|

### 6.4 任务 ID 模板（v4.0+）

```
[v{X}.{Y}.{Z}] {动词} {对象}

如：
[v4.0.0] release v4.0 GA — 切版本号 + tag + Release
[v4.1.0] add HEAP exploitation — primitives/heap.py + 3 strategies
[v4.1.1] type exceptions — ReconError/DetectionError/StrategyError
```

### 6.5 CHANGELOG 模板

```markdown
## [v{X}.{Y}.{Z}] - YYYY-MM-DD

### Added
- 新功能

### Changed
- 行为变更

### Fixed
- bug 修复

### Removed
- 移除功能

详见 `git log v{X}.{Y}.{Z-1}..v{X}.{Y}.{Z}`
```

### 6.6 v4.0 → v4.1 决策表（v4.1 启动时拍板）

| 维度 | v4.0 (当前) | v4.1 候选 |
|---|---|---|
| 二进制类型 | 栈溢出 / 格式串 / canary / PIE | + HEAP（v4.1.0）|
| 异常处理 | `except Exception as e` | 类型化异常（v4.1.1）|
| CLI 模式 | 单 binary | 多 binary 批处理（v4.1.2）|
| 5-binary baseline | 4/5 SUCCESS（canary PARTIAL pre-existing）| 5/5 SUCCESS（v4.1.3，可放弃）|
| 部署模式 | CLI | CLI + Web UI/RPC（v4.1.4）|
| 策略选择 | 静态 priority 排序 | + LLM 动态调整（v4.1.5）|

---

> **最后一条**：
> 本文档是 v4.0+ 迭代的**单一事实来源**。任何"今天起怎么开发 autopwn"问题先查这里。
> 历史档案在 `rebuild.md` + `refactor.md` + `git log`（永不删除）。
