# fix.md — v4.0+ 架构性修复计划

> **角色**：v4.0+ 架构性 bug 修复的**单一事实来源**（与 AGENTS.md / refactor.md / rebuild.md / upgraded.md 并列）
> **状态**：⏳ 等待 Owner 拍板（2026-06-12）
> **触发**：ctf-pwn 2026-06-11 实测 rip + level3_x64 暴露 3 个 bug；fix 落地后 Owner 复盘指出"只针对特定问题 fix，还是从架构角度优化"
> **配套文档**：
> - [`AGENTS.md`](./AGENTS.md) — 4 条铁律 + AI Agent 流程
> - [`refactor.md §3`](./refactor.md) — v4.0 已落地的目标架构
> - [`rebuild.md`](./rebuild.md) — v3.1 → v4.0 重构历史
> - [`upgraded.md §3`](./upgraded.md) — 任务看板（v4.0.5/6/7 在本文件立项后同步到 §3.1）

---

## 0. 阅读指引

| 你是谁 | 先看哪节 |
|---|---|
| **Owner 评审** | §1 背景 + §2 核心架构问题 → §3 修复方案 → §4 与现有 PR 关系 → §5 风险 |
| **实施者** | §3 修复方案 → §6 实施步骤 → §7 6 关验收 |
| **理解"为什么"** | §1 → §2 → §3.1（架构动机） |
| **AI Agent session 启动** | AGENTS.md §5 → 本文件 §3 → §6 |

---

## 1. 背景

### 1.1 已修的 3 个 bug（ctf-pwn 2026-06-11 实测确认）

| Bug ID | 位置 | 现象 | 根因 | 当前 fix（在 `fix/v4.0.2-detect-align-ret2libc-fix` 分支） |
|---|---|---|---|---|
| v4.0.2a | `detect/overflow.py::test_stack_overflow` | rip dynamic padding 30 vs 真实 23 | static 公式（`lea_off + 8`）错套到 dynamic（`padding + 8`，`padding` 是 input length-1） | `final_padding = padding`（裸 loop index）作 lower-bound；static 覆盖逻辑保持 |
| v4.0.2b | `primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload` | level3_x64 stage 2 SIGSEGV | `ret` 对齐 gadget 无条件应用，与调用方 `sub $N, rsp` 大小无关 | **magic number**: `include_ret = (padding < 32)` |
| v4.0.4 | `core/shell_verify.py::verify_shell` finally close io | `autopwn -l binary` 后 Stopped process 立即出现 | verify 协议设计为"探测存活"，未考虑"探测后保持存活" | 加 `keep_alive=True` kwarg + 15 个 strategy 调 `io.interactive()` |

### 1.2 修复落地后的反思

3 个 bug 都"修对了"（`autopwn -l rip` + `autopwn -l level3_x64` 均能拿到真实 root shell + `[*] Switching to interactive mode`），但**修复质量参差不齐**：

| 修复 | 性质 | 评估 |
|---|---|---|
| v4.0.2a | 公式错位 → 改公式 | ✅ 改对了，但 dynamic 测试仍是**死代码**（被 static 永远覆盖） |
| v4.0.2b | magic number 启发式 | ❌ **ad-hoc**：padding=20-31 范围的新 binary 会复现同类 bug |
| v4.0.4 | 加 kwarg + 15 处 sed | ⚠️ **半系统化**：`keep_alive` 模式可复用，但缺端到端 shell 交互测试（无 CI 防回归） |

**核心问题**：3 个 fix 都**症状级**——修了当前 bug，但没建立能早期捕获**同类 bug 在新 binary 上复现**的机制。

---

## 2. 核心架构问题（按优先级）

### 2.1 Primitive 不知道调用方 frame 结构（v4.0.2b 根因）

**问题**：`Ret2LibcWriteX64.build_stage2_payload` 硬编码 ROP 链形状（`padding + pop_rdi + sh + ret + system`），不知道调用方 `vuln_func` 的 `sub $N, rsp` / `lea -M(%rbp)` 实际大小。`ret` gadget 是否需要取决于 frame 大小，但 primitive 用 magic 阈值 `padding < 32` 猜。

**架构层诊断**：
- 违反 `refactor.md §3.2.1` "P5 detect 层是唯一被授权写 ctx 的层" 之外的隐式约束——primitive 应该 query ctx 的 frame info，而不是**重新发现** frame
- v3.1 monolithic 代码里 `padding + alignment` 是 hack；v4.0 重构时**沿用了 hack** 而没**建模 frame**

### 2.2 缺端到端 shell 交互测试（v4.0.4 根因）

**问题**：`verify_shell` 用 mock 单测覆盖，但**没有真实 spawn binary → 验证 shell 可交互**的测试。导致：
- verify 协议改 `id`/`uid=` → `echo PWNED` 没人测过 PWNED 是否真的回显
- `keep_alive=True` 的 close-or-not 行为只能靠手动跑
- `io.interactive()` 在 15 个 strategy 的注入只能靠人 review

**架构层诊断**：
- 测试金字塔缺少"scenarios"层（unit → integration → **scenario**）
- `tests/integration/` 现有 18 个测试都是 **registry 逻辑**（candidates 排序），无 **runtime 行为**（真正跑 binary 看 shell）

### 2.3 Dynamic padding 是死代码（v4.0.2a 根因）

**问题**：`orchestrator/detect.py` 在 `test_stack_overflow` 跑完后**立即**用 `ctx.padding = asm_padding` 覆盖 dynamic 结果。dynamic 测试**实际永远不被使用**——是 v3.1 时代的"双保险"残留，v4.0 重构没清理。

**架构层诊断**：
- 死代码 + magic 公式 = 高风险隐患（v4.0.2a 那种 bug 在死代码里悄悄发生）
- 应该明确分工：dynamic 做 **lower-bound sanity check**（检测 v3.1 类公式错位），static 做 **authoritative value**。两者**差值**应被监控。

---

## 3. 修复方案（3 个 task，按 AGENTS.md §2.4 粒度拆分）

### 3.1 v4.0.5：FrameContext 抽象 + 模拟器 + 根除 magic number

**架构层变更**（per AGENTS.md 铁律 2 步骤 1）：

```
新层：recon/frame.py
   ↓ 填充
新字段：context.py::ExploitContext.frame_context: FrameContext
   ↓ query（替代 magic 阈值）
改写：primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload
   ↓ 同时修改（一致性）
4 个 ret2* primitive 统一用 ctx.frame_context.required_ret_count
```

**具体步骤**：
1. **新增 `autopwn/recon/frame.py`**：
   - `extract_frame_context(binary: Path, vuln_func_name: str) -> FrameContext`
   - 从 disasm 提取 `lea_offset`（如 `-0x80`）、`frame_size`（如 `0x80`）、`vuln_func_addr`
   - `compute_required_ret_count(frame_context) -> Literal[0, 1]`
     - 真实计算 `leave;ret` 后 rsp 对齐方向
     - 比对 do_system prologue 的 `0x30 + 0x388 = 0x3B8` 堆栈消耗
     - 输出 0 或 1（无中间值）
2. **修改 `autopwn/context.py`**：
   - 新增 `@dataclass class FrameContext`（lea_offset, frame_size, vuln_func_addr, required_ret_count）
   - `ExploitContext` 加 `frame_context: FrameContext = field(default_factory=...)`
3. **修改 `autopwn/recon/asm.py::asm_stack_overflow`**：
   - 在返回 padding 之前，**同时**填充 `ctx.frame_context`
   - 调用 `extract_frame_context` + `compute_required_ret_count`
4. **修改 `autopwn/primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload`**：
   - 删 `include_ret = ctx.padding < 32` magic
   - 改 `include_ret = bool(ctx.frame_context.required_ret_count)`
5. **同步 `ret2system.py` / `ret2libc_put.py`**（统一行为）：
   - 替换 `g.ret` 硬编码为 `g.ret if ctx.frame_context.required_ret_count else 0`
   - **条件**：`g.ret != 0`（保护：如果没找到 ret gadget，不要硬塞）
6. **新增 `tests/unit/recon/test_frame.py`**：
   - 单元测试 `extract_frame_context` 在 rip + level3_x64 上
   - 单元测试 `compute_required_ret_count`：rip → 1，level3_x64 → 0
   - 回归测试 `Ret2LibcWriteX64.build_stage2_payload` 在两种 frame 上行为正确

**预期代码量**：~280 行（< 400 行预算 ✓）

**6 关验收**：
- ② `pytest tests/unit -q` 全过
- ④ `autopwn -l rip` + `autopwn -l level3_x64` 仍能拿到 root shell（**无回归**）
- ⑤ Owner 自审
- ⑥ upgraded.md §3.1 v4.0.5 row 状态 ✅

---

### 3.2 v4.0.6：端到端 shell 交互测试（防 v4.0.4 类回归）

**新增** `tests/integration/test_shell_interaction.py`：

```python
@pytest.mark.integration
class TestShellInteraction:
    """End-to-end shell interaction test (v4.0.6).

    Per upgraded.md §3.1 v4.0.6: for each Challenge/ binary, spawn
    autopwn, pipe commands via stdin, assert shell stays alive AND
    commands produce expected output.  Catches future regressions
    of the verify_shell close-tube issue (v4.0.4).
    """

    def test_rip_spawns_interactive_shell(self):
        # (sleep; echo id; sleep; echo 'echo PWNED'; sleep; echo exit) | autopwn -l rip
        # Assert: 'PWNED' in output AND 'uid=0' in output

    def test_level3_x64_spawns_interactive_shell(self):
        # Same for level3_x64

    @pytest.mark.parametrize("binary", ["canary", "fmtstr1", "pie"])
    def test_other_binaries_attempted(self):
        # Smoke test: autopwn runs without hanging
        # (these are expected to FAIL on canary/pie; OK to mark xfail)
```

**预期代码量**：~180 行

**6 关验收**：
- ② `pytest tests/integration -q test_shell_interaction.py` 全过
- ④ 手动 `autopwn -l rip` + `autopwn -l level3_x64` 拿 shell
- ⑤ Owner 自审
- ⑥ upgraded.md §3.1 v4.0.6 row 状态 ✅

---

### 3.3 v4.0.7：padding 探测跨检（防 v4.0.2a 类回归）

**新增** `tests/unit/test_padding_crosscheck.py`：

```python
@pytest.mark.detect
class TestPaddingCrosscheck:
    """v4.0.7: dynamic + static padding cross-check.

    Per upgraded.md §3.1 v4.0.7: for each Challenge/ binary, run
    BOTH asm_stack_overflow (static) and test_stack_overflow
    (dynamic), assert |static - dynamic| ∈ {0, 1, 8, 16, 24, ...}
    (legal deltas: exact match, off-by-one from null terminator,
    or 8-byte saved-rbp boundary).  Catches future regressions
    of dynamic padding formula bugs (v4.0.2a).
    """

    @pytest.mark.parametrize("binary,padding", [
        ("rip", 23), ("level3_x64", 136), ("canary", 3625),
        ("fmtstr1", 0), ("pie", 0),
    ])
    def test_static_dynamic_delta_is_legal(self, binary, padding):
        ...
```

**预期代码量**：~80 行

**6 关验收**：
- ② `pytest tests/unit test_padding_crosscheck.py` 全过
- ⑤ Owner 自审
- ⑥ upgraded.md §3.1 v4.0.7 row 状态 ✅

---

## 4. 与现有 PR 的关系

### 4.1 时间线

```
[已 push 未 merge]  fix/v4.0.2-detect-align-ret2libc-fix (3 commits)
                    ├── v4.0.2a  (改 test_stack_overflow 公式)
                    ├── v4.0.2b  (magic threshold padding<32)  ← v4.0.5 替换
                    └── v4.0.4   (keep_alive + 15 处 sed + 删 banner)

[本 fix.md 计划]    fix/v4.0.5-frame-architecture  (3 commits, NEW branch)
                    ├── v4.0.5  (FrameContext + 4 primitive 重写)
                    ├── v4.0.6  (test_shell_interaction)
                    └── v4.0.7  (test_padding_crosscheck)
```

### 4.2 合并顺序（推荐）

**顺序 A：先 merge 旧 PR，再 merge 新 PR**（推荐）
1. Owner merge `fix/v4.0.2-detect-align-ret2libc-fix` → main（先 unblock 用户拿 shell）
2. 基于 main 开新分支 `fix/v4.0.5-frame-architecture` → 实施 v4.0.5/6/7
3. v4.0.5 替换 v4.0.2b 的 magic 阈值（v4.0.2b commit 留作 history，但代码被 v4.0.5 覆盖）
4. v4.0.6/7 加测试基础设施

**顺序 B：直接 v4.0.5 替换 v4.0.2b**（激进）
- 重新组织 `fix/v4.0.2-detect-align-ret2libc-fix` 分支：
  - 保留 v4.0.2a（公式 fix）
  - 替换 v4.0.2b 为 v4.0.5 风格（FrameContext）
  - 保留 v4.0.4（keep_alive）
- 缺点：force-push，PR review 历史丢失

→ **建议顺序 A**：保留历史 commit，新 PR 叠加。

### 4.3 与 v4.0.2b 的关系

- v4.0.2b 在 main 上是 **临时方案**（magic 阈值），用户已知其性质
- v4.0.5 实施后：
  - 若 ctx.frame_context 已填充 → 用 `required_ret_count`（principled）
  - 若 ctx.frame_context 未填充（fallback）→ 用 v4.0.2b 的 `padding < 32`（向后兼容）
  - 这样 v4.0.5 PR 可以**独立 merge**，不强制依赖 v4.0.2b

---

## 5. 风险层（per AGENTS.md 铁律 2 步骤 3）

| 风险 | 等级 | 缓解措施 |
|---|---|---|
| `FrameContext` 改变 `ExploitContext` 公共 API（新增字段） | 中 | 单 Owner 项目（per §2.2）；dataclass 用 `field(default_factory=...)` 保证 backward compat；现有 17 个 strategy 不传 `frame_context` 也能跑（默认 factory 生成） |
| `compute_required_ret_count` 计算错误 | 高 | **3 个 unit test** 覆盖 rip + level3_x64 + canary 边界 case；v4.0.5 PR 必跑 `autopwn -l rip` + `-l level3_x64` 验证无回归 |
| v4.0.6 端到端测试 flaky（autopwn + pty 交互） | 中 | 复用 v4.0.4 的 `keep_alive` + `io.interactive()`；单测试 5s timeout；flaky 加 `pytest.mark.flaky(reruns=2)` |
| v4.0.7 padding 跨检的"合法 delta 集合"漏判 | 低 | delta 集合 = `{0, 1, 8, 16, 24, 32}`（含 saved-rbp corruption = 8 字节边界 + null terminator = 1）；v3.1 _legacy 测试覆盖 5 binary 真实 delta |
| 新 branch 跟旧 branch 冲突 | 中 | v4.0.5 branch 基于 main（不是 fix/v4.0.2-...）；推荐顺序 A merge |

---

## 6. 实施步骤（per AGENTS.md 铁律 2 步骤 5）

按 6 关验收逐 task 实施。每 task 一 commit + 一 push + 等待 Owner 评审（per AGENTS.md §2.2）。

### 6.1 v4.0.5 实施 checklist

- [ ] 创建分支 `fix/v4.0.5-frame-architecture` (基于 main)
- [ ] 新增 `autopwn/recon/frame.py`（extract_frame_context + compute_required_ret_count）
- [ ] 修改 `autopwn/context.py`（新增 FrameContext dataclass + ExploitContext.frame_context 字段）
- [ ] 修改 `autopwn/recon/asm.py::asm_stack_overflow`（同时填充 frame_context）
- [ ] 修改 `autopwn/primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload`（用 required_ret_count）
- [ ] 修改 `autopwn/primitives/ret2system.py` + `ret2libc_put.py`（统一用 ctx.frame_context）
- [ ] 新增 `tests/unit/recon/test_frame.py`（3 个 unit test）
- [ ] `pytest tests/unit -q` 全过
- [ ] `autopwn -l Challenge/rip` 拿 shell（**无回归**）
- [ ] `autopwn -l Challenge/level3_x64` 拿 shell（**无回归**）
- [ ] commit + push
- [ ] updated.md §3.1 v4.0.5 row 状态 ✅ + commit SHA

### 6.2 v4.0.6 实施 checklist

- [ ] （在 v4.0.5 branch 上）新增 `tests/integration/test_shell_interaction.py`
- [ ] `pytest tests/integration -q test_shell_interaction.py` 全过
- [ ] commit + push
- [ ] updated.md §3.1 v4.0.6 row 状态 ✅ + commit SHA

### 6.3 v4.0.7 实施 checklist

- [ ] （在 v4.0.5 branch 上）新增 `tests/unit/test_padding_crosscheck.py`
- [ ] `pytest tests/unit test_padding_crosscheck.py` 全过
- [ ] commit + push
- [ ] updated.md §3.1 v4.0.7 row 状态 ✅ + commit SHA

### 6.4 PR 标题格式（per AGENTS.md §5）

```
[v4.0.5] 引入 FrameContext 抽象，根除 ret2libc 启发式 magic number
[v4.0.6] 端到端 shell 交互测试 (防 verify_shell close-tube 回归)
[v4.0.7] padding 探测跨检 (防 test_stack_overflow 公式错位回归)
```

PR body 模板（per AGENTS.md §2.2 步骤 2）：
```
## 概述
[一句话]

## Refs
- upgraded.md §3.1 v4.0.5/6/7
- fix.md §3.1/3.2/3.3
- AGENTS.md §5 (6 关验收)
```

---

## 7. 6 关验收（per AGENTS.md §5，适用每个 task）

| 关 | 标准 | 实施方法 |
|---|---|---|
| ① | 代码已合入 | `git log --oneline -1` 确认 commit SHA 在 main |
| ② | `pytest -m "not integration"` 全绿 | `pytest tests/unit -q` |
| ③ | integration test 跑通对应 Challenge/ 二进制 | `pytest tests/integration -q` (v4.0.6/7 包含) |
| ④ | autopwn -l 至少 1 binary 实测成功 | `autopwn -l Challenge/rip` + `autopwn -l Challenge/level3_x64` |
| ⑤ | Owner 自审（单 Owner 项目） | Owner 在本文件 §6 checklist 勾选 |
| ⑥ | upgraded.md §3 文档已同步 | 状态 👀→✅，加 commit SHA + 实施记录 |

**任一关未过 → 状态不能改 ✅**（per AGENTS.md §5 "完成"判定标准）。

---

## 8. 变更日志

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-06-12 | 1.0 | 初版：v4.0.5/6/7 三 task 架构修复计划，基于 ctf-pwn 2026-06-11 实测反馈 |
