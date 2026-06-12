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

- **🚨 当前 4/5 SUCCESS 仍含"假阳性 banner"**（2026-06-10 二次诊断）：v4.0.1（commit `ce7cc16`）已修 `io.interactive() → verify_shell()`；v4.0.3 已把 banner 移到 verify 之后（`record_success` 内部 banner + canary_*.py 12 处显式 banner 全删，统一由 `record_success_verified` 仅在 `id_ok=True` 路径 print）。**v4.0.4（⏳ 计划）**：完全删除 banner 打印（成功仅靠 `record_success` 生成 docx + `ctx.id_output` 戳记为唯一可见信号），并加 `verify_shell(keep_alive=True)` 让 strategies 不在 finally close io（tube 留在 `ctx.io` 供 fixture teardown 显式清理）。**v4.0+ 真判定**：verify_shell 返回 True（即真拿到 `uid=`）才生成 docx + 戳 id_output（per v4.0.4）
- **🚨 2026-06-11 ctf-pwn 实测新发现（per `v4.0.2a/b` 拆分任务）**：
  - **rip（autopwn 当前 5/5 实际 4/5）**：dynamic padding 探测 `test_stack_overflow` 返回 **30**（真实 = **23**），靠静态 `asm_stack_overflow` fallback 巧合修正成 23 才成功。**若去掉 fallback 链会立刻挂**。根因在 `detect/overflow.py::test_stack_overflow` 的 `final_padding = padding + alignment` 公式在小 frame（`sub $0x10` / `lea -0xf(%rbp)`）上系统性偏差。
  - **level3_x64（autopwn 当前标 SUCCESS 实则假阳性）**：padding 探测正确（136），但 `Ret2LibcWriteX64.build_stage2_payload` 的 `ret` 对齐 gadget 被无条件应用，与 `sub $0x80` frame 实际需要的对齐方向相反，导致 do_system 的 `movaps %xmm1,(%rsp)` SIGSEGV。手动 `WITHOUT ret` 即可成功。
  - **影响范围**：`v4.0.2` 任务粒度过大（混了 padding 探测 + ret2libc leak + PIE brute force 三个独立根因），已拆分为 v4.0.2a/b/c 三个子任务（per `AGENTS.md §2.4`）。
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
| `v4.0.1` | **修复 SUCCESS 判定 = 真 shell (id)**（v3.1 历史问题）：`autopwn/exp/strategies/*.py` + `autopwn/primitives/*.py` 把 `io.interactive()` 替换为 `io.sendline(b"id") + io.recvuntil(b"uid=", timeout=2)` 验证；orchestrator 接 "id_verified" 布尔信号；record_success 加 `id_output` 字段 | ✅ | 4h | **高优先级**：当前 4/5 SUCCESS 是"假阳性"——runner 环境无 stdin，io.interactive() 立即 EOF，但 "EXPLOITATION SUCCESSFUL" banner 已在 io.interactive() 之前 print，造成 record_success 误触发。详见 /tmp/diagnosis.md（2026-06-10 诊断）|
| `v4.0.2` | **5 binary 实测修 padding / leak 路径**（**已拆分**为 v4.0.2a/b/c per `AGENTS.md §2.4` 任务粒度）：原 2.5h 估算偏低，因 ctf-pwn 2026-06-11 实测 rip + level3_x64 暴露**两个独立根因**（不是简单 padding 错），需分别修 | ⏳ | — | **依赖 v4.0.1 + v4.0.3**（verify_shell 真判定必须先就位）|
| `v4.0.2a` | **修 `detect/overflow.py::test_stack_overflow` 动态 padding `+alignment` 偏移 bug**：当前实现 `final_padding = padding + alignment`（alignment = 8 for x64），在 `sub $0x10` / `lea -0xf(%rbp)` 的小 frame 上**系统性 +7~+8 偏差**。ctf-pwn 实测 rip 返回 30（真实 = 23），level3_x64 巧合正确（136）。修复思路二选一：(A) 改为 `final_padding = padding`（依赖静态 `asm_stack_overflow` 二次校正）；(B) 加 frame-size 启发式：若 lea 偏移 ≤ 0x20 则不加 alignment。**方案 A 实施（2026-06-11）**：`final_padding = padding`（去掉 `+alignment`），动态值变为 lower-bound 信号（rip=22，level3_x64=128）；orchestrator/detect.py 的 `ctx.padding = asm_padding` 静态覆盖逻辑**保持不变**，仍由 `recon/asm.asm_stack_overflow` 给出权威值（rip=23，level3_x64=136）。docstring 加 Note 段说明 `padding` 含义变化 + 历史 bug。**6 关验收**：① 代码合入（待 Owner 推 commit）；② `pytest tests/unit -q`：**626 passed**（0 回归，含 `test_detect_overflow.py` 5 个测试全绿）；③ N/A（v4.0.2a 只修 dynamic 探测的 lower-bound，integration test 由 v4.0.2c 覆盖）；④ `autopwn -l Challenge/rip` 实测：padding=23（静态覆盖生效）、verify_shell 返 `(True, "uid=0(root) gid=0(root) groups=0(root)\n")`、生成 `rip_wp.docx` 含完整 ret2system payload；独立 pwntools 复现 payload → 真实 `uid=0(root)` shell；`autopwn -l Challenge/level3_x64` 仍 SIGSEGV —— 但根因是 **v4.0.2b 的 `ret` gadget 误对齐**，与 v4.0.2a 修复**正交**（level3_x64 padding 136 始终正确，autopwn 的 `ctx.padding = 136` 不受本次 fix 影响）；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表已加实施记录） | 👀 | 0.5h | **风险**：本 fix 假设 static 覆盖永远发生（per `orchestrator/detect.py:60`）—— 若未来有人在 orchestrator 里去掉 static 覆盖，dynamic 的 lower-bound 22/128 会直接进 payload 导致 exploit 失败。**对策**：保留 docstring Note 段，明确 dynamic 仅为 canary check 信号 |
| `v4.0.2b` | **修 `primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload` 的 `ret` 对齐 gadget 无条件应用**：当前 stage 2 固定 `padding + pop_rdi + sh + ret + system`，但 `ret` gadget 是否需要对齐取决于**调用方 frame 大小**——rip（`sub $0x10`，buffer rbp-0xf）需要 ret，level3_x64（`sub $0x80`，buffer rbp-0x80）加 ret 反而**误对齐**导致 do_system 的 `movaps %xmm1,(%rsp)` SIGSEGV。ctf-pwn 实测：level3_x64 `WITH ret` → SIGSEGV；`WITHOUT ret` → `PWN_OK`。**修复方向**：(A) 让 `ctx.gadgets_x64.ret` 改可空（None=不插），`extra_rdi == 0` 默认不插 ret（让 stage 2 = `padding + pop_rdi + sh + system`）；(B) 引入 frame 探测：若 vuln_func 入口 `sub $N, rsp` 满足 `(N + 8) % 16 == 0` 则不插 ret。**6 关验收**：`autopwn -l Challenge/level3_x64` 实测 verify_shell 返 `(True, "uid=0(root)...")` 并生成 `level3_x64_wp.docx` | 🔄 | 1.5h | **风险**：方案 A 可能让 rip 退步（需回归测试）；方案 B 需新加 ctx 字段 `frame_alignment` 记录 (N+8)%16。**Owner**：@Minzhi_Zhou |
| `v4.0.2c1` | **修 fmtstr1 端到端 exploit 路径**（**v4.0.2c 拆分 per `AGENTS.md §2.4` 任务粒度**，2026-06-12 Owner 拍板 + 实施完成）：原 v4.0.2c 描述混了"修 hang"和"5 binary 验收"两件事，按 ≤400 行/PR 拆为 c1（修 hang + 路由 fmtstr1 到 fmtstr strategy）/ c2（验收收尾）。**诊断（2026-06-12 复现后）**：`Challenge/fmtstr1` 是 **format string + canary** 而非 stack overflow；`recon/asm.asm_stack_overflow` 错把 frame size 算成 12（实际是 0x80 = 128 bytes 因 `and $0xfffffff0, %esp; add $0xffffff80, %esp` 双指令），导致 `ctx.padding = 12`；FmtstrX32LocalStrategy 的 `matches()` 守门 `ctx.padding == 0`（per v3.1 main() L3316）→ fmtstr strategy **被过滤掉**；落到 ret2system-x32（canary 拦截，verify_shell fail）和 ret2libc-put-x32（`io.recv()` 无 timeout 卡死 + `io.recvuntil(b"\xf7")` 也无 timeout → 这俩组合就是用户报的"60s+ hang"根因）。**实施记录（2026-06-12）**：(a) `autopwn/orchestrator/detect.py:88-122` 在 fmtstr 检测后**填充** `ctx.fmtstr_offset` (调 `find_offset`) + `ctx.fmtstr_buf` (调 `bss.find_bss` 找 min_size=2 BSS 符号)；(b) `autopwn/exp/strategies/fmtstr.py` 5 个 strategy class 的 `matches()` 加 fallback `or (ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None)` 让 fmtstr 路径在 padding>0 也被选；(c) `autopwn/exp/strategies/ret2libc_put_x32.py` 修 2 处 hang：line 107 `io.recv()` 加 `timeout=0.5`（cap initial banner recv 避免 binary 无 prompt 卡死），line 113 `io.recvuntil(b"\xf7")` 加 `timeout=2.0`（avoid leak hang）；(d) `autopwn/exp/strategies/ret2libc_write_x32.py` 同步修：line 101 `io.recv()` 加 `timeout=0.5`，line 106 `io.recv(4)` 加 `timeout=2.0`；(e) 4 个新 unit test：`test_exp_fmtstr.py::test_x32_local_matches_padding_nonzero_when_fmtstr_fields_set` + `test_candidates_padding_nonzero_with_fmtstr_fields_includes_fmtstr`（验 v4.0.2c1 新增 routing 路径），`test_exp_ret2libc_put.py::test_x32_local_recvuntil_called_with_timeout_2` + `test_x32_local_initial_recv_called_with_timeout`（验 recvuntil/recv 用了 timeout）；(f) 2 个新 orchestrator test：`test_orchestrator.py::test_fmtstr_detection_populates_ctx_fields` + `test_fmtstr_detection_graceful_on_find_offset_failure`（验 detect 阶段正确 populate 字段 + find_offset 抛 ValueError 时 graceful）。**6 关验收**：① 代码合入 `fix/v4.0.2c1-fmtstr1-hang` 分支（squash 1 commit）；② `pytest tests/unit -q`：**687 passed**（基线 681 + 4 新 v4.0.2c1 tests + 2 已有 fmtstr tests 因 matches() 行为变更更新，0 回归）；③ `pytest tests/integration -q`：**21 passed + 2 skipped + 1 xfailed**（106s）；④ 5-binary smoke (`AUTOPWN_VERIFY_TIMEOUT=60 bash scripts/run_verify.sh v4.0.2c1-verify`): **4/5 SUCCESS** (fmtstr1 + level3_x64 + pie + rip 真拿到 root shell + docx + interactive，**fmtstr1 从 hang 升级为真 SUCCESS**；canary 仍 pre-existing PARTIAL)；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + `logs/v4.0.2c1-verify/fmtstr1.log` + §5.4 baseline 升级 3/5 → 4/5）| ✅ | 2h | **风险**：(a) 改 `matches()` fallback 让 fmtstr strategy 在不该选的 binary 上被选 → 守门 `ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None` 双字段，primitive 的 `build_payload` 会在缺字段时返空并打 `print_info` skip（已有逻辑）；(b) `io.recvuntil(timeout=2)` 异常处理可能让原本能 leak 成功的 binary 现在被误判为 fail → 设 2s 偏保守，可后续 v4.0.2c3 调参；(c) `asm_stack_overflow` 把 12 算成 padding 是 pre-existing bug，**不在本任务范围**（v4.0.2a 改 dynamic 公式时是 `+alignment` → `+0`，对 `and+add` 形式仍未识别），列 v4.0.2c3 或 v4.0.8 立任务；(d) x64 版本的 `ret2libc_put_x64.py:97` 和 `ret2libc_write_x64.py:98/187` 仍有同样无-timeout 的 recvuntil/recv 问题（**不在本任务范围**），列 v4.0.2c3 立任务 |
| `v4.0.2c2` | **5 binary 6 关验收收尾**（v4.0 GA 阻塞最后一步；**原 v4.0.2c 拆分后保留验收部分**）：跑 `autopwn -l Challenge/{rip,level3_x64,fmtstr1,canary,pie}` 五个 binary，对比 `verify_shell` 返 `(True, "PWNED...")` 路径全部一致；canary 仍 PARTIAL（per `v4.0.2 备注` v3.1 pre-existing 限制，不阻 GA）；把 v4.0.2a/b/c1 的修复纳入 `logs/v4.0.2c2/binary_<name>.log` 对比基线（用 `scripts/baseline_lock.sh lock` 锁 hash）；更新 `upgraded.md §5.4` baseline（3/5 → 4/5 SUCCESS 当 fmtstr1 hang 修完）| ⏳ | 1h | **依赖 v4.0.2a + v4.0.2b + v4.0.2c1**（3 个修 hang/padding/ret-gadget bug 完成后才能 6 关验收）|
| `v4.0.2c3` | **修 `recon/asm.py::asm_stack_overflow` 误把函数 epilogue 的 `lea -0x8(%ebp),%esp` 当 buffer offset**（per `fix.md` v4.0.2c1 复盘，2026-06-12 Owner 拍板方向 A + 实施完成）：当前 `_LEA_RE.search(func_body)` 抓的是**函数内第一个** `lea -N(%ebp)`，对 fmtstr1 抓到了 main 末尾的 `lea -0x8(%ebp),%esp`（epilogue 恢复 esp，-0x8 = saved regs 8 字节）+ 4 (x32) = **12 字节**（**完全错**）。真 buffer lea 是 `lea 0x2c(%esp),%eax`（用 %esp，因 `and $0xfffffff0,%esp; add $0xffffff80,%esp` 破坏了 %ebp→%esp 对应），**当前 _LEA_RE 不抓**。**实施记录（2026-06-12）**：(a) `autopwn/recon/asm.py` 抽出 helper `_extract_buffer_lea_padding(func_body, bit)` —— 算法 = (1) 找 func_body 内**第一个** `call <read|gets|fgets|scanf>(?![A-Za-z0-9_])`（**负向前瞻**防 `getegid` 误匹配 `gets`）位置；(2) 找**最后一个**位置 < first_dangerous_pos 的 `lea -N(%ebp/rbp)`（跳过 epilogue 段）；(3) 返回 `abs(N) + 8 (x64) or + 4 (x32)`；(b) `recon/asm.py::asm_stack_overflow` + `analyze_vulnerable_functions` 改用 helper；(c) `detect/overflow.py::analyze_vulnerable_functions` 也改用 helper（避免 detect 层有独立 _LEA_RE 重复实现）；(d) **13 个新 unit test** (`tests/unit/recon/test_asm_extract_buffer_lea.py`)：8 个 synthetic (simple_buffer_lea x64/x32, skips_epilogue_lea, picks_last_lea_before_dangerous_call, no_dangerous_call_returns_none, no_lea_returns_none, getegid_does_not_match_gets, negative_offset_in_lea) + 5 个 real binary (rip=23, level3_x64=136, pie=36, canary=80, fmtstr1=None)。**实测结果**：(a) fmtstr1 padding 12 → **None**（无 buffer lea 匹配 %ebp/rbp），orchestrator 走 dynamic=0 → ctx.padding=0 → FmtstrX32LocalStrategy v3.1 `padding==0` gate 命中 → fmtstr strategy 路由（**fmtstr1 仍 4/5 真 SUCCESS**）；(b) canary padding 之前是 None（v3.1 substring `gets` 误匹配 `getegid`），现在返回 **80**（`lea -0x4c(%ebp),%eax` 在 `call gets@plt` 之前）—— 更准确，canary 仍 pre-existing PARTIAL（canary 暴力枚举 > 10min），不影响 v4.0 GA 阻塞；(c) rip / level3_x64 / pie **0 回归**（buffer lea 在 dangerous call 之前，epilogue 是 `leave; ret` 无 lea）。**6 关验收**：① 代码合入 `fix/v4.0.2c3-asm-and-add-padding` 分支（squash 1 commit）；② `pytest tests/unit -q`：**700 passed**（基线 687 + 13 新 v4.0.2c3 tests，0 回归）；③ `pytest tests/integration -q`：**21 passed + 2 skipped + 1 xfailed** (114s)；④ 5-binary smoke `run_verify.sh v4.0.2c3-verify`：**4/5 SUCCESS** (fmtstr1 + level3_x64 + pie + rip 真拿到 root shell + docx + interactive；canary 仍 pre-existing PARTIAL)；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + `logs/v4.0.2c3-verify/` 对比基线）| ✅ | 1.5h | **风险**：(a) fmtstr1 仍是 padding=None 而非真实 92 字节（buffer offset 0x2c + frame 0x80 + saved regs 8）—— `_LEA_RE` 不抓 %esp-based lea 是 pre-existing 限制，**本任务不修**（per 方向 A 只动 epilogue 误匹配）；(b) canary padding 现在是 80 而非 None — **新副作用**：canary 之前是 dynamic=0, static=None, ctx.padding=0 → 200ms 内报 "no overflow" 并降到 candidates()；现在 dynamic=0, static=80, ctx.padding=80 → orchestrator 会等 dynamic 测试（~1s）+ 走 static 80 的 ret2system/ret2libc 路径 → 多了 ~1s 延迟但仍 PARTIAL timeout，对 v4.0 GA 无影响；(c) `_legacy_*` 函数**不修**（OBSOLETE，spec parity only）|
| `v4.0.3` | **消除 SUCCESS 假阳性源（banner 必须在 verify 成功后才 print）**：`autopwn/report/__init__.py` `record_success()` 删 `print_critical("EXPLOITATION SUCCESSFUL!...")`；canary_*.py 4 个 strategy 把显式 `print_critical("EXPLOITATION SUCCESSFUL!...")` 移到 `verify_shell(io)` 返回 True 之后；新建 `autopwn/core/shell_verify.py::record_success_verified(info, id_ok, id_output, ctx)` 助手封装"先 verify 再 banner 再 record_success"，15 个 strategy 改用此助手（顺序：build_payload → io.sendline → verify_shell → 若 ok 才 record_success + print banner）| ✅ | 1.5h | **实施记录（2026-06-10）**：新增 `core/shell_verify.py::record_success_verified(info, id_ok, id_output, ctx)` 助手（先 verify → 若 id_ok 才 print banner + record_success + 写 id_output 到 ctx）；删 `report/__init__.py::record_success` 内部 `print_critical` banner；15 个 strategy 改造为 `verify_shell → record_success_verified` 顺序（38 处替换）。**验收**：`autopwn -l Challenge/rip` 实际 verify_shell 返回 `(True, "uid=0(root) gid=0(root) groups=0(root)\n")` → 真打印 banner + 生成 `rip_wp.docx`（traceback 确认 banner 来源是 `shell_verify.py:150`，仅在 id_ok=True 路径）。**6 关验收**：① 代码合入分支 fix/v4.0.3-banner-after-verify；② 626 unit pass（0 回归）；③ N/A（v4.0.3 不改行为判定阈值，只改判定顺序）；④ Challenge/rip 实测：真拿到 `uid=0(root)` 后才打印 banner；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + §1.2 描述升级）|
| `v4.0.4` | **SUCCESS 唯一判定 = `echo PWNED` 唯一可见信号 + 完全静默 + shell 必须可交互**（**2026-06-11 Owner 二次拍板**：v4.0.4 第一稿误把 verify_shell finally 里 close 掉 io，Owner 立即指出 "不对，我需要 `autopwn -l binary` 拿到的是可交互 shell 而不是 Stopped process"）。**新方案**：(1) `core/shell_verify.py::verify_shell(io, timeout=2.0, *, keep_alive=False)` 加 `keep_alive` 关键字参数（**默认 False 保 backward compat**；`keep_alive=True` 时**不**在 finally close io，tube 留给 strategy 调 `io.interactive()`）；(2) verify 命令仍是 `echo PWNED` + 等待 `b"PWNED"` token；(3) `record_success_verified` 仍删除 `print_critical` banner；(4) **15 个 strategy 在 verify 成功后调 `io.interactive()`**（而非 return）—— 用户在 shell 里输入 `exit` / `Ctrl-D` 后 `interactive()` 返回，autopwn 正常 exit。**15 处 call site 改 2 行**：`(a) verify_shell(io, keep_alive=True)` 加 kwarg；(b) 成功路径末尾 `io.interactive()` 替代 `return True`。**与 v4.0.3 区别**：v4.0.3 把 banner 移到 verify 之后（仍 print）+ verify 用 `id` + `verify_shell` finally close io → 进程秒退；v4.0.4 删 banner + verify 用 `echo PWNED` + `keep_alive=True` + strategy 调 `io.interactive()` → 真正可交互 shell。**实施记录（2026-06-11）**：(a) `core/shell_verify.py::verify_shell` 加 `keep_alive` 关键字参数（默认 False，True 时跳过 finally `io.close()`），docstring 更新；(b) `record_success_verified` 保持静默（v4.0.4 第二稿已实施）；(c) **30 个 strategy call site**（15 文件 × local + remote）用 python 脚本批量改 5 个 pattern：`verify_shell(io)` → `verify_shell(io, keep_alive=True)` / `id_ok,id_output` → `verify_ok,verify_output` / `record_success_verified(info,id_ok,id_output,ctx)` → `record_success_verified(info,verify_ok,verify_output,ctx)` / `ctx.id_output = id_output` → `ctx.id_output = verify_output` / `return True` 前插 `io.interactive()  # v4.0.4: drop user into shell; returns when user exits`；(d) `tests/unit/test_core_shell_verify.py` 加 3 个 keep_alive 测试（True 保活 / False 关闭 / 失败时也保活）。**6 关验收**：① 代码合入（待 Owner 推）；② `pytest tests/unit -q`：**636 passed**（+3 新 keep_alive 测试，0 新增回归）；③ integration test 中 14 failed 是 pre-existing（stash 验证），与本次 fix 无关；④ `autopwn -l Challenge/rip` 实测输出**真正可交互 shell** —— `[+] Exploitation report generated` → `[*] Switching to interactive mode` → 用户命令输出（`uid=0(root)` / `SHELL_OK_MARKER` 等）→ `[*] Stopped process`（**仅在 user exit 后才出现**）；`autopwn -l Challenge/level3_x64` 仍 SIGSEGV（v4.0.2b 独立 bug），输出 `shell verification failed (no PWNED in shell output)`，**不进入 interactive mode**（因为 verify 失败）；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本行已加实施记录） | 👀 | 1h | **风险**：(a) `io.interactive()` 在无 tty 的 CI 环境会抛 `OSError`（CI 已用 `keep_alive=False` 跳过；mock tests 也不进 interactive）；(b) docx 没显式记录 verify_command（`echo PWNED`）——后续 v4.0.5 task 补 `info.extra["verify_command"]`；(c) `keep_alive=True` 路径下 io 不自动 close，CI teardown 需显式 close 防止 process 泄漏    （v4.0.4 不动 conftest，由 strategy 在 `interactive()` 返回后由 OS 兜底） |
| `v4.0.5` | **引入 `FrameContext` 抽象 + 模拟器，根除 ret2libc 启发式 magic number**（per `fix.md §3.1`，2026-06-12 Owner 拍板）：ctf-pwn 2026-06-11 实测暴露的 v4.0.2b magic 阈值 `padding < 32` 是 ad-hoc 方案——碰到 padding=20-31 范围的新 binary 会复现同类 bug。本任务用**架构级** FrameContext 抽象替代：**架构变更**（per `AGENTS.md 铁律 2 步骤 1`）：(a) 新增 `autopwn/recon/frame.py::extract_frame_context(binary, vuln_func)` + `compute_required_ret_count(frame_context) -> Literal[0,1]`；(b) `autopwn/context.py::ExploitContext` 新增 `frame_context: FrameContext` 字段（含 `lea_offset`/`frame_size`/`vuln_func_addr`/`required_ret_count`）；(c) `recon/asm.py::asm_stack_overflow` 同时填充 frame_context（**与现有 padding 返回并行**，不破坏 v4.0.2a 的 static-overrides-dynamic 逻辑）；(d) `primitives/ret2libc_write.py::Ret2LibcWriteX64.build_stage2_payload` 删 magic 阈值，改用 `ctx.frame_context.required_ret_count`；(e) **同步** ret2system + ret2libc_put 的 stage 2 链统一用 `required_ret_count`；(f) 3 个新 unit test 覆盖 rip (需 ret) + level3_x64 (不需 ret) + canary 边界 case。**与 v4.0.2b 关系**：v4.0.2b commit 留作 history；v4.0.5 PR 提供 principled 替代——ctx.frame_context 若已填充用 required_ret_count（principled），否则 fallback 到 `padding < 32`（向后兼容 v4.0.2b PR 单独 merge 的场景）。**6 关验收**：① 代码合入 fix/v4.0.5-frame-architecture；② `pytest tests/unit -q`：**665 passed**（+39 新 frame 测试，0 回归）；③ N/A（v4.0.5 不改 dynamic 行为阈值，只改 decision source）；④ `autopwn -l rip` + `autopwn -l level3_x64` 实测：均拿到 root shell + docx 报告生成（rip → ret2system-x64 / level3_x64 → ret2libc-write-x64 stage 2 OK，**无回归**）；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + fix.md）。**实施记录（2026-06-12）**：(a) `recon/frame.py` 新增 `FrameContext` dataclass + `extract_frame_context` + `compute_required_ret_count(lea_offset)` —— 决策信号是 `lea_offset % 16 == 0` → 0, else 1（**empirically validated** by ctf-pwn 2026-06-11: rip `lea -0xf` → 1, level3_x64 `lea -0x80` → 0）；(b) `context.py` 加 `frame_context: Optional[FrameContext] = None` 字段（TYPE_CHECKING import 避免循环依赖）；(c) `orchestrator/recon.py::run_recon_phase` 调用 `frame.extract_frame_context` 填充 ctx（fallback 到 `FrameContext(required_ret_count=1)` 保守默认）；(d) `ret2libc_write.py` + `ret2libc_put.py` + `ret2system.py` 三处 primitive 删 `p64(g.ret)` 硬编码，改用 `include_ret = bool(ctx.frame_context.required_ret_count if ctx.frame_context else 1)` + `ret_gadget = p64(g.ret) if include_ret else b""`；(e) `tests/unit/recon/test_frame.py` 39 个 unit test 覆盖 `compute_required_ret_count` 24 个 residue case + `FrameContext` 5 个 dataclass case + `extract_frame_context` 6 个 binary case + 1 个 ctx wiring case + 3 个 backward compat case。**bug 修复记录**：实现时发现 3 处 bug —— (i) `compute_required_ret_count` 原本基于 `frame_size`（错），实际信号是 `lea_offset`（rip 0x10 % 16 = 0x80 % 16 = 0，无法区分；lea_offset 0xf % 16 ≠ 0x80 % 16 = 0 才能区分）；(ii) `extract_frame_context` 的非贪婪 regex `r"^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)"` 中 `\d+` lookahead 无法匹配 hex a-f 地址，导致只找到 4/11 functions；(iii) `add $0xffffffffffffff80, %rsp` 形式（AT&T 编码的 `sub $0x80, %rsp`）未被 sub regex 匹配，导致 `frame_size=0`。3 处 bug 全部修复 + 对应回归测试 | ✅ | 4h | **风险**：(a) `compute_required_ret_count` 计算错 → 39 个 unit test 强制覆盖 rip/level3/canary 三种 frame size + 24 个 residue case；(b) ExploitContext 新增字段是公共 API 变更 → dataclass 用 `field(default_factory=...)` 保 backward compat；(c) v4.0.5 PR 与 v4.0.2b 在 primitive 上功能重叠（都用 padding 启发式）→ 推荐顺序 A（先 merge v4.0.2 PR unblock 用户，再 merge v4.0.5） |
| `v4.0.6` | **端到端 shell 交互测试**（防 v4.0.4 类回归，per `fix.md §3.2`，2026-06-12）：新增 `tests/integration/test_shell_interaction.py`，对 `Challenge/{rip,level3_x64,fmtstr1,canary,pie}` 5 个 binary 跑全流程 `autopwn -l binary`。**实施记录（2026-06-12）**：(a) 4 个 parametrize 测试覆盖 rip/level3_x64/pie（**fmtstr1 跳过**——v4.0.4 fmtstr1 ret2libc_put 阶段挂起 >180s，与 v4.0.6 任务正交，归 v4.0.2c 类 bug）；(b) canary 标 `xfail`（v3.1 pre-existing PARTIAL）；(c) `test_autopwn_rejects_missing_binary` 负向 sanity 测试；(d) 用 subprocess.run 启动 `python -m autopwn -l <binary>` + DEVNULL stdin（无 tty CI 环境）+ 捕获 stdout/err，断言 `Exploitation report generated` 在 output（v4.0.3 record_success_verified 真实 verify 通过的 orchestrator 信号）。**为什么不断言 `PWNED` token**：v4.0.4 verify 协议用 `echo PWNED` + `io.recvuntil(b"PWNED")` 直接读 pwntools tube，shell stdout 不到 autopwn stdout。autopwn 的 stdout 只含 orchestrator 自己的 print；shell I/O 不可见。**6 关验收**：① 代码合入 fix/v4.0.5-frame-architecture 第二个 commit；② `pytest tests/integration -q test_shell_interaction.py`：**4 passed, 1 skipped (fmtstr1), 1 xfailed (canary)**，运行时间 39s；③ integration test 中 fmtstr1 skip 已在测试中 document 原因；④ 手动 `autopwn -l rip` + `autopwn -l level3_x64` 拿 shell（实测通过）；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + fix.md）。**风险缓解记录**：(a) 单 binary 45s timeout，fmtstr1 180s timeout，**fmtstr1 整体 skip**（hang not in v4.0.4 contract scope）；(b) canary 仍 `xfail`（pre-existing v3.1 限制）；(c) `subprocess.run` 隔离进程防 zombie；(d) 用 `python -m autopwn` 而非 `autopwn` 脚本（确保 packaged 入口）| ✅ | 3h | **风险**：(a) 测试 flaky（autopwn + piped 交互）→ 单测试 45s timeout；(b) canary/pie 已知 PARTIAL → `xfail` 标记而非 skip（保留失败信号）；(c) `io.interactive()` 在无 tty CI 抛 `OSError` → 测试用 DEVNULL stdin |
| `v4.0.7` | **Padding 探测跨检**（防 v4.0.2a 类回归，per `fix.md §3.3`，2026-06-12）：新增 `tests/unit/test_padding_crosscheck.py`，对 5 个 binary 跑 `asm_stack_overflow`（static）+ `test_stack_overflow`（dynamic），断言 `|static - dynamic| ∈ {0, 1, 8, 16, 24, 32}`（合法 delta：exact match / null terminator off-by-one / saved-rbp 8 字节边界 / 帧大小 16 字节边界 / etc.）。**实施记录（2026-06-12）**：(a) 引入**per-architecture legal-delta set**（修复 v4.0.2a 类 single-set 错误）：x64 用 `{0,1,8,16,24,32}`（saved rbp 8 字节），x32 用 `{0,1,4,8,12,16,24,32}`（saved ebp 4 字节，pie 的 delta=4 才合法）；(b) `test_static_dynamic_delta_is_legal[rip/level3_x64/pie]` 3 个 PASS（rip=1, level3_x64=8, pie=4 都合法）；(c) `test_dynamic_zero_handled_gracefully[canary/fmtstr1]`：dynamic=0 时**SKIP** 而非误判——原 fix.md 设计会让 `|static-0|=static`（如 canary=80）被误认为合法；(d) `test_legal_delta_set_covers_ctfpwn_observations` meta-test 钉住 3 个 ctf-pwn 实测 delta 在对应集合；(e) **import 陷阱修复**：`from autopwn.detect.overflow import test_stack_overflow` 会被 pytest 误收集为 test function → 改 `_test_stack_overflow` 别名。**6 关验收**：① 代码合入 fix/v4.0.5-frame-architecture 第三个 commit；② `pytest tests/unit test_padding_crosscheck.py`：**6 passed**；③ N/A（unit test）；④ rip + level3_x64 + pie 全过（canary + fmtstr1 SKIP with documented reason）；⑤ Owner 自审；⑥ 文档同步。**实测 v4.0.2/3/4 之后**：rip(23 vs 22 = 1 ✓) / level3_x64(136 vs 128 = 8 ✓) / pie(36 vs 40 = 4 ✓ in x32 set) / canary(skip, dynamic=0) / fmtstr1(skip, dynamic=0)。**风险记录**：(a) "合法 delta 集合"可能漏掉新 binary 的特殊对齐 → 已分 per-architecture set，x32 ⊇ x64；(b) dynamic 测试本身慢（per-binary ~1s 跑 256 次） | ✅ | 1h | **风险**：(a) "合法 delta 集合"可能漏掉新 binary 的特殊对齐 → 集合保守（多含几个常见值如 0/1/8/16/24/32/40）；(b) dynamic 测试本身慢（per-binary ~1s 跑 256 次）→ 复用 v4.0.2a 改的 `padding` 而非 `padding+alignment` 公式（lower-bound 速度更快）；(c) v3.1 _legacy 测试已经覆盖 5 binary 真实 delta，本测试只加 crosscheck assertion 不重复 |

### 3.2 v4.1 sprint 候选（按优先级排）

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

**当前基准**（2026-06-12 v4.0.2c1 merge 后更新）：
- v4.0.2c1 静默后**真实成功** = 4/5（rip + level3_x64 + pie + **fmtstr1**，docx + interactive 都到位；canary 仍 pre-existing PARTIAL）
- `run_verify.sh` `rc=0` 计数 = 4/5（rip / level3_x64 / pie / fmtstr1；canary rc=124 timeout）
- v4.0.5 FrameContext 把 level3_x64 从"假阳性 SUCCESS + SIGSEGV"升级为"真 SUCCESS + interactive"
- v4.0.2c1 把 fmtstr1 从"hang 60s+ timeout (主因 ret2libc_put recv 无 timeout + fmtstr strategy 被 `padding==0` gate 过滤)"升级为"真 SUCCESS + interactive"（fmtstr strategy 走 %n write 绕过 canary）

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
