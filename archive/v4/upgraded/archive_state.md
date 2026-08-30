# archive_state.md — v4.1.21 前的详细状态快照

本文件保留 `upgraded.md` 在 **2026-08-30 / v4.1.21 瘦身前** 的详细状态说明，供历史追溯使用。
非追溯场景默认不读；日常迭代优先看精简后的 `upgraded.md`。

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
- **5/5 SUCCESS 仍不可达**：canary 真正暴力枚举路径仍需 > 10min，属于 pre-existing v3.1 限制；**v4.1.18 起** detect 层默认对 `canary_fuzz()` 加 **20s fail-fast budget**（可用 `--canary-max-seconds 0` 或更大秒数覆盖），避免离线批跑长期刷 `Starting local process`
- **覆盖率 44%**（行覆盖）：剩 56% 主要是 `_legacy_*` 函数（已 obsolete，按 `check_recon_coverage.py` 原则不测）；public API 覆盖率 95%
- **单一 Owner**：默认直接 `commit + push` 到 `main`；Owner 自审自行完成，不要求 PR（per `AGENTS.md §2.2`）。默认只在仓库主目录 `D:\ctf\ctf-env\autopwn`（容器 `/data/autopwn`）迭代，未经 Owner 明确授权不创建额外 worktree / 平行目录。

### 1.3 v4.1 候选方向

- **候选目标打分 + 利用链排序**：对 `win/flag/hack/backdoor/shell` 等候选目标函数，以及 `fmtstr -> leak canary -> second-stage BOF` / `fmt write -> GOT hijack` 等常见链路做 evidence-based scoring，替代 challenge-name / 单函数名热补丁
- **HEAP 利用**：当前 strategies 全部栈 / ROP / PIE，缺 `malloc` / `free` / `tcache` 漏洞利用
- **多 binary 批处理**：当前 CLI 单 binary；`-l <dir>` 多 binary 批跑
- **Web UI / RPC**：`orchestrator.run` 暴露为 HTTP/JSON（per `refactor.md §11` 旧扩展点）
- **类型化异常**：`except Exception as e` 收敛为 `ReconError` / `DetectionError` / `StrategyError`
- **LLM 辅助决策**：`candidates(ctx)` 优先级交给 LLM 微调（与 `mmx-cli` 技能联动）
- **canary 暴力优化**（v4.1.3）：现 v4.0.3 "5/5 SUCCESS" 已被 v4.0.2 占位；如未来需要，可重写为并行爆破 + smarter padding

---
