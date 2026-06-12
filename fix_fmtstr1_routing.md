# fix_fmtstr1_routing.md — fmtstr1 端到端 exploit 路径修复

> **关联任务**：[`upgraded.md §3.1 v4.0.2c1`](./upgraded.md)
> **状态**：✅
> **修复时间**：2026-06-12
> **分支**：`fix/v4.0.2c1-fmtstr1-hang` → squash merge → commit SHA `5a2afed` (parent)
> **关联 fix**：[`fix_asm_and_add_padding.md`](./fix_asm_and_add_padding.md)（v4.0.2c3, 同步修了 asm 静态分析的 epilogue 误匹配），[`fix_x64_recv_timeout.md`](./fix_x64_recv_timeout.md)（v4.0.2c4, x64 mirror 修）

---

## 1. 现象 (Symptom)

`Challenge/fmtstr1` 是 **format string + canary** 二进制（x32，gcc 编译，`mov %gs:0x14, %eax` canary 加载），pre-v4.0.2c1 状态：

```bash
$ timeout 60 python3 -m autopwn -l Challenge/fmtstr1 -v
[1;33m[!][0m [03:44:25] failed to leak canary value (will retry via candidates())
[1;32m[+][0m [03:44:25] format string vulnerability detected
[*] candidates: 3 strategies matched this context
[*] → trying ret2system-x32
[!] Ret2SystemX32LocalStrategy:: shell verification failed (no PWNED in shell output)
[*] → trying ret2libc-put-x32
[PAYLOAD] preparing ret2libc exploit using puts function
[+] Starting local process 'Challenge/fmtstr1': pid ...
# <-- HANGS HERE FOR 60s+ UNTIL TIMEOUT
```

`run_verify.sh` 60s timeout 报 `rc=124`；v4.0.6 commit 描述实测 >180s 仍未完成。`fmtstr1` 在 v3.1 banner 假阳性基线下曾误判 SUCCESS，v4.0.4 静默后露出真 hang。

---

## 2. 根因 (Root Cause)

3 个独立 root cause 协同导致 fmtstr1 hang + exploit 失败：

**(I) `autopwn/orchestrator/detect.py:92-97` 在 fmtstr 检测后未填充 `ctx.fmtstr_offset` 和 `ctx.fmtstr_buf`**
- P5.2 spec 写"do not write to ctx"（per `detect/fmtstr.py:36-39`）
- 但 P7.8 strategy `build_payload` 读 `ctx.fmtstr_offset` / `ctx.fmtstr_buf`，缺字段时返 `b""`
- fmtstr1 因此 fmtstr strategy 虽被选中但 primitive build_payload 返空

**(II) `autopwn/exp/strategies/fmtstr.py::FmtstrX32LocalStrategy.matches()` 守门 `ctx.padding == 0`**
- per v3.1 main() L3316（"only enter fmtstr branch when no BOF"）
- fmtstr1 静态分析返回 `ctx.padding = 12`（`recon/asm.analyze_vulnerable_functions` 误把 main 末尾 epilogue 的 `lea -0x8(%ebp),%esp` 当 buffer offset，详见 [`fix_asm_and_add_padding.md`](./fix_asm_and_add_padding.md)）
- fmtstr strategy 因此在 `candidates(ctx)` 阶段被过滤掉

**(III) `autopwn/exp/strategies/ret2libc_put_x32.py` 无 timeout hang**
- `io.recv()` (line 107) 等待 binary 初始 banner——fmtstr1 无 prompt（先 `read()` 后 `printf()`）→ 永远 hang
- `io.recvuntil(b"\xf7")` (line 113) 等待 puts 泄漏——canary 拦截后 binary 调 `__stack_chk_fail` 退出，puts 永不出现 → 永远 hang
- v3.1 ret2libc_write_x32.py:106 (`io.recv(4)`) 同样无 timeout

---

## 3. 修复 (Fix)

3 处修复 + 6 个新 unit test：

**(a) `autopwn/orchestrator/detect.py`** — fmtstr 检测后填充 ctx 字段
```python
# v4.0.2c1: when fmtstr is detected, populate the primitive's input fields
try:
    ctx.fmtstr_offset = detect_fmtstr.find_offset(ctx, program)
    from autopwn.recon import bss as recon_bss
    bss_syms = recon_bss.find_bss(
        program, min_size=2, name_filter=lambda n: "_" not in n
    )
    if bss_syms:
        ctx.fmtstr_buf = bss_syms[0].address
except Exception as e:
    print_warning(f"fmtstr offset/buf lookup failed: {e}")
```

**(b) `autopwn/exp/strategies/fmtstr.py` 5 个 strategy `matches()`** — 加 fallback
```python
# v4.0.2c1: also accept fmtstr-detected binaries (canary + fmtstr cases)
if ctx.padding == 0:
    return True
if ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None:
    return True
return False
```

**(c) `autopwn/exp/strategies/ret2libc_put_x32.py` + `ret2libc_write_x32.py`** — 加 timeout
```python
# Initial banner (cap 0.5s, allow binary without prompt to proceed)
try:
    io.recv(timeout=0.5)
except Exception:
    pass
io.sendline(payload1)

# Leak parse (cap 2s, raise TimeoutError → caught by except → return False)
try:
    puts_addr = u32(io.recvuntil(b"\xf7", timeout=2)[-4:])
except Exception as e:
    print_info(f"ret2libc-put-x32 leak parse failed: {e}")
    return False
```

**备选方案对比**（未选）：
- **(α) 加全局 hang detection 机制**（per-`io.recv()` watchdog + abort strategy + fallback）：架构层大改，超出本任务范围（per `upgraded.md` v4.0.2c1 row 风险记录）；留给 v4.0.2c3+ 阶段。
- **(β) `io.recv()` 直接删**（认为 banner read 是 no-op）：对 fmtstr1 OK，但对真带 prompt 的 binary（level3_x64 等）会 race condition —— 删不得，cap timeout 是最小侵入。
- **(γ) `io.recvuntil(b"\xf7")` 改 `io.recv(4)`**（size-known read per `io.recv(8)` x64 风格）：v3.1 ret2libc_write_x32.py:106 用 `io.recv(4)` 但也是无 timeout；本 fix 一并加 timeout 比改 design 更稳。

---

## 4. 验证 (Verification)

6 关验收（per AGENTS.md §1 铁律 4 + `upgraded.md §5`）：

| 关 | 标准 | 结果 |
|---|---|---|
| ① | 代码已合并到 main | ✅ commit `5a2afed` 在 main（squash of 1 commit） |
| ② | `pytest -m "not integration"` 全绿 | ✅ 687 passed（基线 681 + 4 新 + 2 改） |
| ③ | `pytest -m integration` 跑通 | ✅ 21 passed + 2 skipped + 1 xfailed（106s） |
| ④ | autopwn -l 至少 1 binary 实测成功 | ✅ 5-binary smoke `run_verify.sh v4.0.2c1-verify`：**4/5 SUCCESS** (fmtstr1 + level3_x64 + pie + rip 真拿到 root shell + docx + interactive) |
| ⑤ | Owner 自审 | ✅（单 Owner 项目） |
| ⑥ | 文档同步 | ✅ `upgraded.md §3.1` v4.0.2c1 标 ✅ + `§5.4` baseline 3/5 → 4/5 |

新增 6 个 unit test（per `upgraded.md` v4.0.2c1 row 实施记录）：

- `tests/unit/test_exp_fmtstr.py::test_x32_local_matches_padding_nonzero_when_fmtstr_fields_set`
- `tests/unit/test_exp_fmtstr.py::test_candidates_padding_nonzero_with_fmtstr_fields_includes_fmtstr`
- `tests/unit/test_exp_ret2libc_put.py::test_x32_local_recvuntil_called_with_timeout_2`
- `tests/unit/test_exp_ret2libc_put.py::test_x32_local_initial_recv_called_with_timeout`
- `tests/unit/test_orchestrator.py::test_fmtstr_detection_populates_ctx_fields`
- `tests/unit/test_orchestrator.py::test_fmtstr_detection_graceful_on_find_offset_failure`

外加 5 个已有 fmtstr tests 因 `matches()` 行为变更更新（`test_x32_local_rejects_padding_nonzero` 等）。

---

## 5. 风险与遗留 (Risk & Followup)

**已确认风险**：
- (a) 改 `matches()` fallback 让 fmtstr strategy 在不该选的 binary 上被选 → 守门 `ctx.fmtstr_offset is not None and ctx.fmtstr_buf is not None` 双字段，primitive 的 `build_payload` 会在缺字段时返空并打 `print_info` skip（已有逻辑）
- (b) `io.recvuntil(timeout=2)` 异常处理可能让原本能 leak 成功的 binary 现在被误判为 fail → 设 2s 偏保守，可后续 v4.0.2c5 调参

**遗留问题**（已立后续任务）：

- **`asm_stack_overflow` 把 `and+add` 形式算成 12 字节** → [`fix_asm_and_add_padding.md`](./fix_asm_and_add_padding.md) v4.0.2c3（已 ✅ merge，方向 A 修 epilogue 误匹配；`%esp`-based buffer lea 未识别仍 pre-existing）
- **x64 `ret2libc_put_x64.py:97` + `ret2libc_write_x64.py:98,187` 同样无 timeout** → [`fix_x64_recv_timeout.md`](./fix_x64_recv_timeout.md) v4.0.2c4（已 ✅ merge，mirror x32 fix）
- **`ret2system-x32` 在 fmtstr1 失败 (no PWNED)** → 是 fmtstr1 应走 fmtstr strategy 而不是 ret2system 的**预期行为**（fmtstr1 不是 ret2system exploit），本 fix 路由 fmtstr1 到 fmtstr 后 ret2system-x32 不会被试到 → **不视为遗留**（per `upgraded.md` v4.0.2c1 row 风险记录 (d)）
- **canary_ret2libc_*.py 同样无 timeout pattern** → v4.0.2c5 立任务（canary 是 pre-existing PARTIAL，列 v4.0.2c5）
- **`io.recv()` 的 0.5s timeout 是拍脑袋** → 可后续 v4.0.2c5 用 empirical 测 level3_x64 / rip 真实 banner 出现时间调优
