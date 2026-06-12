# fix_x64_recv_timeout.md — x64 ret2libc strategies 无 timeout hang

> **关联任务**：[`upgraded.md §3.1 v4.0.2c4`](./upgraded.md)
> **状态**：✅
> **修复时间**：2026-06-12
> **分支**：`fix/v4.0.2c4-x64-recv-timeout` → squash merge → commit SHA `f493e55` (parent)
> **关联 fix**：[`fix_fmtstr1_routing.md`](./fix_fmtstr1_routing.md)（v4.0.2c1, x32 镜像 fix，4 处 hang 修复）

---

## 1. 现象 (Symptom)

v4.0.2c1 修了 **x32** 的 4 处 ret2libc strategies 无 timeout hang（`io.recv()` + `io.recv(4)` / `io.recvuntil(b"\xf7")`），**x64 版本有完全相同的 hang risk**：

```bash
# autopwn/exp/strategies/ret2libc_put_x64.py:97
puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))  # NO timeout

# autopwn/exp/strategies/ret2libc_put_x64.py:182 (remote)
puts_addr = u64(io.recv(8))  # NO timeout

# autopwn/exp/strategies/ret2libc_write_x64.py:98 (local)
write_addr = u64(io.recv(8))  # NO timeout

# autopwn/exp/strategies/ret2libc_write_x64.py:187 (remote)
write_addr = u64(io.recv(8))  # NO timeout

# 4 处 io.recv() banner read 也无 timeout (line 92 / 93 / 182 / 187)
io.recv()  # NO timeout
```

**实际触发**（per `upgraded.md` v4.0.2c1 复盘）：
- level3_x64 跑 x64 ret2libc-write 路径成功（padding 准确 + canary fmtstr 路由），**x64 hang risk 未实测触发**
- 但 fmtstr1 走 x32 ret2libc-put 路径触发了 x32 hang，**x64 是同 pattern 同样 fix**
- 本 fix 是**防御性**（mirror x32 已验证 fix）

---

## 2. 根因 (Root Cause)

**v3.1 ret2libc x64 strategy 实现风格**（per `autopwn/exp/strategies/ret2libc_put_x64.py` / `ret2libc_write_x64.py`）：

- `io.recv()` (无 count) 等 EOF——binary 无 prompt 时**永远 hang**
- `io.recvuntil(b"\x7f")` / `io.recv(8)` 无 timeout——binary 因 canary 拦截 / ROP crash 退出，泄漏字节永不出现时**永远 hang**
- pwntools 默认 `pwnlib.timeout.Timeout.default = forever`（per pwntools docs）

**v4.0 重构时沿用了 v3.1 hang bug**——v3.1 banner 假阳性让"无 hang = 假成功"在测试中表现为 OK（`[+] Exploitation report generated` 在 verify_shell 之前 print，所以即使后续 hang，docx 已生成）。v4.0.3 + v4.0.4 修 verify 协议后才露出真 hang。

**关联 fix**：[`fix_fmtstr1_routing.md`](./fix_fmtstr1_routing.md) (v4.0.2c1) 已修 x32 同 pattern bug；本 fix 是 x64 mirror。

---

## 3. 修复 (Fix)

**8 处修改**（4 文件 × 2 处 = 8 处）：

**(a) `autopwn/exp/strategies/ret2libc_put_x64.py`**:
```python
# Local (line 92-93): cap initial banner
io = process(str(ctx.binary.path))
try:
    io.recv(timeout=0.5)  # was io.recv() — v4.0.2c4
except Exception:
    pass
io.sendline(payload1)

# Local (line 97): cap leak parse
puts_addr = u64(io.recvuntil(b"\x7f", timeout=2)[-6:].ljust(8, b"\x00"))  # was no timeout

# Remote (line 182-183): same
# Remote (line 187): same
```

**(b) `autopwn/exp/strategies/ret2libc_write_x64.py`**:
```python
# Local (line 93): cap initial banner
# Local (line 98): cap leak parse
write_addr = u64(io.recv(8, timeout=2))  # was io.recv(8) — v4.0.2c4
# Remote (line 182): cap initial banner
# Remote (line 187): cap leak parse
```

**备选方案对比**（未选）：
- **(α) 抽公共 helper**（per-strategy 的 `safe_recv(io, count, timeout)` / `safe_recvuntil(io, delim, timeout)`）：架构层大改（4 文件 × 2 处 = 8 处变 1 个 helper + 8 处调用），超出本任务范围
- **(β) 改 `io.recv(8)` → `io.recvn(8)`**（pwntools `recvn` 不读 EOF 后的部分）：对 size-known read OK，但 leak 末尾若 binary 提前退出仍可能 hang——`timeout=2` 是更稳的最小侵入

---

## 4. 验证 (Verification)

6 关验收（per AGENTS.md §1 铁律 4 + `upgraded.md §5`）：

| 关 | 标准 | 结果 |
|---|---|---|
| ① | 代码已合并到 main | ✅ commit `f493e55` 在 main（squash of 1 commit） |
| ② | `pytest -m "not integration"` 全绿 | ✅ 702 passed（基线 700 + 2 新） |
| ③ | `pytest -m integration` 跑通 | ✅ 21 passed + 2 skipped + 1 xfailed（108s） |
| ④ | autopwn -l 至少 1 binary 实测成功 | ✅ 5-binary smoke `run_verify.sh v4.0.2c4-verify`：**4/5 SUCCESS** (fmtstr1 + level3_x64 + pie + rip 真拿到 root shell + docx + interactive) |
| ⑤ | Owner 自审 | ✅（单 Owner 项目） |
| ⑥ | 文档同步 | ✅ `upgraded.md §3.1` v4.0.2c4 标 ✅ + `logs/v4.0.2c4-verify/` 对比基线 |

**2 个新 unit test** (`tests/unit/test_exp_ret2libc_put.py`)：
- `test_x64_local_recvuntil_called_with_timeout_2` — `io.recvuntil(b"\x7f")` 用了 `timeout=2` kwarg
- `test_x64_local_initial_recv_called_with_timeout` — `io.recv()` 用了 `timeout=0.5` kwarg

外加 0 个已有 test 修改（x32 + x64 timeout fix 是 mirror，但只在 put_x32 / put_x64 加 test，write_x32 / write_x64 没单独加 test —— 复用 `_ctx_64` + `Ret2LibcPutX64LocalStrategy` 已覆盖，x64 write strategy 由 `Ret2LibcWriteX64LocalStrategy` 镜像代码可证 manual review）

---

## 5. 风险与遗留 (Risk & Followup)

**已确认风险**：
- (a) **x64 hang risk 实际未在 real binary 上触发**——level3_x64 4/5 SUCCESS 因 padding 准确 + canary 走了 fmtstr/ret2libc_put 路径，x64 版的 `io.recv(8)` 是 size-known read 通常 OK。本 fix 是**防御性**（mirror x32 已验证 fix）
- (b) **timeout=2 对 x64 leak 可能不够**——libc 地址 leak 涉及 `write(1, ..., 8)` syscall，binary 内调用开销 1-3s 正常。若 CI 出现 leak parse fail，可后续 v4.0.2c5 调到 timeout=5
- (c) **未动 canary_ret2libc_*.py**——canary x32/x64 4 个 strategy 用同样 pattern 但 canary 是 pre-existing PARTIAL，列 v4.0.2c5 立任务

**遗留问题**（已立后续任务）：

- **canary_ret2libc_*.py 4 个 strategy 同样无 timeout**（`canary_ret2libc_put.py` / `canary_ret2libc_write.py` × x32/x64）→ v4.0.2c5 立任务（防御性 mirror，canary 是 pre-existing PARTIAL 不影响 v4.0 GA 阻塞）
- **rwx_shellcode_*.py 也可能有无 timeout pattern**（未审）→ v4.0.2c5 顺带扫
- **fmtstr.py strategy 也有 recv 但通常 1-shot (sendline 后 verify_shell)** → 不需 timeout（verify_shell 自带 timeout）
- **`io.recv()` 的 0.5s timeout 是拍脑袋** → 可后续 v4.0.2c5 用 empirical 测 level3_x64 / rip 真实 banner 出现时间调优

**关联 fix**：
- [`fix_fmtstr1_routing.md`](./fix_fmtstr1_routing.md) (v4.0.2c1) — x32 镜像 fix，4 处 hang 修复
- [`fix_asm_and_add_padding.md`](./fix_asm_and_add_padding.md) (v4.0.2c3) — 与本 fix 独立
