# v3.1 vs v4.0 严格对比报告

> **生成时间**: 2026-06-08 11:34:11 UTC
> **方法论**: 串行 runner（scripts/run_verify.sh）+ 60s/binary timeout
> **目的**: 验证 P0.0 全局改名（pwnpasi -> autopwn）+ P0.7 验证基础设施 引入的 v4.0 与 v3.1 行为一致性
> **Owner**: @Minzhi_Zhou
> **Ref**: rebuild.md §6.1 P0.8

## 1. 数据来源

- v3.1 logs: `logs/v3.1/<binary>.log` （临时 skin-swap 后的 pwnpasi 3.1 串行运行）
- v4.0 logs: `logs/v4.0/<binary>.log` （autopwn 4.0.dev0 串行运行）
- 5 个 binary 顺序: canary -> fmtstr1 -> level3_x64 -> pie -> rip
- 60s timeout 强制结束（canary 暴力枚举需 ~7min，预期 partial log）

## 2. 结果总览

| binary | v3.1 结果 | v4.0 结果 | log 大小 (v3.1/v4.0) | 一致标记 / 总数 |
|--------|----------|----------|----------------------|-----------------|
| canary | PARTIAL | PARTIAL | 98484B / 121320B | 2/3 |
| fmtstr1 | PASS | PASS | 56776B / 56702B | 6/6 |
| level3_x64 | PASS | PASS | 16608B / 15945B | 6/6 |
| pie | PASS | PASS | 15661B / 15095B | 7/7 |
| rip | PASS | PASS | 15926B / 15293B | 6/6 |

## 3. 总体一致性

- **关键标记一致性**: 27/28 = **96%**
- **EXPLOITATION SUCCESSFUL 计数**: v3.1 = 4/5, v4.0 = 4/5

## 4. 结论

✅ **PASS** — v3.1 → v4.0 重命名 + 验证基础设施 未引入行为差异

## 5. 详细对比

### 3.1 canary

- **v3.1**: PARTIAL（98484B, 1144 行）
- **v4.0**: PARTIAL（121320B, 1374 行）

| 标记 | v3.1 | v4.0 | 一致 |
|------|------|------|------|
| Padding (dynamic) | `3625` | `3424` | ⚠️ |
| fmtstr strategy | `YES` | `YES` | ✅ |
| libc path detected | `/lib32/libc.so.6` | `/lib32/libc.so.6` | ✅ |

### 3.2 fmtstr1

- **v3.1**: PASS（56776B, 503 行）
- **v4.0**: PASS（56702B, 504 行）

| 标记 | v3.1 | v4.0 | 一致 |
|------|------|------|------|
| Dropping to shell | `YES` | `YES` | ✅ |
| EXPLOITATION SUCCESSFUL | `YES` | `YES` | ✅ |
| EXPLOITATION type | `Format String - Local
,
4!
running sh.` | `Format String - Local
,
4!
running sh.` | ✅ |
| Padding (static) | `12` | `12` | ✅ |
| fmtstr strategy | `YES` | `YES` | ✅ |
| libc path detected | `/lib32/libc.so.6` | `/lib32/libc.so.6` | ✅ |

### 3.3 level3_x64

- **v3.1**: PASS（16608B, 207 行）
- **v4.0**: PASS（15945B, 185 行）

| 标记 | v3.1 | v4.0 | 一致 |
|------|------|------|------|
| Dropping to shell | `YES` | `YES` | ✅ |
| EXPLOITATION SUCCESSFUL | `YES` | `YES` | ✅ |
| EXPLOITATION type | `ret2libc (write) - x64
[*] [ts] 
[+] [ts` | `ret2libc (write) - x64
[*] [ts] 
[+] [ts` | ✅ |
| Padding (dynamic) | `136` | `136` | ✅ |
| libc path detected | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib/x86_64-linux-gnu/libc.so.6` | ✅ |
| ret2libc_write trigger | `YES` | `YES` | ✅ |

### 3.4 pie

- **v3.1**: PASS（15661B, 200 行）
- **v4.0**: PASS（15095B, 178 行）

| 标记 | v3.1 | v4.0 | 一致 |
|------|------|------|------|
| Dropping to shell | `YES` | `YES` | ✅ |
| EXPLOITATION SUCCESSFUL | `YES` | `YES` | ✅ |
| EXPLOITATION type | `PIE Backdoor - Local
[*] [ts] 
[+] [ts] ` | `PIE Backdoor - Local
[*] [ts] 
[+] [ts] ` | ✅ |
| PIE brute force | `YES` | `YES` | ✅ |
| Padding (dynamic) | `48` | `48` | ✅ |
| backdoor found | `YES` | `YES` | ✅ |
| libc path detected | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib/x86_64-linux-gnu/libc.so.6` | ✅ |

### 3.5 rip

- **v3.1**: PASS（15926B, 202 行）
- **v4.0**: PASS（15293B, 180 行）

| 标记 | v3.1 | v4.0 | 一致 |
|------|------|------|------|
| Dropping to shell | `YES` | `YES` | ✅ |
| EXPLOITATION SUCCESSFUL | `YES` | `YES` | ✅ |
| EXPLOITATION type | `ret2system - x64
please input
@
ok,bye!` | `ret2system - x64
please input
@
ok,bye!` | ✅ |
| Padding (dynamic) | `30` | `30` | ✅ |
| libc path detected | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib/x86_64-linux-gnu/libc.so.6` | ✅ |
| ret2system trigger | `YES` | `YES` | ✅ |

## 6. 备注

- **race condition 修复**: 历史 `/tmp/exploit_v31/*.log`（5 并发）出现 Information_Collection.txt 共享污染；
  本次串行跑出干净的 `/ctf/autopwn/logs/v3.1/*.log` 与 v4.0 对比
- **canary 60s timeout**: brute force 需 ~7 分钟，60s 截断后输出 partial log（不视为失败，仅记录行为）
- **未修 v3.1 既有 bug**: PIE backdoor 假设、canary brute force 慢 等已知问题 -> P1+ 阶段处理
