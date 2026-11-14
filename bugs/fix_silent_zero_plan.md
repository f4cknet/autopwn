# fix_silent_zero_plan.md — 零计划静默报 FAILED

> **关联任务**：[`v7.3.0`](../upgraded/v7.3.0.md)
> **状态**：✅ 已进入 `main`
> **修复时间**：2026-11-14
> **发现于**：样本外题十（`0b5afea1`）

---

## 1. 现象

```
[*] 0b5afea1…: i386/amd64 pie=True canary=True nx=True relro=Full vulns=3 wins=0
    => FAILED   (0.1s / 0 attempts)
```

`vulns=3`，但 **0 次尝试、0.1 秒**报 FAILED。输出里看不出是「没有可行计划」还是
「打了打不通」——对复盘零信息。

## 2. 根因

两处叠加：

1. `strategies._offsets` 用 `size_limit <= offset` 过滤（本身正确），
   该题三个 `read` 分别是 `lim=16/off=40`、`lim=1/off=33`、`offset=None` → 全部被滤掉 → 返回 `[]`。
2. `orchestrator.solve` 在「所有策略都没产出计划」时直接 `return res`，
   不填 `res.error`；CLI 只在 `res.error` 非空时打印 `!!`，
   于是 `FAILED` 后面什么都没有。

叠加效果：**事实层已经知道「这题打不了」，但这层知识没有传到人眼前**。

## 3. 修复

1. `Facts` 新增 `unknowns` / `unreachable`，由 `facts._audit_facts()` 在 `analyse` 末尾登记：
   - `plt_map` 为空 → `sink: PLT 映射为空`
   - 有 PLT 但无 sink / sink 被 win 规则剔除 → `sink: <原因>`
   - `v.offset is None` → `offset@0x…: 缓冲区→返回址距离未识别`
   - `size_limit <= offset` → `unreachable`（含 sink/call/offset/limit）
   - `fmt_buf is None` 但 printf 前有栈 lea → `fmt: 未确认参数来自用户输入`
2. `orchestrator._unresolved_reason()`：零计划时拼成 `UNRESOLVED: …` 写进 `res.error`。
3. `res.facts` 序列化 `unknowns` / `unreachable`，进 `results/*.json` 可追溯。

## 4. 验证

| 题 | 修复前 | 修复后 |
|---|---|---|
| 十 0b5a | `FAILED (0.1s / 0 attempts)` | `UNRESOLVED: read@0xc09 写入长度 16 < 返回址距离 40；read@0x1288 写入长度 1 < 33；offset@0x11f8 未识别` |
| 七 71b6 | `FAILED (27.6s / 80 attempts)` 盲打 | `UNRESOLVED: offset@0x804859d 未识别；fmt: 未确认参数来自用户输入` |
| 二 4b71 | `FAILED (24.5s / 35 attempts)` 盲打 | `UNRESOLVED: offset@0x400998 / 0x400a7f 未识别` |
| 一 4ee0 | `FAILED (23.6s / 71 attempts)` 盲打 | `UNRESOLVED: sink: PLT 映射为空（桩形态未识别）` |

10 题总 attempts：**461 → 195**，盲试 **231 → 0**。

## 5. 遗留

- `unknowns` 目前是自由文本，没有机器可读的 `code` 字段；
  做 `v7.5.0` 的「诊断准确率」指标时需要结构化（`{code, detail}`）→ 归 `v7.5.0`
- `--allow-brute` 已保留（默认关），盲试占比指标待 `v7.5.0` 统计
