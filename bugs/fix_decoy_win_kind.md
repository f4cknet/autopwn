# fix_decoy_win_kind.md — `system("echo …")` 被误判成 flag-win

> **关联任务**：[`v7.3.1`](../upgraded/v7.3.1.md)（d 项）
> **状态**：✅ 已进入 `main`
> **修复时间**：2026-11-14
> **发现于**：样本外题五（`fdfaa93a`）+ bench/ch09_cf87

---

## 1. 现象

题五 `hack()` 的函数体是 `system("echo flag")`，`_find_wins` 判成 `kind="flag"`，
于是 `s_ret2win_flag` 生成 3 个计划去打它。payload 真的打中了，输出字面 `flag`，
但判据（`FLAG_RE` 要求 `flag{…}`）不认 → `FAILED`。

ch09_cf87 更明显：`wins` 里出现
`flag@0x4005f6(system("echo Input:"))`、`flag@0x400620(system("echo 'Hello World!'"))`
—— 完全是 `printf` 型的提示输出，被当成了「打印 flag 的 win」。

## 2. 根因

```python
NON_SHELL_CMD = ("echo", "cat ", "ls ", "id", "whoami", "pwd", "date", "ps ")
if any(low.startswith(x) or x in low for x in NON_SHELL_CMD):
    kind = "flag"
```

把「命令是 shell 常见命令」等同于「这个 win 会产出 flag」。
只有 `cat` 类**读文件**的命令才可能产出 flag 内容；`echo/ls/id/whoami` 只输出常量。

## 3. 修复

拆成两个名单，先判读文件：

```python
FILE_READ_CMD = ("cat ", "cat\t", "head ", "tail ", "grep ", "strings ",
                 "xxd ", "more ", "less ", "awk ", "sed ", "tac ")
```

- `"/bin/sh"` → `shell`
- 命中 `FILE_READ_CMD` → `flag`
- 命中 `NON_SHELL_CMD`（echo/ls/id/…）→ **`decoy`**（新增 kind）

`decoy` 不参与 `s_ret2win_flag`（该策略只认 `kind == "flag"`），
并在 `_audit_facts` 里登记：

```
unknowns["win"] = "仅存在诱饵 win（打中也不产出 flag）：system(\"echo flag\")"
```

## 4. 为什么不是「放宽 FLAG_RE」

Owner 最初建议让 `FLAG_RE` 接受裸词 `flag`。**已否决**：
那会让任何 `puts("flag")` 的题假通过，属于 `AGENTS.md` L3 定义的「伪造验收」。
信息不丢的正确做法是新增 `win_reached` 态（不计 AC），归 `v7.4.0`；
`decoy` 只是让策略层不再浪费尝试去打一个注定拿不到 flag 的地址。

## 5. 验证

| 对象 | 修复前 | 修复后 |
|---|---|---|
| 题五 `wins` | `flag@0x804854b(system("echo flag"))` | `decoy@0x804854b(system("echo flag"))` |
| 题五 `unknowns` | 无 | `win: 仅存在诱饵 win（打中也不产出 flag）：system("echo flag")` |
| ch09_cf87 | `wins` 含两个 `system("echo …")` 假 flag win | 降级为 `decoy`，`ret2plt` 正常拿 shell |
| 三套回归 | 13/15、5+1、4/4 | **13/15、5+1、4/4** |
