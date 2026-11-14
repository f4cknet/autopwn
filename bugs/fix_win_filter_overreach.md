# fix_win_filter_overreach.md — win 剔除规则误杀「同函数既有输入又有 win」的题

> **关联任务**：[`v7.3.0`](../upgraded/v7.3.0.md)
> **状态**：✅ 已进入 `main`
> **修复时间**：2026-11-14
> **发现于**：样本外 10 题测试（题三 492f）+ 回归（ch04_5ff0 / ch09_cf87）

---

## 1. 现象

`bench` 从 13/15 掉到 **11/15**，`ch04_5ff0`、`ch09_cf87` 双双归零，`attempts=0`。
同一时间，样本外题三（`492fad50`）报 `vulns=[]`，但该二进制明明有 `scanf("%s", buf)`。

## 2. 根因

`facts.py:analyse` 里的剔除规则：

```python
win_addrs = {w.addr for w in f.wins}
f.vulns = [v for v in f.vulns if v.func_entry not in win_addrs]
```

原意是「`print_flag` 自己 `read(fd,buf,n)` 不算用户输入漏洞」，
但它按**函数入口**整批剔除：只要该函数被 `_find_wins` 判成 win，
函数内**所有** sink 全被删。

于是「同一个函数既收用户输入、又调 `system`」的题被整类误杀：

| 题 | 函数 | 被删的 vuln | 该函数内的 win |
|---|---|---|---|
| 题三 492f | `main@0x400889` | `__isoc99_scanf@0x4008b5` | `system("/bin/sh")` |
| ch04_5ff0 | `@0x400676` | `gets@0x40069d` | `system("cat /flag")` |
| ch09_cf87 | `@0x4005f6` | `read@0x400619` | `system("echo …")` |

**为什么以前没暴露**：`_offsets` 有无证据兜底枚举，`vulns=[]` 时仍会盲试 70 个偏移，
其中恰好命中，于是 ch04/ch09 靠运气过。`v7.3.0` 关掉盲猜，bug 立刻现形。

## 3. 修复

只在「该函数自己 `open/fopen` 了文件」时才剔除——这才是「读 flag 自身」的语义：

```python
file_open_funcs = _funcs_with_file_open(ch, d, entries)
for v in f.vulns:
    if v.func_entry in win_addrs and v.func_entry in file_open_funcs:
        dropped.append(v)
    else:
        kept.append(v)
```

`_funcs_with_file_open` 扫 `open/fopen/openat/open64/fopen64` 调用点，映射到函数入口。

## 4. 验证

| 对象 | 修复前 | 修复后 |
|---|---|---|
| ch04_5ff0 | 0 plans / FAILED | `gets off=56` → `ret2gets` **uid=0(root)** |
| ch09_cf87 | 0 plans / FAILED | `read off=136` → `ret2plt` **uid=0(root)** |
| 题三 492f | `vulns=[]` + 70 次盲打 | `vulns=1`，报 `UNRESOLVED: offset@0x4008b5 未识别` |
| bench_extra/ret2win | 靠剔除规则 | 行为不变（该函数确有 `open`，仍剔除） |
| 全量回归 | 11/15、5+1、4/4 | **13/15、5+1、4/4**（全部恢复，且零盲猜） |

## 5. 遗留

- 题三的报错措辞仍偏笼统：`scanf` 写入的是**全局缓冲区**（`buf@0x6010c0`），
  本就不存在「栈返回址距离」，应报「写入目标是全局缓冲区，无栈溢出」而不是「帧布局未识别」。
  → 归 `v7.3.1`
- ch09 的 `system("echo Input:")` 仍被判成 `flag` kind win（`NON_SHELL_CMD` 含 `"echo"`），
  属诱饵误判，不影响 shell 路径（`ret2plt` 排在 `ret2flag` 之前），→ 归 `v7.3.1`
