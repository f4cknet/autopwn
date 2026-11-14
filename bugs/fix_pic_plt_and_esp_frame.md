# fix_pic_plt_and_esp_frame.md — 32 位 PIC 桩 / esp 相对帧 / i386 槽位传参的识别盲区

> **关联任务**：[`v7.3.1`](../upgraded/v7.3.1.md)（a / b / c / f 四项）
> **状态**：✅ 已进入 `main`
> **修复时间**：2026-11-14
> **发现于**：样本外题一（`4ee0fc91`）、题七（`71b6d3ae`）、题三（`492fad50`）

---

## 1. 现象

| 题 | 表面现象 | 实际原因 |
|---|---|---|
| 题一 4ee0 | `plt_map` 为空 → `vulns=[]` → 71 次盲打 | 桩是 `jmp dword ptr [ebx+0xc]`，旧解析只认 `[rip+X]` 与 `[0xADDR]` |
| 题七 71b6 | `offset=None`、`fmt_buf=None` | `add esp,-0x80` 未被识别；`printf` 走 `mov [esp],eax` 传参 |
| 题三 492f | 报「帧布局未识别」，措辞误导 | 写入目标是全局 `0x6010c0`，本就没有栈溢出可谈 |

## 2. 根因

三处都是「只认见过的编译器输出形态」：

1. **`model._build_plt_map`**：32 位 PIC 的 PLT 桩没有绝对地址，只有 `[ebx + N]`。
   不知 ebx 基址就完全解析不出导入表 → 整个二进制变瞎子（0 个 sink）。
2. **`facts._frame_size`**：只认 `sub esp,N`，且从 `.text` 起点往回扫，
   会抓到上一个函数的 `sub`；题七 `add esp,0xffffff80` 因此被算成 40（应为 128）。
3. **`facts._find_fmt`**：`base in ("rbp","ebp")` 是硬白名单，
   `and esp,0xfffffff0` 之后的 `[esp+0x2c]` 永远不匹配；
   `_pushed_for_call` 只认 `push reg`，不认 `mov dword ptr [esp], reg`。

## 3. 修复

| 位置 | 改法 |
|---|---|
| `_build_plt_map` | 收集所有 `[ebx+N]` 桩 → 对 `GOT地址 - N` 投票 → 得票 ≥2 的基址认定为 GOT 基址 → 反查符号 |
| `_frame_size` | 遇 `ret` 立即返回 None（不跨函数）；`add esp,-N` 与 `add esp,0xFFFFFFNN` 补码写法都换算成正的帧大小 |
| `_find_fmt` | 允许 `rsp/esp` 基址，换算 `val = fs + wordsize - disp`（「相对 rbp 的距离」） |
| `_pushed_for_call` | 增加 `mov dword ptr [esp(+X)], reg` 视为传参 |
| `_audit_facts` | 新增 `_buf_is_global`，`offset is None` 时区分「全局缓冲区」与「帧布局未知」 |

## 4. 验证

| 对象 | 修复前 | 修复后 |
|---|---|---|
| 题一 `plt_map` | 0 个导入 | **8 个**（`printf/puts/system/__isoc99_scanf/setvbuf/alarm/__stack_chk_fail/__libc_start_main`） |
| 题一 `vulns` | `[]` | `__isoc99_scanf@0x12d7` |
| 题七 `_frame_size` | 40 | **128** |
| 题七 `offset` | `None` | **84**（随后被 `limit=20` 正确判 `unreachable`） |
| 题七 `fmt_buf` | `None` | **88** |
| 题三 `unknowns` | 「帧布局未识别」 | 「写入目标是全局缓冲区 `0x6010c0`」 |
| 三套回归 | 13/15、5+1、4/4 | **13/15、5+1、4/4** |

## 5. 边界情况：win 里只有 read 没有 open

新剔除规则按「函数自己 `open`」判，会漏掉一种形态：
win 函数的 `read(fd, buf, n)` 读的是**调用方传进来的文件 fd**，函数内没有 `open`。
这种 read 会被重新当成漏洞候选。

补充判据 `_read_fd()`：解析 read 的第一个实参（x64 看 `edi/rdi` 的 `mov`/`xor`；
i386 看调用前**最近一次** `push`，cdecl 倒序）。`fd > 2` 即非 stdin → 仍剔除。

| 对象 | read 的 fd | 处理 |
|---|---|---|
| ch09_cf87 | 0 | 保留（用户输入，确实是漏洞点） |
| bench_extra/ret2win | 0 | 保留（原有行为不变） |
| ch04_5ff0 | 非 read（gets） | 不走该判据 |

fd 判定不出（如经 `mov [esp+4],reg` 传参）时保守**保留**，交给 `unknowns` 记录，
不静默丢弃——与 `v7.3.0` 的「不猜」原则一致。

## 6. 遗留

- 题七 facts 已全对，但 `s_fmtstr` 的目标只有 GOT，题七要写的是全局 `0x804a02c` → `v7.4.0`
- `add esp,-N` 与 `and esp,0xfffffff0` 组合时，对齐损耗静态不可知（0~12 字节），
  当前靠 `_offsets` 的 ±2 word 展开覆盖 → 若后续出现偏移差 4 的题，应加显式对齐候选
