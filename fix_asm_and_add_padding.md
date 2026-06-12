# fix_asm_and_add_padding.md — asm_stack_overflow 把 epilogue lea 误当 buffer offset

> **关联任务**：[`upgraded.md §3.1 v4.0.2c3`](./upgraded.md)
> **状态**：✅
> **修复时间**：2026-06-12
> **分支**：`fix/v4.0.2c3-asm-and-add-padding` → squash merge → commit SHA `390ea96` (parent)
> **关联 fix**：[`fix_fmtstr1_routing.md`](./fix_fmtstr1_routing.md)（v4.0.2c1, fmtstr1 padding 12 → None 依赖本 fix）

---

## 1. 现象 (Symptom)

`Challenge/fmtstr1` (x32 + format string + canary) 在 v4.0.2c1 fix 之前，`recon/asm.asm_stack_overflow` 返回 **`12` 字节**（v3.1 时代静默 banner 假阳性，v4.0.4 静默后露出）：

```bash
$ python3 -c "from autopwn.recon.asm import asm_stack_overflow; from pathlib import Path; \
              print(asm_stack_overflow(Path('Challenge/fmtstr1'), 32))"
12
```

- 12 字节 = `|lea offset| + 4 (x32)`
- `|lea offset|` = 8 = `-0x8` = `lea -0x8(%ebp),%esp` 的绝对值
- **-0x8 不是 buffer offset**——是 main 末尾的 epilogue，恢复 esp 的指令，8 字节 = saved regs (push %edi; push %ebx)

**fmtstr1 main disassembly**（完整 trace）：
```asm
0804854d <main>:
  804854d:	push   %ebp
  804854e:	mov    %esp,%ebp
  8048550:	push   %edi
  8048551:	push   %ebx
  8048552:	and    $0xfffffff0,%esp          ; align esp to 16 (gcc -mpreferred-stack-boundary=4)
  8048555:	add    $0xffffff80,%esp          ; sub esp, 0x80 (= 128 bytes)
  8048558:	... (canary load: mov %gs:0x14, %eax; mov %eax, 0x7c(%esp))
  8048570:	lea    0x2c(%esp),%eax           ; <-- BUFFER at esp+0x2c (NOT %ebp-based)
  8048574:	... (memset, call read@plt, call printf@plt, canary check)
  8048602:	lea    -0x8(%ebp),%esp           ; <-- EPILOGUE (restore esp from ebp)
  8048606:	pop    %ebx
  8048607:	pop    %edi
  8048608:	pop    %ebp
  8048609:	ret
```

---

## 2. 根因 (Root Cause)

`autopwn/recon/asm.py:78` 的 `_LEA_RE = re.compile(r"lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)")` 只匹配 **%ebp/%rbp** 的 lea，且 `_LEA_RE.search(func_body)` 抓**函数内第一个**匹配。

对 fmtstr1 main：
1. 唯一的 `lea -N(%ebp)` 是 epilogue 的 `lea -0x8(%ebp),%esp`（在 `call read@plt` 之后）
2. 真 buffer lea 是 `lea 0x2c(%esp),%eax`（用 %esp，因 `and+add` 破坏了 %ebp→%esp 标准对应）—— `_LEA_RE` **不匹配**
3. 算法返回 `abs(-0x8) + 4 = 12`（**完全错**）

**Sub-issue**: `_DANGEROUS_CALLS` 用了 `any(c in body for c in _DANGEROUS_CALLS)` 子串匹配，canary 的 `getegid@plt` 含 "gets" 子串 → `has_dangerous_call=True` 误判（但 canary 函数本身无 lea，未触发本 bug，但隐含 substring false positive trap）

**Sub-issue**: `_extract_buffer_lea_padding` 是公共 helper，但 `analyze_vulnerable_functions`（recon/asm.py:166）和 `detect/overflow.py::analyze_vulnerable_functions` (line 190) 都各自重复实现同样 `_LEA_RE.search` 逻辑 —— 3 处需同步修

---

## 3. 修复 (Fix)

**方向 A**（per Owner 2026-06-12 拍板）：抽出 helper `_extract_buffer_lea_padding(func_body, bit)`，算法 = 找**第一个 dangerous call 之前最近的** `lea -N(%ebp/rbp)`（跳过 epilogue 段）。

**代码**（`autopwn/recon/asm.py`）：
```python
# v4.0.2c3: pattern for finding a dangerous call site in func body.
# Loose match — accepts ``call <addr> <name>@plt`` (AT&T objdump) or
# ``call <name>`` (intel).  Negative lookahead so "getegid" doesn't
# match "gets" (substring trap in v3.1 _DANGEROUS_CALLS check).
_DANGEROUS_CALL_RE_TPL = r"call\s+[\w<>, ]*?{name}(?![A-Za-z0-9_])"


def _extract_buffer_lea_padding(func_body: str, bit: int) -> Optional[int]:
    """v4.0.2c3: find the buffer-setup lea in a function body.

    Walks the disassembly to find:
      1. The FIRST dangerous call (read/gets/fgets/scanf)
      2. The LAST ``lea -N(%ebp/%rbp)`` BEFORE that call

    The second pattern is the buffer setup; the lea in the
    function epilogue (``lea -0x8(%ebp),%esp`` to restore esp)
    is AFTER the dangerous call and is correctly excluded.
    """
    first_dangerous_pos = -1
    for dangerous in _DANGEROUS_CALLS:
        pattern = _DANGEROUS_CALL_RE_TPL.format(name=re.escape(dangerous))
        m = re.search(pattern, func_body)
        if m and (first_dangerous_pos == -1 or m.start() < first_dangerous_pos):
            first_dangerous_pos = m.start()
    if first_dangerous_pos == -1:
        return None

    lea_matches = list(_LEA_RE.finditer(func_body))
    valid_leas = [m for m in lea_matches if m.start() < first_dangerous_pos]
    if not valid_leas:
        return None

    lea_match = valid_leas[-1]
    offset_dec = abs(int(lea_match.group(1), 16))
    return offset_dec + 8 if bit == 64 else offset_dec + 4
```

**3 处调用点**改用 helper：
- `recon/asm.py::asm_stack_overflow` (line 124)
- `recon/asm.py::analyze_vulnerable_functions` (line 166)
- `detect/overflow.py::analyze_vulnerable_functions` (line 190) —— 消除独立 `_LEA_RE` 重复实现

**备选方案对比**（未选）：
- **(α) 走 instruction-level parser**（先找 `call read@plt` 位置，回看 10 条指令找 buffer setup）：~50 行，涵盖更多 edge case，但风险中（重写 parser）
- **(β) 加白名单跳过 `lea -0x8(%ebp),%esp` epilogue pattern**：~5 行，但不通用（其他 epilogue pattern 如 `lea -0x10(%rbp),%rsp` 不匹配）
- **(γ) 只改 docstring 说"and+add 形式 padding 不可靠"**：~5 行，0 风险但 fmtstr1 padding 仍 12 错

---

## 4. 验证 (Verification)

6 关验收（per AGENTS.md §1 铁律 4 + `upgraded.md §5`）：

| 关 | 标准 | 结果 |
|---|---|---|
| ① | 代码已合并到 main | ✅ commit `390ea96` 在 main（squash of 1 commit） |
| ② | `pytest -m "not integration"` 全绿 | ✅ 700 passed（基线 687 + 13 新） |
| ③ | `pytest -m integration` 跑通 | ✅ 21 passed + 2 skipped + 1 xfailed（114s） |
| ④ | autopwn -l 至少 1 binary 实测成功 | ✅ 5-binary smoke `run_verify.sh v4.0.2c3-verify`：**4/5 SUCCESS** (fmtstr1 + level3_x64 + pie + rip 真拿到 root shell + docx + interactive) |
| ⑤ | Owner 自审 | ✅（单 Owner 项目） |
| ⑥ | 文档同步 | ✅ `upgraded.md §3.1` v4.0.2c3 标 ✅ + `logs/v4.0.2c3-verify/` 对比基线 |

**13 个新 unit test** (`tests/unit/recon/test_asm_extract_buffer_lea.py`)：

8 个 synthetic：
- `test_simple_buffer_lea_x64` / `test_simple_buffer_lea_x32` — happy path
- `test_skips_epilogue_lea` — **本 fix 的核心 case**（fmtstr1 epilogue lea 正确跳过）
- `test_picks_last_lea_before_dangerous_call` — multiple leas 时取最后一个
- `test_no_dangerous_call_returns_none` — no read/gets → None
- `test_no_lea_returns_none` — no lea at all → None
- `test_getegid_does_not_match_gets` — **substring false positive trap** (negative lookahead 验证)
- `test_negative_offset_in_lea` — `lea -0x80(%rbp)` 工作

5 个 real binary：
- `test_returns_expected_padding[rip-64-23]`
- `test_returns_expected_padding[level3_x64-64-136]`
- `test_returns_expected_padding[pie-32-36]`
- `test_returns_expected_padding[canary-32-80]` — **新副作用**：canary padding 之前 None (v3.1 `gets` 误匹配 `getegid`)，现在 80
- `test_fmtstr1_returns_none` — **fmtstr1 padding 12 → None** (epilogue 跳过 + buffer lea 用 %esp 不匹配 pre-existing)

---

## 5. 风险与遗留 (Risk & Followup)

**已确认风险**：
- (a) **fmtstr1 仍是 padding=None 而非真实 92 字节**（buffer offset 0x2c + frame 0x80 + saved regs 8）—— `_LEA_RE` 不抓 `%esp`-based lea 是 pre-existing 限制，**本任务不修**（per 方向 A 只动 epilogue 误匹配）
- (b) **canary padding 现在是 80 而非 None** — 新副作用：canary 之前 dynamic=0, static=None → 200ms 内报 "no overflow"；现在 dynamic=0, static=80 → 等 dynamic 测试（~1s）+ 走 static 80 的 ret2system/ret2libc 路径 → 多了 ~1s 延迟但仍 PARTIAL timeout，对 v4.0 GA 无影响
- (c) **`_legacy_*` 函数不修**（OBSOLETE，spec parity only）

**遗留问题**（已立后续任务）：

- **fmtstr1 padding 真实值 92 字节未识别**（`%esp`-based buffer lea + `and+add` frame）：需要新增 `%esp`-based lea 的 regex（如 `lea\s+(-?0x[0-9a-f]+)\(%esp\)`）+ frame size 推断（`and 0xfffffff0, %esp; add 0xffffff80, %esp` → frame 0x80）。可立 v4.0.2c5 / v4.0.8，**不是本任务范围**（per `upgraded.md` v4.0.2c3 风险 (a)）
- **`_extract_buffer_lea_padding` 在 `detect/overflow.py` 用了 `TYPE_CHECKING` 风格的 import**（`from autopwn.recon.asm import _extract_buffer_lea_padding`）—— 严格说这是 layer violation（detect 层 import recon 层私有函数），per `refactor.md §3` 分层依赖是 detect → recon 应是 detect → core → recon。**当前不修**（单行 private function import，重构成本 < 收益），列 v4.1 架构优化任务

**关联 fix**：
- [`fix_fmtstr1_routing.md`](./fix_fmtstr1_routing.md) (v4.0.2c1) — 修 fmtstr1 hang，依赖本 fix 把 padding 12 → None 让 fmtstr strategy 路由生效
- [`fix_x64_recv_timeout.md`](./fix_x64_recv_timeout.md) (v4.0.2c4) — x64 mirror fix，与本 fix 独立
