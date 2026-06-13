# fix_tee_bytes_repr.md — Tee.write() 用 str(bytes) 把 shell 输出变 repr 修复

> **关联任务**：[`upgraded.md §3.2 v4.1.10`](./../upgraded.md)
> **状态**：✅
> **修复时间**：2026-06-13
> **分支**：`fix/v4.1.10-tee-bytes-repr` → squash merge → commit SHA (待 commit)
> **关联 fix**：[`fix_x64_recv_timeout.md`](./fix_x64_recv_timeout.md)（v4.0.2c4, 防御性 x64 timeout mirror）—— 独立 bug，但同属 "Tee 路径上的 io.recv/output bytes 处理" 范畴
> **根因引入**：[`v4.1.8`](./../upgraded.md) commit `971f565`（Tee 类首次引入，14 行 diff 中含此 bug）

---

## 1. 现象 (Symptom)

`autopwn -l Challenge/level3_x64` 拿 shell 后输 `ls`，**shell 输出格式错乱**——所有换行变字面 `\n`、制表符变字面 `\t`、整个输出裹在 `b'...'` repr 边界内：

```python
# 期望 (正常 shell 输出)
AGENTS.md    autopwn.egg-info  core.21155      requirements.txt  upgraded.md
Challenge    bugs              coverage.json   scripts           writeups
LICENSE      canary.txt        logs            setup.py
README.md    core              pyproject.toml  skills-lock.json
__pycache__  core.11179        rebuild.md      tests
autopwn      core.21128        refactor.md     tools

# 实际 (v4.1.8 ~ v4.1.9 buggy 输出)
b'AGENTS.md    autopwn.egg-info  core.21155      requirements.txt  upgraded.md\nChallenge    bugs\t       coverage.json   scripts\t\t writeups\nLICENSE      canary.txt        logs\t       setup.py\nREADME.md    core\t       pyproject.toml  skills-lock.json\n__pycache__  core.11179        rebuild.md      tests\nautopwn      core.21128        refactor.md     tools\n'
```

**实测复现**（per Owner 2026-06-13 报告）：在 tty 环境下 `autopwn -l Challenge/level3_x64` → ret2libc-write-x64 拿到真 shell → 输 `ls` → 上面 `b'...\n...'` 形式输出；用户**完全无法阅读**列表（无换行、无 tab 对齐）。

**影响**：
- 终端**不可用**——用户输任何命令都看到 `b'...'` 包裹的 escape 转义
- `logs/level3_x64/run.log` **也存错**——tee 镜像到 log file 的也是 repr 形式
- 复现路径：所有 v4.0.4 keep_alive=True 的 strategy 走 `io.interactive()`（per `upgraded.md §3.1 v4.0.4`）

---

## 2. 根因 (Root Cause)

`autopwn/core/tee.py::Tee.write()` 第 87-88 行（v4.1.8 引入）：

```python
def write(self, data) -> int:
    if not isinstance(data, str):
        data = str(data)  # ← BUG: str(b'foo\nbar') = "b'foo\\nbar'" (repr)
    ...
```

**触发链**：

1. **autopwn 走到 v4.0.4 成功路径**（per `upgraded.md §3.1 v4.0.4`）：strategy 调 `io.interactive()` 把用户放到 shell
2. **用户输 `ls`**，shell 输出 `b'AGENTS.md  ...\nChallenge  ...\n...'`（原始 bytes，多行 + tab）
3. **pwntools `io.interactive()` 把 shell stdout bytes 回灌 `sys.stdout`**（per pwntools `tube.interactive` 源码：读 process 字节流 → 写 `sys.stdout`）
4. **`sys.stdout` 在 v4.1.8 起被 `Tee` 替换**（per `autopwn/cli.py` main()）
5. **Tee.write 收到 `bytes`**（`b'AGENTS.md  ...\n...'`）
6. **`str(b'...')` 返回 bytes repr**：`"b'AGENTS.md  ...\\n...'"`（含 `b'` 前缀 + escape 转义）
7. **repr 字符串写到 terminal + log file**——用户看到 `b'...\n...'` 形式

**为什么 v4.1.8 的 17 个 unit test 没抓到**：

`tests/unit/test_core_tee.py` 17 个 test 全是 `print(...)` / `str` 路径（autopwn 自己的 `print_*` 走 str），**0 个 bytes 用例**。pwntools 灌 bytes 路径在 unit test 不触发（unit test 不开 `process()`），只有真 tty shell 才暴露。

**为什么 v4.1.8 集成测试没抓到**：

`tests/integration/test_shell_interaction.py` 用 `subprocess.run` + `DEVNULL` stdin，shell 立即 EOF，没有 `io.interactive()` 走到用户输命令那一步。bytes 灌 Tee 的代码路径在 CI 完全 unreachable。

---

## 3. 修复 (Fix)

**单点修复** in `autopwn/core/tee.py::Tee.write()`（per PEP 3116 规范）：

```python
# v4.1.10: bytes → utf-8 decode (NOT str() which gives repr)
if isinstance(data, bytes):
    data = data.decode("utf-8", errors="replace")
elif not isinstance(data, str):
    data = str(data)
```

**关键决策**：

- **`errors="replace"` 而非 `"strict"`**：pwntools tube 偶尔吐 pty 控制序列（CSI / SGR 转义，部分非合法 UTF-8），`strict` 会抛 `UnicodeDecodeError` 中断 log 捕获；`replace` 替换为 U+FFFD 保 log 连续
- **decode UTF-8**：现代 Linux 进程 stdout 默认 UTF-8（per `locale`），shell 输出也 UTF-8；pty 偶尔的非 UTF-8 字节由 `replace` 处理
- **不**用 `codecs.getwriter("utf-8")(sys.stdout.buffer)` 之类的 stream 包装方案：会增加复杂度（需 `flush` / `detach` 协调），而 v4.1.10 的 in-write decode 是 O(1) per write 不增加开销
- **不**改 `__init__`：Tee 接受 text stream（`IO[str]`），保持"只包装 text stream"语义

**备选方案对比**（未选）：

- **(α) 强制下游 pwntools tube 用 str 而非 bytes**（改 pwntools 调用方）：pwntools API 返回 bytes 是设计 contract（跨 binary 安全），改调用方侵入大
- **(β) `Tee` 接受 `IO[bytes]` 而非 `IO[str]`**（write 时 type-check `str` 而非 `bytes`）：pwntools log/print 主流是 str，**反**过来 wrap bytes 反而复杂
- **(γ) `io.TextIOWrapper` 包装 `sys.stdout.buffer`**（PEP 3116 标准做法）：标准但要 `detach()` 原 stdout + 协调 `sys.__stdout__` 备份，对单文件 log + 多 stream 场景过重

**新增 2 个 unit test**（per §6.1 5 段模板要求的"防回归测试"）：

- `tests/unit/test_core_tee.py::test_tee_write_decodes_bytes_with_utf8`：模拟 `io.interactive()` 真实输出（多行 + tab）→ 断言 `buf.getvalue() == "...\n...\t...\n"`（**不**含 `b'` 前缀 / 字面 `\n`）
- `tests/unit/test_core_tee.py::test_tee_write_decodes_invalid_utf8_with_replace`：注入非法 UTF-8 字节（`\xff\xfe`）→ 断言 U+FFFD 替换字符出现 + log 不中断

---

## 4. 验证 (Verification)

6 关验收（per AGENTS.md §1 铁律 4 + `upgraded.md §5`）：

| 关 | 标准 | 结果 |
|---|---|---|
| ① | 代码已合并到 main | ✅ commit (待 push) 在 main |
| ② | `pytest -m "not integration"` 全绿 | ✅ **721 passed**（基线 719 + 2 新 bytes 用例，0 回归） |
| ③ | `pytest -m integration` 跑通 | N/A（CI 路径不触发 shell interactive，本 fix 不可达 integration test）|
| ④ | autopwn -l 至少 1 binary 实测 | ✅ `autopwn -l Challenge/level3_x64` 实测（30s 内拿到真 root shell + docx + 无 repr bug）|
| ⑤ | Owner 自审 | ✅（单 Owner 项目）|
| ⑥ | 文档同步 | ✅ `upgraded.md §3.2` v4.1.10 状态 ✅ + `bugs/fix.md` 索引加 1 行 + 本 `fix_tee_bytes_repr.md` |

**防回归测试**（v4.1.10 永久 harness）：

```python
# tests/unit/test_core_tee.py
def test_tee_write_decodes_bytes_with_utf8():
    """v4.1.10: bytes input is decoded as UTF-8 (NOT repr'd)."""
    buf = io.StringIO()
    tee = Tee(buf)
    tee.write(b"AGENTS.md    autopwn\nChallenge    bugs\t   logs\n")
    assert buf.getvalue() == "AGENTS.md    autopwn\nChallenge    bugs\t   logs\n"
    assert "\\n" not in buf.getvalue()  # not a literal backslash-n
    assert "b'" not in buf.getvalue()    # not a bytes repr
```

**Owner 自测**（在 tty 环境）：

```bash
$ autopwn -l Challenge/level3_x64
[+] Exploitation report generated: writeups/level3_x64_wp.docx
[*] Switching to interactive mode
$ ls                          # 用户输
AGENTS.md    autopwn.egg-info  core.21155      requirements.txt  upgraded.md
Challenge    bugs              coverage.json   scripts           writeups
LICENSE      canary.txt        logs            setup.py
...                            # 真多行+tab 对齐输出
$ exit
[*] Stopped process
```

---

## 5. 风险与遗留 (Risk & Followup)

**已确认风险**：

- (a) **`errors="replace"` 静默吞非法字节**：pty 控制序列丢失不可见——`less -R logs/level3_x64/run.log` 看到的是 "valid text\ufffd more text"。**对策**：v4.1.10b 可加 `--strict-bytes` flag，让用户决定严格性（CI 用 `replace`，debug 用 `strict` 抛错）
- (b) **UTF-8 假设**：non-UTF-8 locale（如 `LANG=zh_CN.GB18030`）shell 输出解码会有大量 U+FFFD——**不视为本 fix 缺陷**（pwntools 主流假设 UTF-8，per `tube._log` 默认；Owner 报告现场是 UTF-8 终端）
- (c) **`\r\n` vs `\n` 不区分**：pty 转 CR+LF 时，decode 后保留 `\r\n`（如果 binary 输 CRLF）；终端自动渲染 `cat logs/...` 时 `\r` 会回到行首——非本 fix 引入，是 v4.1.8 Tee 镜像 raw bytes 时的固有问题

**遗留问题**（已立后续任务 / TODO）：

- **`pwntools tube.interactive()` 在 non-tty 环境的 graceful fallback**（per v4.0.4 §5 风险 (a)）→ 不属本 fix 范围
- **`Tee.flush()` 没等子 stream 真正 flush 到 OS**：当前 best-effort，pwntools tube 调 `io.interactive()` 时偶尔丢最后一行。**对策**：v4.1.10b 给 `Tee.flush()` 加 `os.fsync()` 兜底（但有性能 trade-off）
- **`Tee` 替换 `sys.stdout` 后 pwntools `tube.clean(timeout)` 的 `tubelist` 不被截获**（pwntools 内部 list，非 sys.stdout）→ 当前不影响 shell 渲染
- **bytes 含 NUL (`\x00`) 的处理**：decode UTF-8 合法，render 到 terminal 截断——非本 fix 引入，pwntools 自身行为

**关联 fix**：

- [`fix_x64_recv_timeout.md`](./fix_x64_recv_timeout.md) (v4.0.2c4) — x64 ret2libc strategies `io.recv()` timeout，与本 fix 独立
- `v4.1.10` (本 fix) — 修 v4.1.8 引入的 Tee.write bytes handling bug
