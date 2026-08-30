# backlog.md — 历史未完成任务归档

本文件收纳 **v4.1.21 瘦身后** 仍未完成、但暂不在 `upgraded.md` 主索引中展开长描述的历史任务。
这些条目当前视为**休眠 backlog**：默认不算当前活动任务；只有在重新开工时，才需要先回填到 `upgraded.md §3` 并拆出对应的 `upgraded/vX.Y.Z.md` 详情文件，再动代码。

> 说明：下方保留的是**历史任务行快照**；其中出现的旧节号、旧分支名、旧 merge / PR 表述属于当时上下文，不代表现行流程。
<a id="v4_0_0"></a>
## v4.0.0

```markdown
| `v4.0.0` | **v4.0 GA 收尾**：切版本号 4.0.dev0 → 4.0 + tag `v4.0.0` + GitHub Release + CHANGELOG.md + README v4.0 更新 | ⏳ | 1.5h | **阻塞**：等 v4.0.1 / v4.0.2 修复后再做（per 2026-06-10 诊断）。**2026-06-12 状态**：v4.0.1 / v4.0.2a / v4.0.2b / v4.0.3 / v4.0.4 / v4.0.5 / v4.0.6 / v4.0.7 / v4.0.2c1 / v4.0.2c3 / v4.0.2c4 全部 ✅，**GA 阻塞** 仅剩 **v4.0.2c2 (5-binary 6 关验收收尾)** + v4.0.2c5 (3 个防御性 follow-up) + 自身切版本号 |
```

<a id="v4_0_8"></a>
## v4.0.8

```markdown
| `v4.0.8` | **修 `scripts/run_verify.sh` 的 `-v` flag 污染 pwntools tube**（per 2026-06-12 v4.0.2c1 merge report 副作用发现）：`run_verify.sh` 用 `python3 -m autopwn -l <bin> -v` 跑 5-binary 验证，**`autopwn -v` (verbose) 打开的 DEBUG 输出污染 pwntools tube**——实测 level3_x64 用 `-v` 跑 `verify_shell` 返 `(False, "no PWNED in shell output")`（即使无 `-v` 跑返 `(True, "PWNED...")` + 真 SUCCESS）。根因：`autopwn/core/logging.py::print_debug` / `print_info` 走 `print(..., file=sys.stdout)`，pwntools `tube.recv()` 把 stdout 也算 tube 输入，shell 的 PWNED token 被 DEBUG 输出挤掉/打乱。**修复方向**：(A) 修 `logging.py` 把 `print_*` 走 `sys.stderr`（pwntools 不读 stderr）；(B) `run_verify.sh` 跑时 `2>&1` 重定向到 stderr + log 仍捕 stdout；(C) `verify_shell` 改用 `io.clean(timeout=0.1)` 在 recv PWNED 前清掉 tube 缓冲（防御性）。**与 v4.0.2c1 关系**：v4.0.2c1 实测 level3_x64 真 SUCCESS，但**用 `run_verify.sh` 的 `-v` flag 跑同样 binary 会假 fail**——baseline 测量不一致，per `upgraded.md §5.4` "5-binary 应 4/5 SUCCESS" 的 `run_verify.sh` 跑法**不可信**。**6 关验收**：① 代码合入 `fix/v4.0.8-run-verify-verbose` 分支；② `pytest tests/unit -q` 全过；③ `pytest tests/integration -q` 全过；④ `run_verify.sh v4.0.8-verify` 不带 `-v` + 带 `-v` 都 4/5 SUCCESS（**两侧 baseline 一致**）；⑤ Owner 自审；⑥ 文档同步（本表 + `upgraded.md §5.4` baseline 描述 + 对应 `bugs/fix_run_verify_verbose.md`）| ⏳ | 1.5h | **风险**：(a) 改 logging.py 走 stderr 可能破坏现有 unit test（test 用 `capsys` 捕 stdout）—— 需审 test 全部用 `capsys.readouterr()` 同时捕 stderr + stdout；(b) `io.clean(timeout=0.1)` 是 pwntools API 但语义是"清空 tube 缓冲直到 timeout"，可能误清掉早期 shell 启动 banner——需 manual review level3_x64 / rip 实测；(c) **可推迟**：v4.0.2c1 + 2c3 + 2c4 修完，**不带 `-v` 跑** baseline 已 4/5 SUCCESS，CI 可改 `run_verify.sh` 不带 `-v` 暂缓本 fix 到 v4.0.8+ |
```

<a id="v4_0_2"></a>
## v4.0.2

```markdown
| `v4.0.2` | **5 binary 实测修 padding / leak 路径**（**已拆分**为 v4.0.2a/b/c per `AGENTS.md §2.4` 任务粒度）：原 2.5h 估算偏低，因 ctf-pwn 2026-06-11 实测 rip + level3_x64 暴露**两个独立根因**（不是简单 padding 错），需分别修 | ⏳ | — | **依赖 v4.0.1 + v4.0.3**（verify_shell 真判定必须先就位）|
```

<a id="v4_0_2c2"></a>
## v4.0.2c2

```markdown
| `v4.0.2c2` | **5 binary 6 关验收收尾**（v4.0 GA 阻塞最后一步；**原 v4.0.2c 拆分后保留验收部分**）：跑 `autopwn -l Challenge/{rip,level3_x64,fmtstr1,canary,pie}` 五个 binary，对比 `verify_shell` 返 `(True, "PWNED...")` 路径全部一致；canary 仍 PARTIAL（per `v4.0.2 备注` v3.1 pre-existing 限制，不阻 GA）；把 v4.0.2a/b/c1 的修复纳入 `logs/v4.0.2c2/binary_<name>.log` 对比基线（用 `scripts/baseline_lock.sh lock` 锁 hash）；更新 `upgraded.md §5.4` baseline（3/5 → 4/5 SUCCESS 当 fmtstr1 hang 修完）| ⏳ | 1h | **依赖 v4.0.2a + v4.0.2b + v4.0.2c1**（3 个修 hang/padding/ret-gadget bug 完成后才能 6 关验收）|
```

<a id="v4_0_2c5"></a>
## v4.0.2c5

```markdown
| `v4.0.2c5` | **3 个已知防御性 follow-up**（per `bugs/fix_fmtstr1_routing.md` §5 + `bugs/fix_asm_and_add_padding.md` §5 + `bugs/fix_x64_recv_timeout.md` §5 风险与遗留，2026-06-12 立任务）：v4.0.2c1/c3/c4 修了 3 个 root cause 后，剩 3 个边缘情况列同一任务统一收：(I) **canary_ret2libc_*.py 4 strategy 同样无 timeout**（`canary_ret2libc_put.py` + `canary_ret2libc_write.py` × x32/x64）；(II) **fmtstr1 真实 padding 92 字节未识别**（`%esp`-based lea + `and+add` frame size 推断，需新增 regex `lea\s+(-?0x[0-9a-f]+)\(%esp\)` + `and 0xfffffff0, %esp; add 0xffffff80, %esp` → frame 0x80 启发式）；(III) **`io.recv()` 0.5s timeout 是拍脑袋**（需 empirical 测 level3_x64 / rip 真实 banner 出现时间调优到 0.1-0.2s 范围——banner 一出现就 1st print，0.5s 偏长）。**6 关验收**：① 代码合入 `fix/v4.0.2c5-defensive-fixes` 分支；② `pytest tests/unit -q` 全过；③ `pytest tests/integration -q` 全过；④ 5-binary smoke 仍 4/5 SUCCESS（**0 回归**——canary 仍 pre-existing PARTIAL）；⑤ Owner 自审；⑥ 文档同步（本表 + 对应 `fix_*.md` 引用 + `logs/v4.0.2c5-verify/`）| ⏳ | 1h | **风险**：(a) 三 fix 范围跨 strategy + recon + core 三层，per `AGENTS.md §2.4` 任务粒度可能要再拆 v4.0.2c5a/b/c（先拍板粒度）；(b) (II) 需新加 `%esp` lea regex 进 `_LEA_RE` —— `recon/asm.py` 的 `_LEA_RE` 需扩展为同时匹配 %ebp + %esp，可能要新增 `(lea|lea).*%esp` 分支；(c) (III) timeout 调优需 empirical 数据，可先放宽 v4.0.2c5 拍 0.3s，CI 跑 5-binary 看回归再定 |
```

<a id="v4_1_0"></a>
## v4.1.0

```markdown
| `v4.1.0` | **HEAP 利用层**：`primitives/heap.py` + `exp/strategies/heap_*.py` 至少 3 个新 strategy（malloc_hook / tcache / unsorted bin）| ⏳ | 12h | 大需求，Owner review 时机 |
```

<a id="v4_1_1"></a>
## v4.1.1

```markdown
| `v4.1.1` | **类型化异常**：`ReconError` / `DetectionError` / `StrategyError` 替代 `except Exception` | ⏳ | 1.5h | 重构期遗留，含 `orchestrator.run_strategy_phase` 等 |
```

<a id="v4_1_2"></a>
## v4.1.2

```markdown
| `v4.1.2` | **多 binary 批处理**：CLI `-L <dir>` 跑 `Challenge/*.bin` 全集，输出 `logs/batch/` summary | ⏳ | 3h | 跑 5 binary 当前要 5 次 `python -m autopwn` |
```

<a id="v4_1_4"></a>
## v4.1.4

```markdown
| `v4.1.4` | **Web UI / RPC**：`orchestrator.run` 暴露为 FastAPI，POST `/exploit` 返回 JSON | ⏳ | 6h | per `refactor.md §11` 旧扩展点 |
```

<a id="v4_1_5"></a>
## v4.1.5

```markdown
| `v4.1.5` | **LLM 辅助决策**：`candidates(ctx)` 接受外部 LLM override（与 `mmx-cli` 技能联动）| ⏳ | 4h | 实验性 |
```

<a id="v4_1_6"></a>
## v4.1.6

```markdown
| `v4.1.6` | **canary 暴力优化**（如 v4.0.2 未达标）：优化 canary 策略让 canary 60s timeout 内可解（parallel / smarter padding）| ⏳ | 8h | 需算法层重设计；可放弃走 ❌ |
```

<a id="v4_1_7"></a>
## v4.1.7

```markdown
| `v4.1.7` | **默认 writeup 输出到 `writeups/` 目录**（per Owner 2026-06-13 需求）：(a) 项目根新建 `writeups/` 目录（含 `.gitkeep` 占位）；(b) 修改 `autopwn/report/docx.py::generate_docx` + `_generate_markdown` 输出路径从 `out_dir / f"{target}_wp.{ext}"` 改为 `Path("writeups") / f"{target}_wp.{ext}"`（**`out_dir` 参数忽略**——`record_success` 仍传 `ctx.report_dir`，但 `docx.py` 不再使用）。**理由**：(a) 报告散落 cwd 难归档；(b) writeup 概念与 binary 报告分离更清晰。**影响**：`autopwn -l binary` 默认输出从 cwd 改到 `writeups/`，`--report-dir` 仍被 `ctx.report_dir` 接收但**被 `docx.py` 忽略**（**已知 trade-off**——v4.1.7 范围内不保留 `--report-dir` 行为；如需恢复可走 v4.1.7b）。**风险**：(a) 现有 unit test 可能 assert 报告在 cwd 需 grep affected test 改 expected path；(b) `writeups/` 需 `.gitkeep` 进版本控制避免 git 忽略。**6 关验收**：① 代码合入 `fix/v4.1.7-writeups-dir` 分支；② `pytest tests/unit -q` 全过；③ `pytest tests/integration -q` 全过；④ `autopwn -l Challenge/rip` 实测报告生成在 `writeups/rip_wp.docx`（**不**在 cwd）；⑤ Owner 自审（单 Owner 项目）；⑥ 文档同步（本表 + `README.md` "Report control" 段）| 🔄 | 0.5h | **Owner**：@Minzhi_Zhou |
```

<a id="v4_1_8"></a>
## v4.1.8

```markdown
| `v4.1.8` | **运行日志自动保存到 `logs/{challenge_name}/`**（per Owner 2026-06-13 需求，紧接 v4.1.7 报告归档思路）：(a) 新增 `autopwn/core/tee.py::Tee` 类（file-like 写多 stream，包装 `sys.stdout` + log file）；(b) `autopwn/cli.py::main()` 在解析 args 后根据 `args.local` 提取 challenge name（`Path(args.local).stem`），自动建 `logs/{challenge_name}/` 目录并打开 `run.log`（覆盖模式，ANSI 颜色码保留以便 cat 复现），把 `sys.stdout` / `sys.stderr` 替换为 `Tee` 实例——捕获 autopwn `print_*` + pwntools tube 全部 stdout/stderr 输出到 `run.log`，同时仍显示在终端；(c) 退出时在 `finally` 恢复 `sys.stdout`/`sys.stderr` 并 `log_file.close()`；(d) `--no-report` 类的 log toggle 暂不实现（v4.1.8 范围**只**开 log，不开 log-skip flag）。**理由**：报告（`writeups/{target}_wp.docx`）是结果产物，日志（`logs/{challenge}/run.log`）是过程 trace——两者职责分离，便于回放 + 调试 + baseline diff。**影响**：(a) 每次 `autopwn -l <binary>` 自动在 `logs/{binary_name}/run.log` 落盘一份完整终端输出；(b) 旧 `logs/v3.1/`, `logs/v4.0/`, `logs/_debug/`, `logs/comparison/` 目录**不**变（属于历史 baseline + 工具输出，语义不同）；(c) unit test 中 `capsys` 仍可捕 stdout（`Tee` 把 `sys.stdout` 替换后 capsys 拿到的是 tee 写入的 buffer，写入行为不变）。**风险**：(a) `Tee` 替换 `sys.stdout` 后 pwntools `tube.recv()` 不受影响（pwntools 用 fd 而非 Python-level sys.stdout），但 `print(..., file=sys.stdout)` 仍走 tee；(b) log 文件在多次跑同 binary 时被覆盖——若需保留历史，可后续 v4.1.8b 加 `run_{timestamp}.log`；(c) 远程模式 `args.local` 可能为 None → fallback 到 `logs/remote_{ip}_{port}/run.log`；(d) `logs/*.log` 进 `.gitignore` 避免污染仓库。**6 关验收**：① 代码合入 `fix/v4.1.8-logs-dir` 分支；② `pytest tests/unit -q` 全过（无新回归）；③ `pytest tests/integration -q` 全过；④ `autopwn -l Challenge/level3_x64` 实测：日志写入 `logs/level3_x64/run.log`（含 "Exploitation report generated" + pwntools "[+] Starting local process" 等关键行），同时终端仍正常显示；⑤ Owner 自审；⑥ 文档同步（本表 + `README.md` 新增 "Log output" 段）| ⏳ | 1h | **Owner**：@Minzhi_Zhou |
```

<a id="v4_1_9"></a>
## v4.1.9

```markdown
| `v4.1.9` | **治理变更：fix 记录从 root 迁移到 `bugs/` 目录**（per Owner 2026-06-13 需求；与 v4.1.7 报告归档 + v4.1.8 日志归档一致思路——`writeups/`/`logs/`/`bugs/` 三个目录分别承载结果产物 / 过程 trace / bug 修复记录，root 保持"代码 + 索引文档"清爽）：(a) **新规**：所有 v4.0+ 修复单文件 `fix_<bug_name>.md` 写到 `bugs/` 子目录，索引 `fix.md` 也搬到 `bugs/fix.md`；(b) **迁移**：现有 4 个文件 `fix.md` + `fix_fmtstr1_routing.md` + `fix_asm_and_add_padding.md` + `fix_x64_recv_timeout.md` 全部 `git mv` 到 `bugs/`（git rename detection 已识别为 4 renamed）；(c) **交叉引用更新**：`upgraded.md` 中 5 处文本引用 `fix.md` / `fix_*.md` 全部加 `bugs/` 前缀（如 `（per \`bugs/fix.md\` v4.0.2c1 复盘`、`对应 \`bugs/fix_run_verify_verbose.md\``）；§X.Y 逻辑章节锚点（如 `fix.md §3.1`）**不**改（per §6.1 约定，§X.Y 是逻辑锚点非文件路径）；(d) **AGENTS.md 治理变更**（per §7）：§6.1 文档更新 "fix 文件位于 `bugs/`"（新增 "目录位置" 段解释 1.8 修订）+ §6 引用速查表 link 改 `bugs/fix.md` / `bugs/fix_*.md` + §8 changelog 加 1.8 行；(e) **`.py` 注释 / `.md` sibling cross-ref**：`autopwn/primitives/ret2libc_write.py:300` + `autopwn/recon/frame.py:3,94` + `tests/unit/test_padding_crosscheck.py:1,231` + `tests/unit/recon/test_frame.py:3,19` 等 `fix.md §X.Y` 引用**保持**（逻辑章节锚点）；`bugs/fix_*.md` 内部互相引用 `./fix_*.md`（siblings）**保持**。**理由**：(a) root 文件清单已含 `writeups/` + `logs/` + `core*` 临时文件 + `*.docx` 输出——再加 `fix*.md` 让 root 杂乱；(b) `writeups/`（结果产物）+ `logs/{题目}/`（过程 trace）+ `bugs/`（修复记录）形成完整的"产物-过程-记录"三件套目录结构；(c) v4.0+ 已是目录化版本（per v4.0 文档瘦身），fix 文件从 root 抽到子目录与 v4.0 风格一致。**影响**：(a) 4 个 fix 文件物理位置变更，git history 用 `git mv` 保留 rename detection；(b) 外部 link 指向 `./fix.md`（如有 GitHub README 引用）会 404——若 Owner 接受此 break 走 v4.1.9，否则 v4.1.9b 加 root symlink 兼容；(c) tests/ 路径无引用 fix.md 风险。**6 关验收**：① 代码合入（`git mv` + 文本编辑，无逻辑改动）；② `pytest tests/unit -q` 全过（719 passed，无新回归——本任务不碰 .py 代码逻辑）；③ N/A（不涉及行为变化）；④ N/A（不涉及 autopwn 行为）；⑤ Owner 自审（per §2.2 单 Owner）；⑥ 文档同步（本表 + AGENTS.md §6.1 + §8 changelog）| 🔄 | 0.5h | **Owner**：@Minzhi_Zhou |
```

<a id="v4_1_14"></a>
## v4.1.14

```markdown
| `v4.1.14` | **修 `ctf_env` 标准容器下的工具链兼容层**（Owner 2026-08-30 现场新立任务）：范围限于 `autopwn/core/runner.py`、`autopwn/recon/checksec.py`、必要的 runner / recon 单测，以及 `tests/unit/test_context_ssl.py` 的容器路径兼容；**不**改 README / writeup / 其他策略逻辑。**目标**：让现有 `recon/*` 与 integration 流程在 `ctf_env` 里继续沿用既有 public API，而不是把容器工具差异向上泄漏到 `strategy` 层。**实施方向**：(a) `run_checksec()` 同时兼容 `checksec <file>` 与 `checksec --file=<file>` 两种 CLI 契约；(b) `recon.checksec.collect()` 兼容新版表格式 `checksec` 输出——当缺少历史 `Arch:` / `Stripped:` 字段时，回退到 `file` 输出补齐 bit / stripped；(c) `run_ropper()` 在 `ropper` 缺失时自动 fallback 到 `ROPgadget`，并把输出归一化成现有 `recon/rop.py` 可直接解析的 ropper-like 行格式；(d) `run_cyclic_create()` / `run_cyclic_find()` 在独立 `cyclic` 缺失时 fallback 到 `pwn cyclic`；(e) `tests/unit/test_context_ssl.py` 不再硬编码 `/ctf/autopwn/…`，改用 `tests.conftest.CHALLENGE_DIR`（或等价 repo 内解析）适配 `/data/autopwn`。**6 关验收**：① 代码合入 `fix/v4.1.14-ctf-env-toolchain-compat`；② `docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/unit/test_core_runner.py tests/unit/test_context_ssl.py tests/unit/recon/test_recon_public_api.py -q'` 全过；③ `docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/unit -m "not integration" -q'` 不再因 `checksec` / `ropper` / 路径问题失败；④ 将 integration 失败收敛为**非工具契约**问题：`docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/integration/test_shell_interaction.py -q'` 不再出现 `checksec` / `ropper` / `/ctf/autopwn` 路径类假红；⑤ Owner 自审；⑥ 文档同步（本表状态 + 如有必要的 `autopwn/pwntools.md` 交叉引用）。**当前进展（2026-08-30）**：关②已过（`34 passed in 2.02s`）；关③已过（`735 passed, 1 warning in 18.98s`），说明原先 `checksec` / `ropper` / 路径三类**工具链假红**已清空；关④已达成——integration 仅剩 `level3_x64` 这一个 exploit/runtime 兼容问题，已单独归类到 `v4.1.15`，不再属于本行 scope；关①/⑤ 需待实际 merge / Owner 收尾后才能改 `✅`。| 👀 | 1h | **风险**：(a) `ROPgadget` 与 `ropper` 搜索语义不完全等价，必须把兼容层收敛在 `core.runner`，避免上层再分叉解析器；(b) fallback 若返回过宽结果，可能把 `ret` 误识别成 `pop reg; ret`——需用单测锁死归一化规则；(c) 新版 `checksec` 表格不再暴露 `Arch:` 标签，bit / stripped 的回退来源必须固定（优先 `file`），避免在不同发行版间继续漂移；(d) 本任务只解决**工具契约兼容**，若 integration 仍失败，应单独定位为 exploit/基线问题，不在本行偷扩 scope。 |
```

<a id="v4_1_15"></a>
## v4.1.15

```markdown
| `v4.1.15` | **将 `level3_x64` 暴露的失败归类为“x64 三参 leak primitive 缺第三参数控制”并修复**（Owner 2026-08-30 现场新立任务）：**归类理由**：如果把它写成“修 level3_x64”，后续每遇到一个 `write(fd, buf, count)` 型 x64 泄漏题就会继续靠单题热补丁；真正的共性根因是 **`Ret2LibcWriteX64.build_payload()` 把 3 参数函数调用偷简化成只控 `rdi/rsi`，把 `rdx` 留给运行时残值**。这在某些 libc / 调用路径下“碰巧可用”，在 `ctf_env` 当前 runtime 下则直接退化为 0-byte leak。**范围**：限于 `autopwn/primitives/ret2libc_write.py`、相关 x64 write strategy / canary strategy、必要的单元/集成测试，以及本表状态同步；**不**做 challenge-name 特判。**实施方向**：(a) 在 primitive 层引入**通用 x64 三参 call builder**，优先使用直接 `pop rdx`(含 `pop rdx; pop rbx; ret` 变体)；(b) 若无直接 `rdx` gadget，则 fallback 到 **ret2csu**（解析 `__libc_csu_init` 的 pop 链 + call 链）构造 `write(1, write@GOT, 8)`；(c) 让 `Ret2LibcWriteX64` / `CanaryRet2LibcWriteX64*` 共用该 builder，避免再次出现“非 canary 修了、canary 版本漏修”；(d) 把旧的“2 参 write leak”视为不可靠历史实现，不再作为新路径的默认契约；(e) 对这类 **2-stage x64 write leak**，stage2 的 `system("/bin/sh")` 对齐判定必须按“stage1 泄漏后回到 `main` 再次进入漏洞函数”的真实调用路径复核，必要时补 1 个 `ret`，避免把 stage1 修好后又在 verify 前因 MOVAPS/栈对齐倒下。**6 关验收**：① 代码合入 `fix/v4.1.15-x64-write-leak-arg3`；② `docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/unit/test_primitives_ret2libc_write.py tests/unit/test_primitives_ret2libc_extra_rsi.py tests/unit/test_exp_ret2libc_write.py tests/unit/test_exp_canary.py -q'` 全过；③ `docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/unit -m "not integration" -q'` 全过；④ `docker exec ctf_env bash -lc 'cd /data/autopwn && python3 -m pytest tests/integration/test_shell_interaction.py -q'` 恢复既有 pass/skip/xfail 基线；⑤ Owner 自审；⑥ 文档同步（本表状态 + 后续 fix 记录索引）。**当前进展（2026-08-30）**：关②已过（`102 passed in 6.24s`）；关③已过（`738 passed, 1 warning in 19.61s`）；关④已过（`4 passed, 1 skipped, 1 xfailed in 37.10s`）；关①/⑤ 需待实际 merge / Owner 收尾后才能改 `✅`。| 👀 | 1.5h | **风险**：(a) `__libc_csu_init` 在不同编译器/优化级别下寄存器搬运顺序可能不同，不能把 `r13/r14/r15` 的语义硬编码成单一版本——需要解析实际反汇编；(b) x64 write-leak stage1 payload 会变长，必须确认不破坏当前可用的 padding / frame 假设；(c) 若某 binary 同时没有 `pop rdx` 也没有可识别的 ret2csu，策略应 fail-closed 而不是继续赌运行时残值；(d) stage2 对齐若仍直接复用“单次进入漏洞函数”的旧判定，可能在 ret2csu leak 修好后把问题后移成第二阶段 SIGSEGV。 |
```




