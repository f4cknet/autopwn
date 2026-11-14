# HANDOVER — 交接说明（给接手的开发者）

> 一句话：这是一个**离线 pwn 自动利用引擎**，输入题目二进制，输出「真的拿到了 shell / flag」的证据。
> 主线代码只有 `autopwn/engine/` 七个文件（约 3100 行），其余都是题库、容器和文档。

交接时间：2026-11-13 22:20 · 交接前状态：`PROGRESS.md §2` 的基线全部通过。

---

## 1. 五分钟上手

```bat
cd /d D:\hacktools\10-pwn\autopwn

:: 1) 确认镜像在（不在就 build_pwn.bat，8~12 分钟）
docker images | findstr autopwn

:: 2) 单题：先看静态事实，再打
solve.bat chellenges\note --facts-only
solve.bat chellenges\note

:: 3) 全量回归（改完必须跑）
solve.bat bench
solve.bat bench_extra
solve.bat bench_sys
```

期望：`bench` 13/15、`bench_extra` 5 shell + 1 flag-only、`bench_sys` 4/4。
低于这个数字就是回归，不要提交。

> **不要用 `bash docker/solve.sh`**：本机 `bash` 指向未安装发行版的 WSL，会报
> `execvpe(/bin/bash) failed`。一律走 `.bat`。

## 2. 目录导航

| 路径 | 作用 | 改动频率 |
|---|---|---|
| `autopwn/engine/facts.py` | **静态事实**：漏洞点、win、gate、菜单交互、gadget、syscall 包装 | 高 |
| `autopwn/engine/strategies.py` | **候选链生成**：16 个策略，纯函数 | 高 |
| `autopwn/engine/orchestrator.py` | 尝试顺序、预算、按 `tag` 分派特殊流程、留痕 | 中 |
| `autopwn/engine/interact.py` | `Send`/`Wait` 步骤、累积缓冲与游标、唯一一份收发时序 | 中 |
| `autopwn/engine/run.py` | spawn（本地/远程）、按步骤收发、成功判定 | 中 |
| `autopwn/engine/model.py` | `Challenge`：复制到 `.run/`、patchelf、加载 ELF | 低 |
| `autopwn/engine/cli.py` | 参数、目录收集（ELF/zip/平铺目录）、md5 去重 | 低 |
| `docker/Dockerfile` + `build.sh` | `autopwn:pwn22` 镜像 | 很少 |
| `docker/serve.sh` + `target.bat` | 把附件挂成容器内 TCP 靶机 | 很少 |
| `docker/make_sys_variants.py` | 生成 `bench_sys` 的窗口/帧变体 | 很少 |
| `bench/` `bench_extra/` `bench_sys/` `chellenges/` | 题库（回归用） | 加题时 |
| `bench/RESULTS.md` | 逐题实测明细 | 每次改能力 |
| `ARCHITECTURE.md` | 现状架构（先读这个） | 架构变动时 |
| `PROGRESS.md` | 版本演进、基线、能力矩阵、下一步 | 每版 |
| `upgraded/v7.0.0.md` | 四层架构提案（下一步方向） | 少 |
| `DOC_MAP.md` | 哪份文档是活的 / 哪些该清理 | 少 |

关键函数入口（行号会漂，按名字搜）：

| 位置 | 函数 |
|---|---|
| `facts.py:165` | `analyse()` —— 所有静态事实的总入口 |
| `facts.py:245` | `_find_sys_wrappers()` —— `mov eax,NR … int 0x80` 包装 |
| `facts.py:294` | `_find_interact()` —— 菜单题前置字符（`'w'`） |
| `facts.py:335` | `_find_gates()` —— `cmp [rbp-X], imm` 暗号 |
| `facts.py:596` | `_find_wins()` —— 三类 win（system / self-read / 门槛入口） |
| `strategies.py` | `STRATEGIES` 列表 = 尝试顺序；每个 `s_*` 是一个策略 |
| `orchestrator.py:98` | `solve()` —— 主循环 |
| `orchestrator.py:200/274/344` | `_try_pie_partial` / `_try_ret2libc` / `_try_canary_fmt` |
| `interact.py` | `Interaction.run_steps()` —— 所有收发时序的唯一实现 |
| `run.py` | `spawn` / `verify_shell` / `probe_flag` / `execute` / `execute_flag` |

## 3. 铁律（违反会静默出错，不报异常）

1. **成功 = 目标进程里真执行了命令**。策略跑完没报错不算成功；「连上了」不算成功。
2. **判定必须看累积输出**。只看最后一段 `recvrepeat` 会把早到的 flag 判成失败（真实踩过）。
3. **`SHELL` 与 `FLAG-ONLY` 分开记账**，不许合并成「成功率」。
4. **`process(...)` 不要显式传 `stdin=-1, stdout=-1, stderr=-1`**：会把子进程 stdout 接到父进程，tube 读不到任何东西。
5. **`_find_wins` / 任何事实函数不许在开头 `return` 得太早**：曾因 `if not targets: return` 埋掉「无 system 但有 open+puts」的整类题。
6. **远程 ≠ 本地**：远程 stdout 全缓冲（`puts` 泄漏会卡住，优先 `write`）、有 RTT（超时 6s）、每次尝试新连接（加间隔）。
7. **连接类错误立刻中止**（DNS/实例未启动/端口不通），不要烧完 `max-attempts`。
8. **不要写死偏移/地址**：一切从 facts 推导；单题调参的成果必须回到通用规则。
9. **新增能力必须带可复现向量**（`bench`/`bench_extra`/`bench_sys` 里加一题），并在 `bench/RESULTS.md` 登记。
10. **中文提交信息 + 版本前缀**（`[v6.x.y]`），一次提交只做一件事。

## 4. 环境坑（都不是引擎的 bug，但会卡住你）

| 现象 | 原因 | 处理 |
|---|---|---|
| `execvpe(/bin/bash) failed` | 本机 `bash` 指向未安装发行版的 WSL | 用 `.bat`，别用 `bash *.sh` |
| `No global/local python version has been set` | 本机 `python` 是 pyenv-win shim，未设版本 | 用 `py -3` 跑宿主机脚本；容器内仍用 `python3` |
| `Warning: _curses.error: setupterm` | 容器缺 terminfo | 无害，忽略 |
| `.sh` 报 `set: Illegal option -` | 文件被写成 CRLF | 统一 LF（`write_text` 后跑一次 `\r\n → \n`） |
| `setarch: failed to set personality` | Docker 默认 seccomp 拦 `personality()` | 容器加 `--security-opt seccomp=unconfined` |
| 靶机端口通但**无任何输出** | 同上：程序根本没跑，只有 setarch 报错 | 同上 |
| `--host 127.0.0.1` 连不上 | 攻击容器在独立网络命名空间 | `solve.bat` 已自动加 `--network host`；或用 `host.docker.internal` |
| 远程卡在握手 | 平台套了 TLS | `--ssl`（`--sni` 默认等于 host） |
| 靶机每次失败地址都不同 | `socat fork` 每连接新进程 → ASLR 每次变 | PIE 题走 `pie_partial` 的 nib 爆破 |

## 5. 怎么加一个新策略（照着做）

以今天的 `syscall3` 为例，五步：

**① 先在 facts 里把「能推导的事实」补齐。**
不要急着写链。今天的前置事实是「这是自写的 `read` 包装」：

```python
# facts.py
def _find_sys_wrappers(d: Dis) -> dict:
    """识别 mov eax,NR ... int 0x80，返回 {NR: (entry, load, int80)}"""
```

在 `analyse()` 里赋值给 `f.sys_wrappers` / `f.sys_read` / `f.sys_load`。

**② 写策略：纯函数，`yield Plan`，preconditions 不满足就 `return`。**

```python
def s_syscall_execve(ch, f) -> Iterable[Plan]:
    if ch.elf.bits != 32: return
    if not (f.sys_read and f.sys_load and f.data_addr and f.entry_sub): return
    ...
    yield Plan("syscall3", [s1, blob, s2, s3, s4], desc)
```

**③ 注册到 `STRATEGIES`，位置 = 尝试优先级。**
越specific越靠前（`pie_partial` / `syscall*` 在第一梯队）。

**④ 需要特殊交互就给它一个 `tag`，在 `orchestrator.solve()` 里加分支。**

```python
if plan.tag.startswith("pie:"):
    ok, detail, out, cmds = _unpack4(_try_pie_partial(ch, f, plan, post_cmds))
```

**⑤ 加向量 + 跑回归 + 登记。**
今天的做法：`docker/make_sys_variants.py` 从原题派生 4 个变体（只改立即数），
验证「策略是按结构选路，不是单题调参」。

## 6. 调试手法

| 场景 | 做法 |
|---|---|
| 看引擎「为什么 0 次尝试」 | `solve.bat <题> --facts-only`，看 `vulns/wins/gates/interact` |
| 看每次尝试的真实回显 | `results/<题>.json` 里的 `attempts[].tail`（比看终端滚动可靠） |
| 单题反复试某条链 | 容器内 interactive：`shell.bat`，然后手写 pwntools 片段 |
| 确认跳转落点/对齐 | `gdb -q -batch -ex "starti" …`；PIE 题先 `starti` 再取基址 `$pc-0x1100` 不行时用 `/proc/pid/maps` |
| 确认 flag 判定窗口 | 直接看 `run.execute_flag` / `probe_flag`，注意「累积输出」 |
| 造远程形态 | `target.bat <题> 4444`，然后 `solve.bat <题> --host 127.0.0.1 --port 4444` |

## 7. 提交前检查表

> **仓库卫生是硬门禁**（Owner 要求，见 `CLAUDE.md`「工作纪律」与 `AGENTS.md` 铁律 5）：
> 每轮结束必须跑 `py -3 scripts/audit/check_hygiene.py`，非 0 退出则不许提交；
> 提交后立刻 `git push origin main`，不许攒提交过夜。

- [ ] `solve.bat bench` ≥ 13/15，且失败项只有 `ch07_acae`、`ch14_easyheap`
- [ ] `solve.bat bench_extra` ≥ 5 shell + 1 flag-only，失败项只有 `chall`、`fmtstr1`
- [ ] `solve.bat bench_sys` = 4/4
- [ ] `py -3 scripts/audit/check_hygiene.py` 退出码 0（根目录白名单 / 临时文件 / results 误入库）
- [ ] 新增/修改的能力在 `bench/RESULTS.md` 有记录；交互层改动跑 `scripts/test/interaction_vector.py`（容器内 13/13）
- [ ] `PROGRESS.md` 的版本表与基线数字同步
- [ ] `py -3 -m py_compile autopwn/engine/*.py` 通过
- [ ] 提交信息 `[vX.Y.Z] 一句话`，中文
- [ ] 已 `git push origin main`

## 8. 交接时的未完成项（建议从这里开始）

| 优先级 | 任务 | 起点 |
|---|---|---|
| ✅ | ~~`Plan.sends` → `Plan.steps`（`Send`/`Wait`），交互层~~（v7.0.1 已完成） | `interact.Interaction` |
| **P0** | 判定层统一成 `Oracle`（Shell/Flag/File），带 `cause` | `run.verify_shell` / `probe_flag` / 三个 `_try_*` 里的临时判断 |
| P1 | facts 提取 prompt 字符串，策略自动 `Wait(prompt)` | `facts._find_interact` + `strategies._prelude_variants` |
| P1 | 能力声明式注册（`requires`/`forbids`/`evidence`） | `STRATEGIES` 列表 + 各策略开头的 early-return |
| P1 | 支持「给 libc」或「按泄漏找 libc」（解锁 `chellenges/repeater`） | `model.Challenge.libc_path` |
| P2 | 失败归因（tail 分类驱动换分支） | `orchestrator.solve()` 的 attempt 循环 |
| P2 | 堆题（tcache/FSOP） | 无，需新模块 |

详细论证见 `upgraded/v7.0.0.md`；其中「明确不做的事」一节请先读，避免重复讨论。

## 9. 沟通与文档约定

- 交流用简体中文；结论用表格；**没验证的必须显式登记为未验证**，不许含糊。
- 改架构/加依赖/重建镜像前先说清楚影响面。
- 每次会话结束：`PROGRESS.md` 的版本表 + `bench/RESULTS.md` 的明细必须是最新的。
- 文档先行：新增能力先写「它解决哪类题、前置事实是什么」，再写代码（`AGENTS.md` 铁律 2）。
