# CLAUDE.md

本文件是给 Claude Code 的入口指针。**先读这里，再读 `HANDOVER.md`。**

## 这个项目是什么

离线 pwn 自动利用引擎。输入题目二进制，输出「目标进程里真的执行了命令」的证据。
主线代码：`autopwn/engine/`（`facts.py` / `strategies.py` / `orchestrator.py` / `run.py` / `model.py` / `cli.py`，约 3000 行）。

## 读文档顺序

1. `HANDOVER.md` —— 上手、铁律、环境坑、如何加策略（**必读**）
2. `ARCHITECTURE.md` —— 现状架构、数据结构、策略清单、判定链
3. `PROGRESS.md` —— 版本演进、实测基线、能力矩阵、已知边界、下一步
4. `upgraded/v7.0.0.md` —— 四层架构提案（下一步方向）
5. `DOC_MAP.md` —— 哪份文档是活的、哪些是历史

## 必跑命令（Windows，**不要用 bash**）

```bat
solve.bat <题目> --facts-only     :: 先看静态事实（漏洞点/win/gate/菜单字符）
solve.bat <题目>                  :: 打本地
solve.bat bench                   :: 回归，期望 13/15
solve.bat bench_extra             :: 期望 5 shell + 1 flag-only
solve.bat bench_sys               :: 期望 4/4
target.bat <题目> 4444            :: 造容器内 TCP 靶机
solve.bat <题目> --host 127.0.0.1 --port 4444   :: 打靶机（等价真远程）
```

## 五条最容易违反的规则

1. 成功判据是「目标进程里真执行了命令有回显」，**不是**「策略跑完没报错」。
2. 判定必须扫**累积输出**（只看最后一段会把早到的 flag 判负）。
3. 事实函数**不要开头就 `return`**（曾埋掉「无 system 但有 open+puts」的整类题）。
4. `process()` 不要显式传 `stdin=-1, stdout=-1, stderr=-1`（tube 会读不到输出）。
5. 不要写死偏移/地址；新增能力必须带可复现向量并登记到 `bench/RESULTS.md`。

## 不要做的事

- 不要用 `bash docker/solve.sh`（本机 bash 指向未装的 WSL）
- 不要为了单题调参而改通用逻辑
- 不要为了「跑通」而放宽判定（那会制造假成功）
- 不要提交低于基线的回归结果

## 工作纪律（**每轮迭代必须遵守，不可协商**）

Owner 明确要求以下五条。违反其中任何一条的提交都要回退重做。

### 1. 主目录必须保持清洁

仓库根目录**只允许**出现下列条目，多一个都算违规：

```
autopwn/  docker/  bench/  bench_extra/  bench_sys/  chellenges/  Challenge/
scripts/  bugs/  upgraded/  results/  archive/  writeups/  tests/  _target/
solve.bat  target.bat  build_pwn.bat  shell.bat
README.md  CLAUDE.md  AGENTS.md  HANDOVER.md  ARCHITECTURE.md  PROGRESS.md  CHEATSHEET.md  DOC_MAP.md  upgraded.md
LICENSE  pyproject.toml  requirements.txt  setup.py  .gitignore  .venv  .github  .coveragerc  .python-version
```

- **禁止**在根目录新建调试脚本、临时数据、`*.tmp`、`dbg_*.py`、`test_*.py`、日志文件
- 新的脚本一律进 `scripts/test/`（评测回归）或 `scripts/audit/`（一次性审计）
- 新的题目二进制进 `bench*/` 或 `chellenges/`，不进根目录
- 跑到一半的证据进 `results/`，不要另建 `results_xxx/`

### 2. 时代变了就归档，不要留在根目录

- 版本迭代后（如 v6 → v7），旧版设计文档移入 `archive/v<N>/`
- 旧的迭代详情移入 `archive/v<N>/upgraded/`
- 历史日志移入 `archive/v<N>/logs/`
- **归档用 `git mv`**，保留历史；不要直接删（文档是「为什么这么设计」的唯一载体）
- 归档后必须更新 `DOC_MAP.md §3` 的对照表，并修掉所有指向旧路径的链接

### 3. 临时文件用完立刻删

- 调试用的脚本（`dbg_*.py`、`bf*.py`、`probe_*.py`）**在当轮提交前删除**；需要留作回归的，改造成 `scripts/test/` 或 `scripts/audit/` 并写清用途
- 一次性生成的中间产物（反汇编导出、strings 导出、解包目录）用完即删，**不入库**
- `results/` 下每次跑都会变的 json 已在 `.gitignore`，**不要 `git add -f`**
- 提交前自查：`git status --short` 里不该出现你以为「等会儿再处理」的东西

### 4. 文档先行，实施在后

- 先改 `upgraded.md §3` 加任务行 + 建 `upgraded/vX.Y.Z.md`，再写代码
- 架构变了先改 `ARCHITECTURE.md`，基线变了先改 `PROGRESS.md`
- 提交时**代码与文档必须在同一个 commit 里**
- 「我先把功能做完再补文档」= 违规

### 5. 每轮迭代结束必须 commit + push 到 GitHub

```bash
git add -A
git -c core.safecrlf=false commit -m "[v{X}.{Y}.{Z}] {动词} {对象}"
git push origin main
```

- 远程：`git@github.com:f4cknet/autopwn.git`，分支 `main`
- **不允许**把提交攒在本地过夜；不允许「等全部做完一起推」
- push 前必须跑完 §「每轮收尾清单」的四步

## 每轮收尾清单（4 步，缺一不可）

```bat
:: 1) 回归：不低于基线（13/15 / 5+1 / 4-4）
solve.bat bench && solve.bat bench_extra && solve.bat bench_sys

:: 2) 清洁检查：根目录白名单 + 临时文件 + 误提交
python scripts\audit\check_hygiene.py

:: 3) 文档同步：upgraded.md 状态 + PROGRESS.md 基线（如变）
git diff --stat

:: 4) 提交并推送
git add -A && git commit -m "[vX.Y.Z] ..." && git push origin main
```

> `check_hygiene.py` 会检查：根目录多余条目、临时文件残留、`results/` 被误跟踪、构建产物、超过 5 MB 的单文件。有问题会以非 0 退出。

## 当前进度

见 `PROGRESS.md §2`。已知未覆盖：菜单式堆、SROP、20 字节极限 fmt、ORW、无 libc 的 ret2libc（`chellenges/repeater`）。
