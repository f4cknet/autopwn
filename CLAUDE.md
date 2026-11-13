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

## 当前进度

见 `PROGRESS.md §2`。已知未覆盖：菜单式堆、SROP、20 字节极限 fmt、ORW、无 libc 的 ret2libc（`chellenges/repeater`）。
