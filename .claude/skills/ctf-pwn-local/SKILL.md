---
name: ctf-pwn-local
description: Use this skill when solving, debugging, or manually exploiting a pwn challenge in the autopwn repository on this Windows host. It documents the local Docker image autopwn:pwn22, the pwn-target container, the solve.bat / target.bat / shell.bat workflow, installed pwn tooling and versions, and host-specific gotchas (WSL bash, pyenv python, seccomp, host networking, remote buffering). Prefer it before re-discovering the local environment from scratch.
license: MIT
compatibility: Windows 10/11 + Docker Desktop; Git Bash or CMD. Repo mounted at /work inside the container.
allowed-tools: Bash Read Write Edit Glob Grep
metadata:
  user-invocable: "true"
---

# ctf-pwn-local — 本仓库的本地 pwn 解题环境

## 0. 先分清两条路

| 场景 | 走哪条 |
|---|---|
| 引擎能自动打的常规栈题 | `solve.bat <题>`（facts → strategies → 真实执行验证） |
| 引擎失败、需要手工看汇编/调试 | `shell.bat` 进容器，用 pwntools / gdb / ROPgadget 手工做 |
| 要复现「远程形态」 | `target.bat` 起 `pwn-target` 容器，再 `solve.bat --host 127.0.0.1` |
| 真实比赛平台 | `solve.bat --host ... --port ... [--ssl --sni ...] [--libc ...]` |

本 Skill 只描述**本机环境**。漏洞技术本身（堆、SROP、FSOP 等）查 `ctf-pwn` Skill。

## 1. 环境总览（实测）

| 项 | 值 |
|---|---|
| 宿主机工作目录 | `D:\hacktools\10-pwn\autopwn` |
| 容器内挂载 | `/work`（也是 WORKDIR） |
| 镜像 | `autopwn:pwn22`（Ubuntu 22.04，约 1.4 GB） |
| 一次性容器 | `solve.bat` / `shell.bat`：`docker run --rm`，**没有固定容器名** |
| 靶机容器 | `target.bat`：固定名 **`pwn-target`**，`docker logs pwn-target` 看日志 |
| 运行时权限 | `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`（gdb / setarch 需要） |
| 容器用户 | `root` |
| 网络 | `--host 127.0.0.1` / `localhost` 自动 `--network host`；其它地址走 `host.docker.internal` |
| 镜像内 Python | Python 3.10.12 |

`solve.bat` 实际执行：

```bat
docker run --rm --add-host=host.docker.internal:host-gateway ^
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ^
  -e AUTOPWN_HOST_ROOT="%CD%" -v "%CD%:/work" -w /work ^
  autopwn:pwn22 python3 -m autopwn.engine.cli %*
```

## 2. 工具清单（镜像内实测）

| 工具 | 状态 / 版本 | 用途 |
|---|---|---|
| `pwntools` | **4.14.1** | ELF / ROP / process / remote / fmtstr_payload |
| `capstone` | **6.0.0a11** | 引擎静态反汇编 |
| `gdb` | ✓ | 手调（**没有 pwndbg**，见下） |
| `checksec` | ✓ `/usr/local/bin/checksec` | 保护检查 |
| `ROPgadget` | ✓ 7.6 | gadget 搜索 |
| `ropper` | ✓ 1.13.13 | gadget 搜索 |
| `one_gadget` | ✓ 1.9.0 | libc one-gadget |
| `seccomp-tools` | ✓ 1.6.1 | sandbox 规则 |
| `patchelf` | ✓ | 换 libc / interpreter |
| `socat` / `nc` | ✓ | 起靶机 / 手连 |
| `qemu-i386` | ✓ | 交叉跑 32 位 |
| `strace` / `ltrace` | ✓ | 行为观察 |
| `gcc` / `g++` / `make` | ✓ | 临时编译验证 |
| `ruby` | ✓ | one_gadget / seccomp-tools 依赖 |

**缺失（构建时 GitHub 受限，属预期）**：`pwndbg`、`pwninit`、`libc-database`（`/opt` 为空）。
需要 pwndbg 时用普通 `gdb`，或临时 `git clone`（会污染容器，`--rm` 退出即消失）。

### 重新探测（环境变了先跑这个）

```bash
docker run --rm autopwn:pwn22 sh -c '
  python3 --version; pip3 show pwntools capstone | grep -E "^(Name|Version):"
  for t in gdb checksec ROPgadget ropper one_gadget seccomp-tools patchelf socat nc qemu-i386 strace ltrace; do
    printf "%-14s " "$t"; command -v "$t" || echo MISSING; done'
```

## 3. 宿主侧命令（Windows）

> 一律优先用 `.bat`。**不要**在 CMD 里 `bash docker/solve.sh`：本机 `bash` 指向未安装发行版的 WSL。

```bat
:: 静态事实（1 秒，不执行利用）
solve.bat <题> --facts-only

:: 本地自动打
solve.bat <题>

:: 三套回归（基线：13/15、5 shell + 1 flag-only、4/4）
solve.bat bench
solve.bat bench_extra
solve.bat bench_sys

:: 起/停容器靶机（pwn-target）
target.bat <题> 4444
target.bat <题> 4444 noaslr
target.bat stop

:: 交互 shell（一次性容器，退出即删）
shell.bat

:: 仓库卫生门禁（宿主机 python 是 pyenv shim，必须用 py -3）
py -3 scripts\audit\check_hygiene.py
```

`target.bat` 的行为刻意贴近真平台：`socat TCP-LISTEN,fork` 每次连接新进程（**ASLR 每次变**）、
不给 pty（stdout 全缓冲）、`_target/flag` 默认 `CTF2{docker-local-target}`（可用 `TARGET_FLAG` 覆盖）。

## 4. 手工调试（容器内）

进入与 `shell.bat` 等价的容器（Git Bash 下需要 `MSYS_NO_PATHCONV=1`，否则 `-w /work` 会被改写成 Windows 路径）：

```bash
MSYS_NO_PATHCONV=1 docker run --rm -it \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "D:/hacktools/10-pwn/autopwn:/work" -w /work autopwn:pwn22 bash
```

容器内常用：

```bash
cd /work/<bench|bench_extra|chellenges>/<题名>
checksec --file=./bin
ROPgadget --binary ./bin --only "pop|ret"
ropper -f ./bin --search "pop rdi"
seccomp-tools dump ./bin
one_gadget ./libc/libc.so.6          # 有自带 libc 时
gdb -q ./bin                          # 普通 gdb；先 set disassembly-flavor intel
```

pwntools 一次性脚本（留在 `scripts/` 或临时写完删除，不要放仓库根目录）：

```python
from pwn import *
context.binary = elf = ELF("./bin")
context.log_level = "debug"
p = process("./bin")
# ...
```

## 5. 环境坑（按现象对号入座）

| 现象 | 原因 | 处理 |
|---|---|---|
| `execvpe(/bin/bash) failed` | 本机 `bash` 是未装发行版的 WSL | 用 `.bat`，或在 Git Bash 里直接跑 docker |
| `No global/local python version has been set` | 宿主机 `python` 是 pyenv-win shim | 用 `py -3` |
| `_curses.error: setupterm` | 容器缺 terminfo | **无害**，忽略 |
| `setarch: failed to set personality` | Docker 默认 seccomp 拦 `personality()` | 容器加 `--security-opt seccomp=unconfined` |
| 靶机端口通但**没有任何输出** | 同上，程序根本没跑 | 同上；`target.bat` 已自动加 |
| `--host 127.0.0.1` 连不上 | 容器在独立网络命名空间 | `solve.bat` 已自动 `--network host` |
| 远程卡握手 | 平台套了 TLS | `--ssl`（`--sni` 默认等于 host） |
| 远程 `puts` 泄漏不回来 | 远程 stdout 全缓冲 | 引擎远程优先 `write(1,got,8)`；手工时也优先 `write` |
| 每次失败地址都不同 | `socat fork` 每连接新进程 | PIE 题按 nib 爆破；`noaslr` 只用于复现 |
| `pwn-target` 已存在 | 上次没停 | `target.bat stop`；脚本本身会先 `docker rm -f` |
| Windows 路径进容器 | 容器只认 `/work` | `serve.sh` 会把 `\` 转 `/`；手工命令用正斜杠 |

## 6. 自动解题流程与证据

1. `solve.bat <题> --facts-only`
   看 `prot / vulns / wins / binsh / gadgets / csu / mmap_rwx / fmtbuf`。
2. `solve.bat <题>`
   成功输出 `=> SHELL` 或 `=> FLAG-ONLY`；失败看 `FAILED` 与 `!!` 原因。
3. 复盘看 `results/<题名>.json`：
   `facts`、`strategy`、`attempts[].tail`（每次尝试的真实回显）。
4. 远程：
   ```bat
   solve.bat <题> --host H --port P [--ssl --sni H] [--libc libc.so.6] --cmd "id" --cmd "cat /flag"
   ```
5. 判定铁律：**目标进程里真的执行了命令**才算成功；策略跑完没报错、连接成功都不算。

## 7. 仓库纪律（手工做题也必须遵守）

- 临时脚本/反汇编导出**不要落仓库根目录**；回归用脚本放 `scripts/test/`，一次性审计放 `scripts/audit/`，用完即删。
- 证据 JSON 落 `results/`（已 gitignore），不要 `git add -f`。
- 每轮收尾：`py -3 scripts/audit/check_hygiene.py` 退出码必须为 0 → 回归 → 文档同步 → `commit + push origin main`。
- 新能力/新需求先登记 `upgraded.md §2` 并建 `upgraded/vX.Y.Z.md`，再改代码。
- 已覆盖与未覆盖题型见 `PROGRESS.md §3`；未覆盖：菜单式堆、SROP、20 字节极限 fmt、ORW、无 libc 的 ret2libc。

## 8. 本 Skill 的来源

基于 2026-11-13 的 `autopwn:pwn22` 镜像实测，事实来源：
`Dockerfile`、`solve.bat`、`target.bat`、`shell.bat`、`docker/serve.sh`、`HANDOVER.md §4`。
镜像或脚本改动后，跑 §2 的探测命令并更新本文件。
