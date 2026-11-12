# bench 评测结果（2026-11-13 凌晨）

> 判据：**本地进程里执行 `whoami` / `id` / `echo PWNED_$((6*7))` 有正确回显**，不看「策略跑完没报错」。

## 1. 总览

| 项 | 值 |
|---|---|
| 题目数 | 16（`chellenges/` 原始目录去重后 16 个唯一二进制；`bench/` 里是其中 15 个） |
| 解出 | **14**（`bench/` 15 题里 13；多出的 `f5b5…` 静态 32 位也解出） |
| 成功率 | **87.5%** |
| 全量耗时 | 约 90 秒（16 题，含容器启动） |
| 稳定性 | 连跑 5 轮：4 轮 14/16、1 轮 13/16（偶发时序抖动，重跑即恢复） |

## 2. 逐题结果

| # | 题目 | 保护 | 采用策略 | 关键产物 |
|---|---|---|---|---|
| 1 | ch01_note | NX / Partial RELRO | ret2win | 跳 `fun()` → `system("/bin/sh")`，off=23 + 对齐 ret |
| 2 | ch02_x86_4d79 | i386 / canary / NX | fmtstr | `printf(buf)` arg#10，`atoi@got → system@plt`，再喂 `/bin/sh` |
| 3 | ch03_58a4 | NX / Partial RELRO | ret2win | `scanf` 长度喂 1024 → `read` 溢出，off=24 |
| 4 | ch04_5ff0 | NX / Partial RELRO | ret2gets | `gets(bss)` → `system(bss)`，off=48 |
| 5 | ch05_82cf | NX / No RELRO | ret2win | 跳 `callsystem()`，off=136 + 对齐 ret |
| 6 | ch06_8835 | NX / Partial RELRO | ret2gets | 二进制只给 `cat flag.txt`，改写为 `gets(bss)+system(bss)`，off=64 |
| 7 | ch07_acae | canary / Full RELRO / 菜单堆 | —— | **未解**：Full RELRO + 2.35 堆利用，未实现堆策略 |
| 8 | ch08_b69c | NX / Partial RELRO | ret2win | 长度校验 `%d` 传 `-1` 绕过 → `read(0xffffffff)`，off=24 |
| 9 | ch09_cf87 | NX / No RELRO | ret2plt | `pop rdi; "/bin/sh"; system@plt`，off=136 |
| 10 | ch10_static32 | i386 / static / NX | ret2sys_write | 无 `/bin/sh`：先 `gets(bss)` 写入，再回 main，`int 0x80` execve，off=45 |
| 11 | ch11_fd2e | NX / Full RELRO | ret2win | 跳 `backdoor()` → `execve("/bin/sh")`，off=40 |
| 12 | ch12_zip3143 | NX / Partial RELRO | ret2win | `scanf("%s")` 溢出 → `backdooOo0r()`，off=40 |
| 13 | ch13_zip76c8 | NX / Partial RELRO / 自带 libc 2.31 | ret2libc | 同进程两阶段：泄漏 `puts@got` → `system("/bin/sh")`，off=40 |
| 14 | ch14_easyheap | canary / 菜单堆 | —— | **未解**：同上，堆利用未覆盖 |
| 15 | ch15_zip_e62d | PIE / Full RELRO / NX | ret2shellcode | `mmap(0x233000, RWX)` + 两段 read，off=56，手写 24 字节 execve |

## 3. 失败原因（如实记录）

| 题目 | 真实原因 | 若要补，需要什么 |
|---|---|---|
| ch07_acae | 菜单式堆（malloc/free/printf），Full RELRO，容器 glibc 2.35（`__free_hook`/`__malloc_hook` 已移除） | tcache/fastbin 攻击 + 堆地址泄漏 + 2.35 下的 FSOP/exit handler 路线 |
| ch14_easyheap | 同上；且程序不打印堆内容，无地址泄漏，safe-linking 需要堆基址 | 先构造信息泄漏再打 tcache poisoning |

> 这两题**不属于「参数没调对」**，是引擎目前没有堆策略，属于能力边界，不能算误报。

## 3.1 原始目录直跑（推荐，免手工整理）

```bat
solve.bat chellenges
```

引擎会自动：识别 ELF / 解压 zip / 识别「已解压的平铺目录（pwn + libc + ld）」，
按 md5 去重，再逐题打。无需先跑 `prep_bench.sh`。

## 4. 复现方式

```bash
# 构建镜像（只需一次）
bash docker/build.sh

# 全量
bash docker/solve.sh bench

# 单题（只看静态事实）
bash docker/solve.sh bench/ch13_zip76c8 --facts-only

# 远程
bash docker/solve.sh ./你的/bin --host 1.2.3.4 --port 31337 --libc ./libc.so.6
```

结果落在 `results/<题目>.json`：包含保护、漏洞点、win 函数、gadget、每次尝试的策略/耗时/输出尾部。

---

## 5. 补充：仓库自带样例（`bench_extra/`，来自 `Challenge/`）

这批是项目原有的经典题型，用来检验泛化能力（不是用户那 10 道题）：

| 样例 | 保护 | 结果 | 说明 |
|---|---|---|---|
| rip | NX / Partial RELRO | ✓ shell | 同 ret2win，off=23 |
| ret2libc | NX / Partial RELRO | ✓ shell | puts 泄漏 → system |
| level3_x64 | NX / No RELRO | ✓ shell | 只有 write 没有 puts：用 `__libc_csu_init` 拼 `write(1, got, 8)` 泄漏（新策略 `ret2libc_write`） |
| pie | PIE / Partial RELRO | ✗ | 局部覆盖 ret 到 `backdoor` 时栈未对齐，`system` 内 `movaps` 崩溃；无泄漏无法补 ret 滑板 |
| canary | i386 + canary | ✓ shell | 新策略 `canary_fmt`：`%p` 泄漏 canary → 带 canary 溢出泄漏 `puts@got` → 回 main → `system("/bin/sh")` |
| fmtstr1 | i386 + canary / 20 字节输入 | ✗ | 同上，且输入长度限制严格 |
| chall | NX / No RELRO / 仅 syscall gadget | ✗ | 需要 SROP（`rax=15`）路线，未实现 |
| ret2win | Full RELRO / 只打 flag | ✗ | 函数只 `cat /home/ctf/flag`，容器内无该文件；也不是 shell |

**结论**：8 题解 4 题（50%）。通用栈题（含 canary + fmt 组合）已覆盖；
SROP、20 字节极限输入的 fmt、纯 PIE 局部覆盖（栈对齐）仍需补策略，`ret2win` 那题只打 flag 且容器内无 flag 文件。

## 6. 判定口径

- **SHELL**：payload 后在目标进程执行 `echo PWNED_$((6*7))` / `whoami` / `id` 有正确回显 → 计入成功率
- **FLAG-ONLY**：只跳到 `system("cat flag")` 并匹配 `flag{...}` → 单独记账，**不计入** shell 成功率
- **FAILED**：以上都不成立
