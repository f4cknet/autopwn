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


---

## 7. 2026-11-13 新增：纯 int 0x80 手写汇编（`chellenges/7a4abf36…`）

| 项 | 值 |
|---|---|
| 特征 | 724 字节、stripped、i386 静态、**无 libc**、`.data`/栈均不可执行 |
| 原症状 | `vulns=0 goggles=0` → **0 次尝试**，直接 FAILED |
| 根因 | 引擎只认 `call gets/read@plt`，而这类题 call 的是自写的 `int 0x80` 包装 |
| 修复 | `facts` 增加 syscall 包装识别（`mov eax,NR ... int 0x80`）；新增策略 `syscall3` |
| 结果 | 本地 `SHELL syscall3 uid=0(root)`、远程 `uid=1000(ctf)`，均 **1 次尝试** |
| 泛化 | 拆成两条：`syscall1`（`limit >= off+0x18`，一次 read 拿全三参）/ `syscall3`（`limit == off+0x14`，种 0 + 重入 `_start`） |

`syscall3` 的触发条件很窄（只有真正需要的题才会命中）：i386 + 存在 `mov eax,3` 包装 +
窗口恰好 `limit == off + 0x14` + `.data` 可写 + `_start` 有 `sub esp,imm`。
不满足就 return，不会给其它题型制造假 plan。


### 7.1 变体回归矩阵（`bench_sys/`，由 `docker/make_sys_variants.py` 生成）

只改立即数、其余字节不动，验证策略是按结构选路而不是写死偏移：

| 变体 | 改动 | off / limit | 命中策略 | 结果 |
|---|---|---|---|---|
| `v_fr28` | `sub esp,0x28` / `add esp,0x28` | 24 / 52 | `syscall1` | ✓ shell |
| `v_fr2c` | `sub esp,0x2c` / `add esp,0x2c` | 28 / 52 | `syscall1` | ✓ shell |
| `v_lim38` | `read` 数量 0x38 | 32 / 56 | `syscall1` | ✓ shell |
| `v_lim3c` | `read` 数量 0x3c | 32 / 60 | `syscall1` | ✓ shell |
| 原始 | 0x30 / 0x34 | 32 / 52 | `syscall3` | ✓ shell |

4/4 变体 + 原始题全部一次打通（本地）。这说明 `limit` 与 `off` 的关系决定走哪条路，而不是靠单题调参。


---

## 8. PIE + 无泄漏 + win 函数（`chellenges/pwn`，2026-11-13 晚）

| 项 | 值 |
|---|---|
| 特征 | amd64 PIE / Full RELRO / NX / 无 canary / stripped / 14472 字节 |
| 漏洞 | `read(0, rbp-0x30, 0xc8)`；`cmp dword [rbp-4], 0x7024f984` 校验 |
| win | `0x11e9`：`system("cat flag")` —— **是死代码，没有任何 call 指向它** |
| 原症状 | `vulns=1 wins=1` 但 **0 次尝试** |
| 根因 1 | 三条 ret2win 路线全部跳过：`s_ret2win` 见 PIE 就退、`s_ret2win_flag` 同理、`s_ret2win_pie` 只认 `kind=shell`（这题是 flag） |
| 根因 2 | win 地址被算成 `0x1130`：`_func_entries` 只认「符号 ∪ call 目标 ∪ entrypoint」，而 win 没人调用 → `call system` 被归到上一个函数 |
| 根因 3 | 就算跳到正确的 `0x11e9` 也会崩：`ret` 进入比 `call` 进入的 `rsp` 高 8 字节，`system` 内 `movaps` 对不齐 |
| 根因 4 | PIE + 零泄漏：返回地址 `0x12e6` 与 win `0x11e9` 在同一个 64K、但不同 0x100 页 → 必须 2 字节覆盖，而低 16 位里的 `0x1000` 位随基址变化 |

修复：

| 改动 | 内容 |
|---|---|
| `_func_entries` | 把 `endbr64/endbr32` 也算函数入口（CET 标记就在函数首地址，stripped 时的唯一线索）→ win 变成 `0x11e9` |
| `Win.alt` | 记录「跳过 `push rbp; mov rbp,rsp`」后的入口 → 这题是 `0x11f3`，用它栈就对得齐 |
| `Facts.gates` | 识别 `cmp dword [rbp-X], imm` + 条件跳转，换算成缓冲区偏移（这题 = 偏移 44 写 `0x7024f984`） |
| `s_pie_partial_win` | 只覆盖栈上已有返回地址的低 2 字节；本地读 `/proc/pid/maps` 拿精确基址（1 次），远程枚举 16 个 nib（32 个 plan） |

结果：

| 场景 | 结果 |
|---|---|
| 本地（有 flag 文件） | `FLAG-ONLY pie_partial flag:CTF2{local-test-flag}`，**1 次尝试 / 0.7s** |
| 本地（无 flag 文件） | `win reached (no local flag file)`，1 次尝试 —— 证明利用链成立 |
| 强制盲打 `AUTOPWN_NO_MAPS=1` | 第 **8** 次尝试命中，取出 flag（模拟远程） |
| `bench` 回归 | 13/15，无退化 |
| `bench_sys` 回归 | 4/4 |


### 8.1 用容器靶机验证「远程形态」

真实比赛结束后远程地址失效，改用 `target.bat` 把附件挂成 TCP 靶机（`socat TCP-LISTEN,fork`，
每连接一个新进程，ASLR 每次变化），再走和真远程完全一样的代码路径：

| 场景 | 命令 | 结果 |
|---|---|---|
| 容器靶机 + ASLR on | `solve.bat chellenges\pwn --host 127.0.0.1 --port 4444 --max-attempts 80` | 1 / 2 / 2 次尝试命中，`flag:CTF2{docker-local-target}` |
| 走 `host.docker.internal` | `--host host.docker.internal` | 7 次尝试命中 |
| 关 ASLR（`target.bat ... noaslr`） | 同上 | nib=4（基址 `0x555555554000`）固定，1 次命中 |

这一步的价值：验证了「无 `/proc` 访问」时 nib 爆破这条路真的能走通，而不是只在本地读 maps 的捷径上有效。


---

## 9. 「只要 flag、不落 shell」的三种形态（2026-11-13 晚）

结论先说：**只有前两种是同一种打法（ret2win 的变体），第三种难度等同交互 shell。**

| 形态 | 典型代码 | 打法 | 引擎策略 |
|---|---|---|---|
| ① 内置 `system("cat flag")` | `lea rdi,"cat flag"; call system` | 直接跳函数入口；注意 `system` 的栈对齐 | `ret2win_flag` / `pie_partial:flag` |
| ② 程序自己 `open()`+`puts()` 打印 flag，但**带全局/参数门槛** | `if (clearance != 0xdecafbad) return; open(FLAG_PATH); puts(buf)` | 跳「设门槛 + call win」的那条指令，**不是** win 本身 | `ret2win_flag`（win 排序会把门槛入口提前） |
| ③ 什么都没内置 | 只有 `read`/`printf` | 自己拼 ORW（open/read/write）ROP | 无（等同 ret2libc 难度） |

本批实测（`bench_extra/`）：

| 样例 | 形态 | 本轮结果 |
|---|---|---|
| `ret2win` | ②（`clearance==0xdecafbad` 才 `open("/home/ctf/flag")`） | ✓ 1 次尝试；本地无该文件 → `win reached (no flag file)`；放入文件后实取 `CTF2{self-read-flag}` |
| `pie` | ① + PIE | ✓ 之前因栈对齐崩，现在走 `pie_partial` 用 `alt` 入口修复 |
| `rip` / `ret2libc` / `level3_x64` / `canary` | 落 shell | ✓ |

本轮新修的真 bug：

| bug | 影响 | 修法 |
|---|---|---|
| `_find_wins` 顶部 `if not targets: return` 早退 | 没有 `system/execve` 的题（②型）永远识别不到 win | 改成「既没 system 也没 open+puts 才早退」 |
| 门槛入口算成 `mov [rip+X],rax` | 直接进去 `rax` 是垃圾，门槛永远不满足 → 只打印 "lock closed" | 回溯一条：用前面的 `mov eax, imm` 作入口 |
| `probe_flag` 只看新读到的数据 | flag 在前一段 `recvrepeat` 就到达 → **成功被判失败** | 判定改为对整个累积输出做正则 |
| 无 shell 可判、flag 文件又不存在 | 明明打到 win 却报 FAILED | 输出含 `No such file`/`unavailable` → 记 `win reached` |
