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
| fmtstr1 | i386 + canary / 20 字节输入 | ✓ shell | v7.4.0 `guard_fmt`：fmt 写全局门；与 `chellenges/71b6d3ae…` 同一二进制（md5 `eaef2247796c11db798a579396482399`），见 §17 |
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


---

## 10. 菜单式题：`chellenges/note`（2026-11-13 深夜）

| 项 | 值 |
|---|---|
| 特征 | amd64 non-PIE / NX / Partial RELRO / not stripped / 16536 字节 |
| 结构 | main 读一个命令字符：`'w'`→`write_note`，`'p'`→`preview_note`，**只跑一次** |
| 漏洞 1 | `write_note`: `read(0, rbp-0x40, 0x200)` → off=72，可直接 ret2win |
| 漏洞 2 | `preview_note`: `printf(buf)` 格式化字符串，但 127 字节到不了返回地址，且 main 不循环 → 不可用 |
| win | `print_flag` @ `0x401256`：`getenv("FLAG_PATH")` 默认 `/flag`，`open`+`read`+打印，**无门槛** |
| 原症状 | `s_ret2win_flag: 10 plans` 全空，程序只回 `Bye.` |
| 根因 | **没发菜单选择字符**：main 先 `fgets` 读一行，payload 的第一个字节不是 `w` 就走到 usage 分支 |
| 修法 | `Facts.interact`：扫 `cmp al,imm; jne <跳过 call>` 得出「进该函数要发的字符」（`'w'`/`'p'`），策略在 payload 前自动补 `b"w\n"` |
| 附带清理 | `print_flag` 内部 `read(fd, buf, 0x7f)` 曾被当成漏洞点（`vulns=4`）；现在按「函数入口 ∈ wins」剔除 → `vulns=3` |

结果：

| 场景 | 结果 |
|---|---|
| 本地（容器内造 `/flag`） | `FLAG-ONLY ret2flag flag:CTF2{note-test-flag}`，**1 次尝试** |
| 容器靶机（`target.bat` + `--host 127.0.0.1`） | `flag:CTF2{note-target-flag}`，**1 次尝试** |
| `bench` 回归 | 13/15，无退化 |

---

## 11. v7.0.1 交互层回归向量（2026-11-14）

| 项 | 值 |
|---|---|
| 脚本 | `scripts/test/interaction_vector.py` |
| 运行环境 | 容器 `autopwn:pwn22`（脚本导入 `autopwn.engine` 会拉 pwntools） |
| 命令 | `python3 scripts/test/interaction_vector.py` |
| 覆盖 | 跨 chunk / 重复 prompt 游标 / 静默屏障 / 超时 partial / EOF 快速失败 / `Send→Wait` 不自动读 / `Send→Send` 仍同步 / Send 失败转 `StepError` / `Plan` 归一化 / `run.execute` 两条错误路径 / 真实 C 菜单程序 |
| 结果 | **13/13 PASS**；真实 C 程序由 `Wait(b"menu> ")` 驱动三段交互，回显 `PWNED_42` |

不放进 `bench/` 的原因：旧引擎用「读到静默」也能过同类菜单题，放进题库会制造「新解出」的错觉；
本向量验证的是**表达力与时序语义**，不是新增题型。

另记一次观察（未复现）：全量 `bench_extra` 首次运行时 `ret2libc` 的 stage1 泄漏只回读到部分字节，
5 个 plan 全失败；随后连续 4 次单题与 1 次全量均通过。与本次交互层改动无已证实的因果关系，留待后续归因。

---

## 12. v7.0.2 判定 Oracle 向量（2026-11-14）

| 项 | 值 |
|---|---|
| 位置 | `scripts/test/interaction_vector.py` 新增 `judge_shell` / `judge_flag` 两项 |
| 覆盖 | marker/uid/无匹配三态；真 flag 优先于 win reached；**累积输出里早到的 flag**（§9 踩过的坑）；普通 `{}` 文本排除；大小写变体 |
| 结果 | **15/15 PASS** |
| 语义 | 判定正则逐字符复制自原实现，`bench` 13/15 / `bench_extra` 5+1 / `bench_sys` 4/4 与基线完全一致 |
| cause | `results/*.json` 的 `attempts[].cause`：shell 路径 `marker`/`uid`，flag 路径 `flag_re`/`no_flag_file` |

---

## 13. v7.0.3 repeater 解锁：canary-echo 泄漏 + 对齐重入 ret2libc（2026-11-14）

| 项 | 值 |
|---|---|
| 题目 | `chellenges/repeater`（2021 stripped amd64 / canary / NX / Partial RELRO / 无自带 libc） |
| 结果 | **`=> SHELL canary_echo uid=0(root)`**，连续 3 次全中（每次 41 attempts，先烧完 ret2libc 的 40 个再命中） |
| 前置修复 ① | `_find_fmt` 误报：repeater 的 `fmt=48` 实为 puts 回显的 lea 被记到常量串 printf 头上；`ret2win` 的 `printf("Hello, %s", buf)`（buf 在 rsi）同样误报。修法：`_flows_to_rdi` 用 alive 跟踪（lea 值被重写即死）+ last-write-wins + 中间有 call 重置（rdi 会被中间调用用掉） |
| 前置修复 ② | stripped 题从 `_start` 推 main：`lea rdi,[imm]`/`mov edi,imm` + `call __libc_start_main@plt` → imm 即 main（repeater=0x4007d9）。`s_ret2libc` / `s_canary_fmt` 直接吃上 |
| 新事实 | `Facts.echo_leak`：read 溢出 + 紧随 puts(同 buf) 回显的结构（正负例矩阵：repeater ✓ / note/canary/ch02/ch13 无误报） |
| 新策略 | `s_canary_echo` → `orchestrator._try_canary_echo` 三阶段同进程：①发 `A*(buf_size-8)+B` 盖 canary LSB 0x00 → puts 回显带出 canary[1:8]，重组 `b"\x00"+leak7`；②真 canary + 假 rbp + `pop_rdi(puts@got); puts@plt; 重入 main` → 算 libc base；③`ret 对齐 + pop_rdi(binsh) + system` → 真拿 shell |
| canary 检查 | 窗口条件 `off > canary_pos + word*2 - 1`；canary 距 buf 起点 = `buf_size - wordsize` |

三个坑（都是通用规则，已写进策略注释）：

| 坑 | 教训 |
|---|---|
| **时序**：probe 轮之后必须先 `send(b"0\n")` 让 scanf/getchar 消费完 | 否则 stage1 被 `scanf("%d")` 吃进 stdio 缓冲（匹配失败留在缓冲区），read 拿到残缺输入 → smash。gdb 断点 + `/proc/pid/mem` 对拍才定位 |
| **重入点**：必须重入带 prologue 的函数体（`_start` 推导的 main），不能跳循环体 | 跳循环体时 rbp 保持垃圾值，退出时 `mov rcx,[rbp-8]` canary 检查读垃圾必 smash |
| **对齐**：stage2 必须插裸 `ret`（`f.gadgets["ret"]`） | 缺它 `do_system` 内 `__sigemptyset` SIGSEGV（movaps 类对齐要求） |

fmt 判定矩阵（修复后）：

| 二进制 | 期望 | 实测 |
|---|---|---|
| `bench/ch02_x86_4d79`（i386 真 fmt） | 112 | 112 ✓ |
| `chellenges/repeater`（puts 回显 + 常量 printf） | None | None ✓ |
| `bench_extra/ret2win`（buf 在 rsi 第二参） | None | None ✓ |
| `chellenges/note`（真 fmt） | 144 | 144 ✓ |
| `bench_extra/canary`（i386 真 fmt） | 76 | 76 ✓ |

回归：`bench` 13/15、`bench_extra` 5+1、`bench_sys` 4/4，全部与基线一致。

---

## 14. v7.0.4 远程 libc 识别：repeater 远程全自动拿 flag（2026-11-14）

| 项 | 值 |
|---|---|
| 靶机 | `a5345cafaf17ea1c3f699e19.tcp-ctf2.dasctf.com:9999`（TLS） |
| 结果 | **`=> SHELL canary_echo remote-libc[libc6_2.23-0ubuntu11.3_amd64]`，6 次尝试，`--cmd "cat /flag"` 真取 `CTF2{b884870c-…}`** |
| 根因 | 本地容器 glibc 2.35（puts low12=0xe10）≠ 远程 2.23（low12=0x6a0）→ `_find_libc_base` 永不匹配 |
| 新模块 | `libcsearch.py`：`candidates(low12_map)` 双符号指纹 → LibcSearcher 离线库（镜像内置 1.1.5）；单符号允许 amd64 候选 ≤6 放行；libc.rip API 兜底；`rebase()` 页对齐校验 |
| 接入 ① | `s_ret2libc`：远程无 `ch.libc_path` 时 stage1 双泄（puts + printf GOT），desc 带 `+printf` 标记；同时跳过 scanf preset（repeater 实测 1024 会把 cont 喂成非 0 → 程序退出） |
| 接入 ② | `_try_ret2libc`：本地 `_find_libc_base` 失败 → `_stage2_remote_cands` 逐候选发 stage2（带循环闸的 plan 才喂退出 `9\n`，ch13 的 fgets 循环多喂一行会把 stage2 顶掉一位——实测回归后改为按 desc 门控） |
| 接入 ③ | `_try_canary_echo`：同路径；单符号多候选时**一连接试一候选**（打错地址进程就死），`cand_idx` 轮换起点，外层 attempt 换新连接接续 |
| 验证 | 远程 2/2 全中；本地 `ch13` / `bench_extra/ret2libc` 路径不变（1 attempts）；`repeater` 本地 3/3 不变；三套回归 13/15、5+1、4/4；向量 15/15 |
| flag | `CTF2{b884870c-f5f2-4379-9c1d-fb8d7f6b54e8}`（`results/remote/FLAGS.md` 口径） |

---

## 15. v7.1.0 prompt 驱动交互：`Wait(prompt)` 从能力变成引擎自动产出（2026-11-14）

| 项 | 值 |
|---|---|
| 新事实 | `Facts.prompts: {函数入口: [常量提示串]}`（`facts._find_prompts`） |
| 提取模式 | ①`lea rax,[rip+…]→mov rdi,rax`（note）②`mov edi,0x400a70` 直接进 rdi（repeater）③i386 `push imm`；归组到其后 25 条内最近的 read/gets/fgets/scanf 所在函数 |
| 过滤 | 4~64 字节 / 可打印 / 含 `: ? ! >`；banner 与错误信息自然落选（正负例矩阵：note/repeater/ch13/ret2win ✓，canary/pwn 空 ✓） |
| 策略 | `_prelude_variants` → `(menu, prompt)` 对；菜单题 `Send(m)` 后 `Wait(prompt)` 替代盲等静默；desc 带 `prompt=…` |
| 坑 | capstone `detail=True` 时 `mov edi,imm` 的 `operands[0]` 是 REG、`operands[1]` 才是 IMM；PLT 桩地址成对（+0/+4）要用 `_puts_plts` 全集 |
| 向量 | `interaction_vector.py` 17/17（prompt 过滤规则 8 例） |
| 实打 | `note` 容器内 1 attempts 取 `CTF2{v710-note}`，desc：`menu=b'w\n' prompt=b'Write a note:'` |
| 回归 | bench 13/15 / bench_extra 5+1 / bench_sys 4/4；repeater 本地 3/3、远程 libc 识别路径不受影响 |

---

## 16. v7.2.0 hints + canary_fmt 四 bug 修复：cannary 自动打穿（2026-11-14）

| 项 | 值 |
|---|---|
| 题目 | `chellenges/f13e67870…`（NewStar「cannary」：amd64 / canary / Full RELRO / stripped / backdoor=execve('/bin/sh')） |
| 结果 | **`=> SHELL canary_fmt canary=… -> win 0x401262`，11 attempts（候选轮），反复 2 次全中** |
| 修复 ① | `_try_canary_fmt` probe 长度按 `size_limit` 截断——原 184B probe > 32B limit 被 read 截断，fmt 串残缺 |
| 修复 ② | probe 改位置参数 `%N$p`，arg0 = 6 + canary_off/wordsize（cannary 实测 arg11 = 6+40/8） |
| 修复 ③ | `_canary_candidates` 删两项误杀：`v%0x1000==0` 页对齐（canary 1/16 概率恰页对齐，0x…a000 被杀）、`v < 2^56` 上界（15/16 的 canary 被杀——canary 是满 64 位随机值） |
| 修复 ④ | `_try_canary_fmt` 有 backdoor（execve/system win）且本地时直接 ret 到 win，不走 ret2libc（cannary 无 pop_rdi 也能打） |
| hints | `_find_wins` 排序加 hints 插队（符号名含 getflag/backdoor/shell/win/flag 且落 .text）——只做排序证据不做判定（铁律 1） |
| cc7e9c60 | 判定能力边界：scanf(%s) 坏字节封死唯一 pop rdi；fmt 泄漏卡 resolver xsave 区越界（bss 栈 rsp≥0x601110 物理不可达）；brute 不适用（写 8 字节完整地址，高位 20-bit 熵）。GDB 逐级实证入 PROGRESS §4 |
| 修复 ⑤ | **cannary 远程打穿**：win 直跳分支原限定 `not host`（本地），远程落到 ret2libc 分支需要 pop_rdi（cannary 没有）→ 必败。修正为本地/远程通吃（backdoor 自带 execve，无参数需求，不依赖 libc）→ 远程 `=> SHELL canary_fmt -> win`，`cat /flag` 真取 `CTF2{891eecf6-…}` |
| 修复 ⑥ | `verify_shell` 加空读容忍：远程 TLS/socat 的 shell 输出可能延迟超过 1 个 wait 窗口，首个空读直接 break 会把活 shell 判负；timeout>3s（远程）时空读容忍 1 次 |
| 修复 ⑦ | **ae3f24d3 远程打穿**：`ret2libc_write`（csu 泄漏型）没有接 v7.0.4 的远程 libc 识别——本地 2.35 偏移打远程 2.23 → core dump。三处补齐：①`s_ret2libc_write` 远程无 libc 时双泄（write + read/printf GOT）；②**csu 双块连用的链错位修复**——第二块不能重复 `p64(A)`（pop 槽会把它当值消费），直接续 6 参数 + call 块（手工 GDB 实证）；③`_parse_leaks` 支持 write 型连续 16 字节双段解析（原只认 puts 行分隔）→ 远程 `remote-libc[libc6_2.23]` 自动识别，真取 `CTF2{163031b6-…}` |

---

## 17. v7.4.0 守卫分析：逻辑校验 / 回填 / 诱饵 win（2026-11-14）

> 全部为**样本外**赛题（`chellenges/`，未参与调参）。命令在仓库根目录执行；
> `--facts-only` 可先看 `guards` / `backfil` / `unknown`，再真打。

| # | 二进制 | 策略 | 载荷 / 交互 | 期望结果 |
|---|---|---|---|---|
| 1 | `chellenges/492fad5075a97028c5d87632a6012695e984851ccdd7474d02fcfb9b4e9fed28` | `guard_write` | 121 B：`dead-` + 111 字节 + `-beef`（约束构造，不写死） | `=> SHELL guard_write uid=0(root)`，1 次 |
| 2 | `chellenges/4ee0fc91df7c8128f4b660c68e40ca64fc2064ef45505ee387d398628a0be453` | `guard_write` | 53 B：`A*0x34 + \x11`；`dword[0x38]` 由 `.bss` 零值保证 | `=> SHELL guard_write uid=0(root)`，1 次 |
| 3 | `chellenges/71b6d3ae9f85667e0f275d9f41ac4d8c96e2b366744ad3942049a3175a65ebf8` | `guard_fmt` | `%p` 探针 arg#11；`fmtstr_payload` `write_size=byte` 写 `0x804a02c=4` | `=> SHELL guard_fmt uid=0(root)`，1 次 |
| 4 | `chellenges/434ced4523885b245513a32a867390f445565390be82abb520a94af1e5351684` | `guard_backfill` | 读程序打印的随机 token，回填前 4 字节 | `=> FAILED` + `!! GATE: 门控通过但未执行命令；不记为 SHELL/FLAG`；**0/1 shell** |
| 5 | `chellenges/fdfaa93a42e2e5121967cd59ae78ba5d250f2f43e1a35a5c17c2d24434ea5d1b` | `ret2decoy` | 先喂 `0\n` 占位，再送 `A*44 + p32(0x804854b)`（48 B） | `=> FAILED` + `!! WIN: 诱饵 win 已执行（仅回显固定串）；不记为 SHELL/FLAG`；**0/1 shell** |

复现：

```bat
solve.bat chellenges/492fad50... --facts-only
solve.bat chellenges/492fad50...
:: 其余四题同理；题四/五的「不算成功」是判据要求，不是失败回归
```

关键事实（`--facts-only`）：

- 492f：`guards: shell@0x4008dc solved buf=global:0x6010c0 len=121 …`；
  `Serialization` 返回 EAX 判据 `test eax,eax; je 4008eb(fail)` 必须落下
  → `mov eax,1@0x40087b` → `strlen==0x79` + `0x0..0x4`/`0x74..0x78` 字节约束。
- 4ee0：`guards: shell@0x133d solved buf=global:0x4060 dword[0x34]=0x11,dword[0x38]=0x0`；
  两级守卫（`0x12eb` / `0x132a`）以落到 `system` 的最后一级为准。
- 71b6：`guards: shell@0x80485e6 fmt … global[0x804a02c]=0x4 fmt=0x80485ad`。
- 434c：`backfil: strncmp@0x8048652 backfill n=4 marker=good job!!`；
  gate 后无命令执行路径，因此只记 `gate_passed`。
- 题五：`wins: decoy@0x804854b(system("echo flag"))`、`guards: []`、`backfil: []`；
  诱饵 win 显式打 1 次，只记 `win_executed`。

判定口径（**不得放宽**）：

- `guard_write` / `guard_fmt` 的 SHELL 必须看到 `uid=` 或 `PWNED_42`；gate 通过本身不算。
- 434c 的 `good job!!`、题五的 `flag` 回显都是**证据态**（`ok=False`），
  `attempts[].cause` 分别为 `gate_passed` / `win_executed`，CLI 的 shell/flag 计数不增加。

回归：`bench` 13/15（`ch07_acae`、`ch14_easyheap`）、`bench_extra` **6 shell + 1 flag-only**
（`fmtstr1` 与 71b6 同一二进制 md5 `eaef2247796c11db798a579396482399`，由同一 `guard_fmt` 解开，
高于基线 5+1）、`bench_sys` 4/4；`--allow-brute` 未开启，盲试 0。

## 18. v7.4.2 合成向量：数字菜单 / 全局写→win / 静态事实 / shell 判据（2026-11-14）

> **不新增 bench 题**（套件规模仍 15/8/4）。向量在容器内用 x64 gcc 临时编译，
> 二进制不落库；镜像缺 32 位 crt 与 i386 libc.a，**未尝试 `-m32`**。
> C1 的 32 位形态用 `bench/ch10_static32 --facts-only` 兜底。
> 真样本命中由验证方下轮盲测确认（目标题在 `holdout/`，执行方不读）。

复现（仓库根目录，cmd.exe）：

```bat
docker run --rm -v "%CD%:/work" -w /work autopwn:pwn22 python3 scripts/test/v742_vectors.py
:: Git Bash 下需加 MSYS_NO_PATHCONV=1，否则 /work 会被改写成 Windows 路径
```

实测：**29 passed / 0 failed**。

| 组 | 向量 | 断言 | 实测 |
|---|---|---|---|
| D | `/bin/sh`、`/bin//sh`、`/usr/bin/sh`、`sh` | 判 shell | 4/4 |
| D | `fish`、`push`、`C:\foo\sh`、`/bbbb?/sh`（目录不存在） | 不判 shell | 4/4 |
| D | `/bin/sh -c id`、`cat /flag`、`echo flag` | 非 shell；flag / decoy 分类不变 | 3/3 |
| A | 内联 `scanf("%d")` 菜单 / helper 读选择+分派 / `read`+`atoi` 菜单 | `f.interact` 含 `b"1\n"` | 3/3 |
| A | 长度输入无横幅 / 有编号横幅但比较的是 100、50 | `f.interact` 为空 | 2/2 |
| B | `struct { char buf[64]; void (*fn)(void); } g` + `fgets(g.buf,128,stdin)` + `g.fn()` + `system("/bin/sh")` | `global_writes`/`global_calls` 非空；payload 末字 = `win.addr`；端到端 `PWNED_42` 且 `strategy=global_write_win` | 7/7 |
| C1 | x64 `-static`：`fgets` 写栈缓冲 + `system("/bin/sh")` win | `static=True`、无 PLT 误诊、`analyse` 有 vuln、`_static_vulns` 命中 `fgets` 且 offset 非空、静态 shell win 识别 | 6/6 |

关键事实：

- **A 暴露的真实 bug**：`.plt` 与 `.plt.sec` 同时映射同一符号（如 `__isoc99_scanf`
  在 `0x401060` / `0x401064`），调用点只落其中一个而 `ch.plt(name)` 只返回一个。
  已改为从 `ch.plt_map` 收全部同名地址；旧 `scanf("%d")` 路径同样受益。
- **B**：`_buf_is_global` 新增 x64 `lea reg, [rip+disp]` 识别；策略按 `ch.wordsize`
  打包（32 位题不再误用 `p64`）。
- **C1**：`ch10_static32` 输出与改前一致（`gets@0x80489f6 disp=15 off=45`，wins `[]`，
  无「PLT 映射为空」），旧路径优先级未变。

回归（同轮实跑）：`bench` **13/15**（仅 `ch07_acae`、`ch14_easyheap`）、
`bench_extra` **6 shell + 1 flag-only**（仅 `chall`）、`bench_sys` **4/4**；
`--allow-brute` 未开启，盲试 0。
