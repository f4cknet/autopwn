# 早上好用这个（pwn 速用卡）

> 全部命令都在 `D:\ctf\ctf-env\autopwn` 下执行，镜像已构建好（`autopwn:pwn22`）。

## 1. 拿到题目后三步

```bash
# ① 把题目放成 bench/<题名>/bin（自带 libc 就放 bench/<题名>/libc/）
# ② 先看静态事实（1 秒，不执行利用）
bash docker/solve.sh bench/<题名> --facts-only

# ③ 直接打（本地拿 shell）
bash docker/solve.sh bench/<题名>
```

判成功只看一行：`=> SHELL ...`，并且 `results/<题名>.json` 里 `ok: true`。
`=> FLAG-ONLY` 表示只打出了 flag（不算 shell）；`=> FAILED` 就是没打通。

## 2. 一次打一批

```bash
bash docker/solve.sh bench                 # 跑 bench/ 下所有题
bash docker/bench_all.sh                   # 同上，带汇总表
```

## 3. 打远程（比赛现场）

```bash
bash docker/solve.sh ./pwn --host 1.2.3.4 --port 31337 --libc ./libc-6.so
```

> 远程打 ret2libc 必须给**题目同版本 libc**，否则算出来的 system 地址是错的。

## 4. 输出怎么读

| 输出 | 含义 |
|---|---|
| `prot=... vulns=[gets@0x... off=24]` | 保护 + 漏洞点 + 推导出的偏移 |
| `wins=[shell@0x... (system("/bin/sh"))]` | 二进制里现成的后门函数 |
| `-> s_ret2win: 70 plans` | 正在尝试哪个策略、共几套 payload |
| `[OK] ret2win ... (0.67s)` | 命中，且已用 whoami/id 验证 |

## 5. 打不通怎么办

1. `--facts-only` 看 `vulns` 是否为空：
   - 空 → 不是栈溢出（堆/格式化字符串/逻辑漏洞），本工具覆盖有限
   - 有 → 看 `off=` 是否合理，可手动试相邻值
2. `results/<题名>.json` 里 `attempts` 有每次的输出尾部，能看出是不是格式串/堆/长度限制
3. 已知不支持：菜单式堆（tcache/fastbin）、SROP、纯 PIE 无泄漏、超短输入的 fmt

## 6. 环境自查（万一镜像没了）

```bash
bash docker/build.sh          # 重建 ubuntu22.04 + pwntools/one_gadget/seccomp-tools/i386 库
docker images | grep pwn22    # 应该有 autopwn:pwn22
```

## 7. 本次离线评测成绩（可复核）

- `chellenges/` 15 题：**13 题拿到 shell（86.7%）**，三连跑稳定
- 未解：`ch07_acae`、`ch14_easyheap`（菜单式堆，glibc 2.35 下未实现堆策略）
- 明细见 `bench/RESULTS.md`，逐题记录见 `results/*.json`
