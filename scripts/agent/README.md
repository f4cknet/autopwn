# 多 agent 无人值守迭代 —— 服务器部署指南

> 目标：你在服务器上跑一次 `deploy.sh`，之后**只提供题库 + 通过率目标**，
> 循环自己跑：实施改代码 → 脚本评测 → 达标合入 / 不达标回滚。

## 0. 你将得到什么

```
/srv/autopwn/
├── origin.git/     bare 仓库（两个 clone 的共同 remote，不用 GitHub）
├── impl/           Agent A 的 clone，分支 dev —— 唯一能改代码
├── verify/         Agent B 的 clone —— 只读，只写归因
├── eval/           root:root 755 —— 冻结评测器，Agent 只读
├── sealed/         root 700 —— 终检题，Agent 完全看不到
├── state/          last.json / best.json / history.jsonl / ALERT
└── logs/           每轮 agent 的原始输出
```

**谁能决定「通过」**：`supervisor.py`（纯 Python，无 LLM）。Agent 只交代码和文字。

---

## 1. 基础环境（15 分钟，其中镜像构建最久）

### 1.0 已实测环境（可直接跳到 §1.2）

| 项 | 实测值 | 是否满足 |
|---|---|---|
| OS | OpenCloudOS **9.6**（RHEL 9 系，用 `dnf`） | ✅ |
| Python | **3.11.6** | ✅ ≥3.7 |
| Docker | **29.7.0**（已装） | ✅ |
| Node | **20.20.2** | ✅ ≥18 |
| SELinux | **Disabled** | ✅ 不需要 `chcon` |

> 这套环境**零额外安装**：只要 `docker info` 能通、`claude --version` 能出版本，就直接跳 §3。

### 1.1 按发行版补齐缺的项

**RHEL 系（OpenCloudOS / TencentOS / CentOS / openEuler）：**

```bash
python3 -V                                    # 需 ≥3.7；<3.7 见下方
docker info >/dev/null 2>&1 && echo "docker OK" || {
  dnf install -y docker || {
    dnf install -y dnf-plugins-core
    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    dnf install -y docker-ce docker-ce-cli containerd.io
  }
  systemctl enable --now docker
}
node -v || { curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -; dnf install -y nodejs; }
getenforce                                    # 若 Enforcing：chcon -Rt container_file_t /srv/autopwn
```

**Debian / Ubuntu：**

```bash
apt update && apt install -y docker.io git python3 python3-pip
systemctl enable --now docker
```

> **Python <3.7 的处理**：`run_eval.py` / `supervisor.py` 用了 `from __future__ import annotations`，
> 需要 3.7+。装 `python39`/`python3.11` 后，命令里的 `python3` 换成对应解释器即可。

> **`sudo` 可能没有**：RHEL 最小安装常不装 `sudo`，`deploy.sh` 会优先用 `runuser`
>（util-linux 自带），没有才退回 `sudo`。

### 1.2 建镜像（**只做一次**，10–20 分钟）

Dockerfile 里有 i386 多架构 + gdb/ropper，首次构建最久：

```bash
cd /path/to/autopwn && bash docker/build.sh
```

**验收**：
```bash
docker run --rm autopwn:pwn22 python3 -c "import pwn;print('pwn ok')"
# 期望打印 pwn ok（这一步与宿主发行版无关）
```

---

## 2. 装 Claude Code（每个用户各自一份配置）

```bash
node -v            # 必须 ≥18，RHEL 系常见是 10/16，需要先升级
npm i -g @anthropic-ai/claude-code   # 或按官方脚本
claude --version
```

**无人值守必须用 API key，不能用 OAuth 登录**（OAuth 需要浏览器，headless 会挂）：

```bash
# 写进每个用户的环境（不要放全局）
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> /home/impl/.bashrc
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> /home/verify/.bashrc
```

> 想省事也可以两个用户共用一个 key；分开的好处是**配额/账单可分辨**，排障时有用。
> 但**隔离上下文靠的是不同 Linux 用户（各自 `~/.claude`）**，不是不同 key。

**验收**：
```bash
sudo -u impl bash -lc 'claude -p "say ok" --output-format json' | head -c 200
# 期望是一段 JSON，不是登录提示
```

---

## 3. 部署目录与权限

```bash
bash scripts/agent/deploy.sh /srv/autopwn "$(pwd)"
```

它做 6 件事：建 `impl`/`verify` 用户 → 建目录 → bare origin → 两个 clone → 把评测器拷到
`/srv/autopwn/eval/`（root:root 755）→ **权限自检并用 `[OK]/[FAIL]` 打印**。

**验收**（脚本会自己打印，三行都应是 OK）：
```
[OK] impl 读不到 sealed
[OK] impl 改不了评测器
[OK] verify 不改 impl
```

> 还要让 `impl` 能跑容器（自测用）：
> `usermod -aG docker impl` —— 注意 **docker 组 ≈ root**，接受它意味着 impl 能碰宿主。

---

## 4. 题库准备（**最容易出错的一步**）

```bash
# agent 可见的迭代集
mkdir -p /srv/autopwn/impl/dev/<题目名>/
# 终检集（agent 不可见）
mkdir -p /srv/autopwn/sealed/<题目名>/
```

每题目录**直接解压原样**即可（引擎的 `_normalize_dir` 会规范化），但有三条必须检查：

| 坑 | 检查 | 后果 |
|---|---|---|
| 附件自带 `flag` / `flag.txt` | `find dev sealed -name 'flag*'` 应为空 | 不删 → `cat flag` 直接成功，分数是假的 |
| libc 文件名是哈希 | 打开 `--facts-only` 看 `libc:` 那行，不能是 `None` | 认不出 → `ret2libc` 全废，或者 **2MB 的 libc 被当成题目 bin** |
| 与已有题库重复 | `md5sum` 去重 | 重复 = 不干净样本，测不出泛化 |

逐题自检：

```bash
cd /srv/autopwn/impl
for d in dev/*/; do bash docker/solve.sh "$d" --facts-only | grep -E "prot|libc"; done
```

**`libc:` 为 `None` 的题要么补 libc，要么记为「缺 libc」不计入分母。**

---

## 5. 起循环

```bash
python3 scripts/agent/supervisor.py \
  --root /srv/autopwn/impl \
  --state /srv/autopwn/state \
  --eval /srv/autopwn/eval/run_eval.py \
  --prompt-impl /srv/autopwn/eval/prompt_impl.md \
  --prompt-verify /srv/autopwn/eval/prompt_verify.md \
  --dev dev --target 0.7 --rounds 3 --max-hours 4
```

**第一次务必 `--rounds 3`**。先看曲线斜率，别一上来跑 20 轮。

systemd（可选，常驻）：

```ini
# /etc/systemd/system/autopwn-loop.service
[Service]
Type=simple
User=root
WorkingDirectory=/srv/autopwn
ExecStart=/usr/bin/python3 /srv/autopwn/impl/scripts/agent/supervisor.py \
  --root /srv/autopwn/impl --state /srv/autopwn/state \
  --eval /srv/autopwn/eval/run_eval.py \
  --prompt-impl /srv/autopwn/eval/prompt_impl.md \
  --prompt-verify /srv/autopwn/eval/prompt_verify.md \
  --dev dev --target 0.7 --rounds 20 --max-hours 8
Restart=on-failure
RestartSec=120
```

> 用 `User=root` 是因为 supervisor 要切换 git 分支、跑 docker。它不跑 LLM。

---

## 6. 怎么观察（不用盯着）

| 看什么 | 含义 |
|---|---|
| `state/history.jsonl` | 每轮一行：`dev_rate` / 三套回归 / `ok` / `why` |
| `state/ALERT` | **循环已停**（无提升 / 判据被改 / 超时）→ 这是你要处理的 |
| `state/DONE` | 达到目标 |
| `logs/*.json` | 每轮 agent 完整输出，事后追责用 |

**建议把 `ALERT` 接到你的手机**（企业微信机器人 / Telegram，10 行脚本），
否则「停在半夜」等于白跑。

---

## 7. 常见故障

| 现象 | 原因 | 处理 |
|---|---|---|
| `[eval] xxx: parsed=False` | 输出里没有 `=== N/M shell ===` | 看 `raw_tail`，多半是镜像没建好或题目加载失败 |
| 每轮 `ok=False, why=回归掉分` | impl 改了通用逻辑，牺牲了旧题 | 已自动 `reset --hard`，看 `logs/impl-*.json` 找原因 |
| `why=判据被改` | 有人动了 `oracle.py` | **立刻停**，查 git log；这是 L3 红线 |
| `claude: command not found` | systemd 不读 `.bashrc` | 在 unit 里写绝对路径或用 `Environment=` |
| 学生成堆在 `dev/` 但 `sealed` 空的 | 忘了留终检集 | 立刻补，否则你不知道真实泛化率 |

---

## 8. 停止与回滚

```bash
# 停循环
systemctl stop autopwn-loop
# 回滚到上一轮合入点（main 上每次合入都有 merge commit）
git -C /srv/autopwn/impl log --oneline main | head
git -C /srv/autopwn/impl reset --hard <merge_sha>^
```

`dev` 分支保留每轮提交，方便逐个复盘。

---

## 9. 这套东西的边界（务必读）

- **它不会提升"能力上限"，只会把已具备的能力补全**。3 轮不涨 = 缺能力，需要人加策略，别让它空转。
- **`sealed` 集必须是你没给过 agent 的题**。给过就等于没有终检。
- **判据永远不能被自动化**（`oracle.py` 的口径、`FLAG_RE`、gate 是否算成功）。
  哈希锁只是拦住意外，真拦住要靠你 review 每次 `[auto]` 提交里有没有碰 `oracle.py`。
- **不要在 `--target 1.0` 下跑**。100% 意味着要么样本太简单，要么判据被放宽了。
