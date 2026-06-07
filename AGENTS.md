# AGENTS.md — AutoPwn 项目治理

> 本文件是 AutoPwn 项目重构期间的**顶层治理规则**。
> 性质：**项目级（governance）**，仅约束本仓库 `autopwn.py` / `autopwn/` / `refactor.md` / `rebuild.md` 范围内的工作。
> 与"全局 AGENTS.md"（`/ctf/AGENTS.md`，agent 操作手册）的关系：
> - 全局 AGENTS.md 约束 agent **怎么运行**（权限、记忆、心跳、Owner 认证等）
> - 本文件约束本项目**怎么被改动**（任务、状态、文档、验收）
> - 两者**正交**，互不覆盖；不要把项目级规则写进全局
> - agent 启动时已自动加载 cwd 下的本文件
>
> 优先级：本文 > `rebuild.md`（实施手册） > `refactor.md`（架构设计） > 其他。
> 读者：项目 Owner、维护者、参与重构的**所有 AI Agent 与人类开发者**。
> 生效范围：v3.1 → v4.0 重构周期内；v4.0 发布后由 `CONTRIBUTING.md` 接管日常开发治理。

---

## 0. 三层文档契约

| 文件 | 性质 | 回答 | 维护者 | 更新时机 |
|---|---|---|---|---|
| `AGENTS.md`（本文件） | 顶层治理（governance） | **能不能做 / 不做会怎样** | Owner | 极少（治理变更） |
| `refactor.md` | 架构设计（design） | **为什么 / 是什么** | 架构师 / Owner | 阶段切换、架构变更 |
| `rebuild.md` | 实施手册（execution） | **做什么 / 谁做 / 做到哪** | 任务 Owner | 每个 PR |

**单一事实来源**：所有"项目当前状态"的真相，由以上三份文档共同承载。**不允许存在第四份事实来源**（私聊决策、群消息、Notion 页面、commit message 中的"顺便提一下"）。

> **不变量**：任何代码改动 ⇒ 至少触及以上三份文档之一。代码与文档始终同源。

---

## 1. 铁律（不可绕过）

### 铁律 1：实施以 `rebuild.md` 为准
- 任何代码改动必须对应 `rebuild.md` §4 中的一个 `P{阶段}.{子任务}` 行
- 在 `rebuild.md` 中找不到对应项 ⇒ **该任务不存在**
- 如果你觉得自己要做的事在 `rebuild.md` 中没有：
  1. 先在 `rebuild.md` §4 中 grep 关键字（确认不是漏看）
  2. 确认漏看 ⇒ 该项是**新需求** ⇒ 立即停手，走铁律 2
- 例外：纯文档 / typo / 链接修正可不挂任务，但需在 PR 描述中写明

### 铁律 2：新需求先更新文档，再实施
**严禁直接实施未经文档记录的新需求。** 哪怕需求看起来"显而易见"或"十分钟能搞定"。

新需求包括但不限于：
- 重构过程中冒出的"我顺便改一下这里"
- 同事 / 业务方 / Issue 跟踪中的临时请求
- 看到代码 smell 临时起意的优化
- 工具链调整（CI、依赖、lint 配置、pre-commit）
- 新增利用方式 / 新增支持的架构 / 新增二进制类型
- `autopwn.py` 中任何非 `rebuild.md` §4 覆盖到的改动

**强制流程（缺一步都不算完成）**：
1. **架构层**（`refactor.md`）：加一节或修改既有节，说明
   - 为什么这个需求存在
   - 对应什么架构问题
   - 影响哪些层 / 哪些模块
2. **执行层**（`rebuild.md` §4）：加一行任务，含 ID / 状态 ⏳ / 预估 / Owner（可先 `待认领`）
3. **风险层**（`rebuild.md` §8）：评估风险（哪怕 🟢 低），写缓解措施
4. **评审**：Owner 或指定 Reviewer 签字（PR 中 `@` 到具体人）
5. **实施**：上述 4 步完成并通过后，才能写代码
6. **追溯**：PR 标题格式 `[P{阶段}.{子任务}] ...`，描述必须链接到本任务的 `rebuild.md` 章节锚点

### 铁律 3：任务必须有状态，且双文档同步
- `rebuild.md` §4 中**每一行**任务都必须有状态（⏳🔄👀✅⚠️❌ 之一，不允许空着）
- 状态定义与转换规则见 `rebuild.md` §2.1
- **每次代码合并后，必须在同一 PR 中更新文档**：
  - `rebuild.md` §4 对应行：状态、Owner、PR#、实际工时
  - `rebuild.md` §6 对应阶段：打勾验收项
  - `rebuild.md` §10：若有新增阻塞 / 解除阻塞
  - `refactor.md`：仅当架构决策本身变化时才动；任务状态本身不在 `refactor.md` 中跟踪
- 文档更新与代码改动**禁止分两个 PR**
- 仅文档变更（无代码）可以独立 PR，但仍需引用任务 ID

### 铁律 4：未经验证 = 未完成
"完成"的判定标准（**全部满足**才能把状态改 ✅）：

1. ✅ 代码已合并到 `dev` 分支
2. ✅ `pytest -m "not integration"` 全绿
3. ✅ 若涉及行为变化：`pytest -m integration` 跑通对应 `Challenge/` 二进制
4. ✅ 若涉及 `autopwn.py` 行为：在至少 1 个 `Challenge/` 二进制上跑一次，对比关键日志（`EXPLOITATION SUCCESSFUL` / 选中的 strategy 名 / 关键地址）一致
5. ✅ 至少 1 位 Reviewer 签字
6. ✅ 文档已同步（铁律 3）

**任何一条不满足，状态都不能改 ✅**。"代码写完了没空跑测试" 不构成完成；"本地跑过了没 push" 也不构成完成。

---

## 2. 衍生规则（强化铁律）

### 2.1 任务粒度
- 单个 PR ≤ 400 行 diff（不含被自动生成的文档与 lock 文件）
- 单个 PR 只动**一个层**（如 P4 阶段只动 `recon/`，不允许顺手改 `primitives/`）
- 单个 PR 不跨阶段（P4 + P5 必须分两个 PR）
- 任务粒度过大 ⇒ 在 `rebuild.md` 中拆分（用 `P{x}.{y}a` / `P{x}.{y}b` 标注）

### 2.2 Owner 责任
- 一旦 `rebuild.md` §4 中 Owner 字段被填写（含 `@handle`），该 Owner 负责：
  - 在合理时间内启动任务（不做 ⇒ 必须明示阻塞并填 §10）
  - PR 描述完整（链接到 `rebuild.md` 的对应 ID 小节）
  - 合并后 24h 内更新 §4 / §6 / §8 / §10
- Owner 转让：直接修改 §4 中的 Owner 字段并在 PR 描述中说明，旧 Owner 不再承担责任

### 2.3 Reviewer 责任
- Reviewer **必须**验证 PR 是否违反本文档的 4 条铁律
- 任意一条违反 ⇒ **Request Changes**，不允许 Approve
- 特别关注：
  - 任务 ID 是否在 `rebuild.md` §4 中存在
  - 状态是否在 PR 中更新
  - 验收标准是否全部满足（铁律 4 的 6 条）
  - 是否有"顺手改"的越界改动

### 2.4 文档与代码同 PR
- 禁止"先合代码、下个 PR 再补文档"
- 禁止"先开 PR 改文档、再开 PR 改代码"
- 禁止"批量 PR 把 5 个任务合在一起"（违反 §2.1 粒度）

### 2.5 阻塞透明
- 任何阻塞必须在 `rebuild.md` §10 登记
- 阻塞超过 3 天 ⇒ Owner 升级到项目 Owner
- 阻塞超过 7 天 ⇒ 任务在周例会重新评估（继续 / 拆分 / 取消）

### 2.6 验证方法论（Owner 决策 2026-06-07，临时需求 #3）

> **本节是铁律 4（"未经验证 = 未完成"）的具体落地规范**。所有代码任务的验证必须按本节执行。

#### 2.6.1 四大原则
1. **串行执行**：验证脚本必须**串行**跑每个 binary。**禁止并发**——并发会引入 race condition（如 `Information_Collection.txt` 共享污染，详见 R13）。
2. **关键节点 debug 日志**：在以下 7 个关键节点必须调用 `print_debug()`，输出到 stderr：
   - `print_section_header` 入口（每个 section 标题）
   - `collect_binary_info` 中 `checksec` 调用
   - `set_permission`（提权前）
   - `pie_backdoor_exploit` / `pie_backdoor_exploit_remote`（PIE 爆破）
   - `ret2_system_x64` / `ret2_system_x32`（ret2system 触发）
   - `detect_libc`（libc 探测）
   - `canary_fuzz`（canary 暴力枚举）
3. **logs/ 目录**：所有验证产物必须落到 `logs/<version>/<binary>.log`。`logs/` 下分 4 个子目录：
   - `logs/v3.1/`：原 pwnpasi 3.1 baseline
   - `logs/v4.0/`：当前 autopwn 4.0.dev0
   - `logs/comparison/`：2-log 对比报告（`summary.md`）
   - `logs/_debug/`：verbose 模式详细日志（不入仓，加 `.gitignore`）
4. **2-log 对比为主**：验证结论以 v3.1 log 与 v4.0 log 的对比为依据（关键行为标记一致性 ≥ 90% 为 PASS）。

#### 2.6.2 标准流程
```bash
# 1. 备份当前 _legacy.py
cp autopwn/_legacy.py /tmp/_legacy_backup.py

# 2. 串行跑目标版本
bash scripts/run_verify.sh <version-tag> <bin1> [bin2] ...   # 默认 60s/binary
# 或设长 timeout:
AUTOPWN_VERIFY_TIMEOUT=600 bash scripts/run_verify.sh v4.0 canary fmtstr1 level3_x64 pie rip

# 3. 2-log 对比
python3 tools/verify_v31_v40.py    # 生成 logs/comparison/summary.md

# 4. 验证 PASS 判定
#    - 关键标记一致性 ≥ 90%
#    - SUCCESS 计数与 baseline 持平或更好
#    - 无新增 KeyError / "no suitable shellcode" 失败模式
```

#### 2.6.3 工具与脚本
- **runner**：`scripts/run_verify.sh`（不入主包）
- **debug helper**：`autopwn._legacy.print_debug()`（临时落 `_legacy.py`，P1 阶段移入 `core/logging.py`）
- **对比脚本**：`tools/verify_v31_v40.py`（19 个关键行为标记）
- **timeout**：默认 60s/二进制，可用 `AUTOPWN_VERIFY_TIMEOUT` 环境变量调整

#### 2.6.4 豁免
- 单文件 PR（≤ 50 行）可仅跑相关 1-2 个 binary 即可，**不豁免 2.6.2 流程**
- 文档-only PR（`AGENTS.md` / `rebuild.md` / `refactor.md`）**不适用**本节

---

## 3. 违规与升级

| 等级 | 行为 | 处理 | 恢复 |
|---|---|---|---|
| **L1 轻微** | 文档漏更新但任务已合并 | Reviewer 退回 PR，要求同 PR 补文档 | 补完即恢复 |
| **L1 轻微** | PR 标题未引用任务 ID | Reviewer 退回 | 改 PR 标题 |
| **L1 轻微** | 任务粒度超 400 行 | Reviewer 退回要求拆分 | 拆完重开 |
| **L1 轻微** | 状态未及时更新（合并后 24h） | Owner 主动补；超过 3 天则升级 L2 | 补完即恢复 |
| **L2 中度** | 绕过文档直接实施新需求（铁律 2） | 该 PR 关闭；任务走铁律 2 重新立项；Owner 约谈 | 走完铁律 2 后恢复 |
| **L2 中度** | 任务标 ✅ 但验收未过 | 状态回退到 👀 或 🔄；要求补验收 | 补完验收恢复 |
| **L2 中度** | 同一 PR 混动多个层 / 跨阶段 | Reviewer 退回要求拆分 | 拆完重开 |
| **L3 严重** | 伪造验收（声称跑过但实际未跑） | 撤销 PR；该 Owner 暂停认领新任务一周；记录到本文件 §5 | 一周冷却期后恢复 |
| **L3 严重** | 反复违反铁律 2 / 4 | 撤销该 Owner 资格；需 Owner 重新授权 | 需 Owner 重新签字 |

> 违规记录在 PR 描述和 `rebuild.md` §10 中留痕，不在本文件留痕（本文件是规则，不是案例库）。

---

## 4. 紧急通道

以下三种情况可临时跳过铁律 2（**仅铁律 2**，铁律 1/3/4 永远不能跳过）：

1. **线上 / 安全类紧急修复**（如 `autopwn.py` 触发误报、安全漏洞 CVE）
   - 必须 24h 内补走铁律 2
   - 需 Owner 在 PR 中签字
2. **CI 全红且阻塞合入**（hotfix 模式）
   - 文档更新必须同 PR 跟上
3. **Owner 明确授权的临时特批**
   - 必须在 `rebuild.md` §10 阻塞登记表中写明：原因、起止时间、授权人
   - 特批超过 7 天自动失效

**其他一切情况，铁律不可绕过。** "看起来很简单"、"只改一行"、"下不为例" 均不构成跳过理由。

---

## 5. AI Agent 特别条款

任何参与本项目的 AI Agent（Codex CLI / 其他）**在每个 session 启动时必须按序执行**：

1. 读取本文件（`AGENTS.md`）——完整
2. 读取 `rebuild.md` §0 阅读指引 + §2 状态图例 —— 完整
3. 读取 `rebuild.md` §3 里程碑 —— 完整
4. 读取 `rebuild.md` §4 中**Owner 为当前 session 标识**的所有任务行
5. `refactor.md` **不全读**，按需查阅对应小节，避免 context 浪费

**硬性约束**：

| ❌ 禁止 | ✅ 允许 |
|---|---|
| 主动修改 `rebuild.md` 之外的文件（即便看起来"顺手"） | 对未识别的需求做"需求澄清"提问（不实施，先问） |
| 跳过 `rebuild.md` 直接生成代码 | 建议"这看起来是新需求，建议走铁律 2" |
| 在 PR 描述 / commit message 中遗漏任务 ID | 在 PR 描述中加 `Refs: rebuild.md#P{x}.{y}` |
| 推测 / 编造文件路径、函数名、任务 ID | 引用 `rebuild.md` §11 附录 B 的"文件路径速查" |
| 跨多个 task ID 同时改代码 | 一次只动一个 task ID |
| 把 `autopwn.py` 的功能直接"复述"在新代码里而不抽到 `core/` / `recon/` 等层 | 严格遵守 `refactor.md` §3 的分层依赖方向 |
| 删除 `rebuild.md` §10 的阻塞记录 | 修改 `rebuild.md` §10 时保留历史 |

> **关键自检**：每次输出代码前，AI Agent 必须在内部回答"这个改动对应 `rebuild.md` §4 哪一行？对应 `refactor.md` 哪一节？"，回答不出就停手。

---

## 6. 文档引用速查

| 你想做什么 | 查 |
|---|---|
| 理解整体架构 | `refactor.md` §1–§3 |
| 找当前可认领任务 | `rebuild.md` §4（找 ⏳） |
| 看具体任务步骤 | `rebuild.md` §6 |
| 了解 Review 流程 | `rebuild.md` §7 + 本文件 §3 |
| 报告 / 解决阻塞 | `rebuild.md` §10 + 本文件 §4 |
| 治理规则变更 | 本文件，需 Owner 签字 |
| 旧→新文件路径 | `rebuild.md` §11 附录 B |
| 决策树优先级 | `rebuild.md` §11 附录 A |
| `_legacy.py` / `_compat.py` 是什么 | `refactor.md §13`（架构 WHY）+ `rebuild.md §3.1`（行数追踪表）|

---

## 7. 治理变更

本文件的修改需要：

1. **Owner 起草**变更提案
2. 在 PR 描述中写明 **"治理变更"** + 原因
3. **至少 1 位**其他维护者 Review
4. 合并后**立即通知**所有 Owner（issue / 群通知）
5. 重要变更应回填到 `refactor.md` 的"后续扩展点"或 `rebuild.md` 的 §3 里程碑

> 治理变更记录保留在本文件 §8"变更日志"，不允许只写在 PR 描述里。

---

## 8. 变更日志

| 日期 | 版本 | 变更 | 起草 | Review |
|---|---|---|---|---|
| 2026-06-06 | 1.0 | 初版：4 条铁律 + L1/L2/L3 违规分级 + 紧急通道 + AI Agent 条款 + 签字栏 | @Minzhi_Zhou | （待 Reviewer 签字） |
| 2026-06-06 | 1.1 | **首次实战**：临时需求 #1（项目改名 pwnpasi→autopwn）按铁律 2 跑通——先更新 refactor.md §3.3 + rebuild.md §4.1/§6.1/§8/§10 → Owner 拍板（4 项决策）→ 实施 → 三关验证。验证 P0.0/P0.6 ✅。 | @Minzhi_Zhou | — |
| 2026-06-07 | 1.2 | **临时需求 #2+#3 落地**：B-002 验证方法论规范化——加 §2.6（串行 + logs/ + 7 关键节点 debug + 2-log 对比）。P0.7（验证基础设施）+ P0.8（v3.1 vs v4.0 严格对比 96% 一致 PASS）按 §2.6 跑通。B-002 Resolved 2026-06-07。 | @Minzhi_Zhou | — |
| 2026-06-07 | 1.3 | **临时需求 #4 + Owner rename**：B-001 团队改名 B-002 已 Resolved 后，**临时需求 #4**（runner 工具集扩展）按铁律 2 跑通——4 个子任务 P1.3a-d 加 14 个工具 + 2 个 qemu Popen 接口；同时 **Owner 名字从 @Ba1_Ma0 改为 @Minzhi_Zhou**——本文件签字栏 / changelog 三行 / rebuild.md §4.2 16 行 Owner 列 / tools/verify_v31_v40.py header / logs/comparison/summary.md 共 ~50 处全替换。**保留**（非 Owner）：refactor.md:265 + README.md:185 + LICENSE:3 + rebuild.md:286/294/408 中 pwnpasi 原作者 @Ba1_Ma0 引用（MIT 历史致谢，不可改）；git 历史中 9+ 个 commit 的 author name **不可改**（git 不可篡改原则）。 | @Minzhi_Zhou | — |

---

> **最后一条**：
> 文档先行不是繁文缛节，是为了**让团队（包括未来的你和未来的 AI）能在任何时间点快速进入状态**。一次不遵守的代价是后续十次混乱。
>
> **签字栏**（首次发布由 Owner 签字）：
> - 项目 Owner：@Minzhi_Zhou（2026-06-07 由 @Ba1_Ma0 改名）
> - 首次发布：2026-06-06
