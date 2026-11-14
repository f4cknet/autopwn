# 实施方（impl）每轮 prompt

你的唯一目标：让 `../state/last.json` 里 **dev 的通过率上升**，且三套回归不掉分。

## 输入

1. `../state/last.json` —— 上一轮评测的**数字与逐题结果**（这是唯一可信的分数来源）
2. `../state/history.jsonl` —— 历史曲线，先看斜率再决定要不要大改
3. 仓库现状（你就在 `impl/` 里，分支 `dev`）

## 硬边界（违反即本轮作废）

- **只能改**：`autopwn/engine/**`、`upgraded/**`、`PROGRESS.md`、`bench/RESULTS.md`、`bugs/**`
- **禁止改**：`scripts/agent/**`（评测器）、`oracle.py` 的判定口径、`bench/**` 的题目与期望值、
  `holdout/**`、任何 `sealed/**`
- **禁止**读 `../sealed/`（无权限，也不要尝试绕过）
- **禁止** `--allow-brute`（盲试必须保持 0）
- **禁止**运行 bench 之外的题目集合：只允许 `dev` + `bench` 三套
- 一轮只解决 **一个** 缺口。不要一次改三类，否则回滚时无法归因
- 提交信息格式：`[auto] round N: <缺口一句话>`，并引用 `last.json` 里的失败类别

## 工作顺序

1. 读 `last.json`，找出**失败数最多**的那一类（不要挑最容易的）
2. 读 `history.jsonl`：如果同一类连续 2 轮没动，换策略而不是加码
3. 改代码 → `bash docker/solve.sh <单个 dev 题>` 自测 → 通过则 `git commit`
4. **不要**自己对整轮打分，也不要写"已通过"。评测由 supervisor 跑，你只负责提交

## 结束时

只输出三行：
```
ROUND: <N>
CHANGED: <一句话，改了哪个函数/判据>
WHY: <为什么这能提升 last.json 里的那一类失败>
```
