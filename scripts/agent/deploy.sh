#!/usr/bin/env bash
# 服务器一次性初始化：用户 / 权限 / bare origin / 冻结评测器 / 哈希快照
# 用法（root）：bash scripts/agent/deploy.sh /srv/autopwn /path/to/repo
set -euo pipefail
BASE="${1:-/srv/autopwn}"
REPO="${2:-$(cd "$(dirname "$0")/../.." && pwd)}"

echo "==> 1/6 用户"
for u in impl verify; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
done
groupadd -f agentrun
usermod -aG agentrun impl
usermod -aG agentrun verify

echo "==> 2/6 目录"
mkdir -p "$BASE"/{origin.git,impl,verify,eval,sealed,state,logs}
chown -R root:root "$BASE/eval" "$BASE/sealed"
chmod 700 "$BASE/sealed"          # sealed 只有 root 可读
chmod 755 "$BASE/eval"

echo "==> 3/6 bare origin"
if [ ! -f "$BASE/origin.git/HEAD" ]; then
  git init --bare "$BASE/origin.git"
fi
chown -R root:root "$BASE/origin.git"

echo "==> 4/6 两个 clone"
for u in impl verify; do
  d="$BASE/$u"
  if [ ! -d "$d/.git" ]; then
    sudo -u "$u" git clone "$BASE/origin.git" "$d"
    sudo -u "$u" git -C "$d" config user.name  "$u-agent"
    sudo -u "$u" git -C "$d" config user.email "$u@autopwn.local"
  fi
done

echo "==> 5/6 冻结评测器（从仓库拷到 root 只读目录）"
install -o root -g root -m 755 "$REPO/scripts/agent/run_eval.py" "$BASE/eval/run_eval.py"
cp "$REPO/scripts/agent/prompt_impl.md"   "$BASE/eval/prompt_impl.md"
cp "$REPO/scripts/agent/prompt_verify.md" "$BASE/eval/prompt_verify.md"
chmod 644 "$BASE/eval"/prompt_*.md
sha256sum "$BASE/eval/run_eval.py" > "$BASE/eval/SHA256SUMS"

echo "==> 6/6 权限校验"
set +e
sudo -u impl  test -r "$BASE/sealed" && echo "[FAIL] impl 能读 sealed" || echo "[OK] impl 读不到 sealed"
sudo -u impl  test -w "$BASE/eval/run_eval.py" && echo "[FAIL] impl 能写评测器" || echo "[OK] impl 改不了评测器"
sudo -u verify test -w "$BASE/impl"  && echo "[WARN] verify 能写 impl" || echo "[OK] verify 不改 impl"
set -e

cat <<EOF

初始化完成。下一步：
  1. 把题库放进 $BASE/impl/dev/（agent 可见，带 libc）
  2. 把终检题放进 $BASE/sealed/（agent 不可见）
  3. 在 $BASE/impl 里提交一个初始 commit 并 push 到 origin
  4. 起循环：python3 scripts/agent/supervisor.py --root $BASE/impl ...
EOF
