#!/bin/bash
# AutoPwn 串行验证 runner
# 用法: scripts/run_verify.sh <version-tag> <bin1> [bin2] ...
# 例:   scripts/run_verify.sh v3.1 canary fmtstr1 level3_x64 pie rip
# 行为: 串行跑每个 binary，输出到 logs/<version-tag>/<bin>.log
set -e
VERSION_TAG=$1
if [ -z "$VERSION_TAG" ]; then
  echo "Usage: $0 <version-tag> <bin1> [bin2] ..."
  echo "Example: $0 v3.1 canary fmtstr1 level3_x64 pie rip"
  exit 1
fi
shift
if [ $# -eq 0 ]; then
  echo "Error: at least one binary required"
  exit 1
fi

# 切到项目根
cd "$(dirname "$0")/.."

# 确保 logs 目录存在
mkdir -p "logs/$VERSION_TAG"

TIMEOUT_SEC=${AUTOPWN_VERIFY_TIMEOUT:-60}

for bin in "$@"; do
  if [ ! -f "Challenge/$bin" ]; then
    echo "[SKIP] Challenge/$bin 不存在"
    continue
  fi
  echo ">>> [$VERSION_TAG] $bin (timeout=${TIMEOUT_SEC}s)"
  start=$(date +%s)
  if timeout "$TIMEOUT_SEC" python3 -m autopwn -l "Challenge/$bin" -v > "logs/$VERSION_TAG/$bin.log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  end=$(date +%s)
  size=$(stat -c%s "logs/$VERSION_TAG/$bin.log" 2>/dev/null || echo 0)
  echo "    rc=$rc, ${end}-${start}s, ${size}B → logs/$VERSION_TAG/$bin.log"
done

echo
echo "[DONE] logs saved to logs/$VERSION_TAG/"
ls -la "logs/$VERSION_TAG/" | grep -v '^total\|^d'
