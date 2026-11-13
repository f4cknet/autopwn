#!/bin/bash
# AutoPwn baseline lock helper (P11.4)
# 用法: scripts/baseline_lock.sh <action> [args...]
# 例:
#   scripts/baseline_lock.sh lock logs/v3.1            # 创建 baseline.lock 含 sha256sum
#   scripts/baseline_lock.sh lock logs/v4.0-600s
#   scripts/baseline_lock.sh verify logs/v3.1          # 对照 lock 验证文件未被改
#   scripts/baseline_lock.sh list                      # 列出所有 lockfile
#
# 行为: 给 baseline logs 目录生成 .lock 文件 (sha256sum + 文件大小 + mtime)，
# 防止后续 rebuild/rerun 意外覆盖 baseline。
# 设计原则: 既然 .gitignore 排除 *.log，git tag 不能直接引用 baseline log；
# 改用 git-trackable 的 .lock 文件 + sha256sum 内容寻址作为 baseline 治理手段。
set -e
cd "$(dirname "$0")/.."

ACTION=$1
shift || { echo "Usage: $0 <lock|verify|list> ..."; exit 1; }

case "$ACTION" in
  lock)
    PATH_ARG=$1
    if [ -z "$PATH_ARG" ] || [ ! -d "$PATH_ARG" ]; then
      echo "Usage: $0 lock <baseline-dir>"; exit 1
    fi
    LOCK="${PATH_ARG}/.lock"
    {
      echo "# AutoPwn baseline lock (P11.4)"
      echo "# Created: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "# Host: $(hostname)"
      echo "# Files: $(ls "$PATH_ARG"/*.log 2>/dev/null | wc -l) .log files"
      echo "# Format: <sha256sum>  <size>B  <mtime>  <path>"
      cd "$PATH_ARG" && find . -name '*.log' -type f -printf '%T@ %p\n' | sort | \
        while read mtime path; do
          size=$(stat -c%s "$path")
          sum=$(sha256sum "$path" | cut -d' ' -f1)
          printf '%s  %sB  mtime=%s  %s\n' "$sum" "$size" "$(date -u -d @"${mtime%.*}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "$mtime")" "$path"
        done
    } > "$LOCK"
    echo "[OK] wrote $LOCK"
    echo "     $(grep -c '\.log' "$LOCK" 2>/dev/null) entries + 4 header lines"
    echo "     baseline is locked; subsequent rerun must use a NEW dir (e.g. logs/v3.1-2/)"
    ;;
  verify)
    PATH_ARG=$1
    if [ -z "$PATH_ARG" ] || [ ! -d "$PATH_ARG" ]; then
      echo "Usage: $0 verify <baseline-dir>"; exit 1
    fi
    LOCK="${PATH_ARG}/.lock"
    if [ ! -f "$LOCK" ]; then
      echo "[ERROR] no lock file at $LOCK — has this baseline been locked?"
      exit 1
    fi
    rc=0
    count=0
    while read -r line; do
      [[ "$line" == \#* || -z "$line" ]] && continue
      sum=$(echo "$line" | awk '{print $1}')
      path=$(echo "$line" | awk '{print $NF}')
      full_path="${PATH_ARG}/${path#./}"
      actual=$(sha256sum "$full_path" 2>/dev/null | cut -d' ' -f1)
      if [ "$actual" = "$sum" ]; then
        echo "[OK]  $path"
      else
        echo "[FAIL] $path (expected $sum, got $actual)"
        rc=1
      fi
      count=$((count+1))
    done < "$LOCK"
    if [ $rc -eq 0 ]; then
      echo "[OK] all $count baseline files match"
    else
      echo "[FAIL] baseline tampered — see lines above"
    fi
    exit $rc
    ;;
  list)
    find logs -name '.lock' -type f 2>/dev/null | sort
    ;;
  *)
    echo "Unknown action: $ACTION (expected: lock | verify | list)"
    exit 1
    ;;
esac
