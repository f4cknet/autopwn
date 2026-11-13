#!/bin/sh
# 把题目挂成一个 TCP 靶机（容器内执行）。
#
#   serve.sh <binary> <port> [flag]
#
# 环境变量：
#   NO_ASLR=1   关闭 ASLR（setarch -R），方便复现、一次命中；默认保持开启（更像真远程）
#               注意：需要容器带 --security-opt seccomp=unconfined，否则 personality() 被拦
#
# 行为刻意贴近真实平台：
#   * socat TCP-LISTEN,fork —— 每次连接 exec 一个新进程，ASLR 每次变化
#   * 题目在同目录下有 flag 文件（供 system("cat flag") 这类 win 用）
#   * stderr 一起转出去，避免 "cat: flag: No such file" 被吞掉
set -e

# Windows 风格的路径（chellenges\pwn 或 D:/.../chellenges/pwn）统一成正斜杠
BIN=$(printf '%s' "${1:-}" | tr '\\' '/')
PORT="${2:-4444}"
FLAG="${3:-CTF2{docker-local-target}}"

if [ -z "$BIN" ]; then
    echo "[error] usage: serve.sh <binary> <port> [flag]" >&2
    exit 2
fi

# 兼容 Windows 绝对路径（D:/.../chellenges/pwn）：找不到就按 basename 在 /work 里找
if [ ! -f "$BIN" ]; then
    b=$(basename "$BIN")
    cand=$(find /work -maxdepth 3 -name "$b" -type f 2>/dev/null | head -1)
    if [ -n "$cand" ]; then
        echo "[*] path fallback: $BIN -> $cand"
        BIN="$cand"
    fi
fi
if [ ! -f "$BIN" ]; then
    echo "[error] binary not found: $BIN" >&2
    exit 3
fi

DIR=/work/_target
mkdir -p "$DIR"
cp -f "$BIN" "$DIR/pwn"
chmod +x "$DIR/pwn"
printf '%s\n' "$FLAG" > "$DIR/flag"

# 每条连接 exec 一次：包一层 run.sh，顺便支持关 ASLR
if [ "$NO_ASLR" = "1" ]; then
    printf '#!/bin/sh\nexec setarch -R ./pwn\n' > "$DIR/run.sh"
    MODE="ASLR off (setarch -R)"
else
    printf '#!/bin/sh\nexec ./pwn\n' > "$DIR/run.sh"
    MODE="ASLR on"
fi
chmod +x "$DIR/run.sh"
cd "$DIR"

echo "[*] binary : $BIN -> $DIR/pwn"
echo "[*] flag   : $FLAG  ($DIR/flag)"
echo "[*] mode   : $MODE"
echo "[*] listen : 0.0.0.0:$PORT (fork per connection)"
exec socat TCP-LISTEN:"$PORT",reuseaddr,fork EXEC:./run.sh,stderr
