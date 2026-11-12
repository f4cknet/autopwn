#!/usr/bin/env bash
# 在 pwn 容器里跑 autopwn 引擎。
#   用法: bash docker/solve.sh bench                 # 跑全部
#         bash docker/solve.sh bench/ch13_zip76c8    # 跑单题
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-bench}"
shift || true

MSYS_NO_PATHCONV=1 docker run --rm \
  --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "${ROOT}:/work" -w /work \
  autopwn:pwn22 \
  python3 -m autopwn.engine.cli "$TARGET" --out results "$@"
