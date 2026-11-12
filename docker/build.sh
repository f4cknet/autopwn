#!/usr/bin/env bash
# 构建 pwn 环境镜像（ubuntu 22.04 + 全量工具链）
set -e
cd "$(dirname "$0")"
docker build -t autopwn:pwn22 "$@" . 2>&1 | tail -30
echo "=== 构建完成，镜像信息 ==="
docker images autopwn:pwn22 --format '{{.Repository}}:{{.Tag}} {{.Size}}'
