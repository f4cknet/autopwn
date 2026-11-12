#!/usr/bin/env bash
# 全量评测（结果写 results/，控制台打印汇总）
#   用法: bash docker/bench_all.sh [max_attempts]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
bash docker/solve.sh bench --max-attempts "${1:-60}"
