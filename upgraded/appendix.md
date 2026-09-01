# appendix.md — upgraded 索引附录

本文件承接 `upgraded.md` 中不适合常驻主索引的速查内容：文件路径、工具脚本、模板与决策表。

## 1. 文件路径速查（v4.0 完整）

```text
upgraded/
├── vX.Y.Z.md            # 单次迭代的需求详情 / 风险 / 验收记录

autopwn/
├── __init__.py          # __version__ = "4.0.dev0"
├── __main__.py          # python -m autopwn 入口
├── cli.py               # argparse + dispatch orchestrator
├── context.py           # 6 个 dataclass
├── core/
│   ├── logging.py       # Colors + 12 print_* + VERBOSE
│   ├── fs.py            # set_permission + temp_workdir
│   └── runner.py        # 14 个 run_* 工具包装
├── recon/
│   ├── checksec.py      # collect() / display()
│   ├── libc.py          # detect()
│   ├── plt.py           # scan()
│   ├── rop.py           # find_x64/32()
│   ├── asm.py           # vuln_func_name / asm_stack_overflow
│   └── bss.py           # BSSSymbol / find_bss()
├── detect/
│   ├── binsh.py         # check_binsh()
│   ├── canary.py        # canary_fuzz() / leakage_canary_value()
│   ├── fmtstr.py        # detect_format_string_vulnerability()
│   └── overflow.py      # test_stack_overflow()
├── primitives/
│   ├── ret2system.py     # Ret2SystemX32 / X64
│   ├── ret2libc_put.py   # Ret2LibcPutX32 / X64
│   ├── ret2libc_write.py # Ret2LibcWriteX32 / X64
│   ├── execve_syscall.py # ExecveSyscall x32
│   ├── fmtstr.py         # FmtStr
│   ├── pie_backdoor.py   # PieBackdoor
│   └── shellcode.py      # RWX shellcode 通用
├── exp/
│   ├── base.py          # ExploitStrategy 抽象类
│   ├── registry.py      # @register / candidates(ctx)
│   └── strategies/      # 17 文件 40 strategies
├── orchestrator/        # 三阶段调度（拆子包）
│   ├── __init__.py      # run() 入口 + re-exports
│   ├── recon.py         # run_recon_phase
│   ├── detect.py        # run_detect_phase
│   └── strategy.py      # run_strategy_phase
├── report/
│   ├── model.py         # ExploitInfo
│   ├── docx.py          # generate_docx()
│   ├── code.py          # generate_code()
│   └── __init__.py      # record_success()
└── pwntools.md          # pwntools 笔记

tests/
├── conftest.py          # 共享 fixture (ctx_for, CHALLENGE_DIR)
├── unit/                # 626 tests（无 IO 副作用）
└── integration/         # 17+1 tests（真跑 Challenge 二进制）

scripts/
├── run_verify.sh        # 串行 5-binary 验证 runner
└── baseline_lock.sh     # sha256sum baseline 锁

tools/
├── check_recon_coverage.py      # recon 95% public API 覆盖 gate
├── check_public_api_coverage.py # primitive 80% public API 覆盖 gate
└── verify_v31_v40.py            # v3.1 vs v4.0 历史审计工具（仅保留）

Challenge/
├── canary               # x32 + canary
├── fmtstr1              # x32 + 格式串
├── level3_x64           # x64 + 64-bit libc
├── pie                  # x64 + PIE
└── rip                  # x64 + ret2system
```

## 2. 决策树优先级（v4.0 现状）

| Priority | Strategy | 适用 binary |
|---|---|---|
| 200 | CANARY (canary_*.py) | canary |
| 180 | PIE_BACKDOOR (pie_backdoor.py) | pie |
| 150 | RET2SYSTEM (ret2system_*.py) | fmtstr1, rip |
| 120 | RET2LIBC_PUT (ret2libc_put_*.py) | level3_x64 (fallback) |
| 110 | RET2LIBC_WRITE (ret2libc_write_*.py) | level3_x64 |
| 90 | RWX_SHELLCODE (rwx_shellcode_*.py) | future RWX binaries |
| 80 | EXECVE_SYSCALL (execve_syscall.py) | canary (x32 fallback) |
| 50 | FMTSTR (fmtstr.py) | canary (兜底) |

## 3. 工具脚本

所有验证命令都默认在 `ctf_env` 容器内执行（Python 3.12.11）。

| 工具 | 用途 | 何时用 |
|---|---|---|
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && ./.venv/bin/python -m pytest tests/unit/ -m 'not integration' -q"` | 单元测试 | 每次改代码后必跑（关 2） |
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && ./.venv/bin/python -m pytest tests/integration/ -q"` | 集成测试 | 改 orchestrator / strategy 时必跑（关 3） |
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && AUTOPWN_VERIFY_TIMEOUT=60 bash scripts/run_verify.sh <tag> canary fmtstr1 level3_x64 pie rip"` | 5-binary 串行 smoke | 改 autopwn 行为时必跑（关 4） |
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && bash scripts/baseline_lock.sh lock logs/v<X>-smoke"` | 锁 baseline log 文件 hash | 发布前 / 长期 baseline 留存时 |
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && ./.venv/bin/python tools/check_recon_coverage.py"` | recon 95% 覆盖 gate | CI 跑（关 2 增强） |
| `docker exec ctf_env /bin/bash -lc "cd /data/autopwn && ./.venv/bin/python tools/check_public_api_coverage.py"` | primitive 80% 覆盖 gate | CI 跑（关 2 增强） |
## 4. 任务 ID 模板（v4.0+）

```text
[v{X}.{Y}.{Z}] {动词} {对象}
Refs: `upgraded.md §3`, `upgraded/vX.Y.Z.md`

如：
[v4.0.0] release v4.0 GA — 切版本号 + tag + Release
[v4.1.0] add HEAP exploitation — primitives/heap.py + 3 strategies
[v4.1.1] type exceptions — ReconError/DetectionError/StrategyError
```

## 5. CHANGELOG 模板

```markdown
## [v{X}.{Y}.{Z}] - YYYY-MM-DD

### Added
- 新功能

### Changed
- 行为变化

### Fixed
- bug 修复
```
