# AutoPwn 重构计划（refactor.md）

> 角色：系统架构师
> 目标读者：项目维护者 / 后续贡献者
> 范围：仅 `autopwn.py`（3720 行单文件）的拆分与架构重整，不引入新的攻击能力，不改变对外 CLI 行为
> 版本基线：`autopwn.py` v3.1

---

## 1. 现状盘点与架构气味

### 1.1 量化数据
| 指标 | 数值 | 说明 |
|---|---|---|
| 文件总行数 | **3720** | 单文件 |
| 顶层 `def` / `class` | **79** | 全部平铺 |
| `globals().` 使用次数 | **22** | 用作"全局动态标志位"传递函数可用性 |
| `sys.exit(0)` | **43** | 全集中在 `main()` 决策树，深度耦合 |
| `os.system` 落盘 | **15** | `ropper.txt` / `Objdump_Scan.txt` / `libc_path.txt` / `Information_Collection.txt` 污染当前目录 |
| 全局可变状态 | `exploit_info` 字典 + 动态注入的 `system`/`puts`/`write`/`backdoor`/`callsystem`/`eax`/`ebx`/`ecx`/`edx` | 没有任何显式接口 |

### 1.2 功能分层（按代码区段）
| 行号区间 | 层 | 关键函数 |
|---|---|---|
| 1–170 | 控制台 / UI | `Colors`, `print_banner`, `print_info/success/...`, `print_*_table`, `cleanup_core_files` |
| 170–440 | 报告生成 | `update_exploit_info`, `generate_exploitation_code`, `generate_docx_report`, `handle_exploitation_success` |
| 441–505 | 文件 / 进程工具 | `set_permission`, `add_current_directory_prefix`, `detect_libc`, `ldd_libc` |
| 505–720 | 二进制信息收集 | `Information_Collection`, `collect_binary_info`, `display_binary_info`, `find_large_bss_symbols`, `scan_plt_functions`, `set_function_flags` |
| 723–855 | ROP 解析 | `find_rop_gadgets_x64`, `find_rop_gadgets_x32` |
| 858–1050 | 漏洞检测 | `test_stack_overflow`, `analyze_vulnerable_functions`, `vuln_func_name`, `asm_stack_overflow`, `check_binsh_string`, `check_binsh` |
| 1054–1170 | 格式化字符串检测 | `detect_format_string_vulnerability`, `find_ftmstr_bss_symbols`, `find_offset` |
| 1168–1580 | 格式化字符串利用 | `system_fmtstr[_remote]`, `fmtstr_print_strings[_remote]` |
| 1582–1746 | Canary 处理 | `leakage_canary_value`, `canary_fuzz` |
| 1746–1815 | PIE + backdoor | `pie_backdoor_exploit[_remote]` |
| 1816–3315 | **核心利用函数 30+ 个** | `ret2_system_*` / `ret2libc_put_*` / `ret2libc_write_*` / `execve_syscall*` / `rwx_shellcode_*`，各 4 个变体（32/64 × 本地/远端），其中 14 个是 Canary 变体 |
| 3316–3720 | CLI 编排 | `main()` —— 5 层 if 嵌套的大决策树 |

### 1.3 核心架构气味（按严重度排序）
1. **决策树式的 `main()`**：400+ 行嵌套 if，每条分支都调一个具体函数 + `sys.exit(0)`，没有策略可插拔点。每加一种利用都要改 `main()`。
2. **`globals().get('system', 0)` 滥用**：`set_function_flags` 把 `system`、`puts`、`write` 等标志位直接注入模块全局；后续 22 处通过 `globals().get(...)` 读取。看上去"省事"，实际是隐式数据流，IDE 跳转不到、单元测试无法替换。
3. **超长参数列表**：典型函数形如 `ret2libc_write_x64(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, libc_path)`（9 个位置参数）。同一组参数在 30+ 函数间复制粘贴。
4. **重复的利用函数**：30+ 函数中，30 行里有 20 行在做同一件事（开 IO、计算地址、构造 padding + ROP、调用 `handle_exploitation_success`、`io.interactive`）。**真正差异化的 payload 构造只有 5–10 行**。Canary 变体进一步把这 5–10 行又复制了 14 遍。
5. **IO 与逻辑强耦合**：`scan_plt_functions` 写文件再读回、`find_rop_gadgets_*` 同样。`print_*` 调用洒满业务函数，无法在测试中静默。
6. **临时文件污染 cwd**：`ropper.txt`、`libc_path.txt`、`Objdump_Scan.txt`、`Information_Collection.txt` 全留在工作目录，没有清理。
7. **报告 / 代码生成在主线流程中串行同步执行**：成功利用后立刻生成 docx，无法关闭也无法替换。
8. **没有包结构**：`setup.py` 里写的是 `packages=find_packages()`，但根本没有 `__init__.py`，所有依赖都靠 `scripts=['autopwn.py']` 维持。这导致 `python -m autopwn`、IDE 静态分析、跨平台 wheel 都不可用。
9. **没有测试**：72 个函数中无一是纯函数，全部副作用（开进程、读文件、I/O）。后续任何人改一行都要全量跑二进制。

### 1.4 你提的 `exp/` 拆分思路的评判
你的方向是对的，但**只把 exploit 函数搬到 `exp/` 不够**，原因：
- 决策树 `main()` 仍会跨模块调用 30+ 顶层函数，新增一种利用要改 `main()` 两次。
- 共享的"上下文"（gadgets、padding、canary、libc 路径、模式）若不抽出来，跨包传递只能继续走"超长参数列表"或 `globals()`。
- 报告生成、UI、IO 工具若不分层，`exp/` 内的函数会反向依赖一堆本应单向流动的层。

下面给出一套**先分层、再策略化、最后收敛 main()** 的方案。

---

## 2. 设计目标

| 目标 | 验收标准 |
|---|---|
| **G1 可维护** | 单文件不超过 500 行；任意修改引发的 git diff 主要落在一个包内 |
| **G2 可扩展** | 新增一种利用 = 在 `exp/strategies/` 放一个文件 + 一个装饰器注册；`main()` 零修改 |
| **G3 可测试** | 关键 pure 函数（payload 拼接、gadget 选择、决策矩阵）有 pytest 覆盖；可 monkeypatch IO |
| **G4 兼容** | 旧 `python autopwn.py -l ./Challenge/canary` 行为不变；`setup.py` 不破坏；CI 不破坏 |
| **G5 显式状态** | 用一个 `ExploitContext` dataclass 替换全局 dict / `globals().` 注入 |
| **G6 清洁 cwd** | 所有 ropper / objdump / ldd 输出走 `tempfile.TemporaryDirectory`；不污染用户目录 |
| **G7 边界清晰** | UI 层 / Recon 层 / Detect 层 / Primitive 层 / Strategy 层 / Orchestrator 层 各自只依赖下层 |

---

## 3. 目标架构

### 3.1 分层模型（自下而上，单向依赖）

```
┌─────────────────────────────────────────────────────────┐
│  CLI / Orchestrator  (cli.py, orchestrator.py)          │   ← 输入解析 + 决策调度
├─────────────────────────────────────────────────────────┤
│  Strategies  (exp/strategies/*.py)                      │   ← 一次完整利用流程
├─────────────────────────────────────────────────────────┤
│  Primitives  (primitives/*.py)                          │   ← 可复用的 payload 构造
├─────────────────────────────────────────────────────────┤
│  Detect  (detect/*.py)                                  │   ← 漏洞存在性判定
├─────────────────────────────────────────────────────────┤
│  Recon  (recon/*.py)                                    │   ← 二进制静态 / 动态信息收集
├─────────────────────────────────────────────────────────┤
│  Core  (core/*.py)                                      │   ← logging, IO, subprocess 包装
└─────────────────────────────────────────────────────────┘
```

依赖方向严格自上而下，**禁止反向 import**。

### 3.2 关键抽象

#### 3.2.1 `ExploitContext`（替换 `globals().` 和 `exploit_info`）
```python
# autopwn/context.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

@dataclass
class BinaryInfo:
    path: Path
    bit: int                          # 32 / 64
    stack_canary: bool
    pie: bool
    nx: bool
    relro: str                        # "Full" / "Partial" / "No"
    rwx_segments: bool
    stripped: bool

@dataclass
class LibcInfo:
    path: Optional[Path]              # None 表示走 LibcSearcher
    elf: Optional[object] = None      # pwntools.ELF
    base: int = 0

@dataclass
class RopGadgetsX64:
    pop_rdi: int
    pop_rsi: int
    ret: int
    extra_rdi: int = 0                # 是否带 pop r15 等附加
    extra_rsi: int = 0

@dataclass
class RopGadgetsX32:
    pop_eax: int
    pop_ebx: int
    pop_ecx: int
    pop_edx: int
    pop_ecx_ebx: int
    ret: int
    int_0x80: int
    has_eax_ebx_ecx_edx: bool         # 一并打包，避免 4 个 bool

@dataclass
class CanaryInfo:
    value: int
    diff: int                         # canary 末端 \x00 与 ret 之间的偏移

@dataclass
class ExploitContext:
    # 目标
    binary: BinaryInfo
    mode: str                         # "local" / "remote"
    remote: Optional[tuple[str, int]] = None

    # 利用资源
    libc: LibcInfo = field(default_factory=LibcInfo)
    gadgets_x64: Optional[RopGadgetsX64] = None
    gadgets_x32: Optional[RopGadgetsX32] = None

    # 漏洞信息
    padding: int = 0
    canary: Optional[CanaryInfo] = None
    has_system: bool = False
    has_puts: bool = False
    has_write: bool = False
    has_printf: bool = False
    has_backdoor: bool = False
    has_callsystem: bool = False
    binsh_in_binary: bool = False
    fmtstr_offset: Optional[int] = None
    fmtstr_buf: Optional[int] = None

    # 运行时
    verbose: bool = False
    report_dir: Path = Path(".")
```
所有函数签名从 `f(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ...)` 简化为 `f(ctx) → bool`。彻底消灭 9 参函数。

#### 3.2.2 `ExploitStrategy`（替换 `main()` 决策树）
```python
# autopwn/exp/base.py
from abc import ABC, abstractmethod
from autopwn.context import ExploitContext

class ExploitStrategy(ABC):
    name: str = ""
    priority: int = 0                       # 数字越大越优先

    # 元数据：用于自动匹配
    requires_canary: bool = False
    requires_remote: bool | None = None     # True/False/None(均可)
    requires_arch: int | None = None         # 32 / 64 / None
    requires = ()                            # 依赖哪些 ctx 标志: ("has_system", "binsh_in_binary")

    @abstractmethod
    def run(self, ctx: ExploitContext) -> bool:
        """返回 True 表示成功拿 shell / 完成利用"""
        ...

    def matches(self, ctx: ExploitContext) -> bool:
        if self.requires_arch is not None and ctx.binary.bit != self.requires_arch:
            return False
        if self.requires_remote is not None:
            is_remote = ctx.mode == "remote"
            if self.requires_remote != is_remote:
                return False
        if self.requires_canary and ctx.canary is None:
            return False
        return all(getattr(ctx, k) for k in self.requires)
```
所有具体策略在文件顶层用装饰器注册：
```python
# autopwn/exp/registry.py
_REGISTRY: list[ExploitStrategy] = []

def register(strategy: ExploitStrategy):
    _REGISTRY.append(strategy)
    return strategy

def candidates(ctx: ExploitContext) -> list[ExploitStrategy]:
    return sorted(
        (s for s in _REGISTRY if s.matches(ctx)),
        key=lambda s: s.priority,
        reverse=True,
    )
```
Orchestrator 只需 `for s in candidates(ctx): if s.run(ctx): break`。

#### 3.2.3 `ExploitPrimitive`（拆解 30+ 函数里的重复部分）
```python
# autopwn/primitives/base.py
class ExploitPrimitive(ABC):
    @abstractmethod
    def build_payload(self, ctx: ExploitContext) -> bytes: ...

    def open_io(self, ctx: ExploitContext):
        if ctx.mode == "remote":
            host, port = ctx.remote
            return remote(host, port)
        return process(str(ctx.binary.path))
```
子类只实现 `build_payload`；`Strategy` 在外层负责开 IO、写入 payload、循环 `io.interactive()`、调用 `report.record_success(...)`。

### 3.3 命名约定（项目品牌变更）

**v4.0 起，原开源项目 `pwnpasi` 改名为自研项目 `autopwn`**。本次重构同步品牌变更（临时需求 #1，见 `rebuild.md` §4.1 P0.0）。

| 旧 | 新 | 备注 |
|---|---|---|
| `pwnpasi`（包名 / 模块名 / CLI 命令 / 仓库名） | `autopwn` | 遵循 PEP 8 小写 + 命令行惯例 |
| `PwnPasi`（品牌显示 / Banner） | `AutoPwn` | PascalCase 显示名 |
| `pwnpasi.py`（根脚本） | `autopwn.py` | `git mv` 保留历史 |
| `pwnpasi/`（包目录） | `autopwn/` | |
| `pwnpasi 3.1` / `pwnpasi 3.0.0`（版本） | `autopwn 4.0.dev0` | 重构 + 改名，首版 v4.0 |
| 入口 `pwnpasi.cli:main` | `autopwn.cli:main` | |
| 控制台命令 `pwnpasi` | `autopwn` | `pip install .` 后 `autopwn` 可用 |
| GitHub repo `heimao-box/pwnpasi` | `<your-org>/autopwn` | **待 Owner 拍板**（见 §8 R12） |

**不变项**（保留原项目属性）：
- 协议：MIT（沿用原 `LICENSE` 文件，不改）
- `Challenge/` 下 4 个二进制：不改（与项目名无关）
- 外部依赖（`pwntools` / `LibcSearcher` / `ropper` / `python-docx`）：不改
- `elftools` / 等工具：不变

**作者归属决策**：✅ Owner 拍板 2026-06-06，**采用方案 B**
- 团队署名：`qzdx_soc`（`衢州电信安全运营中心`）
- 仓库归属：`https://github.com/f4cknet/autopwn`
- 不再保留 `@Ba1_Ma0` 作为代码作者；其原项目以 MIT 协议开源，attribution 写在 README 历史致谢段
- 决策记录见 `rebuild.md` §10 B-001（已 ✅ Resolved）

**回归保证**：v3.1 的 `Challenge/` 4 个二进制跑出的行为（strategy 名 / 关键地址 / shell 行为），在 v4.0 必须**完全一致**。P0.5 实施时要做一次完整 diff。

**实施位置**：所有文件层面的实际改名集中在 `rebuild.md` §6.1 P0.0 任务中；本节只描述**目标命名**与**决策点**。

---

## 4. 目录结构

```
autopwn/
├── pyproject.toml                 # 新增：现代打包（PEP 621）
├── README.md
├── LICENSE
├── autopwn.py                     # 兼容 shim：仅转发到 cli.main()
├── refactor.md                    # 本文档
│
├── autopwn/                       # 真正的包
│   ├── __init__.py                # VERSION, __all__
│   ├── __main__.py                # python -m autopwn
│   ├── cli.py                     # argparse + 入口
│   ├── context.py                 # ExploitContext + 子 dataclass
│   ├── orchestrator.py            # recon → detect → select → execute
│   │
│   ├── core/                      # 基础设施
│   │   ├── __init__.py
│   │   ├── logging.py             # Colors, print_*, banner
│   │   ├── fs.py                  # set_permission, add_prefix, tmpdir ctxmgr
│   │   └── runner.py              # checksec/ropper/objdump/ldd 的 subprocess 包装
│   │
│   ├── recon/                     # 二进制信息收集
│   │   ├── __init__.py
│   │   ├── checksec.py            # collect_binary_info, display_binary_info
│   │   ├── libc.py                # detect_libc, ldd_libc
│   │   ├── plt.py                 # scan_plt_functions
│   │   ├── rop.py                 # find_rop_gadgets_x64/x32
│   │   ├── bss.py                 # find_large_bss_symbols, find_ftmstr_bss_symbols
│   │   └── asm.py                 # vuln_func_name, asm_stack_overflow
│   │
│   ├── detect/                    # 漏洞检测
│   │   ├── __init__.py
│   │   ├── overflow.py            # test_stack_overflow, analyze_vulnerable_functions
│   │   ├── fmtstr.py              # detect_format_string_vulnerability, find_offset
│   │   ├── canary.py              # leakage_canary_value, canary_fuzz
│   │   └── binsh.py               # check_binsh_string, check_binsh
│   │
│   ├── primitives/                # payload 构造原语（纯函数优先）
│   │   ├── __init__.py
│   │   ├── base.py                # ExploitPrimitive, ExploitResult
│   │   ├── ret2system.py          # build_ret2system_x32/x64
│   │   ├── ret2libc_put.py
│   │   ├── ret2libc_write.py
│   │   ├── execve_syscall.py
│   │   ├── shellcode.py
│   │   ├── fmtstr.py
│   │   └── pie_backdoor.py
│   │
│   ├── exp/                       # 你建议的目录：完整利用策略
│   │   ├── __init__.py
│   │   ├── base.py                # ExploitStrategy, ExploitResult
│   │   ├── registry.py            # @register, candidates()
│   │   └── strategies/
│   │       ├── __init__.py        # 显式 import 所有策略以触发注册
│   │       ├── ret2system_x32.py
│   │       ├── ret2system_x64.py
│   │       ├── ret2libc_put_x32.py
│   │       ├── ret2libc_put_x64.py
│   │       ├── ret2libc_write_x32.py
│   │       ├── ret2libc_write_x64.py
│   │       ├── rwx_shellcode_x32.py
│   │       ├── rwx_shellcode_x64.py
│   │       ├── execve_syscall.py
│   │       ├── fmtstr.py
│   │       ├── pie_backdoor.py
│   │       ├── canary_ret2system_x32.py
│   │       ├── canary_ret2system_x64.py
│   │       ├── canary_ret2libc_put_x32.py
│   │       ├── canary_ret2libc_put_x64.py
│   │       ├── canary_ret2libc_write_x32.py
│   │       ├── canary_ret2libc_write_x64.py
│   │       └── canary_execve_syscall.py
│   │
│   └── report/                    # 报告 / 代码生成
│       ├── __init__.py
│       ├── model.py               # ExploitInfo / ExploitReport dataclass
│       ├── docx.py                # generate_docx_report
│       └── code.py                # generate_exploitation_code
│
└── tests/                         # 新增
    ├── conftest.py                # 复用 Challenge/ 下的四个二进制
    ├── unit/
    │   ├── test_primitives_ret2system.py
    │   ├── test_primitives_ret2libc.py
    │   ├── test_registry.py
    │   ├── test_recon_checksec.py
    │   └── test_recon_plt.py
    └── integration/
        └── test_challenge_canary.py    # 端到端跑 Challenge/canary
```

---

## 5. 拆分映射表

> 数字为 `autopwn.py` 中的起始行号；命名沿用旧名以便 review 时对照。

| 旧函数 | 新位置 | 备注 |
|---|---|---|
| `Colors` / `print_banner` / `print_*` | `core/logging.py` | 保持 API 兼容 |
| `cleanup_core_files` | `core/fs.py` | 整合进 `core` 启动钩子 |
| `update_exploit_info` / `handle_exploitation_success` | `report/model.py` | 改用 `ExploitContext` 字段赋值 |
| `generate_exploitation_code` | `report/code.py` | 改读 `ExploitContext` 而非全局 dict |
| `generate_docx_report` | `report/docx.py` | 不变 |
| `set_permission` / `add_current_directory_prefix` | `core/fs.py` | 工具函数 |
| `detect_libc` / `ldd_libc` | `recon/libc.py` | 合并为一个 `detect_libc(ctx, program)` |
| `Information_Collection` / `collect_binary_info` / `display_binary_info` | `recon/checksec.py` | 改为 `collect(ctx) → BinaryInfo` |
| `find_large_bss_symbols` / `find_ftmstr_bss_symbols` | `recon/bss.py` | 返回 `(found, addr, name)` |
| `scan_plt_functions` / `set_function_flags` | `recon/plt.py` | `scan(ctx) → dict[str, int]`，写入 ctx 标志 |
| `find_rop_gadgets_x64` / `find_rop_gadgets_x32` | `recon/rop.py` | 返回 `RopGadgetsX64/X32` |
| `vuln_func_name` / `asm_stack_overflow` | `recon/asm.py` | 静态分析 |
| `test_stack_overflow` / `analyze_vulnerable_functions` | `detect/overflow.py` | 写入 `ctx.padding` |
| `check_binsh_string` / `check_binsh` | `detect/binsh.py` | 写入 `ctx.binsh_in_binary` |
| `detect_format_string_vulnerability` / `find_offset` | `detect/fmtstr.py` | 写入 `ctx.fmtstr_offset` |
| `leakage_canary_value` / `canary_fuzz` | `detect/canary.py` | 写入 `ctx.canary` |
| `system_fmtstr` / `system_fmtstr_remote` | `exp/strategies/fmtstr.py` | 单一策略，内部选 local/remote |
| `fmtstr_print_strings` / `fmtstr_print_strings_remote` | `exp/strategies/fmtstr.py` | 同一策略的"只 leak"分支 |
| `pie_backdoor_exploit` / `pie_backdoor_exploit_remote` | `exp/strategies/pie_backdoor.py` | 同上 |
| `ret2libc_write_x32` / `_x64` / `_x32_remote` / `_x64_remote` | `exp/strategies/ret2libc_write_x32.py` + `_x64.py` | 拆分后由 `requires_arch` / `requires_remote` 区分 |
| `ret2libc_put_x32` / `_x64` / `_x32_remote` / `_x64_remote` | `exp/strategies/ret2libc_put_x32.py` + `_x64.py` | 同上 |
| `ret2_system_x32` / `_x64` / `_x32_remote` / `_x64_remote` | `exp/strategies/ret2system_x32.py` + `_x64.py` | 同上 |
| `rwx_shellcode_x32` / `_x64` / `_x32_remote` / `_x64_remote` | `exp/strategies/rwx_shellcode_x32.py` + `_x64.py` | 同上 |
| `execve_syscall` / `_remote` | `exp/strategies/execve_syscall.py` | 单文件（仅 32 位适用） |
| 全部 Canary 变体（14 个） | `exp/strategies/canary_*.py` | 共用 base strategy + 装饰器覆盖 `requires_canary=True` |
| `main()` | `cli.py` + `orchestrator.py` | 决策树改写为 ~30 行的 `select → run` 循环 |

**结果**：30+ 个具体利用函数收敛为 12 个策略文件 + 7 个 primitive 文件；`cli.py` + `orchestrator.py` 总计预计 < 250 行。

---

## 6. 编排层：从 400 行 if 树到 30 行调度

替换 `main()` 决策树的 `orchestrator.py` 草案：

```python
# autopwn/orchestrator.py
from autopwn.context import ExploitContext
from autopwn import exp  # 触发策略注册
from autopwn.exp.registry import candidates
from autopwn.report.model import record_success
from autopwn.recon import run_recon_phase
from autopwn.detect import run_detect_phase

def run(ctx: ExploitContext) -> int:
    # Phase 1: 收集
    run_recon_phase(ctx)
    # Phase 2: 探测
    run_detect_phase(ctx)
    # Phase 3: 选策略 + 执行
    for strat in candidates(ctx):
        ctx.log(f"trying strategy: {Colors.CYAN}{strat.name}{Colors.END}")
        try:
            if strat.run(ctx):
                record_success(ctx, strat)
                return 0
        except Exception as e:
            ctx.log(f"strategy {strat.name} failed: {e}", level="warning")
            continue
    return 1
```
`run_recon_phase` / `run_detect_phase` 内部按需调用各 recon/detect 模块。**新增利用 = 写一个 strategy 文件 + 在 `exp/strategies/__init__.py` 加一行 import，零修改 orchestrator**。

---

## 7. 拆分阶段（按风险递增、可独立合并）

| 阶段 | 内容 | 风险 | 验收 |
|---|---|---|---|
| **P0 准备** | 新建包骨架 + `pyproject.toml`；`autopwn.py` 改为从 `autopwn.cli` 转发 | 极低 | `python autopwn.py -l Challenge/canary` 与重构前行为一致 |
| **P1 基础设施** | 抽 `core/logging.py`、`core/fs.py`、`core/runner.py`；引入 `tempfile.TemporaryDirectory` 清理 ropper.txt 等 | 低 | 跑完 `Challenge/canary` 后 `cwd` 干净 |
| **P2 模型层** | 引入 `ExploitContext` + 子 dataclass；旧函数签名逐步迁移为 `f(ctx)` | 中 | 旧函数依然能跑（可保留 wrapper） |
| **P3 报告层** | 抽 `report/`；`handle_exploitation_success` 改为订阅者模式（docx / code 生成可独立关闭） | 低 | `--no-report` 参数生效 |
| **P4 Recon 层** | 抽 `recon/*.py`；所有 `globals()[func] = available` 改为 `ctx.has_system = ...` | 中 | 所有 `globals().get('system', 0)` 消失 |
| **P5 Detect 层** | 抽 `detect/*.py` | 中 | 漏洞检测可独立单元测试 |
| **P6 Primitives 层** | 抽 `primitives/*.py`；把 30+ 函数中"构造 payload"那 5–10 行变成 pure 函数 | 中 | 新增 pytest 覆盖 ≥80% primitive |
| **P7 Strategies 层** | 抽 `exp/strategies/*.py`；引入 `@register` 装饰器；30+ 函数收敛为 12 个策略文件 | **高** | 每个 Challenge/ 二进制至少 1 个 strategy 命中 |
| **P8 Orchestrator + 新 `main()`** | `main()` 决策树改写为 `candidates(ctx) → run`；43 处 `sys.exit(0)` 收敛 | **高** | CLI 行为完全一致；日志格式可读性不退化 |
| **P9 测试 + CI** | 补 unit test；用 `Challenge/` 4 个二进制做 integration test；加 GitHub Actions | 中 | CI 绿 |
| **P10 打包升级** | 落 `pyproject.toml`；`setup.py` 改为向后兼容的最小文件；支持 `pip install .` / `python -m autopwn` | 低 | `pip install .` 后 `autopwn` 命令可用 |

**合并策略**：每完成一个阶段开一个 PR，旧 `autopwn.py` 保留为转发 shim 直到 P8 完成；P8 完成后删除 shim。

---

## 4. 临时需求 #4：工具集扩展

> 状态：🔄 进行中（Owner 决策 2026-06-07）
> 范围：仅 `autopwn/core/runner.py`
> 任务 ID：`P1.3a` / `P1.3b` / `P1.3c` / `P1.3d`
> Refs：`rebuild.md#P1.3a` ... `P1.3d`

### 4.1 为什么需要

P1.3 落地后，`autopwn/core/runner.py` 只包装了 4 个工具（`checksec`/`ropper`/`objdump`/`ldd`），刚好覆盖 P4 recon 阶段的最小需求。**但 P4.2（libc）/ P5.x（detect 各种漏洞）/ P6（primitives）/ P7（strategies）会需要更多工具**（`file` / `readelf` / `strings` / `nm` / `ROPgadget` / `cyclic` / `one_gadget` / `seccomp-tools` / `strace` / `ltrace` / `gdb` / `qemu-system-x86`）。

**等到 P4-P7 当下要用了再补 wrapper**，会出现两类问题：
1. **接口分裂**：每个调用现场自己拼 `subprocess.run(...)` 参数，签名不一致（路径传 str 还是 Path、是否传 `capture_output`、是否用 `shell=True`）
2. **收口不彻底**：违反 §1 铁律 1 "实施以 `rebuild.md` 为准" —— 调用现场绕开 `core/runner` 直接 subprocess，不在治理范围内

**提前在 P1.3 阶段把工具集收口**，让 P4-P7 阶段直接 `from autopwn.core.runner import run_xxx`，不再各自写 subprocess 拼装代码。

### 4.2 架构约束（沿用 §3.1 + §3.2）

- **依赖方向不变**：`core/runner.py` 不向上 import（不引 `recon` / `detect` / `exp` / `primitives`）
- **接口最小化**：每个 `run_X(program, **kwargs) -> str` / `-> Path` / `-> subprocess.Popen`（视工具特性而定）
- **错误处理**：
  - 必须成功的工具（`checksec`）→ 抛 `ToolError`
  - 可降级的工具（`strings` / `nm` / `ROPgadget` 等即使失败也返回空字符串/空 Path）
  - 交互式工具（`gdb` / `qemu-system-x86`）→ 不抛异常，由调用者管生命周期
- **stdin/stdout/stderr 策略**：
  - 默认 `subprocess.run(capture_output=True, text=True, check=False)`
  - 大输出（`objdump` / `strings` / `nm`）→ `text=True` 直接返回字符串（与 P1.3 一致）
  - 流式输出（`strace` / `ltrace`）→ 暂时不实现流式，仅一次性 `capture_output`
  - 交互式（`gdb` / `qemu`）→ `subprocess.Popen`，不 wait

### 4.3 任务拆分

| ID | 范围 | 工时 | 工具 | 关键决策点 |
|----|------|------|------|------------|
| **P1.3a** | 静态 binutils 套件 | 2h | `file` / `readelf` / `strings` / `nm` | 这 4 个都有标准 binutils 输出格式；返回 `str`；失败 → 空串 |
| **P1.3b** | ROP / 模式 套件 | 2h | `ROPgadget` / `cyclic` / `one_gadget` | ROPgadget 与 ropper 接口相似但输出格式不同；cyclic 用于 PADDING 校准；one_gadget 用于 libc-based 快速 RCE |
| **P1.3c** | 动态 / sandbox 套件 | 3h | `strace` / `ltrace` / `seccomp-tools` / `gdb` | strace/ltrace 一次性 capture；seccomp-tools 返回 JSON；gdb 用 `-batch -ex` 跑脚本 |
| **P1.3d** | 跨架构模拟 | 2h | `qemu-system-x86`（+`qemu-system-i386` / `qemu-system-aarch64`）| 返回 Popen 句柄；**不**用 capture_output（qemu 是常驻进程） |

合计 9h。每个子任务 1 PR，遵守 §2.1 400 行 diff 上限。

### 4.4 与 P1.3 的关系

- P1.3 是 "**做地基**"：4 个最小工具 + `ToolError` + 接口范式
- P1.3a/b/c/d 是 "**扩工具集**"：沿用 P1.3 的接口范式，加 11+ 工具
- 不破坏 P1.3 既有 API：`run_checksec` / `run_ropper` / `run_objdump_disasm` / `run_ldd` 签名不变
- 不替换 `_legacy.py` 调用点：调用点替换是 P1.5 任务；P1.3a/b/c/d 只提供工具

### 4.5 风险与缓解

详见 `rebuild.md#R14`。要点：
- **接口一致性**：每个 `run_X` 签名遵守 §4.2 范式；Reviewer 必查
- **输出解析鲁棒性**：每个 `run_X` 输出格式不固定（特别是 `one_gadget` / `seccomp-tools`），调用方需先 sanity check
- **依赖工具版本**：工具不同版本输出格式略变；P9.1 单元测试用 docker 固定版本（暂未实现，先用本机版本）

---

## 8. 兼容性与迁移策略

### 8.1 CLI 兼容
- 旧命令：`python autopwn.py -l ./Challenge/canary -f 112 -v`
- 重构后：`python -m autopwn -l ./Challenge/canary -f 112 -v` 或保留 `autopwn.py` shim
- 参数集合保持不变（`-l / -ip / -p / -libc / -f / -v`）；如需新增，用 `--` 前缀避免冲突

### 8.2 `setup.py` 兼容
- 短期：`setup.py` 改写为：
  ```python
  from setuptools import setup
  setup()  # 全部配置在 pyproject.toml
  ```
- 中期：保留 `console_scripts`：`autopwn=autopwn.cli:main`

### 8.3 状态机兼容
- P2 阶段：保留 `exploit_info` 全局 dict（写一份 setter 到 `ExploitContext` 字段的同步桥），逐步替换
- P4 阶段：彻底删除 `exploit_info` 与 `globals().` 注入

### 8.4 报告输出
- 默认输出位置不变（cwd 根目录）
- 引入 `ctx.report_dir`，支持 `--report-dir <path>`，渐进迁移

---

## 9. 测试策略

### 9.1 单元测试（无副作用）
- 所有 `primitives/*.py` 的 `build_payload` 应当接受 fake address 输入返回纯 bytes
- `exp/registry.candidates(ctx)` 的过滤逻辑（`requires` / `requires_arch` / `requires_canary` / `requires_remote`）可被 monkeypatch 测
- `report/code.py` 的代码生成可对比 snapshot

### 9.2 集成测试（跑 `Challenge/` 下的真实二进制）
- `tests/integration/test_challenge_canary.py` 等
- 用 pytest fixture 启动 binary（timeout 5s），喂 payload，断言 `io.recvline()` 含 `'$ '` 或 `'/bin/sh'` 等标志
- CI 中若二进制缺失则 `pytest.mark.skip`

### 9.3 不变量测试
- 对 `Challenge/level3_x64`、`Challenge/canary`、`Challenge/fmtstr1`、`Challenge/pie` 各跑一次完整利用，断言 `run(ctx) == 0`

---

## 10. 风险与权衡

| 风险 | 缓解 |
|---|---|
| **重构引入回归** | 每阶段保留 `autopwn.py` shim 跑同一批 `Challenge/`；P8 前任何阶段都可回滚 |
| **`globals().` 删除破坏 `set_function_flags` 的隐式调用链** | P4 阶段先在 shim 中保留 `globals()` 同步桥，跑通后再删 |
| **30+ 函数签名迁移工作量大** | 一次性迁移到 `ctx` 的成本是 N×9 参 → N×1 参；可写一个 `legacy_to_ctx(args, kwargs)` 自动 wrapper 缓解 |
| **决策树优先级不明确** | 老代码靠 if 顺序隐式表达优先级，重构后用 `priority: int` 显式；P7 时同步梳理一份"原 if 顺序 → priority 值"对照表 |
| **Canary 变体与基类行为漂移** | 14 个 canary 变体应共享一个基类（`CanaryStrategy(ExploitStrategy)`），仅 `requires_canary=True` + 拼接 canary 字节；不要 fork 14 份 |
| **docx 报告依赖 python-docx** | `report/docx.py` 保留为可选：try/except `ImportError`，缺失时降级为 markdown |
| **临时文件清理后某些工具路径依赖** | ropper / objdump 默认输出到 stdout，全部走 `subprocess.run(capture_output=True)` 捕获，不再落盘 |

---

## 11. 后续扩展点（不在本次范围）

1. **配置文件**：`.autopwnrc` 控制默认 libc 路径、gadget 搜索深度、报告格式
2. **插件机制**：`exp/strategies/` 之外允许通过 `entry_points` 加载第三方策略包
3. **并行探测**：`recon` 阶段的多条命令（checksec、ldd、objdump）可改 `concurrent.futures` 并发
4. **Web UI / RPC**：把 `orchestrator.run` 暴露为 HTTP/JSON，便于远程触发
5. **类型化异常**：把 `except Exception as e` 收敛为 `ReconError` / `DetectionError` / `StrategyError`
6. **LLM 辅助决策**：把 `candidates(ctx)` 的优先级交给模型微调（与本仓库 `mmx-cli` 技能联动）

---

## 12. 立即可执行的下一步（建议你授权的最小起步）

如果你认可上面的设计，建议从 **P0 + P1 + P2** 起步，作为第一个 PR：

1. 新建 `autopwn/` 包骨架与 `pyproject.toml`
2. 把 `Colors` / `print_*` / `set_permission` / `add_current_directory_prefix` 抽到 `core/`
3. 把 `exploit_info` 与 `handle_exploitation_success` 抽到 `report/model.py` + `ExploitContext`
4. `autopwn.py` 改为：
   ```python
   from autopwn.cli import main
   if __name__ == "__main__":
       main()
   ```
5. 跑一次 `python autopwn.py -l Challenge/canary -v`，确认行为一致

预计该 PR < 400 行 diff、零行为变更、奠定后续所有阶段的地基。

---

> 维护约定（建议同步进 `AGENTS.md`）：
> - `core/` / `recon/` / `detect/` 不允许 `import` 上层
> - `exp/strategies/` 的每个文件 < 150 行；超过即拆
> - `orchestrator.py` 不允许出现具体函数名（`ret2_system_x32` 之类），只允许 `ExploitStrategy` 类引用
> - 任何 PR 必须跑通 `pytest tests/integration/` 再合
