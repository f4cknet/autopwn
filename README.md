<div align="center">

# 🚀 AutoPwn v4.0 (refactor in progress)

**Professional Automated Binary Exploitation Framework**

[![Version](https://img.shields.io/badge/version-4.0.dev0-blue.svg)](https://github.com/f4cknet/autopwn)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/f4cknet/autopwn)
[![Tests](https://img.shields.io/badge/tests-604%20passed-brightgreen.svg)](.github/workflows/ci.yml)


</div>

---

## 🎯 What is AutoPwn?

AutoPwn is a **cutting-edge automated binary exploitation framework** designed for CTF competitions and security research, AutoPwn transforms complex binary exploitation into an automated, streamlined process.

### ✨ Key Features

🔍 **Smart Vulnerability Detection**
- Automatic stack overflow detection with dynamic padding calculation
- Format string vulnerability identification and exploitation
- Binary protection analysis (RELRO, Stack Canary, NX, PIE)
- Assembly code analysis for vulnerable function detection
- Automatically generating reports

⚡ **Advanced Exploitation Techniques**
- **ret2system**: Direct system function calls
- **ret2libc**: ASLR bypass through libc address leaking
- **ROP Chain Construction**: Automated gadget discovery and chaining
- **Syscall Exploitation**: execve system call chains
- **Shellcode Injection**: RWX segment exploitation
- **Stack Canary Bypass**: Format string canary leaking
- **PIE Bypass**: Position Independent Executable circumvention

🏗️ **Multi-Architecture Support**
- **x86 (32-bit)**: Complete 32-bit exploitation chains
- **x86_64 (64-bit)**: Full 64-bit exploitation support
- **Auto-detection**: Intelligent architecture recognition

🌐 **Flexible Deployment**
- **Local Mode**: Direct binary file exploitation
- **Remote Mode**: Network service targeting
- **Hybrid Approach**: Seamless local-to-remote transition

---

## 🚀 Quick Start

### Installation

```bash
# Install from source (recommended for v4.0.dev0)
git clone https://github.com/f4cknet/autopwn.git
cd autopwn
pip install -e .

# After install, both entry points are available:
#   - `autopwn` (PEP 517 console_scripts)
#   - `python -m autopwn` (PEP 338)
```

The `pip install -e .` step will:
- Install Python dependencies (pwntools, LibcSearcher, ropper, python-docx, pyelftools)
- Register the `autopwn` console script (Linux/macOS PATH)
- Keep the source tree editable for development

**System dependencies** (install separately via your package manager):
- `ropper` (Python wrapper also accepted, but system ropper is faster)
- `checksec` (binary security analysis)
- `objdump` / `strings` / `ldd` (part of `binutils` on most distros)
- `gdb` + `pwndbg` / `gef` (optional, for interactive debugging)

### Basic Usage

```bash
# Analyze local binary
autopwn -l ./target_binary

# Remote exploitation
autopwn -l ./binary -ip 192.168.1.100 -p 9999

# Custom libc and padding
autopwn -l ./binary -libc ./libc-2.19.so -f 112

# Verbose mode
autopwn -l ./binary -v
```

### Report control

> **v4.1.7 change**: Reports are now always written to the
> `writeups/` subdirectory of the current working directory
> (`./writeups/{target}_wp.docx`).  The `--report-dir` flag is still
> accepted (backward-compat) but its value is **ignored** at the
> file-write step — see `upgraded.md` §3.2 v4.1.7 for the rationale
> and trade-off.  The `writeups/` directory is auto-created if missing.

```bash
# Skip DOCX report generation (exploit still runs)
autopwn -l ./binary --no-report

# Reports are written to ./writeups/{target}_wp.docx by default
# (the --report-dir flag is currently ignored — v4.1.7 trade-off)
autopwn -l ./binary
```

---

## 💡 Usage Examples

### 🎪 Local Binary Analysis
```bash
# Comprehensive local analysis
autopwn -l ./vuln_binary
```

### 🌍 Remote Service Exploitation
```bash
# Target remote CTF service
autopwn -l ./local_binary -ip ctf.example.com -p 31337
```

### 🔧 Advanced Configuration
```bash
# Specify custom libc and manual padding
autopwn -l ./binary -libc /lib/x86_64-linux-gnu/libc.so.6 -f 88 -v
```

---

## 📋 Command Line Options

| Option | Description | Example |
|--------|-------------|----------|
| `-l, --local` | Target binary file (required) | `-l ./vuln_app` |
| `-ip, --ip` | Remote target IP address | `-ip 192.168.1.100` |
| `-p, --port` | Remote target port | `-p 9999` |
| `-libc, --libc` | Custom libc file path | `-libc ./libc-2.27.so` |
| `-f, --fill` | Manual overflow padding size | `-f 112` |
| `-v, --verbose` | Enable verbose output | `-v` |

---

## 🛠️ Technical Arsenal

### Core Dependencies
- **pwntools** - The ultimate CTF framework
- **LibcSearcher** - Libc database and version detection
- **ropper** - Advanced ROP gadget discovery
- **checksec** - Binary security feature analysis

### System Tools Integration
- **objdump** - Assembly analysis and disassembly
- **strings** - String extraction and analysis
- **ldd** - Dynamic library dependency mapping
- **gdb** - Advanced debugging capabilities

---

## 🎨 Output Preview



https://github.com/user-attachments/assets/1395d646-eeeb-4342-8b93-e05eed282b92



---

## 🏆 Why Choose AutoPwn?

### 🎯 **Precision & Automation**
No more manual gadget hunting or address calculation. AutoPwn automates the entire exploitation pipeline with surgical precision.

### 🚀 **Speed & Efficiency**
From vulnerability detection to shell acquisition in seconds, not hours. Perfect for time-critical CTF scenarios.

### 🧠 **Intelligence & Adaptability**
Smart fallback mechanisms ensure maximum success rate across different binary configurations and protection schemes.

### 🏛️ **Clean Architecture (v4.0)**
Refactored from a 3688-line monolith into a layered package:
- `autopwn.core` — logging / fs / runner
- `autopwn.recon` — binary protection / libc / ROP gadgets / PLT / BSS / ASM
- `autopwn.detect` — overflow / fmtstr / canary / binsh
- `autopwn.primitives` — 9 reusable payload builders (ret2system, ret2libc, fmtstr, …)
- `autopwn.exp.strategies` — 40 concrete strategies, ranked by `requires_*` metadata
- `autopwn.report` — dataclass-driven DOCX + code generators
- `autopwn.orchestrator` — 3-phase dispatch (recon → detect → strategy)

---

## 🤝 Contributing

We welcome contributions! Whether it's:
- 🐛 Bug reports and fixes
- ✨ New exploitation techniques
- 📚 Documentation improvements
- 🔧 Performance optimizations

**开发流程**：先读 [`upgraded.md`](./upgraded.md)（v4.0+ 迭代流程 + 任务看板）→ 必读 [`AGENTS.md`](./AGENTS.md) §1 铁律 → 了解 v4.0 架构 [`refactor.md §3`](./refactor.md) → 看重构历史 [`rebuild.md §3`](./rebuild.md) 阶段总结。

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

AutoPwn is designed for **educational purposes** and **authorized security testing** only. Users are responsible for ensuring compliance with applicable laws and regulations. The developers assume no liability for misuse of this tool.

---

<div align="center">

**Made with ❤️ by qzdx_soc（衢州电信安全运营中心）**

> 基于开源项目 [heimao-box/autopwn](https://github.com/heimao-box/autopwn) 改造（MIT 协议，原作者 @Ba1_Ma0）

*Star ⭐ this repo if AutoPwn helped you pwn some binaries!*

</div>
