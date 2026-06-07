"""core.runner — subprocess wrappers for external tools.

Refactored from autopwn._legacy (P1.3). P1.5 will switch call sites from
`os.system(\"tool ... > file\")` patterns to these in-process wrappers,
ending the cwd pollution and the 15 os.system shell-outs.

Layer: core (no upward dependency). Sibling to core.logging and core.fs
within the same layer (can import from them).
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class ToolError(RuntimeError):
    """Raised when a recon tool fails (e.g., checksec exits non-zero)."""


def run_checksec(program) -> str:
    """Run `checksec` on `program` and return combined output.

    checksec (pwntools) writes its banner + analysis to stderr, not
    stdout. The legacy `os.system("checksec X > file 2>&1")` combined
    both streams. We replicate that here by returning `stdout + stderr`.

    Raises ToolError on non-zero returncode (checksec must succeed for
    recon to make sense; other tools degrade gracefully below).
    """
    cp = subprocess.run(
        ["checksec", str(program)],
        capture_output=True, text=True, check=False,
    )
    if cp.returncode != 0:
        raise ToolError(f"checksec failed (rc={cp.returncode}): {cp.stderr.strip()}")
    return cp.stdout + cp.stderr


def run_ropper(program, search: str) -> str:
    """Run `ropper --file X --search 'Y' --nocolor` and return combined output.

    ropper writes matches to stdout and a banner to stderr. Legacy
    `os.system("ropper ... > file 2>&1")` combined both; we do the same.
    Do not raise on rc != 0 (ropper may exit non-zero on internal errors
    but still return useful partial output).
    """
    cp = subprocess.run(
        ["ropper", "--file", str(program), "--search", search, "--nocolor"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout + cp.stderr


def run_objdump_disasm(program) -> str:
    """Run `objdump -d -M intel X --no-show-raw-insn` and return stdout.

    objdump writes only to stdout (no banner on stderr). Intel syntax +
    no-raw-insn matches the spec in rebuild.md §6.2 P1.3.

    L580 in _legacy uses the basic `objdump -d`; P1.5 may use this same
    function for both since the extra flags are output-only and produce
    nicer (lossless) disassembly.
    """
    cp = subprocess.run(
        ["objdump", "-d", "-M", "intel", str(program), "--no-show-raw-insn"],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


def run_ldd(program) -> str:
    """Run `ldd X` and return stdout.

    ldd writes only to stdout. L360 in _legacy pipes through `awk` to
    strip leading whitespace; P1.5 will do that in Python (split + strip),
    not in shell.
    """
    cp = subprocess.run(
        ["ldd", str(program)],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


# =====================================================================
# P1.3a: static binutils suite (临时需求 #4)
# =====================================================================
# All four are "degrade gracefully" tools per refactor.md §4.2:
#   - return str (not Path or process)
#   - on rc != 0 or empty output, return "" (no ToolError)
#   - caller is expected to check truthiness before parsing
# These will be adopted by P4 (recon) and P5 (detect) stages.


def run_file(program) -> str:
    """Run `file X` and return the single-line file-type description.

    Example output: "ELF 32-bit LSB executable, Intel 80386, ..."
    Used in P4 recon to confirm arch (32 vs 64) and binary type.
    """
    cp = subprocess.run(
        ["file", str(program)],
        capture_output=True, text=True, check=False,
    )
    return (cp.stdout or cp.stderr).strip()


def run_readelf(program, *flags: str) -> str:
    """Run `readelf <flags> X` and return stdout.

    Common flag presets (caller picks):
      - "-h"  ELF header (arch, type, entry point)
      - "-d"  dynamic section (NEEDED libs, RUNPATH/RPATH)
      - "-s"  symbol table (.symtab + .dynsym)
      - "-l"  program headers (segments, INTERP)
      - "-S"  section headers
      - "-a"  all of the above (large output)

    Flags are passed as-is; do not pass user input. Defaults to no
    flags (readelf prints summary).
    """
    cmd = ["readelf", *flags, str(program)]
    cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return cp.stdout


def run_strings(program, min_len: int = 4) -> str:
    """Run `strings -n <min_len> X` and return newline-separated strings.

    Default min_len=4 matches binutils default. Used to extract candidate
    format-string / "/bin/sh" / error-message candidates for detect phase.
    """
    cp = subprocess.run(
        ["strings", "-n", str(min_len), str(program)],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


def run_nm(program) -> str:
    """Run `nm X` and return the symbol table (one entry per line).

    Format: "ADDR TYPE NAME" (e.g., "0804bf14 d _DYNAMIC"). Used in P4
    recon to find libc-required symbols (system / puts / printf / gets).
    May fail on stripped binaries (returns "" — caller must check).
    """
    cp = subprocess.run(
        ["nm", str(program)],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout


# =====================================================================
# P1.3b: ROP / pattern suite (临时需求 #4)
# =====================================================================
# ROPgadget is an alternative to ropper with a different output format
# (one gadget per line, `0xADDR : INSTR`); useful as a secondary ROP
# scanner for cross-validation in P6/P7.
#
# cyclic is pwntools' pattern generator; its CLI wrapper prints a
# DeprecationWarning to stderr (still works) — we drop stderr silently.
#
# one_gadget finds one-shot RCE gadgets in a libc (not the target binary);
# P6 primitives will use these for libc-based exploits.


def run_ropgadget(program, *filters: str) -> str:
    """Run `ROPgadget --binary X [--only <f1>] [--only <f2>]...` and return stdout.

    Each positional arg in `filters` becomes a `--only` clause. Common
    patterns: "pop|ret", "leave|ret", "int". Empty filters list runs
    the full scan (slow for large binaries).

    Output format (one gadget per line, prefixed by a 2-line header):
        Gadgets information
        ============================================================
        0x080492fb : pop ebp ; ret
        0x0804900a : ret

    Note: ROPgadget does NOT support `--nocolor` (unlike ropper). ANSI
    color codes appear in stdout; strip them with re before parsing.
    """
    cmd = ["ROPgadget", "--binary", str(program)]
    for f in filters:
        cmd.extend(["--only", f])
    cp = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return cp.stdout


def run_cyclic_create(length: int) -> str:
    """Run `cyclic <length>` and return the cyclic pattern (no trailing newline).

    cyclic's CLI prints a DeprecationWarning to stderr (pwntools
    prefers `pwn cyclic` or `pwn.cyclic()` directly); we drop stderr
    silently. Used in P5.1 / P7.10 to build payload + post-exploit
    crash analysis.
    """
    cp = subprocess.run(
        ["cyclic", str(length)],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout.strip()


def run_cyclic_find(pattern: str) -> str:
    """Run `cyclic -l <pattern>` and return the offset as a string (e.g., "140").

    Returns "" on miss. The pattern should be a 4-byte substring of a
    cyclic-generated buffer (typical usage: paste the first 4 bytes of
    the saved return address from a crash).
    """
    cp = subprocess.run(
        ["cyclic", "-l", pattern],
        capture_output=True, text=True, check=False,
    )
    return cp.stdout.strip()


def run_one_gadget(libc_path) -> str:
    """Run `one_gadget <libc>` and return the structured gadget list.

    one_gadget finds one-shot RCE gadgets in the given libc (not the
    target binary). Output format:
        0xebc81 execve("/bin/sh", r10, [rbp-0x70])
        constraints:
          address rbp-0x78 is writable
          [r10] == NULL || r10 == NULL || r10 is a valid argv
          [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

    Returns stdout (or stderr if stdout empty — one_gadget sometimes
    writes to either depending on version).
    """
    cp = subprocess.run(
        ["one_gadget", str(libc_path)],
        capture_output=True, text=True, check=False,
    )
    return (cp.stdout or cp.stderr).strip()


# =====================================================================
# P1.3c: dynamic / sandbox suite (临时需求 #4)
# =====================================================================
# All four write their "useful" output to stderr (syscall traces,
# library call traces, seccomp events, pwndbg color output). Wrapper
# returns stdout+stderr combined to match legacy `2>&1` semantics.
#
# These are exploratory / diagnostic tools; P5 detect will use them
# for runtime analysis, P7 strategies may use gdb batch for crash
# post-mortem.


def run_strace(program, *args: str) -> str:
    """Run `strace <args> <program>` and return combined stdout+stderr.

    strace writes syscall traces to stderr. Useful common args:
      - "-c"             summary table (counts + time)
      - "-e trace=open"  filter specific syscalls
      - "-f"             follow forks
      - "-o <file>"      write to file (use subprocess.Popen for this)

    The target's stdout is captured and prepended (strace interleaves
    target output with trace lines). Callers wanting only strace
    output should redirect the target's stdout first.

    Uses errors='replace' because the target's stdout may contain
    non-UTF-8 bytes (binary data from format strings / uninitialized
    memory / BOF output) that would otherwise crash the decode.
    """
    cmd = ["strace", *args, str(program)]
    cp = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", check=False,
    )
    return cp.stdout + cp.stderr


def run_ltrace(program, *args: str) -> str:
    """Run `ltrace <args> <program>` and return combined stdout+stderr.

    ltrace writes library call traces to stderr. Useful common args:
      - "-e puts+printf"  filter specific library calls
      - "-L"              count time + library calls
      - "-x <hex_addr>"   dereference a specific address in trace

    As with strace, the target's stdout is captured and interleaved.
    Uses errors='replace' for non-UTF-8 target output.
    """
    cmd = ["ltrace", *args, str(program)]
    cp = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", check=False,
    )
    return cp.stdout + cp.stderr


def run_seccomp(program, *args: str) -> str:
    """Run `seccomp-tools <args> <program>` and return combined stdout+stderr.

    seccomp-tools has multiple subcommands. Common ones:
      - "dump"   run target and print seccomp events as they occur
      - "disasm" disassemble the seccomp filter (if binary has one)
      - "inspect" show filter summary

    If the target has no seccomp filter, "dump" just runs the target
    normally (returns its stdout/stderr). Default usage:
      run_seccomp(program)            # equivalent to "seccomp-tools dump <prog>"
      run_seccomp(program, "disasm")  # disasm subcommand

    Uses errors='replace' for non-UTF-8 target output.
    """
    if not args:
        args = ("dump",)
    cmd = ["seccomp-tools", *args, str(program)]
    cp = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", check=False,
    )
    return cp.stdout + cp.stderr


def run_gdb_batch(program, *commands: str) -> str:
    """Run `gdb -batch -nx -ex <cmd1> -ex <cmd2>... <program>` and return stderr.

    gdb + pwndbg writes all output to stderr (with ANSI color codes).
    Use this for crash post-mortem analysis (read registers / stack
    after a fault), or scripted binary inspection.

    Always inserts:
      - "-batch" (no interactive prompt)
      - "-nx"    (skip ~/.gdbinit, reproducible)
      - "-ex set pagination off" (avoid --More-- prompts)

    Caller supplies commands; must include "quit" (or "q") as the
    last command or gdb will hang on the post-mortem prompt.

    Example: run_gdb_batch("./canary", "b main", "run", "info reg", "quit")

    Uses errors='replace' for non-UTF-8 target output (gdb captures
    target's stdout/stderr and may pass through arbitrary bytes).
    """
    cmd = ["gdb", "-batch", "-nx", "-ex", "set pagination off"]
    for c in commands:
        cmd.extend(["-ex", c])
    cmd.append(str(program))
    cp = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", check=False,
    )
    return cp.stdout + cp.stderr


__all__ = [
    "ToolError",
    "run_checksec", "run_ropper", "run_objdump_disasm", "run_ldd",
    # P1.3a: static binutils suite (临时需求 #4)
    "run_file", "run_readelf", "run_strings", "run_nm",
    # P1.3b: ROP / pattern suite (临时需求 #4)
    "run_ropgadget", "run_cyclic_create", "run_cyclic_find", "run_one_gadget",
    # P1.3c: dynamic / sandbox suite (临时需求 #4)
    "run_strace", "run_ltrace", "run_seccomp", "run_gdb_batch",
]
