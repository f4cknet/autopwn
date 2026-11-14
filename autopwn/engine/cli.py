"""命令行入口：

    python -m autopwn.engine.cli bench/            # 跑整个目录
    python -m autopwn.engine.cli bench/ch01_note   # 单题
    python -m autopwn.engine.cli chellenges/        # 原始目录（ELF/zip 混放，自动整理）
    python -m autopwn.engine.cli bench/ch13 --libc path/to/libc.so.6
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import zipfile

from .model import Challenge
from .orchestrator import solve

ELF_MAGIC = b"\x7fELF"


def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == ELF_MAGIC
    except Exception:
        return False


def _normalize_dir(src: str, dest: str) -> list[str]:
    """把一个「平铺目录」（pwn + libc.so.6 + ld-*.so，或 pwn 单独一个）整理成
    <dest>/bin（+ <dest>/libc/）的规范结构。"""
    os.makedirs(dest, exist_ok=True)
    files = []
    for name in os.listdir(src):
        p = os.path.join(src, name)
        if os.path.isfile(p) and not name.startswith("."):
            files.append(p)
    elfs = [f for f in files if _is_elf(f)]
    if not elfs:
        return []

    def rank(p):
        n = os.path.basename(p).lower()
        if n in ("pwn", "chall", "challenge", "main"):
            return (0, -os.path.getsize(p))
        if "libc" in n or n.startswith("ld-"):
            return (2, -os.path.getsize(p))
        return (1, -os.path.getsize(p))

    elfs.sort(key=rank)
    main_elf = elfs[0]
    shutil.copy2(main_elf, os.path.join(dest, "bin"))
    libc_dir = os.path.join(dest, "libc")
    for f in elfs[1:]:
        n = os.path.basename(f).lower()
        if "libc" in n or n.startswith("ld-"):
            os.makedirs(libc_dir, exist_ok=True)
            shutil.copy2(f, os.path.join(libc_dir, os.path.basename(f)))
    return [dest]


def _unpack_zip(zpath: str, dest: str) -> list[str]:
    """解压题目包到临时目录，再整理成规范结构。"""
    tmp = dest.rstrip("/\\") + ".raw"
    os.makedirs(tmp, exist_ok=True)
    with zipfile.ZipFile(zpath) as zf:
        for name in zf.namelist():
            if name.startswith("__MACOSX") or name.endswith("/"):
                continue
            base = os.path.basename(name)
            if not base:
                continue
            with zf.open(name) as src, open(os.path.join(tmp, base), "wb") as out:
                shutil.copyfileobj(src, out)
    return _normalize_dir(tmp, dest)


def _collect(target: str, workroot: str) -> list[tuple[str, str]]:
    """返回 [(challenge_path, workdir)]。

    支持：
      1) 单个二进制 / 单个 zip
      2) 规范题目目录（含 bin）
      3) 原始目录：混放 ELF、zip、以及「已解压的平铺目录」（pwn + libc + ld）
    """
    target = os.path.abspath(target)
    workroot = os.path.abspath(workroot)
    stage = os.path.join(workroot, "_staged")

    def _stage(src: str, tag: str) -> list[str]:
        dest = os.path.join(stage, tag[:40])
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)
        return _normalize_dir(src, dest)

    if os.path.isfile(target):
        if zipfile.is_zipfile(target):
            stem = os.path.splitext(os.path.basename(target))[0][:24]
            return [(d, "") for d in _unpack_zip(target, os.path.join(stage, stem))]
        return [(target, os.path.join(workroot, "_work",
                                      os.path.splitext(os.path.basename(target))[0]))]

    if os.path.exists(os.path.join(target, "bin")):
        return [(target, "")]

    out: list[tuple[str, str]] = []
    for name in sorted(os.listdir(target)):
        if name.startswith("."):
            continue
        p = os.path.join(target, name)
        if os.path.isdir(p):
            if os.path.exists(os.path.join(p, "bin")):
                out.append((p, ""))
            else:
                for d in _stage(p, name):
                    out.append((d, ""))
            continue
        if _is_elf(p):
            out.append((p, os.path.join(workroot, "_work", os.path.splitext(name)[0])))
        elif zipfile.is_zipfile(p):
            stem = os.path.splitext(name)[0][:24]
            for d in _unpack_zip(p, os.path.join(stage, stem)):
                out.append((d, ""))
    return out


def _norm_target(t: str) -> str:
    """把 Windows 写法（bench\\ch01、D:////...////autopwn////bench////ch01）换成容器内路径。"""
    t = t.replace("\\", "/")
    root = os.environ.get("AUTOPWN_HOST_ROOT", "").replace("\\", "/").rstrip("/")
    if root and t.lower().startswith(root.lower()):
        t = "/work" + t[len(root):]
    return t


def _md5_of(ch: Challenge) -> str:
    try:
        with open(ch.bin_src, "rb") as fh:
            return hashlib.md5(fh.read()).hexdigest()
    except Exception:
        return ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="autopwn.engine")
    ap.add_argument("target", help="题目目录 / 二进制 / 含多题的父目录")
    ap.add_argument("--libc", default=None)
    ap.add_argument("--ld", default=None)
    ap.add_argument("--host", default=None, help="远程地址（配合 --port 使用）")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--ssl", action="store_true", help="远程走 TLS（stunnel 类平台）")
    ap.add_argument("--sni", default=None, help="TLS SNI，默认等于 --host")
    ap.add_argument("--max-attempts", type=int, default=80)
    ap.add_argument("--budget", type=float, default=240.0, help="单题时间预算（秒）")
    ap.add_argument("--facts-only", action="store_true", help="只打印静态事实，不执行利用")
    ap.add_argument("--cmd", action="append", default=None, metavar="CMD",
                    help="拿到 shell 后执行的命令，可重复：--cmd \"cat /flag\" --cmd ls")
    ap.add_argument("--no-dedup", action="store_true", help="按 md5 去重（默认开启）")
    ap.add_argument("--allow-brute", action="store_true",
                    help="允许无证据的偏移盲枚举（v7.3.0 起默认关闭；开启后计入盲试占比）")
    ap.add_argument("--out", default="results")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)
    args.target = _norm_target(args.target)
    # CMD 会把 --cmd "ls -la /" 的引号原样传进来，剥一层
    if args.cmd:
        args.cmd = [c[1:-1] if len(c) >= 2 and c[0] == c[-1] == '"' else c
                    for c in args.cmd]

    os.makedirs(args.out, exist_ok=True)
    pairs = _collect(args.target, args.out)
    if not pairs:
        print("no challenge found", file=sys.stderr)
        return 2

    # 按二进制 md5 去重（原始目录里常混有重复样本）
    targets: list[tuple[str, str]] = []
    seen: dict[str, str] = {}
    for path, workdir in pairs:
        try:
            probe = Challenge(path, libc=args.libc, ld=args.ld).prepare()
        except Exception:
            continue
        digest = _md5_of(probe)
        if digest and digest in seen and not args.no_dedup:
            print(f"[=] {probe.name}: 与 {seen[digest]} 重复，跳过")
            continue
        if digest:
            seen[digest] = probe.name
        targets.append((path, workdir))

    print(f"[*] 共 {len(targets)} 个唯一题目（原始 {len(pairs)} 个）\n")
    results = []
    for path, workdir in targets:
        ch = Challenge(path, libc=args.libc, ld=args.ld,
                       host=args.host, port=args.port,
                       ssl=args.ssl, sni=args.sni,
                       workdir=workdir or None)
        ch.allow_brute = bool(getattr(args, "allow_brute", False))
        print(f"[*] {ch.name}: {ch.bin_src}")
        if args.facts_only:
            from .facts import analyse
            ch.prepare()
            f = analyse(ch)
            print(f"    prot   : {ch.prot}")
            print(f"    libc   : {ch.libc_path}")
            print(f"    vulns  : {[str(v) for v in f.vulns]}")
            print(f"    wins   : {[str(w) for w in f.wins]}")
            print(f"    binsh  : {hex(f.binsh) if f.binsh else None}")
            print(f"    gadgets: {{{', '.join(f'{k}: {hex(v)}' for k, v in f.gadgets.items())}}}")
            print(f"    csu    : {f.csu}")
            print(f"    mmapRX : {hex(f.mmap_rwx) if f.mmap_rwx else None}")
            print(f"    fmtbuf : {f.fmt_buf}")
            continue
        res = solve(ch, max_attempts=args.max_attempts,
                    budget=args.budget, verbose=not args.quiet,
                    post_cmds=args.cmd or None)
        results.append(res)
        status = "SHELL" if (res.ok and not res.flag_only) else ("FLAG-ONLY" if res.ok else "FAILED")
        print(f"    => {status} {res.strategy} "
              f"{res.detail} ({res.elapsed:.1f}s / {len(res.attempts)} attempts)")
        if not res.ok and res.error:
            print(f"    !! {res.error}")
        for cmd, out in (res.cmds or []):
            print(f"    $ {cmd}")
            text = out.decode("latin-1", "replace").rstrip()
            for line in (text.splitlines() or [""]):
                print(f"      {line}")
        import json
        with open(os.path.join(args.out, f"{ch.name}.json"), "w", encoding="utf-8") as fh:
            json.dump(res.as_dict(), fh, ensure_ascii=False, indent=2)

    shell = sum(1 for r in results if r.ok and not r.flag_only)
    flag = sum(1 for r in results if r.ok and r.flag_only)
    if not results:
        return 0
    print(f"\n=== {shell}/{len(results)} shell, {flag} flag-only ===")
    for r in results:
        mark = "✓" if (r.ok and not r.flag_only) else ("⚑" if r.ok else "✗")
        print(f"  {mark} {r.name:<24} {r.strategy:<14} {r.detail[:70]}")
    return 0 if shell else 1


if __name__ == "__main__":
    raise SystemExit(main())
