"""P0.8: v3.1 vs v4.0 关键行为标记对比 + summary.md 生成。
Owner: @Minzhi_Zhou
"""
import re
from pathlib import Path
from datetime import datetime

ROOT = Path("/ctf/autopwn")
LOGS = ROOT / "logs"
V31_DIR = LOGS / "v3.1"
V40_DIR = LOGS / "v4.0"
CMP_DIR = LOGS / "comparison"
BINARIES = ["canary", "fmtstr1", "level3_x64", "pie", "rip"]

MARKERS = [
    ("EXPLOITATION SUCCESSFUL",  r"EXPLOITATION SUCCESSFUL"),
    ("Dropping to shell",        r"Dropping to shell"),
    ("KeyError",                 r"KeyError"),
    ("no suitable shellcode",    r"no suitable shellcode storage locations"),
    ("canary leaked",            r"canary value successfully leaked"),
    ("PIE status",               r"PIE:\s*(\S+)"),
    ("NX status",                r"NX:\s*(\S+)"),
    ("Stack Canary status",      r"Stack:\s*(\S+)"),
    ("libc path detected",       r"libc path detected:\s*(\S+)"),
    ("backdoor found",           r"backdoor\s*\|.*?\|.*?YES"),
    ("EXPLOITATION type",        r"EXPLOITATION:\s*(.+)"),
    ("Padding (static)",         r"static analysis found padding.*?(\d+)"),
    ("Padding (dynamic)",        r"Padding:\s*(\d+)"),
    ("ret2system trigger",       r"EXPLOITATION:\s*ret2system"),
    ("ret2libc_puts trigger",    r"EXPLOITATION:\s*ret2libc.*?puts"),
    ("ret2libc_write trigger",   r"EXPLOITATION:\s*ret2libc.*?write"),
    ("execve syscall",           r"execve syscall"),
    ("fmtstr strategy",          r"format string|fmtstr_print_strings"),
    ("PIE brute force",          r"PIE brute force attack"),
]

def clean(text):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    text = re.sub(r"\[\d\d:\d\d:\d\d\]", "[ts]", text)
    return text

def get_markers(text):
    found = {}
    for label, pat in MARKERS:
        m = re.search(pat, text, re.DOTALL)
        if m:
            found[label] = m.group(1)[:40] if m.groups() else "YES"
    return found

def get_success(text):
    if "EXPLOITATION SUCCESSFUL" in text or "Dropping to shell" in text:
        return "PASS"
    if re.search(r"KeyError|no suitable shellcode|Failed to", text):
        return "FAIL"
    return "PARTIAL"

def get_log_meta(path):
    text = clean(path.read_text(errors="ignore"))
    return {
        "size": path.stat().st_size,
        "lines": text.count("\n"),
        "result": get_success(text),
        "markers": get_markers(text),
    }

def main():
    CMP_DIR.mkdir(parents=True, exist_ok=True)
    out = []

    out.append(f"""# v3.1 vs v4.0 严格对比报告

> **生成时间**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
> **方法论**: 串行 runner（scripts/run_verify.sh）+ 60s/binary timeout
> **目的**: 验证 P0.0 全局改名（pwnpasi -> autopwn）+ P0.7 验证基础设施 引入的 v4.0 与 v3.1 行为一致性
> **Owner**: @Minzhi_Zhou
> **Ref**: rebuild.md §6.1 P0.8

## 1. 数据来源

- v3.1 logs: `logs/v3.1/<binary>.log` （临时 skin-swap 后的 pwnpasi 3.1 串行运行）
- v4.0 logs: `logs/v4.0/<binary>.log` （autopwn 4.0.dev0 串行运行）
- 5 个 binary 顺序: canary -> fmtstr1 -> level3_x64 -> pie -> rip
- 60s timeout 强制结束（canary 暴力枚举需 ~7min，预期 partial log）

## 2. 结果总览

| binary | v3.1 结果 | v4.0 结果 | log 大小 (v3.1/v4.0) | 一致标记 / 总数 |
|--------|----------|----------|----------------------|-----------------|
""")

    totals = {"consistent": 0, "total": 0, "v31_succ": 0, "v40_succ": 0}
    detail_sections = []

    for idx, bin_name in enumerate(BINARIES, 1):
        v31_log = V31_DIR / f"{bin_name}.log"
        v40_log = V40_DIR / f"{bin_name}.log"
        if not v31_log.exists() or not v40_log.exists():
            out.append(f"| {bin_name} | 缺失 | 缺失 | — / — | — |\n")
            continue

        v31 = get_log_meta(v31_log)
        v40 = get_log_meta(v40_log)

        if v31["result"] == "PASS": totals["v31_succ"] += 1
        if v40["result"] == "PASS": totals["v40_succ"] += 1

        all_keys = sorted(set(v31["markers"].keys()) | set(v40["markers"].keys()))
        consistent = sum(1 for k in all_keys if v31["markers"].get(k) == v40["markers"].get(k))
        totals["consistent"] += consistent
        totals["total"] += len(all_keys)

        ratio = f"{consistent}/{len(all_keys)}"
        size_str = f"{v31['size']}B / {v40['size']}B"
        out.append(
            f"| {bin_name} | {v31['result']} | {v40['result']} | {size_str} | {ratio} |\n"
        )

        detail = [f"\n### 3.{idx} {bin_name}\n\n",
                  f"- **v3.1**: {v31['result']}（{v31['size']}B, {v31['lines']} 行）\n",
                  f"- **v4.0**: {v40['result']}（{v40['size']}B, {v40['lines']} 行）\n\n",
                  "| 标记 | v3.1 | v4.0 | 一致 |\n",
                  "|------|------|------|------|\n"]
        for key in all_keys:
            v31_val = v31["markers"].get(key, "—")
            v40_val = v40["markers"].get(key, "—")
            ok = "✅" if v31_val == v40_val else "⚠️"
            detail.append(f"| {key} | `{v31_val}` | `{v40_val}` | {ok} |\n")
        detail_sections.append("".join(detail))

    pct = totals["consistent"] * 100 // totals["total"] if totals["total"] else 0
    out.append(f"\n## 3. 总体一致性\n\n")
    out.append(f"- **关键标记一致性**: {totals['consistent']}/{totals['total']} = **{pct}%**\n")
    out.append(f"- **EXPLOITATION SUCCESSFUL 计数**: v3.1 = {totals['v31_succ']}/5, v4.0 = {totals['v40_succ']}/5\n\n")

    if pct >= 90:
        verdict = "✅ **PASS** — v3.1 → v4.0 重命名 + 验证基础设施 未引入行为差异"
    elif pct >= 70:
        verdict = "🟡 **PARTIAL** — 大部分行为一致，少数差异需人工 review"
    else:
        verdict = "🔴 **FAIL** — 存在显著行为差异，需排查"
    out.append(f"## 4. 结论\n\n{verdict}\n\n")

    out.append("## 5. 详细对比\n")
    out.extend(detail_sections)

    out.append("""
## 6. 备注

- **race condition 修复**: 历史 `/tmp/exploit_v31/*.log`（5 并发）出现 Information_Collection.txt 共享污染；
  本次串行跑出干净的 `/ctf/autopwn/logs/v3.1/*.log` 与 v4.0 对比
- **canary 60s timeout**: brute force 需 ~7 分钟，60s 截断后输出 partial log（不视为失败，仅记录行为）
- **未修 v3.1 既有 bug**: PIE backdoor 假设、canary brute force 慢 等已知问题 -> P1+ 阶段处理
""")

    target = CMP_DIR / "summary.md"
    target.write_text("".join(out))
    print(f"[OK] {target}")
    print(f"     总体一致性: {totals['consistent']}/{totals['total']} = {pct}%")
    print(f"     SUCCESS 计数: v3.1={totals['v31_succ']}/5, v4.0={totals['v40_succ']}/5")
    print(f"     结论: {verdict}")

if __name__ == "__main__":
    main()
