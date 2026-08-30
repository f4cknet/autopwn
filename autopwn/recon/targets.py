"""Recon helpers for v4.1.19 candidate target discovery."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from autopwn.context import ExploitContext, FunctionCandidate
from autopwn.core.runner import run_nm, run_objdump_disasm, run_readelf


_FUNCTION_RE = re.compile(
    r"^([0-9a-fA-F]+)\s+<([^>]+)>:(.*?)(?=^[0-9a-fA-F]+ <[^>]+>:|\Z)",
    re.MULTILINE | re.DOTALL,
)
_CALL_TARGET_RE = re.compile(r"\bcall\b(?:\s+[0-9a-fA-Fx]+)?\s+<([^>]+)>")
_COMMENT_ADDR_RE = re.compile(r"#\s*([0-9a-fA-F]+)")
_SECTION_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+([.\w$@+-]+)\s+\S+\s+([0-9a-fA-F]+)\s+",
    re.MULTILINE,
)
_STRING_RE = re.compile(r"^\s*\[\s*([0-9a-fA-F]+)\]\s+(.*)$")
_NM_RE = re.compile(r"^\s*([0-9A-Fa-f]+)?\s*([A-Za-z])\s+(.+)$")

_STRONG_NAME_TOKENS = (
    "print_flag",
    "getflag",
    "backdoor",
    "hacked",
    "secret",
    "admin",
    "shell",
    "hack",
    "flag",
    "pwn",
    "win",
)
_WEAK_NAME_TOKENS = ("vulnerable", "vuln")
_INTERESTING_STRING_TOKENS = (
    "/bin/sh",
    "you win",
    "how did you get in here",
    "get flag",
    "flag",
)
_CONTROL_CALLS = frozenset({"system", "execve"})
_OUTPUT_CALLS = frozenset({"open", "read", "puts", "printf"})
_INPUT_CALLS = frozenset({"read", "gets", "fgets", "scanf"})
_RUNTIME_NOISE_PREFIXES = ("@", ".", "_init", "_fini")
_RUNTIME_NOISE_NAMES = frozenset(
    {
        "_start",
        "__libc_csu_init",
        "__libc_csu_fini",
        "__do_global_dtors_aux",
        "deregister_tm_clones",
        "register_tm_clones",
        "frame_dummy",
        "__x86.get_pc_thunk.ax",
        "__x86.get_pc_thunk.bx",
        "__x86.get_pc_thunk.cx",
        "__x86.get_pc_thunk.dx",
    }
)


@dataclass(slots=True)
class DiscoveredFunction:
    """Disassembly-derived function facts shared by recon and detect."""

    name: str
    addr: int
    body: str
    call_targets: tuple[str, ...]
    imported_calls: tuple[str, ...]
    string_refs: tuple[str, ...]
    input_call_count: int
    output_call_count: int
    xref_count: int = 0


def inspect_functions(program: Path) -> list[DiscoveredFunction]:
    """Return disassembled functions with normalized call/string metadata."""
    return list(_inspect_functions_cached(str(program)))

@lru_cache(maxsize=None)
def _inspect_functions_cached(program_str: str) -> tuple[DiscoveredFunction, ...]:
    """Cached worker behind :func:`inspect_functions`."""
    program = Path(program_str)
    objdump_out = run_objdump_disasm(program, intel=True)
    imported_symbols = _parse_imported_symbols(run_nm(program))
    strings_by_addr = _parse_interesting_strings(program)

    functions: list[DiscoveredFunction] = []
    for match in _FUNCTION_RE.finditer(objdump_out):
        addr = int(match.group(1), 16)
        name = match.group(2)
        if _should_skip_function_name(name):
            continue

        body = match.group(3)
        raw_call_targets = _extract_raw_call_targets(body)
        call_targets = tuple(target for _, target in raw_call_targets)
        imported_calls = tuple(
            _dedupe_preserve_order(
                target
                for raw_target, target in raw_call_targets
                if target in imported_symbols or "@plt" in raw_target
            )
        )
        string_refs = tuple(_dedupe_preserve_order(_extract_string_refs(body, strings_by_addr)))
        functions.append(
            DiscoveredFunction(
                name=name,
                addr=addr,
                body=body,
                call_targets=call_targets,
                imported_calls=imported_calls,
                string_refs=string_refs,
                input_call_count=sum(1 for target in call_targets if target in _INPUT_CALLS),
                output_call_count=sum(
                    1
                    for target in call_targets
                    if target in _OUTPUT_CALLS or target in _CONTROL_CALLS
                ),
            )
        )

    return tuple(_with_xrefs(functions))


def collect_target_candidates(
    ctx: ExploitContext,
    program: Path,
) -> list[FunctionCandidate]:
    """Score likely internal targets such as win/backdoor/helper functions."""
    candidates: list[FunctionCandidate] = []
    for func in inspect_functions(program):
        candidate = _score_function_candidate(ctx, func)
        if candidate is not None:
            candidates.append(candidate)
    return sorted(candidates, key=lambda item: (-item.score, item.addr))


def _score_function_candidate(
    ctx: ExploitContext,
    func: DiscoveredFunction,
) -> FunctionCandidate | None:
    reasons: list[str] = []
    score = 0

    name_bonus = _name_bonus(func.name, stripped=ctx.binary.stripped)
    if name_bonus:
        score += name_bonus
        reasons.append(f"name bonus +{name_bonus}")

    interesting_strings = tuple(
        hit for hit in func.string_refs if _is_interesting_string(hit)
    )
    if interesting_strings:
        score += 15
        reasons.append("interesting string reference +15")

    import_bonus, import_reason = _import_bonus(func.imported_calls)
    if import_bonus:
        score += import_bonus
        reasons.append(import_reason)

    if score <= 0:
        return None

    if func.xref_count <= 1:
        score += 10
        reasons.append("isolated xref profile +10")

    if not ctx.binary.pie:
        score += 5
        reasons.append("no-PIE direct ret2win bonus +5")

    return FunctionCandidate(
        name=func.name,
        addr=func.addr,
        score=score,
        reasons=tuple(reasons),
        string_hits=interesting_strings,
        imported_calls=func.imported_calls,
        xref_count=func.xref_count,
    )


def _with_xrefs(functions: list[DiscoveredFunction]) -> list[DiscoveredFunction]:
    xrefs = {func.name: 0 for func in functions}
    function_names = frozenset(xrefs)

    for func in functions:
        for target in func.call_targets:
            if target in function_names and target != func.name:
                xrefs[target] += 1

    return [
        DiscoveredFunction(
            name=func.name,
            addr=func.addr,
            body=func.body,
            call_targets=func.call_targets,
            imported_calls=func.imported_calls,
            string_refs=func.string_refs,
            input_call_count=func.input_call_count,
            output_call_count=func.output_call_count,
            xref_count=xrefs.get(func.name, 0),
        )
        for func in functions
    ]


def _parse_imported_symbols(nm_out: str) -> set[str]:
    imported: set[str] = set()
    for line in nm_out.splitlines():
        match = _NM_RE.match(line)
        if not match:
            continue
        if match.group(2) == "U":
            imported.add(_normalize_symbol_name(match.group(3)))
    return imported


def _parse_interesting_strings(program: Path) -> list[tuple[int, int, str]]:
    section_addrs = {
        name: int(addr, 16)
        for name, addr in _SECTION_RE.findall(run_readelf(program, "-S"))
        if "rodata" in name
    }
    entries: list[tuple[int, int, str]] = []
    for section_name, base_addr in section_addrs.items():
        dump = run_readelf(program, "-p", section_name)
        for line in dump.splitlines():
            match = _STRING_RE.match(line)
            if not match:
                continue
            offset = int(match.group(1), 16)
            text = match.group(2).strip()
            if text:
                absolute = base_addr + offset
                entries.append((absolute, absolute + len(text) + 1, text))
    return entries


def _extract_raw_call_targets(body: str) -> list[tuple[str, str]]:
    return [
        (match.group(1), _normalize_symbol_name(match.group(1)))
        for match in _CALL_TARGET_RE.finditer(body)
    ]


def _extract_string_refs(
    body: str,
    strings_by_addr: list[tuple[int, int, str]],
) -> list[str]:
    refs: list[str] = []
    for match in _COMMENT_ADDR_RE.finditer(body):
        addr = int(match.group(1), 16)
        for start, end, text in strings_by_addr:
            if start <= addr < end and _is_interesting_string(text):
                refs.append(text)
                break
    return refs


def _name_bonus(name: str, *, stripped: bool) -> int:
    if stripped:
        return 0

    lowered = _normalize_symbol_name(name).lower()
    bonus = _keyword_bonus(lowered, _STRONG_NAME_TOKENS, 20)
    bonus += _keyword_bonus(lowered, _WEAK_NAME_TOKENS, 5)
    return min(bonus, 30)


def _import_bonus(imported_calls: tuple[str, ...]) -> tuple[int, str]:
    score = 0
    reasons: list[str] = []
    if any(call in _CONTROL_CALLS for call in imported_calls):
        score += 25
        reasons.append("control import +25")
    if any(call in _OUTPUT_CALLS for call in imported_calls):
        score += 10
        reasons.append("output import +10")
    return score, ", ".join(reasons)


def _is_interesting_string(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _INTERESTING_STRING_TOKENS)


def _normalize_symbol_name(name: str) -> str:
    return name.strip().split("@", 1)[0].split("+", 1)[0]


def _should_skip_function_name(name: str) -> bool:
    normalized = _normalize_symbol_name(name)
    if normalized in _RUNTIME_NOISE_NAMES:
        return True
    if name.endswith("@plt"):
        return True
    return normalized.startswith(_RUNTIME_NOISE_PREFIXES)


def _dedupe_preserve_order(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _keyword_bonus(lowered: str, tokens: tuple[str, ...], per_hit: int) -> int:
    """Overlap-aware keyword bonus so ``hacked`` doesn't double-count ``hack``."""
    spans: list[tuple[int, int]] = []
    bonus = 0
    for token in sorted(tokens, key=len, reverse=True):
        for match in re.finditer(re.escape(token), lowered):
            start, end = match.span()
            if any(not (end <= left or start >= right) for left, right in spans):
                continue
            spans.append((start, end))
            bonus += per_hit
            break
    return bonus


__all__ = [
    "DiscoveredFunction",
    "inspect_functions",
    "collect_target_candidates",
]
