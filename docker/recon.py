import sys, os, json, subprocess
from pwn import ELF, context, log
context.log_level = 'error'

rows = []
for ch in sorted(os.listdir('/work/bench')):
    d = os.path.join('/work/bench', ch)
    b = os.path.join(d, 'bin')
    if not os.path.exists(b):
        continue
    try:
        e = ELF(b, checksec=False)
    except Exception as ex:
        rows.append((ch, 'PARSE-FAIL', str(ex)))
        continue
    # checksec
    info = {
        'arch': f'{e.arch}/{e.bits}/{e.endian}',
        'type': e.elftype,
        'pie': e.pie,
        'canary': e.canary,
        'nx': e.nx,
        'relro': e.relro,
        'static': 'libc' not in [l.name for l in []] ,
    }
    try:
        interp = e.get_section_by_name('.interp')
        interp = interp.data().strip(b'\x00').decode() if interp else 'none'
    except Exception:
        interp = 'none'
    syms = [s for s in e.symbols if e.symbols[s] and e.symbols[s] < 0x100000]
    interesting = [s for s in syms if any(k in s.lower() for k in
                   ('win','flag','shell','system','exec','gift','vuln','read','gets','printf','back','magic','note','admin','cat'))]
    got = {k: hex(v) for k, v in list(e.got.items())[:12]}
    print(f'=== {ch} ===')
    print(f"  {info['arch']} {info['type']} pie={e.pie} canary={e.canary} nx={e.nx} relro={e.relro} interp={interp}")
    print(f"  entry={hex(e.entry)} base={hex(e.address)}")
    print(f"  syms: {sorted(interesting)[:25]}")
    print(f"  funcs(plt): {sorted(e.plt)[:20]}")
    try:
        rbss = e.bss()
        print(f"  bss={hex(rbss)} end={hex(e.bss(0))}")
    except Exception:
        pass
    # rwx segments
    try:
        rwx = [s.name for s in e.segments if (s.header.p_flags & 7) == 7]
        if rwx:
            print(f"  RWX segments: {rwx}")
    except Exception:
        pass
