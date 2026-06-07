"""AutoPwn report layer — DOCX report generator.

Moved from ``autopwn/_legacy.py`` v3.1 in P3.2 (see ``rebuild.md`` §4.4 +
§6.4).  Reads from the typed :class:`ExploitInfo` dataclass (P3.1) instead
of the loose ``exploit_info`` dict, and writes to ``out_dir`` instead of
the current working directory.

Design
======
* **Pure-ish function**: takes ``info`` and ``out_dir``, returns the
  generated ``Path``.  Caller (P3.4 ``record_success``) is responsible
  for success-gating (``--no-report``).
* **Lazy python-docx import**: P3.6 will wrap this in
  ``try/except ImportError`` and fall back to markdown.  For P3.2 the
  import is at function top (matches legacy behavior); P3.6 moves it
  to module level with a fallback function.
* **No more global state**: the legacy ``global exploit_info`` declaration
  is gone.  All 14 ``exploit_info['x']`` reads become ``info.x`` (or
  computed from ``info`` — see the table below).
* **Cross-call to code generator**: still imports
  ``autopwn._legacy.generate_exploitation_code`` (legacy global fn).
  P3.3 will replace this with ``from autopwn.report.code import
  generate_code`` once the code generator is moved.

Field mapping (legacy dict → ExploitInfo)
-----------------------------------------
========================================== ==============================
``exploit_info['x']``                       ``info.x`` (or derived)
========================================== ==============================
``'target_binary'``                         ``info.target_binary``
                                           (basename extracted via
                                           ``Path().stem`` in this fn)
``'exploit_type'``                          ``info.exploit_type``
``'architecture'``                          ``info.architecture``
``'vulnerability_type'``                    ``info.vulnerability_type``
``'padding'``                               ``info.padding``
``'addresses'``                             ``info.addresses``
``'payload'`` (bytes → hex; str → str)      ``info.payload``
``'timestamp'``                             ``info.timestamp``
``'success'``                               *removed* (ExploitInfo is
                                           constructed only on success;
                                           gate is P3.4 record_success)
========================================== ==============================

Adoption roadmap (see ``rebuild.md`` §4.4)
------------------------------------------
* P3.1 (✅) — :class:`ExploitInfo` dataclass.
* P3.2 (this PR) — move ``generate_docx_report`` here as
  ``generate_docx(info, out_dir)``; re-export from ``_legacy`` for
  backward compat in 1 call site (``handle_exploitation_success``).
* P3.3 — move ``generate_exploitation_code`` to
  ``autopwn/report/code.py``; switch this module's import.
* P3.6 — wrap the ``python-docx`` import in ``try/except ImportError``
  with a markdown fallback (see ``refactor.md`` §10).
* P3.4 — refactor ``handle_exploitation_success`` to construct an
  ``ExploitInfo`` directly and call ``report.record_success`` (no
  more dict bridge).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from autopwn.core.logging import Colors, print_error, print_success, VERSION
from autopwn.report.model import ExploitInfo
from autopwn.report.code import generate_code


def generate_docx(info: ExploitInfo, out_dir: Path) -> Optional[Path]:
    """Generate a DOCX exploitation report and return its path.

    Parameters
    ----------
    info : ExploitInfo
        Typed result of a successful exploitation run.  All 8 fields
        are read; ``success`` gate is **not** checked here (caller
        responsibility — P3.4 ``record_success``).
    out_dir : Path
        Directory to write ``{target}_wp.docx`` into.  Defaults to
        ``cwd`` (``Path('.')``) in the caller for backward compat;
        P3.5 will let users override via ``--report-dir``.

    Returns
    -------
    Path or None
        Path of the generated ``.docx`` on success; ``None`` on any
        failure (matches the legacy behavior of swallowing exceptions
        and printing an error — the caller is expected to log
        success/failure via ``ctx.log``).

    Side effects
    ------------
    * Writes ``{target}_wp.docx`` to ``out_dir``.
    * Prints success / error messages via ``core.logging``.
    """
    try:
        # Extract target name: basename without path / extension.
        # Legacy behavior strips a leading "./" defensively.
        target_name = Path(info.target_binary).name
        if target_name.startswith("./"):
            target_name = target_name[2:]
        target_name = Path(target_name).stem  # strip extension
        report_filename = f"{target_name}_wp.docx"
        report_path = out_dir / report_filename

        # python-docx imports (P3.6 will move to module-level with
        # try/except ImportError fallback to markdown).
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH

        # Build the document
        doc = Document()

        # Title
        title = doc.add_heading("PWN Exploitation Report", 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Basic information
        doc.add_heading("Basic Information", level=1)
        basic_info = doc.add_paragraph()
        basic_info.add_run("Target Binary: ").bold = True
        basic_info.add_run(f"{info.target_binary}\n")
        basic_info.add_run("Exploitation Time: ").bold = True
        basic_info.add_run(f"{info.timestamp}\n")
        basic_info.add_run("Architecture: ").bold = True
        basic_info.add_run(f"{info.architecture}\n")
        basic_info.add_run("Vulnerability Type: ").bold = True
        basic_info.add_run(f"{info.vulnerability_type}\n")
        basic_info.add_run("Exploitation Method: ").bold = True
        basic_info.add_run(f"{info.exploit_type}\n")

        # Buffer overflow information
        doc.add_heading("Buffer Overflow Information", level=1)
        padding_info = doc.add_paragraph()
        padding_info.add_run("Buffer Overflow Padding: ").bold = True
        padding_info.add_run(f"{info.padding} bytes\n")

        # Key address information (table)
        if info.addresses:
            doc.add_heading("Key Address Information", level=1)
            addr_table = doc.add_table(rows=1, cols=2)
            addr_table.style = "Table Grid"
            hdr_cells = addr_table.rows[0].cells
            hdr_cells[0].text = "Address Type"
            hdr_cells[1].text = "Address Value"

            for addr_type, addr_value in info.addresses.items():
                row_cells = addr_table.add_row().cells
                row_cells[0].text = addr_type
                # Hex formatting (verbatim from legacy L288-302)
                if isinstance(addr_value, int):
                    row_cells[1].text = f"0x{addr_value:x}"
                elif isinstance(addr_value, str) and addr_value.isdigit():
                    row_cells[1].text = f"0x{int(addr_value):x}"
                elif isinstance(addr_value, str) and addr_value.startswith("0x"):
                    row_cells[1].text = addr_value
                else:
                    try:
                        if "x" in str(addr_value):
                            row_cells[1].text = str(addr_value)
                        else:
                            row_cells[1].text = f"0x{int(str(addr_value)):x}"
                    except Exception:
                        row_cells[1].text = str(addr_value)

        # Exploitation code (only if we have a payload)
        if info.payload:
            doc.add_heading("Exploitation Code", level=1)
            payload_para = doc.add_paragraph()
            payload_para.add_run("Complete Python Exploitation Code:\n").bold = True

            # P3.3: code generator moved to report.code; signature is
            # (info, out_dir) -> str (forward-compat: out_dir may be
            # used in P3.4 / P3.5 to write a .py file artifact).
            exploitation_code = generate_code(info, out_dir)
            payload_para.add_run(f"{exploitation_code}\n")

            payload_para.add_run("Payload Length: ").bold = True
            if isinstance(info.payload, bytes):
                payload_para.add_run(f"{len(info.payload)} bytes\n")
            else:
                payload_para.add_run(f"{len(str(info.payload))} characters\n")

        # Exploitation summary
        doc.add_heading("Exploitation Summary", level=1)
        summary_para = doc.add_paragraph()
        summary_para.add_run("Exploitation Status: ").bold = True
        summary_para.add_run("Successful\n")
        summary_para.add_run("Exploitation Method: ").bold = True
        summary_para.add_run(
            f"Successfully gained shell access through {info.vulnerability_type} "
            f"vulnerability using {info.exploit_type} technique.\n"
        )

        # Footer
        doc.add_paragraph("\n" + "─" * 50)
        footer_para = doc.add_paragraph()
        footer_para.add_run("Report Generation Tool: ").bold = True
        footer_para.add_run(f"AutoPwn v{VERSION}\n")
        footer_para.add_run("Generation Time: ").bold = True
        footer_para.add_run(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Save
        doc.save(str(report_path))
        print_success(
            f"Exploitation report generated: {Colors.YELLOW}{report_path}{Colors.END}"
        )
        return report_path

    except Exception as e:
        print_error(f"Failed to generate report: {e}")
        return None


__all__ = ["generate_docx"]
