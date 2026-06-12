"""core.logging — Colors + print_* utilities.

Refactored from autopwn._legacy (P1.1).

Layer: core (no upward dependency).
"""
from __future__ import annotations

import datetime
import os
import sys

from autopwn import __author__ as AUTHOR
from autopwn import __github__ as GITHUB
from autopwn import __org__ as ORG_CN
from autopwn import __version__ as VERSION

VERBOSE = False


class Colors:
    DEBUG = '\033[90m'
    DIM = '\033[2m'
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    INFO = '\033[1;34m'
    SUCCESS = '\033[1;32m'
    WARNING = '\033[1;33m'
    ERROR = '\033[1;31m'
    CRITICAL = '\033[1;35m'
    PAYLOAD = '\033[1;36m'


def print_banner():
    """AutoPwn v4.0 startup banner (box style, v4 onward)."""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
    ┌────────────────────────────────────────────────────────────────┐
    │                                                                │
    │   {Colors.YELLOW}AutoPwn{Colors.CYAN}  ·  Automated Binary Exploitation Framework          │
    │                                                                │
    │   v{VERSION:<10}  by {AUTHOR}{Colors.CYAN}  ({ORG_CN})           │
    │   {Colors.UNDERLINE}{GITHUB}{Colors.END}{Colors.CYAN}                           │
    │                                                                │
    └────────────────────────────────────────────────────────────────┘
{Colors.END}
"""
    print(banner)


def print_debug(message, prefix="[DEBUG]"):
    """Print debug message (only when VERBOSE=True or AUTOPWN_DEBUG=1)."""
    if not (VERBOSE or os.environ.get("AUTOPWN_DEBUG") == "1"):
        return
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.DEBUG}{prefix}{Colors.END} {Colors.DIM}[{timestamp}]{Colors.END} {message}", file=sys.stderr)


def print_info(message, prefix="[*]"):
    """Print info message with sqlmap-style formatting."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.INFO}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_success(message, prefix="[+]"):
    """Print success message."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.SUCCESS}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_warning(message, prefix="[!]"):
    """Print warning message."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.WARNING}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_error(message, prefix="[-]"):
    """Print error message."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.ERROR}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_critical(message, prefix="[CRITICAL]"):
    """Print critical message."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.CRITICAL}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_payload(message, prefix="[PAYLOAD]"):
    """Print payload information."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.PAYLOAD}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")


def print_section_header(title):
    """Print section header with decorative lines."""
    print_debug(f"phase: {title}")
    line = "─" * 60
    print(f"\n{Colors.BOLD}{Colors.BLUE}┌{line}┐{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}│{Colors.END} {Colors.BOLD}{title.center(58)}{Colors.END} {Colors.BOLD}{Colors.BLUE}│{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}└{line}┘{Colors.END}")


def print_progress(current, total, task_name):
    """Print progress bar similar to sqlmap."""
    percentage = int((current / total) * 100)
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    print(f"\r{Colors.INFO}[*]{Colors.END} {task_name}: {Colors.CYAN}[{bar}]{Colors.END} {percentage}%", end='', flush=True)
    if current == total:
        print_info("")


def print_table_header(headers):
    """Print table header."""
    header_line = " | ".join([f"{h:^15}" for h in headers])
    separator = "-" * len(header_line)
    print(f"{Colors.BOLD}{header_line}{Colors.END}")
    print(separator)


def print_table_row(values, colors=None):
    """Print table row with optional colors."""
    if colors is None:
        colors = [Colors.END] * len(values)

    formatted_values = []
    for i, (value, color) in enumerate(zip(values, colors)):
        formatted_values.append(f"{color}{str(value):^15}{Colors.END}")

    row_line = " | ".join(formatted_values)
    print(row_line)


def set_verbose(value: bool) -> None:
    """Set the global VERBOSE flag (called by main() from -v / --verbose).

    P1.1: print_debug lives in this module, so its closure reads core.logging.VERBOSE.
    CLI must use this setter instead of rebinding a re-exported VERBOSE in its own
    namespace (which would shadow but not propagate).
    """
    global VERBOSE
    VERBOSE = value


__all__ = [
    "VERSION", "AUTHOR", "GITHUB", "ORG_CN", "VERBOSE",
    "Colors",
    "print_banner", "print_debug", "print_info", "print_success",
    "print_warning", "print_error", "print_critical", "print_payload",
    "print_section_header", "print_progress",
    "print_table_header", "print_table_row",
    "set_verbose",
]
