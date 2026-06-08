"""Unit tests for ``autopwn.primitives.shellcode`` (P6.6).

Per ``rebuild.md`` §6.7 P6.9 + §6.7 P6.6: every primitive needs
``build_payload(ctx) -> bytes`` asserted against a fake
address.  P6.6 has 2 primitives (``RwxShellcodeX32`` +
``RwxShellcodeX64``) that share the same shape:

    [shellcode.ljust(padding, asm('nop'))] [p32/p64(bss_addr)]

Neither v4.0's nor v3.1's ``Challenge/`` binaries have
RWX segments (verified via ``pwnlib.ELF`` segment flags), so
all real-binary smoke tests assert ``b""``.  The happy path
is exercised by monkey-patching the module-level
``_lookup_bss_addr`` helper to return a known address.

Test plan
---------
* :class:`RwxShellcodeX32` + :class:`RwxShellcodeX64`:
    * ``name`` + ``stage_count()`` = 1 (single-stage; no leak)
    * x32 / x64 bit-width gate (wrong bit → ``b""``)
    * ``rwx_segments=False`` → ``b""``
    * ``padding == 0`` → ``b""``
    * BSS lookup returns ``None`` (no large BSS) → ``b""``
    * Happy path (synthetic, monkey-patched BSS lookup):
        - x32 payload length = padding + 4
        - x32 payload starts with ``asm(shellcraft.sh())``
        - x32 ret addr = bss_addr (last 4 bytes)
        - x64 payload length = padding + 8
        - x64 ret addr = bss_addr (last 8 bytes)
    * Real-binary smoke: all 5 Challenge/ binaries → ``b""``
      (none have RWX segments)
"""
from __future__ import annotations

import pytest

from tests.conftest import ctx_for


pytestmark = pytest.mark.primitive


# Fake BSS address used in synthetic happy-path tests.
# Picked to be visually distinct in hex dumps.
_FAKE_BSS_ADDR_32 = 0x0804A050
_FAKE_BSS_ADDR_64 = 0x404060


def _ctx_rwx(binary_name, bit, padding=112, *, rwx=True):
    """Build a context with ``rwx_segments=True`` set explicitly."""
    ctx = ctx_for(binary_name, bit=bit)
    ctx.padding = padding
    # ctx_for sets rwx_segments=False by default; flip it for happy-path tests.
    ctx.binary = ctx.binary.__class__(
        path=ctx.binary.path, bit=bit,
        stack_canary=ctx.binary.stack_canary, pie=ctx.binary.pie,
        nx=ctx.binary.nx, relro=ctx.binary.relro,
        rwx_segments=rwx, stripped=ctx.binary.stripped,
    )
    return ctx


class TestShellcodeMetadata:
    """Class-level invariants for both primitives."""

    def test_x32_name_is_canonical(self):
        from autopwn.primitives.shellcode import RwxShellcodeX32

        assert RwxShellcodeX32.name == "rwx-shellcode-x32"

    def test_x64_name_is_canonical(self):
        from autopwn.primitives.shellcode import RwxShellcodeX64

        assert RwxShellcodeX64.name == "rwx-shellcode-x64"

    def test_x32_stage_count_is_one(self):
        """RWX shellcode is single-stage — no leak, no second stage."""
        from autopwn.primitives.shellcode import RwxShellcodeX32

        assert RwxShellcodeX32().stage_count() == 1

    def test_x64_stage_count_is_one(self):
        from autopwn.primitives.shellcode import RwxShellcodeX64

        assert RwxShellcodeX64().stage_count() == 1

    def test_x32_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.shellcode import RwxShellcodeX32

        assert issubclass(RwxShellcodeX32, ExploitPrimitive)

    def test_x64_subclass_of_exploit_primitive(self):
        from autopwn.primitives.base import ExploitPrimitive
        from autopwn.primitives.shellcode import RwxShellcodeX64

        assert issubclass(RwxShellcodeX64, ExploitPrimitive)

    def test_x32_re_exported(self):
        from autopwn.primitives import RwxShellcodeX32 as Re
        from autopwn.primitives.shellcode import RwxShellcodeX32 as FromMod

        assert Re is FromMod

    def test_x64_re_exported(self):
        from autopwn.primitives import RwxShellcodeX64 as Re
        from autopwn.primitives.shellcode import RwxShellcodeX64 as FromMod

        assert Re is FromMod


class TestRwxShellcodeX32EdgeCases:
    """All ``b""``-returning branches for x32."""

    def test_returns_empty_for_x64_binary(self, challenge_dir):
        """x32 primitive ignores x64 binaries (different ABI)."""
        from autopwn.primitives.shellcode import RwxShellcodeX32

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_rwx_segments_false(self, challenge_dir):
        """BSS is not RWX → can't execute the shellcode we just wrote."""
        from autopwn.primitives.shellcode import RwxShellcodeX32

        # fmtstr1 has no RWX (and no large BSS) — use it as the "no RWX" case
        ctx = _ctx_rwx("fmtstr1", bit=32, padding=80, rwx=False)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_padding_is_zero(self, challenge_dir):
        """padding == 0 means no room for shellcode + ret address."""
        from autopwn.primitives.shellcode import RwxShellcodeX32

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=0)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_no_bss_symbol(self, challenge_dir, monkeypatch):
        """No ``STT_OBJECT`` with ``st_size > 30`` → no storage location."""
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX32

        # Patch the helper to return None (no BSS found)
        monkeypatch.setattr(shellcode_mod, "_lookup_bss_addr", lambda p: None)

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=80, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b""


class TestRwxShellcodeX64EdgeCases:
    """All ``b""``-returning branches for x64."""

    def test_returns_empty_for_x32_binary(self, challenge_dir):
        """x64 primitive ignores x32 binaries (different ABI)."""
        from autopwn.primitives.shellcode import RwxShellcodeX64

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=80)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_rwx_segments_false(self, challenge_dir):
        from autopwn.primitives.shellcode import RwxShellcodeX64

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80, rwx=False)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_padding_is_zero(self, challenge_dir):
        from autopwn.primitives.shellcode import RwxShellcodeX64

        ctx = _ctx_rwx("level3_x64", bit=64, padding=0)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b""

    def test_returns_empty_when_no_bss_symbol(self, challenge_dir, monkeypatch):
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX64

        monkeypatch.setattr(shellcode_mod, "_lookup_bss_addr", lambda p: None)

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80, rwx=True)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b""


class TestRwxShellcodeX32HappyPath:
    """Synthetic happy path with monkey-patched BSS lookup (x32)."""

    def test_payload_length_is_padding_plus_4(self, challenge_dir, monkeypatch):
        """Layout: [shellcode.ljust(padding, nop)] [p32(bss_addr)] → padding + 4 bytes."""
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX32

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_32
        )

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=112, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)
        # 112 padding + 4 (p32 of BSS addr) = 116
        assert len(payload) == 112 + 4

    def test_payload_starts_with_shellcraft_sh(self, challenge_dir, monkeypatch):
        """First bytes must be ``asm(shellcraft.sh())`` — pwntools sh() emits ~44B x32."""
        from pwn import asm, shellcraft

        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX32

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_32
        )

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=200, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)

        sh = asm(shellcraft.sh())
        assert payload[:len(sh)] == sh, (
            f"first {len(sh)} bytes should be asm(shellcraft.sh()); "
            f"got {payload[:len(sh)].hex()!r}"
        )

    def test_ret_addr_is_fake_bss_addr(self, challenge_dir, monkeypatch):
        """The last 4 bytes are the BSS address (return target)."""
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX32

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_32
        )

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=80, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)
        import struct
        ret_addr = struct.unpack("<I", payload[-4:])[0]
        assert ret_addr == _FAKE_BSS_ADDR_32

    def test_middle_is_nop_sled(self, challenge_dir, monkeypatch):
        """Bytes between the shellcode and the ret address are NOPs."""
        from pwn import asm, shellcraft

        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX32

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_32
        )

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=200, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)

        sh = asm(shellcraft.sh())
        nop_sled = asm("nop")
        # shellcode occupies [0:len(sh)]; nop-sled is [len(sh):-4]
        middle = payload[len(sh):-4]
        assert middle == nop_sled * len(middle), (
            "bytes between shellcode and ret addr should all be NOPs"
        )


class TestRwxShellcodeX64HappyPath:
    """Synthetic happy path with monkey-patched BSS lookup (x64)."""

    def test_payload_length_is_padding_plus_8(self, challenge_dir, monkeypatch):
        """x64 layout: [shellcode.ljust(padding, nop)] [p64(bss_addr)] → padding + 8 bytes."""
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX64

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_64
        )

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80, rwx=True)
        payload = RwxShellcodeX64().build_payload(ctx)
        # 80 padding + 8 (p64 of BSS addr) = 88
        assert len(payload) == 80 + 8

    def test_ret_addr_is_fake_bss_addr(self, challenge_dir, monkeypatch):
        """The last 8 bytes are the BSS address (return target)."""
        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX64

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_64
        )

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80, rwx=True)
        payload = RwxShellcodeX64().build_payload(ctx)
        import struct
        ret_addr = struct.unpack("<Q", payload[-8:])[0]
        assert ret_addr == _FAKE_BSS_ADDR_64

    def test_payload_starts_with_shellcraft_sh(self, challenge_dir, monkeypatch):
        """x64 ``asm(shellcraft.sh())`` is ~48 bytes — first bytes match."""
        from pwn import asm, shellcraft

        from autopwn.primitives import shellcode as shellcode_mod
        from autopwn.primitives.shellcode import RwxShellcodeX64

        monkeypatch.setattr(
            shellcode_mod, "_lookup_bss_addr", lambda p: _FAKE_BSS_ADDR_64
        )

        ctx = _ctx_rwx("level3_x64", bit=64, padding=200, rwx=True)
        payload = RwxShellcodeX64().build_payload(ctx)

        sh = asm(shellcraft.sh())
        assert payload[:len(sh)] == sh, (
            f"first {len(sh)} bytes should be asm(shellcraft.sh()); "
            f"got {payload[:len(sh)].hex()!r}"
        )


class TestRwxShellcodeRealBinarySmoke:
    """None of the Challenge/ binaries have RWX segments — all return ``b""``.

    Verified externally: ``pwnlib.ELF`` shows no PT_LOAD segment
    with all of R/W/X flags for any of canary/fmtstr1/level3_x64/
    pie/rip.  So the primitive is correctly a no-op on every
    current target.
    """

    @pytest.mark.parametrize("binary,bit", [
        ("canary", 32),
        ("fmtstr1", 32),
        ("level3_x64", 64),
        ("pie", 64),
        ("rip", 64),
    ])
    def test_x32_returns_empty_for_real_binary(self, challenge_dir, binary, bit):
        """``RwxShellcodeX32`` returns ``b""`` for every Challenge/ binary."""
        from autopwn.primitives.shellcode import RwxShellcodeX32

        ctx = _ctx_rwx(binary, bit=bit, padding=80)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b"", f"{binary} should return b'' (no RWX)"

    @pytest.mark.parametrize("binary,bit", [
        ("canary", 32),
        ("fmtstr1", 32),
        ("level3_x64", 64),
        ("pie", 64),
        ("rip", 64),
    ])
    def test_x64_returns_empty_for_real_binary(self, challenge_dir, binary, bit):
        """``RwxShellcodeX64`` returns ``b""`` for every Challenge/ binary."""
        from autopwn.primitives.shellcode import RwxShellcodeX64

        ctx = _ctx_rwx(binary, bit=bit, padding=80)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b"", f"{binary} should return b'' (no RWX)"

    def test_x32_rwx_flag_override_still_returns_empty(self, challenge_dir):
        """Even forcing ``rwx_segments=True`` returns ``b""`` (no BSS symbols).

        Verifies the second gate (BSS lookup) — fmtstr1 has
        no ``STT_OBJECT`` with ``st_size > 30``, so the
        primitive correctly bails even when the RWX flag is
        artificially set.
        """
        from autopwn.primitives.shellcode import RwxShellcodeX32

        ctx = _ctx_rwx("fmtstr1", bit=32, padding=80, rwx=True)
        payload = RwxShellcodeX32().build_payload(ctx)
        assert payload == b""

    def test_x64_rwx_flag_override_still_returns_empty(self, challenge_dir):
        from autopwn.primitives.shellcode import RwxShellcodeX64

        ctx = _ctx_rwx("level3_x64", bit=64, padding=80, rwx=True)
        payload = RwxShellcodeX64().build_payload(ctx)
        assert payload == b""
