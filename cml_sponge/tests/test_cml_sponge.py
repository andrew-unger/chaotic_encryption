"""
Test suite for CML-Sponge stream cipher.

Run with pytest:
    python -m pytest tests/test_cml_sponge.py -v

Run standalone:
    python tests/test_cml_sponge.py
"""

from __future__ import annotations

import os
import sys
import random
import struct

# ---------------------------------------------------------------------------
# Path setup — allow running from the project root or from tests/
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from cml_sponge import (
    cipher_init,
    keystream,
    cipher_encrypt,
    cipher_decrypt,
    CMLSpongeState,
    BLOCK_BYTES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_key(seed: int = 42) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(32))


def _make_iv(seed: int = 0) -> bytes:
    rng = random.Random(seed + 1000)
    return bytes(rng.getrandbits(8) for _ in range(16))


def _flip_bit(b: bytes, bit_index: int) -> bytes:
    """Return b with bit bit_index (0=MSB of byte 0) flipped."""
    arr = bytearray(b)
    byte_idx = bit_index // 8
    bit_off = 7 - (bit_index % 8)
    arr[byte_idx] ^= (1 << bit_off)
    return bytes(arr)


def _count_differing_bits(a: bytes, b: bytes) -> int:
    """Count the number of bits that differ between two equal-length byte strings."""
    assert len(a) == len(b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

def test_determinism() -> None:
    """Identical key+IV must produce identical keystream on two independent runs."""
    key = _make_key(1)
    iv = _make_iv(1)

    state_a = cipher_init(key, iv)
    state_b = cipher_init(key, iv)

    ks_a = keystream(state_a, 128)
    ks_b = keystream(state_b, 128)

    assert ks_a == ks_b, "Keystream is not deterministic"


def test_key_avalanche() -> None:
    """
    Flipping 1 bit in the key should flip ≈50% of output bits.
    Accept 180–332 differing bits out of 512 (64 bytes × 8 bits).
    That is 35.2%–64.8%, a generous ±15% window around 50%.
    """
    key = _make_key(2)
    iv = _make_iv(2)
    flipped_key = _flip_bit(key, 17)  # flip bit 17

    state_a = cipher_init(key, iv)
    state_b = cipher_init(flipped_key, iv)

    ks_a = keystream(state_a, 64)
    ks_b = keystream(state_b, 64)

    diff = _count_differing_bits(ks_a, ks_b)
    print(f"  key_avalanche: {diff}/512 bits differ ({100*diff/512:.1f}%)")
    assert 180 < diff < 332, (
        f"Key avalanche outside [180, 332]: got {diff} differing bits"
    )


def test_iv_avalanche() -> None:
    """
    Flipping 1 bit in the IV should flip ≈50% of output bits.
    Accept 180–332 differing bits out of 512.
    """
    key = _make_key(3)
    iv = _make_iv(3)
    flipped_iv = _flip_bit(iv, 5)  # flip bit 5

    state_a = cipher_init(key, iv)
    state_b = cipher_init(key, flipped_iv)

    ks_a = keystream(state_a, 64)
    ks_b = keystream(state_b, 64)

    diff = _count_differing_bits(ks_a, ks_b)
    print(f"  iv_avalanche: {diff}/512 bits differ ({100*diff/512:.1f}%)")
    assert 180 < diff < 332, (
        f"IV avalanche outside [180, 332]: got {diff} differing bits"
    )


def test_keystream_changes_with_iv() -> None:
    """
    100 random IVs with the same key must all produce distinct 64-byte keystreams.
    Collision probability is negligible (birthday paradox on 2^512 space).
    """
    key = _make_key(4)
    rng = random.Random(4)

    seen: set = set()
    for _ in range(100):
        iv = bytes(rng.getrandbits(8) for _ in range(16))
        state = cipher_init(key, iv)
        ks = keystream(state, 64)
        assert ks not in seen, "Two different IVs produced the same keystream"
        seen.add(ks)


def test_round_trip() -> None:
    """
    For 1000 random (key, iv, plaintext) triples, decrypt(encrypt(pt)) == pt.
    """
    rng = random.Random(5)
    for _ in range(1000):
        key = bytes(rng.getrandbits(8) for _ in range(32))
        iv = bytes(rng.getrandbits(8) for _ in range(16))
        length = rng.randint(0, 200)
        pt = bytes(rng.getrandbits(8) for _ in range(length))

        enc_state = cipher_init(key, iv)
        dec_state = cipher_init(key, iv)

        ct = cipher_encrypt(enc_state, pt)
        recovered = cipher_decrypt(dec_state, ct)
        assert recovered == pt, f"Round-trip failed for length {length}"


def test_chi_square() -> None:
    """
    1 MB of keystream should have a byte-frequency chi-square statistic
    close to 255 (degrees of freedom).  We accept 175 < chi_sq < 350.

    With 1 048 576 bytes, expected frequency per byte = 4096.0.
    Uniform: chi_sq ≈ 255.  The ±4σ bounds (Bonferroni-safe) are ≈ 175–350.
    """
    key = _make_key(6)
    iv = _make_iv(6)
    state = cipher_init(key, iv)

    n_bytes = 1 << 20  # 1 048 576
    data = keystream(state, n_bytes)

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    expected = n_bytes / 256.0  # 4096.0
    chi_sq = sum((c - expected) ** 2 / expected for c in counts)
    print(f"  chi_square: {chi_sq:.2f} (255 dof, bounds [175, 350])")
    assert 175 < chi_sq < 350, (
        f"Chi-square {chi_sq:.2f} outside bounds [175, 350]"
    )


def test_empty_plaintext() -> None:
    """Encrypting an empty byte string returns an empty byte string."""
    key = _make_key(7)
    iv = _make_iv(7)
    state = cipher_init(key, iv)
    assert cipher_encrypt(state, b"") == b""


def test_single_byte() -> None:
    """A single byte round-trips correctly."""
    key = _make_key(8)
    iv = _make_iv(8)

    enc_state = cipher_init(key, iv)
    dec_state = cipher_init(key, iv)

    ct = cipher_encrypt(enc_state, b"\xAB")
    pt = cipher_decrypt(dec_state, ct)
    assert pt == b"\xAB"


def test_large_plaintext() -> None:
    """Encrypt and decrypt a 1 MB plaintext correctly."""
    key = _make_key(9)
    iv = _make_iv(9)
    rng = random.Random(9)

    pt = bytes(rng.getrandbits(8) for _ in range(1 << 20))

    enc_state = cipher_init(key, iv)
    dec_state = cipher_init(key, iv)

    ct = cipher_encrypt(enc_state, pt)
    recovered = cipher_decrypt(dec_state, ct)
    assert recovered == pt, "1 MB round-trip failed"


def test_all_zero_key() -> None:
    """An all-zero key must not produce an all-zero keystream."""
    key = b"\x00" * 32
    iv = _make_iv(10)
    state = cipher_init(key, iv)
    ks = keystream(state, 64)
    assert ks != b"\x00" * 64, "All-zero key produced all-zero keystream"


def test_all_zero_iv() -> None:
    """An all-zero IV must not produce an all-zero keystream."""
    key = _make_key(11)
    iv = b"\x00" * 16
    state = cipher_init(key, iv)
    ks = keystream(state, 64)
    assert ks != b"\x00" * 64, "All-zero IV produced all-zero keystream"


def test_block_boundary() -> None:
    """
    192 bytes of keystream in one call == three 64-byte calls on a fresh state.

    This exercises the buffering logic: the second and third sub-calls each
    span a permutation boundary (at byte 64 and 128 respectively).
    """
    key = _make_key(12)
    iv = _make_iv(12)

    # Single call
    state_a = cipher_init(key, iv)
    big = keystream(state_a, 192)

    # Three calls on a separate but identical initial state
    state_b = cipher_init(key, iv)
    chunk1 = keystream(state_b, 64)
    chunk2 = keystream(state_b, 64)
    chunk3 = keystream(state_b, 64)

    assert big == chunk1 + chunk2 + chunk3, (
        "Block-boundary buffering inconsistency detected"
    )


def test_state_serialize() -> None:
    """
    Serialize state mid-stream, deserialize into a new object, continue
    generating.  Output must match uninterrupted generation.
    """
    key = _make_key(13)
    iv = _make_iv(13)

    # Reference: generate 200 bytes uninterrupted.
    ref_state = cipher_init(key, iv)
    _ = keystream(ref_state, 70)   # advance past one full block
    ref_tail = keystream(ref_state, 130)

    # Test: advance 70 bytes, serialize, restore, generate 130 bytes.
    test_state = cipher_init(key, iv)
    _ = keystream(test_state, 70)
    blob = test_state.serialize()
    restored = CMLSpongeState.deserialize(blob)
    test_tail = keystream(restored, 130)

    assert test_tail == ref_tail, (
        "Serialized/deserialized state produced different keystream"
    )


def test_plaintext_avalanche() -> None:
    """
    Stream cipher property: flipping 1 bit in the plaintext flips exactly 1
    bit in the ciphertext (XOR keystream means changes are local).
    """
    key = _make_key(14)
    iv = _make_iv(14)
    rng = random.Random(14)

    pt = bytes(rng.getrandbits(8) for _ in range(64))
    pt_flipped = _flip_bit(pt, 23)  # flip bit 23

    state_a = cipher_init(key, iv)
    state_b = cipher_init(key, iv)

    ct_a = cipher_encrypt(state_a, pt)
    ct_b = cipher_encrypt(state_b, pt_flipped)

    diff = _count_differing_bits(ct_a, ct_b)
    assert diff == 1, (
        f"Stream cipher must change exactly 1 bit when 1 plaintext bit flips; "
        f"got {diff} differing bits"
    )


# ---------------------------------------------------------------------------
# Standalone runner (python tests/test_cml_sponge.py)
# ---------------------------------------------------------------------------

TESTS = [
    ("test_determinism",           test_determinism),
    ("test_key_avalanche",         test_key_avalanche),
    ("test_iv_avalanche",          test_iv_avalanche),
    ("test_keystream_changes_iv",  test_keystream_changes_with_iv),
    ("test_round_trip",            test_round_trip),
    ("test_chi_square",            test_chi_square),
    ("test_empty_plaintext",       test_empty_plaintext),
    ("test_single_byte",           test_single_byte),
    ("test_large_plaintext",       test_large_plaintext),
    ("test_all_zero_key",          test_all_zero_key),
    ("test_all_zero_iv",           test_all_zero_iv),
    ("test_block_boundary",        test_block_boundary),
    ("test_state_serialize",       test_state_serialize),
    ("test_plaintext_avalanche",   test_plaintext_avalanche),
]


def run_all() -> None:
    """Run all tests and print pass/fail for each."""
    print("=" * 60)
    print("CML-Sponge Test Suite")
    print("=" * 60)
    passed = 0
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {name}: {exc}")
            failed += 1
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {len(TESTS)} tests")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_all()
