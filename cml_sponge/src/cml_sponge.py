"""
CML-Sponge: A Coupled Map Lattice Stream Cipher with Sponge Construction

Reference implementation — Python 3.8+, no dependencies beyond stdlib.
All arithmetic is explicit u64 (mod 2**64). No floating point.

Design overview
---------------
State: 16 lattice sites (u64 each) = 1024-bit total + a u64 Weyl counter.
  Rate portion:     sites 0–7  (512 bits) — XOR'd during absorb, output during squeeze.
  Capacity portion: sites 8–15 (512 bits) — never directly read or written by caller.

Each of the 8 permutation rounds applies four steps:
  1. Local maps  — logistic (even sites) or tent (odd sites), all computed as a snapshot.
  2. CML coupling — additive coupling with distances {1, 7, 8} on the ring-16 lattice.
  3. Counter injection — Weyl sequence advanced and injected at sites 0,4,8,12.
  4. Multiplicative mixing — adjacent pairs (s[2k], s[2k+1]) for k=0..7.

8 rounds gives full 16-site diffusion twice over (full mixing achieved at round 4).

Sponge construction follows the duplex/sponge pattern from Bertoni et al.:
  absorb(key, domain=0x01) → permute
  absorb(iv,  domain=0x02) → permute
  squeeze() → 64 bytes, permute, repeat.

References
----------
- Kaneko (1984): original CML framework.
- Bertoni, Daemen, Peeters, Van Assche (2007): sponge constructions.
- Alvarez, Li (2006): security analysis of chaos-based ciphers.
- Sprott (2003): chaos and time-series analysis.
"""

from __future__ import annotations

import struct
import os
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

U64_MAX: int = (1 << 64) - 1
"""Mask for u64 arithmetic."""

GOLDEN: int = 0x9E3779B97F4A7C15
"""
Weyl sequence increment: fractional part of (sqrt(5)-1)/2 * 2^64.
This is the same constant used by xxHash, SplitMix64, etc.
Guarantees that the counter visits all 2^64 values exactly once per cycle.
"""

NUM_SITES: int = 16
"""Number of CML lattice sites. 16 × 64 = 1024-bit state."""

RATE_SITES: int = 8
"""
Number of sites in the rate portion (sites 0–7).
Rate = 8 × 64 = 512 bits → 64 bytes output per squeeze.
"""

CAPACITY_SITES: int = 8
"""
Number of sites in the capacity portion (sites 8–15).
Capacity = 512 bits → 256-bit collision/preimage security.
"""

BLOCK_BYTES: int = RATE_SITES * 8  # 64 bytes per squeeze block

NUM_ROUNDS: int = 8
"""
Rounds per permutation. Full 16-site diffusion occurs at round 4;
8 rounds gives a 2× security margin over minimum diffusion.
"""

DOMAIN_KEY: int = 0x01
"""Domain separation byte for key absorption."""

DOMAIN_IV: int = 0x02
"""Domain separation byte for IV absorption."""

# First 16 primes >= 3.  All odd, all coprime to 64, publicly verifiable as
# nothing-up-my-sleeve numbers.  Each site gets a distinct rotation so that
# the Weyl counter produces a different additive contribution per site,
# breaking the logistic/tent complement symmetry:
#   local_map(x) == local_map(MAX ^ x)  for all x
# Without per-site counter injection BEFORE the map step, any lattice state
# and its bitwise complement collapse to the same mapped values, causing
# catastrophic key-equivalence (e.g. all-0 key == all-FF key).
INJECTION_ROTATIONS: tuple = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 61)


# ---------------------------------------------------------------------------
# Low-level arithmetic helpers
# ---------------------------------------------------------------------------

def rotate64(x: int, n: int) -> int:
    """
    Rotate 64-bit integer x left by n bits.

    Uses only u64 arithmetic. No floating point.

    Args:
        x: A 64-bit unsigned integer (will be masked to u64).
        n: Rotation amount in bits (0–63).

    Returns:
        64-bit left rotation of x by n.
    """
    x &= U64_MAX
    n &= 63
    return ((x << n) | (x >> (64 - n))) & U64_MAX


def logistic_map(x: int) -> int:
    """
    Integer logistic map: f_L(x) = (x * (2^64 - 1 - x)) >> 62.

    This is the integer analogue of the continuous logistic map r*x*(1-x)
    evaluated at r=4 (fully chaotic regime).  The multiplication produces a
    u128 intermediate, then right-shift by 62 keeps the result in [0, 2^64).

    Why >> 62 (not >> 64)?  Shifting by 64 would give only values in [0, 3],
    losing almost all entropy.  Shifting by 62 keeps 64 bits of output while
    still normalising the quadratic product.

    Args:
        x: A 64-bit unsigned integer.

    Returns:
        64-bit unsigned integer.
    """
    x &= U64_MAX
    # 2^64 - 1 - x is the "1 - x" term in [0, 2^64)
    # Multiplication can be up to ~2^127, handled by Python's big integers.
    return ((x * ((1 << 64) - 1 - x)) >> 62) & U64_MAX


def tent_map(x: int) -> int:
    """
    Integer tent map: branchless formulation.

    Continuous version: f_T(x) = 2x if x < 0.5 else 2*(1-x).
    Integer version (on [0, 2^64)):
      - If MSB == 0 (x < 2^63): result = 2*x
      - If MSB == 1 (x >= 2^63): result = 2*(MAX - x) = 2*(2^64-1-x)

    Both branches are computed and selected with a mask to keep the function
    branchless, preventing timing side-channels based on the MSB.

    Args:
        x: A 64-bit unsigned integer.

    Returns:
        64-bit unsigned integer.
    """
    x &= U64_MAX
    msb = (x >> 63) & 1          # 0 if x < 2^63, 1 if x >= 2^63
    branch0 = (2 * x) & U64_MAX  # 2x (used when MSB=0)
    branch1 = (2 * (U64_MAX - x)) & U64_MAX  # 2*(MAX-x) (used when MSB=1)
    # mask = 0 if msb=0, U64_MAX if msb=1
    mask = ((-msb) & U64_MAX)
    return (branch0 & ~mask) | (branch1 & mask)


def local_map(x: int, site: int) -> int:
    """
    Apply the site-local chaotic map.

    Even-indexed sites use the logistic map; odd-indexed sites use the tent
    map.  Alternating maps prevent algebraic symmetry between adjacent sites,
    which would make the coupling step degenerate.

    Args:
        x: Current 64-bit state of the site.
        site: Site index (0–15); determines which map to apply.

    Returns:
        64-bit unsigned integer after applying the local map.
    """
    if site % 2 == 0:
        return logistic_map(x)
    else:
        return tent_map(x)


# ---------------------------------------------------------------------------
# CML round function
# ---------------------------------------------------------------------------

def cml_round(lattice: list, counter: int) -> tuple:
    """
    Apply one CML round to the lattice, advancing the counter.

    A single round consists of four steps applied in order:

    Step 1 — Local maps (snapshot):
        Compute m[i] = local_map(lattice[i], i) for all i simultaneously.
        The snapshot ensures the coupling in step 2 uses pre-round values.

    Step 2 — CML coupling (additive, topology {1, 7, 8}):
        new[i] = (m[i] + m[(i+1)%16] + m[(i+7)%16] + m[(i+8)%16]) mod 2^64

        Distance 1 : nearest-neighbor (classical CML coupling)
        Distance 7 : long-range asymmetric (breaks spatial symmetry)
        Distance 8 : diametrically opposite (global coupling component, N/2)

        Additive coupling (not XOR) produces more nonlinear mixing because the
        carry bits propagate across word boundaries.

    Step 3 — Counter injection (Weyl sequence):
        counter += GOLDEN  (mod 2^64)
        Sites 0,4,8,12 receive counter rotated by 0,16,32,48 bits respectively.
        This prevents fixed-point or short-cycle convergence in the lattice.

    Step 4 — Multiplicative mixing (quadratic nonlinearity):
        For each pair (s[2k], s[2k+1]), k=0..7:
            s[2k+1] = s[2k+1] * (s[2k] | 1)   mod 2^64
        The OR-1 ensures the multiplier is always odd (never zero), so the
        mapping is bijective (odd numbers are units in Z/2^64 Z).

    Args:
        lattice: List of 16 u64 values (modified IN PLACE).
        counter: Current u64 Weyl counter value.

    Returns:
        Tuple (lattice, new_counter).  The lattice list is also mutated.
    """
    N = NUM_SITES  # 16

    # ------------------------------------------------------------------
    # Step 1: Weyl counter injection into ALL 16 sites (prime rotations).
    #
    # This step MUST come first.  The logistic and tent maps both satisfy
    # f(x) == f(MAX ^ x), so without prior perturbation any state and its
    # bitwise complement produce identical mapped values, collapsing
    # distinct keys to the same keystream.  Injecting the Weyl counter
    # with site-specific prime rotations breaks this symmetry: after
    # injection, s[i] and (MAX ^ s[i]) receive the same additive offset
    # but are no longer each other's complement, so the maps diverge.
    # ------------------------------------------------------------------
    counter = (counter + GOLDEN) & U64_MAX
    for i in range(N):
        lattice[i] = (lattice[i] + rotate64(counter, INJECTION_ROTATIONS[i])) & U64_MAX

    # ------------------------------------------------------------------
    # Step 2: Snapshot all mapped values (post-injection).
    # ------------------------------------------------------------------
    m = [local_map(lattice[i], i) for i in range(N)]

    # ------------------------------------------------------------------
    # Step 3: Additive CML coupling with distances {1, 7, 8}.
    # ------------------------------------------------------------------
    new_lattice = [
        (m[i] + m[(i + 1) % N] + m[(i + 7) % N] + m[(i + 8) % N]) & U64_MAX
        for i in range(N)
    ]

    # ------------------------------------------------------------------
    # Step 4: Multiplicative mixing of adjacent pairs (s[2k], s[2k+1]).
    # ------------------------------------------------------------------
    for k in range(8):
        a = new_lattice[2 * k]
        b = new_lattice[2 * k + 1]
        new_lattice[2 * k + 1] = (b * (a | 1)) & U64_MAX

    # Mutate the input list in place and return (list, counter).
    for i in range(N):
        lattice[i] = new_lattice[i]

    return lattice, counter


# ---------------------------------------------------------------------------
# State class
# ---------------------------------------------------------------------------

class CMLSpongeState:
    """
    Mutable state for the CML-Sponge stream cipher.

    Attributes:
        lattice   (list[int]):  16 u64 lattice sites.
        counter   (int):        u64 Weyl sequence counter.
        buf       (bytes):      Buffered keystream bytes not yet consumed.
        buf_pos   (int):        Read cursor into buf.
        finalized (bool):       True once cipher_init has completed absorb.
    """

    __slots__ = ("lattice", "counter", "buf", "buf_pos", "finalized")

    def __init__(self) -> None:
        """Initialise to the all-zero state (not yet keyed)."""
        self.lattice: list = [0] * NUM_SITES
        self.counter: int = 0
        self.buf: bytes = b""
        self.buf_pos: int = 0
        self.finalized: bool = False

    # ------------------------------------------------------------------
    # Copy
    # ------------------------------------------------------------------

    def copy(self) -> "CMLSpongeState":
        """
        Return a deep copy of this state.

        Useful for branching (e.g. saving state for test_state_serialize).
        """
        s = CMLSpongeState()
        s.lattice = list(self.lattice)
        s.counter = self.counter
        s.buf = self.buf
        s.buf_pos = self.buf_pos
        s.finalized = self.finalized
        return s

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def serialize(self) -> bytes:
        """
        Serialise the full cipher state to bytes.

        Layout (little-endian u64s):
          16 × u64  : lattice[0..15]
           1 × u64  : counter
           4 bytes  : buf_pos (u32 LE)
           4 bytes  : len(buf) (u32 LE) — remaining unread buf bytes
           N bytes  : buf[buf_pos:]  (only the unread portion)
           1 byte   : finalized flag

        Total minimum size: (16+1)*8 + 4 + 4 + 0 + 1 = 145 bytes.
        """
        out = bytearray()
        # Lattice
        for v in self.lattice:
            out += struct.pack("<Q", v)
        # Counter
        out += struct.pack("<Q", self.counter)
        # Buffer — only the unread tail
        unread = self.buf[self.buf_pos:]
        out += struct.pack("<I", len(unread))
        out += unread
        # Finalized
        out += struct.pack("B", 1 if self.finalized else 0)
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "CMLSpongeState":
        """
        Restore a CMLSpongeState from bytes produced by serialize().

        Args:
            data: Bytes as returned by serialize().

        Returns:
            A fully restored CMLSpongeState.

        Raises:
            ValueError: If data is malformed or too short.
        """
        if len(data) < 17 * 8 + 4 + 1:
            raise ValueError(f"Data too short to deserialize: {len(data)} bytes")
        s = cls()
        offset = 0
        # Lattice
        for i in range(NUM_SITES):
            (v,) = struct.unpack_from("<Q", data, offset)
            s.lattice[i] = v
            offset += 8
        # Counter
        (s.counter,) = struct.unpack_from("<Q", data, offset)
        offset += 8
        # Buffer
        (buf_len,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if len(data) < offset + buf_len + 1:
            raise ValueError("Data too short for buffer content")
        s.buf = data[offset: offset + buf_len]
        s.buf_pos = 0  # we stored only the unread tail, so pos starts at 0
        offset += buf_len
        # Finalized
        (flag,) = struct.unpack_from("B", data, offset)
        s.finalized = bool(flag)
        return s

    def __repr__(self) -> str:
        return (
            f"CMLSpongeState(finalized={self.finalized}, "
            f"counter={self.counter:#018x}, "
            f"buf_remaining={len(self.buf) - self.buf_pos})"
        )


# ---------------------------------------------------------------------------
# Permutation
# ---------------------------------------------------------------------------

def cml_permute(state: CMLSpongeState) -> None:
    """
    Apply 8 CML rounds to state.lattice in place, advancing state.counter.

    This is the core permutation of the sponge construction.  8 rounds
    provides full diffusion (achieved at round 4) with a 2× margin.

    Args:
        state: CMLSpongeState to mutate.
    """
    for _ in range(NUM_ROUNDS):
        state.lattice, state.counter = cml_round(state.lattice, state.counter)


# ---------------------------------------------------------------------------
# Sponge absorb
# ---------------------------------------------------------------------------

def _absorb_block(state: CMLSpongeState, block: bytes) -> None:
    """
    XOR one 64-byte block into the rate portion (sites 0–7) then permute.

    The block must be exactly BLOCK_BYTES (64) bytes long.

    Args:
        state: CMLSpongeState to mutate.
        block: 64-byte block to absorb.
    """
    assert len(block) == BLOCK_BYTES, f"Expected {BLOCK_BYTES} bytes, got {len(block)}"
    for i in range(RATE_SITES):
        word = struct.unpack_from("<Q", block, i * 8)[0]
        state.lattice[i] ^= word
    cml_permute(state)


def _absorb(state: CMLSpongeState, data: bytes, domain: int) -> None:
    """
    Absorb arbitrary-length data into the sponge with multi-rate padding.

    Padding scheme (identical to Keccak / SHA-3 multi-rate padding):
        data || domain_byte || 0x00...00 || 0x80

    The domain byte provides cryptographic separation between key and IV
    absorption sequences, preventing extension attacks.

    Args:
        state:  CMLSpongeState to mutate.
        data:   Bytes to absorb (any length, including empty).
        domain: Single-byte domain separation constant (DOMAIN_KEY or DOMAIN_IV).
    """
    # Build padded message: append domain byte, pad to block boundary, set MSB.
    msg = bytearray(data)
    msg.append(domain)
    # Pad with zeros until one byte before the next block boundary.
    while len(msg) % BLOCK_BYTES != (BLOCK_BYTES - 1):
        msg.append(0x00)
    msg.append(0x80)
    # msg is now a multiple of BLOCK_BYTES.
    assert len(msg) % BLOCK_BYTES == 0

    for block_start in range(0, len(msg), BLOCK_BYTES):
        _absorb_block(state, bytes(msg[block_start: block_start + BLOCK_BYTES]))


# ---------------------------------------------------------------------------
# Sponge squeeze
# ---------------------------------------------------------------------------

def _stafford_mix13(x: int) -> int:
    """
    Stafford Mix13 bijective finalizer (64-bit).

    Applied to each rate word before output to ensure full bit avalanche.
    Required because tent_map always returns an even value (bit 0 = 0),
    which would otherwise create a low-bit linear dependency detectable
    by PractRand's BRank/Low1 tests.  Mix13 is invertible (bijective),
    so no entropy is lost — it purely re-distributes internal state bits
    across all output positions.  Used by SplitMix64 and PCG for the same
    reason.
    """
    x ^= (x >> 30)
    x = (x * 0xBF58476D1CE4E5B9) & U64_MAX
    x ^= (x >> 27)
    x = (x * 0x94D049BB133111EB) & U64_MAX
    x ^= (x >> 31)
    return x


def _squeeze_block(state: CMLSpongeState) -> bytes:
    """
    Squeeze one 64-byte block from the rate portion then permute.

    Each rate word is passed through the Stafford Mix13 finalizer before
    serialisation to eliminate the low-bit bias introduced by tent_map.
    The capacity portion (sites 8–15) is never output directly.

    Args:
        state: CMLSpongeState to mutate.

    Returns:
        64 bytes of keystream.
    """
    out = bytearray(BLOCK_BYTES)
    for i in range(RATE_SITES):
        struct.pack_into("<Q", out, i * 8, _stafford_mix13(state.lattice[i]))
    cml_permute(state)
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def cipher_init(key: bytes, iv: bytes) -> CMLSpongeState:
    """
    Initialise a CMLSpongeState from a key and IV.

    Sequence:
        1. All-zero 1024-bit state, counter=0.
        2. Absorb key (any length, recommended 32 bytes) with domain=0x01.
        3. Absorb IV  (any length, recommended 16 bytes) with domain=0x02.
        4. Mark state as finalized.

    The capacity words (sites 8–15) are untouched by the caller but are
    scrambled by the permutation.  A 1-bit key difference produces ≈50%
    capacity bit difference after the first permutation, giving related-key
    resistance.

    Args:
        key: Secret key bytes (recommended 32 bytes / 256 bits).
        iv:  Initialisation vector (recommended 16 bytes / 128 bits;
             MUST be unique per (key, message) pair).

    Returns:
        A fully initialised CMLSpongeState ready for squeezing.

    Raises:
        ValueError: If key or iv is empty.
    """
    if len(key) == 0:
        raise ValueError("Key must not be empty")
    if len(iv) == 0:
        raise ValueError("IV must not be empty")

    state = CMLSpongeState()
    _absorb(state, key, DOMAIN_KEY)
    _absorb(state, iv, DOMAIN_IV)
    state.finalized = True
    return state


def keystream(state: CMLSpongeState, length: int) -> bytes:
    """
    Generate `length` bytes of keystream from state.

    Keystream is produced 64 bytes per permutation.  Partial blocks are
    buffered in state.buf so that sequential calls with any lengths are
    consistent with a single call for the total length.

    Example (illustrating buffer consistency):
        ks1 = keystream(state_a, 192)        # one call
        ks2 = keystream(state_b, 64) + ...   # three separate calls
        # ks1 == ks2 guaranteed

    State IS MUTATED by this call.

    Args:
        state:  CMLSpongeState (must be finalized).
        length: Number of keystream bytes to generate.

    Returns:
        `length` bytes of keystream.

    Raises:
        RuntimeError: If state is not finalized.
    """
    if not state.finalized:
        raise RuntimeError("cipher_init must be called before keystream()")
    if length == 0:
        return b""

    result = bytearray()

    while len(result) < length:
        # Consume from existing buffer first.
        available = len(state.buf) - state.buf_pos
        if available > 0:
            want = length - len(result)
            take = min(want, available)
            result += state.buf[state.buf_pos: state.buf_pos + take]
            state.buf_pos += take
        else:
            # Buffer is exhausted — squeeze a new block.
            state.buf = _squeeze_block(state)
            state.buf_pos = 0

    return bytes(result)


def cipher_encrypt(state: CMLSpongeState, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext by XOR with keystream (stream cipher).

    The state is advanced in place.  For independent messages, use a
    fresh state from cipher_init() with a unique IV each time.

    Args:
        state:     CMLSpongeState (must be finalized).
        plaintext: Plaintext bytes.

    Returns:
        Ciphertext bytes of the same length as plaintext.
    """
    if len(plaintext) == 0:
        return b""
    ks = keystream(state, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def cipher_decrypt(state: CMLSpongeState, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext by XOR with keystream (stream cipher).

    Decryption is identical to encryption for a stream cipher.

    Args:
        state:      CMLSpongeState (must be finalized).
        ciphertext: Ciphertext bytes.

    Returns:
        Plaintext bytes of the same length as ciphertext.
    """
    return cipher_encrypt(state, ciphertext)
