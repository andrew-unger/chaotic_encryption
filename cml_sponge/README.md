# CML-Sponge Stream Cipher

## Abstract

We present CML-Sponge, a stream cipher combining a Coupled Map Lattice (CML)
permutation with the sponge construction of Bertoni et al. (2007).  The 16-site
CML lattice (1024-bit state) employs alternating logistic and tent maps at
adjacent sites, additive coupling across distances {1, 7, 8} on a ring topology,
a Weyl-sequence counter injection for fixed-point resistance, and multiplicative
inter-pair mixing; eight rounds of this permutation achieve full 16-site
diffusion with a 2× margin.  The sponge parameters — 512-bit rate, 512-bit
capacity — target a 256-bit security level.  The design is motivated by the
rich nonlinear dynamics of CMLs, which provide structural properties (sensitive
dependence on initial conditions, dense periodic orbits, topological transitivity)
beyond what algebraically simple ARX constructions offer, while the sponge
framework gives a clean separation between the permutation's security properties
and the mode of operation.  This is a research prototype requiring formal
cryptanalysis before deployment.

---

## Design Rationale

### Why a Coupled Map Lattice?

Classical ARX (Add-Rotate-XOR) stream ciphers achieve diffusion and confusion
through iterated linear operations punctuated by S-box substitutions or modular
arithmetic.  CMLs offer an alternative source of complexity: the emergent
unpredictability of coupled nonlinear dynamical systems.  In a CML, each site
evolves under a chaotic map, and the sites are coupled so that local perturbations
spread globally within a small number of rounds.

Key advantages for cryptographic use:
- **Nonlinearity without lookup tables**: The logistic and tent maps are
  simple algebraic functions with well-understood chaotic properties; no
  large S-boxes or lookup tables are required.
- **Tunable diffusion via topology**: The coupling topology directly controls
  how fast information spreads across the lattice.  The distances {1, 7, 8}
  were chosen to achieve full 16-site diffusion in exactly 4 rounds.
- **Integer-arithmetic portability**: All operations use u64 wrapping
  arithmetic; no floating-point and no platform-specific intrinsics.

The primary risk of CML-based cryptography is that CML dynamics, while
complex in the chaos-theory sense, may have algebraic structure exploitable
by tools (Gröbner bases, nonlinear invariant search) that are not relevant to
the continuous-domain analysis on which CML theory is built.  This is the
central open question discussed in `docs/security_argument.md`.

### Why the Sponge Construction?

The sponge construction (Bertoni et al. 2007, standardized as Keccak/SHA-3)
gives a well-analyzed framework for building a stream cipher from a permutation:

1. **Clean security reduction**: Security reduces to the permutation's quality
   as a pseudorandom permutation.  A rigorous cryptanalysis of the CML permutation
   directly translates to a security proof for the full cipher.
2. **Capacity-based security**: The capacity (512 bits, sites 8–15) is never
   directly output.  State recovery from keystream requires inverting the
   permutation, bounded by 2^(c/2) = 2^256 work.
3. **Domain separation**: Separate domain bytes for key and IV absorption
   prevent extension attacks and related-input attacks.
4. **Padding**: Multi-rate padding (identical to SHA-3) ensures correct
   handling of messages of any length.

### Why This Coupling Topology?

Distances {1, 7, 8} on a ring of 16 sites were chosen by the following criteria:

1. **Fast full diffusion**: Must achieve all-to-all influence within 4 rounds
   (verified analytically; see `docs/design.md`, Section 4.2).
2. **Asymmetry**: Distance 7 ≠ distance 9 (= 16 − 7), so the topology has no
   reflection symmetry.  This prevents any pair of sites from being "mirrors"
   of each other.
3. **Global component**: Distance 8 = N/2 provides a mean-field coupling
   component (every site connects to its diametrically opposite site),
   accelerating global mixing.
4. **Minimal coupling degree**: Only 4 inputs per site (self + 3 neighbors).
   This keeps the per-round algebraic degree manageable for analysis.

---

## Algorithm Specification

This section is precise enough to reimplement the cipher from scratch.

### State

```
lattice[0..15]   : 16 unsigned 64-bit integers
counter          : 1 unsigned 64-bit integer (Weyl sequence)
```

All arithmetic is modulo 2^64 (u64 wrapping).

### Constants

```
GOLDEN = 0x9E3779B97F4A7C15   # Weyl increment (fractional part of (√5−1)/2 × 2^64)
NUM_ROUNDS = 8
RATE_SITES = 8                 # sites 0–7 are the rate portion
```

### Local Maps

```
rotate64(x, n) = ((x << n) | (x >> (64-n))) & U64_MAX

logistic_map(x) = (x * ((2^64 - 1) - x)) >> 62

tent_map(x):
    msb = (x >> 63) & 1
    branch0 = (2 * x) mod 2^64          # used if msb == 0
    branch1 = (2 * (2^64 - 1 - x)) mod 2^64  # used if msb == 1
    return branch0 if msb==0 else branch1  # implemented branchlessly

local_map(x, site):
    return logistic_map(x) if (site % 2 == 0) else tent_map(x)
```

### CML Round (one of 8 per permutation)

```
Step 1 — Snapshot local maps:
    m[i] = local_map(lattice[i], i)   for i = 0..15
    (compute ALL m[i] from the current lattice before any update)

Step 2 — Additive CML coupling:
    lattice[i] = (m[i] + m[(i+1)%16] + m[(i+7)%16] + m[(i+8)%16]) mod 2^64
    for i = 0..15

Step 3 — Weyl counter injection:
    counter = (counter + GOLDEN) mod 2^64
    lattice[0]  = (lattice[0]  + counter) mod 2^64
    lattice[4]  = (lattice[4]  + rotate64(counter, 16)) mod 2^64
    lattice[8]  = (lattice[8]  + rotate64(counter, 32)) mod 2^64
    lattice[12] = (lattice[12] + rotate64(counter, 48)) mod 2^64

Step 4 — Multiplicative mixing:
    for k = 0..7:
        lattice[2k+1] = (lattice[2k+1] * (lattice[2k] | 1)) mod 2^64
```

### Permutation

```
permute(state):
    apply CML_round 8 times (mutates state.lattice and state.counter)
```

### Sponge: Absorb

```
pad(data, domain):
    msg = data + bytes([domain])
    while len(msg) % 64 != 63:
        msg += b'\x00'
    msg += b'\x80'
    return msg    # length is a multiple of 64

absorb(state, data, domain):
    for each 64-byte block B in pad(data, domain):
        for i = 0..7:
            state.lattice[i] ^= unpack_u64_le(B, offset=i*8)
        permute(state)
```

### Sponge: Squeeze

```
squeeze_block(state):
    output = pack_u64_le(state.lattice[0..7])   # 64 bytes, little-endian
    permute(state)
    return output
```

### Initialization

```
cipher_init(key: bytes, iv: bytes) -> state:
    state = all-zero lattice, counter=0
    absorb(state, key, domain=0x01)
    absorb(state, iv,  domain=0x02)
    return state
```

### Stream Generation

```
keystream(state, n_bytes):
    collect bytes from squeeze_block() until n_bytes bytes available
    (buffer unused tail for next call)
    return first n_bytes

encrypt(state, plaintext):
    return bytes(p ^ k for p,k in zip(plaintext, keystream(state, len(plaintext))))

decrypt = encrypt   # stream cipher: decryption is identical
```

---

## Security Claims

The following claims are asserted based on design analysis.  They are NOT
formally proven.

1. **Keystream indistinguishability (conjectured)**: The keystream output is
   computationally indistinguishable from a uniformly random byte sequence,
   assuming the 8-round CML permutation is a secure pseudorandom permutation
   on {0,1}^1024.

2. **State recovery resistance**: Recovering the full 1024-bit state from
   observed keystream requires work proportional to 2^512 (the sponge capacity
   bound with c=512).

3. **Key recovery resistance**: With a 256-bit key, exhaustive key search
   requires 2^256 evaluations.  No shortcut is known.

4. **IV uniqueness requirement**: Two messages encrypted with the same
   (key, IV) pair leak the XOR of their plaintexts.  IV uniqueness per
   (key, message) pair is mandatory.

5. **Related-key/IV resistance (heuristic)**: A 1-bit difference in key or IV
   produces ≈50% difference in all lattice sites after the first permutation,
   as evidenced by the empirical avalanche tests in the test suite.

---

## Parameter Recommendations

| Parameter | Recommended | Minimum | Notes                                      |
|-----------|-------------|---------|---------------------------------------------|
| Key       | 32 bytes    | 16 bytes | 32 bytes targets 256-bit security           |
| IV        | 16 bytes    | 8 bytes  | Must be unique per (key, message) pair      |
| IV source | CSPRNG      | —        | Never reuse IV with the same key            |

---

## Known Limitations

1. **No formal security proof**: The security of the CML permutation as a
   pseudorandom permutation has not been formally established.

2. **No external cryptanalysis**: This design has not been reviewed by
   independent cryptographers.  No third-party analysis has been published.

3. **Python reference only**: This is a reference implementation in Python.
   It is not optimized for throughput (a C implementation would be 10–100×
   faster), and it has not been hardened against side-channel attacks.

4. **No AEAD construction**: This cipher provides confidentiality only.
   Integrity and authenticity require a separate MAC (e.g., BLAKE3 or HMAC-SHA3).

5. **No formal diffusion proof for the CML permutation as a PRP**: The 4-round
   diffusion proof (see `docs/design.md`) proves that information spreads to
   all sites.  It does NOT prove pseudorandomness.  The latter is a strictly
   stronger property.

6. **Unknown weak-key classes**: No systematic search for weak keys, fixed
   points of the permutation, or short permutation cycles has been conducted.

---

## References

1. Kaneko, K. (1984). *Period-doubling of kink-antikink patterns, quasiperiodicity,
   and randomness in coupled logistic lattice.* Progress of Theoretical Physics,
   72(3), 480–486.

2. Bertoni, G., Daemen, J., Peeters, M., & Van Assche, G. (2007).
   *Sponge functions.* ECRYPT Hash Workshop.

3. Alvarez, G., & Li, S. (2006). *Some basic cryptographic requirements for
   chaos-based cryptosystems.* International Journal of Bifurcation and Chaos,
   16(08), 2129–2151.

4. Sprott, J. C. (2003). *Chaos and Time-Series Analysis.* Oxford University Press.

5. Todo, Y., Leander, G., & Sasaki, Y. (2018). *Nonlinear invariant attack —
   practical attack on full SCREAM, iSCREAM, and Midori64.* Journal of Cryptology,
   31(4), 1164–1207.  (Cited as a relevant attack model for chaos-based ciphers.)

6. Bertoni, G., Daemen, J., Peeters, M., & Van Assche, G. (2011).
   *Cryptographic sponge functions.* Submission to NIST SHA-3 competition.
   (Formal sponge security proof.)
