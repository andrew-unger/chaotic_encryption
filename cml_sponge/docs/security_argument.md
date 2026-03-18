# CML-Sponge: Security Argument

**Status**: Research prototype.  No formal security proof exists.
This document is an honest assessment of the design's security properties,
attack surface, and open questions.  It is not a substitute for professional
cryptanalysis.

---

## 1. State Size and Security Level

| Component        | Size       | Security Implication                              |
|------------------|------------|---------------------------------------------------|
| Total state      | 1024 bits  | No generic state-recovery attack below 2^512     |
| Capacity         | 512 bits   | Collision/preimage security bound: 2^256         |
| Key              | 32 bytes (recommended) | Key-recovery bound: 2^128 (minimum); 2^256 with full 256-bit key entropy |
| IV               | 16 bytes (recommended) | Per-message nonce; 2^128 IV space                |

**Security level**: min(capacity/2, key_bits) = min(256, key_bits).

With a 32-byte (256-bit) key, the design targets **256-bit security** against
all generic attacks.

### Generic Attack Bounds

**State recovery from keystream**: An adversary who observes `k` bytes of
keystream and attempts to recover the 1024-bit internal state would need to
solve a system that depends on all 16 lattice sites and the counter.  Even if
the full state were observable, recovering the capacity portion from only the
rate output requires inverting the permutation — believed to require 2^512
work.  The sponge capacity argument (Bertoni et al. 2007) gives a concrete
bound: an adversary can distinguish the output from random with probability at
most `q^2 / 2^c = q^2 / 2^512`, where `q` is the number of permutation calls.

**Key recovery**: With a 256-bit key, exhaustive key search requires 2^256
evaluations of the key schedule.  No shortcut is known.

**IV collision**: Two messages encrypted with the same (key, IV) pair reveal
the XOR of their plaintexts.  The IV space is 2^128; birthday-bound collision
occurs after 2^64 messages.  This is the standard stream-cipher nonce
constraint; users must ensure IV uniqueness.

---

## 2. Diffusion Analysis

Full proof of 4-round diffusion is given in `docs/design.md`, Section 4.2.
Summary:

Starting from a single perturbed site:
- Round 1: 4 sites influenced.
- Round 2: 8 sites influenced.
- Round 3: 12 sites influenced.
- Round 4: All 16 sites influenced.

With 8 rounds per permutation, the design achieves full diffusion in the first
4 rounds and spends the remaining 4 rounds on nonlinear mixing.  This is
analogous to the "wide trail strategy" in AES: guarantee diffusion first, then
add nonlinearity on top.

The multiplicative step in each round adds nonlinearity that is difficult to
track with standard linear/differential analysis.

---

## 3. Three Most Likely Attack Vectors

### 3.1 Algebraic Attack on Local Maps (Low-Round Distinguisher)

**Description**: The logistic map `f(x) = x·(2^64−1−x) >> 62` is a degree-2
polynomial over Z/2^64 Z.  The tent map is piecewise linear (degree 1 per
branch, but branching on the MSB introduces a conditional that can be
expressed as a quadratic in GF(2)^64).  An attacker might search for a
low-degree algebraic relation between input and output that holds over many
rounds.

**Why this is the most accessible attack**: Algebraic attacks on chaos-based
ciphers are the standard first step in the literature (Alvarez and Li 2006).
The maps are simple enough that a motivated analyst could write down the
algebraic normal form (ANF) of 2–3 rounds and search for multivariate
polynomial relations using Gröbner basis techniques.

**What the design does to resist this**: The Weyl counter injection adds an
input-independent additive constant each round, which breaks the pure algebraic
structure.  The multiplicative mixing step adds degree-2 nonlinearity at the
word level.  After 4+ rounds, the algebraic degree of the output as a function
of the input grows exponentially (similar to how AES S-box degree grows).

**Honest assessment**: For 2-round reduced variants, a skilled analyst could
likely find distinguishers.  Whether 8 rounds is sufficient to defeat all
algebraic attacks is unknown without formal analysis.

---

### 3.2 Differential Attack Exploiting Coupling Topology

**Description**: Because the coupling topology ({1, 7, 8}) is fixed and public,
an attacker who can observe the output for two inputs that differ in a known
pattern might be able to predict how that difference propagates through the
lattice.  Standard differential cryptanalysis computes the probability that
a chosen input difference leads to a specific output difference.

**Why this matters**: The additive coupling (not XOR) means that a difference
`Δm[i]` at site `i` creates a difference `Δm[i]` at sites `{i, i+1, i+7, i+8}`
after one coupling step.  Unlike XOR-based designs, addition carries can
"leak" a difference into higher-weight positions.  However, carries are also
probabilistic, making differential paths harder to track.

**What the design does to resist this**: The counter injection perturbs the
lattice at every round, breaking any differential path that depends on the
state being deterministically mapped.  The multiplicative step makes
differential propagation through `s[2k+1] = s[2k+1] * (s[2k] | 1)` highly
nonlinear and input-dependent.

**Honest assessment**: No differential analysis has been performed.  The
coupling topology is simple and structured enough that a differential
characteristic for 3–4 rounds might be constructible.  8-round security
against differential attacks is an open question.

---

### 3.3 State Recovery from Known Keystream (Sponge Capacity Argument)

**Description**: The most powerful generic attack against a sponge-based
stream cipher is to observe a long keystream and attempt to recover the full
1024-bit internal state, then predict future output.

**Theoretical bound**: By the sponge security proof (Bertoni et al. 2007), an
adversary who makes at most `q` queries to the construction cannot recover the
capacity (512 bits) with probability greater than `q / 2^(c/2) = q / 2^256`.
For any computationally bounded adversary (`q << 2^256`), the capacity remains
hidden.

**What this means in practice**: Even if an adversary observes an unbounded
amount of keystream, they observe only the rate portion (sites 0–7) of the
state after each permutation.  The capacity (sites 8–15) is never output.
Recovering the capacity requires inverting the 8-round CML permutation, which
is believed to be computationally infeasible.

**The critical assumption**: This argument holds **only if the CML permutation
is a good pseudorandom permutation**.  If the permutation has structural
weaknesses (e.g., linear invariants, short cycles), the capacity argument
breaks down.  This is the fundamental open question for this cipher.

---

## 4. What a Professional Cryptanalyst Would Target First

A professional cryptanalyst's first priority would be **reduced-round
analysis** of the CML permutation.

### Approach

1. **2-round CML permutation**: Write out the full algebraic expression for
   `lattice_output` as a function of `lattice_input` through 2 CML rounds.
   Search for linear or nonlinear invariants:  values `f(lattice)` such that
   `f(CML_permute(lattice))` has a simple relationship to `f(lattice)`.

2. **Nonlinear invariant search**: The class of attacks introduced by
   Todo, Leander, and Sasaki (2016) searches for Boolean functions `g` of
   moderate algebraic degree such that `g(CML_permute(state)) + g(state)`
   is biased (not uniformly distributed over {0,1}).  Such invariants would
   be a fundamental structural break.

3. **Cycle structure analysis**: For small state sizes (e.g., 8-bit lattice
   sites instead of 64-bit), experimentally map the full cycle structure of the
   permutation.  Very short cycles or a small number of large cycles would
   indicate structural weakness.

4. **Differential characteristic for 3 rounds**: Using the known coupling
   topology and local map derivatives, attempt to construct a differential
   characteristic with probability > 2^{-n} for some small n.  If such a
   characteristic exists, it might be extendable to a distinguishing attack on
   the full 8-round permutation.

### Why the CML permutation is the first target

The sponge construction is a well-understood framework with a clean security
proof.  The security of the full cipher reduces entirely to the security of the
underlying permutation.  If the permutation is a good pseudorandom permutation,
the cipher is secure.  The permutation is therefore the single critical
component.

---

## 5. What Is Needed Before Serious Use

This cipher is a **research prototype** and should not be used in production
without the following:

### 5.1 Formal Analysis of the CML Permutation

The permutation's security properties need to be established rigorously.
Specifically:

- **PRP distinguishing advantage**: What is the best known circuit for
  distinguishing 8-round CML from a uniformly random permutation on {0,1}^1024?
  For comparison, AES-128 has a known distinguisher for 7 rounds (but not 10);
  Keccak-f[1600] has known distinguishers up to ~24 rounds (but uses 24).

- **Algebraic degree analysis**: Track the algebraic degree of the permutation's
  output bits as a function of the input bits, round by round.  For a secure
  permutation, degree should reach maximum (≈ 2^{n−1}) within a few rounds.

### 5.2 Differential and Linear Cryptanalysis

Full differential and linear analysis of the 8-round permutation, including:
- Computation of the maximum differential probability (MDP) for each round.
- Construction of the best linear approximation (maximum linear bias).
- Verification that 8 rounds provides sufficient security margin over the
  minimum number of rounds to defeat differential/linear attacks.

### 5.3 Third-Party Review

Independent cryptanalysis by at least two separate teams with no access to
the design team's internal analysis.  Open publication and a public review
period (as was done for AES, SHA-3, etc.).

### 5.4 Statistical Validation

- PractRand validation to at least 1 TB (current: conceptually straightforward
  but not yet executed at this scale).
- TestU01 BigCrush battery.
- NIST SP 800-22 statistical test suite.
- Multi-seed validation (50+ independent seeds per test suite).

### 5.5 Side-Channel Analysis

The tent map is implemented branchlessly to prevent timing side-channels from
the MSB branch.  However:
- Cache-timing attacks on the Python interpreter itself have not been analyzed.
- Power analysis and EM analysis are relevant for embedded implementations.
- A production implementation would require constant-time guarantees at the
  hardware level.

---

## 6. Honest Open Questions

1. **Is 8 rounds sufficient?**

   Full diffusion is achieved at round 4.  The remaining 4 rounds provide
   nonlinear mixing.  But "nonlinear mixing" is not the same as
   "pseudorandom permutation security."  The number of rounds needed to defeat
   the best known algebraic attack on this specific CML construction is
   unknown.

2. **Is the coupling topology cryptographically sound?**

   Distances {1, 7, 8} were chosen to guarantee fast diffusion.  Whether this
   topology — or any CML topology — is sound for cryptographic purposes is an
   open research question.  CML dynamics are well-studied for chaos and
   information theory, but not for cryptographic PRP security.

3. **Are there weak-key classes?**

   The Weyl counter injection prevents the trivial weak key (all-zero lattice
   as a fixed point), but other weak-key phenomena are possible:
   - Keys that produce lattice states with very short permutation cycles.
   - Keys for which two different IVs produce related keystreams.
   - Keys for which the logistic/tent maps converge to low-entropy attractors
     before the Weyl injection can rescue them.
   None of these have been systematically excluded.

4. **Is additive coupling the right choice?**

   Additive coupling was chosen over XOR coupling for its carry-based nonlinearity.
   However, addition introduces algebraic structure (it is a group operation on
   Z/2^64 Z) that might be exploitable.  The relative merits of additive vs.
   XOR coupling for CML-based ciphers have not been formally analyzed.

5. **What is the impact of the domain-separation constants?**

   The values `0x01` (key) and `0x02` (IV) are simple and standard.  A formal
   proof that these constants provide domain separation (in the random
   permutation model) follows from standard sponge theory, but has not been
   carried through for this specific construction.

---

## 7. Summary

CML-Sponge is a novel stream cipher with a well-motivated design but no
formal security proof.  The design rationale is sound:  the coupling topology
guarantees fast diffusion, the counter injection prevents degeneracy, and the
sponge framework provides a clean security reduction to the permutation's PRP
security.

The main risk is that the CML permutation may have structural weaknesses —
algebraic invariants, short cycles, or differential characteristics — that
are not visible from the design rationale alone.  A rigorous security argument
requires formal cryptanalysis, which has not yet been performed.

**Bottom line**: Promising research prototype.  Not for production use without
formal cryptanalysis.
