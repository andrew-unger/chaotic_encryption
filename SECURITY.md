# Security Policy

## Scope

CATWALK is **research-grade** authenticated encryption. The CML-Sponge cipher
has not undergone formal cryptographic review. It is published for academic
study, cryptanalysis, and reproducibility of the accompanying paper. **Do not
use CATWALK to protect production data or any information of real
consequence.**

The reportable surface for this repository is:

- The CML-Sponge primitive in [`Catwalk/src/cml_sponge.rs`](Catwalk/src/cml_sponge.rs)
- The AEAD layer in [`Catwalk/src/crypto.rs`](Catwalk/src/crypto.rs) (header
  parsing, key derivation, tag verification, streaming I/O)
- File-format and metadata handling in [`Catwalk/src/utils.rs`](Catwalk/src/utils.rs)
- Archive extraction in [`Catwalk/src/archive.rs`](Catwalk/src/archive.rs)
- The CLI in [`Catwalk/src/main.rs`](Catwalk/src/main.rs) and GUI in
  [`Catwalk/src/gui.rs`](Catwalk/src/gui.rs)
- Test vectors and proptest suite under [`Support/tests/`](Support/tests/)

Out of scope: build tooling, documentation typos, the LaTeX paper sources,
PractRand harness scripts.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to:

- **Email:** `ungerandrew2@gmail.com`
- **Subject line:** `CATWALK security report — <one-line summary>`

If you would prefer encrypted communication, request a current key in your
first message and a PGP key will be provided in reply.

Please include:

1. CATWALK version / git commit hash you tested against
2. Reproduction steps or proof-of-concept (a minimal Rust program is ideal)
3. Affected component (e.g. `crypto::decrypt_v9`, `archive::extract`)
4. Impact assessment (confidentiality / integrity / availability)
5. Suggested mitigation, if you have one

## What to expect

- Acknowledgment within **5 business days**
- Initial assessment and severity rating within **14 days**
- For valid reports, a coordinated fix and public advisory once a patch is
  available

Because CATWALK is a personal research project, response times are best-effort
and not contractually guaranteed.

## What qualifies

In-scope examples:

- Authentication bypasses or tag forgeries
- Plaintext recovery without the key (statistical or algebraic distinguishers
  with non-negligible advantage count)
- Memory-safety bugs in `unsafe` blocks
- Panics on attacker-controlled input (denial of service)
- KDF parameter downgrade or replay attacks
- Path traversal, zip-slip, or symlink attacks in archive extraction
- Side-channels exploitable from a co-located attacker (timing, cache)

Out-of-scope examples:

- Brute-force attacks on weak passwords (the password policy is enforced; the
  user is the trust boundary)
- Theoretical attacks against Argon2id or BLAKE3 (refer those upstream)
- Issues that require local administrative privileges already
- Reports about CATWALK being unsuitable for production — this is acknowledged

## Public disclosure

Coordinated disclosure is preferred. Please give the maintainer a reasonable
window (typically 90 days, shorter for trivial fixes) before publishing
details. The maintainer will credit reporters in the advisory unless anonymity
is requested.
