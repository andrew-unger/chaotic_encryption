# CATWALK

Research-grade authenticated encryption built on a Coupled Map Lattice sponge
(CML-Sponge AEAD) primitive in Rust. Available as a CLI and an optional
cross-platform GUI.

> **CATWALK is experimental cryptography.** It has not undergone formal review
> and must not be used to protect production data. See [LICENSE](LICENSE) and
> [SECURITY.md](SECURITY.md).

## Quick start

```bash
git clone https://github.com/andrew-unger/chaotic_encryption.git catwalk
cd catwalk/Catwalk
cargo build --release
./target/release/catwalk encrypt input.bin output.catwalk
./target/release/catwalk decrypt output.catwalk recovered.bin
```

Build with the GUI: `cargo build --release --features gui`.

## Repository layout

```
.               # repository root (project: Catwalk)
├── Catwalk/    # Rust crate (library + CLI binary)
├── Support/    # tests, benches, docs, paper
├── CLAUDE.md   # contributor / agent guidelines
├── LICENSE     # All rights reserved
└── SECURITY.md # vulnerability disclosure
```

## Read next

- [Support/README.md](Support/README.md) — full feature list, file format, password
  policy, dependency table, statistical validation summary.
- [Support/paper/catwalk.tex](Support/paper/catwalk.tex) — design specification,
  coupling-matrix analysis, security argument.
- [Support/docs/](Support/docs/) — design spec, security argument, and
  empirical analysis (PractRand validation, reduced-round, algebraic degree).
- [CHANGELOG.md](CHANGELOG.md) — notable changes, including format history.
- [CLAUDE.md](CLAUDE.md) — coding conventions and build commands.

## License

All rights reserved. See [LICENSE](LICENSE) for details. For licensing inquiries
contact `ungerandrew2@gmail.com`.
