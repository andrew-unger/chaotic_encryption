/// Criterion benchmark harness for CATWALK (CML-Sponge AEAD).
///
/// Measures:
///   - Permutation throughput (permutation_only)
///   - Keystream generation for small output (keystream_64b)
///   - AEAD encrypt at 1 KB, 64 KB, and 1 MB (encrypt_1kb, encrypt_64kb, encrypt_1mb)
///   - AEAD decrypt at 1 KB, 64 KB, and 1 MB (decrypt_1kb, decrypt_64kb, decrypt_1mb)
///   - Argon2id KDF at minimum accepted parameters (kdf_only)
///
/// Usage:
///   cargo bench --bench catwalk_bench
///   cargo bench --bench catwalk_bench -- --save-baseline v10
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use argon2::{Algorithm, Argon2, Params, Version};
use catwalk::cml_sponge::{
    absorb_aad, aead_decrypt_chunk, aead_encrypt_chunk, aead_finalize, cipher_init,
    cml_permute_r, keystream,
};

// ── Fixed test vectors ──────────────────────────────────────────────────────

const KEY: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

const IV: [u8; 16] = [
    0x19, 0x8c, 0xb0, 0x4a, 0x2a, 0x71, 0xb5, 0x14,
    0x58, 0x9f, 0xd1, 0x5c, 0x16, 0x2e, 0xd5, 0xda,
];

const AAD: &[u8] = b"CATWALK benchmark AAD";

// ── Helper: encrypt a buffer and return (ciphertext, tag) ──────────────────

fn aead_encrypt(plaintext: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut state = cipher_init(&KEY, &IV);
    absorb_aad(&mut state, AAD);
    let mut ct = plaintext.to_vec();
    aead_encrypt_chunk(&mut state, &mut ct);
    let tag = aead_finalize(&mut state);
    (ct, tag)
}

// ── Benchmark: single permutation ──────────────────────────────────────────

fn bench_permutation(c: &mut Criterion) {
    let mut state = cipher_init(&KEY, &IV);
    c.bench_function("permutation_only", |b| {
        b.iter(|| cml_permute_r(&mut state, 8));
    });
}

// ── Benchmark: keystream for 64 bytes ──────────────────────────────────────

fn bench_keystream_64b(c: &mut Criterion) {
    let mut group = c.benchmark_group("keystream");
    group.throughput(Throughput::Bytes(64));
    group.bench_function("keystream_64b", |b| {
        let mut state = cipher_init(&KEY, &IV);
        let mut buf = [0u8; 64];
        b.iter(|| keystream(&mut state, &mut buf));
    });
    group.finish();
}

// ── Benchmark: AEAD encrypt at multiple payload sizes ──────────────────────

fn bench_encrypt(c: &mut Criterion) {
    let sizes: &[(&str, usize)] = &[
        ("1KB",  1024),
        ("64KB", 65536),
        ("1MB",  1048576),
    ];

    let mut group = c.benchmark_group("aead_encrypt");
    for (label, size) in sizes {
        let plaintext = vec![0x5au8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.iter(|| {
                let mut state = cipher_init(&KEY, &IV);
                absorb_aad(&mut state, AAD);
                let mut ct = plaintext.clone();
                aead_encrypt_chunk(&mut state, &mut ct);
                aead_finalize(&mut state)
            });
        });
    }
    group.finish();
}

// ── Benchmark: AEAD decrypt at multiple payload sizes ──────────────────────

fn bench_decrypt(c: &mut Criterion) {
    let sizes: &[(&str, usize)] = &[
        ("1KB",  1024),
        ("64KB", 65536),
        ("1MB",  1048576),
    ];

    let mut group = c.benchmark_group("aead_decrypt");
    for (label, size) in sizes {
        let plaintext = vec![0x5au8; *size];
        let (ciphertext, _) = aead_encrypt(&plaintext);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &ciphertext, |b, ct| {
            b.iter(|| {
                let mut state = cipher_init(&KEY, &IV);
                absorb_aad(&mut state, AAD);
                let mut buf = ct.clone();
                aead_decrypt_chunk(&mut state, &mut buf);
                aead_finalize(&mut state)
            });
        });
    }
    group.finish();
}

// ── Benchmark: Argon2id KDF at minimum accepted parameters ─────────────────
//
// The production KDF uses m=2^18 (256 MB) / t=4 / p=1.  Running that in a
// loop would make the benchmark suite take hours.  Instead we use the minimum
// parameters accepted by decrypt() — m=2^16 (64 MB) / t=2 / p=1 — which
// still gives a realistic shape: total memory traffic ≈ 128 MiB per call.
//
// To measure the full production KDF once, run:
//   cargo bench --bench catwalk_bench -- kdf_only --profile-time 1

fn bench_kdf(c: &mut Criterion) {
    const SALT: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    const PASSWORD: &[u8] = b"bench password for kdf benchmark";

    // m_log2=16 → 64 MB, t=2, p=1 — minimum accepted by decrypt()
    let m_cost: u32 = 1 << 16;
    let params = Params::new(m_cost, 2, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    c.bench_function("kdf_only (m=64MB t=2 p=1)", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            argon2.hash_password_into(PASSWORD, &SALT, &mut out).unwrap();
        });
    });
}

// ── Registration ───────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_permutation,
    bench_keystream_64b,
    bench_encrypt,
    bench_decrypt,
    bench_kdf,
);
criterion_main!(benches);
