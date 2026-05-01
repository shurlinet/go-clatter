# go-clatter

Go implementation of the [PQNoise](https://eprint.iacr.org/2022/539) protocol framework. Port of [Rust Clatter v2.2.0](https://github.com/jmlepisto/clatter).

## What

Post-quantum Noise handshakes for Go. Three handshake modes from the ACM CCS 2022 paper:

- **NQ** - Classical DH-only (X25519)
- **PQ** - KEM-only (ML-KEM-768, ML-KEM-1024)
- **Hybrid** - DH + KEM combined
- **DualLayer** / **HybridDualLayer** - Two-layer composite handshakes

90 handshake patterns. 4 hash functions (SHA-256, SHA-512, BLAKE2s, BLAKE2b). 2 AEAD ciphers (ChaCha20-Poly1305, AES-256-GCM).

## Status

**Work in progress.** Batch 1 (foundation) complete: error types, secret key types, crypto primitives (X25519, ML-KEM, ciphers, hashes), DummyRng, constants, and 10 interop test vectors generated from Rust Clatter.

Not yet implemented: CipherState, SymmetricState, handshake state machines, pattern definitions, transport state.

## Crypto

- **DH**: X25519 via `crypto/ecdh`
- **KEM**: ML-KEM-768/1024 via `crypto/mlkem` (FIPS 203)
- **Cipher**: ChaCha20-Poly1305 via `golang.org/x/crypto`, AES-256-GCM via `crypto/aes`
- **Hash**: SHA-256/512 via `crypto/sha*`, BLAKE2s/b via `golang.org/x/crypto`

All secret key material stored in fixed-size arrays. Every type holding secrets implements `Destroy()` for explicit zeroing.

## Interop

10 golden test vectors generated from Rust Clatter with deterministic RNG. Byte-identical output verified. X25519 keygen interop confirmed against Rust at the primitive level.

## Dependencies

Go stdlib + `golang.org/x/crypto` (ChaCha20-Poly1305, BLAKE2). No other external dependencies.

## License

MIT - matching the upstream Rust Clatter license.
