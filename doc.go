// Package clatter implements the PQNoise protocol framework (post-quantum Noise).
//
// This is a Go port of Rust Clatter v2.2.0 (github.com/jmlepisto/clatter, MIT).
// It implements all three PQNoise handshake modes from the ACM CCS 2022 paper:
// NQ (classical DH), PQ (KEM-only), and Hybrid (DH+KEM), plus DualLayer
// and HybridDualLayer composite handshakes.
//
// Cryptographic primitives:
//   - DH: X25519 (crypto/ecdh)
//   - KEM: ML-KEM-768, ML-KEM-1024 (crypto/mlkem, FIPS 203)
//   - Cipher: ChaCha20-Poly1305 (x/crypto), AES-256-GCM (crypto/aes)
//   - Hash: SHA-256, SHA-512 (crypto/sha256, crypto/sha512), BLAKE2s, BLAKE2b (x/crypto)
//
// All secret key material is stored in fixed-size arrays ([32]byte, [64]byte)
// that don't move during garbage collection. Every type holding secrets
// implements Destroy() for explicit zeroing.
package clatter
