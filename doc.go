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
//
// # Observability
//
// Attach an Observer via WithObserver to receive HandshakeEvent notifications
// after each handshake message (Write/Read) and on Finalize (IsComplete=true).
// Error events are delivered via OnError when the handshake enters error state.
// A nil observer has zero overhead (nil check only). Observer callbacks execute
// on the handshake goroutine and must return quickly. Panics in OnMessage are
// recovered and forwarded to OnError; panics in OnError are silently discarded.
//
// # Message Length Limits
//
// The Noise specification mandates a maximum message length of 65535 bytes
// (MaxMessageLen). Per-handshake limits can be configured via WithMaxMessageLen
// to enforce smaller limits for constrained environments, security policy, or
// memory exhaustion defense. Zero or unset means the default (65535). Values
// above MaxMessageLen are rejected at construction time.
//
// The limit applies to both handshake messages and post-handshake transport
// messages. Handshake constructors validate that the limit is large enough for
// every message in the pattern, returning a descriptive error if not.
// TransportState inherits the limit from the handshake that created it.
// Use TransportState.MaxMessageLen() to query the active limit.
package clatter
