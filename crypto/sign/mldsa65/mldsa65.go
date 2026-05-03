// Package mldsa65 provides ML-DSA-65 (FIPS 204) post-quantum digital signatures.
//
// ML-DSA-65 offers NIST Security Level 3 (~192-bit classical security) with
// 32-byte seeds, 1952-byte public keys, and 3309-byte signatures.
//
// This package wraps filippo.io/mldsa (pre-release of Go 1.27 crypto/mldsa)
// with explicit key lifecycle management (Destroy/zeroing) and a simplified API
// that hides crypto.SignerOpts complexity from consumers.
//
// Thread safety: PublicKey is safe for concurrent use. PrivateKey is safe for
// concurrent Sign/Verify operations via sync.RWMutex; Destroy acquires an
// exclusive lock and zeros all secret material.
//
// Destroy semantics: Destroy zeros the 32-byte seed copy held by this wrapper
// and nils the reference to the underlying library key. The expanded key
// material inside the underlying library is subject to Go's garbage collector
// timing. This is a known limitation of garbage-collected languages shared by
// all Go crypto libraries including the stdlib.
//
// Signing uses hedged randomness by default (recommended for production).
// SignDeterministic removes hedging and is for test vector generation ONLY.
// Deterministic signatures have identical timing patterns for the same input,
// making them more vulnerable to timing side-channel analysis.
//
// Applications MUST use distinct context strings for distinct signing purposes
// to prevent cross-purpose signature replay. Context must be at most 255 bytes.
//
// To serialize a private key, export with Seed() and reconstruct with
// NewPrivateKeyFromSeed(). Do not attempt to marshal PrivateKey directly
// (it contains a sync.RWMutex).
package mldsa65

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"filippo.io/mldsa"
)

// Size constants for ML-DSA-65 (FIPS 204, NIST Level 3).
const (
	SeedSize      = 32   // Private key seed size in bytes.
	PublicKeySize = 1952 // Public key encoding size in bytes.
	SignatureSize = 3309 // Signature size in bytes.
)

// Errors returned by this package.
var (
	ErrDestroyed           = errors.New("mldsa65: private key destroyed")
	ErrInvalidSeedSize     = errors.New("mldsa65: seed must be exactly 32 bytes")
	ErrInvalidPublicKeySize = errors.New("mldsa65: public key must be exactly 1952 bytes")
	ErrInvalidPublicKey    = errors.New("mldsa65: invalid public key encoding")
	ErrContextTooLong      = errors.New("mldsa65: context must be at most 255 bytes")
)

// PrivateKey is an ML-DSA-65 private key with explicit lifecycle management.
//
// A PrivateKey is safe for concurrent use: all signing methods acquire a
// shared read lock, while Destroy acquires an exclusive write lock. After
// Destroy is called, all methods return ErrDestroyed. The associated
// PublicKey (obtained via PublicKey()) remains valid after Destroy.
//
// Two PrivateKey instances created from the same seed are independent;
// destroying one does not affect the other.
type PrivateKey struct {
	mu        sync.RWMutex
	key       *mldsa.PrivateKey
	seed      [SeedSize]byte
	pub       *PublicKey // cached, survives Destroy
	destroyed bool
}

// PublicKey is an ML-DSA-65 public key. It is immutable and safe for
// concurrent use from multiple goroutines without synchronization.
// A PublicKey remains valid even after the corresponding PrivateKey
// is destroyed.
type PublicKey struct {
	key *mldsa.PublicKey
}

// GenerateKey generates a new random ML-DSA-65 private key using the
// system's cryptographic random number generator.
func GenerateKey() (*PrivateKey, error) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("mldsa65: generate: %w", err)
	}
	return privateKeyFromLib(sk), nil
}

// NewPrivateKeyFromSeed creates a private key from a 32-byte seed.
// The seed must be cryptographically random or KDF-derived with sufficient entropy.
func NewPrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) != SeedSize {
		return nil, ErrInvalidSeedSize
	}
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, fmt.Errorf("mldsa65: %w", err)
	}
	return privateKeyFromLib(sk), nil
}

// privateKeyFromLib wraps a library PrivateKey into our type with cached PublicKey.
func privateKeyFromLib(sk *mldsa.PrivateKey) *PrivateKey {
	pub := &PublicKey{key: sk.PublicKey()}
	k := &PrivateKey{
		key: sk,
		pub: pub,
	}
	copy(k.seed[:], sk.Bytes())
	return k
}

// NewPublicKey parses a 1952-byte ML-DSA-65 public key encoding and returns
// a new PublicKey. The input bytes are copied; subsequent modification of pub
// does not affect the returned key.
//
// Returns ErrInvalidPublicKeySize if len(pub) != 1952, or ErrInvalidPublicKey
// if the encoding is malformed (note: ML-DSA-65's 10-bit coefficient packing
// accepts all valid-length inputs with current library versions).
func NewPublicKey(pub []byte) (*PublicKey, error) {
	if len(pub) != PublicKeySize {
		return nil, ErrInvalidPublicKeySize
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{key: pk}, nil
}

// Seed returns a copy of the 32-byte private key seed.
// The caller is responsible for zeroing the returned slice when done.
// Returns ErrDestroyed if the key has been destroyed.
func (k *PrivateKey) Seed() ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.destroyed {
		return nil, ErrDestroyed
	}
	out := make([]byte, SeedSize)
	copy(out, k.seed[:])
	return out, nil
}

// PublicKey returns the corresponding public key.
// The public key is cached at construction and survives Destroy.
func (k *PrivateKey) PublicKey() *PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// Sign signs msg using hedged randomness (internal DRBG + system entropy).
// This is the recommended signing mode for production. The same message
// produces a different signature each time due to the random component,
// which provides fault protection against RNG failures and resistance to
// timing side-channel analysis.
//
// Returns ErrDestroyed if the key has been destroyed.
func (k *PrivateKey) Sign(msg []byte) ([]byte, error) {
	return k.signInternal(msg, "", false)
}

// SignWithContext signs msg with a FIPS 204 context string for domain
// separation. The context binds the signature to a specific purpose: a
// signature created with context "auth/v1" will not verify under context
// "payment/v1", preventing cross-purpose replay attacks.
//
// The context must be at most 255 bytes (FIPS 204 limit). An empty string
// is valid and equivalent to calling Sign.
//
// Returns ErrContextTooLong if len(ctx) > 255, or ErrDestroyed if the key
// has been destroyed.
func (k *PrivateKey) SignWithContext(msg []byte, ctx string) ([]byte, error) {
	return k.signInternal(msg, ctx, false)
}

// SignDeterministic signs msg without hedging randomness: the same
// (key, message) pair always produces the identical signature.
//
// WARNING: For test vector generation and reproducibility testing ONLY.
// Production code MUST use Sign. Deterministic signatures leak timing
// information (identical inputs take identical rejection-sampling paths)
// and provide no fault protection against RNG compromise.
//
// Returns ErrDestroyed if the key has been destroyed.
func (k *PrivateKey) SignDeterministic(msg []byte) ([]byte, error) {
	return k.signInternal(msg, "", true)
}

// SignDeterministicWithContext combines deterministic signing with context
// separation. For test vector generation ONLY. See SignDeterministic for
// warnings about deterministic mode.
//
// Returns ErrContextTooLong if len(ctx) > 255, or ErrDestroyed if the key
// has been destroyed.
func (k *PrivateKey) SignDeterministicWithContext(msg []byte, ctx string) ([]byte, error) {
	return k.signInternal(msg, ctx, true)
}

func (k *PrivateKey) signInternal(msg []byte, ctx string, deterministic bool) ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.destroyed {
		return nil, ErrDestroyed
	}
	if len(ctx) > 255 {
		return nil, ErrContextTooLong
	}
	opts := &mldsa.Options{Context: ctx}
	var sig []byte
	var err error
	if deterministic {
		sig, err = k.key.SignDeterministic(msg, opts)
	} else {
		sig, err = k.key.Sign(nil, msg, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("mldsa65: sign: %w", err)
	}
	return sig, nil
}

// Equal reports whether k and x are derived from the same seed
// (constant-time comparison). Returns false if either key is nil or
// destroyed. Intermediate seed copies are zeroed after comparison.
func (k *PrivateKey) Equal(x *PrivateKey) bool {
	if k == nil || x == nil {
		return false
	}
	aSeed, aErr := k.Seed()
	if aErr != nil {
		return false
	}
	bSeed, bErr := x.Seed()
	if bErr != nil {
		zeroSlice(aSeed)
		return false
	}
	result := subtle.ConstantTimeCompare(aSeed, bSeed) == 1
	zeroSlice(aSeed)
	zeroSlice(bSeed)
	return result
}

// zeroSlice overwrites a byte slice with zeros.
func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Destroy zeros the 32-byte seed, nils the reference to the underlying
// library key (making it eligible for garbage collection), and marks this
// key as permanently destroyed. All subsequent Sign/Seed/Equal operations
// return ErrDestroyed. Calling Destroy multiple times is safe (idempotent).
//
// The cached PublicKey remains valid and usable after Destroy. This allows
// verifying previously-created signatures even after the signing key is
// discarded.
func (k *PrivateKey) Destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.destroyed {
		return
	}
	k.destroyed = true
	for i := range k.seed {
		k.seed[i] = 0
	}
	k.key = nil
}

// Bytes returns a fresh copy of the 1952-byte public key encoding.
// Each call allocates a new slice; the caller may freely modify it.
// Returns nil if k is nil.
func (k *PublicKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	return k.key.Bytes()
}

// Verify reports whether sig is a valid ML-DSA-65 signature of msg under
// this public key with an empty context string.
//
// Returns false if k is nil, if len(sig) != SignatureSize, or if the
// cryptographic verification fails. There is no distinction between
// "wrong length" and "wrong signature" from the caller's perspective;
// both mean "do not trust this signature."
func (k *PublicKey) Verify(msg, sig []byte) bool {
	if k == nil {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	return mldsa.Verify(k.key, msg, sig, nil) == nil
}

// VerifyWithContext reports whether sig is a valid signature of msg under
// this public key with the given context string. The context must match the
// one used during signing exactly, or verification will fail.
//
// A context longer than 255 bytes will always return false (no valid
// signature can exist for an oversized context because Sign rejects it).
func (k *PublicKey) VerifyWithContext(msg, sig []byte, ctx string) bool {
	if k == nil {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	return mldsa.Verify(k.key, msg, sig, &mldsa.Options{Context: ctx}) == nil
}

// Equal reports whether k and x represent the same public key
// (constant-time comparison). Returns false if either is nil.
func (k *PublicKey) Equal(x *PublicKey) bool {
	if k == nil || x == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.Bytes(), x.Bytes()) == 1
}
