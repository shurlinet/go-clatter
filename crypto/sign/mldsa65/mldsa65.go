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
// All signing methods acquire a read lock; Destroy acquires a write lock.
// After Destroy, all methods return ErrDestroyed.
type PrivateKey struct {
	mu        sync.RWMutex
	key       *mldsa.PrivateKey
	seed      [SeedSize]byte
	pub       *PublicKey // cached, survives Destroy
	destroyed bool
}

// PublicKey is an ML-DSA-65 public key.
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

// NewPublicKey creates a public key from its 1952-byte encoded form.
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

// Sign signs a message using hedged randomness (recommended for production).
func (k *PrivateKey) Sign(msg []byte) ([]byte, error) {
	return k.signInternal(msg, "", false)
}

// SignWithContext signs a message with a context string (max 255 bytes).
func (k *PrivateKey) SignWithContext(msg []byte, ctx string) ([]byte, error) {
	return k.signInternal(msg, ctx, false)
}

// SignDeterministic signs a message deterministically.
// For test vector generation ONLY. Production code MUST use Sign.
func (k *PrivateKey) SignDeterministic(msg []byte) ([]byte, error) {
	return k.signInternal(msg, "", true)
}

// SignDeterministicWithContext signs deterministically with a context string.
// For test vector generation ONLY.
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

// Equal reports whether k and x hold the same seed.
// Returns false if either key is nil or destroyed.
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

// Destroy zeros the seed, nils the underlying key, and marks this key as
// destroyed. All subsequent operations return ErrDestroyed. Idempotent.
// The cached PublicKey remains valid after Destroy.
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

// Bytes returns a copy of the public key encoding (1952 bytes).
func (k *PublicKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	return k.key.Bytes()
}

// Verify reports whether sig is a valid signature of msg by this public key.
func (k *PublicKey) Verify(msg, sig []byte) bool {
	if k == nil {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	return mldsa.Verify(k.key, msg, sig, nil) == nil
}

// VerifyWithContext verifies a signature with a context string.
func (k *PublicKey) VerifyWithContext(msg, sig []byte, ctx string) bool {
	if k == nil {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}
	return mldsa.Verify(k.key, msg, sig, &mldsa.Options{Context: ctx}) == nil
}

// Equal reports whether k and x are the same public key.
func (k *PublicKey) Equal(x *PublicKey) bool {
	if k == nil || x == nil {
		return false
	}
	return subtle.ConstantTimeCompare(k.Bytes(), x.Bytes()) == 1
}
