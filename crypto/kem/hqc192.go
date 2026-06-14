//go:build hqc

package kem

import (
	"bytes"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/internal/entropy"
	"github.com/shurlinet/go-hqc"
	"github.com/shurlinet/go-hqc/hqctest"
)

// Hqc192 implements HQC-192 (NIST backup KEM, pre-FIPS 207) using go-hqc.
// Secret keys are stored as 32-byte seeds (seed_kem), not full expanded keys.
//
// HQC is experimental: every GenerateKeypair, Encapsulate, and Decapsulate
// call checks [clatter.AllowExperimental] and returns
// [clatter.ErrExperimentalNotAllowed] if false. This gate will be removed
// when NIST publishes FIPS 207.
type Hqc192 struct {
	// testing enables deterministic encapsulation via go-hqc's testing API.
	testing bool
}

// Compile-time check: Hqc192 supports SEEC-hedged encapsulation.
var _ clatter.CoinsEncapsulator = (*Hqc192)(nil)

// NewHqc192 returns an HQC-192 KEM instance for production use.
func NewHqc192() *Hqc192 { return &Hqc192{testing: false} }

// NewHqc192Testing returns an HQC-192 instance that uses deterministic
// encapsulation (reads 40 bytes from RNG for m+salt). For test vector
// generation only.
func NewHqc192Testing() *Hqc192 { return &Hqc192{testing: true} }

// Name returns the Noise protocol name for this KEM ("HQC192").
func (k *Hqc192) Name() string { return "HQC192" }

// PubKeyLen returns the encapsulation key length in bytes (4514).
func (k *Hqc192) PubKeyLen() int { return hqc.PublicKeySize192 }

// SecretKeyLen returns the secret key length in bytes (32, seed form).
func (k *Hqc192) SecretKeyLen() int { return hqc.SeedSize192 }

// CiphertextLen returns the ciphertext length in bytes (8978).
func (k *Hqc192) CiphertextLen() int { return hqc.CiphertextSize192 }

// SharedSecretLen returns the shared secret length in bytes (32).
func (k *Hqc192) SharedSecretLen() int { return hqc.SharedSecretSize192 }

// GenerateKeypair generates an HQC-192 keypair from 32 bytes of rng entropy.
// The expanded decapsulation key is destroyed immediately after extracting
// the encapsulation key. Returns [clatter.ErrExperimentalNotAllowed] if
// [clatter.AllowExperimental] is false.
func (k *Hqc192) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	if !clatter.AllowExperimental.Load() {
		return clatter.KeyPair{}, fmt.Errorf("%w: HQC192", clatter.ErrExperimentalNotAllowed)
	}

	var seed [hqc.SeedSize192]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if err := entropy.Fill(rng, seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %w", clatter.ErrKEM, err)
	}

	dk, err := hqc.NewDecapsulationKey192(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %w", clatter.ErrKEM, err)
	}

	ek := dk.EncapsulationKey()
	dk.Destroy()

	return clatter.NewKeyPair(ek.Bytes(), seed[:]), nil
}

// Encapsulate generates a shared secret and ciphertext from a public key.
// In testing mode, reads 40 bytes from rng into a local buffer and passes
// a [bytes.NewReader] to go-hqc's deterministic encapsulation. In production
// mode, go-hqc draws from crypto/rand internally (rng is unused for encaps).
// Returns [clatter.ErrExperimentalNotAllowed] if [clatter.AllowExperimental]
// is false.
func (k *Hqc192) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	if !clatter.AllowExperimental.Load() {
		return nil, nil, fmt.Errorf("%w: HQC192", clatter.ErrExperimentalNotAllowed)
	}

	// Parse the public key BEFORE any rng read: an invalid pk must not
	// consume entropy (preserves the v0.5.0 rng draw order on error
	// paths, which deterministic-replay consumers can observe).
	ek, err := hqc.ParseEncapsulationKey192(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", clatter.ErrKEMInvalidKey, err)
	}

	if k.testing {
		// Deterministic: read the coins from rng, then run the same coins
		// path as EncapsulateWithCoins.
		var coins [40]byte // 24 bytes m + 16 bytes salt
		defer func() {
			for i := range coins {
				coins[i] = 0
			}
		}()
		if err := entropy.Fill(rng, coins[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", clatter.ErrKEM, err)
		}
		return k.encapsWithCoins(pk, coins[:])
	}

	sharedSecret, ciphertext := ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// EncapsCoinsLen returns the encapsulation coin length in bytes
// (40: 24 bytes m + 16 bytes salt).
func (k *Hqc192) EncapsCoinsLen() int { return 40 }

// EncapsulateWithCoins encapsulates to pk using externally supplied coins
// (go-hqc's deterministic encapsulation interface). len(coins) must be
// exactly 40. Used by SEEC-hedged handshakes; the same (pk, coins) pair
// always produces the same (ct, ss). Returns
// [clatter.ErrExperimentalNotAllowed] if [clatter.AllowExperimental] is
// false: the experimental gate applies to every HQC entry point.
func (k *Hqc192) EncapsulateWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	return k.encapsWithCoins(pk, coins)
}

// encapsWithCoins is the single coins-driven encapsulation path shared by
// testing-mode Encapsulate and EncapsulateWithCoins. The experimental gate
// is enforced here so no coins-driven path can bypass it.
func (k *Hqc192) encapsWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	if !clatter.AllowExperimental.Load() {
		return nil, nil, fmt.Errorf("%w: HQC192", clatter.ErrExperimentalNotAllowed)
	}

	if len(coins) != 40 {
		return nil, nil, fmt.Errorf("%w: encapsulation coins must be 40 bytes, got %d", clatter.ErrKEM, len(coins))
	}

	ek, err := hqc.ParseEncapsulationKey192(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", clatter.ErrKEMInvalidKey, err)
	}

	sharedSecret, ciphertext := hqctest.Encapsulate192(ek, bytes.NewReader(coins))
	// Validate the upstream return against the declared geometry: a
	// truncated ciphertext or shared secret must fail closed here, not
	// silently truncate at a wire copy downstream.
	if len(ciphertext) != k.CiphertextLen() || len(sharedSecret) != k.SharedSecretLen() {
		return nil, nil, fmt.Errorf("%w: encapsulation returned %d-byte ciphertext and %d-byte secret (want %d and %d)",
			clatter.ErrKEM, len(ciphertext), len(sharedSecret), k.CiphertextLen(), k.SharedSecretLen())
	}
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext and a 32-byte
// secret key seed. The expanded decapsulation key is reconstructed from
// the seed and destroyed immediately after use. Returns
// [clatter.ErrExperimentalNotAllowed] if [clatter.AllowExperimental] is false.
func (k *Hqc192) Decapsulate(ct, sk []byte) ([]byte, error) {
	if !clatter.AllowExperimental.Load() {
		return nil, fmt.Errorf("%w: HQC192", clatter.ErrExperimentalNotAllowed)
	}

	if len(sk) != hqc.SeedSize192 {
		return nil, clatter.ErrKEMInvalidKey
	}

	dk, err := hqc.NewDecapsulationKey192(sk)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", clatter.ErrKEMInvalidKey, err)
	}
	defer dk.Destroy()

	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", clatter.ErrKEMDecapsulate, err)
	}

	return ss, nil
}
