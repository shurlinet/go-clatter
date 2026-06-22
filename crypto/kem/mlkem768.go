// Package kem provides Key Encapsulation Mechanism implementations for go-clatter.
package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/internal/entropy"
)

// MlKem768 implements ML-KEM-768 (FIPS 203) using Go's crypto/mlkem.
// Secret keys are stored as 64-byte seeds (d||z), NOT full 2400-byte keys.
// Wire-compatible with Rust: public keys and ciphertexts are identical.
type MlKem768 struct {
	// testing enables deterministic encapsulation via mlkem's testing API.
	testing bool
}

// Compile-time check: MlKem768 supports SEEC-hedged encapsulation.
var _ clatter.CoinsEncapsulator = (*MlKem768)(nil)

// NewMlKem768 returns an ML-KEM-768 KEM instance for production use.
func NewMlKem768() *MlKem768 { return &MlKem768{testing: false} }

// NewMlKem768Testing returns an ML-KEM-768 instance that uses deterministic
// encapsulation (reads 32 bytes from RNG for m). For test vector generation only.
func NewMlKem768Testing() *MlKem768 { return &MlKem768{testing: true} }

// Name returns the Noise protocol name for this KEM ("MLKEM768").
func (k *MlKem768) Name() string { return "MLKEM768" }

// PubKeyLen returns the encapsulation key length in bytes (1184).
func (k *MlKem768) PubKeyLen() int { return mlkem.EncapsulationKeySize768 }

// SecretKeyLen returns the secret key length in bytes (64, seed form).
func (k *MlKem768) SecretKeyLen() int { return 64 }

// CiphertextLen returns the ciphertext length in bytes (1088).
func (k *MlKem768) CiphertextLen() int { return mlkem.CiphertextSize768 }

// SharedSecretLen returns the shared secret length in bytes (32).
func (k *MlKem768) SharedSecretLen() int { return mlkem.SharedKeySize }

// GenerateKeypair reads 64 bytes from rng as seed (d||z), then calls
// NewDecapsulationKey768(seed). FIPS 203 deterministic expansion.
func (k *MlKem768) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [64]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if err := entropy.Fill(rng, seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %w", clatter.ErrKEM, err)
	}

	dk, err := mlkem.NewDecapsulationKey768(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	ek := dk.EncapsulationKey()
	// NewKeyPair copies both slices, so seed[:] is safe to zero after this.
	return clatter.NewKeyPair(ek.Bytes(), seed[:]), nil
}

// Encapsulate generates a shared secret and ciphertext from a public key.
// In testing mode, reads 32 bytes from rng for deterministic encapsulation.
// In production mode, uses Go's internal DRBG (rng is ignored for encaps).
func (k *MlKem768) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	// Parse the public key BEFORE any rng read: an invalid pk must not
	// consume entropy (preserves the v0.5.0 rng draw order on error
	// paths, which deterministic-replay consumers can observe).
	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	if k.testing {
		// Deterministic: read 32 bytes from rng as encapsulation coins,
		// then run the same coins path as EncapsulateWithCoins.
		var coins [32]byte
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

	// Production: internal randomness
	sharedKey, ciphertext := ek.Encapsulate()
	return ciphertext, sharedKey, nil
}

// EncapsCoinsLen returns the encapsulation coin length in bytes (32, the
// FIPS 203 message m).
func (k *MlKem768) EncapsCoinsLen() int { return 32 }

// EncapsulateWithCoins encapsulates to pk using externally supplied coins
// (FIPS 203 Encaps_internal via crypto/mlkem/mlkemtest). len(coins) must
// be exactly 32. Used by SEEC-hedged handshakes; the same (pk, coins)
// pair always produces the same (ct, ss).
func (k *MlKem768) EncapsulateWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	return k.encapsWithCoins(pk, coins)
}

// encapsWithCoins is the single coins-driven encapsulation path shared by
// testing-mode Encapsulate and EncapsulateWithCoins.
func (k *MlKem768) encapsWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	if len(coins) != 32 {
		return nil, nil, fmt.Errorf("%w: encapsulation coins must be 32 bytes, got %d", clatter.ErrKEM, len(coins))
	}

	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	// mlkemtest.Encapsulate768 returns (sharedKey, ciphertext, err)
	sharedKey, ciphertext, err := mlkemtest.Encapsulate768(ek, coins)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}
	// Validate the upstream return against the declared geometry: a
	// truncated ciphertext or shared secret must fail closed here, not
	// silently truncate at a wire copy downstream.
	if len(ciphertext) != k.CiphertextLen() || len(sharedKey) != k.SharedSecretLen() {
		return nil, nil, fmt.Errorf("%w: encapsulation returned %d-byte ciphertext and %d-byte secret (want %d and %d)",
			clatter.ErrKEM, len(ciphertext), len(sharedKey), k.CiphertextLen(), k.SharedSecretLen())
	}
	return ciphertext, sharedKey, nil
}

// ValidatePublicKey reports whether pk is a well-formed ML-KEM-768
// encapsulation key, running the FIPS 203 length + modulus/encoding check via
// crypto/mlkem.NewEncapsulationKey768 (the same parse Encapsulate performs).
// No rng, no side effects. Returns ErrKEMInvalidKey on a malformed key.
func (k *MlKem768) ValidatePublicKey(pk []byte) error {
	if _, err := mlkem.NewEncapsulationKey768(pk); err != nil {
		return fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}
	return nil
}

// Decapsulate recovers the shared secret from ciphertext and secret key seed.
func (k *MlKem768) Decapsulate(ct, sk []byte) ([]byte, error) {
	if len(sk) != 64 {
		return nil, clatter.ErrKEMInvalidKey
	}

	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMDecapsulate, err)
	}

	return ss, nil
}
