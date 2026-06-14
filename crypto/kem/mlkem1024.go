package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/internal/entropy"
)

// MlKem1024 implements ML-KEM-1024 (FIPS 203) using Go's crypto/mlkem.
type MlKem1024 struct {
	testing bool
}

// Compile-time check: MlKem1024 supports SEEC-hedged encapsulation.
var _ clatter.CoinsEncapsulator = (*MlKem1024)(nil)

// NewMlKem1024 returns an ML-KEM-1024 KEM instance for production use.
func NewMlKem1024() *MlKem1024 { return &MlKem1024{testing: false} }

// NewMlKem1024Testing returns an ML-KEM-1024 instance that uses deterministic
// encapsulation (reads 32 bytes from RNG for m). For test vector generation only.
func NewMlKem1024Testing() *MlKem1024 { return &MlKem1024{testing: true} }

// Name returns the Noise protocol name for this KEM ("MLKEM1024").
func (k *MlKem1024) Name() string { return "MLKEM1024" }

// PubKeyLen returns the encapsulation key length in bytes (1568).
func (k *MlKem1024) PubKeyLen() int { return mlkem.EncapsulationKeySize1024 }

// SecretKeyLen returns the secret key length in bytes (64, seed form).
func (k *MlKem1024) SecretKeyLen() int { return 64 }

// CiphertextLen returns the ciphertext length in bytes (1568).
func (k *MlKem1024) CiphertextLen() int { return mlkem.CiphertextSize1024 }

// SharedSecretLen returns the shared secret length in bytes (32).
func (k *MlKem1024) SharedSecretLen() int { return mlkem.SharedKeySize }

// GenerateKeypair reads 64 bytes from rng as seed (d||z), then calls
// NewDecapsulationKey1024(seed). FIPS 203 deterministic expansion.
func (k *MlKem1024) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [64]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if err := entropy.Fill(rng, seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %w", clatter.ErrKEM, err)
	}

	dk, err := mlkem.NewDecapsulationKey1024(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	ek := dk.EncapsulationKey()
	return clatter.NewKeyPair(ek.Bytes(), seed[:]), nil
}

// Encapsulate generates a shared secret and ciphertext from a public key.
// In testing mode, reads 32 bytes from rng for deterministic encapsulation.
// In production mode, uses Go's internal DRBG (rng is ignored for encaps).
func (k *MlKem1024) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	// Parse the public key BEFORE any rng read: an invalid pk must not
	// consume entropy (preserves the v0.5.0 rng draw order on error
	// paths, which deterministic-replay consumers can observe).
	ek, err := mlkem.NewEncapsulationKey1024(pk)
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
func (k *MlKem1024) EncapsCoinsLen() int { return 32 }

// EncapsulateWithCoins encapsulates to pk using externally supplied coins
// (FIPS 203 Encaps_internal via crypto/mlkem/mlkemtest). len(coins) must
// be exactly 32. Used by SEEC-hedged handshakes; the same (pk, coins)
// pair always produces the same (ct, ss).
func (k *MlKem1024) EncapsulateWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	return k.encapsWithCoins(pk, coins)
}

// encapsWithCoins is the single coins-driven encapsulation path shared by
// testing-mode Encapsulate and EncapsulateWithCoins.
func (k *MlKem1024) encapsWithCoins(pk, coins []byte) (ct, ss []byte, err error) {
	if len(coins) != 32 {
		return nil, nil, fmt.Errorf("%w: encapsulation coins must be 32 bytes, got %d", clatter.ErrKEM, len(coins))
	}

	ek, err := mlkem.NewEncapsulationKey1024(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	sharedKey, ciphertext, err := mlkemtest.Encapsulate1024(ek, coins)
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

// Decapsulate recovers the shared secret from ciphertext and secret key seed.
func (k *MlKem1024) Decapsulate(ct, sk []byte) ([]byte, error) {
	if len(sk) != 64 {
		return nil, clatter.ErrKEMInvalidKey
	}

	dk, err := mlkem.NewDecapsulationKey1024(sk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMDecapsulate, err)
	}

	return ss, nil
}
