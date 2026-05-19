//go:build hqc

package kem

import (
	"bytes"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-hqc"
	"github.com/shurlinet/go-hqc/hqctest"
)

// Hqc128 implements HQC-128 (NIST backup KEM, pre-FIPS 207) using go-hqc.
// Secret keys are stored as 32-byte seeds (seed_kem), not full expanded keys.
//
// HQC is experimental: every GenerateKeypair, Encapsulate, and Decapsulate
// call checks [clatter.AllowExperimental] and returns
// [clatter.ErrExperimentalNotAllowed] if false. This gate will be removed
// when NIST publishes FIPS 207.
type Hqc128 struct {
	// testing enables deterministic encapsulation via go-hqc's testing API.
	testing bool
}

// NewHqc128 returns an HQC-128 KEM instance for production use.
func NewHqc128() *Hqc128 { return &Hqc128{testing: false} }

// NewHqc128Testing returns an HQC-128 instance that uses deterministic
// encapsulation (reads 32 bytes from RNG for m+salt). For test vector
// generation only.
func NewHqc128Testing() *Hqc128 { return &Hqc128{testing: true} }

// Name returns the Noise protocol name for this KEM ("HQC128").
func (k *Hqc128) Name() string { return "HQC128" }

// PubKeyLen returns the encapsulation key length in bytes (2241).
func (k *Hqc128) PubKeyLen() int { return hqc.PublicKeySize128 }

// SecretKeyLen returns the secret key length in bytes (32, seed form).
func (k *Hqc128) SecretKeyLen() int { return hqc.SeedSize128 }

// CiphertextLen returns the ciphertext length in bytes (4433).
func (k *Hqc128) CiphertextLen() int { return hqc.CiphertextSize128 }

// SharedSecretLen returns the shared secret length in bytes (32).
func (k *Hqc128) SharedSecretLen() int { return hqc.SharedSecretSize128 }

// GenerateKeypair generates an HQC-128 keypair from 32 bytes of rng entropy.
// The expanded decapsulation key is destroyed immediately after extracting
// the encapsulation key. Returns [clatter.ErrExperimentalNotAllowed] if
// [clatter.AllowExperimental] is false.
func (k *Hqc128) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	if !clatter.AllowExperimental.Load() {
		return clatter.KeyPair{}, fmt.Errorf("%w: HQC128", clatter.ErrExperimentalNotAllowed)
	}

	var seed [hqc.SeedSize128]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if _, err := rng.Read(seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	dk, err := hqc.NewDecapsulationKey128(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	ek := dk.EncapsulationKey()
	dk.Destroy()

	return clatter.NewKeyPair(ek.Bytes(), seed[:]), nil
}

// Encapsulate generates a shared secret and ciphertext from a public key.
// In testing mode, reads 32 bytes from rng into a local buffer and passes
// a [bytes.NewReader] to go-hqc's deterministic encapsulation. In production
// mode, go-hqc draws from crypto/rand internally (rng is unused for encaps).
// Returns [clatter.ErrExperimentalNotAllowed] if [clatter.AllowExperimental]
// is false.
func (k *Hqc128) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	if !clatter.AllowExperimental.Load() {
		return nil, nil, fmt.Errorf("%w: HQC128", clatter.ErrExperimentalNotAllowed)
	}

	ek, err := hqc.ParseEncapsulationKey128(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	if k.testing {
		var entropy [32]byte // 16 bytes m + 16 bytes salt
		defer func() {
			for i := range entropy {
				entropy[i] = 0
			}
		}()
		if _, err := rng.Read(entropy[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
		}
		sharedSecret, ciphertext := hqctest.Encapsulate128(ek, bytes.NewReader(entropy[:]))
		return ciphertext, sharedSecret, nil
	}

	sharedSecret, ciphertext := ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

// Decapsulate recovers the shared secret from ciphertext and a 32-byte
// secret key seed. The expanded decapsulation key is reconstructed from
// the seed and destroyed immediately after use. Returns
// [clatter.ErrExperimentalNotAllowed] if [clatter.AllowExperimental] is false.
func (k *Hqc128) Decapsulate(ct, sk []byte) ([]byte, error) {
	if !clatter.AllowExperimental.Load() {
		return nil, fmt.Errorf("%w: HQC128", clatter.ErrExperimentalNotAllowed)
	}

	if len(sk) != hqc.SeedSize128 {
		return nil, clatter.ErrKEMInvalidKey
	}

	dk, err := hqc.NewDecapsulationKey128(sk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}
	defer dk.Destroy()

	ss, err := dk.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrKEMDecapsulate, err)
	}

	return ss, nil
}
