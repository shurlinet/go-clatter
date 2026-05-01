// Package kem provides Key Encapsulation Mechanism implementations for go-clatter.
package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
)

// MlKem768 implements ML-KEM-768 (FIPS 203) using Go's crypto/mlkem.
// Secret keys are stored as 64-byte seeds (d||z), NOT full 2400-byte keys.
// Wire-compatible with Rust: public keys and ciphertexts are identical.
type MlKem768 struct {
	// testing enables deterministic encapsulation via mlkem's testing API.
	testing bool
}

// NewMlKem768 returns an ML-KEM-768 KEM instance for production use.
func NewMlKem768() *MlKem768 { return &MlKem768{testing: false} }

// NewMlKem768Testing returns an ML-KEM-768 instance that uses deterministic
// encapsulation (reads 32 bytes from RNG for m). For test vector generation only.
func NewMlKem768Testing() *MlKem768 { return &MlKem768{testing: true} }

func (k *MlKem768) Name() string          { return "MLKEM768" }
func (k *MlKem768) PubKeyLen() int        { return mlkem.EncapsulationKeySize768 }
func (k *MlKem768) SecretKeyLen() int      { return 64 } // seed form
func (k *MlKem768) CiphertextLen() int     { return mlkem.CiphertextSize768 }
func (k *MlKem768) SharedSecretLen() int   { return mlkem.SharedKeySize }

// GenerateKeypair reads 64 bytes from rng as seed (d||z), then calls
// NewDecapsulationKey768(seed). FIPS 203 deterministic expansion.
func (k *MlKem768) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [64]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if _, err := rng.Read(seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
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
	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	if k.testing {
		// Deterministic: read 32 bytes from rng as entropy (F175)
		var entropy [32]byte
		defer func() {
			for i := range entropy {
				entropy[i] = 0
			}
		}()
		if _, err := rng.Read(entropy[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
		}
		// mlkemtest.Encapsulate768 returns (sharedKey, ciphertext, err)
		sharedKey, ciphertext, err := mlkemtest.Encapsulate768(ek, entropy[:])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
		}
		return ciphertext, sharedKey, nil
	}

	// Production: internal randomness
	sharedKey, ciphertext := ek.Encapsulate()
	return ciphertext, sharedKey, nil
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
