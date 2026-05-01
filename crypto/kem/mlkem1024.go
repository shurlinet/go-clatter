package kem

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
)

// MlKem1024 implements ML-KEM-1024 (FIPS 203) using Go's crypto/mlkem.
type MlKem1024 struct {
	testing bool
}

func NewMlKem1024() *MlKem1024        { return &MlKem1024{testing: false} }
func NewMlKem1024Testing() *MlKem1024 { return &MlKem1024{testing: true} }

func (k *MlKem1024) Name() string        { return "MlKem1024" }
func (k *MlKem1024) PubKeyLen() int      { return mlkem.EncapsulationKeySize1024 }
func (k *MlKem1024) SecretKeyLen() int    { return 64 }
func (k *MlKem1024) CiphertextLen() int   { return mlkem.CiphertextSize1024 }
func (k *MlKem1024) SharedSecretLen() int { return mlkem.SharedKeySize }

func (k *MlKem1024) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [64]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if _, err := rng.Read(seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	dk, err := mlkem.NewDecapsulationKey1024(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
	}

	ek := dk.EncapsulationKey()
	return clatter.NewKeyPair(ek.Bytes(), seed[:]), nil
}

func (k *MlKem1024) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey1024(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEMInvalidKey, err)
	}

	if k.testing {
		var entropy [32]byte
		defer func() {
			for i := range entropy {
				entropy[i] = 0
			}
		}()
		if _, err := rng.Read(entropy[:]); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
		}
		sharedKey, ciphertext, err := mlkemtest.Encapsulate1024(ek, entropy[:])
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", clatter.ErrKEM, err)
		}
		return ciphertext, sharedKey, nil
	}

	sharedKey, ciphertext := ek.Encapsulate()
	return ciphertext, sharedKey, nil
}

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
