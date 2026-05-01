// Package dh provides Diffie-Hellman implementations for go-clatter.
package dh

import (
	"crypto/ecdh"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
)

// X25519 implements the X25519 DH algorithm.
type X25519 struct{}

// NewX25519 returns an X25519 DH instance.
func NewX25519() *X25519 { return &X25519{} }

func (x *X25519) Name() string   { return "25519" }
func (x *X25519) PubKeyLen() int { return 32 }

// GenerateKeypair reads 32 bytes from rng as a private key scalar.
// Uses ecdh.X25519().NewPrivateKey (F174: GenerateKey ignores rand in Go 1.26).
func (x *X25519) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [32]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if _, err := rng.Read(seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	privKey, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	return clatter.NewKeyPair(privKey.PublicKey().Bytes(), privKey.Bytes()), nil
}

// DH performs X25519 DH. Returns zeros on low-order point (F84).
func (x *X25519) DH(kp clatter.KeyPair, pubkey []byte) ([]byte, error) {
	privKey, err := ecdh.X25519().NewPrivateKey(kp.SecretSlice())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	remotePub, err := ecdh.X25519().NewPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrDHLowOrder, err)
	}

	shared, err := privKey.ECDH(remotePub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	// Check for all-zero output (low-order point)
	allZero := true
	for _, b := range shared {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil, clatter.ErrDHLowOrder
	}

	return shared, nil
}
