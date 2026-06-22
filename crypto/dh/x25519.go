// Package dh provides Diffie-Hellman implementations for go-clatter.
package dh

import (
	"crypto/ecdh"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/internal/entropy"
)

// X25519 implements the X25519 DH algorithm.
type X25519 struct{}

// Compile-time interface compliance check.
var _ clatter.DH = (*X25519)(nil)

// NewX25519 returns an X25519 DH instance.
func NewX25519() *X25519 { return &X25519{} }

// Name returns the Noise protocol name for this DH function ("25519").
func (x *X25519) Name() string { return "25519" }

// PubKeyLen returns the public key length in bytes (32).
func (x *X25519) PubKeyLen() int { return 32 }

// SecretKeyLen returns the secret key length in bytes (32).
func (x *X25519) SecretKeyLen() int { return 32 }

// GenerateKeypair reads 32 bytes from rng as a private key scalar.
// Uses ecdh.X25519().NewPrivateKey (GenerateKey ignores rand in Go 1.26).
func (x *X25519) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	var seed [32]byte
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()

	if err := entropy.Fill(rng, seed[:]); err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %w", clatter.ErrDH, err)
	}

	privKey, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return clatter.KeyPair{}, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	return clatter.NewKeyPair(privKey.PublicKey().Bytes(), privKey.Bytes()), nil
}

// DH performs X25519 DH. Rejects low-order peer public keys with
// ErrDHLowOrder. The Noise spec (section 4.1) permits either returning
// output that is purely a function of the public key or signaling an
// error; go-clatter signals an error, which is the safer legal choice.
func (x *X25519) DH(kp clatter.KeyPair, pubkey []byte) ([]byte, error) {
	privKey, err := ecdh.X25519().NewPrivateKey(kp.SecretSlice())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	remotePub, err := ecdh.X25519().NewPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrDH, err)
	}

	shared, err := privKey.ECDH(remotePub)
	if err != nil {
		// For X25519, crypto/ecdh's only ECDH failure is the all-zero
		// shared secret produced by a low-order peer public key.
		return nil, fmt.Errorf("%w: %v", clatter.ErrDHLowOrder, err)
	}

	return shared, nil
}
