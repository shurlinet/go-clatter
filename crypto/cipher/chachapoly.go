// Package cipher provides AEAD cipher implementations for go-clatter.
package cipher

import (
	"encoding/binary"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaChaPoly implements ChaCha20-Poly1305 with little-endian nonce encoding.
type ChaChaPoly struct{}

// NewChaChaPoly returns a ChaChaPoly cipher instance.
func NewChaChaPoly() *ChaChaPoly { return &ChaChaPoly{} }

// Name returns the Noise protocol name for this cipher ("ChaChaPoly").
func (c *ChaChaPoly) Name() string { return "ChaChaPoly" }

// TagLen returns the authentication tag length in bytes (16).
func (c *ChaChaPoly) TagLen() int { return 16 }

// KeyLen returns the key length in bytes (32).
func (c *ChaChaPoly) KeyLen() int { return 32 }

// chachaPolyNonce constructs a 12-byte nonce: 4 zero bytes + 8 little-endian nonce.
func chachaPolyNonce(n uint64) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

// Encrypt encrypts plaintext with the given key, nonce, and additional data.
// The result is appended to out and returned.
func (c *ChaChaPoly) Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	n := chachaPolyNonce(nonce)
	// In-place: Seal appends to out[:0], which may alias plaintext.
	result := aead.Seal(out[:0], n[:], plaintext, ad)
	return result, nil
}

// Decrypt decrypts ciphertext with the given key, nonce, and additional data.
// Returns [clatter.ErrDecrypt] on authentication failure.
func (c *ChaChaPoly) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	n := chachaPolyNonce(nonce)
	result, err := aead.Open(out[:0], n[:], ciphertext, ad)
	if err != nil {
		return nil, clatter.ErrDecrypt
	}
	return result, nil
}
