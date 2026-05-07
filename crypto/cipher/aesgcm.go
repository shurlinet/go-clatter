package cipher

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"encoding/binary"
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
)

// AesGcm implements AES-256-GCM with big-endian nonce encoding.
type AesGcm struct{}

// NewAesGcm returns an AES-256-GCM cipher instance.
func NewAesGcm() *AesGcm { return &AesGcm{} }

// Name returns the Noise protocol name for this cipher ("AESGCM").
func (a *AesGcm) Name() string { return "AESGCM" }

// TagLen returns the authentication tag length in bytes (16).
func (a *AesGcm) TagLen() int { return 16 }

// KeyLen returns the key length in bytes (32).
func (a *AesGcm) KeyLen() int { return 32 }

// aesGcmNonce constructs a 12-byte nonce: 4 zero bytes + 8 big-endian nonce.
func aesGcmNonce(n uint64) [12]byte {
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], n)
	return nonce
}

// Encrypt encrypts plaintext with the given key, nonce, and additional data.
// The result is appended to out and returned.
func (a *AesGcm) Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	aead, err := gocipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	n := aesGcmNonce(nonce)
	result := aead.Seal(out[:0], n[:], plaintext, ad)
	return result, nil
}

// Decrypt decrypts ciphertext with the given key, nonce, and additional data.
// Returns [clatter.ErrDecrypt] on authentication failure.
func (a *AesGcm) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	aead, err := gocipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", clatter.ErrCipher, err)
	}
	n := aesGcmNonce(nonce)
	result, err := aead.Open(out[:0], n[:], ciphertext, ad)
	if err != nil {
		return nil, clatter.ErrDecrypt
	}
	return result, nil
}
