// Package hash provides hash function implementations for go-clatter.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	gohash "hash"

	clatter "github.com/shurlinet/go-clatter"
)

// hmacWriter wraps Go's crypto/hmac to implement clatter.HMACWriter.
type hmacWriter struct {
	mac gohash.Hash
}

func (h *hmacWriter) Write(p []byte) (int, error) { return h.mac.Write(p) }
func (h *hmacWriter) Sum() []byte                 { return h.mac.Sum(nil) }

// Sha256 implements SHA-256 for Noise.
type Sha256 struct{}

// NewSha256 returns a SHA-256 hash function instance.
func NewSha256() *Sha256 { return &Sha256{} }

// Name returns the Noise protocol name for this hash function ("SHA256").
func (s *Sha256) Name() string { return "SHA256" }

// HashLen returns the hash output length in bytes (32).
func (s *Sha256) HashLen() int { return 32 }

// BlockLen returns the hash block length in bytes (64).
func (s *Sha256) BlockLen() int { return 64 }

// Hash returns the SHA-256 digest of data.
func (s *Sha256) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// NewHMAC returns an HMAC-SHA-256 writer keyed with key.
func (s *Sha256) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(sha256.New, key)}
}

// Sha512 implements SHA-512 for Noise.
type Sha512 struct{}

// NewSha512 returns a SHA-512 hash function instance.
func NewSha512() *Sha512 { return &Sha512{} }

// Name returns the Noise protocol name for this hash function ("SHA512").
func (s *Sha512) Name() string { return "SHA512" }

// HashLen returns the hash output length in bytes (64).
func (s *Sha512) HashLen() int { return 64 }

// BlockLen returns the hash block length in bytes (128).
func (s *Sha512) BlockLen() int { return 128 }

// Hash returns the SHA-512 digest of data.
func (s *Sha512) Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

// NewHMAC returns an HMAC-SHA-512 writer keyed with key.
func (s *Sha512) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(sha512.New, key)}
}
