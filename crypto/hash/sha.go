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

func NewSha256() *Sha256 { return &Sha256{} }

func (s *Sha256) Name() string    { return "SHA256" }
func (s *Sha256) HashLen() int    { return 32 }
func (s *Sha256) BlockLen() int   { return 64 }

func (s *Sha256) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (s *Sha256) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(sha256.New, key)}
}

// Sha512 implements SHA-512 for Noise.
type Sha512 struct{}

func NewSha512() *Sha512 { return &Sha512{} }

func (s *Sha512) Name() string    { return "SHA512" }
func (s *Sha512) HashLen() int    { return 64 }
func (s *Sha512) BlockLen() int   { return 128 }

func (s *Sha512) Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}

func (s *Sha512) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(sha512.New, key)}
}
