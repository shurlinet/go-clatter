package hash

import (
	"crypto/hmac"
	gohash "hash"

	clatter "github.com/shurlinet/go-clatter"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// Blake2s implements BLAKE2s-256 for Noise.
type Blake2s struct{}

// NewBlake2s returns a BLAKE2s-256 hash function instance.
func NewBlake2s() *Blake2s { return &Blake2s{} }

// Name returns the Noise protocol name for this hash function ("BLAKE2s").
func (b *Blake2s) Name() string { return "BLAKE2s" }

// HashLen returns the hash output length in bytes (32).
func (b *Blake2s) HashLen() int { return 32 }

// BlockLen returns the hash block length in bytes (64).
func (b *Blake2s) BlockLen() int { return 64 }

// Hash returns the BLAKE2s-256 digest of data.
func (b *Blake2s) Hash(data []byte) []byte {
	h := blake2s.Sum256(data)
	return h[:]
}

// NewHMAC returns an HMAC-BLAKE2s writer keyed with key.
func (b *Blake2s) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(func() gohash.Hash {
		h, _ := blake2s.New256(nil) // unkeyed
		return h
	}, key)}
}

// Blake2b implements BLAKE2b-512 for Noise.
type Blake2b struct{}

// NewBlake2b returns a BLAKE2b-512 hash function instance.
func NewBlake2b() *Blake2b { return &Blake2b{} }

// Name returns the Noise protocol name for this hash function ("BLAKE2b").
func (b *Blake2b) Name() string { return "BLAKE2b" }

// HashLen returns the hash output length in bytes (64).
func (b *Blake2b) HashLen() int { return 64 }

// BlockLen returns the hash block length in bytes (128).
func (b *Blake2b) BlockLen() int { return 128 }

// Hash returns the BLAKE2b-512 digest of data.
func (b *Blake2b) Hash(data []byte) []byte {
	h := blake2b.Sum512(data)
	return h[:]
}

// NewHMAC returns an HMAC-BLAKE2b writer keyed with key.
func (b *Blake2b) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(func() gohash.Hash {
		h, _ := blake2b.New512(nil) // unkeyed
		return h
	}, key)}
}
