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

func NewBlake2s() *Blake2s { return &Blake2s{} }

func (b *Blake2s) Name() string    { return "BLAKE2s" }
func (b *Blake2s) HashLen() int    { return 32 }
func (b *Blake2s) BlockLen() int   { return 64 }

func (b *Blake2s) Hash(data []byte) []byte {
	h := blake2s.Sum256(data)
	return h[:]
}

func (b *Blake2s) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(func() gohash.Hash {
		h, _ := blake2s.New256(nil) // unkeyed
		return h
	}, key)}
}

// Blake2b implements BLAKE2b-512 for Noise.
type Blake2b struct{}

func NewBlake2b() *Blake2b { return &Blake2b{} }

func (b *Blake2b) Name() string    { return "BLAKE2b" }
func (b *Blake2b) HashLen() int    { return 64 }
func (b *Blake2b) BlockLen() int   { return 128 }

func (b *Blake2b) Hash(data []byte) []byte {
	h := blake2b.Sum512(data)
	return h[:]
}

func (b *Blake2b) NewHMAC(key []byte) clatter.HMACWriter {
	return &hmacWriter{mac: hmac.New(func() gohash.Hash {
		h, _ := blake2b.New512(nil) // unkeyed
		return h
	}, key)}
}
