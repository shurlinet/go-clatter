package hash

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

func TestSha256_Hash(t *testing.T) {
	h := NewSha256()
	data := []byte("test data")
	got := h.Hash(data)
	expected := sha256.Sum256(data)
	if !bytes.Equal(got, expected[:]) {
		t.Fatal("SHA-256 hash mismatch")
	}
}

func TestSha512_Hash(t *testing.T) {
	h := NewSha512()
	data := []byte("test data")
	got := h.Hash(data)
	expected := sha512.Sum512(data)
	if !bytes.Equal(got, expected[:]) {
		t.Fatal("SHA-512 hash mismatch")
	}
}

func TestBlake2s_Hash(t *testing.T) {
	h := NewBlake2s()
	got := h.Hash([]byte("test"))
	if len(got) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(got))
	}
}

func TestBlake2b_Hash(t *testing.T) {
	h := NewBlake2b()
	got := h.Hash([]byte("test"))
	if len(got) != 64 {
		t.Fatalf("expected 64-byte hash, got %d", len(got))
	}
}

func testHashProperties(t *testing.T, h clatter.HashFunc) {
	t.Helper()

	// HashLen matches actual output
	got := h.Hash([]byte("abc"))
	if len(got) != h.HashLen() {
		t.Fatalf("%s: HashLen()=%d but Hash() produced %d bytes", h.Name(), h.HashLen(), len(got))
	}

	// Deterministic
	got2 := h.Hash([]byte("abc"))
	if !bytes.Equal(got, got2) {
		t.Fatalf("%s: hash not deterministic", h.Name())
	}

	// Different input -> different output
	diff := h.Hash([]byte("abd"))
	if bytes.Equal(got, diff) {
		t.Fatalf("%s: different inputs produced same hash", h.Name())
	}
}

func TestHashProperties(t *testing.T) {
	for _, h := range []clatter.HashFunc{NewSha256(), NewSha512(), NewBlake2s(), NewBlake2b()} {
		t.Run(h.Name(), func(t *testing.T) {
			testHashProperties(t, h)
		})
	}
}

func testHMACProperties(t *testing.T, h clatter.HashFunc) {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)

	// Basic HMAC
	mac := h.NewHMAC(key)
	mac.Write([]byte("hello"))
	mac.Write([]byte(" world"))
	sum1 := mac.Sum()
	if len(sum1) != h.HashLen() {
		t.Fatalf("%s: HMAC output %d bytes, expected %d", h.Name(), len(sum1), h.HashLen())
	}

	// Multi-write equals single write (F173: RFC 2104 compliance)
	mac2 := h.NewHMAC(key)
	mac2.Write([]byte("hello world"))
	sum2 := mac2.Sum()
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("%s: multi-write HMAC differs from single-write", h.Name())
	}

	// Different key -> different HMAC
	mac3 := h.NewHMAC(bytes.Repeat([]byte{0x43}, 32))
	mac3.Write([]byte("hello world"))
	sum3 := mac3.Sum()
	if bytes.Equal(sum2, sum3) {
		t.Fatalf("%s: different keys produced same HMAC", h.Name())
	}

	// Empty message HMAC
	mac4 := h.NewHMAC(key)
	sum4 := mac4.Sum()
	if len(sum4) != h.HashLen() {
		t.Fatalf("%s: empty HMAC wrong length", h.Name())
	}
}

func TestHMACProperties(t *testing.T) {
	for _, h := range []clatter.HashFunc{NewSha256(), NewSha512(), NewBlake2s(), NewBlake2b()} {
		t.Run(h.Name(), func(t *testing.T) {
			testHMACProperties(t, h)
		})
	}
}

func TestHashNames(t *testing.T) {
	tests := []struct {
		h    clatter.HashFunc
		name string
	}{
		{NewSha256(), "SHA256"},
		{NewSha512(), "SHA512"},
		{NewBlake2s(), "BLAKE2s"},
		{NewBlake2b(), "BLAKE2b"},
	}
	for _, tt := range tests {
		if tt.h.Name() != tt.name {
			t.Fatalf("expected %q, got %q", tt.name, tt.h.Name())
		}
	}
}

func TestHashBlockLen(t *testing.T) {
	tests := []struct {
		h   clatter.HashFunc
		bl  int
	}{
		{NewSha256(), 64},
		{NewSha512(), 128},
		{NewBlake2s(), 64},
		{NewBlake2b(), 128},
	}
	for _, tt := range tests {
		if tt.h.BlockLen() != tt.bl {
			t.Fatalf("%s: expected BlockLen=%d, got %d", tt.h.Name(), tt.bl, tt.h.BlockLen())
		}
	}
}
