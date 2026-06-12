package dh

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	clatter "github.com/shurlinet/go-clatter"
)

var errEntropyHealth = errors.New("entropy health failed")

// fullThenErrRNG fills the entire request in one call and returns the
// configured error with it - the io.ReadFull fail-open case (H-11).
type fullThenErrRNG struct{ err error }

func (r *fullThenErrRNG) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xA5
	}
	return len(p), r.err
}

func patternedBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%255 + 1)
	}
	return b
}

func TestX25519_KeygenRNGSemantics(t *testing.T) {
	x := NewX25519()

	// Truncated (k > 0 then EOF): must error, propagating io.EOF.
	// v0.5.0 silently zero-padded this seed.
	_, err := x.GenerateKeypair(bytes.NewReader(patternedBytes(16)))
	if err == nil {
		t.Fatal("truncated rng keygen must fail")
	}
	if !errors.Is(err, clatter.ErrDH) || !errors.Is(err, io.EOF) {
		t.Fatalf("truncated keygen error must wrap ErrDH and io.EOF, got: %v", err)
	}

	// Chunked-but-alive: succeeds with the SAME key as a contiguous read.
	src := patternedBytes(32)
	kp1, err := x.GenerateKeypair(bytes.NewReader(src))
	if err != nil {
		t.Fatalf("contiguous keygen: %v", err)
	}
	kp2, err := x.GenerateKeypair(iotest.OneByteReader(bytes.NewReader(src)))
	if err != nil {
		t.Fatalf("chunked keygen must succeed: %v", err)
	}
	if !bytes.Equal(kp1.Public, kp2.Public) {
		t.Fatal("chunked rng produced a different key than contiguous rng")
	}

	// Full read + non-nil error: THE H-11 case - must be rejected.
	_, err = x.GenerateKeypair(&fullThenErrRNG{err: errEntropyHealth})
	if err == nil {
		t.Fatal("full-read+error keygen must fail closed")
	}
	if !errors.Is(err, clatter.ErrDH) || !errors.Is(err, errEntropyHealth) {
		t.Fatalf("keygen error must wrap ErrDH and the rng error, got: %v", err)
	}

	// Full read + io.EOF: also rejected (matches v0.5.0's fail-closed).
	if _, err = x.GenerateKeypair(&fullThenErrRNG{err: io.EOF}); err == nil {
		t.Fatal("full-read+io.EOF keygen must fail closed")
	}
}
