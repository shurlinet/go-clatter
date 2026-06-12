package kem

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	clatter "github.com/shurlinet/go-clatter"
)

// errEntropyHealth simulates an rng that returns full bytes alongside a
// non-nil error - the io.ReadFull fail-open case (H-11) that must be
// rejected fail-closed.
var errEntropyHealth = errors.New("entropy health failed")

// fullThenErrRNG fills the entire request in one call and returns the
// configured error with it.
type fullThenErrRNG struct{ err error }

func (r *fullThenErrRNG) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xA5
	}
	return len(p), r.err
}

// patternedBytes returns n distinct non-zero bytes for deterministic seeds.
func patternedBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%255 + 1)
	}
	return b
}

// testKeygenRNGSemantics drives the four-case RNG matrix through a KEM's
// GenerateKeypair path: truncated fails, chunked-but-alive succeeds with
// the same key as a contiguous read, full+error and full+EOF fail closed.
func testKeygenRNGSemantics(t *testing.T, k clatter.KEM, seedLen int) {
	t.Helper()

	// Truncated (k > 0 bytes then EOF): must error, propagating io.EOF
	// through the %w chain. v0.5.0 silently zero-padded this seed.
	_, err := k.GenerateKeypair(bytes.NewReader(patternedBytes(seedLen / 2)))
	if err == nil {
		t.Fatal("truncated rng keygen must fail")
	}
	if !errors.Is(err, clatter.ErrKEM) || !errors.Is(err, io.EOF) {
		t.Fatalf("truncated keygen error must wrap ErrKEM and io.EOF, got: %v", err)
	}

	// Chunked-but-alive: succeeds with the SAME key as a contiguous read
	// of the same bytes (the loop completes the seed).
	src := patternedBytes(seedLen)
	kp1, err := k.GenerateKeypair(bytes.NewReader(src))
	if err != nil {
		t.Fatalf("contiguous keygen: %v", err)
	}
	kp2, err := k.GenerateKeypair(iotest.OneByteReader(bytes.NewReader(src)))
	if err != nil {
		t.Fatalf("chunked keygen must succeed: %v", err)
	}
	if !bytes.Equal(kp1.Public, kp2.Public) {
		t.Fatal("chunked rng produced a different key than contiguous rng")
	}

	// Full read + non-nil error: THE H-11 case - must be rejected.
	_, err = k.GenerateKeypair(&fullThenErrRNG{err: errEntropyHealth})
	if err == nil {
		t.Fatal("full-read+error keygen must fail closed")
	}
	if !errors.Is(err, clatter.ErrKEM) || !errors.Is(err, errEntropyHealth) {
		t.Fatalf("keygen error must wrap ErrKEM and the rng error, got: %v", err)
	}

	// Full read + io.EOF: also rejected (matches v0.5.0's fail-closed).
	if _, err = k.GenerateKeypair(&fullThenErrRNG{err: io.EOF}); err == nil {
		t.Fatal("full-read+io.EOF keygen must fail closed")
	}
}

// testEncapsRNGSemantics drives the same matrix through a testing-mode
// KEM's deterministic encapsulation coin read.
func testEncapsRNGSemantics(t *testing.T, k clatter.KEM, coinsLen int) {
	t.Helper()

	kp, err := k.GenerateKeypair(clatter.NewDummyRng(0xdeadbeef))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Truncated.
	_, _, err = k.Encapsulate(kp.Public, bytes.NewReader(patternedBytes(coinsLen-1)))
	if err == nil {
		t.Fatal("truncated rng encaps must fail")
	}
	if !errors.Is(err, clatter.ErrKEM) || !errors.Is(err, io.EOF) {
		t.Fatalf("truncated encaps error must wrap ErrKEM and io.EOF, got: %v", err)
	}

	// Chunked == contiguous.
	coins := patternedBytes(coinsLen)
	ct1, ss1, err := k.Encapsulate(kp.Public, bytes.NewReader(coins))
	if err != nil {
		t.Fatalf("contiguous encaps: %v", err)
	}
	ct2, ss2, err := k.Encapsulate(kp.Public, iotest.OneByteReader(bytes.NewReader(coins)))
	if err != nil {
		t.Fatalf("chunked encaps must succeed: %v", err)
	}
	if !bytes.Equal(ct1, ct2) || !bytes.Equal(ss1, ss2) {
		t.Fatal("chunked rng produced different encapsulation than contiguous rng")
	}

	// Full read + non-nil error.
	_, _, err = k.Encapsulate(kp.Public, &fullThenErrRNG{err: errEntropyHealth})
	if err == nil {
		t.Fatal("full-read+error encaps must fail closed")
	}
	if !errors.Is(err, clatter.ErrKEM) || !errors.Is(err, errEntropyHealth) {
		t.Fatalf("encaps error must wrap ErrKEM and the rng error, got: %v", err)
	}

	// Full read + io.EOF.
	if _, _, err = k.Encapsulate(kp.Public, &fullThenErrRNG{err: io.EOF}); err == nil {
		t.Fatal("full-read+io.EOF encaps must fail closed")
	}
}

func TestMlKem768_KeygenRNGSemantics(t *testing.T) {
	testKeygenRNGSemantics(t, NewMlKem768(), 64)
}

func TestMlKem1024_KeygenRNGSemantics(t *testing.T) {
	testKeygenRNGSemantics(t, NewMlKem1024(), 64)
}

func TestMlKem768_EncapsRNGSemantics(t *testing.T) {
	testEncapsRNGSemantics(t, NewMlKem768Testing(), 32)
}

func TestMlKem1024_EncapsRNGSemantics(t *testing.T) {
	testEncapsRNGSemantics(t, NewMlKem1024Testing(), 32)
}
