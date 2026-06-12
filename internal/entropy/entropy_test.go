package entropy

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// fullReadErrReader fills the entire request in one call and returns the
// configured error alongside it: the io.ReadFull fail-open case (H-11).
type fullReadErrReader struct{ err error }

func (r *fullReadErrReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xA5
	}
	return len(p), r.err
}

// zeroNilReader returns (0, nil) forever: a wedged source.
type zeroNilReader struct{}

func (zeroNilReader) Read(p []byte) (int, error) { return 0, nil }

// lyingCountReader violates the io.Reader contract with an impossible count.
type lyingCountReader struct{ n int }

func (r *lyingCountReader) Read(p []byte) (int, error) { return r.n, nil }

func TestFill_FullRead(t *testing.T) {
	src := bytes.Repeat([]byte{0x42}, 32)
	buf := make([]byte, 32)
	if err := Fill(bytes.NewReader(src), buf); err != nil {
		t.Fatalf("full read should succeed: %v", err)
	}
	if !bytes.Equal(buf, src) {
		t.Fatal("buffer not filled with source bytes")
	}
}

func TestFill_ChunkedButAliveSucceeds(t *testing.T) {
	src := make([]byte, 64)
	for i := range src {
		src[i] = byte(i + 1)
	}
	buf := make([]byte, 64)
	if err := Fill(iotest.OneByteReader(bytes.NewReader(src)), buf); err != nil {
		t.Fatalf("chunked-but-alive reader should succeed: %v", err)
	}
	if !bytes.Equal(buf, src) {
		t.Fatal("chunked read did not assemble the full correct buffer")
	}
}

func TestFill_TruncatedReaderFails(t *testing.T) {
	// k > 0 bytes available, fewer than requested (C-17: k=0 is plain EOF).
	for _, k := range []int{1, 16, 31} {
		buf := make([]byte, 32)
		err := Fill(bytes.NewReader(make([]byte, k)), buf)
		if err == nil {
			t.Fatalf("truncated reader (%d of 32) must fail", k)
		}
		if !errors.Is(err, io.EOF) {
			t.Fatalf("truncated reader error must propagate io.EOF, got: %v", err)
		}
	}
}

func TestFill_FullReadWithErrorFails(t *testing.T) {
	// THE H-11 case: full bytes + non-nil error. io.ReadFull would
	// silently accept this; Fill must reject it.
	healthErr := errors.New("entropy health failed")
	buf := make([]byte, 32)
	err := Fill(&fullReadErrReader{err: healthErr}, buf)
	if err == nil {
		t.Fatal("full read + error must fail closed")
	}
	if !errors.Is(err, healthErr) {
		t.Fatalf("reader error must stay errors.Is-reachable, got: %v", err)
	}
}

func TestFill_FullReadWithEOFFails(t *testing.T) {
	// (len, io.EOF) is also rejected: fail-closed matches v0.5.0's
	// single-Read+err check.
	buf := make([]byte, 32)
	err := Fill(&fullReadErrReader{err: io.EOF}, buf)
	if err == nil {
		t.Fatal("full read + io.EOF must fail closed")
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("io.EOF must stay errors.Is-reachable, got: %v", err)
	}
}

func TestFill_ZeroNilReaderFails(t *testing.T) {
	buf := make([]byte, 32)
	if err := Fill(zeroNilReader{}, buf); err == nil {
		t.Fatal("(0, nil) reader must fail, not spin")
	}
}

func TestFill_LyingCountFails(t *testing.T) {
	for _, n := range []int{-1, 33, 1 << 20} {
		buf := make([]byte, 32)
		if err := Fill(&lyingCountReader{n: n}, buf); err == nil {
			t.Fatalf("invalid read count %d must fail", n)
		}
	}
}

func TestFill_NilRngFails(t *testing.T) {
	buf := make([]byte, 32)
	if err := Fill(nil, buf); err == nil {
		t.Fatal("nil rng must fail, not panic")
	}
}

func TestFill_ZeroLengthNoOp(t *testing.T) {
	// Zero-length buffer succeeds without touching the reader.
	if err := Fill(zeroNilReader{}, nil); err != nil {
		t.Fatalf("zero-length fill should be a no-op: %v", err)
	}
	if err := Fill(zeroNilReader{}, []byte{}); err != nil {
		t.Fatalf("zero-length fill should be a no-op: %v", err)
	}
}
