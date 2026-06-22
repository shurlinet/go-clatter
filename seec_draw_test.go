package clatter

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// --- hostile SEEC implementations (the nyquist kem.go:175 panic class:
// a length-contract-violating GenRand must be an error, never a partial
// seed and never a panic) ---

// shortSEEC returns one byte fewer than requested.
type shortSEEC struct{}

func (shortSEEC) GenRand(_ io.Reader, _ SEECPurpose, n int) ([]byte, error) {
	return make([]byte, n-1), nil
}

// longSEEC returns one byte more than requested.
type longSEEC struct{}

func (longSEEC) GenRand(_ io.Reader, _ SEECPurpose, n int) ([]byte, error) {
	return make([]byte, n+1), nil
}

// nilSEEC returns (nil, nil) - no coins, no error.
type nilSEEC struct{}

func (nilSEEC) GenRand(_ io.Reader, _ SEECPurpose, _ int) ([]byte, error) {
	return nil, nil
}

// recordingSEEC records the purposes and widths it is asked for and
// delegates to an inner SEEC. Used to pin purpose pass-through and the
// chunk split.
type recordingSEEC struct {
	inner    SEEC
	purposes []SEECPurpose
	widths   []int
}

func (r *recordingSEEC) GenRand(rng io.Reader, purpose SEECPurpose, n int) ([]byte, error) {
	r.purposes = append(r.purposes, purpose)
	r.widths = append(r.widths, n)
	return r.inner.GenRand(rng, purpose, n)
}

// constReader is a dead rng: an endless stream of one byte value.
type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

func testSEECPRFForDraw(t *testing.T) *SEECPRF {
	t.Helper()
	return mustSEECPRF(t, &testSha256{})
}

func TestSeecDrawer_HostileImplsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    SEEC
	}{
		{"short", shortSEEC{}},
		{"long", longSEEC{}},
		{"nil-return", nilSEEC{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &seecDrawer{seec: tc.s, rng: constReader(7), purpose: SEECKeygen}

			out := make([]byte, 32)
			err := d.draw(out)
			if err == nil {
				t.Fatal("hostile SEEC implementation must be rejected")
			}
			if !errors.Is(err, ErrSEEC) {
				t.Fatalf("error must wrap ErrSEEC, got: %v", err)
			}
			// Never a partial seed: the output stays all zero.
			for _, b := range out {
				if b != 0 {
					t.Fatal("draw left partial output after a hostile SEEC return")
				}
			}

			// And through the io.Reader face used by keygen paths.
			n, err := d.Read(out)
			if err == nil || n != 0 {
				t.Fatalf("Read with hostile SEEC: want (0, error), got (%d, %v)", n, err)
			}
		})
	}
}

func TestSeecDrawer_ZeroLengthReadNoCall(t *testing.T) {
	rec := &recordingSEEC{inner: testSEECPRFForDraw(t)}
	d := &seecDrawer{seec: rec, rng: constReader(7), purpose: SEECKeygen}

	n, err := d.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("zero-length Read: want (0, nil), got (%d, %v)", n, err)
	}
	if err := d.draw(nil); err != nil {
		t.Fatalf("zero-length draw: want nil, got %v", err)
	}
	if len(rec.widths) != 0 {
		t.Fatal("zero-length Read/draw must not call GenRand")
	}
}

func TestSeecDrawer_PurposePassthrough(t *testing.T) {
	rec := &recordingSEEC{inner: testSEECPRFForDraw(t)}

	const customPurpose = SEECPurpose(0xAB) // opaque, not a defined constant
	d := &seecDrawer{seec: rec, rng: constReader(7), purpose: customPurpose}
	if err := d.draw(make([]byte, 32)); err != nil {
		t.Fatalf("draw: %v", err)
	}
	if len(rec.purposes) != 1 || rec.purposes[0] != customPurpose {
		t.Fatalf("purpose not passed through opaquely: %v", rec.purposes)
	}
}

// TestSeecDrawer_ChunkedPRFIndexSeparation pins the chunk-index-separation property: with the
// built-in SEECPRF under a DEAD rng (same r every call), two equal-size
// chunks of one wide draw MUST differ, because the chunk index is bound
// into the per-chunk Expand info. Without index binding a 510-byte seed
// under a repeating rng would be X||X.
func TestSeecDrawer_ChunkedPRFIndexSeparation(t *testing.T) {
	s := testSEECPRFForDraw(t)
	d := &seecDrawer{seec: s, rng: constReader(0x42), purpose: SEECKeygen}

	out := make([]byte, 510) // two 255-byte chunks
	if err := d.draw(out); err != nil {
		t.Fatalf("draw: %v", err)
	}
	if bytes.Equal(out[:255], out[255:]) {
		t.Fatal("equal-size chunks of one draw are byte-identical under a dead rng: chunk index not bound")
	}

	// The chunked draw is exactly the composition of genRandChunk calls
	// with ascending offsets (same dead rng makes this reproducible).
	c0, err := s.genRandChunk(constReader(0x42), SEECKeygen, 255, 510, 0)
	if err != nil {
		t.Fatalf("genRandChunk 0: %v", err)
	}
	c1, err := s.genRandChunk(constReader(0x42), SEECKeygen, 255, 510, 255)
	if err != nil {
		t.Fatalf("genRandChunk 1: %v", err)
	}
	if !bytes.Equal(out[:255], c0) || !bytes.Equal(out[255:], c1) {
		t.Fatal("chunked draw does not compose from genRandChunk(total 510, offsets 0/255)")
	}

	// A single-call draw keeps the frozen 2-byte info layout: a 255-byte
	// draw must NOT equal chunk 0 of a wider draw (different info layouts).
	single, err := s.GenRand(constReader(0x42), SEECKeygen, 255)
	if err != nil {
		t.Fatalf("GenRand: %v", err)
	}
	if bytes.Equal(single, c0) {
		t.Fatal("single-call draw equals chunk 0: chunk info layout not separated from the frozen GenRand layout")
	}

	// Cross-width separation (the total-width binding): chunk 0 of a
	// 300-byte draw and chunk 0 of a 400-byte draw must differ even under
	// a dead rng - draws of different total widths share no chunks.
	d300 := &seecDrawer{seec: s, rng: constReader(0x42), purpose: SEECKeygen}
	out300 := make([]byte, 300)
	if err := d300.draw(out300); err != nil {
		t.Fatalf("draw 300: %v", err)
	}
	d400 := &seecDrawer{seec: s, rng: constReader(0x42), purpose: SEECKeygen}
	out400 := make([]byte, 400)
	if err := d400.draw(out400); err != nil {
		t.Fatalf("draw 400: %v", err)
	}
	if bytes.Equal(out300[:255], out400[:255]) {
		t.Fatal("draws of different total widths share their leading chunk under a dead rng: total width not bound into chunk info")
	}
}

// TestSeecDrawer_DrawCeiling pins the allocation bound: a single draw
// request beyond maxSEECDrawLen is rejected before any allocation or
// GenRand call (the hostile-EncapsCoinsLen OOM class).
func TestSeecDrawer_DrawCeiling(t *testing.T) {
	rec := &recordingSEEC{inner: testSEECPRFForDraw(t)}
	d := &seecDrawer{seec: rec, rng: constReader(7), purpose: SEECEncaps}

	err := d.draw(make([]byte, maxSEECDrawLen+1))
	if err == nil {
		t.Fatal("draw beyond maxSEECDrawLen must be rejected")
	}
	if !errors.Is(err, ErrSEEC) {
		t.Fatalf("ceiling error must wrap ErrSEEC, got: %v", err)
	}
	if len(rec.widths) != 0 {
		t.Fatal("over-ceiling draw must not call GenRand")
	}

	// The hostile-KEM route: an EncapsCoinsLen beyond the ceiling fails
	// closed at the encaps helper, never reaching make.
	h := &HandshakeInternals{seec: testSEECPRFForDraw(t), rng: constReader(7)}
	if _, _, err := h.encapsulateKEM(hugeCoinsLenKEM{}, nil); !errors.Is(err, ErrSEEC) {
		t.Fatalf("hostile EncapsCoinsLen must fail closed with ErrSEEC, got: %v", err)
	}
	if err := validateSEECKEMCapability(hugeCoinsLenKEM{}, "EKEM"); !errors.Is(err, ErrSEEC) {
		t.Fatalf("constructor validation must reject a hostile EncapsCoinsLen, got: %v", err)
	}
}

// hugeCoinsLenKEM declares an absurd coin length (the OOM-panic probe).
type hugeCoinsLenKEM struct{ badCoinsLenKEM }

func (hugeCoinsLenKEM) EncapsCoinsLen() int { return 1 << 40 }

// lyingCtKEM declares CiphertextLen=32/SharedSecretLen=32 but RETURNS a
// 33-byte ciphertext from both Encapsulate and EncapsulateWithCoins - the
// untrusted-KEM wire-corruption probe. encapsulateKEM must reject it at
// the choke point (before any token writer copies ct onto the wire),
// uniformly on the seec==nil and seec!=nil branches.
type lyingCtKEM struct{ badCoinsLenKEM }

func (lyingCtKEM) EncapsCoinsLen() int { return 32 }
func (lyingCtKEM) Encapsulate(_ []byte, _ RNG) ([]byte, []byte, error) {
	return make([]byte, 33), make([]byte, 32), nil
}
func (lyingCtKEM) EncapsulateWithCoins(_, _ []byte) ([]byte, []byte, error) {
	return make([]byte, 33), make([]byte, 32), nil
}

// TestEncapsulateKEM_RejectsWrongLengthOutput pins the F1 choke-point
// guard: a KEM whose Encapsulate / EncapsulateWithCoins returns a
// ciphertext or shared secret of the wrong declared length is rejected
// with ErrKEM on BOTH the SEEC-off and SEEC-on branches, never letting a
// corrupt ct reach the wire copy.
func TestEncapsulateKEM_RejectsWrongLengthOutput(t *testing.T) {
	lying := struct{ KEM }{lyingCtKEM{}}

	// seec == nil branch (production path).
	hOff := &HandshakeInternals{rng: constReader(7)}
	if _, _, err := hOff.encapsulateKEM(lying, nil); !errors.Is(err, ErrKEM) {
		t.Fatalf("seec-off: wrong-length KEM output must fail with ErrKEM, got: %v", err)
	}

	// seec != nil branch (CoinsEncapsulator path). lying embeds
	// badCoinsLenKEM but overrides EncapsCoinsLen to 32, so it is a valid
	// CoinsEncapsulator that simply lies about its output length.
	hOn := &HandshakeInternals{seec: testSEECPRFForDraw(t), rng: constReader(7)}
	lyingCE := struct{ CoinsEncapsulator }{lyingCtKEM{}}
	if _, _, err := hOn.encapsulateKEM(lyingCE, nil); !errors.Is(err, ErrKEM) {
		t.Fatalf("seec-on: wrong-length KEM output must fail with ErrKEM, got: %v", err)
	}
}

// plainStubKEM implements ONLY the KEM interface (no CoinsEncapsulator).
type plainStubKEM struct{ badCoinsLenKEM }

// TestEncapsulateKEM_DefenseInDepth covers the encaps helper's own guards
// for direct HandshakeInternals embedders that bypass constructor
// validation: a non-CoinsEncapsulator KEM fails closed (never a silent
// downgrade to unhedged encapsulation).
func TestEncapsulateKEM_DefenseInDepth(t *testing.T) {
	h := &HandshakeInternals{seec: testSEECPRFForDraw(t), rng: constReader(7)}

	// plainStubKEM embeds badCoinsLenKEM but hides its CoinsEncapsulator
	// methods behind a KEM-only interface value.
	var plain KEM = struct{ KEM }{plainStubKEM{}}
	if _, _, err := h.encapsulateKEM(plain, nil); !errors.Is(err, ErrSEEC) {
		t.Fatalf("non-CoinsEncapsulator KEM must fail closed with ErrSEEC, got: %v", err)
	}
}

// hostileChunkSEEC behaves until failAt calls, then returns a wrong-length
// slice (the mid-chunk length-violation path).
type hostileChunkSEEC struct {
	inner  SEEC
	calls  int
	failAt int
}

func (h *hostileChunkSEEC) GenRand(rng io.Reader, purpose SEECPurpose, n int) ([]byte, error) {
	h.calls++
	if h.calls > h.failAt {
		return make([]byte, n-1), nil
	}
	return h.inner.GenRand(rng, purpose, n)
}

// TestSeecDrawer_ChunkedHostileLengthZeroesPartial covers the chunked
// path's takeCoins-failure branch: a length violation on a later chunk
// zeroes everything already written.
func TestSeecDrawer_ChunkedHostileLengthZeroesPartial(t *testing.T) {
	hostile := &hostileChunkSEEC{inner: testSEECPRFForDraw(t), failAt: 1}
	d := &seecDrawer{seec: hostile, rng: constReader(7), purpose: SEECKeygen}

	out := make([]byte, 510)
	if err := d.draw(out); !errors.Is(err, ErrSEEC) {
		t.Fatalf("mid-chunk length violation must fail with ErrSEEC, got: %v", err)
	}
	for _, b := range out {
		if b != 0 {
			t.Fatal("partial chunk output not zeroed after mid-chunk length violation")
		}
	}
}

// TestSeecDrawer_ChunkedThirdPartySplit pins the third-party chunking
// contract: a non-SEECPRF implementation gets plain GenRand calls, one per
// chunk, with the correct widths (255, 255, 90 for a 600-byte draw).
func TestSeecDrawer_ChunkedThirdPartySplit(t *testing.T) {
	rec := &recordingSEEC{inner: testSEECPRFForDraw(t)}
	d := &seecDrawer{seec: rec, rng: constReader(7), purpose: SEECEncaps}

	if err := d.draw(make([]byte, 600)); err != nil {
		t.Fatalf("draw: %v", err)
	}
	wantWidths := []int{255, 255, 90}
	if len(rec.widths) != len(wantWidths) {
		t.Fatalf("chunk widths %v, want %v", rec.widths, wantWidths)
	}
	for i, w := range wantWidths {
		if rec.widths[i] != w {
			t.Fatalf("chunk widths %v, want %v", rec.widths, wantWidths)
		}
		if rec.purposes[i] != SEECEncaps {
			t.Fatalf("chunk %d purpose %v, want SEECEncaps", i, rec.purposes[i])
		}
	}
}

// TestSeecDrawer_ChunkedErrorZeroesPartial asserts a mid-chunk failure
// zeroes the partially filled output (no partial seed leaves the helper).
func TestSeecDrawer_ChunkedErrorZeroesPartial(t *testing.T) {
	fail := &failAfterSEEC{inner: testSEECPRFForDraw(t), failAt: 1}
	d := &seecDrawer{seec: fail, rng: constReader(7), purpose: SEECKeygen}

	out := make([]byte, 510)
	if err := d.draw(out); err == nil {
		t.Fatal("draw must fail when a chunk draw fails")
	}
	for _, b := range out {
		if b != 0 {
			t.Fatal("partial chunk output not zeroed on failure")
		}
	}
}

// failAfterSEEC succeeds for calls before failAt, then errors.
type failAfterSEEC struct {
	inner  SEEC
	calls  int
	failAt int
}

func (f *failAfterSEEC) GenRand(rng io.Reader, purpose SEECPurpose, n int) ([]byte, error) {
	if f.calls >= f.failAt {
		return nil, errors.New("induced SEEC failure")
	}
	f.calls++
	return f.inner.GenRand(rng, purpose, n)
}

// TestValidateSEECKEMCapability_BadCoinsLen pins the EncapsCoinsLen
// validation: a CoinsEncapsulator declaring a non-positive coin length is
// rejected at constructor validation and at the encaps helper.
func TestValidateSEECKEMCapability_BadCoinsLen(t *testing.T) {
	bad := badCoinsLenKEM{}
	if err := validateSEECKEMCapability(bad, "EKEM"); err == nil {
		t.Fatal("zero EncapsCoinsLen must be rejected")
	} else if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}

	h := &HandshakeInternals{seec: testSEECPRFForDraw(t), rng: constReader(7)}
	if _, _, err := h.encapsulateKEM(bad, nil); err == nil {
		t.Fatal("encapsulateKEM must reject a zero EncapsCoinsLen")
	}
}

// badCoinsLenKEM is a minimal CoinsEncapsulator declaring zero coins.
type badCoinsLenKEM struct{}

func (badCoinsLenKEM) Name() string                         { return "BADKEM" }
func (badCoinsLenKEM) GenerateKeypair(RNG) (KeyPair, error) { return KeyPair{}, nil }
func (badCoinsLenKEM) Encapsulate(_ []byte, _ RNG) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (badCoinsLenKEM) Decapsulate(_, _ []byte) ([]byte, error) { return nil, nil }
func (badCoinsLenKEM) PubKeyLen() int                          { return 32 }
func (badCoinsLenKEM) SecretKeyLen() int                       { return 32 }
func (badCoinsLenKEM) CiphertextLen() int                      { return 32 }
func (badCoinsLenKEM) SharedSecretLen() int                    { return 32 }
func (badCoinsLenKEM) ValidatePublicKey([]byte) error          { return nil }
func (badCoinsLenKEM) EncapsCoinsLen() int                     { return 0 }
func (badCoinsLenKEM) EncapsulateWithCoins(_, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}
