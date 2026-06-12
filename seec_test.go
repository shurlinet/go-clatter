package clatter

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	gohash "hash"
	"io"
	"sync"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	xhkdf "golang.org/x/crypto/hkdf"
)

// --- test HashFunc wrappers for BLAKE2 (SHA wrappers live in hash_test.go) ---

type testBlake2s struct{}

func (t *testBlake2s) Name() string  { return "BLAKE2s" }
func (t *testBlake2s) HashLen() int  { return 32 }
func (t *testBlake2s) BlockLen() int { return 64 }
func (t *testBlake2s) Hash(data []byte) []byte {
	h := blake2s.Sum256(data)
	return h[:]
}
func (t *testBlake2s) NewHMAC(key []byte) HMACWriter {
	return &testHMACWriter{mac: hmac.New(newBlake2s, key)}
}

type testBlake2b struct{}

func (t *testBlake2b) Name() string  { return "BLAKE2b" }
func (t *testBlake2b) HashLen() int  { return 64 }
func (t *testBlake2b) BlockLen() int { return 128 }
func (t *testBlake2b) Hash(data []byte) []byte {
	h := blake2b.Sum512(data)
	return h[:]
}
func (t *testBlake2b) NewHMAC(key []byte) HMACWriter {
	return &testHMACWriter{mac: hmac.New(newBlake2b, key)}
}

func newBlake2s() gohash.Hash {
	h, _ := blake2s.New256(nil) // unkeyed; cannot fail
	return h
}

func newBlake2b() gohash.Hash {
	h, _ := blake2b.New512(nil) // unkeyed; cannot fail
	return h
}

// --- test readers ---

// constByteReader returns the same byte forever: a dead rng. Stateless,
// safe for concurrent use.
type constByteReader byte

func (c constByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

// fullThenErrReader fills the entire request and returns an error with it.
type fullThenErrReader struct{ err error }

func (r *fullThenErrReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xA5
	}
	return len(p), r.err
}

// countingRNG counts bytes served while delegating to an inner reader.
type countingRNG struct {
	inner io.Reader
	n     int
}

func (c *countingRNG) Read(p []byte) (int, error) {
	n, err := c.inner.Read(p)
	c.n += n
	return n, err
}

func testSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

func mustSEECPRF(t *testing.T, h HashFunc) *SEECPRF {
	t.Helper()
	s, err := NewSEECPRF(h, testSecret())
	if err != nil {
		t.Fatalf("NewSEECPRF: %v", err)
	}
	return s
}

// --- RFC 5869 vectors driven directly through the internal Expand chain ---

func TestHkdfExpand_RFC5869Vectors(t *testing.T) {
	mustHexDecode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad hex in vector: %v", err)
		}
		return b
	}

	vectors := []struct {
		name                      string
		ikm, salt, info, prk, okm string
		l                         int
	}{
		{
			name: "A.1 basic",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "000102030405060708090a0b0c",
			info: "f0f1f2f3f4f5f6f7f8f9",
			l:    42,
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "A.2 long inputs",
			ikm:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			l:    82,
			prk:  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okm:  "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name: "A.3 empty salt and info",
			ikm:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt: "",
			info: "",
			l:    42,
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	h := &testSha256{}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			ikm, salt, info := mustHexDecode(v.ikm), mustHexDecode(v.salt), mustHexDecode(v.info)

			// RFC 5869 Extract: PRK = HMAC(salt, IKM), salt in key position.
			// hmacHash deliberately rejects keys longer than the block
			// (A.2's 80-byte salt), so verify Extract through it only when
			// the salt fits, and through crypto/hmac otherwise. SEEC never
			// hits the oversized case (label is 22 bytes, prk is hashLen).
			var prk []byte
			if len(salt) <= h.BlockLen() {
				prk = mustHmacHash(t, h, salt, ikm)
			} else {
				mac := hmac.New(sha256.New, salt)
				mac.Write(ikm)
				prk = mac.Sum(nil)
			}
			if !bytes.Equal(prk, mustHexDecode(v.prk)) {
				t.Fatalf("PRK mismatch:\n got  %x\n want %s", prk, v.prk)
			}

			okm, err := hkdfExpand(h, prk, info, v.l)
			if err != nil {
				t.Fatalf("hkdfExpand: %v", err)
			}
			if !bytes.Equal(okm, mustHexDecode(v.okm)) {
				t.Fatalf("OKM mismatch:\n got  %x\n want %s", okm, v.okm)
			}
		})
	}
}

func TestHkdfExpand_LengthLimits(t *testing.T) {
	h := &testSha256{}
	prk := bytes.Repeat([]byte{0x0d}, 32)

	if _, err := hkdfExpand(h, prk, nil, 0); err == nil {
		t.Fatal("expand length 0 must error")
	}
	if _, err := hkdfExpand(h, prk, nil, 255*32+1); err == nil {
		t.Fatal("expand beyond RFC 5869 limit must error")
	}
	out, err := hkdfExpand(h, prk, nil, 255*32)
	if err != nil || len(out) != 255*32 {
		t.Fatalf("expand at RFC limit should succeed: %v", err)
	}
}

// --- independent oracle cross-check: full construction, all four HashFuncs ---

// TestSEECPRF_OracleCrossCheck recomputes the complete construction via TWO
// independent HKDF implementations (x/crypto/hkdf and stdlib crypto/hkdf):
//
//	prk = Extract(IKM=secret, salt="go-clatter/seec/v1/prf")
//	k_r = Extract(IKM=r, salt=prk)        // the re-key IS an Extract
//	out = Expand(k_r, purpose||uint8(n), n)
//
// and asserts byte equality with SEECPRF.GenRand for all four supported
// hash functions, covering the 64-byte-prk path (SHA-512, BLAKE2b).
func TestSEECPRF_OracleCrossCheck(t *testing.T) {
	hashes := []struct {
		name string
		hf   HashFunc
		newH func() gohash.Hash
	}{
		{"SHA256", &testSha256{}, func() gohash.Hash { return sha256.New() }},
		{"SHA512", &testSha512{}, func() gohash.Hash { return sha512.New() }},
		{"BLAKE2s", &testBlake2s{}, newBlake2s},
		{"BLAKE2b", &testBlake2b{}, newBlake2b},
	}

	secret := testSecret()
	r := bytes.Repeat([]byte{0x77}, 32)
	label := []byte(seecPRFLabel)

	for _, hh := range hashes {
		t.Run(hh.name, func(t *testing.T) {
			s, err := NewSEECPRF(hh.hf, secret)
			if err != nil {
				t.Fatalf("NewSEECPRF: %v", err)
			}
			for _, n := range []int{1, 32, 42, 64, 255} {
				for _, purpose := range []SEECPurpose{SEECKeygen, SEECEncaps} {
					got, err := s.GenRand(bytes.NewReader(r), purpose, n)
					if err != nil {
						t.Fatalf("GenRand(n=%d): %v", n, err)
					}
					if len(got) != n {
						t.Fatalf("GenRand returned %d bytes, want %d", len(got), n)
					}

					info := []byte{byte(purpose), byte(n)}

					// Oracle 1: x/crypto/hkdf.
					prk := xhkdf.Extract(hh.newH, secret, label)
					kr := xhkdf.Extract(hh.newH, r, prk)
					want1 := make([]byte, n)
					if _, err := io.ReadFull(xhkdf.Expand(hh.newH, kr, info), want1); err != nil {
						t.Fatalf("x/crypto expand: %v", err)
					}
					if !bytes.Equal(got, want1) {
						t.Fatalf("x/crypto oracle mismatch (purpose=%d n=%d):\n got  %x\n want %x",
							purpose, n, got, want1)
					}

					// Oracle 2: stdlib crypto/hkdf (go1.26).
					sprk, err := hkdf.Extract(hh.newH, secret, label)
					if err != nil {
						t.Fatalf("stdlib extract: %v", err)
					}
					skr, err := hkdf.Extract(hh.newH, r, sprk)
					if err != nil {
						t.Fatalf("stdlib extract (re-key): %v", err)
					}
					want2, err := hkdf.Expand(hh.newH, skr, string(info), n)
					if err != nil {
						t.Fatalf("stdlib expand: %v", err)
					}
					if !bytes.Equal(got, want2) {
						t.Fatalf("stdlib oracle mismatch (purpose=%d n=%d)", purpose, n)
					}
				}
			}
		})
	}
}

// --- SEEC-29 corrected property set ---

func TestSEECPRF_DeterministicInSecretAndR(t *testing.T) {
	r := bytes.Repeat([]byte{0x33}, 32)
	s1 := mustSEECPRF(t, &testSha256{})
	s2 := mustSEECPRF(t, &testSha256{})

	out1, err1 := s1.GenRand(bytes.NewReader(r), SEECKeygen, 64)
	out2, err2 := s2.GenRand(bytes.NewReader(r), SEECKeygen, 64)
	if err1 != nil || err2 != nil {
		t.Fatalf("GenRand: %v / %v", err1, err2)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("same (secret, r, purpose, n) must produce identical output")
	}
}

func TestSEECPRF_DistinctR(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	out1, _ := s.GenRand(bytes.NewReader(bytes.Repeat([]byte{0x01}, 32)), SEECKeygen, 32)
	out2, _ := s.GenRand(bytes.NewReader(bytes.Repeat([]byte{0x02}, 32)), SEECKeygen, 32)
	if bytes.Equal(out1, out2) {
		t.Fatal("distinct r with same secret must produce distinct output")
	}
}

func TestSEECPRF_DistinctSecret(t *testing.T) {
	r := bytes.Repeat([]byte{0x44}, 32)
	secret2 := testSecret()
	secret2[0] ^= 0xFF

	s1 := mustSEECPRF(t, &testSha256{})
	s2, err := NewSEECPRF(&testSha256{}, secret2)
	if err != nil {
		t.Fatal(err)
	}
	out1, _ := s1.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	out2, _ := s2.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	if bytes.Equal(out1, out2) {
		t.Fatal("distinct secret with same r must produce distinct output")
	}
}

func TestSEECPRF_PurposeSeparation(t *testing.T) {
	r := bytes.Repeat([]byte{0x55}, 32)
	s := mustSEECPRF(t, &testSha256{})
	outK, _ := s.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	outE, _ := s.GenRand(bytes.NewReader(r), SEECEncaps, 32)
	if bytes.Equal(outK, outE) {
		t.Fatal("same (secret, r) with different purpose must produce distinct output")
	}
}

func TestSEECPRF_PurposeOpaquePassThrough(t *testing.T) {
	// Purpose is not validated (D-1): undefined values are accepted and
	// domain-separate like any other.
	r := bytes.Repeat([]byte{0x66}, 32)
	s := mustSEECPRF(t, &testSha256{})
	out0, err := s.GenRand(bytes.NewReader(r), SEECPurpose(0), 32)
	if err != nil {
		t.Fatalf("purpose 0 must be accepted: %v", err)
	}
	out7, err := s.GenRand(bytes.NewReader(r), SEECPurpose(7), 32)
	if err != nil {
		t.Fatalf("purpose 7 must be accepted: %v", err)
	}
	if bytes.Equal(out0, out7) {
		t.Fatal("distinct purposes must produce distinct output")
	}
}

func TestSEECPRF_NBinding(t *testing.T) {
	// n is bound into the info: out32 must NOT be a prefix of out64.
	r := bytes.Repeat([]byte{0x99}, 32)
	s := mustSEECPRF(t, &testSha256{})
	out32, _ := s.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	out64, _ := s.GenRand(bytes.NewReader(r), SEECKeygen, 64)
	if bytes.Equal(out32, out64[:32]) {
		t.Fatal("output for n=32 must not be a prefix of output for n=64")
	}
}

func TestSEECPRF_ConstantRngRepeatsOutput(t *testing.T) {
	// Document-by-test: under a dead rng the same r recurs, so the same
	// coins recur. SEEC hedges coin SECRECY, not coin FRESHNESS - this is
	// the model (paper: fresh-but-possibly-known coins), not a bug.
	s := mustSEECPRF(t, &testSha256{})
	dead := constByteReader(0x5A)
	out1, err1 := s.GenRand(dead, SEECKeygen, 32)
	out2, err2 := s.GenRand(dead, SEECKeygen, 32)
	if err1 != nil || err2 != nil {
		t.Fatalf("GenRand: %v / %v", err1, err2)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("constant rng implies identical r implies identical output - that is the model")
	}
}

func TestSEECPRF_FreshRPerCall(t *testing.T) {
	// SEEC-28: every call draws fresh r. Under an advancing deterministic
	// rng, consecutive same-width calls must differ.
	s := mustSEECPRF(t, &testSha256{})
	rng := NewDummyRng(0xdeadbeef)
	out1, _ := s.GenRand(rng, SEECKeygen, 32)
	out2, _ := s.GenRand(rng, SEECKeygen, 32)
	if bytes.Equal(out1, out2) {
		t.Fatal("consecutive calls under an advancing rng must produce distinct output")
	}
}

func TestSEECPRF_DrawWidthIs32PerCall(t *testing.T) {
	// SEEC-26: GenRand reads exactly 32 bytes of r per call regardless of n.
	s := mustSEECPRF(t, &testSha256{})
	for _, n := range []int{1, 32, 255} {
		c := &countingRNG{inner: NewDummyRng(1)}
		if _, err := s.GenRand(c, SEECKeygen, n); err != nil {
			t.Fatalf("GenRand(n=%d): %v", n, err)
		}
		if c.n != 32 {
			t.Fatalf("GenRand(n=%d) consumed %d rng bytes, want exactly 32", n, c.n)
		}
	}
}

// --- lifecycle ---

func TestNewSEECPRF_Validation(t *testing.T) {
	h := &testSha256{}

	cases := []struct {
		name   string
		h      HashFunc
		secret []byte
	}{
		{"nil HashFunc", nil, testSecret()},
		{"nil secret", h, nil},
		{"short secret", h, make([]byte, 31)},
		{"long secret", h, make([]byte, 33)},
		{"empty secret", h, []byte{}},
		{"all-zero secret", h, make([]byte, 32)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewSEECPRF(c.h, c.secret)
			if err == nil {
				t.Fatal("constructor must reject")
			}
			if !errors.Is(err, ErrSEEC) {
				t.Fatalf("error must wrap ErrSEEC, got: %v", err)
			}
			if s != nil {
				t.Fatal("rejected constructor must return nil instance")
			}
		})
	}
}

func TestSEECPRF_SecretCopiedNotAliased(t *testing.T) {
	// The constructor copies the secret; mutating the caller's slice after
	// construction must not change outputs.
	secret := testSecret()
	s, err := NewSEECPRF(&testSha256{}, secret)
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.Repeat([]byte{0x21}, 32)
	before, _ := s.GenRand(bytes.NewReader(r), SEECKeygen, 32)

	for i := range secret {
		secret[i] = 0xFF
	}
	after, _ := s.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	if !bytes.Equal(before, after) {
		t.Fatal("mutating the caller's secret slice changed output: secret was aliased")
	}
}

func TestSEECPRF_NRange(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	rng := NewDummyRng(1)
	for _, n := range []int{0, -1, 256, 1 << 16} {
		if _, err := s.GenRand(rng, SEECKeygen, n); err == nil {
			t.Fatalf("n=%d must be rejected", n)
		} else if !errors.Is(err, ErrSEEC) {
			t.Fatalf("n=%d error must wrap ErrSEEC, got: %v", n, err)
		}
	}
}

func TestSEECPRF_NilRng(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	_, err := s.GenRand(nil, SEECKeygen, 32)
	if err == nil {
		t.Fatal("nil rng must fail closed, not panic")
	}
	if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}
}

func TestSEECPRF_DestroyDualSentinel(t *testing.T) {
	// H-7: post-Destroy GenRand wraps BOTH ErrDestroyed and ErrSEEC.
	s := mustSEECPRF(t, &testSha256{})
	s.Destroy()

	_, err := s.GenRand(NewDummyRng(1), SEECKeygen, 32)
	if err == nil {
		t.Fatal("GenRand after Destroy must fail")
	}
	if !errors.Is(err, ErrDestroyed) {
		t.Fatalf("error must wrap ErrDestroyed, got: %v", err)
	}
	if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}
}

func TestSEECPRF_DestroyIdempotent(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	s.Destroy()
	s.Destroy() // must not panic
	if _, err := s.GenRand(NewDummyRng(1), SEECKeygen, 32); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("still destroyed after double Destroy, got: %v", err)
	}
}

// --- rng failure semantics through SEECPRF (the fillEntropy matrix) ---

func TestSEECPRF_TruncatedRngFails(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	_, err := s.GenRand(bytes.NewReader(make([]byte, 16)), SEECKeygen, 32)
	if err == nil {
		t.Fatal("truncated rng must fail closed")
	}
	if !errors.Is(err, ErrSEEC) || !errors.Is(err, io.EOF) {
		t.Fatalf("error must wrap ErrSEEC and propagate io.EOF, got: %v", err)
	}
}

func TestSEECPRF_ChunkedRngSucceeds(t *testing.T) {
	r := bytes.Repeat([]byte{0x13}, 32)
	s := mustSEECPRF(t, &testSha256{})

	whole, err := s.GenRand(bytes.NewReader(r), SEECKeygen, 32)
	if err != nil {
		t.Fatal(err)
	}
	chunked, err := s.GenRand(iotest.OneByteReader(bytes.NewReader(r)), SEECKeygen, 32)
	if err != nil {
		t.Fatalf("chunked-but-alive rng must succeed: %v", err)
	}
	if !bytes.Equal(whole, chunked) {
		t.Fatal("chunked rng must assemble the same r and produce identical output")
	}
}

func TestSEECPRF_FullReadWithErrorFails(t *testing.T) {
	// THE H-11 case at the SEEC layer.
	healthErr := errors.New("entropy health failed")
	s := mustSEECPRF(t, &testSha256{})
	_, err := s.GenRand(&fullThenErrReader{err: healthErr}, SEECKeygen, 32)
	if err == nil {
		t.Fatal("full read + error must fail closed")
	}
	if !errors.Is(err, ErrSEEC) || !errors.Is(err, healthErr) {
		t.Fatalf("error must wrap ErrSEEC and the rng error, got: %v", err)
	}
}

func TestSEECPRF_FullReadWithEOFFails(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	_, err := s.GenRand(&fullThenErrReader{err: io.EOF}, SEECKeygen, 32)
	if err == nil {
		t.Fatal("full read + io.EOF must fail closed")
	}
	if !errors.Is(err, ErrSEEC) || !errors.Is(err, io.EOF) {
		t.Fatalf("error must wrap ErrSEEC and io.EOF, got: %v", err)
	}
}

// --- hostile HashFunc ---

// shortSumHash declares HashLen 32 but its HMAC returns 16-byte sums:
// a contract-violating HashFunc that must be rejected, never silently
// produce truncated key material.
type shortSumHash struct{ testSha256 }

func (s *shortSumHash) NewHMAC(key []byte) HMACWriter {
	return &truncatingHMAC{inner: (&testSha256{}).NewHMAC(key)}
}

type truncatingHMAC struct{ inner HMACWriter }

func (t *truncatingHMAC) Write(p []byte) (int, error) { return t.inner.Write(p) }
func (t *truncatingHMAC) Sum() []byte                 { return t.inner.Sum()[:16] }

// badGeometryHash declares HashLen > BlockLen: its prk could never be
// used as an HMAC re-key. Must be rejected at construction (SEEC-16:
// config errors surface at construction, not on the first handshake draw).
type badGeometryHash struct{ testSha256 }

func (b *badGeometryHash) HashLen() int { return 65 }

func TestNewSEECPRF_BadGeometryRejected(t *testing.T) {
	_, err := NewSEECPRF(&badGeometryHash{}, testSecret())
	if err == nil {
		t.Fatal("constructor must reject HashLen > BlockLen")
	}
	if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}
}

func TestSEECPRF_HostileHashFuncRejected(t *testing.T) {
	// Constructor catches it: prk length != declared HashLen.
	_, err := NewSEECPRF(&shortSumHash{}, testSecret())
	if err == nil {
		t.Fatal("constructor must reject a HashFunc whose HMAC violates HashLen")
	}
	if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}

	// The expand chain catches it independently (per-block validation).
	_, err = hkdfExpand(&shortSumHash{}, bytes.Repeat([]byte{0x0d}, 32), nil, 64)
	if err == nil {
		t.Fatal("hkdfExpand must reject short HMAC blocks")
	}
}

// --- concurrency ---

func TestSEECPRF_ConcurrentGenRand(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	dead := constByteReader(0x42)
	expected, err := s.GenRand(dead, SEECKeygen, 48)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				out, err := s.GenRand(dead, SEECKeygen, 48)
				if err != nil {
					t.Errorf("concurrent GenRand: %v", err)
					return
				}
				if !bytes.Equal(out, expected) {
					t.Error("concurrent GenRand produced wrong (torn?) output")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSEECPRF_DestroyConcurrentWithGenRand(t *testing.T) {
	// C-1 + R10 corrected assertion: under -race this must be race-clean,
	// and every result is valid (expected) coins XOR an ErrDestroyed-
	// wrapped error. An in-flight call that passed the destroyed check
	// legitimately COMPLETES (Destroy waits on the read locks); torn
	// output (HMAC over half-zeroed prk) would surface as a successful
	// result with WRONG bytes, which the constant-rng expectation catches.
	s := mustSEECPRF(t, &testSha256{})
	dead := constByteReader(0x42)
	expected, err := s.GenRand(dead, SEECKeygen, 32)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 500; i++ {
				out, err := s.GenRand(dead, SEECKeygen, 32)
				if err != nil {
					if !errors.Is(err, ErrDestroyed) || !errors.Is(err, ErrSEEC) {
						t.Errorf("post-destroy error must wrap both sentinels, got: %v", err)
					}
					return
				}
				if !bytes.Equal(out, expected) {
					t.Error("GenRand returned torn output during concurrent Destroy")
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		s.Destroy()
	}()

	close(start)
	wg.Wait()

	if _, err := s.GenRand(dead, SEECKeygen, 32); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("instance must stay destroyed, got: %v", err)
	}
}
