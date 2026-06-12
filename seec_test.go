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

	// Overflow probes: n near MaxInt must error, never wrap negative and
	// panic in make.
	const maxInt = int(^uint(0) >> 1)
	for _, n := range []int{maxInt, maxInt - 1, maxInt - 31} {
		if _, err := hkdfExpand(h, prk, nil, n); err == nil {
			t.Fatalf("expand length %d must error, not overflow", n)
		}
	}
}

// hugeLenHash declares an absurd HashLen whose 255x block buffer would
// overflow int: hkdfExpand must error, never panic on a negative make
// capacity.
type hugeLenHash struct{ testSha256 }

func (hugeLenHash) HashLen() int  { return int(^uint(0)>>1) - 1 }
func (hugeLenHash) BlockLen() int { return int(^uint(0) >> 1) }

func TestHkdfExpand_HostileHashLenNoPanic(t *testing.T) {
	if _, err := hkdfExpand(&hugeLenHash{}, []byte{0x01}, nil, 64); err == nil {
		t.Fatal("absurd HashLen must error, not panic or allocate")
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

// TestSEECPRF_PinnedRegressionVectors pins the COMPLETE construction -
// label bytes, Extract shape, re-key, info layout - against hardcoded
// expected output generated through an independent path (x/crypto/hkdf
// with the label as a string literal). Deliberately does NOT reference
// seecPRFLabel or any library constant: the oracle cross-check tests
// build the label from the const, so a mutated label would survive them
// (the oracle follows the mutation); these vectors do not.
func TestSEECPRF_PinnedRegressionVectors(t *testing.T) {
	secret := testSecret() // 0x01..0x20
	r := bytes.Repeat([]byte{0xA0}, 32)

	vectors := []struct {
		name   string
		hf     HashFunc
		n      int
		expect string
	}{
		{"SHA256/32", &testSha256{}, 32, "4b585ecddafb05992a2a5acb91c665e5b37becdfd6b586a09e09e8bf14f2342e"},
		{"SHA256/64", &testSha256{}, 64, "64cb61c93a4b6302cd0db244e1d8832b19f2a2a19544b0b8363d88704c2ff1f460c6529aca88886abf29876ef4ba1946ac13067569f8b8a42ffe314b7623bf64"},
		{"SHA512/32", &testSha512{}, 32, "83537beec0995ed1e782271dec7ee557f3260d9cea20914b7142a8d44e272646"},
		{"SHA512/64", &testSha512{}, 64, "1b9c501f2a7b918db1230617e0b3d208688ace7ae1e9fb3f332503b2115ff4f71497f68613b94068c3d7f2f76c9b8eb5ae4c454d1334c16741c9e156f46b58ae"},
		{"BLAKE2s/32", &testBlake2s{}, 32, "ed3e0a02dc6ae6aff727539263f55e138769bf8ecdaaf359b2f1b58130317856"},
		{"BLAKE2s/64", &testBlake2s{}, 64, "e01fb4b24a7e986c40012cece7047febd3b5a184e1e2619580eed3c58c4daaf38210e026832740df4662d62d10f9acd6a304ad66e00d51af350b5ab0ddc41934"},
		{"BLAKE2b/32", &testBlake2b{}, 32, "011f4ffa543382620927b684578be116ad0be5dee4b2d6ce2efa8b59201bd658"},
		{"BLAKE2b/64", &testBlake2b{}, 64, "88b6eb6b961c4c2371f344f40ef2468d8063264b73a6bd28da99fa10d706cbe19b9e2fe71019fbcf47caa9d3d61afac0f04af9cb3585ffb753169fe167833cba"},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			s, err := NewSEECPRF(v.hf, secret)
			if err != nil {
				t.Fatalf("NewSEECPRF: %v", err)
			}
			got, err := s.GenRand(bytes.NewReader(r), SEECKeygen, v.n)
			if err != nil {
				t.Fatalf("GenRand: %v", err)
			}
			want, err := hex.DecodeString(v.expect)
			if err != nil {
				t.Fatalf("bad vector hex: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("pinned vector mismatch:\n got  %x\n want %s", got, v.expect)
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

func TestSEECPRF_DestroyZeroesPRK(t *testing.T) {
	// Pins the zeroing itself, not just the latch: a Destroy that only
	// sets the flag would pass every other test while leaving the PRF
	// key in memory (same-package access to the unexported field).
	s := mustSEECPRF(t, &testSha256{})
	if len(s.prk) == 0 {
		t.Fatal("precondition: prk must be populated before Destroy")
	}
	prk := s.prk // alias the backing array before Destroy drops the reference
	s.Destroy()
	if s.prk != nil {
		t.Fatal("Destroy must drop the prk reference")
	}
	for i, b := range prk {
		if b != 0 {
			t.Fatalf("Destroy left non-zero prk byte at index %d", i)
		}
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

// capturingReader fills each Read with a fixed byte and retains a
// reference to the exact buffer slice it filled - which aliases GenRand's
// internal r array - so a test can observe whether that entropy is zeroed
// after the call returns.
type capturingReader struct {
	fill     byte
	captured []byte
}

func (c *capturingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.fill
	}
	c.captured = p
	return len(p), nil
}

// TestSEECPRF_DrawnEntropyZeroed pins the zeroing of the fresh per-call
// entropy r: without it, secret-adjacent material would linger in memory.
// (Kills the surviving zeroSlice(r[:]) mutation the audit found.)
func TestSEECPRF_DrawnEntropyZeroed(t *testing.T) {
	s := mustSEECPRF(t, &testSha256{})
	cr := &capturingReader{fill: 0xAB}
	if _, err := s.GenRand(cr, SEECKeygen, 32); err != nil {
		t.Fatalf("GenRand: %v", err)
	}
	if cr.captured == nil {
		t.Fatal("reader never received the entropy buffer")
	}
	for i, b := range cr.captured {
		if b != 0 {
			t.Fatalf("drawn entropy not zeroed after GenRand: byte %d = 0x%02x", i, b)
		}
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

// bigConsistentHash declares HashLen 100 > BlockLen 64 with a CONSISTENT
// 100-byte HMAC output, so the prk-length check passes (100 == 100) and
// ONLY the geometry guard can reject it. Without that guard the instance
// would construct and then fail on the first GenRand re-key (a 100-byte
// prk is too long to be an HMAC key) - the exact SEEC-16 mid-handshake
// trap the construction-time guard exists to prevent.
type bigConsistentHash struct{}

func (bigConsistentHash) Name() string                  { return "BIG" }
func (bigConsistentHash) HashLen() int                  { return 100 }
func (bigConsistentHash) BlockLen() int                 { return 64 }
func (bigConsistentHash) Hash(data []byte) []byte       { return make([]byte, 100) }
func (bigConsistentHash) NewHMAC(key []byte) HMACWriter { return bigHMAC{} }

type bigHMAC struct{}

func (bigHMAC) Write(p []byte) (int, error) { return len(p), nil }
func (bigHMAC) Sum() []byte                 { return make([]byte, 100) }

func TestNewSEECPRF_BigGeometryRejectedAtConstruction(t *testing.T) {
	// Pins the geometry guard as load-bearing: this hash's consistent
	// output passes the prk-length check, so only the hl>bl guard catches
	// it, and only at construction (not the first draw).
	_, err := NewSEECPRF(bigConsistentHash{}, testSecret())
	if err == nil {
		t.Fatal("HashLen > BlockLen with consistent output must be rejected at construction")
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

// scriptedHash wraps testSha256 but lets each successive HMAC instance
// misbehave per a script: "" = honest, "err" = Write refuses, "short" =
// truncated Sum. Instance order through SEECPRF: 1 = constructor Extract,
// 2 = GenRand re-key, 3 = expand T(1), 4 = expand T(2), ...
type scriptedHash struct {
	testSha256
	script []string
	calls  int
}

func (s *scriptedHash) NewHMAC(key []byte) HMACWriter {
	mode := ""
	if s.calls < len(s.script) {
		mode = s.script[s.calls]
	}
	s.calls++
	return &scriptedHMAC{inner: (&testSha256{}).NewHMAC(key), mode: mode}
}

type scriptedHMAC struct {
	inner HMACWriter
	mode  string
}

func (m *scriptedHMAC) Write(p []byte) (int, error) {
	if m.mode == "err" {
		return 0, errors.New("hmac write refused")
	}
	return m.inner.Write(p)
}

func (m *scriptedHMAC) Sum() []byte {
	s := m.inner.Sum()
	if m.mode == "short" {
		return s[:16]
	}
	return s
}

// TestSEECPRF_HMACFailurePaths drives every internal HMAC failure branch:
// each must fail closed with ErrSEEC, never return partial output.
func TestSEECPRF_HMACFailurePaths(t *testing.T) {
	rng := func() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)) }

	// Constructor Extract fails.
	if _, err := NewSEECPRF(&scriptedHash{script: []string{"err"}}, testSecret()); err == nil {
		t.Fatal("constructor must reject failing Extract")
	} else if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}

	// GenRand re-key HMAC fails (construction honest, second instance errs).
	s, err := NewSEECPRF(&scriptedHash{script: []string{"", "err"}}, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.GenRand(rng(), SEECKeygen, 32); err == nil || out != nil {
		t.Fatalf("re-key failure must fail closed with nil output, got (%v, %v)", out, err)
	} else if !errors.Is(err, ErrSEEC) {
		t.Fatalf("error must wrap ErrSEEC, got: %v", err)
	}

	// Expand T(1) HMAC fails.
	s, err = NewSEECPRF(&scriptedHash{script: []string{"", "", "err"}}, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.GenRand(rng(), SEECKeygen, 32); err == nil || out != nil {
		t.Fatalf("expand T(1) failure must fail closed, got (%v, %v)", out, err)
	}

	// Expand T(1) returns a short block.
	s, err = NewSEECPRF(&scriptedHash{script: []string{"", "", "short"}}, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.GenRand(rng(), SEECKeygen, 32); err == nil || out != nil {
		t.Fatalf("expand short T(1) must fail closed, got (%v, %v)", out, err)
	}
}

// zeroLenHash declares HashLen 0: hkdfExpand must reject it directly
// (the constructor's geometry check is not in the direct-call path).
type zeroLenHash struct{ testSha256 }

func (zeroLenHash) HashLen() int { return 0 }

func TestHkdfExpand_MidChainFailures(t *testing.T) {
	prk := bytes.Repeat([]byte{0x0d}, 32)

	if _, err := hkdfExpand(&zeroLenHash{}, prk, nil, 32); err == nil {
		t.Fatal("zero hash length must error")
	}

	// T(2) HMAC fails mid-chain (2-block expand, first instance honest).
	if _, err := hkdfExpand(&scriptedHash{script: []string{"", "err"}}, prk, nil, 64); err == nil {
		t.Fatal("mid-chain HMAC failure must error")
	}

	// T(2) shrinks mid-chain.
	if _, err := hkdfExpand(&scriptedHash{script: []string{"", "short"}}, prk, nil, 64); err == nil {
		t.Fatal("mid-chain size change must error")
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
