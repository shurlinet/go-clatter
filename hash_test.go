package clatter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// testHashFunc wraps crypto/sha256 to implement HashFunc for hash.go tests.
// Lives here so hash.go tests don't depend on crypto/hash subpackage.
type testSha256 struct{}

func (t *testSha256) Name() string  { return "SHA256" }
func (t *testSha256) HashLen() int  { return 32 }
func (t *testSha256) BlockLen() int { return 64 }
func (t *testSha256) Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
func (t *testSha256) NewHMAC(key []byte) HMACWriter {
	return &testHMACWriter{mac: hmac.New(sha256.New, key)}
}

type testSha512 struct{}

func (s *testSha512) Name() string  { return "SHA512" }
func (s *testSha512) HashLen() int  { return 64 }
func (s *testSha512) BlockLen() int { return 128 }
func (s *testSha512) Hash(data []byte) []byte {
	h := sha512.Sum512(data)
	return h[:]
}
func (s *testSha512) NewHMAC(key []byte) HMACWriter {
	return &testHMACWriter{mac: hmac.New(sha512.New, key)}
}

type testHMACWriter struct {
	mac interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}
}

func (h *testHMACWriter) Write(p []byte) (int, error) { return h.mac.Write(p) }
func (h *testHMACWriter) Sum() []byte                  { return h.mac.Sum(nil) }

// F107: Counter bytes 0x01 vs ASCII "1" produce different HKDF output.
func TestHKDF2_CounterBytesNotASCII(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0xaa}, 32)
	ikm := []byte("test key material")

	out1, out2 := HKDF2(h, ck, ikm)

	// Compute what we'd get with ASCII "1" and "2" instead
	tempKey := hmacHash(h, ck, ikm)
	wrongOut1 := hmacHash(h, tempKey, []byte("1"))  // ASCII 0x31
	wrongOut2 := hmacHash(h, tempKey, wrongOut1, []byte("2")) // ASCII 0x32

	if bytes.Equal(out1, wrongOut1) {
		t.Fatal("HKDF output1 matches ASCII counter - should use raw 0x01")
	}
	if bytes.Equal(out2, wrongOut2) {
		t.Fatal("HKDF output2 matches ASCII counter - should use raw 0x02")
	}
}

// F53: Verify manual HKDF matches Noise spec, NOT RFC 5869.
func TestHKDF2_MatchesNoiseSpec(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0x01}, 32)
	ikm := []byte("input key material")

	out1, out2 := HKDF2(h, ck, ikm)

	// Manually compute expected values using raw HMAC
	tempKey := hmacHash(h, ck, ikm)
	expectedOut1 := hmacHash(h, tempKey, []byte{0x01})
	expectedOut2 := hmacHash(h, tempKey, expectedOut1, []byte{0x02})

	if !bytes.Equal(out1, expectedOut1) {
		t.Fatalf("HKDF2 out1 mismatch:\n  got:  %s\n  want: %s",
			hex.EncodeToString(out1), hex.EncodeToString(expectedOut1))
	}
	if !bytes.Equal(out2, expectedOut2) {
		t.Fatalf("HKDF2 out2 mismatch:\n  got:  %s\n  want: %s",
			hex.EncodeToString(out2), hex.EncodeToString(expectedOut2))
	}
}

// F108: split() calls HKDF with empty IKM.
func TestHKDF2_EmptyIKM(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0x42}, 32)

	out1, out2 := HKDF2(h, ck, []byte{})

	if len(out1) != 32 || len(out2) != 32 {
		t.Fatalf("empty IKM: expected 32-byte outputs, got %d and %d", len(out1), len(out2))
	}
	// Must not be all zeros
	allZero := true
	for _, b := range out1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("empty IKM produced all-zero output1")
	}
}

// F108: Nil IKM should work the same as empty.
func TestHKDF2_NilIKM(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0x42}, 32)

	out1Empty, out2Empty := HKDF2(h, ck, []byte{})
	out1Nil, out2Nil := HKDF2(h, ck, nil)

	if !bytes.Equal(out1Empty, out1Nil) || !bytes.Equal(out2Empty, out2Nil) {
		t.Fatal("nil IKM should equal empty IKM")
	}
}

// HKDF3 test: verify third output.
func TestHKDF3_ThreeOutputs(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0xcc}, 32)
	ikm := []byte("three outputs")

	out1, out2, out3 := HKDF3(h, ck, ikm)

	// Manual verification
	tempKey := hmacHash(h, ck, ikm)
	expectedOut1 := hmacHash(h, tempKey, []byte{0x01})
	expectedOut2 := hmacHash(h, tempKey, expectedOut1, []byte{0x02})
	expectedOut3 := hmacHash(h, tempKey, expectedOut2, []byte{0x03})

	if !bytes.Equal(out1, expectedOut1) {
		t.Fatal("HKDF3 out1 mismatch")
	}
	if !bytes.Equal(out2, expectedOut2) {
		t.Fatal("HKDF3 out2 mismatch")
	}
	if !bytes.Equal(out3, expectedOut3) {
		t.Fatal("HKDF3 out3 mismatch")
	}
}

// F118: Verify ck is not corrupted when it could alias output.
func TestHKDF2_CKNotCorrupted(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0xdd}, 32)
	ckCopy := make([]byte, 32)
	copy(ckCopy, ck)
	ikm := []byte("test")

	HKDF2(h, ck, ikm)

	if !bytes.Equal(ck, ckCopy) {
		t.Fatal("HKDF2 corrupted the ck input")
	}
}

// SHA-512 test: outputs should be 64 bytes each.
func TestHKDF2_SHA512_OutputLength(t *testing.T) {
	h := &testSha512{}
	ck := bytes.Repeat([]byte{0xee}, 64)
	ikm := []byte("sha512 test")

	out1, out2 := HKDF2(h, ck, ikm)

	if len(out1) != 64 {
		t.Fatalf("SHA-512 HKDF2 out1 length: got %d, want 64", len(out1))
	}
	if len(out2) != 64 {
		t.Fatalf("SHA-512 HKDF2 out2 length: got %d, want 64", len(out2))
	}
}

// F110: Verify temp keys are zeroed (we can't directly test defer, but we can
// verify that calling HKDF2 twice with same inputs produces same outputs,
// confirming no state leakage).
func TestHKDF2_Deterministic(t *testing.T) {
	h := &testSha256{}
	ck := bytes.Repeat([]byte{0x11}, 32)
	ikm := []byte("deterministic")

	a1, a2 := HKDF2(h, ck, ikm)
	b1, b2 := HKDF2(h, ck, ikm)

	if !bytes.Equal(a1, b1) || !bytes.Equal(a2, b2) {
		t.Fatal("HKDF2 not deterministic")
	}
}

// Test zeroSlice utility.
func TestZeroSlice(t *testing.T) {
	b := []byte{0xff, 0xfe, 0xfd, 0xfc}
	zeroSlice(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %02x", i, v)
		}
	}
}

func TestZeroSlice_Empty(t *testing.T) {
	zeroSlice(nil)
	zeroSlice([]byte{})
}
