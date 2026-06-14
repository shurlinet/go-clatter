package clatter_test

import (
	"bytes"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// Suite-boundary validation tests: consumer-chosen primitives with
// impossible declared geometry must fail at construction with errors,
// never panic mid-handshake or silently corrupt the wire.

// hugeLenHash wraps a real hash but declares an oversized HashLen
// (beyond the MaxHashLen state arrays - the slice-out-of-range probe).
type hugeLenHash struct{ clatter.HashFunc }

func (hugeLenHash) HashLen() int { return 100 }

// zeroLenHash declares a zero HashLen.
type zeroLenHash struct{ clatter.HashFunc }

func (zeroLenHash) HashLen() int { return 0 }

// badTagCipher wraps a real cipher but declares a 12-byte tag.
type badTagCipher struct{ clatter.Cipher }

func (badTagCipher) TagLen() int { return 12 }

// badKeyCipher wraps a real cipher but declares a 16-byte key.
type badKeyCipher struct{ clatter.Cipher }

func (badKeyCipher) KeyLen() int { return 16 }

func TestSuiteValidation_GeometryRejected(t *testing.T) {
	base := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqBase := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyBase := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	for _, tc := range []struct {
		name   string
		mutate func(s clatter.CipherSuite) clatter.CipherSuite
	}{
		{"hash-too-long", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Hash = hugeLenHash{s.Hash}
			return s
		}},
		{"hash-zero", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Hash = zeroLenHash{s.Hash}
			return s
		}},
		{"tag-not-16", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Cipher = badTagCipher{s.Cipher}
			return s
		}},
		{"key-not-32", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Cipher = badKeyCipher{s.Cipher}
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, tc.mutate(base)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("NQ constructor: want ErrInvalidSuite, got %v", err)
			}
			if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, tc.mutate(pqBase)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("PQ constructor: want ErrInvalidSuite, got %v", err)
			}
			if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, tc.mutate(hyBase)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("Hybrid constructor: want ErrInvalidSuite, got %v", err)
			}
		})
	}
}

// TestSuiteValidation_InitializeSymmetricLatches covers direct users of
// the exported SymmetricState API: an impossible declared HashLen latches
// the error state instead of panicking on the fixed-size arrays.
func TestSuiteValidation_InitializeSymmetricLatches(t *testing.T) {
	ss := clatter.InitializeSymmetric(hugeLenHash{hash.NewSha256()}, cipher.NewChaChaPoly(), "Noise_XX_25519_ChaChaPoly_SHA256")
	if ss.Err() == nil {
		t.Fatal("InitializeSymmetric with an oversized declared HashLen must latch an error")
	}
	ss.MixHash([]byte("must not panic"))
	if _, err := ss.EncryptAndHash([]byte("payload")); err == nil {
		t.Fatal("operations on the latched state must fail")
	}
}

// TestPresetKeyLengthValidation pins the constructor-time length checks
// for pre-set key options: a wrong-length key is a loud ErrInvalidKeyLength
// at construction, not a silently malformed wire message.
func TestPresetKeyLengthValidation(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqS := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyS := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	shortKP := clatter.NewKeyPair(make([]byte, 16), make([]byte, 16))

	if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithStaticKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithEphemeralKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short ephemeral: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewNqHandshake(clatter.PatternIK, true, nqS, clatter.WithRemoteStatic(make([]byte, 16))); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short remote static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS, clatter.WithStaticKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("PQ short static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, clatter.WithStaticKEMKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("Hybrid short KEM static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, clatter.WithRemoteStaticKEMKey(make([]byte, 16))); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("Hybrid short remote KEM static: want ErrInvalidKeyLength, got %v", err)
	}
}

// allocCipher wraps a real cipher but VIOLATES the in-place contract:
// it writes its (correct) output into a freshly allocated buffer instead
// of the caller's out. The in-place transport paths must detect this and
// still put real ciphertext on the wire - never report success with the
// plaintext left in the buffer.
type allocCipher struct{ inner clatter.Cipher }

func (a allocCipher) Name() string { return a.inner.Name() }
func (a allocCipher) TagLen() int  { return a.inner.TagLen() }
func (a allocCipher) KeyLen() int  { return a.inner.KeyLen() }
func (a allocCipher) Encrypt(key [32]byte, nonce uint64, ad, plaintext, _ []byte) ([]byte, error) {
	out := make([]byte, 0, len(plaintext)+a.inner.TagLen())
	return a.inner.Encrypt(key, nonce, ad, plaintext, out)
}
func (a allocCipher) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, _ []byte) ([]byte, error) {
	out := make([]byte, 0, len(ciphertext))
	return a.inner.Decrypt(key, nonce, ad, ciphertext, out)
}

func TestInPlaceTransport_ContractViolatingCipher(t *testing.T) {
	suite := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: allocCipher{cipher.NewChaChaPoly()}, Hash: hash.NewSha256()}

	a, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	b, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = runHandshakeRecorded(t, a, b)
	tsA, err := a.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	tsB, err := b.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	defer tsA.Destroy()
	defer tsB.Destroy()

	payload := []byte("must never appear on the wire")
	buf := make([]byte, 4096)
	copy(buf, payload)
	n, err := tsA.SendInPlace(buf, len(payload))
	if err != nil {
		t.Fatalf("SendInPlace: %v", err)
	}
	if bytes.Contains(buf[:n], payload) {
		t.Fatal("in-place send left the PLAINTEXT in the wire buffer (contract-violating cipher undetected)")
	}
	out := make([]byte, 4096)
	pn, err := tsB.Receive(buf[:n], out)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(out[:pn], payload) {
		t.Fatal("round-trip payload mismatch")
	}
}
