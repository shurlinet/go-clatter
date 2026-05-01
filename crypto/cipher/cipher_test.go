package cipher

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testCipher(t *testing.T, c interface {
	Name() string
	TagLen() int
	KeyLen() int
	Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error)
	Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error)
}) {
	t.Helper()
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	ad := []byte("associated data")
	plaintext := []byte("hello world noise protocol")

	// Encrypt
	out := make([]byte, len(plaintext)+c.TagLen())
	ct, err := c.Encrypt(key, 0, ad, plaintext, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(plaintext)+c.TagLen() {
		t.Fatalf("ciphertext length: expected %d, got %d", len(plaintext)+c.TagLen(), len(ct))
	}

	// Decrypt
	ptOut := make([]byte, len(plaintext))
	pt, err := c.Decrypt(key, 0, ad, ct, ptOut)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted mismatch: %q vs %q", pt, plaintext)
	}

	// Wrong key should fail
	var wrongKey [32]byte
	wrongKey[0] = 0xff
	_, err = c.Decrypt(wrongKey, 0, ad, ct, ptOut)
	if err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}

	// Wrong nonce should fail
	_, err = c.Decrypt(key, 1, ad, ct, ptOut)
	if err == nil {
		t.Fatal("expected decrypt failure with wrong nonce")
	}

	// Wrong AD should fail
	_, err = c.Decrypt(key, 0, []byte("wrong AD"), ct, ptOut)
	if err == nil {
		t.Fatal("expected decrypt failure with wrong AD")
	}
}

func TestChaChaPoly(t *testing.T) {
	testCipher(t, NewChaChaPoly())
}

func TestAesGcm(t *testing.T) {
	testCipher(t, NewAesGcm())
}

func TestChaChaPoly_NonceLE(t *testing.T) {
	// Verify nonce encoding is little-endian
	n := chachaPolyNonce(1)
	// First 4 bytes zero, then LE uint64(1)
	if n[4] != 1 {
		t.Fatalf("expected LE nonce byte 4 = 1, got %d", n[4])
	}
	for i := 5; i < 12; i++ {
		if n[i] != 0 {
			t.Fatalf("expected zero at byte %d", i)
		}
	}
}

func TestAesGcm_NonceBE(t *testing.T) {
	// Verify nonce encoding is big-endian
	n := aesGcmNonce(1)
	// First 4 bytes zero, then BE uint64(1) -> last byte is 1
	if n[11] != 1 {
		t.Fatalf("expected BE nonce byte 11 = 1, got %d", n[11])
	}
	for i := 4; i < 11; i++ {
		if n[i] != 0 {
			t.Fatalf("expected zero at byte %d", i)
		}
	}
}

func TestNonce_MaxValue(t *testing.T) {
	// Verify MaxUint64 nonce encodes correctly (used by Rekey)
	chNonce := chachaPolyNonce(^uint64(0))
	var val uint64
	val = binary.LittleEndian.Uint64(chNonce[4:])
	if val != ^uint64(0) {
		t.Fatalf("ChaCha nonce MaxUint64 encoding wrong")
	}

	aeNonce := aesGcmNonce(^uint64(0))
	val = binary.BigEndian.Uint64(aeNonce[4:])
	if val != ^uint64(0) {
		t.Fatalf("AES nonce MaxUint64 encoding wrong")
	}
}

func TestCipher_EmptyPlaintext(t *testing.T) {
	// Noise uses empty plaintext during handshake (pre-key)
	for _, c := range []struct {
		name string
		c    interface {
			Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error)
			Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error)
			TagLen() int
		}
	}{
		{"ChaChaPoly", NewChaChaPoly()},
		{"AesGcm", NewAesGcm()},
	} {
		t.Run(c.name, func(t *testing.T) {
			var key [32]byte
			out := make([]byte, c.c.TagLen())
			ct, err := c.c.Encrypt(key, 0, nil, nil, out)
			if err != nil {
				t.Fatal(err)
			}
			if len(ct) != c.c.TagLen() {
				t.Fatalf("expected tag-only output, got %d bytes", len(ct))
			}

			ptOut := make([]byte, 0)
			pt, err := c.c.Decrypt(key, 0, nil, ct, ptOut)
			if err != nil {
				t.Fatal(err)
			}
			if len(pt) != 0 {
				t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
			}
		})
	}
}

func TestCipher_InPlace(t *testing.T) {
	// In-place Seal/Open verified for both ciphers
	for _, c := range []struct {
		name string
		c    interface {
			Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error)
			Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error)
			TagLen() int
		}
	}{
		{"ChaChaPoly", NewChaChaPoly()},
		{"AesGcm", NewAesGcm()},
	} {
		t.Run(c.name, func(t *testing.T) {
			var key [32]byte
			plaintext := []byte("in-place test data for noise")
			buf := make([]byte, len(plaintext)+c.c.TagLen())
			copy(buf, plaintext)

			// Encrypt in-place
			ct, err := c.c.Encrypt(key, 0, nil, buf[:len(plaintext)], buf)
			if err != nil {
				t.Fatal(err)
			}

			// Decrypt in-place
			pt, err := c.c.Decrypt(key, 0, nil, ct, buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatal("in-place round-trip mismatch")
			}
		})
	}
}
