package clatter

import (
	"bytes"
	"math"
	"testing"
)

// testCipher implements Cipher for CipherState unit tests.
// Uses a simple XOR "cipher" that is NOT secure but verifies state machine logic.
type testCipher struct{}

func (c *testCipher) Name() string  { return "TestCipher" }
func (c *testCipher) TagLen() int   { return TagLen }
func (c *testCipher) KeyLen() int   { return KeyLen }

func (c *testCipher) Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error) {
	// Simple XOR with first key byte for testing, append 16-byte fake tag
	result := out[:0]
	for _, b := range plaintext {
		result = append(result, b^key[0])
	}
	// Fake tag: 16 bytes of key[1]
	for i := 0; i < TagLen; i++ {
		result = append(result, key[1])
	}
	return result, nil
}

func (c *testCipher) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error) {
	if len(ciphertext) < TagLen {
		return nil, ErrDecrypt
	}
	// Verify fake tag
	tagStart := len(ciphertext) - TagLen
	for i := tagStart; i < len(ciphertext); i++ {
		if ciphertext[i] != key[1] {
			return nil, ErrDecrypt
		}
	}
	// XOR back
	result := out[:0]
	for i := 0; i < tagStart; i++ {
		result = append(result, ciphertext[i]^key[0])
	}
	return result, nil
}

func newTestCipherState(t *testing.T) *CipherState {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, KeyLen)
	cs, err := NewCipherState(&testCipher{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// CipherState starts at nonce 0.
func TestCipherState_InitialNonce(t *testing.T) {
	cs := newTestCipherState(t)
	if cs.Nonce() != 0 {
		t.Fatalf("initial nonce: got %d, want 0", cs.Nonce())
	}
}

// Wrong key length returns error.
func TestCipherState_InvalidKeyLength(t *testing.T) {
	_, err := NewCipherState(&testCipher{}, make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

// HasKey is true after construction.
func TestCipherState_HasKey(t *testing.T) {
	cs := newTestCipherState(t)
	if !cs.HasKey() {
		t.Fatal("expected HasKey=true")
	}
}

// Nil CipherState HasKey returns false.
func TestCipherState_NilHasKey(t *testing.T) {
	var cs *CipherState
	if cs.HasKey() {
		t.Fatal("nil CipherState should return HasKey=false")
	}
}

// Basic encrypt/decrypt round-trip.
func TestCipherState_EncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeyLen)
	enc, _ := NewCipherState(&testCipher{}, key)
	dec, _ := NewCipherState(&testCipher{}, key)

	plaintext := []byte("hello noise protocol")
	ad := []byte("associated data")

	ct, err := enc.EncryptWithAd(ad, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := dec.DecryptWithAd(ad, ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", pt, plaintext)
	}
}

// Nonce increments after each encrypt.
func TestCipherState_NonceIncrements(t *testing.T) {
	cs := newTestCipherState(t)

	for i := uint64(0); i < 5; i++ {
		if cs.Nonce() != i {
			t.Fatalf("before encrypt %d: nonce=%d", i, cs.Nonce())
		}
		_, err := cs.EncryptWithAd(nil, []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if cs.Nonce() != 5 {
		t.Fatalf("after 5 encrypts: nonce=%d, want 5", cs.Nonce())
	}
}

// MaxUint64 nonce encrypts successfully, then blocks.
func TestCipherState_NonceOverflow(t *testing.T) {
	cs := newTestCipherState(t)
	cs.setNonce(math.MaxUint64)

	// First encrypt at MaxUint64 should succeed
	_, err := cs.EncryptWithAd(nil, []byte("last encrypt"))
	if err != nil {
		t.Fatalf("encrypt at MaxUint64 should succeed: %v", err)
	}

	// overflowed should now be true
	if !cs.overflowed {
		t.Fatal("expected overflowed=true after MaxUint64 encrypt")
	}

	// Next encrypt should fail
	_, err = cs.EncryptWithAd(nil, []byte("should fail"))
	if err != ErrNonceOverflow {
		t.Fatalf("expected ErrNonceOverflow, got %v", err)
	}
}

// Same overflow logic for decrypt.
func TestCipherState_NonceOverflowDecrypt(t *testing.T) {
	// Encrypt at MaxUint64, then try to decrypt at MaxUint64
	key := bytes.Repeat([]byte{0x42}, KeyLen)
	enc, _ := NewCipherState(&testCipher{}, key)
	enc.setNonce(math.MaxUint64)
	ct, err := enc.EncryptWithAd(nil, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	dec, _ := NewCipherState(&testCipher{}, key)
	dec.setNonce(math.MaxUint64)
	_, err = dec.DecryptWithAd(nil, ct)
	if err != nil {
		t.Fatalf("decrypt at MaxUint64 should succeed: %v", err)
	}

	// Next decrypt should fail
	_, err = dec.DecryptWithAd(nil, ct)
	if err != ErrNonceOverflow {
		t.Fatalf("expected ErrNonceOverflow, got %v", err)
	}
}

// Destroy zeros ALL fields (key, nonce, cipher ref).
func TestCipherState_Destroy(t *testing.T) {
	cs := newTestCipherState(t)
	cs.setNonce(42)
	cs.Destroy()

	if !cs.IsDestroyed() {
		t.Fatal("expected destroyed")
	}
	for i, b := range cs.key {
		if b != 0 {
			t.Fatalf("key byte %d not zeroed: %02x", i, b)
		}
	}
	if cs.hasKey {
		t.Fatal("hasKey should be false after Destroy")
	}
	if cs.nonce != 0 {
		t.Fatal("nonce should be zeroed after Destroy")
	}
	if cs.overflowed {
		t.Fatal("overflowed should be false after Destroy")
	}
	if cs.cipher != nil {
		t.Fatal("cipher should be nil after Destroy")
	}
}

// Operations on destroyed CipherState return error.
func TestCipherState_DestroyedOperations(t *testing.T) {
	cs := newTestCipherState(t)
	cs.Destroy()

	_, err := cs.EncryptWithAd(nil, []byte("x"))
	if err != ErrDestroyed {
		t.Fatalf("encrypt after destroy: expected ErrDestroyed, got %v", err)
	}

	_, err = cs.DecryptWithAd(nil, bytes.Repeat([]byte{0}, TagLen+1))
	if err != ErrDestroyed {
		t.Fatalf("decrypt after destroy: expected ErrDestroyed, got %v", err)
	}

	err = cs.Rekey()
	if err != ErrDestroyed {
		t.Fatalf("rekey after destroy: expected ErrDestroyed, got %v", err)
	}
}

// Nil CipherState operations return error (not panic).
func TestCipherState_NilOperations(t *testing.T) {
	var cs *CipherState

	_, err := cs.EncryptWithAd(nil, []byte("x"))
	if err != ErrCipher {
		t.Fatalf("nil encrypt: expected ErrCipher, got %v", err)
	}

	_, err = cs.DecryptWithAd(nil, bytes.Repeat([]byte{0}, TagLen+1))
	if err != ErrCipher {
		t.Fatalf("nil decrypt: expected ErrCipher, got %v", err)
	}

	err = cs.Rekey()
	if err != ErrCipher {
		t.Fatalf("nil rekey: expected ErrCipher, got %v", err)
	}
}

// Rekey uses MaxUint64 nonce, does NOT affect the counter nonce.
// Rekey does NOT reset nonce.
func TestCipherState_RekeyDoesNotAffectNonce(t *testing.T) {
	// Use a key with byte[0]=0 so XOR with zeros produces zeros,
	// which differs from the original key (byte[0]=0, byte[1]=0xff).
	var key [KeyLen]byte
	key[0] = 0x00
	key[1] = 0xff
	for i := 2; i < KeyLen; i++ {
		key[i] = byte(i)
	}
	cs, err := NewCipherState(&testCipher{}, key[:])
	if err != nil {
		t.Fatal(err)
	}
	cs.setNonce(42)

	oldKey := cs.key
	err = cs.Rekey()
	if err != nil {
		t.Fatal(err)
	}

	// Nonce should still be 42 (rekey does NOT reset nonce)
	if cs.Nonce() != 42 {
		t.Fatalf("nonce after rekey: got %d, want 42", cs.Nonce())
	}

	// Key should have changed (zeros XOR key[0]=0 = zeros, + tag=key[1]=0xff)
	// New key first 32 bytes: all 0x00 (XOR with 0). Old key[2:] != 0x00.
	if cs.key == oldKey {
		t.Fatal("key should change after Rekey")
	}
}

// Decrypt with too-short ciphertext returns error.
func TestCipherState_DecryptTooShort(t *testing.T) {
	cs := newTestCipherState(t)
	_, err := cs.DecryptWithAd(nil, make([]byte, TagLen-1))
	if err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt for short CT, got %v", err)
	}
}

// setNonce is unexported (compile-time check - it's lowercase).
// This test verifies the method exists and works internally.
func TestCipherState_SetNonceInternal(t *testing.T) {
	cs := newTestCipherState(t)
	cs.setNonce(100)
	if cs.Nonce() != 100 {
		t.Fatal("setNonce failed")
	}
}

// Nil Destroy doesn't panic.
func TestCipherState_NilDestroy(t *testing.T) {
	var cs *CipherState
	cs.Destroy() // should not panic
}

// Nil IsDestroyed returns true.
func TestCipherState_NilIsDestroyed(t *testing.T) {
	var cs *CipherState
	if !cs.IsDestroyed() {
		t.Fatal("nil CipherState should be destroyed")
	}
}
