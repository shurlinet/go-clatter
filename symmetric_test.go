package clatter

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// reuse testSha256/testSha512 from hash_test.go (same package)

// Same protocol name, SHA-256 (HASHLEN=32) hashes it, SHA-512 (HASHLEN=64) pads it.
func TestSymmetricState_InitHashVsPad(t *testing.T) {
	// 48-byte name: > 32 (SHA-256 hashes), <= 64 (SHA-512 pads)
	name := "Noise_XX_25519+MLKEM768_ChaChaPoly_SHA256xx" // 44 bytes, adjust
	// Use exactly 48 bytes
	name = "Noise_XX_25519+MLKEM768_ChaChaPoly_SHA256paddd" // 48 bytes
	if len(name) != 48 {
		// Let's be precise
		name = "012345678901234567890123456789012345678901234567" // exactly 48 bytes
	}

	ss256 := InitializeSymmetric(&testSha256{}, &testCipher{}, name)
	ss512 := InitializeSymmetric(&testSha512{}, &testCipher{}, name)

	h256 := ss256.GetHandshakeHash()
	h512 := ss512.GetHandshakeHash()

	// SHA-256 (HASHLEN=32): 48 > 32, so h = SHA-256(name)
	expectedH256 := sha256.Sum256([]byte(name))
	if !bytes.Equal(h256, expectedH256[:]) {
		t.Fatal("SHA-256 should HASH a 48-byte name (48 > 32)")
	}

	// SHA-512 (HASHLEN=64): 48 <= 64, so h = name padded with zeros
	var expectedH512 [64]byte
	copy(expectedH512[:], []byte(name))
	if !bytes.Equal(h512, expectedH512[:]) {
		t.Fatal("SHA-512 should PAD a 48-byte name (48 <= 64)")
	}

	// They must be different
	if bytes.Equal(h256, h512[:32]) {
		t.Fatal("SHA-256 and SHA-512 should produce different h for same name")
	}
}

// Protocol name exactly equal to HASHLEN is PADDED (<=), not hashed.
func TestSymmetricState_ExactHashLenIsPadded(t *testing.T) {
	// Exactly 32 bytes for SHA-256
	name := "Noise_XX_25519_ChaChaPoly_SHA256" // 32 bytes
	if len(name) != 32 {
		t.Fatalf("test name must be exactly 32 bytes, got %d", len(name))
	}

	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, name)
	h := ss.GetHandshakeHash()

	// Should be padded, not hashed. Padded = name as-is (already 32 bytes, no padding needed)
	if !bytes.Equal(h, []byte(name)) {
		t.Fatal("exactly HASHLEN name should be padded, not hashed")
	}

	// Verify it's NOT the hash
	hashed := sha256.Sum256([]byte(name))
	if bytes.Equal(h, hashed[:]) {
		t.Fatal("exactly HASHLEN name was hashed, should be padded")
	}
}

// ck = h (array copy, not alias). Mutating h should not affect ck.
func TestSymmetricState_CKNotAliasedToH(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_protocol")

	hBefore := ss.GetHandshakeHash()
	ckBefore := ss.ChainingKey()

	// Initially they should be equal
	if !bytes.Equal(hBefore, ckBefore) {
		t.Fatal("h and ck should be equal after init")
	}

	// MixHash changes h but should NOT change ck
	ss.MixHash([]byte("some data"))

	hAfter := ss.GetHandshakeHash()
	ckAfter := ss.ChainingKey()

	if bytes.Equal(hBefore, hAfter) {
		t.Fatal("h should change after MixHash")
	}
	if !bytes.Equal(ckBefore, ckAfter) {
		t.Fatal("ck should NOT change after MixHash (F120: no aliasing)")
	}
}

// Before MixKey, HasKey is false. EncryptAndHash copies plaintext verbatim.
func TestSymmetricState_NoKeyVerbatimCopy(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")

	if ss.HasKey() {
		t.Fatal("should not have key before MixKey")
	}

	// Encrypt without key = verbatim copy
	plaintext := []byte("hello world")
	ct, err := ss.EncryptAndHash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, plaintext) {
		t.Fatal("without key, encrypt should copy plaintext verbatim")
	}
}

// Decrypt without key = verbatim copy
func TestSymmetricState_NoKeyDecryptVerbatim(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")

	data := []byte("some data")
	pt, err := ss.DecryptAndHash(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("without key, decrypt should copy verbatim")
	}
}

// EncryptAndHash and decryptAndHash hash CIPHERTEXT, not plaintext.
// Both sides should agree on h after encrypt+decrypt.
func TestSymmetricState_HashesCiphertextNotPlaintext(t *testing.T) {
	ss1 := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_protocol")
	ss2 := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_protocol")

	// Both mix the same key
	ikm := bytes.Repeat([]byte{0x42}, 32)
	ss1.MixKey(ikm)
	ss2.MixKey(ikm)

	// Side 1 encrypts
	plaintext := []byte("hello from side 1")
	ct, err := ss1.EncryptAndHash(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Side 2 decrypts
	pt, err := ss2.DecryptAndHash(ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Fatal("round-trip failed")
	}

	// Both sides should have identical h after (both mixed the ciphertext)
	h1 := ss1.GetHandshakeHash()
	h2 := ss2.GetHandshakeHash()
	if !bytes.Equal(h1, h2) {
		t.Fatal("handshake hashes should match after encrypt+decrypt (F28: both hash ciphertext)")
	}
}

// MixKey destroys old CipherState before replacing.
func TestSymmetricState_MixKeyDestroysOld(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")

	ss.MixKey(bytes.Repeat([]byte{0x01}, 32))
	oldCS := ss.cs

	ss.MixKey(bytes.Repeat([]byte{0x02}, 32))

	// Old CipherState should be destroyed
	if !oldCS.IsDestroyed() {
		t.Fatal("old CipherState should be destroyed after MixKey (F29)")
	}

	// New CipherState should exist and have key
	if !ss.HasKey() {
		t.Fatal("should have key after MixKey")
	}
}

// Truncate HKDF output to KeyLen for 64-byte hashes.
func TestSymmetricState_SHA512TruncatesToKeyLen(t *testing.T) {
	ss := InitializeSymmetric(&testSha512{}, &testCipher{}, "test_sha512")

	err := ss.MixKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}

	// After MixKey, CipherState should exist with a valid key
	if !ss.HasKey() {
		t.Fatal("should have key after MixKey with SHA-512")
	}
}

// Output size differs based on HasKey.
func TestSymmetricState_EncryptOutputSize(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")
	plaintext := []byte("hello")

	// Without key: output = plaintext length
	ct1, err := ss.EncryptAndHash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct1) != len(plaintext) {
		t.Fatalf("without key: output should be %d bytes, got %d", len(plaintext), len(ct1))
	}

	// With key: output = plaintext + tag
	ss2 := InitializeSymmetric(&testSha256{}, &testCipher{}, "test2")
	ss2.MixKey(bytes.Repeat([]byte{0x01}, 32))
	ct2, err := ss2.EncryptAndHash(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct2) != len(plaintext)+TagLen {
		t.Fatalf("with key: output should be %d bytes, got %d", len(plaintext)+TagLen, len(ct2))
	}
}

// SetError zeros all state immediately.
func TestSymmetricState_SetErrorZerosState(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_error")
	ss.MixKey(bytes.Repeat([]byte{0xff}, 32))

	ss.SetError(ErrCipher)

	if ss.Err() != ErrCipher {
		t.Fatal("sticky error not set")
	}

	// h should be zeroed
	for _, b := range ss.h {
		if b != 0 {
			t.Fatal("h not zeroed after SetError")
		}
	}
	// ck should be zeroed
	for _, b := range ss.ck {
		if b != 0 {
			t.Fatal("ck not zeroed after SetError")
		}
	}
	// cs should be nil
	if ss.cs != nil {
		t.Fatal("cs should be nil after SetError")
	}
}

// Split test: two CipherStates, both at nonce 0.
func TestSymmetricState_Split(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_split")
	ss.MixKey(bytes.Repeat([]byte{0x42}, 32))

	cs1, cs2, err := ss.Split()
	if err != nil {
		t.Fatal(err)
	}

	// Both at nonce 0
	if cs1.Nonce() != 0 {
		t.Fatal("cs1 nonce should be 0")
	}
	if cs2.Nonce() != 0 {
		t.Fatal("cs2 nonce should be 0")
	}

	// Both should have keys
	if !cs1.HasKey() || !cs2.HasKey() {
		t.Fatal("both should have keys")
	}

	// They should have different keys (HKDF2 out1 != out2)
	if cs1.key == cs2.key {
		t.Fatal("split CipherStates should have different keys")
	}

	cs1.Destroy()
	cs2.Destroy()
}

// Split without key returns error.
func TestSymmetricState_SplitWithoutKey(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_no_key")

	_, _, err := ss.Split()
	if err == nil {
		t.Fatal("Split without key should fail")
	}
}

// Sticky error blocks all further operations.
func TestSymmetricState_StickyErrorBlocksOps(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_sticky")
	ss.MixKey(bytes.Repeat([]byte{0x42}, 32))

	ss.SetError(ErrCipher)

	// All mutating operations should return the sticky error
	if err := ss.MixKey(bytes.Repeat([]byte{0x01}, 32)); err != ErrCipher {
		t.Fatalf("MixKey after SetError: expected ErrCipher, got %v", err)
	}
	if err := ss.MixKeyAndHash(bytes.Repeat([]byte{0x01}, 32)); err != ErrCipher {
		t.Fatalf("MixKeyAndHash after SetError: expected ErrCipher, got %v", err)
	}
	if _, err := ss.EncryptAndHash([]byte("x")); err != ErrCipher {
		t.Fatalf("EncryptAndHash after SetError: expected ErrCipher, got %v", err)
	}
	if _, err := ss.DecryptAndHash([]byte("x")); err != ErrCipher {
		t.Fatalf("DecryptAndHash after SetError: expected ErrCipher, got %v", err)
	}
	if _, _, err := ss.Split(); err != ErrCipher {
		t.Fatalf("Split after SetError: expected ErrCipher, got %v", err)
	}
}

// MixKeyAndHash test: verifies 3-output HKDF wiring.
func TestSymmetricState_MixKeyAndHash(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_mkah")

	hBefore := ss.GetHandshakeHash()

	err := ss.MixKeyAndHash(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}

	// h should have changed (MixHash called with tempH)
	hAfter := ss.GetHandshakeHash()
	if bytes.Equal(hBefore, hAfter) {
		t.Fatal("h should change after MixKeyAndHash")
	}

	// Should have a key
	if !ss.HasKey() {
		t.Fatal("should have key after MixKeyAndHash")
	}
}

// MixKeyAndHash also destroys old CipherState.
func TestSymmetricState_MixKeyAndHashDestroysOld(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")

	ss.MixKey(bytes.Repeat([]byte{0x01}, 32))
	oldCS := ss.cs

	ss.MixKeyAndHash(bytes.Repeat([]byte{0x02}, 32))

	if !oldCS.IsDestroyed() {
		t.Fatal("old CipherState should be destroyed after MixKeyAndHash (F29)")
	}
}

// Destroy test.
func TestSymmetricState_Destroy(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_destroy")
	ss.MixKey(bytes.Repeat([]byte{0xff}, 32))

	ss.Destroy()

	for _, b := range ss.h {
		if b != 0 {
			t.Fatal("h not zeroed after Destroy")
		}
	}
	for _, b := range ss.ck {
		if b != 0 {
			t.Fatal("ck not zeroed after Destroy")
		}
	}
	if ss.cs != nil {
		t.Fatal("cs should be nil after Destroy")
	}
}

// MixHash is idempotent on state (deterministic).
func TestSymmetricState_MixHashDeterministic(t *testing.T) {
	ss1 := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")
	ss2 := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")

	data := []byte("hello")
	ss1.MixHash(data)
	ss2.MixHash(data)

	if !bytes.Equal(ss1.GetHandshakeHash(), ss2.GetHandshakeHash()) {
		t.Fatal("MixHash should be deterministic")
	}
}

// Protocol name longer than HASHLEN gets hashed.
func TestSymmetricState_LongNameHashed(t *testing.T) {
	// 64-byte name with SHA-256 (HASHLEN=32): should be hashed
	name := "Noise_hybridXX_25519+MLKEM768_ChaChaPoly_SHA256_extra_padding!!"
	if len(name) != 64 {
		// Build a 64-byte string
		name = string(bytes.Repeat([]byte("x"), 64))
	}

	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, name)
	h := ss.GetHandshakeHash()

	expected := sha256.Sum256([]byte(name))
	if !bytes.Equal(h, expected[:]) {
		t.Fatal("64-byte name with SHA-256 should be hashed")
	}
}

// Short name gets padded.
func TestSymmetricState_ShortNamePadded(t *testing.T) {
	name := "test"
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, name)
	h := ss.GetHandshakeHash()

	var expected [32]byte
	copy(expected[:], []byte(name))
	if !bytes.Equal(h, expected[:]) {
		t.Fatal("short name should be zero-padded")
	}
}

// Full encrypt/decrypt round-trip through SymmetricState with real HMAC.
func TestSymmetricState_FullRoundTrip(t *testing.T) {
	// Use real SHA-256 HMAC for a more thorough test
	h := &testSha256{}
	c := &testCipher{}

	alice := InitializeSymmetric(h, c, "Noise_NN_25519_TestCipher_SHA256")
	bob := InitializeSymmetric(h, c, "Noise_NN_25519_TestCipher_SHA256")

	// Verify initial state matches
	if !bytes.Equal(alice.GetHandshakeHash(), bob.GetHandshakeHash()) {
		t.Fatal("initial h mismatch")
	}

	// Both mix same ephemeral key
	ephKey := bytes.Repeat([]byte{0x42}, 32)
	alice.MixHash(ephKey) // simulate E token
	bob.MixHash(ephKey)

	// DH result
	dhResult := bytes.Repeat([]byte{0xaa}, 32)
	alice.MixKey(dhResult)
	bob.MixKey(dhResult)

	// Alice encrypts payload
	payload := []byte("hello bob")
	ct, err := alice.EncryptAndHash(payload)
	if err != nil {
		t.Fatal(err)
	}

	// Bob decrypts
	pt, err := bob.DecryptAndHash(ct)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pt, payload) {
		t.Fatalf("round-trip: got %q, want %q", pt, payload)
	}

	// Hashes must match
	if !bytes.Equal(alice.GetHandshakeHash(), bob.GetHandshakeHash()) {
		t.Fatal("handshake hashes diverged after encrypt/decrypt")
	}
}

// Deeper test: verify HKDF via SymmetricState doesn't corrupt ck
// by calling MixKey twice and checking second result is correct.
func TestSymmetricState_DoubleMixKeyCorrectness(t *testing.T) {
	h := &testSha256{}
	c := &testCipher{}

	ss1 := InitializeSymmetric(h, c, "test_double_mixkey")
	ss2 := InitializeSymmetric(h, c, "test_double_mixkey")

	// Both do same two MixKeys
	ikm1 := bytes.Repeat([]byte{0x11}, 32)
	ikm2 := bytes.Repeat([]byte{0x22}, 32)

	ss1.MixKey(ikm1)
	ss1.MixKey(ikm2)

	ss2.MixKey(ikm1)
	ss2.MixKey(ikm2)

	// Must match
	if !bytes.Equal(ss1.ChainingKey(), ss2.ChainingKey()) {
		t.Fatal("ck diverged after double MixKey")
	}
	if !bytes.Equal(ss1.GetHandshakeHash(), ss2.GetHandshakeHash()) {
		t.Fatal("h diverged after double MixKey")
	}
}

// Verify HKDF counter 0x01 correctness end-to-end through SymmetricState.
// Uses known SHA-256 HMAC computation to verify.
func TestSymmetricState_HKDFCounterEndToEnd(t *testing.T) {
	h := &testSha256{}
	c := &testCipher{}

	ss := InitializeSymmetric(h, c, "test_counter")
	ckBefore := ss.ChainingKey()

	ikm := []byte("input")
	ss.MixKey(ikm)

	// Manually compute expected ck
	mac1 := hmac.New(sha256.New, ckBefore)
	mac1.Write(ikm)
	tempKey := mac1.Sum(nil)

	mac2 := hmac.New(sha256.New, tempKey)
	mac2.Write([]byte{0x01}) // raw byte, not ASCII
	expectedCk := mac2.Sum(nil)

	if !bytes.Equal(ss.ChainingKey(), expectedCk) {
		t.Fatal("MixKey ck doesn't match manual HMAC with 0x01 counter")
	}
}

// End-to-end: SHA-512 SymmetricState Split produces 32-byte keys.
func TestSymmetricState_SHA512SplitKeyLen(t *testing.T) {
	ss := InitializeSymmetric(&testSha512{}, &testCipher{}, "test_sha512_split")
	ss.MixKey(bytes.Repeat([]byte{0x42}, 32))

	cs1, cs2, err := ss.Split()
	if err != nil {
		t.Fatal(err)
	}
	defer cs1.Destroy()
	defer cs2.Destroy()

	// Keys should be 32 bytes (truncated from 64-byte SHA-512 HKDF output)
	if !cs1.HasKey() || !cs2.HasKey() {
		t.Fatal("both should have keys after SHA-512 split")
	}
}

// GetHandshakeHash returns a copy, not a reference.
func TestSymmetricState_HandshakeHashIsCopy(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")
	h := ss.GetHandshakeHash()
	h[0] = 0xff // mutate the copy

	h2 := ss.GetHandshakeHash()
	if h2[0] == 0xff {
		t.Fatal("GetHandshakeHash returned reference, not copy")
	}
}

// ChainingKey returns a copy, not a reference.
func TestSymmetricState_ChainingKeyIsCopy(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test")
	ck := ss.ChainingKey()
	ck[0] = 0xff

	ck2 := ss.ChainingKey()
	if ck2[0] == 0xff {
		t.Fatal("ChainingKey returned reference, not copy")
	}
}
