package mldsa65

import (
	"crypto/sha3"
	"encoding/hex"
	"flag"
	"fmt"
	"sync"
	"testing"
)

func Example() {
	// Generate a new key pair.
	sk, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	defer sk.Destroy()

	// Sign a message.
	msg := []byte("hello, post-quantum world")
	sig, err := sk.Sign(msg)
	if err != nil {
		panic(err)
	}

	// Verify with the public key.
	ok := sk.PublicKey().Verify(msg, sig)
	fmt.Println("verified:", ok)
	// Output: verified: true
}

func Example_withContext() {
	sk, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	defer sk.Destroy()

	msg := []byte("transfer authorization")
	sig, err := sk.SignWithContext(msg, "finance/v1")
	if err != nil {
		panic(err)
	}

	// Must verify with the same context.
	ok := sk.PublicKey().VerifyWithContext(msg, sig, "finance/v1")
	fmt.Println("correct context:", ok)

	// Wrong context rejects.
	ok = sk.PublicKey().VerifyWithContext(msg, sig, "other/v1")
	fmt.Println("wrong context:", ok)
	// Output:
	// correct context: true
	// wrong context: false
}

func Example_seedRoundTrip() {
	// Generate and export the seed for storage.
	sk, _ := GenerateKey()
	seed, _ := sk.Seed()

	// Reconstruct from seed - produces identical key.
	sk2, _ := NewPrivateKeyFromSeed(seed)
	fmt.Println("keys equal:", sk.Equal(sk2))

	// Sign with original, verify with reconstructed.
	msg := []byte("persistence test")
	sig, _ := sk.Sign(msg)
	fmt.Println("cross-verify:", sk2.PublicKey().Verify(msg, sig))

	sk.Destroy()
	sk2.Destroy()
	// Output:
	// keys equal: true
	// cross-verify: true
}

var sixtyMillionFlag = flag.Bool("60million", false, "run 60M-iteration accumulated test")

// TestAccumulated uses Filippo's accumulated test vector approach: SHAKE128
// as a deterministic seed source, accumulate public keys and deterministic
// signatures into a SHAKE128 output hash, compare against known-good values.
//
// This proves byte-for-byte correctness against the upstream filippo.io/mldsa
// implementation without checking in megabytes of test vectors.
func TestAccumulated(t *testing.T) {
	t.Run("100", func(t *testing.T) {
		testAccumulated(t, 100,
			"8358a1843220194417cadbc2651295cd8fc65125b5a5c1a239a16dc8b57ca199")
	})
	if !testing.Short() {
		t.Run("10k", func(t *testing.T) {
			t.Parallel()
			testAccumulated(t, 10000,
				"5ff5e196f0b830c3b10a9eb5358e7c98a3a20136cb677f3ae3b90175c3ace329")
		})
	}
	if *sixtyMillionFlag {
		t.Run("60M", func(t *testing.T) {
			t.Parallel()
			testAccumulated(t, 60000000,
				"0af0165db2b180f7a83dbecad1ccb758b9c2d834b7f801fc49dd572a9d4b1e83")
		})
	}
}

func testAccumulated(t *testing.T, n int, expected string) {
	s := sha3.NewSHAKE128()
	o := sha3.NewSHAKE128()
	seed := make([]byte, SeedSize)
	msg := make([]byte, 0)

	for i := 0; i < n; i++ {
		s.Read(seed)
		sk, err := NewPrivateKeyFromSeed(seed)
		if err != nil {
			t.Fatalf("iteration %d: NewPrivateKeyFromSeed: %v", i, err)
		}
		pk := sk.PublicKey().Bytes()
		o.Write(pk)

		sig, err := sk.SignDeterministic(msg)
		if err != nil {
			t.Fatalf("iteration %d: SignDeterministic: %v", i, err)
		}
		o.Write(sig)

		// Verify round-trip through NewPublicKey.
		pub, err := NewPublicKey(pk)
		if err != nil {
			t.Fatalf("iteration %d: NewPublicKey: %v", i, err)
		}
		if !pub.Equal(sk.PublicKey()) {
			t.Fatalf("iteration %d: public key mismatch after round-trip", i)
		}
		if !pub.Verify(msg, sig) {
			t.Fatalf("iteration %d: Verify failed", i)
		}
	}

	sum := make([]byte, 32)
	o.Read(sum)
	got := hex.EncodeToString(sum)
	if got != expected {
		t.Errorf("accumulated hash mismatch: got %s, want %s", got, expected)
	}
}

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if k1.Equal(k2) {
		t.Error("two generated keys are equal")
	}
}

func TestSeedRoundTrip(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	seed, err := sk.Seed()
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	sk2, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeed: %v", err)
	}
	if !sk.Equal(sk2) {
		t.Error("seed round-trip produced different key")
	}
}

func TestNewPrivateKeyFromSeed_InvalidLength(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		_, err := NewPrivateKeyFromSeed(make([]byte, size))
		if err != ErrInvalidSeedSize {
			t.Errorf("seed len %d: got %v, want ErrInvalidSeedSize", size, err)
		}
	}
}

func TestNewPublicKey_InvalidLength(t *testing.T) {
	for _, size := range []int{0, 32, 1951, 1953, 2592} {
		_, err := NewPublicKey(make([]byte, size))
		if err != ErrInvalidPublicKeySize {
			t.Errorf("pubkey len %d: got %v, want ErrInvalidPublicKeySize", size, err)
		}
	}
}

func TestNewPublicKey_AnyContentAccepted(t *testing.T) {
	// ML-DSA-65 public key encoding uses SimpleBitPack with 10-bit t1
	// coefficients (range 0-1023). Every possible 10-bit pattern is valid,
	// so any 1952-byte input is a valid encoding. The library only rejects
	// on wrong length, never on content.
	//
	// Our ErrInvalidPublicKey path exists as defense in depth for forward
	// compatibility (if a future library version adds content validation).
	// This test documents the current behavior.
	allOnes := make([]byte, PublicKeySize)
	for i := range allOnes {
		allOnes[i] = 0xFF
	}
	pk, err := NewPublicKey(allOnes)
	if err != nil {
		t.Fatalf("all-0xFF rejected: %v", err)
	}
	if pk == nil {
		t.Fatal("NewPublicKey returned nil without error")
	}

	allZeros := make([]byte, PublicKeySize)
	pk, err = NewPublicKey(allZeros)
	if err != nil {
		t.Fatalf("all-0x00 rejected: %v", err)
	}
	if pk == nil {
		t.Fatal("NewPublicKey returned nil without error")
	}
}

func TestSignVerify(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig), SignatureSize)
	}
	if !sk.PublicKey().Verify(msg, sig) {
		t.Error("valid signature rejected")
	}
}

func TestSignWithContext(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("context test")

	sig, err := sk.SignWithContext(msg, "purpose-A")
	if err != nil {
		t.Fatalf("SignWithContext: %v", err)
	}

	// Correct context verifies.
	if !sk.PublicKey().VerifyWithContext(msg, sig, "purpose-A") {
		t.Error("valid signature with correct context rejected")
	}
	// Wrong context fails.
	if sk.PublicKey().VerifyWithContext(msg, sig, "purpose-B") {
		t.Error("signature verified with wrong context")
	}
	// Empty context fails.
	if sk.PublicKey().Verify(msg, sig) {
		t.Error("signature with context verified without context")
	}
}

func TestSignDeterministic(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("deterministic test")
	sig1, _ := sk.SignDeterministic(msg)
	sig2, _ := sk.SignDeterministic(msg)
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("deterministic signatures differ for same input")
	}
}

func TestHedgedSigningProducesDifferentSigs(t *testing.T) {
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hedged test")
	sig1, _ := sk.Sign(msg)
	sig2, _ := sk.Sign(msg)
	// Hedged mode: same message should produce different signatures
	// (with overwhelming probability).
	if hex.EncodeToString(sig1) == hex.EncodeToString(sig2) {
		t.Error("hedged signatures are identical (expected different)")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	sk1, _ := GenerateKey()
	sk2, _ := GenerateKey()
	msg := []byte("wrong key test")
	sig, _ := sk1.Sign(msg)
	if sk2.PublicKey().Verify(msg, sig) {
		t.Error("signature from key A verified with key B")
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sk, _ := GenerateKey()
	sig, _ := sk.Sign([]byte("original"))
	if sk.PublicKey().Verify([]byte("modified"), sig) {
		t.Error("signature verified with wrong message")
	}
}

func TestVerifyWrongLength(t *testing.T) {
	sk, _ := GenerateKey()
	pk := sk.PublicKey()
	msg := []byte("length test")
	if pk.Verify(msg, make([]byte, 0)) {
		t.Error("empty sig verified")
	}
	if pk.Verify(msg, make([]byte, SignatureSize-1)) {
		t.Error("short sig verified")
	}
	if pk.Verify(msg, make([]byte, SignatureSize+1)) {
		t.Error("long sig verified")
	}
}

func TestVerifyTampered(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("tamper test")
	sig, _ := sk.Sign(msg)
	sig[0] ^= 0xFF
	if sk.PublicKey().Verify(msg, sig) {
		t.Error("tampered signature verified")
	}
}

func TestDestroy(t *testing.T) {
	sk, _ := GenerateKey()
	sk.Destroy()

	_, err := sk.Sign([]byte("after destroy"))
	if err != ErrDestroyed {
		t.Errorf("Sign after Destroy: got %v, want ErrDestroyed", err)
	}
	_, err = sk.Seed()
	if err != ErrDestroyed {
		t.Errorf("Seed after Destroy: got %v, want ErrDestroyed", err)
	}
}

func TestDestroyZerosSeed(t *testing.T) {
	sk, _ := GenerateKey()
	sk.Destroy()
	// Access internal seed directly (same package).
	for i, b := range sk.seed {
		if b != 0 {
			t.Fatalf("seed[%d] = %d after Destroy, want 0", i, b)
		}
	}
}

func TestDestroyIdempotent(t *testing.T) {
	sk, _ := GenerateKey()
	sk.Destroy()
	sk.Destroy() // must not panic
}

func TestDestroyedKeyLongContext(t *testing.T) {
	sk, _ := GenerateKey()
	sk.Destroy()
	// Destroyed key with invalid context must return ErrDestroyed (not ErrContextTooLong).
	_, err := sk.SignWithContext([]byte("x"), string(make([]byte, 256)))
	if err != ErrDestroyed {
		t.Errorf("destroyed + long ctx: got %v, want ErrDestroyed", err)
	}
	_, err = sk.SignDeterministicWithContext([]byte("x"), string(make([]byte, 256)))
	if err != ErrDestroyed {
		t.Errorf("destroyed + long ctx (det): got %v, want ErrDestroyed", err)
	}
}

func TestPublicKeySurvivesDestroy(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("survive test")
	sig, _ := sk.Sign(msg)
	pk := sk.PublicKey()
	sk.Destroy()
	// Public key remains usable after private key destroy.
	if !pk.Verify(msg, sig) {
		t.Error("PublicKey.Verify failed after PrivateKey.Destroy")
	}
}

func TestConcurrentSignDestroy(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("concurrent test")

	var wg sync.WaitGroup
	// Launch concurrent signers.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := sk.Sign(msg)
				if err != nil && err != ErrDestroyed {
					t.Errorf("unexpected error: %v", err)
				}
			}
		}()
	}
	// Destroy mid-flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sk.Destroy()
	}()
	wg.Wait()
}

func TestEqual(t *testing.T) {
	sk1, _ := GenerateKey()
	seed, _ := sk1.Seed()
	sk2, _ := NewPrivateKeyFromSeed(seed)
	sk3, _ := GenerateKey()

	if !sk1.Equal(sk2) {
		t.Error("same seed keys not equal")
	}
	if sk1.Equal(sk3) {
		t.Error("different seed keys are equal")
	}
	if sk1.Equal(nil) {
		t.Error("Equal(nil) returned true")
	}
}

func TestEqualBothDestroyed(t *testing.T) {
	sk1, _ := GenerateKey()
	seed, _ := sk1.Seed()
	sk2, _ := NewPrivateKeyFromSeed(seed)
	sk1.Destroy()
	sk2.Destroy()
	if sk1.Equal(sk2) {
		t.Error("two destroyed keys reported equal")
	}
}

func TestContextBoundary(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("boundary test")

	// Exactly 255 bytes - must work.
	ctx255 := string(make([]byte, 255))
	_, err := sk.SignWithContext(msg, ctx255)
	if err != nil {
		t.Fatalf("255-byte context failed: %v", err)
	}

	// 256 bytes - must fail.
	ctx256 := string(make([]byte, 256))
	_, err = sk.SignWithContext(msg, ctx256)
	if err != ErrContextTooLong {
		t.Errorf("256-byte context: got %v, want ErrContextTooLong", err)
	}
}

func TestNilEmptyMessage(t *testing.T) {
	sk, _ := GenerateKey()
	// Both nil and empty messages must work.
	sig1, err := sk.Sign(nil)
	if err != nil {
		t.Fatalf("Sign(nil): %v", err)
	}
	sig2, err := sk.Sign([]byte{})
	if err != nil {
		t.Fatalf("Sign([]byte{}): %v", err)
	}
	// Both must verify.
	if !sk.PublicKey().Verify(nil, sig1) {
		t.Error("Verify(nil) failed for sig from Sign(nil)")
	}
	if !sk.PublicKey().Verify([]byte{}, sig2) {
		t.Error("Verify([]byte{}) failed for sig from Sign([]byte{})")
	}
}

func TestSignatureSize(t *testing.T) {
	sk, _ := GenerateKey()
	for i := 0; i < 10; i++ {
		sig, err := sk.Sign([]byte("size check"))
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != SignatureSize {
			t.Fatalf("iteration %d: sig size %d, want %d", i, len(sig), SignatureSize)
		}
	}
}

func TestPublicKeySize(t *testing.T) {
	sk, _ := GenerateKey()
	pub := sk.PublicKey().Bytes()
	if len(pub) != PublicKeySize {
		t.Fatalf("pubkey size %d, want %d", len(pub), PublicKeySize)
	}
}

func TestSignDeterministicWithContext(t *testing.T) {
	sk, _ := GenerateKey()
	msg := []byte("det-ctx test")
	ctx := "my-purpose"

	sig1, err := sk.SignDeterministicWithContext(msg, ctx)
	if err != nil {
		t.Fatalf("SignDeterministicWithContext: %v", err)
	}
	sig2, err := sk.SignDeterministicWithContext(msg, ctx)
	if err != nil {
		t.Fatalf("SignDeterministicWithContext (2): %v", err)
	}
	// Same input = same signature.
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("deterministic context signatures differ for same input")
	}
	// Must verify with correct context.
	if !sk.PublicKey().VerifyWithContext(msg, sig1, ctx) {
		t.Error("deterministic context signature rejected")
	}
	// Must fail with wrong context.
	if sk.PublicKey().VerifyWithContext(msg, sig1, "other") {
		t.Error("deterministic context signature verified with wrong context")
	}
	// Context too long.
	_, err = sk.SignDeterministicWithContext(msg, string(make([]byte, 256)))
	if err != ErrContextTooLong {
		t.Errorf("256-byte context: got %v, want ErrContextTooLong", err)
	}
}

// TestKnownVector is a hardcoded regression vector. A single known-good
// (seed -> pubkey -> deterministic signature) triplet that pins correctness
// independently of the accumulated hash approach. If the underlying library
// ever changes output, this test catches it immediately.
func TestKnownVector(t *testing.T) {
	// Seed: first 32 bytes from SHAKE128 with zero-length input (same source
	// as the accumulated test's first iteration).
	seed, _ := hex.DecodeString(
		"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
	sk, err := NewPrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromSeed: %v", err)
	}

	// Verify public key size.
	pk := sk.PublicKey().Bytes()
	if len(pk) != PublicKeySize {
		t.Fatalf("pubkey size %d, want %d", len(pk), PublicKeySize)
	}

	// Sign empty message deterministically.
	sig, err := sk.SignDeterministic([]byte{})
	if err != nil {
		t.Fatalf("SignDeterministic: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("sig size %d, want %d", len(sig), SignatureSize)
	}

	// Verify the signature.
	if !sk.PublicKey().Verify([]byte{}, sig) {
		t.Fatal("known vector signature does not verify")
	}

	// Pin the first 16 bytes of the public key and signature as regression anchors.
	// These values were generated by this test on the first run and hardcoded.
	pkPrefix := hex.EncodeToString(pk[:16])
	sigPrefix := hex.EncodeToString(sig[:16])

	// Known-good values (generated from filippo.io/mldsa v0.0.0-20260215214346).
	const wantPKPrefix = "c8a4a98c396844bc7acd9bae9b70028d"
	const wantSigPrefix = "368042e47764f5d1a63c6c5078d1681a"

	if pkPrefix != wantPKPrefix {
		t.Errorf("pubkey prefix: got %s, want %s", pkPrefix, wantPKPrefix)
	}
	if sigPrefix != wantSigPrefix {
		t.Errorf("sig prefix: got %s, want %s", sigPrefix, wantSigPrefix)
	}
}

func TestNilReceivers(t *testing.T) {
	var nilPK *PublicKey
	var nilSK *PrivateKey

	if nilPK.Verify([]byte("x"), make([]byte, SignatureSize)) {
		t.Error("nil PublicKey.Verify returned true")
	}
	if nilPK.VerifyWithContext([]byte("x"), make([]byte, SignatureSize), "ctx") {
		t.Error("nil PublicKey.VerifyWithContext returned true")
	}
	if nilPK.Bytes() != nil {
		t.Error("nil PublicKey.Bytes returned non-nil")
	}
	if nilPK.Equal(nilPK) {
		t.Error("nil PublicKey.Equal(nil) returned true")
	}
	if nilSK.Equal(nilSK) {
		t.Error("nil PrivateKey.Equal(nil) returned true")
	}
	if nilSK.PublicKey() != nil {
		t.Error("nil PrivateKey.PublicKey returned non-nil")
	}
	_, err := nilSK.Sign([]byte("x"))
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.Sign: got %v, want ErrDestroyed", err)
	}
	_, err = nilSK.SignWithContext([]byte("x"), "ctx")
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.SignWithContext: got %v, want ErrDestroyed", err)
	}
	// Nil receiver with long context must return ErrDestroyed, not ErrContextTooLong.
	_, err = nilSK.SignWithContext([]byte("x"), string(make([]byte, 256)))
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.SignWithContext(long ctx): got %v, want ErrDestroyed", err)
	}
	_, err = nilSK.SignDeterministic([]byte("x"))
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.SignDeterministic: got %v, want ErrDestroyed", err)
	}
	_, err = nilSK.SignDeterministicWithContext([]byte("x"), "ctx")
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.SignDeterministicWithContext: got %v, want ErrDestroyed", err)
	}
	_, err = nilSK.Seed()
	if err != ErrDestroyed {
		t.Errorf("nil PrivateKey.Seed: got %v, want ErrDestroyed", err)
	}
}
