package slhdsa_test

import (
	"crypto"
	"testing"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

// FuzzSignAndVerify tests the sign-verify round-trip with arbitrary messages.
// Uses SHA2-128f (fastest param set, ~10ms per sign).
//
// Invariants per iteration:
// 1. Sign(msg) succeeds
// 2. Verify(msg, sig) returns true
// 3. Verify(corrupted_sig) returns false
// 4. Verify(wrong_msg, sig) returns false
//
// The key is generated once and shared across parallel fuzz workers.
// This is safe because Sign acquires a shared read lock (RWMutex).
func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte("hello SLH-DSA"))
	f.Add(make([]byte, 255))
	f.Add(make([]byte, 1024))

	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		f.Fatal(err)
	}
	pub := priv.PublicKey()

	f.Fuzz(func(t *testing.T, msg []byte) {
		sig, err := priv.SignMessage(msg)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		if !pub.Verify(msg, sig) {
			t.Fatal("valid signature failed verification")
		}

		// Corrupt first byte of signature
		if len(sig) > 0 {
			corrupted := make([]byte, len(sig))
			copy(corrupted, sig)
			corrupted[0] ^= 0x01
			if pub.Verify(msg, corrupted) {
				t.Fatal("corrupted signature passed verification")
			}
		}

		// Wrong message
		wrongMsg := append([]byte{}, msg...)
		wrongMsg = append(wrongMsg, 0xFF)
		if pub.Verify(wrongMsg, sig) {
			t.Fatal("wrong message passed verification")
		}

		// Also test via crypto.Signer interface
		var signer crypto.Signer = priv
		sigBytes, err := signer.Sign(nil, msg, nil)
		if err != nil {
			t.Fatalf("crypto.Signer.Sign: %v", err)
		}
		if !pub.Verify(msg, sigBytes) {
			t.Fatal("crypto.Signer signature failed verification")
		}
	})
}

// FuzzLoaders tests that random bytes never cause panics in key/signature loading.
func FuzzLoaders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 0})
	f.Add(make([]byte, 34))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParsePublicKey must not panic on any input
		_, _ = slhdsa.ParsePublicKey(data)

		// NewPrivateKeyFromBytes must not panic for any param set
		for ps := slhdsa.ParamSet(0); ps <= slhdsa.ParamSet(17); ps++ {
			_, _ = slhdsa.NewPrivateKeyFromBytes(ps, data)
		}

		// NewPublicKey must not panic for any param set
		for ps := slhdsa.ParamSet(0); ps <= slhdsa.ParamSet(17); ps++ {
			_, _ = slhdsa.NewPublicKey(ps, data)
		}
	})
}
