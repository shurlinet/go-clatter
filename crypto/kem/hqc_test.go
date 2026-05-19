//go:build hqc

package kem

import (
	"bytes"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-hqc"
)

// NO t.Parallel() in any HQC test. AllowExperimental is a global
// atomic.Bool; parallel tests would race on it. Sequential execution
// guarantees defer cleanup between tests.

func TestHqc128_Production(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc128(), false)
}

func TestHqc128_Testing(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc128Testing(), true)
}

func TestHqc192_Production(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc192(), false)
}

func TestHqc192_Testing(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc192Testing(), true)
}

func TestHqc256_Production(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc256(), false)
}

func TestHqc256_Testing(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKEM(t, NewHqc256Testing(), true)
}

func TestHqc128_Deterministic(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	k := NewHqc128Testing()

	rng1 := clatter.NewDummyRng(42)
	kp1, _ := k.GenerateKeypair(rng1)
	ct1, ss1, _ := k.Encapsulate(kp1.Public, rng1)

	rng2 := clatter.NewDummyRng(42)
	kp2, _ := k.GenerateKeypair(rng2)
	ct2, ss2, _ := k.Encapsulate(kp2.Public, rng2)

	if !bytes.Equal(kp1.Public, kp2.Public) {
		t.Fatal("deterministic keygen should produce same public key")
	}
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("deterministic encapsulate should produce same ciphertext")
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("deterministic encapsulate should produce same shared secret")
	}
}

func TestHqc128_InvalidPubKey(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	k := NewHqc128()
	rng := clatter.NewDummyRng(0)
	_, _, err := k.Encapsulate([]byte{1, 2, 3}, rng)
	if err == nil {
		t.Fatal("expected error on invalid public key")
	}
	if !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("expected ErrKEMInvalidKey, got: %v", err)
	}
}

func TestHqc128_InvalidSecretKey(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	k := NewHqc128()
	_, err := k.Decapsulate(make([]byte, k.CiphertextLen()), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error on invalid secret key length")
	}
	if !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("expected ErrKEMInvalidKey, got: %v", err)
	}
}

// Verify names are exactly "HQC128", "HQC192", "HQC256" (no hyphen).
func TestHqcNames(t *testing.T) {
	tests := []struct {
		name string
		kem  clatter.KEM
	}{
		{"HQC128", NewHqc128()},
		{"HQC192", NewHqc192()},
		{"HQC256", NewHqc256()},
	}
	for _, tt := range tests {
		if tt.kem.Name() != tt.name {
			t.Fatalf("expected %q, got %q", tt.name, tt.kem.Name())
		}
	}
}

// Verify size constants match go-hqc constants.
func TestHqcSizeConstants(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	tests := []struct {
		name      string
		kem       clatter.KEM
		pubKey    int
		secretKey int
		ct        int
		ss        int
	}{
		{"HQC128", NewHqc128(), hqc.PublicKeySize128, hqc.SeedSize128, hqc.CiphertextSize128, hqc.SharedSecretSize128},
		{"HQC192", NewHqc192(), hqc.PublicKeySize192, hqc.SeedSize192, hqc.CiphertextSize192, hqc.SharedSecretSize192},
		{"HQC256", NewHqc256(), hqc.PublicKeySize256, hqc.SeedSize256, hqc.CiphertextSize256, hqc.SharedSecretSize256},
	}
	for _, tt := range tests {
		if tt.kem.PubKeyLen() != tt.pubKey {
			t.Fatalf("%s: PubKeyLen: expected %d, got %d", tt.name, tt.pubKey, tt.kem.PubKeyLen())
		}
		if tt.kem.SecretKeyLen() != tt.secretKey {
			t.Fatalf("%s: SecretKeyLen: expected %d, got %d", tt.name, tt.secretKey, tt.kem.SecretKeyLen())
		}
		if tt.kem.CiphertextLen() != tt.ct {
			t.Fatalf("%s: CiphertextLen: expected %d, got %d", tt.name, tt.ct, tt.kem.CiphertextLen())
		}
		if tt.kem.SharedSecretLen() != tt.ss {
			t.Fatalf("%s: SharedSecretLen: expected %d, got %d", tt.name, tt.ss, tt.kem.SharedSecretLen())
		}
	}
}

// AllowExperimental gate at KEM level (suspenders layer).
func TestHqc_ExperimentalGate_GenerateKeypair(t *testing.T) {
	clatter.AllowExperimental.Store(false) // explicitly false
	defer clatter.AllowExperimental.Store(false)

	rng := clatter.NewDummyRng(0)
	for _, k := range []clatter.KEM{NewHqc128(), NewHqc192(), NewHqc256()} {
		_, err := k.GenerateKeypair(rng)
		if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
			t.Fatalf("%s: GenerateKeypair should fail with ErrExperimentalNotAllowed, got: %v", k.Name(), err)
		}
	}
}

func TestHqc_ExperimentalGate_Encapsulate(t *testing.T) {
	// First generate a valid public key with experimental enabled
	clatter.AllowExperimental.Store(true)
	rng := clatter.NewDummyRng(99)
	k128 := NewHqc128()
	kp, err := k128.GenerateKeypair(rng)
	if err != nil {
		t.Fatal(err)
	}

	// Now disable and try to encapsulate
	clatter.AllowExperimental.Store(false)
	defer clatter.AllowExperimental.Store(false)

	_, _, err = k128.Encapsulate(kp.Public, rng)
	if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
		t.Fatalf("Encapsulate should fail with ErrExperimentalNotAllowed, got: %v", err)
	}
}

func TestHqc_ExperimentalGate_Decapsulate(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	rng := clatter.NewDummyRng(77)
	k128 := NewHqc128()
	kp, err := k128.GenerateKeypair(rng)
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := k128.Encapsulate(kp.Public, rng)
	if err != nil {
		t.Fatal(err)
	}

	// Disable and try to decapsulate
	clatter.AllowExperimental.Store(false)
	defer clatter.AllowExperimental.Store(false)

	_, err = k128.Decapsulate(ct, kp.SecretSlice())
	if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
		t.Fatalf("Decapsulate should fail with ErrExperimentalNotAllowed, got: %v", err)
	}
}
