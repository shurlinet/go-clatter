package kem

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"testing/iotest"

	clatter "github.com/shurlinet/go-clatter"
)

// Production-entropy freshness tests (H-13).
//
// These exist as the ONLY detector for a refactor slip that routes
// production-mode encapsulation or key generation through fixed or derived
// entropy. Every other pin in the suite stays green under such a slip:
// vectors use testing-mode adapters, round-trips pass with any coins, and
// transcripts cannot pin nondeterminism. A production path that stops
// drawing fresh entropy ships green and leaks every session key, so these
// tests run the production constructors twice and assert the outputs
// differ. They were added BEFORE the CoinsEncapsulator refactor landed and
// must never be weakened.

// testProductionEncapsFreshness asserts two production-mode Encapsulate
// calls on the same public key produce different ciphertexts and shared
// secrets (fresh internal entropy per call).
func testProductionEncapsFreshness(t *testing.T, k clatter.KEM) {
	t.Helper()

	kp, err := k.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	ct1, ss1, err := k.Encapsulate(kp.Public, rand.Reader)
	if err != nil {
		t.Fatalf("encaps 1: %v", err)
	}
	ct2, ss2, err := k.Encapsulate(kp.Public, rand.Reader)
	if err != nil {
		t.Fatalf("encaps 2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("production encapsulation produced identical ciphertexts: fixed or derived entropy in the production path")
	}
	if bytes.Equal(ss1, ss2) {
		t.Fatal("production encapsulation produced identical shared secrets: fixed or derived entropy in the production path")
	}

	// The documented contract's other half: production encapsulation
	// IGNORES the caller's rng entirely. A dead/erroring reader and a nil
	// reader must both succeed - a refactor slip that routes production
	// coins through the caller's rng fails here, which the
	// different-outputs check above cannot catch.
	if _, _, err := k.Encapsulate(kp.Public, iotest.ErrReader(errors.New("rng must not be read"))); err != nil {
		t.Fatalf("production encapsulation must ignore the caller rng (erroring reader): %v", err)
	}
	if _, _, err := k.Encapsulate(kp.Public, nil); err != nil {
		t.Fatalf("production encapsulation must ignore the caller rng (nil reader): %v", err)
	}
}

// testProductionKeygenFreshness asserts two production keygen calls with
// crypto/rand produce different public keys.
func testProductionKeygenFreshness(t *testing.T, k clatter.KEM) {
	t.Helper()

	kp1, err := k.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("keygen 1: %v", err)
	}
	kp2, err := k.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("keygen 2: %v", err)
	}

	if bytes.Equal(kp1.Public, kp2.Public) {
		t.Fatal("production keygen produced identical public keys: fixed or derived entropy in the keygen path")
	}
}

func TestMlKem768_ProductionEncapsFreshness(t *testing.T) {
	testProductionEncapsFreshness(t, NewMlKem768())
}

func TestMlKem1024_ProductionEncapsFreshness(t *testing.T) {
	testProductionEncapsFreshness(t, NewMlKem1024())
}

func TestMlKem768_ProductionKeygenFreshness(t *testing.T) {
	testProductionKeygenFreshness(t, NewMlKem768())
}

func TestMlKem1024_ProductionKeygenFreshness(t *testing.T) {
	testProductionKeygenFreshness(t, NewMlKem1024())
}
