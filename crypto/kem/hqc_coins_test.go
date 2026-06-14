//go:build hqc

package kem

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// HQC CoinsEncapsulator pins: equivalence, length validation, and the
// experimental gate on the coins entrance (the gate applies to EVERY HQC
// entry point - a coins-driven path that bypassed it would defeat the
// three-layer experimental defense).
//
// NO t.Parallel() in any HQC test (AllowExperimental is a global atomic).

func TestHqc128_CoinsEquivalence(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsEquivalence(t, NewHqc128(), NewHqc128Testing())
}

func TestHqc192_CoinsEquivalence(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsEquivalence(t, NewHqc192(), NewHqc192Testing())
}

func TestHqc256_CoinsEquivalence(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsEquivalence(t, NewHqc256(), NewHqc256Testing())
}

func TestHqc128_CoinsLengthValidation(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsLengthValidation(t, NewHqc128())
}

func TestHqc192_CoinsLengthValidation(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsLengthValidation(t, NewHqc192())
}

func TestHqc256_CoinsLengthValidation(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testCoinsLengthValidation(t, NewHqc256())
}

// TestHqc_CoinsExperimentalGate asserts EncapsulateWithCoins refuses to
// run when AllowExperimental is off, for all three parameter sets.
func TestHqc_CoinsExperimentalGate(t *testing.T) {
	// Generate keys with the gate ON, then flip it OFF for the assertion.
	clatter.AllowExperimental.Store(true)
	kems := []clatter.CoinsEncapsulator{NewHqc128(), NewHqc192(), NewHqc256()}
	pks := make([][]byte, len(kems))
	for i, k := range kems {
		kp, err := k.GenerateKeypair(clatter.NewDummyRng(uint64(i + 1)))
		if err != nil {
			t.Fatalf("keygen %s: %v", k.Name(), err)
		}
		pks[i] = kp.Public
	}
	clatter.AllowExperimental.Store(false)

	for i, k := range kems {
		ct, ss, err := k.EncapsulateWithCoins(pks[i], make([]byte, k.EncapsCoinsLen()))
		if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
			t.Fatalf("%s EncapsulateWithCoins with gate off must return ErrExperimentalNotAllowed, got: %v", k.Name(), err)
		}
		if ct != nil || ss != nil {
			t.Fatalf("%s returned output alongside the gate error", k.Name())
		}
	}
}
