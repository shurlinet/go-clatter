package kem

import (
	"bytes"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// CoinsEncapsulator equivalence pins: EncapsulateWithCoins must produce
// byte-identical output to the testing-mode Encapsulate fed the same coins
// through its rng. The two entrances share one private path; these pins
// keep that true if the paths ever diverge.

// testCoinsEquivalence drives prod.EncapsulateWithCoins and
// testing.Encapsulate with identical coins and asserts identical output.
func testCoinsEquivalence(t *testing.T, prod clatter.CoinsEncapsulator, testing clatter.KEM) {
	t.Helper()

	kp, err := prod.GenerateKeypair(clatter.NewDummyRng(0xdeadbeef))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	coins := patternedBytes(prod.EncapsCoinsLen())

	ct1, ss1, err := prod.EncapsulateWithCoins(kp.Public, coins)
	if err != nil {
		t.Fatalf("EncapsulateWithCoins: %v", err)
	}
	ct2, ss2, err := testing.Encapsulate(kp.Public, bytes.NewReader(coins))
	if err != nil {
		t.Fatalf("testing Encapsulate: %v", err)
	}

	if !bytes.Equal(ct1, ct2) {
		t.Fatal("EncapsulateWithCoins ciphertext differs from testing-mode Encapsulate with same coins")
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("EncapsulateWithCoins shared secret differs from testing-mode Encapsulate with same coins")
	}

	// Decapsulation round-trip closes the loop: the coins-driven
	// ciphertext recovers the same shared secret.
	ss3, err := prod.Decapsulate(ct1, kp.SecretSlice())
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ss1, ss3) {
		t.Fatal("decapsulated shared secret differs from encapsulated one")
	}

	// Implementation-INDEPENDENT order pin: the interface contract (and
	// wire safety) requires ct first, ss second. The equivalence check
	// above is blind to a swap that affects both code paths identically
	// (they share one private function), so assert the geometry directly:
	// a ciphertext-length ct and a 32-byte ss are never interchangeable,
	// and a swap would put the shared secret on the wire.
	if len(ct1) != prod.CiphertextLen() {
		t.Fatalf("ciphertext length %d, want %d (ct/ss return order swapped?)", len(ct1), prod.CiphertextLen())
	}
	if len(ss1) != prod.SharedSecretLen() {
		t.Fatalf("shared secret length %d, want %d (ct/ss return order swapped?)", len(ss1), prod.SharedSecretLen())
	}
	if bytes.Equal(ct1, ss1) {
		t.Fatal("ciphertext equals shared secret: return order is unverifiable")
	}

	// Determinism pin: the contract promises the same (pk, coins) pair
	// always yields the same (ct, ss). Call twice and compare directly
	// rather than inferring it from two implementations agreeing once.
	ct4, ss4, err := prod.EncapsulateWithCoins(kp.Public, coins)
	if err != nil {
		t.Fatalf("EncapsulateWithCoins (second call): %v", err)
	}
	if !bytes.Equal(ct1, ct4) || !bytes.Equal(ss1, ss4) {
		t.Fatal("EncapsulateWithCoins not deterministic in (pk, coins)")
	}
}

// testCoinsLengthValidation asserts every wrong coin length is rejected
// with ErrKEM and nil outputs (the house exact-length reject pattern).
func testCoinsLengthValidation(t *testing.T, prod clatter.CoinsEncapsulator) {
	t.Helper()

	kp, err := prod.GenerateKeypair(clatter.NewDummyRng(0xdeadbeef))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	want := prod.EncapsCoinsLen()
	for _, n := range []int{0, 1, want - 1, want + 1, 2 * want} {
		if n < 0 {
			continue
		}
		ct, ss, err := prod.EncapsulateWithCoins(kp.Public, make([]byte, n))
		if err == nil {
			t.Fatalf("EncapsulateWithCoins accepted %d-byte coins, want exactly %d", n, want)
		}
		if !errors.Is(err, clatter.ErrKEM) {
			t.Fatalf("wrong-length coins error must wrap ErrKEM, got: %v", err)
		}
		if ct != nil || ss != nil {
			t.Fatal("EncapsulateWithCoins returned output alongside an error")
		}
	}

	// nil coins (length 0) covered above via n=0; nil public key must
	// also fail closed, not panic.
	if _, _, err := prod.EncapsulateWithCoins(nil, make([]byte, want)); err == nil {
		t.Fatal("EncapsulateWithCoins accepted a nil public key")
	}
}

func TestMlKem768_CoinsEquivalence(t *testing.T) {
	testCoinsEquivalence(t, NewMlKem768(), NewMlKem768Testing())
}

func TestMlKem1024_CoinsEquivalence(t *testing.T) {
	testCoinsEquivalence(t, NewMlKem1024(), NewMlKem1024Testing())
}

func TestMlKem768_CoinsLengthValidation(t *testing.T) {
	testCoinsLengthValidation(t, NewMlKem768())
}

func TestMlKem1024_CoinsLengthValidation(t *testing.T) {
	testCoinsLengthValidation(t, NewMlKem1024())
}
