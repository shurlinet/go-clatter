package kem

import (
	"bytes"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

func testKEM(t *testing.T, k clatter.KEM, testing bool) {
	t.Helper()
	rng := clatter.NewDummyRng(0xdeadbeef)

	// Generate keypair
	kp, err := k.GenerateKeypair(rng)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.Public) != k.PubKeyLen() {
		t.Fatalf("public key length: expected %d, got %d", k.PubKeyLen(), len(kp.Public))
	}
	if len(kp.SecretSlice()) != k.SecretKeyLen() {
		t.Fatalf("secret key length: expected %d, got %d", k.SecretKeyLen(), len(kp.SecretSlice()))
	}

	// Encapsulate
	ct, ss, err := k.Encapsulate(kp.Public, rng)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != k.CiphertextLen() {
		t.Fatalf("ciphertext length: expected %d, got %d", k.CiphertextLen(), len(ct))
	}
	if len(ss) != k.SharedSecretLen() {
		t.Fatalf("shared secret length: expected %d, got %d", k.SharedSecretLen(), len(ss))
	}

	// Decapsulate
	ss2, err := k.Decapsulate(ct, kp.SecretSlice())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("shared secrets do not match")
	}
}

func TestMlKem768_Production(t *testing.T) {
	testKEM(t, NewMlKem768(), false)
}

func TestMlKem768_Testing(t *testing.T) {
	testKEM(t, NewMlKem768Testing(), true)
}

func TestMlKem1024_Production(t *testing.T) {
	testKEM(t, NewMlKem1024(), false)
}

func TestMlKem1024_Testing(t *testing.T) {
	testKEM(t, NewMlKem1024Testing(), true)
}

func TestMlKem768_Deterministic(t *testing.T) {
	k := NewMlKem768Testing()

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

func TestMlKem768_InvalidPubKey(t *testing.T) {
	k := NewMlKem768()
	rng := clatter.NewDummyRng(0)
	_, _, err := k.Encapsulate([]byte{1, 2, 3}, rng)
	if err == nil {
		t.Fatal("expected error on invalid public key")
	}
}

func TestMlKem768_InvalidSecretKey(t *testing.T) {
	k := NewMlKem768()
	_, err := k.Decapsulate(make([]byte, k.CiphertextLen()), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error on invalid secret key length")
	}
}

func TestMlKem768_Name(t *testing.T) {
	if NewMlKem768().Name() != "MLKEM768" {
		t.Fatal("wrong name")
	}
}

func TestMlKem1024_Name(t *testing.T) {
	if NewMlKem1024().Name() != "MLKEM1024" {
		t.Fatal("wrong name")
	}
}

// testImplicitRejection exercises the FIPS 203 implicit rejection path:
// decapsulating a TAMPERED ciphertext must succeed (no error - errors
// would be a decapsulation oracle) and return a pseudorandom shared
// secret different from the real one, deterministically derived from the
// secret key's rejection seed (same tampered ct -> same wrong ss).
// Wrong-LENGTH ciphertexts are the only structural error.
func testImplicitRejection(t *testing.T, k clatter.KEM) {
	t.Helper()
	rng := clatter.NewDummyRng(0xfeedface)

	kp, err := k.GenerateKeypair(rng)
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := k.Encapsulate(kp.Public, rng)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper one byte at the start, middle, and end of the ciphertext.
	for _, pos := range []int{0, len(ct) / 2, len(ct) - 1} {
		bad := append([]byte{}, ct...)
		bad[pos] ^= 0x01

		wrongSS, err := k.Decapsulate(bad, kp.SecretSlice())
		if err != nil {
			t.Fatalf("tamper at %d: Decapsulate errored (%v): implicit rejection must not create an error oracle", pos, err)
		}
		if len(wrongSS) != k.SharedSecretLen() {
			t.Fatalf("tamper at %d: shared secret length %d", pos, len(wrongSS))
		}
		if bytes.Equal(wrongSS, ss) {
			t.Fatalf("tamper at %d: tampered ciphertext produced the REAL shared secret", pos)
		}

		// Implicit rejection is deterministic per (sk, ct).
		again, err := k.Decapsulate(bad, kp.SecretSlice())
		if err != nil {
			t.Fatalf("tamper at %d: second decapsulation errored: %v", pos, err)
		}
		if !bytes.Equal(wrongSS, again) {
			t.Fatalf("tamper at %d: implicit rejection not deterministic", pos)
		}
	}

	// Wrong-length ciphertext is the only structural error path.
	for _, n := range []int{0, 1, k.CiphertextLen() - 1, k.CiphertextLen() + 1} {
		if _, err := k.Decapsulate(make([]byte, n), kp.SecretSlice()); err == nil {
			t.Errorf("ciphertext length %d accepted", n)
		}
	}
}

func TestMlKem768_ImplicitRejection(t *testing.T) {
	testImplicitRejection(t, NewMlKem768())
}

func TestMlKem768Testing_ImplicitRejection(t *testing.T) {
	testImplicitRejection(t, NewMlKem768Testing())
}

func TestMlKem1024_ImplicitRejection(t *testing.T) {
	testImplicitRejection(t, NewMlKem1024())
}
