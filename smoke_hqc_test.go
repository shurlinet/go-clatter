//go:build hqc

// HQC smoke tests for PQ, Hybrid, DualLayer, and mixed KEM configurations.
// NO t.Parallel() in any test. AllowExperimental is a global atomic.Bool.

package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// Smoke test all 3 HQC param sets in PQ mode.
func TestSmokeHqcPqHandshakes(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	hqcKEMs := []struct {
		ekem clatter.KEM
		skem clatter.KEM
		name string
	}{
		{kem.NewHqc128(), kem.NewHqc128(), "HQC128"},
		{kem.NewHqc192(), kem.NewHqc192(), "HQC192"},
		{kem.NewHqc256(), kem.NewHqc256(), "HQC256"},
	}

	count := 0
	for _, k := range hqcKEMs {
		suite := clatter.CipherSuite{
			EKEM:         k.ekem,
			SKEM:         k.skem,
			Cipher:       cipher.NewChaChaPoly(),
			Hash:         hash.NewSha256(),
			Experimental: true,
		}
		label := "pqXN_" + k.name

		aliceS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(10))
		bobS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(20))

		alice, err := clatter.NewPqHandshake(clatter.PatternPqXN, true, suite,
			clatter.WithStaticKey(aliceS),
			clatter.WithRemoteStatic(bobS.Public),
		)
		if err != nil {
			t.Fatalf("%s: alice: %v", label, err)
		}

		bob, err := clatter.NewPqHandshake(clatter.PatternPqXN, false, suite,
			clatter.WithStaticKey(bobS),
			clatter.WithRemoteStatic(aliceS.Public),
		)
		if err != nil {
			t.Fatalf("%s: bob: %v", label, err)
		}

		verifyHandshake(t, alice, bob, label)
		count++
	}

	t.Logf("HQC PQ smoke: %d handshakes (3 param sets)", count)
}

// DualLayer smoke with HQC-128 as inner PQ layer.
func TestSmokeHqcDualLayer(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	x := dh.NewX25519()
	hqc128 := kem.NewHqc128()

	nqSuite := clatter.CipherSuite{DH: x, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqSuite := clatter.CipherSuite{
		EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}

	alicePqS, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(200))
	bobPqS, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(201))

	aliceNQ, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	if err != nil {
		t.Fatal(err)
	}
	bobNQ, err := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)
	if err != nil {
		t.Fatal(err)
	}

	alicePQ, err := clatter.NewPqHandshake(clatter.PatternPqXN, true, pqSuite,
		clatter.WithStaticKey(alicePqS),
		clatter.WithRemoteStatic(bobPqS.Public),
	)
	if err != nil {
		t.Fatal(err)
	}
	bobPQ, err := clatter.NewPqHandshake(clatter.PatternPqXN, false, pqSuite,
		clatter.WithStaticKey(bobPqS),
		clatter.WithRemoteStatic(alicePqS.Public),
	)
	if err != nil {
		t.Fatal(err)
	}

	aliceDL, err := clatter.NewDualLayerHandshake(aliceNQ, alicePQ, 65535)
	if err != nil {
		t.Fatal(err)
	}
	bobDL, err := clatter.NewDualLayerHandshake(bobNQ, bobPQ, 65535)
	if err != nil {
		t.Fatal(err)
	}

	verifyHandshake(t, aliceDL, bobDL, "DL_NN+pqXN_HQC128")
}

// Hybrid smoke with HQC-128
func TestSmokeHqcHybridHandshake(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	x := dh.NewX25519()
	hqc128 := kem.NewHqc128()

	suite := clatter.CipherSuite{
		DH: x, EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}

	aliceDH, _ := x.GenerateKeypair(clatter.NewDummyRng(30))
	bobDH, _ := x.GenerateKeypair(clatter.NewDummyRng(40))
	aliceKEM, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(50))
	bobKEM, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(60))

	alice, err := clatter.NewHybridHandshake(clatter.PatternHybridXN, true, suite,
		clatter.WithStaticKey(aliceDH),
		clatter.WithRemoteStatic(bobDH.Public),
		clatter.WithStaticKEMKey(aliceKEM),
		clatter.WithRemoteStaticKEMKey(bobKEM.Public),
	)
	if err != nil {
		t.Fatal(err)
	}

	bob, err := clatter.NewHybridHandshake(clatter.PatternHybridXN, false, suite,
		clatter.WithStaticKey(bobDH),
		clatter.WithRemoteStatic(aliceDH.Public),
		clatter.WithStaticKEMKey(bobKEM),
		clatter.WithRemoteStaticKEMKey(aliceKEM.Public),
	)
	if err != nil {
		t.Fatal(err)
	}

	verifyHandshake(t, alice, bob, "Hybrid_XN_HQC128")
}

// Mixed KEM smoke: EKEM=MLKEM768, SKEM=HQC128.
func TestSmokeHqcMixedKEM(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	mlkem768 := kem.NewMlKem768()
	hqc128 := kem.NewHqc128()

	suite := clatter.CipherSuite{
		EKEM:         mlkem768,
		SKEM:         hqc128,
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}

	// Static keys are SKEM type (HQC128)
	aliceS, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(10))
	bobS, _ := hqc128.GenerateKeypair(clatter.NewDummyRng(20))

	alice, err := clatter.NewPqHandshake(clatter.PatternPqXN, true, suite,
		clatter.WithStaticKey(aliceS),
		clatter.WithRemoteStatic(bobS.Public),
	)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}

	bob, err := clatter.NewPqHandshake(clatter.PatternPqXN, false, suite,
		clatter.WithStaticKey(bobS),
		clatter.WithRemoteStatic(aliceS.Public),
	)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	verifyHandshake(t, alice, bob, "Mixed_MLKEM768+HQC128")
}

// Negative test: mismatched KEM param sets must fail handshake.
func TestSmokeHqcMismatchedKEMFails(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	hqc128 := kem.NewHqc128()
	hqc192 := kem.NewHqc192()

	suiteAlice := clatter.CipherSuite{
		EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}
	// Bob uses HQC-192 - different param set, must fail
	suiteBob := clatter.CipherSuite{
		EKEM: hqc192, SKEM: hqc192,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}

	alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suiteAlice)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suiteBob)
	if err != nil {
		t.Fatal(err)
	}

	aliceBuf := make([]byte, 65535)
	bobBuf := make([]byte, 65535)

	// Alice writes first message (E token with HQC-128 EKEM key)
	n, err := alice.WriteMessage(nil, aliceBuf)
	if err != nil {
		t.Fatalf("alice write: %v", err)
	}

	// Bob tries to read with HQC-192 - must fail (wrong PK size or decrypt)
	_, err = bob.ReadMessage(aliceBuf[:n], bobBuf)
	if err == nil {
		t.Fatal("expected handshake to fail with mismatched KEMs")
	}
}

// Constructor-level experimental gate test (belt)
func TestSmokeHqcConstructorGate(t *testing.T) {
	clatter.AllowExperimental.Store(false) // explicitly disabled
	defer clatter.AllowExperimental.Store(false)

	hqc128 := kem.NewHqc128()
	suite := clatter.CipherSuite{
		EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true, // suite says experimental
	}

	_, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
		t.Fatalf("PQ constructor should reject experimental suite, got: %v", err)
	}

	x := dh.NewX25519()
	hybridSuite := clatter.CipherSuite{
		DH: x, EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}
	_, err = clatter.NewHybridHandshake(clatter.PatternHybridNN, true, hybridSuite)
	if !errors.Is(err, clatter.ErrExperimentalNotAllowed) {
		t.Fatalf("Hybrid constructor should reject experimental suite, got: %v", err)
	}
}

// Mid-handshake toggle: disable AllowExperimental during handshake,
// next KEM operation fails, handshake enters error state
func TestSmokeHqcMidHandshakeToggle(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	hqc128 := kem.NewHqc128()
	suite := clatter.CipherSuite{
		EKEM: hqc128, SKEM: hqc128,
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}

	alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}

	aliceBuf := make([]byte, 65535)
	bobBuf := make([]byte, 65535)

	// Alice writes first message successfully
	n, err := alice.WriteMessage(nil, aliceBuf)
	if err != nil {
		t.Fatalf("alice write 1: %v", err)
	}

	// Bob reads successfully
	_, err = bob.ReadMessage(aliceBuf[:n], bobBuf)
	if err != nil {
		t.Fatalf("bob read 1: %v", err)
	}

	// Disable experimental flag mid-handshake
	clatter.AllowExperimental.Store(false)

	// Bob's next write should fail because KEM-level check fires
	_, err = bob.WriteMessage(nil, bobBuf)
	if err == nil {
		t.Fatal("expected error after disabling AllowExperimental mid-handshake")
	}
}

// Fuzz target for HQC PQ handshake.
func FuzzHqcPqHandshake(f *testing.F) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	f.Add([]byte("hello from the other side"))
	f.Add([]byte{})
	f.Add(make([]byte, 4096))

	hqc128 := kem.NewHqc128()

	f.Fuzz(func(t *testing.T, payload []byte) {
		clatter.AllowExperimental.Store(true)
		defer clatter.AllowExperimental.Store(false)

		if len(payload) > 4096 {
			payload = payload[:4096]
		}

		suite := clatter.CipherSuite{
			EKEM: hqc128, SKEM: hqc128,
			Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
			Experimental: true,
		}

		alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
		if err != nil {
			t.Fatal(err)
		}
		bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
		if err != nil {
			t.Fatal(err)
		}

		aliceBuf := make([]byte, 65535)
		bobBuf := make([]byte, 65535)

		// Handshake with empty payloads
		for !alice.IsFinished() && !bob.IsFinished() {
			if alice.IsWriteTurn() {
				n, err := alice.WriteMessage(nil, aliceBuf)
				if err != nil {
					t.Fatal(err)
				}
				_, err = bob.ReadMessage(aliceBuf[:n], bobBuf)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				n, err := bob.WriteMessage(nil, bobBuf)
				if err != nil {
					t.Fatal(err)
				}
				_, err = alice.ReadMessage(bobBuf[:n], aliceBuf)
				if err != nil {
					t.Fatal(err)
				}
			}
		}

		aliceT, err := alice.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		defer aliceT.Destroy()

		bobT, err := bob.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		defer bobT.Destroy()

		// Send fuzzed payload
		n, err := aliceT.Send(payload, aliceBuf)
		if err != nil {
			t.Fatal(err)
		}
		n, err = bobT.Receive(aliceBuf[:n], bobBuf)
		if err != nil {
			t.Fatal(err)
		}
		if len(payload) > 0 && string(bobBuf[:n]) != string(payload) {
			t.Fatal("payload mismatch")
		}
	})
}
