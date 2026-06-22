//go:build hqc

// HQC pre-set ephemeral tests for WithEphemeralKEMKey. These prove the
// dynamic secret-length validation (suite.EKEM.SecretKeyLen()) works for
// the 32-byte HQC seed form, distinct from ML-KEM's 64-byte seed.
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

// TestPqHandshake_WithEphemeralKEMKey_HQC_RoundTrip verifies a pre-set HQC
// ephemeral (32-byte seed) produces a working PQ handshake end-to-end, across
// all three HQC parameter sets.
func TestPqHandshake_WithEphemeralKEMKey_HQC_RoundTrip(t *testing.T) {
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

	for _, k := range hqcKEMs {
		suite := clatter.CipherSuite{
			EKEM:         k.ekem,
			SKEM:         k.skem,
			Cipher:       cipher.NewChaChaPoly(),
			Hash:         hash.NewSha256(),
			Experimental: true,
		}

		// HQC seed form is 32 bytes - confirm the KEM agrees before relying on it.
		if got := suite.EKEM.SecretKeyLen(); got != 32 {
			t.Fatalf("%s: expected 32-byte HQC seed, got %d", k.name, got)
		}

		ekp, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0xA1))
		if err != nil {
			t.Fatalf("%s: gen ephemeral: %v", k.name, err)
		}

		i, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite,
			clatter.WithEphemeralKEMKey(ekp))
		if err != nil {
			t.Fatalf("%s: initiator: %v", k.name, err)
		}
		r, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
		if err != nil {
			t.Fatalf("%s: responder: %v", k.name, err)
		}

		verifyHandshake(t, i, r, "pqNN_presetEph_"+k.name)
	}
}

// TestPqHandshake_WithEphemeralKEMKey_HQC_WrongSecretLen confirms a 64-byte
// (ML-KEM-shaped) secret is rejected for an HQC suite: the boundary is
// suite-specific, not a hardcoded constant.
func TestPqHandshake_WithEphemeralKEMKey_HQC_WrongSecretLen(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	suite := clatter.CipherSuite{
		EKEM:         kem.NewHqc128(),
		SKEM:         kem.NewHqc128(),
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}
	// Correct HQC pub length, but a 64-byte secret (ML-KEM seed size, not HQC's 32).
	badKP := clatter.NewKeyPair(make([]byte, suite.EKEM.PubKeyLen()), make([]byte, 64))
	_, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite,
		clatter.WithEphemeralKEMKey(badKP))
	if !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("want ErrInvalidKeyLength for 64-byte secret on HQC suite, got %v", err)
	}
}

// TestHybridHandshake_WithEphemeralKEMKey_HQC_RoundTrip verifies a pre-set
// HQC KEM ephemeral works in a Hybrid handshake (X25519 DH-e + HQC KEM-e).
func TestHybridHandshake_WithEphemeralKEMKey_HQC_RoundTrip(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	suite := clatter.CipherSuite{
		DH:           dh.NewX25519(),
		EKEM:         kem.NewHqc128(),
		SKEM:         kem.NewHqc128(),
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}

	dhE, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xB1))
	kemE, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0xB2))
	if err != nil {
		t.Fatalf("gen KEM ephemeral: %v", err)
	}

	i, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite,
		clatter.WithEphemeralKey(dhE),
		clatter.WithEphemeralKEMKey(kemE))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	verifyHandshake(t, i, r, "hybridNN_presetEph_HQC128")
}
