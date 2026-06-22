//go:build hqc

package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// TestKeyPairConsistency_HQC_LocalMismatchRejected proves the consistency check
// works for the HQC seed form (32-byte secret) on both KEM local slots, under
// the experimental gate. flipPublicByte is defined in the always-compiled
// handshake_keypair_consistency_test.go (same package).
func TestKeyPairConsistency_HQC_LocalMismatchRejected(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	suite := clatter.CipherSuite{
		EKEM:         kem.NewHqc128(),
		SKEM:         kem.NewHqc128(),
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}

	staticKP, err := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0xC1))
	if err != nil {
		t.Fatalf("gen HQC static: %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithStaticKey(staticKP)); err != nil {
		t.Fatalf("valid HQC static must construct: %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithStaticKey(flipPublicByte(staticKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("HQC static mismatch: want ErrKEMInvalidKey, got %v", err)
	}

	ephKP, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0xC2))
	if err != nil {
		t.Fatalf("gen HQC ephemeral: %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithEphemeralKEMKey(flipPublicByte(ephKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("HQC ephemeral mismatch: want ErrKEMInvalidKey, got %v", err)
	}
}
