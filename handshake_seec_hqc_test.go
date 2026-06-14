//go:build hqc

package clatter_test

import (
	"crypto/rand"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// HQC + SEEC integration under the hqc build tag. The three-layer
// experimental defense (build tag, AllowExperimental, Experimental suite
// flag) composes with SEEC: a gated suite constructs and completes a
// SEEC-hedged handshake when the gate is open, and the constructor
// refuses when it is closed.
//
// NO t.Parallel() in any HQC test (AllowExperimental is a global atomic).

func hqcSeecSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		EKEM: kem.NewHqc128(), SKEM: kem.NewHqc128(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		Experimental: true,
	}
}

func TestSEEC_HQCHandshake(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	suite := hqcSeecSuite()
	s, err := clatter.NewSEECPRF(hash.NewSha256(), seecTestSecret())
	if err != nil {
		t.Fatal(err)
	}

	aS, err := suite.SKEM.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bS, err := suite.SKEM.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	a, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
		clatter.WithStaticKey(aS), clatter.WithSEEC(s))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	b, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite,
		clatter.WithStaticKey(bS), clatter.WithSEEC(s))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	_, _, _ = runHandshakeRecorded(t, a, b)
	completeAndVerifyTransport(t, a, b)
}

func TestSEEC_HQCGateClosedRejected(t *testing.T) {
	// Gate closed: the experimental-suite check fires before anything
	// SEEC-related, and SEEC must not provide a bypass.
	clatter.AllowExperimental.Store(false)

	s, err := clatter.NewSEECPRF(hash.NewSha256(), seecTestSecret())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, hqcSeecSuite(), clatter.WithSEEC(s)); err == nil {
		t.Fatal("experimental suite with gate closed must be rejected, SEEC or not")
	}
}
