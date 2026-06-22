//go:build hqc

package clatter_test

import (
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// HQC length-only pin. go-hqc's ParseEncapsulationKey performs no
// structural validation beyond length (any right-length byte string decodes
// into a vector via XOF expansion), so HQC's ValidatePublicKey is deliberately
// a length check. A malformed-but-right-length HQC remote static is therefore
// ACCEPTED at construction (it would fail later only via the AEAD tag, like
// any wrong key). This pins that documented limitation: when go-hqc adds a
// structural encapsulation-key check (and HQC ValidatePublicKey is upgraded to
// call it), this test will start failing and must be updated to expect a
// construction-time rejection. No t.Parallel(): AllowExperimental is a global.
func TestRemoteKEMKeyValidation_HQC_MalformedRemoteStatic_AcceptedAtConstruction_LengthOnlyPin(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	suite := clatter.CipherSuite{
		EKEM:         kem.NewHqc128(),
		SKEM:         kem.NewHqc128(),
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}
	iKP, err := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x01))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	bad := make([]byte, suite.SKEM.PubKeyLen()) // right length, all-zero: structurally meaningless
	hs, err := clatter.NewPqHandshake(clatter.PatternPqIK, true, suite,
		clatter.WithStaticKey(iKP), clatter.WithRemoteStatic(bad))
	if err != nil {
		t.Fatalf("HQC length-only pin: a right-length remote static was rejected at construction (%v) - has go-hqc added structural validation? upgrade Hqc*.ValidatePublicKey and this test", err)
	}
	if hs == nil {
		t.Fatal("expected a constructed handshake")
	}
	hs.Destroy()
}
