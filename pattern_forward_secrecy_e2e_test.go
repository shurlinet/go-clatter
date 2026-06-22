package clatter_test

import (
	"bytes"
	crand "crypto/rand"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// End-to-end proof that the forward-secrecy construction rules do not regress a
// real handshake: a representative KEM pattern (pqNK - whose initiator seals a
// static-KEM at time zero) and a representative hybrid pattern (hybridKK - whose
// static-KEM seals follow an ephemeral-KEM) both still complete a full handshake
// and exchange transport traffic. Construction-time reject-only validation must
// leave every accepted pattern byte-for-byte unchanged on the wire.

func pqProdSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func hybridProdSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// exchange drives a two-message handshake (initiator sends msg0, responder sends
// msg1) to completion through the public Handshaker interface and asserts a
// transport round-trip in both directions.
func exchange(t *testing.T, i, r clatter.Handshaker) {
	t.Helper()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	if _, err = r.ReadMessage(buf[:n], payloadBuf); err != nil {
		t.Fatalf("msg0 read: %v", err)
	}

	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	if _, err = i.ReadMessage(buf[:n], payloadBuf); err != nil {
		t.Fatalf("msg1 read: %v", err)
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("handshake should be finished after two messages")
	}

	tsI, err := i.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	defer tsI.Destroy()
	tsR, err := r.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}
	defer tsR.Destroy()

	payload := []byte("forward-secrecy e2e payload")
	n, err = tsI.Send(payload, buf)
	if err != nil {
		t.Fatalf("transport send: %v", err)
	}
	pn, err := tsR.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("transport receive: %v", err)
	}
	if !bytes.Equal(payloadBuf[:pn], payload) {
		t.Fatalf("transport round-trip mismatch: got %q want %q", payloadBuf[:pn], payload)
	}
}

func TestForwardSecrecyE2E_PqNK(t *testing.T) {
	suite := pqProdSuite()
	rKEM, err := suite.SKEM.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatalf("responder keygen: %v", err)
	}

	i, err := clatter.NewPqHandshake(clatter.PatternPqNK, true, suite,
		clatter.WithRemoteStatic(rKEM.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()
	r, err := clatter.NewPqHandshake(clatter.PatternPqNK, false, suite,
		clatter.WithStaticKey(rKEM))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	exchange(t, i, r)
}

func TestForwardSecrecyE2E_HybridKK(t *testing.T) {
	suite := hybridProdSuite()
	iDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	rDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	iKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	rKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	// hybridKK: both parties pre-share both statics (DH + KEM).
	i, err := clatter.NewHybridHandshake(clatter.PatternHybridKK, true, suite,
		clatter.WithStaticKey(iDH),
		clatter.WithRemoteStatic(rDH.Public),
		clatter.WithStaticKEMKey(iKEM),
		clatter.WithRemoteStaticKEMKey(rKEM.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()
	r, err := clatter.NewHybridHandshake(clatter.PatternHybridKK, false, suite,
		clatter.WithStaticKey(rDH),
		clatter.WithRemoteStatic(iDH.Public),
		clatter.WithStaticKEMKey(rKEM),
		clatter.WithRemoteStaticKEMKey(iKEM.Public))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	exchange(t, i, r)
}
