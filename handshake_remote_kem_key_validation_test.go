package clatter_test

import (
	crand "crypto/rand"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// Structural validation of remote KEM encapsulation keys (FIPS 203
// Section 7.2) at the point they are supplied or received, instead of
// deferring the only structural parse to the first encapsulation
// mid-handshake. Three sites: pre-set remote static (construction),
// wire-learned remote static (readTokenS), wire-learned remote ephemeral
// (readTokenE). ML-KEM rejects a malformed-but-right-length key; HQC is
// length-only (see handshake_remote_kem_key_validation_hqc_test.go); DH is untouched.

// allFF returns an n-byte all-0xFF slice: a right-length but structurally
// malformed ML-KEM encapsulation key (fails the FIPS 203 modulus check).
func allFF(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xFF
	}
	return b
}

// remoteKeyValidationObserver records whether a message event and/or an error event
// were delivered, and the error.
type remoteKeyValidationObserver struct {
	gotMessage bool
	gotError   bool
	err        error
}

func (o *remoteKeyValidationObserver) OnMessage(clatter.HandshakeEvent) { o.gotMessage = true }
func (o *remoteKeyValidationObserver) OnError(e clatter.HandshakeErrorEvent) {
	o.gotError = true
	o.err = e.Err
}

// TestRemoteKEMKeyValidation_Pq_MalformedRemoteStatic_RejectedAtConstruction: a pre-set remote
// static that is the right length but malformed is rejected at construction
// with ErrKEMInvalidKey, not mid-handshake.
func TestRemoteKEMKeyValidation_Pq_MalformedRemoteStatic_RejectedAtConstruction(t *testing.T) {
	suite := pqSuiteProd()
	iKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x01))

	hs, err := clatter.NewPqHandshake(clatter.PatternPqIK, true, suite,
		clatter.WithStaticKey(iKP),
		clatter.WithRemoteStatic(allFF(suite.SKEM.PubKeyLen())))
	if !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey at construction, got %v", err)
	}
	if hs != nil {
		t.Fatal("constructor must return nil handshake on a rejected remote static")
	}
}

// TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteStaticKEM_RejectedAtConstruction: same for
// the Hybrid remote KEM static (the DH remote static is unaffected).
func TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteStaticKEM_RejectedAtConstruction(t *testing.T) {
	suite := hybridSuiteProd()
	iDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	rDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	iKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	hs, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, true, suite,
		clatter.WithStaticKey(iDH),
		clatter.WithRemoteStatic(rDH.Public),
		clatter.WithStaticKEMKey(iKEM),
		clatter.WithRemoteStaticKEMKey(allFF(suite.SKEM.PubKeyLen())))
	if !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey at construction, got %v", err)
	}
	if hs != nil {
		t.Fatal("constructor must return nil handshake on a rejected remote KEM static")
	}
}

// TestRemoteKEMKeyValidation_Pq_MalformedRemoteEphemeral_RejectedOnRead: the wire-learned
// remote ephemeral (Token E, sent in plaintext) is structurally validated in
// readTokenE. Tampering the initiator's ephemeral public key to a malformed
// value makes the responder's ReadMessage abort with ErrKEMInvalidKey, and the
// malformed key is never delivered to the observer (the error aborts the read
// before the message notification).
func TestRemoteKEMKeyValidation_Pq_MalformedRemoteEphemeral_RejectedOnRead(t *testing.T) {
	suite := pqSuiteProd()
	obs := &remoteKeyValidationObserver{}

	i, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite, clatter.WithObserver(obs))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("write msg0: %v", err)
	}

	// Token E is the first field in pqNN msg0 and is sent in plaintext: tamper
	// the ephemeral public key into a malformed-but-right-length ML-KEM key.
	pubLen := suite.EKEM.PubKeyLen()
	for j := 0; j < pubLen; j++ {
		buf[j] = 0xFF
	}

	out := make([]byte, 65535)
	if _, rerr := r.ReadMessage(buf[:n], out); !errors.Is(rerr, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey on read of a malformed remote ephemeral, got %v", rerr)
	}
	if !obs.gotError || !errors.Is(obs.err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("observer must receive an error event wrapping ErrKEMInvalidKey, gotError=%v err=%v", obs.gotError, obs.err)
	}
	if obs.gotMessage {
		t.Fatal("observer must NOT receive a message event for a message whose remote key was rejected")
	}
}

// TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteKEMEphemeral_RejectedOnRead: the Hybrid KEM
// ephemeral (the second field of Token E, after the 32-byte DH ephemeral, in
// plaintext) is validated in readTokenE; the DH ephemeral is not touched.
func TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteKEMEphemeral_RejectedOnRead(t *testing.T) {
	suite := hybridSuiteProd()

	i, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	buf := make([]byte, 65535)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("write msg0: %v", err)
	}

	// Hybrid Token E = DH pub (PubKeyLen) then KEM pub (EKEM.PubKeyLen), both
	// plaintext. Tamper only the KEM ephemeral portion.
	dhLen := suite.DH.PubKeyLen()
	kemLen := suite.EKEM.PubKeyLen()
	for j := dhLen; j < dhLen+kemLen; j++ {
		buf[j] = 0xFF
	}

	out := make([]byte, 65535)
	if _, rerr := r.ReadMessage(buf[:n], out); !errors.Is(rerr, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey on read of a malformed remote KEM ephemeral, got %v", rerr)
	}
}

// TestRemoteKEMKeyValidation_ValidRemoteKeys_NoFalsePositive: a valid pre-set remote static
// constructs successfully and the handshake completes - the new validation
// must not reject well-formed keys.
func TestRemoteKEMKeyValidation_ValidRemoteKeys_NoFalsePositive(t *testing.T) {
	suite := pqSuiteProd()
	iKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x33))
	rKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x44))

	i, err := clatter.NewPqHandshake(clatter.PatternPqIK, true, suite,
		clatter.WithStaticKey(iKP), clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("initiator with valid remote static rejected: %v", err)
	}
	r, err := clatter.NewPqHandshake(clatter.PatternPqIK, false, suite, clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	verifyHandshake(t, i, r, "pqIK_validRemoteStatic")
}

// TestRemoteKEMKeyValidation_Pq_MalformedRemoteStatic_RejectedOnRead proves the wire-learned
// remote static validation site (readTokenS) end-to-end. A compliant node cannot
// hold a static whose public does not correspond to its secret (the
// construction-time consistency check rejects it), so this simulates a
// NON-COMPLIANT / malicious sender: the responder is built with a VALID static,
// then its static public is overwritten with a malformed-but-right-length key
// AFTER construction. The responder sends the malformed static encrypted in msg1;
// the initiator decrypts it and must reject it in readTokenS, before it would
// later be encapsulated to.
func TestRemoteKEMKeyValidation_Pq_MalformedRemoteStatic_RejectedOnRead(t *testing.T) {
	suite := pqSuiteProd()
	rKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x55))

	i, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite, clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	// Simulate the malicious sender: corrupt the local static public after
	// construction so the responder transmits a malformed key on the wire.
	clatter.SetLocalStaticPublicForTest(r, allFF(suite.SKEM.PubKeyLen()))

	buf := make([]byte, 65535)
	out := make([]byte, 65535)
	// msg0: initiator ephemeral.
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	if _, err := r.ReadMessage(buf[:n], out); err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	// msg1: responder sends ekem + its (now malformed) static, encrypted.
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	if _, rerr := i.ReadMessage(buf[:n], out); !errors.Is(rerr, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey on read of a malformed wire-learned remote static, got %v", rerr)
	}
}

// TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteStaticKEM_RejectedOnRead is the Hybrid analogue
// of the readTokenS proof. As in the Pq case, a compliant node cannot hold a
// self-inconsistent KEM static, so this simulates a non-compliant sender: the
// responder is built with a valid DH static and a valid KEM static, then its KEM
// static public is overwritten with a malformed-but-right-length key AFTER
// construction. The responder sends both statics encrypted in msg1, and the
// initiator must reject the KEM static in readTokenS (the DH static is not validated).
func TestRemoteKEMKeyValidation_Hybrid_MalformedRemoteStaticKEM_RejectedOnRead(t *testing.T) {
	suite := hybridSuiteProd()
	rDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	rKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	i, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, false, suite,
		clatter.WithStaticKey(rDH), clatter.WithStaticKEMKey(rKEM))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	// Simulate the malicious sender: corrupt the local KEM static public after
	// construction (the DH static is left valid).
	clatter.SetLocalStaticPublicForTest(r, allFF(suite.SKEM.PubKeyLen()))

	buf := make([]byte, 65535)
	out := make([]byte, 65535)
	n, err := i.WriteMessage(nil, buf) // msg0: initiator e
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	if _, err := r.ReadMessage(buf[:n], out); err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	n, err = r.WriteMessage(nil, buf) // msg1: ekem, e, ee, s (malformed KEM static), es
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	if _, rerr := i.ReadMessage(buf[:n], out); !errors.Is(rerr, clatter.ErrKEMInvalidKey) {
		t.Fatalf("want ErrKEMInvalidKey on read of a malformed wire-learned remote KEM static, got %v", rerr)
	}
}

// mixedPqSuite uses DISTINCT EKEM and SKEM (ML-KEM-768 ephemeral, ML-KEM-1024
// static) so each validation site is exercised with the correct, differently-
// sized KEM. A wrong-KEM-field bug (validating a static with EKEM or an
// ephemeral with SKEM) would reject a valid, correctly-sized key for wrong
// length and break these round-trips - which same-KEM suites cannot detect.
func mixedPqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem1024(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// TestRemoteKEMKeyValidation_MixedSuite_PqIK_ValidRoundTrip proves the CONSTRUCTION remote-static
// validation uses suite.SKEM (1024), not EKEM: the pre-set remote static is a
// valid 1568-byte SKEM key; validating it with EKEM (1184) would reject it for
// wrong length and the handshake would never start.
func TestRemoteKEMKeyValidation_MixedSuite_PqIK_ValidRoundTrip(t *testing.T) {
	suite := mixedPqSuite()
	iKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	rKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	i, err := clatter.NewPqHandshake(clatter.PatternPqIK, true, suite,
		clatter.WithStaticKey(iKP), clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("mixed-suite pqIK rejected a valid SKEM remote static at construction (wrong KEM field?): %v", err)
	}
	r, err := clatter.NewPqHandshake(clatter.PatternPqIK, false, suite, clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	verifyHandshake(t, i, r, "mixedSuite_pqIK")
}

// TestRemoteKEMKeyValidation_MixedSuite_PqXX_ValidRoundTrip proves the WIRE-LEARNED static
// validation (readTokenS) uses hs.skem (1024) and the ephemeral validation
// (readTokenE) uses hs.ekem (768): pqXX has both parties learn the other's
// SKEM static over the wire and read the other's EKEM ephemeral, so a swapped
// KEM field at either site rejects a valid key and breaks the round-trip.
func TestRemoteKEMKeyValidation_MixedSuite_PqXX_ValidRoundTrip(t *testing.T) {
	suite := mixedPqSuite()
	iKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	rKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	i, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithStaticKey(iKP))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite, clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	verifyHandshake(t, i, r, "mixedSuite_pqXX")
}
