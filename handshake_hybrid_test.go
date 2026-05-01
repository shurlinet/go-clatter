package clatter_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func hybridSuiteChachaSha256() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768Testing(),
		SKEM:   kem.NewMlKem768Testing(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func hybridSuiteAesSha512() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768Testing(),
		SKEM:   kem.NewMlKem768Testing(),
		Cipher: cipher.NewAesGcm(),
		Hash:   hash.NewSha512(),
	}
}

func hybridSuiteProd() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// --- Round-trip tests ---

func TestHybridHandshake_NN_RoundTrip(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	i, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	if !i.IsWriteTurn() {
		t.Fatal("initiator should write first")
	}

	// hybridNN: -> e, <- ekem, e, ee
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}

	if !r.IsWriteTurn() {
		t.Fatal("responder should write second")
	}
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	_, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("handshake should be finished")
	}

	// Verify handshake hashes match
	iHash := i.GetHandshakeHash()
	rHash := r.GetHandshakeHash()
	if hex.EncodeToString(iHash) != hex.EncodeToString(rHash) {
		t.Fatal("handshake hashes differ")
	}

	// Finalize and test transport
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

	// Transport round-trip
	payload := []byte("hybrid quantum payload")
	n, err = tsI.Send(payload, buf)
	if err != nil {
		t.Fatalf("transport send: %v", err)
	}
	pn, err := tsR.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("transport receive: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload) {
		t.Fatal("transport payload mismatch")
	}
}

func TestHybridHandshake_XX_RoundTrip(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	// Generate DH static keys
	iDH, err := suite.DH.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rDH, err := suite.DH.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Generate KEM static keys
	iKEM, err := suite.SKEM.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rKEM, err := suite.SKEM.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	i, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite,
		clatter.WithStaticKey(iDH),
		clatter.WithStaticKEMKey(iKEM))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, false, suite,
		clatter.WithStaticKey(rDH),
		clatter.WithStaticKEMKey(rKEM))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// hybridXX: -> e, <- ekem, e, ee, s, es, -> skem, s, se, <- skem
	// msg0: initiator sends (e)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}

	// msg1: responder sends (ekem, e, ee, s, es)
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	_, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}

	// msg2: initiator sends (skem, s, se)
	n, err = i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg2 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg2 read: %v", err)
	}

	// msg3: responder sends (skem)
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg3 write: %v", err)
	}
	_, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg3 read: %v", err)
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("handshake should be finished")
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

	// Both directions
	payload := []byte("hybrid XX from initiator")
	n, err = tsI.Send(payload, buf)
	if err != nil {
		t.Fatalf("transport I->R send: %v", err)
	}
	pn, err := tsR.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("transport I->R receive: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload) {
		t.Fatal("I->R mismatch")
	}

	payload2 := []byte("hybrid XX from responder")
	n, err = tsR.Send(payload2, buf)
	if err != nil {
		t.Fatalf("transport R->I send: %v", err)
	}
	pn, err = tsI.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("transport R->I receive: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload2) {
		t.Fatal("R->I mismatch")
	}
}

func TestHybridHandshake_IK_RoundTrip(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	iDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	rDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	iKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	rKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	// hybridIK: <- s, ..., -> skem, e, es, s, ss, <- ekem, skem, e, ee, se
	// Initiator knows responder's static key (pre-message)
	i, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, true, suite,
		clatter.WithStaticKey(iDH),
		clatter.WithRemoteStatic(rDH.Public),
		clatter.WithStaticKEMKey(iKEM),
		clatter.WithRemoteStaticKEMKey(rKEM.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, false, suite,
		clatter.WithStaticKey(rDH),
		clatter.WithStaticKEMKey(rKEM))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// msg0: initiator sends (skem, e, es, s, ss)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}

	// msg1: responder sends (ekem, skem, e, ee, se)
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	_, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("handshake should be finished")
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

	payload := []byte("hybrid IK payload")
	n, err = tsI.Send(payload, buf)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	pn, err := tsR.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload) {
		t.Fatal("payload mismatch")
	}
}

// --- Interop vector tests ---

func TestHybridHandshake_VectorXX(t *testing.T) {
	runHybridVectorTest(t, "vectors/hybrid_xx_x25519_mlkem768_chacha_sha256.txt")
}

func TestHybridHandshake_VectorIK(t *testing.T) {
	runHybridVectorTest(t, "vectors/hybrid_ik_x25519_mlkem768_aes_sha512.txt")
}

func runHybridVectorTest(t *testing.T, path string) {
	t.Helper()
	v := parseVectorFile(t, path)

	suite := lookupHybridSuite(t, v)
	pattern := lookupPattern(t, v.pattern)

	// Rust uses a SINGLE global DummyRng counter shared by both sides.
	sharedRng := clatter.NewDummyRng(0xdeadbeef)

	var iOpts, rOpts []clatter.Option
	iOpts = append(iOpts, clatter.WithPrologue(v.prologue), clatter.WithRNG(sharedRng))
	rOpts = append(rOpts, clatter.WithPrologue(v.prologue), clatter.WithRNG(sharedRng))

	// Generate DH and KEM static keys matching Rust vector generator order.
	// Rust gen_hybrid() generates: alice_dh, bob_dh, alice_kem, bob_kem
	iDH, err := suite.DH.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen initiator DH: %v", err)
	}
	rDH, err := suite.DH.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen responder DH: %v", err)
	}
	iKEM, err := suite.SKEM.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen initiator KEM: %v", err)
	}
	rKEM, err := suite.SKEM.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen responder KEM: %v", err)
	}

	// Rust gen_hybrid() ALWAYS passes all keys (with_s, with_rs, with_s_kem, with_rs_kem).
	// We mirror this via options so pre-message processing can access KEM keys.
	iOpts = append(iOpts,
		clatter.WithStaticKey(iDH), clatter.WithRemoteStatic(rDH.Public),
		clatter.WithStaticKEMKey(iKEM), clatter.WithRemoteStaticKEMKey(rKEM.Public))
	rOpts = append(rOpts,
		clatter.WithStaticKey(rDH), clatter.WithRemoteStatic(iDH.Public),
		clatter.WithStaticKEMKey(rKEM), clatter.WithRemoteStaticKEMKey(iKEM.Public))

	initiator, err := clatter.NewHybridHandshake(pattern, true, suite, iOpts...)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}

	responder, err := clatter.NewHybridHandshake(pattern, false, suite, rOpts...)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	for _, vm := range v.messages {
		var writer, reader clatter.Handshaker
		if vm.sender == "initiator" {
			writer = initiator
			reader = responder
		} else {
			writer = responder
			reader = initiator
		}

		n, err := writer.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("msg[%d] %s write: %v", vm.index, vm.sender, err)
		}

		gotMsg := hex.EncodeToString(buf[:n])
		wantMsg := hex.EncodeToString(vm.msgHex)
		if gotMsg != wantMsg {
			t.Fatalf("msg[%d] mismatch:\n  got:  %s...\n  want: %s...",
				vm.index,
				truncHex(gotMsg, 80),
				truncHex(wantMsg, 80))
		}

		_, err = reader.ReadMessage(buf[:n], payloadBuf)
		if err != nil {
			t.Fatalf("msg[%d] %s read: %v", vm.index, vm.sender, err)
		}

		if vm.hashHex != nil {
			wantHash := hex.EncodeToString(vm.hashHex)
			gotWH := hex.EncodeToString(writer.GetHandshakeHash())
			gotRH := hex.EncodeToString(reader.GetHandshakeHash())

			if gotWH != wantHash {
				t.Fatalf("h[%d] writer mismatch:\n  got:  %s\n  want: %s", vm.index, gotWH, wantHash)
			}
			if gotRH != wantHash {
				t.Fatalf("h[%d] reader mismatch:\n  got:  %s\n  want: %s", vm.index, gotRH, wantHash)
			}
		}
	}

	if v.hsHash != nil {
		gotHash := hex.EncodeToString(initiator.GetHandshakeHash())
		wantHash := hex.EncodeToString(v.hsHash)
		if gotHash != wantHash {
			t.Fatalf("final hash mismatch:\n  got:  %s\n  want: %s", gotHash, wantHash)
		}
	}

	tsI, err := initiator.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := responder.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}

	for _, vt := range v.transports {
		var sender, receiver *clatter.TransportState
		if vt.sender == "initiator" {
			sender = tsI
			receiver = tsR
		} else {
			sender = tsR
			receiver = tsI
		}

		var payload []byte
		switch vt.index {
		case 0:
			payload = []byte("Scream without a sound")
		case 1:
			payload = []byte("Flying off the handle")
		case 2:
			payload = []byte("Eugene gene the dance machine")
		}

		n, err := sender.Send(payload, buf)
		if err != nil {
			t.Fatalf("transport[%d] send: %v", vt.index, err)
		}

		gotCt := hex.EncodeToString(buf[:n])
		wantCt := hex.EncodeToString(vt.data)
		if gotCt != wantCt {
			t.Fatalf("transport[%d] mismatch:\n  got:  %s\n  want: %s", vt.index, gotCt, wantCt)
		}

		pn, err := receiver.Receive(buf[:n], payloadBuf)
		if err != nil {
			t.Fatalf("transport[%d] receive: %v", vt.index, err)
		}
		if string(payloadBuf[:pn]) != string(payload) {
			t.Fatalf("transport[%d] payload mismatch", vt.index)
		}
	}
}

func lookupHybridSuite(t *testing.T, v *vectorData) clatter.CipherSuite {
	t.Helper()
	suite := clatter.CipherSuite{
		DH:   dh.NewX25519(),
		EKEM: kem.NewMlKem768Testing(),
		SKEM: kem.NewMlKem768Testing(),
	}
	switch v.cipherName {
	case "ChaChaPoly":
		suite.Cipher = cipher.NewChaChaPoly()
	case "AESGCM":
		suite.Cipher = cipher.NewAesGcm()
	default:
		t.Fatalf("unknown cipher: %s", v.cipherName)
	}
	switch v.hashName {
	case "SHA256":
		suite.Hash = hash.NewSha256()
	case "SHA512":
		suite.Hash = hash.NewSha512()
	default:
		t.Fatalf("unknown hash: %s", v.hashName)
	}
	return suite
}

// --- Error path tests ---

func TestHybridHandshake_WrongPatternType(t *testing.T) {
	suite := hybridSuiteProd()
	// DH-only pattern should fail
	_, err := clatter.NewHybridHandshake(clatter.PatternNN, true, suite)
	if err == nil {
		t.Fatal("expected error for DH pattern")
	}
	// KEM-only pattern should fail
	_, err = clatter.NewHybridHandshake(clatter.PatternPqNN, true, suite)
	if err == nil {
		t.Fatal("expected error for KEM pattern")
	}
}

func TestHybridHandshake_MissingSuite(t *testing.T) {
	// Missing DH
	_, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	})
	if err == nil {
		t.Fatal("expected error for missing DH")
	}

	// Missing EKEM
	_, err = clatter.NewHybridHandshake(clatter.PatternHybridNN, true, clatter.CipherSuite{
		DH:     dh.NewX25519(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	})
	if err == nil {
		t.Fatal("expected error for missing EKEM")
	}
}

func TestHybridHandshake_DoubleFinalize(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	i, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	r, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	_, err := i.Finalize()
	if err != nil {
		t.Fatalf("first Finalize: %v", err)
	}

	_, err = i.Finalize()
	if err == nil {
		t.Fatal("expected error on double Finalize")
	}
}

// --- Overhead accuracy tests ---

func TestHybridHandshake_OverheadNN(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	i, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	r, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	defer i.Destroy()
	defer r.Destroy()

	// msg0: initiator sends E (DH pub + KEM pub), no key yet -> no payload tag
	overhead0, err := i.GetNextMessageOverhead()
	if err != nil {
		t.Fatalf("overhead msg0: %v", err)
	}
	n, _ := i.WriteMessage(nil, buf)
	if n != overhead0 {
		t.Fatalf("msg0 overhead mismatch: predicted %d, actual %d", overhead0, n)
	}
	r.ReadMessage(buf[:n], payloadBuf)

	// msg1: responder sends Ekem + E + EE -> key established by EE -> payload tag
	overhead1, err := r.GetNextMessageOverhead()
	if err != nil {
		t.Fatalf("overhead msg1: %v", err)
	}
	n, _ = r.WriteMessage(nil, buf)
	if n != overhead1 {
		t.Fatalf("msg1 overhead mismatch: predicted %d, actual %d", overhead1, n)
	}
}

// --- buildName format tests ---

func TestHybridBuildName_SameKEM(t *testing.T) {
	suite := hybridSuiteChachaSha256()
	hs, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Destroy()

	// hybridBuildName with EKEM==SKEM: "Noise_hybridXX_25519+MLKEM768_ChaChaPoly_SHA256"
	// Verify the hash matches the protocol name format by checking it doesn't error.
	// The actual protocol name is internal but is hashed into the symmetric state.
	// We verify by checking that two handshakes with same suite produce same initial hash.
	hs2, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	defer hs2.Destroy()

	h1 := hex.EncodeToString(hs.GetHandshakeHash())
	h2 := hex.EncodeToString(hs2.GetHandshakeHash())
	if h1 != h2 {
		t.Fatal("same suite + pattern should produce same initial hash")
	}
}

// --- Payload round-trip test ---

func TestHybridHandshake_NN_PayloadRoundTrip(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	i, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	r, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	defer i.Destroy()
	defer r.Destroy()

	// msg0: initiator sends E with no payload (no key yet, payload would be cleartext)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}

	// msg1: responder sends Ekem+E+EE with payload (key IS established after EE)
	payload := []byte("hybrid payload in handshake msg1")
	n, err = r.WriteMessage(payload, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	pn, err := i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload) {
		t.Fatalf("msg1 payload mismatch: got %q, want %q", payloadBuf[:pn], payload)
	}
}

// --- Overhead accuracy with Token::S (tag*2) ---

func TestHybridHandshake_OverheadXX_WithS(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)
	payloadBuf := make([]byte, 65535)

	iDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	rDH, _ := suite.DH.GenerateKeypair(crand.Reader)
	iKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	rKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	i, _ := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite,
		clatter.WithStaticKey(iDH), clatter.WithStaticKEMKey(iKEM))
	r, _ := clatter.NewHybridHandshake(clatter.PatternHybridXX, false, suite,
		clatter.WithStaticKey(rDH), clatter.WithStaticKEMKey(rKEM))
	defer i.Destroy()
	defer r.Destroy()

	// msg0: initiator sends E
	oh0, _ := i.GetNextMessageOverhead()
	n, _ := i.WriteMessage(nil, buf)
	if n != oh0 {
		t.Fatalf("msg0: predicted %d, actual %d", oh0, n)
	}
	r.ReadMessage(buf[:n], payloadBuf)

	// msg1: responder sends Ekem, E, EE, S, ES
	// After EE, key is established. S should include tag*2 (DH pub + KEM pub encrypted).
	oh1, _ := r.GetNextMessageOverhead()
	n, _ = r.WriteMessage(nil, buf)
	if n != oh1 {
		t.Fatalf("msg1: predicted %d, actual %d", oh1, n)
	}
	i.ReadMessage(buf[:n], payloadBuf)

	// msg2: initiator sends Skem, S, SE
	// Key established. S adds tag*2. Skem adds tag (encrypted).
	oh2, _ := i.GetNextMessageOverhead()
	n, _ = i.WriteMessage(nil, buf)
	if n != oh2 {
		t.Fatalf("msg2: predicted %d, actual %d", oh2, n)
	}
	r.ReadMessage(buf[:n], payloadBuf)

	// msg3: responder sends Skem
	oh3, _ := r.GetNextMessageOverhead()
	n, _ = r.WriteMessage(nil, buf)
	if n != oh3 {
		t.Fatalf("msg3: predicted %d, actual %d", oh3, n)
	}
}

// --- Wrong turn test ---

func TestHybridHandshake_WriteWhenNotTurn(t *testing.T) {
	suite := hybridSuiteProd()
	buf := make([]byte, 65535)

	i, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	r, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite)
	defer i.Destroy()
	defer r.Destroy()

	// Responder should NOT be able to write first (initiator writes first)
	_, err := r.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("responder should not be able to write first")
	}

	// Initiator should NOT be able to read first
	_, err = i.ReadMessage(buf[:32], make([]byte, 65535))
	if err == nil {
		t.Fatal("initiator should not be able to read first")
	}
}

// --- Destroy test ---

func TestHybridHandshake_DestroyZerosState(t *testing.T) {
	suite := hybridSuiteProd()
	hs, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite)
	hs.Destroy()

	// After Destroy, status should be error (no operations possible)
	if hs.IsWriteTurn() {
		t.Fatal("should not be write turn after Destroy")
	}
	if hs.IsFinished() {
		t.Fatal("should not be finished after Destroy")
	}
}
