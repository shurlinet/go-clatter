package clatter_test

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
)

func suiteChachaSha256() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func suiteAesSha512() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewAesGcm(),
		Hash:   hash.NewSha512(),
	}
}

func TestNqHandshake_NN_RoundTrip(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	if !i.IsWriteTurn() {
		t.Fatal("initiator should write first")
	}
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
		t.Fatal("both should be finished")
	}

	tsI, err := i.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := r.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}

	verifyTransport(t, tsI, tsR)
}

func TestNqHandshake_XX_RoundTrip(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	iKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x11111111))
	if err != nil {
		t.Fatalf("gen initiator key: %v", err)
	}
	rKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x22222222))
	if err != nil {
		t.Fatalf("gen responder key: %v", err)
	}

	i, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(iKP))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()
	r, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// msg0 (e)
	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	// msg1 (e, ee, s, es)
	n, err = r.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	_, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}
	// msg2 (s, se)
	n, err = i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg2 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg2 read: %v", err)
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("both should be finished after 3 messages")
	}

	tsI, err := i.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := r.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}
	verifyTransport(t, tsI, tsR)
}

func TestNqHandshake_IK_RoundTrip(t *testing.T) {
	suite := suiteAesSha512()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	iKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x33333333))
	rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x44444444))

	i, err := clatter.NewNqHandshake(clatter.PatternIK, true, suite,
		clatter.WithStaticKey(iKP),
		clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewNqHandshake(clatter.PatternIK, false, suite,
		clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
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
		t.Fatal("both should be finished")
	}

	tsI, _ := i.Finalize()
	tsR, _ := r.Finalize()
	verifyTransport(t, tsI, tsR)
}

func TestNqHandshake_NNpsk2_RoundTrip(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	psk := make([]byte, clatter.PSKLen)
	psk[0] = 0x42

	i, err := clatter.NewNqHandshake(clatter.PatternNNpsk2, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()
	if err := i.PushPSK(psk); err != nil {
		t.Fatalf("initiator PushPSK: %v", err)
	}

	r, err := clatter.NewNqHandshake(clatter.PatternNNpsk2, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()
	if err := r.PushPSK(psk); err != nil {
		t.Fatalf("responder PushPSK: %v", err)
	}

	n, err := i.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	_, err = r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
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
		t.Fatal("both should be finished")
	}

	tsI, err := i.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := r.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}
	verifyTransport(t, tsI, tsR)
}

func TestNqHandshake_DoubleFinalize(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

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

	_, err = i.Finalize()
	if err != nil {
		t.Fatalf("first Finalize: %v", err)
	}

	_, err = i.Finalize()
	if err == nil {
		t.Fatal("expected error on double finalize")
	}
}

func TestNqHandshake_PatternTypeCheck(t *testing.T) {
	suite := suiteChachaSha256()
	_, err := clatter.NewNqHandshake(clatter.PatternPqNN, true, suite)
	if err == nil {
		t.Fatal("expected error for PQ pattern in NQ handshake")
	}
}

func TestNqHandshake_NilCipherSuite(t *testing.T) {
	// Missing DH
	_, err := clatter.NewNqHandshake(clatter.PatternNN, true, clatter.CipherSuite{})
	if err == nil {
		t.Fatal("expected error for nil CipherSuite fields")
	}
}

func TestNqHandshake_WithPayload(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	payload0 := []byte("hello from initiator")
	n, err := i.WriteMessage(payload0, buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	pn, err := r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload0) {
		t.Fatalf("msg0 payload mismatch")
	}

	payload1 := []byte("hello from responder")
	n, err = r.WriteMessage(payload1, buf)
	if err != nil {
		t.Fatalf("msg1 write: %v", err)
	}
	pn, err = i.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg1 read: %v", err)
	}
	if string(payloadBuf[:pn]) != string(payload1) {
		t.Fatalf("msg1 payload mismatch")
	}
}

func TestNqHandshake_HandshakeHashMatch(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

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

	iHash := i.GetHandshakeHash()
	rHash := r.GetHandshakeHash()
	if hex.EncodeToString(iHash) != hex.EncodeToString(rHash) {
		t.Fatalf("handshake hash mismatch:\n  i: %s\n  r: %s",
			hex.EncodeToString(iHash), hex.EncodeToString(rHash))
	}
}

// --- One-way pattern tests (F139: one-way is NQ-only) ---

func TestNqHandshake_OneWayN(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	rKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xAAAAAAAA))
	if err != nil {
		t.Fatalf("gen responder key: %v", err)
	}

	// N pattern: initiator sends one message (e, es). No responder messages.
	// Responder has pre-message s.
	i, err := clatter.NewNqHandshake(clatter.PatternN, true, suite,
		clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	r, err := clatter.NewNqHandshake(clatter.PatternN, false, suite,
		clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// msg0: initiator -> responder (e, es)
	n, err := i.WriteMessage([]byte("one-way data"), buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	pn, err := r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	if string(payloadBuf[:pn]) != "one-way data" {
		t.Fatalf("payload mismatch: got %q", payloadBuf[:pn])
	}

	if !i.IsFinished() || !r.IsFinished() {
		t.Fatal("both should be finished after one-way message")
	}

	tsI, err := i.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := r.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}

	// One-way: initiator can send, responder receives
	n, err = tsI.Send([]byte("transport msg"), buf)
	if err != nil {
		t.Fatalf("transport send: %v", err)
	}
	pn, err = tsR.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("transport receive: %v", err)
	}
	if string(payloadBuf[:pn]) != "transport msg" {
		t.Fatalf("transport payload mismatch")
	}
}

// --- Error path tests ---

func TestNqHandshake_WriteWhenShouldRead(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	// Responder should receive first, not write
	_, err = r.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("expected error writing when should read")
	}

	// Initiator should write first, not read
	_, err = i.ReadMessage(buf[:32], payloadBuf)
	if err == nil {
		t.Fatal("expected error reading when should write")
	}
}

func TestNqHandshake_BufferTooSmall(t *testing.T) {
	suite := suiteChachaSha256()

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()

	// NN msg0 needs 32 (ephemeral pubkey) + 0 (no payload tag, no key yet)
	// Actually with the always-EncryptAndHash fix, there's no tag before first DH.
	// The overhead includes the pubkey. Try a buffer that's too small.
	tinyBuf := make([]byte, 16)
	_, err = i.WriteMessage(nil, tinyBuf)
	if err == nil {
		t.Fatal("expected buffer too small error")
	}
}

func TestNqHandshake_ReadMessageTooShort(t *testing.T) {
	suite := suiteChachaSha256()
	payloadBuf := make([]byte, 8192)

	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// Feed responder a message that's too short (needs at least 32 bytes for ephemeral)
	shortMsg := []byte{0x01, 0x02, 0x03}
	_, err = r.ReadMessage(shortMsg, payloadBuf)
	if err == nil {
		t.Fatal("expected error for short message")
	}
}

func TestNqHandshake_ReadOutBufferTooSmall(t *testing.T) {
	suite := suiteChachaSha256()
	buf := make([]byte, 8192)

	i, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	// Write msg0 with a payload
	payload := []byte("this is a payload that needs space in the output buffer")
	n, err := i.WriteMessage(payload, buf)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read with an out buffer that's too small for the payload
	tinyOut := make([]byte, 2)
	_, err = r.ReadMessage(buf[:n], tinyOut)
	if err == nil {
		t.Fatal("expected error for small output buffer")
	}
}

// --- Overhead accuracy test ---

func TestNqHandshake_OverheadAccuracy(t *testing.T) {
	suite := suiteChachaSha256()

	// Test overhead prediction for several patterns
	patterns := []*clatter.HandshakePattern{
		clatter.PatternNN,
		clatter.PatternXX,
		clatter.PatternIK,
		clatter.PatternKK,
		clatter.PatternNK,
	}

	for _, pattern := range patterns {
		t.Run(pattern.Name(), func(t *testing.T) {
			iKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x11111111))
			rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x22222222))

			var iOpts, rOpts []clatter.Option
			if needsStaticKey(pattern, true) {
				iOpts = append(iOpts, clatter.WithStaticKey(iKP))
			}
			if needsStaticKey(pattern, false) {
				rOpts = append(rOpts, clatter.WithStaticKey(rKP))
			}
			if hasPreToken(pattern.PreResponder(), clatter.TokenS) {
				iOpts = append(iOpts, clatter.WithRemoteStatic(rKP.Public))
			}
			if hasPreToken(pattern.PreInitiator(), clatter.TokenS) {
				rOpts = append(rOpts, clatter.WithRemoteStatic(iKP.Public))
			}

			i, err := clatter.NewNqHandshake(pattern, true, suite, iOpts...)
			if err != nil {
				t.Fatalf("initiator: %v", err)
			}
			r, err := clatter.NewNqHandshake(pattern, false, suite, rOpts...)
			if err != nil {
				t.Fatalf("responder: %v", err)
			}

			buf := make([]byte, 8192)
			payloadBuf := make([]byte, 8192)

			for !i.IsFinished() || !r.IsFinished() {
				var writer, reader *clatter.NqHandshake
				if i.IsWriteTurn() {
					writer = i
					reader = r
				} else {
					writer = r
					reader = i
				}

				// Get predicted overhead BEFORE writing
				overhead, err := writer.GetNextMessageOverhead()
				if err != nil {
					t.Fatalf("GetNextMessageOverhead: %v", err)
				}

				// Write with empty payload
				n, err := writer.WriteMessage(nil, buf)
				if err != nil {
					t.Fatalf("WriteMessage: %v", err)
				}

				// Actual message size with empty payload must equal predicted overhead
				if n != overhead {
					t.Fatalf("overhead mismatch: predicted %d, actual %d", overhead, n)
				}

				if _, err = reader.ReadMessage(buf[:n], payloadBuf); err != nil {
					t.Fatalf("ReadMessage: %v", err)
				}
			}
		})
	}
}

// --- Interop vector tests ---

func TestNqHandshake_VectorNN(t *testing.T) {
	runNqVectorTest(t, "testdata/vectors/nq_nn_chacha_sha256.txt")
}

func TestNqHandshake_VectorXX(t *testing.T) {
	runNqVectorTest(t, "testdata/vectors/nq_xx_chacha_sha256.txt")
}

func TestNqHandshake_VectorIK(t *testing.T) {
	runNqVectorTest(t, "testdata/vectors/nq_ik_aes_sha512.txt")
}

func TestNqHandshake_VectorNNpsk2(t *testing.T) {
	runNqVectorTest(t, "testdata/vectors/nq_nnpsk2_chacha_sha256.txt")
}

func runNqVectorTest(t *testing.T, path string) {
	t.Helper()
	v := parseVectorFile(t, path)

	suite := lookupSuite(t, v)
	pattern := lookupPattern(t, v.pattern)

	// F178: Rust uses a SINGLE global DummyRng counter shared by both sides.
	// Both initiator and responder draw from the same counter.
	sharedRng := clatter.NewDummyRng(0xdeadbeef)

	var iOpts, rOpts []clatter.Option
	iOpts = append(iOpts, clatter.WithPrologue(v.prologue), clatter.WithRNG(sharedRng))
	rOpts = append(rOpts, clatter.WithPrologue(v.prologue), clatter.WithRNG(sharedRng))

	setupStaticKeys(t, pattern, suite, sharedRng, sharedRng, &iOpts, &rOpts)

	initiator, err := clatter.NewNqHandshake(pattern, true, suite, iOpts...)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}

	// PSKs must be pushed AFTER construction (Rust pushes before handshake start)
	if pattern.HasPSK() {
		pushVectorPSKs(t, initiator, pattern, true)
	}

	responder, err := clatter.NewNqHandshake(pattern, false, suite, rOpts...)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}

	if pattern.HasPSK() {
		pushVectorPSKs(t, responder, pattern, false)
	}

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	for _, vm := range v.messages {
		var writer, reader *clatter.NqHandshake
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
			t.Fatalf("msg[%d] mismatch:\n  got:  %s\n  want: %s", vm.index, gotMsg, wantMsg)
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

// setupStaticKeys generates static keys matching Rust vector generator order.
// CRITICAL: Rust gen_nq() ALWAYS generates both static keys from the shared RNG
// (consuming 64 bytes) even for patterns like NN that don't use them.
// We must consume the same RNG bytes to keep the counter in sync.
func setupStaticKeys(t *testing.T, p *clatter.HandshakePattern, suite clatter.CipherSuite,
	iRng, rRng clatter.RNG, iOpts, rOpts *[]clatter.Option) {
	t.Helper()

	// ALWAYS generate both keys to consume RNG bytes (matches Rust gen_nq)
	iStaticKP, err := suite.DH.GenerateKeypair(iRng)
	if err != nil {
		t.Fatalf("gen initiator static: %v", err)
	}
	rStaticKP, err := suite.DH.GenerateKeypair(rRng)
	if err != nil {
		t.Fatalf("gen responder static: %v", err)
	}

	// Only pass keys as options when the pattern uses them
	iNeedsStatic := needsStaticKey(p, true)
	rNeedsStatic := needsStaticKey(p, false)

	if iNeedsStatic {
		*iOpts = append(*iOpts, clatter.WithStaticKey(iStaticKP))
	}
	if rNeedsStatic {
		*rOpts = append(*rOpts, clatter.WithStaticKey(rStaticKP))
	}

	// Pre-message remote static (Rust passes Some(bob_s_pub) to alice always)
	if hasPreToken(p.PreResponder(), clatter.TokenS) {
		*iOpts = append(*iOpts, clatter.WithRemoteStatic(rStaticKP.Public))
	}
	if hasPreToken(p.PreInitiator(), clatter.TokenS) {
		*rOpts = append(*rOpts, clatter.WithRemoteStatic(iStaticKP.Public))
	}
}

// pushVectorPSKs pushes PSKs matching Rust test data: [0;32], [1;32], etc.
// Counts PSK tokens for the given role and pushes that many PSKs.
func pushVectorPSKs(t *testing.T, hs *clatter.NqHandshake, p *clatter.HandshakePattern, initiator bool) {
	t.Helper()

	// Count PSK tokens this side will encounter during write
	count := 0
	if initiator {
		for idx := 0; idx < p.NumInitiatorMessages(); idx++ {
			for _, tok := range p.InitiatorMessage(idx) {
				if tok == clatter.TokenPsk {
					count++
				}
			}
		}
	} else {
		for idx := 0; idx < p.NumResponderMessages(); idx++ {
			for _, tok := range p.ResponderMessage(idx) {
				if tok == clatter.TokenPsk {
					count++
				}
			}
		}
	}

	// Also count PSKs consumed during read (reader also pops PSK)
	if initiator {
		for idx := 0; idx < p.NumResponderMessages(); idx++ {
			for _, tok := range p.ResponderMessage(idx) {
				if tok == clatter.TokenPsk {
					count++
				}
			}
		}
	} else {
		for idx := 0; idx < p.NumInitiatorMessages(); idx++ {
			for _, tok := range p.InitiatorMessage(idx) {
				if tok == clatter.TokenPsk {
					count++
				}
			}
		}
	}

	for idx := 0; idx < count; idx++ {
		var psk [clatter.PSKLen]byte
		for j := range psk {
			psk[j] = byte(idx)
		}
		if err := hs.PushPSK(psk[:]); err != nil {
			t.Fatalf("PushPSK[%d]: %v", idx, err)
		}
	}
}

func needsStaticKey(p *clatter.HandshakePattern, initiator bool) bool {
	if initiator {
		for _, tok := range p.PreInitiator() {
			if tok == clatter.TokenS {
				return true
			}
		}
		for idx := 0; idx < p.NumInitiatorMessages(); idx++ {
			for _, tok := range p.InitiatorMessage(idx) {
				if tok == clatter.TokenS {
					return true
				}
			}
		}
	} else {
		for _, tok := range p.PreResponder() {
			if tok == clatter.TokenS {
				return true
			}
		}
		for idx := 0; idx < p.NumResponderMessages(); idx++ {
			for _, tok := range p.ResponderMessage(idx) {
				if tok == clatter.TokenS {
					return true
				}
			}
		}
	}
	return false
}

func hasPreToken(tokens []clatter.Token, target clatter.Token) bool {
	for _, t := range tokens {
		if t == target {
			return true
		}
	}
	return false
}

// --- Vector file parsing ---

type vectorData struct {
	pattern    string
	cipherName string
	hashName   string
	prologue   []byte
	messages   []vectorMessage
	hsHash     []byte
	transports []vectorTransport
}

type vectorMessage struct {
	index   int
	sender  string
	msgHex  []byte
	hashHex []byte
}

type vectorTransport struct {
	index  int
	sender string
	data   []byte
}

func parseVectorFile(t *testing.T, path string) *vectorData {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open vector: %v", err)
	}
	defer f.Close()

	v := &vectorData{}
	scanner := bufio.NewScanner(f)
	section := "header"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "---" {
			if section == "header" {
				section = "messages"
			} else {
				section = "transport"
			}
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]

		switch section {
		case "header":
			switch key {
			case "pattern":
				v.pattern = val
			case "cipher":
				v.cipherName = val
			case "hash":
				v.hashName = val
			case "prologue_hex":
				v.prologue, _ = hex.DecodeString(val)
			}
		case "messages":
			if strings.HasPrefix(key, "msg[") {
				idx, sender := parseMsgKey(key)
				data, _ := hex.DecodeString(val)
				v.messages = append(v.messages, vectorMessage{index: idx, sender: sender, msgHex: data})
			} else if strings.HasPrefix(key, "h[") {
				idx := parseHKey(key)
				data, _ := hex.DecodeString(val)
				for i := range v.messages {
					if v.messages[i].index == idx {
						v.messages[i].hashHex = data
					}
				}
			}
		case "transport":
			if key == "handshake_hash" {
				v.hsHash, _ = hex.DecodeString(val)
			} else if strings.HasPrefix(key, "transport[") {
				idx, sender := parseMsgKey(key)
				data, _ := hex.DecodeString(val)
				v.transports = append(v.transports, vectorTransport{index: idx, sender: sender, data: data})
			}
		}
	}
	return v
}

func parseMsgKey(key string) (int, string) {
	var idx int
	if i := strings.Index(key, "["); i >= 0 {
		fmt.Sscanf(key[i+1:], "%d]", &idx)
	}
	sender := ""
	if strings.Contains(key, "initiator") {
		sender = "initiator"
	} else if strings.Contains(key, "responder") {
		sender = "responder"
	}
	return idx, sender
}

func parseHKey(key string) int {
	var idx int
	fmt.Sscanf(key, "h[%d]", &idx)
	return idx
}

func lookupSuite(t *testing.T, v *vectorData) clatter.CipherSuite {
	t.Helper()
	s := clatter.CipherSuite{DH: dh.NewX25519()}
	switch v.cipherName {
	case "ChaChaPoly":
		s.Cipher = cipher.NewChaChaPoly()
	case "AESGCM":
		s.Cipher = cipher.NewAesGcm()
	default:
		t.Fatalf("unknown cipher: %s", v.cipherName)
	}
	switch v.hashName {
	case "SHA256":
		s.Hash = hash.NewSha256()
	case "SHA512":
		s.Hash = hash.NewSha512()
	default:
		t.Fatalf("unknown hash: %s", v.hashName)
	}
	return s
}

func lookupPattern(t *testing.T, name string) *clatter.HandshakePattern {
	t.Helper()
	for _, p := range clatter.AllPatterns() {
		if p.Name() == name {
			return p
		}
	}
	t.Fatalf("unknown pattern: %s", name)
	return nil
}

func verifyTransport(t *testing.T, tsI, tsR *clatter.TransportState) {
	t.Helper()
	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	msgs := []struct {
		payload string
		sender  *clatter.TransportState
		recvr   *clatter.TransportState
	}{
		{"Scream without a sound", tsI, tsR},
		{"Flying off the handle", tsR, tsI},
		{"Eugene gene the dance machine", tsI, tsR},
	}

	for i, m := range msgs {
		n, err := m.sender.Send([]byte(m.payload), buf)
		if err != nil {
			t.Fatalf("transport[%d] send: %v", i, err)
		}
		pn, err := m.recvr.Receive(buf[:n], payloadBuf)
		if err != nil {
			t.Fatalf("transport[%d] receive: %v", i, err)
		}
		if string(payloadBuf[:pn]) != m.payload {
			t.Fatalf("transport[%d]: got %q, want %q", i, payloadBuf[:pn], m.payload)
		}
	}
}
