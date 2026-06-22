package clatter_test

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
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

// --- One-way pattern tests (one-way is NQ-only) ---

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
	runNqVectorTest(t, "vectors/nq_nn_chacha_sha256.txt", 2)
}

func TestNqHandshake_VectorXX(t *testing.T) {
	runNqVectorTest(t, "vectors/nq_xx_chacha_sha256.txt", 3)
}

func TestNqHandshake_VectorIK(t *testing.T) {
	runNqVectorTest(t, "vectors/nq_ik_aes_sha512.txt", 2)
}

func TestNqHandshake_VectorNNpsk2(t *testing.T) {
	runNqVectorTest(t, "vectors/nq_nnpsk2_chacha_sha256.txt", 2)
}

func runNqVectorTest(t *testing.T, path string, wantMsgs int) {
	t.Helper()
	v := parseVectorFile(t, path)
	assertVectorShape(t, path, v, wantMsgs)

	suite := lookupSuite(t, v)
	pattern := lookupPattern(t, v.pattern)

	// Rust uses a SINGLE global DummyRng counter shared by both sides.
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
	// SEEC-on vector files declare the secret + hash used; the SEEC
	// runner honors these (it does not hardcode them) so editing them in
	// a vector file changes the handshake and fails the pin loudly.
	seecSecret []byte
	seecHash   string
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

// parseVectorFile parses a .txt vector file FAIL-CLOSED: every malformed
// line, undecodable hex value, unknown key, orphaned hash line, or scanner
// error is fatal. A vector parser that silently skips lines turns a buggy
// generator's output into vacuous pins that assert less than believed -
// the exact failure mode this strictness exists to prevent.
func parseVectorFile(t *testing.T, path string) *vectorData {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open vector: %v", err)
	}
	defer f.Close()

	mustHex := func(key, val string) []byte {
		data, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("%s: %s: invalid hex: %v", path, key, err)
		}
		return data
	}

	v := &vectorData{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section := "header"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "---" {
			switch section {
			case "header":
				section = "messages"
			case "messages":
				section = "transport"
			default:
				t.Fatalf("%s: unexpected third section separator", path)
			}
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			t.Fatalf("%s: malformed line (no 'key: value'): %q", path, line)
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
				v.prologue = mustHex(key, val)
			case "seec_secret_hex":
				v.seecSecret = mustHex(key, val)
			case "seec_hash":
				v.seecHash = val
			case "dh", "kem", "ekem", "skem":
				// Suite details consumed by the per-family runners.
			default:
				t.Fatalf("%s: unknown header key %q", path, key)
			}
		case "messages":
			switch {
			case strings.HasPrefix(key, "msg["):
				idx, sender := parseMsgKey(key)
				if sender == "" {
					t.Fatalf("%s: %s: missing sender", path, key)
				}
				v.messages = append(v.messages, vectorMessage{index: idx, sender: sender, msgHex: mustHex(key, val)})
			case strings.HasPrefix(key, "h["):
				idx := parseHKey(key)
				attached := false
				for i := range v.messages {
					if v.messages[i].index == idx {
						if v.messages[i].hashHex != nil {
							t.Fatalf("%s: duplicate h[%d]", path, idx)
						}
						v.messages[i].hashHex = mustHex(key, val)
						attached = true
					}
				}
				if !attached {
					t.Fatalf("%s: h[%d] has no preceding msg[%d] (h lines must follow their message)", path, idx, idx)
				}
			default:
				t.Fatalf("%s: unknown messages key %q", path, key)
			}
		case "transport":
			switch {
			case key == "handshake_hash":
				if v.hsHash != nil {
					t.Fatalf("%s: duplicate handshake_hash", path)
				}
				v.hsHash = mustHex(key, val)
			case strings.HasPrefix(key, "transport["):
				idx, sender := parseMsgKey(key)
				if sender == "" {
					t.Fatalf("%s: %s: missing sender", path, key)
				}
				v.transports = append(v.transports, vectorTransport{index: idx, sender: sender, data: mustHex(key, val)})
			default:
				t.Fatalf("%s: unknown transport key %q", path, key)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("%s: scan: %v", path, err)
	}
	return v
}

// assertVectorShape pins the exact shape of a parsed vector file: the
// message count, a handshake-hash pin on EVERY message, the final
// handshake hash, and the transport message count. Mirrors the JSON
// harness's wantCompleted pattern so a drifting generator cannot produce
// a file that pins less than intended.
func assertVectorShape(t *testing.T, path string, v *vectorData, wantMsgs int) {
	t.Helper()
	if len(v.messages) != wantMsgs {
		t.Fatalf("%s: parsed %d messages, want %d", path, len(v.messages), wantMsgs)
	}
	for _, m := range v.messages {
		if m.hashHex == nil {
			t.Fatalf("%s: msg[%d] has no h[%d] hash pin", path, m.index, m.index)
		}
	}
	if v.hsHash == nil {
		t.Fatalf("%s: missing final handshake_hash", path)
	}
	if len(v.transports) != 3 {
		t.Fatalf("%s: parsed %d transport messages, want 3", path, len(v.transports))
	}
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

// TestNqHandshake_ConcurrentAccessorsRaceFree drives a handshake while
// other goroutines hammer the public read accessors. Before the accessor
// guards, GetHandshakeHash could race setError nilling the symmetric
// state; the race detector is the oracle here. Accessor results must be
// coherent (nil or a full-length hash), never torn.
func TestNqHandshake_ConcurrentAccessorsRaceFree(t *testing.T) {
	suite := suiteChachaSha256()

	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	defer alice.Destroy()
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	defer bob.Destroy()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if h := alice.GetHandshakeHash(); h != nil && len(h) != 32 {
					t.Errorf("torn handshake hash: %d bytes", len(h))
					return
				}
				alice.IsFinished()
				alice.IsWriteTurn()
				if _, err := alice.GetNextMessageOverhead(); err != nil &&
					!errorsIsAny(err, clatter.ErrConcurrentUse, clatter.ErrInvalidState, clatter.ErrAlreadyFinished, clatter.ErrErrorState) {
					t.Errorf("unexpected accessor error: %v", err)
					return
				}
			}
		}()
	}

	// Handshake ops share the same single-goroutine guard as the
	// accessors, so an op can transiently lose the race to a concurrent
	// accessor with ErrConcurrentUse (the documented fail-loud contract).
	// Retry on contention; any other error is fatal.
	retry := func(label string, op func() (int, error)) int {
		for {
			n, err := op()
			if err == nil {
				return n
			}
			if !errors.Is(err, clatter.ErrConcurrentUse) {
				t.Fatalf("%s: %v", label, err)
			}
		}
	}

	buf := make([]byte, 4096)
	out := make([]byte, 4096)
	n := retry("alice write", func() (int, error) { return alice.WriteMessage(nil, buf) })
	retry("bob read", func() (int, error) { return bob.ReadMessage(buf[:n], out) })
	n = retry("bob write", func() (int, error) { return bob.WriteMessage(nil, buf) })
	retry("alice read", func() (int, error) { return alice.ReadMessage(buf[:n], out) })

	close(stop)
	wg.Wait()

	// Single-goroutine again: accessors must report completion.
	if !alice.IsFinished() {
		t.Fatal("alice not finished")
	}
}

// errorsIsAny reports whether err matches any of the given targets.
func errorsIsAny(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// TestTransport_AEADTamperRejected flips bytes on real Noise transport
// ciphertext (ChaCha20-Poly1305 through a completed XX handshake) and
// asserts ErrDecrypt. Also verifies auth failure leaves the receive
// state consistent: the untampered original still decrypts afterwards.
func TestTransport_AEADTamperRejected(t *testing.T) {
	x := dh.NewX25519()
	suite := suiteChachaSha256()

	aliceS, err := x.GenerateKeypair(clatter.NewDummyRng(11))
	if err != nil {
		t.Fatalf("alice keygen: %v", err)
	}
	bobS, err := x.GenerateKeypair(clatter.NewDummyRng(22))
	if err != nil {
		t.Fatalf("bob keygen: %v", err)
	}

	alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(aliceS))
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	bob, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(bobS))
	if err != nil {
		t.Fatalf("bob: %v", err)
	}

	buf := make([]byte, 4096)
	out := make([]byte, 4096)
	for i := 0; i < 3; i++ {
		w, r := alice, bob
		if i%2 == 1 {
			w, r = bob, alice
		}
		n, err := w.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("msg %d write: %v", i, err)
		}
		if _, err := r.ReadMessage(buf[:n], out); err != nil {
			t.Fatalf("msg %d read: %v", i, err)
		}
	}

	aliceTS, err := alice.Finalize()
	if err != nil {
		t.Fatalf("alice finalize: %v", err)
	}
	defer aliceTS.Destroy()
	bobTS, err := bob.Finalize()
	if err != nil {
		t.Fatalf("bob finalize: %v", err)
	}
	defer bobTS.Destroy()

	payload := []byte("authenticated transport message")
	n, err := aliceTS.Send(payload, buf)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	original := append([]byte{}, buf[:n]...)

	// Flip one byte in the ciphertext body, middle, and the AEAD tag.
	for _, pos := range []int{0, n / 2, n - 1} {
		tampered := append([]byte{}, original...)
		tampered[pos] ^= 0x01

		m, err := bobTS.Receive(tampered, out)
		if err == nil {
			t.Fatalf("tamper at %d: Receive accepted tampered ciphertext (%d bytes plaintext)", pos, m)
		}
		if !errors.Is(err, clatter.ErrDecrypt) {
			t.Fatalf("tamper at %d: got %v, want ErrDecrypt", pos, err)
		}
	}

	// Auth failure must not corrupt receive state: the original
	// untampered message still decrypts.
	m, err := bobTS.Receive(original, out)
	if err != nil {
		t.Fatalf("receive original after tamper attempts: %v", err)
	}
	if string(out[:m]) != string(payload) {
		t.Fatalf("payload mismatch after recovery: %q", out[:m])
	}
}

// TestNqHandshake_DerivedOneWay_EndToEnd proves the FULL wiring of the derived
// one-way bit: a CUSTOM one-way pattern built via the public NewPattern (which no
// longer takes a one-way parameter) is reported one-way by the pattern AND by the
// Handshaker interface, and its TransportState enforces the one-way direction
// (responder cannot Send, initiator cannot Receive). This closes the
// derive -> IsOneWay -> transport gating chain for a user-constructed pattern, not
// only the built-in N/K/X.
func TestNqHandshake_DerivedOneWay_EndToEnd(t *testing.T) {
	suite := suiteChachaSha256()

	// A custom one-way pattern (N's structure: -> e, es; responder pre-shares s and
	// writes nothing). One-way is DERIVED from numResponder == 0, never declared.
	pat, err := clatter.NewPattern("customOneWay",
		[][]clatter.Token{{clatter.TokenE, clatter.TokenES}}, nil,
		nil, []clatter.Token{clatter.TokenS})
	if err != nil {
		t.Fatalf("NewPattern(customOneWay): %v", err)
	}
	if !pat.IsOneWay() {
		t.Fatal("custom responder-silent pattern must be derived one-way")
	}

	rKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xAAAAAAAA))
	if err != nil {
		t.Fatalf("gen responder key: %v", err)
	}

	i, err := clatter.NewNqHandshake(pat, true, suite, clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	defer i.Destroy()
	r, err := clatter.NewNqHandshake(pat, false, suite, clatter.WithStaticKey(rKP))
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer r.Destroy()

	// The Handshaker interface surfaces the same derived bit.
	if !i.IsOneWay() || !r.IsOneWay() {
		t.Fatal("Handshaker.IsOneWay() must report the derived one-way bit")
	}

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)
	n, err := i.WriteMessage([]byte("one-way"), buf)
	if err != nil {
		t.Fatalf("msg0 write: %v", err)
	}
	pn, err := r.ReadMessage(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("msg0 read: %v", err)
	}
	if string(payloadBuf[:pn]) != "one-way" {
		t.Fatalf("handshake payload mismatch: %q", payloadBuf[:pn])
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

	// Allowed direction: initiator -> responder.
	out := make([]byte, 8192)
	wn, err := tsI.Send([]byte("hello"), out)
	if err != nil {
		t.Fatalf("initiator Send (allowed) failed: %v", err)
	}
	rn, err := tsR.Receive(out[:wn], payloadBuf)
	if err != nil {
		t.Fatalf("responder Receive (allowed) failed: %v", err)
	}
	if string(payloadBuf[:rn]) != "hello" {
		t.Fatalf("transport payload mismatch: %q", payloadBuf[:rn])
	}

	// Forbidden direction: the derived one-way bit must gate the reverse channel.
	if _, err := tsR.Send([]byte("nope"), out); !errors.Is(err, clatter.ErrOneWayViolation) {
		t.Fatalf("responder Send must be ErrOneWayViolation on a derived one-way pattern, got: %v", err)
	}
	if _, err := tsI.Receive(out[:48], payloadBuf); !errors.Is(err, clatter.ErrOneWayViolation) {
		t.Fatalf("initiator Receive must be ErrOneWayViolation on a derived one-way pattern, got: %v", err)
	}
}
