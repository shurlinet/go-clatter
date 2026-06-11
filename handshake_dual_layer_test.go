package clatter_test

import (
	"bufio"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// -----------------------------------------------------------------------
// DualLayer round-trip tests
// -----------------------------------------------------------------------

func TestDualLayerHandshake_NN_pqXX_RoundTrip(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	buf := make([]byte, 16384)
	payloadBuf := make([]byte, 8192)

	// Create outer NN handshakes
	outerI, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	if err != nil {
		t.Fatalf("outer initiator: %v", err)
	}
	outerR, err := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)
	if err != nil {
		t.Fatalf("outer responder: %v", err)
	}

	// PQ XX requires static KEM keypairs for each side
	iSKEM, err := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x11111111))
	if err != nil {
		t.Fatalf("gen initiator SKEM: %v", err)
	}
	rSKEM, err := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x22222222))
	if err != nil {
		t.Fatalf("gen responder SKEM: %v", err)
	}

	// Create inner pqXX handshakes
	innerI, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite,
		clatter.WithStaticKey(iSKEM))
	if err != nil {
		t.Fatalf("inner initiator: %v", err)
	}
	innerR, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite,
		clatter.WithStaticKey(rSKEM))
	if err != nil {
		t.Fatalf("inner responder: %v", err)
	}

	// Create dual-layer handshakes with 8KB buffer
	alice, err := clatter.NewDualLayerHandshake(outerI, innerI, 8192)
	if err != nil {
		t.Fatalf("alice dual: %v", err)
	}
	defer alice.Destroy()
	bob, err := clatter.NewDualLayerHandshake(outerR, innerR, 8192)
	if err != nil {
		t.Fatalf("bob dual: %v", err)
	}
	defer bob.Destroy()

	// Drive handshake to completion
	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, werr := alice.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("alice write: %v", werr)
			}
			_, rerr := bob.ReadMessage(buf[:n], payloadBuf)
			if rerr != nil {
				t.Fatalf("bob read: %v", rerr)
			}
		} else if bob.IsWriteTurn() {
			n, werr := bob.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("bob write: %v", werr)
			}
			_, rerr := alice.ReadMessage(buf[:n], payloadBuf)
			if rerr != nil {
				t.Fatalf("alice read: %v", rerr)
			}
		} else {
			t.Fatal("neither side has write turn")
		}
	}

	// Finalize
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

	// Transport round-trip
	msg := []byte("Hello from Alice through dual-layer!")
	sendBuf := make([]byte, 2048)
	recvBuf := make([]byte, 2048)

	n, err := aliceTS.Send(msg, sendBuf)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	m, err := bobTS.Receive(sendBuf[:n], recvBuf)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(recvBuf[:m]) != string(msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recvBuf[:m], msg)
	}

	// Reverse direction
	msg2 := []byte("Hello from Bob!")
	n, err = bobTS.Send(msg2, sendBuf)
	if err != nil {
		t.Fatalf("bob send: %v", err)
	}
	m, err = aliceTS.Receive(sendBuf[:n], recvBuf)
	if err != nil {
		t.Fatalf("alice receive: %v", err)
	}
	if string(recvBuf[:m]) != string(msg2) {
		t.Fatalf("payload mismatch: got %q, want %q", recvBuf[:m], msg2)
	}
}

// -----------------------------------------------------------------------
// HybridDualLayer round-trip test
// -----------------------------------------------------------------------

func TestHybridDualLayerHandshake_NN_pqXX_RoundTrip(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	buf := make([]byte, 16384)
	payloadBuf := make([]byte, 8192)

	iSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x33333333))
	rSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x44444444))

	outerI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	outerR, _ := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)
	innerI, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite,
		clatter.WithStaticKey(iSKEM))
	innerR, _ := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite,
		clatter.WithStaticKey(rSKEM))

	alice, err := clatter.NewHybridDualLayerHandshake(outerI, innerI, 8192)
	if err != nil {
		t.Fatalf("alice hybrid dual: %v", err)
	}
	defer alice.Destroy()
	bob, err := clatter.NewHybridDualLayerHandshake(outerR, innerR, 8192)
	if err != nil {
		t.Fatalf("bob hybrid dual: %v", err)
	}
	defer bob.Destroy()

	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, werr := alice.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("alice write: %v", werr)
			}
			_, rerr := bob.ReadMessage(buf[:n], payloadBuf)
			if rerr != nil {
				t.Fatalf("bob read: %v", rerr)
			}
		} else if bob.IsWriteTurn() {
			n, werr := bob.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("bob write: %v", werr)
			}
			_, rerr := alice.ReadMessage(buf[:n], payloadBuf)
			if rerr != nil {
				t.Fatalf("alice read: %v", rerr)
			}
		} else {
			t.Fatal("neither side has write turn")
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

	// Verify handshake hashes match
	if hex.EncodeToString(aliceTS.GetHandshakeHash()) != hex.EncodeToString(bobTS.GetHandshakeHash()) {
		t.Fatal("handshake hashes don't match")
	}

	msg := []byte("Hybrid dual-layer transport works!")
	sendBuf := make([]byte, 2048)
	recvBuf := make([]byte, 2048)
	n, _ := aliceTS.Send(msg, sendBuf)
	m, _ := bobTS.Receive(sendBuf[:n], recvBuf)
	if string(recvBuf[:m]) != string(msg) {
		t.Fatalf("payload mismatch")
	}
}

// -----------------------------------------------------------------------
// DualLayer handshake hashes differ from HybridDualLayer (domain binding)
// -----------------------------------------------------------------------

func TestDualVsHybridDual_DifferentHashes(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}
	seed := uint64(0xdeadbeef)

	// Generate static KEM keys for pqXX (same seeds so both DualLayer and Hybrid get same keys)
	diSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x55555555))
	drSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x66666666))
	hiSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x55555555))
	hrSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x66666666))

	// DualLayer with deterministic RNG
	rng1 := clatter.NewDummyRng(seed)
	dOI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite, clatter.WithRNG(rng1))
	dII, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite, clatter.WithRNG(rng1),
		clatter.WithStaticKey(diSKEM))
	rng2 := clatter.NewDummyRng(seed + 1)
	dOR, _ := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite, clatter.WithRNG(rng2))
	dIR, _ := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite, clatter.WithRNG(rng2),
		clatter.WithStaticKey(drSKEM))

	dl1, _ := clatter.NewDualLayerHandshake(dOI, dII, 8192)
	dl2, _ := clatter.NewDualLayerHandshake(dOR, dIR, 8192)

	// HybridDualLayer with same deterministic RNG
	rng3 := clatter.NewDummyRng(seed)
	hOI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite, clatter.WithRNG(rng3))
	hII, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite, clatter.WithRNG(rng3),
		clatter.WithStaticKey(hiSKEM))
	rng4 := clatter.NewDummyRng(seed + 1)
	hOR, _ := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite, clatter.WithRNG(rng4))
	hIR, _ := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite, clatter.WithRNG(rng4),
		clatter.WithStaticKey(hrSKEM))

	hdl1, _ := clatter.NewHybridDualLayerHandshake(hOI, hII, 8192)
	hdl2, _ := clatter.NewHybridDualLayerHandshake(hOR, hIR, 8192)

	buf := make([]byte, 16384)
	payloadBuf := make([]byte, 8192)

	// Drive both to completion
	for !dl1.IsFinished() || !hdl1.IsFinished() {
		if !dl1.IsFinished() {
			if dl1.IsWriteTurn() {
				n, _ := dl1.WriteMessage(nil, buf)
				dl2.ReadMessage(buf[:n], payloadBuf)
			} else {
				n, _ := dl2.WriteMessage(nil, buf)
				dl1.ReadMessage(buf[:n], payloadBuf)
			}
		}
		if !hdl1.IsFinished() {
			if hdl1.IsWriteTurn() {
				n, _ := hdl1.WriteMessage(nil, buf)
				hdl2.ReadMessage(buf[:n], payloadBuf)
			} else {
				n, _ := hdl2.WriteMessage(nil, buf)
				hdl1.ReadMessage(buf[:n], payloadBuf)
			}
		}
	}

	dlTS, _ := dl1.Finalize()
	hdlTS, _ := hdl1.Finalize()
	defer dlTS.Destroy()
	defer hdlTS.Destroy()

	dlHash := hex.EncodeToString(dlTS.GetHandshakeHash())
	hdlHash := hex.EncodeToString(hdlTS.GetHandshakeHash())

	if dlHash == hdlHash {
		t.Fatal("DualLayer and HybridDualLayer should produce DIFFERENT handshake hashes due to domain binding")
	}
}

// -----------------------------------------------------------------------
// Interop vector tests (DualLayer + HybridDualLayer)
// -----------------------------------------------------------------------

// Reconstructed from the Rust Clatter generator conventions (2026-06-11).
// The original skip claimed this needed an FFI bridge; it actually needed
// the generator's exact harness setup, recovered as follows:
//   - ONE shared DummyRng(0xdeadbeef) counter for both sides and both
//     layers (Rust uses a single global counter), drawing in this order:
//     NQ initiator static -> NQ responder static -> KEM initiator static
//     -> KEM responder static -> handshake operations in message order.
//     Empirically confirmed: the first ephemeral matches only after
//     exactly 32+32+64+64 = 192 prefix bytes.
//   - Per Rust Clatter's smoke test convention (tests/src/smoke.rs
//     dual_layer_handshakes), the layers get DIFFERENT prologues: outer
//     "Spinning round and round", inner "Stumbling all around".
//     Verified: H(H(pqXX protocol name) || "Stumbling all around")
//     equals the vectors' recorded h[0] exactly.
//
// Rust dual_layer.rs mixes nothing else into the inner hash at
// construction (verified against source), so go-clatter's composition is
// a faithful port and these vectors exercise it byte-for-byte.
func TestDualLayerHandshake_VectorNN_pqXX(t *testing.T) {
	runDualLayerVectorTest(t, "vectors/dual_nn_pqxx_chacha_sha256.txt", false)
}

func TestHybridDualLayerHandshake_VectorNN_pqXX(t *testing.T) {
	runDualLayerVectorTest(t, "vectors/hybriddual_nn_pqxx_chacha_sha256.txt", true)
}

func runDualLayerVectorTest(t *testing.T, path string, hybrid bool) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open vector file: %v", err)
	}
	defer f.Close()

	// Parse the vector file
	type vectorMsg struct {
		sender string // "initiator" or "responder"
		data   []byte
		h      []byte
	}
	type transportMsg struct {
		sender string
		data   []byte
	}

	var prologue []byte
	var msgs []vectorMsg
	var transportMsgs []transportMsg
	var handshakeHash []byte
	inTransport := false

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	headerDone := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if line == "---" {
			if !headerDone {
				headerDone = true
			} else {
				inTransport = true
			}
			continue
		}

		if !headerDone {
			if strings.HasPrefix(line, "prologue_hex:") {
				hexStr := strings.TrimSpace(strings.TrimPrefix(line, "prologue_hex:"))
				prologue, _ = hex.DecodeString(hexStr)
			}
			continue
		}

		if inTransport {
			if strings.HasPrefix(line, "handshake_hash:") {
				hexStr := strings.TrimSpace(strings.TrimPrefix(line, "handshake_hash:"))
				handshakeHash, _ = hex.DecodeString(hexStr)
				continue
			}
			if strings.HasPrefix(line, "transport[") {
				parts := strings.SplitN(line, " ", 3)
				if len(parts) < 3 {
					continue
				}
				sender := strings.TrimSuffix(parts[1], ":")
				data, _ := hex.DecodeString(strings.TrimSpace(parts[2]))
				transportMsgs = append(transportMsgs, transportMsg{sender: sender, data: data})
			}
			continue
		}

		// Handshake messages
		if strings.HasPrefix(line, "msg[") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) < 3 {
				continue
			}
			sender := strings.TrimSuffix(parts[1], ":")
			data, _ := hex.DecodeString(strings.TrimSpace(parts[2]))
			msgs = append(msgs, vectorMsg{sender: sender, data: data})
		} else if strings.HasPrefix(line, "h[") {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) < 2 {
				continue
			}
			hBytes, _ := hex.DecodeString(strings.TrimSpace(parts[1]))
			if len(msgs) > 0 {
				msgs[len(msgs)-1].h = hBytes
			}
		}
	}

	// Create handshakes with DummyRng
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	// Testing KEM variant: production Encapsulate uses crypto/rand
	// internally; only the Testing variant draws encapsulation entropy
	// from the injected RNG, which vector replay requires.
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768Testing(),
		SKEM:   kem.NewMlKem768Testing(),
	}

	// The Rust vector generator uses ONE global DummyRng counter shared by
	// both sides and both layers, drawing in this order: NQ initiator
	// static -> NQ responder static -> KEM initiator static -> KEM
	// responder static -> handshake operations in message order. The NQ
	// statics are generated even though NN never uses them (the generator
	// always consumes those bytes); the KEM statics are pqXX's static keys.
	// Empirically verified: this order reproduces the vector files
	// byte-for-byte (first ephemeral matches only after exactly
	// 32+32+64+64 = 192 prefix bytes).
	sharedRng := clatter.NewDummyRng(0xdeadbeef)

	if _, err := nqSuite.DH.GenerateKeypair(sharedRng); err != nil {
		t.Fatalf("gen NQ initiator static: %v", err)
	}
	if _, err := nqSuite.DH.GenerateKeypair(sharedRng); err != nil {
		t.Fatalf("gen NQ responder static: %v", err)
	}
	kemI, err := pqSuite.SKEM.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen KEM initiator static: %v", err)
	}
	kemR, err := pqSuite.SKEM.GenerateKeypair(sharedRng)
	if err != nil {
		t.Fatalf("gen KEM responder static: %v", err)
	}

	outerI, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite,
		clatter.WithPrologue(prologue), clatter.WithRNG(sharedRng))
	if err != nil {
		t.Fatalf("outer initiator: %v", err)
	}
	outerR, err := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite,
		clatter.WithPrologue(prologue), clatter.WithRNG(sharedRng))
	if err != nil {
		t.Fatalf("outer responder: %v", err)
	}
	// Inner prologue differs from the outer one per the Rust generator
	// convention (tests/src/smoke.rs dual_layer_handshakes).
	innerPrologue := []byte("Stumbling all around")

	innerI, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite,
		clatter.WithPrologue(innerPrologue), clatter.WithRNG(sharedRng),
		clatter.WithStaticKey(kemI))
	if err != nil {
		t.Fatalf("inner initiator: %v", err)
	}
	innerR, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite,
		clatter.WithPrologue(innerPrologue), clatter.WithRNG(sharedRng),
		clatter.WithStaticKey(kemR))
	if err != nil {
		t.Fatalf("inner responder: %v", err)
	}

	var alice, bob clatter.Handshaker
	if hybrid {
		a, err := clatter.NewHybridDualLayerHandshake(outerI, innerI, 8192)
		if err != nil {
			t.Fatalf("hybrid dual alice: %v", err)
		}
		b, err := clatter.NewHybridDualLayerHandshake(outerR, innerR, 8192)
		if err != nil {
			t.Fatalf("hybrid dual bob: %v", err)
		}
		alice = a
		bob = b
	} else {
		a, err := clatter.NewDualLayerHandshake(outerI, innerI, 8192)
		if err != nil {
			t.Fatalf("dual alice: %v", err)
		}
		b, err := clatter.NewDualLayerHandshake(outerR, innerR, 8192)
		if err != nil {
			t.Fatalf("dual bob: %v", err)
		}
		alice = a
		bob = b
	}
	defer alice.Destroy()
	defer bob.Destroy()

	buf := make([]byte, 16384)
	payloadBuf := make([]byte, 8192)

	// Process each message
	for idx, vm := range msgs {
		var writer, reader clatter.Handshaker
		if vm.sender == "initiator" {
			writer = alice
			reader = bob
		} else {
			writer = bob
			reader = alice
		}

		n, werr := writer.WriteMessage(nil, buf)
		if werr != nil {
			t.Fatalf("msg[%d] %s write: %v", idx, vm.sender, werr)
		}

		// Compare wire bytes
		got := hex.EncodeToString(buf[:n])
		want := hex.EncodeToString(vm.data)
		if got != want {
			t.Fatalf("msg[%d] %s wire mismatch:\n  got:  %s\n  want: %s",
				idx, vm.sender, got[:min(80, len(got))], want[:min(80, len(want))])
		}

		_, rerr := reader.ReadMessage(buf[:n], payloadBuf)
		if rerr != nil {
			t.Fatalf("msg[%d] %s read: %v", idx, vm.sender, rerr)
		}

		// Compare handshake hash after this message
		if vm.h != nil {
			writerH := hex.EncodeToString(writer.GetHandshakeHash())
			readerH := hex.EncodeToString(reader.GetHandshakeHash())
			wantH := hex.EncodeToString(vm.h)

			// After outer completes, hash comes from inner which may differ between writer/reader check
			// For the vector we compare the writer's hash against expected
			if writerH != wantH {
				t.Fatalf("msg[%d] h mismatch (writer):\n  got:  %s\n  want: %s", idx, writerH, wantH)
			}
			_ = readerH
		}
	}

	// Finalize
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

	// Check handshake hash
	if handshakeHash != nil {
		gotH := hex.EncodeToString(aliceTS.GetHandshakeHash())
		wantH := hex.EncodeToString(handshakeHash)
		if gotH != wantH {
			t.Fatalf("handshake_hash mismatch:\n  got:  %s\n  want: %s", gotH, wantH)
		}
	}

	// Transport messages
	sendBuf := make([]byte, 4096)
	recvBuf := make([]byte, 4096)
	for idx, tm := range transportMsgs {
		var sender, receiver *clatter.TransportState
		if tm.sender == "initiator" {
			sender = aliceTS
			receiver = bobTS
		} else {
			sender = bobTS
			receiver = aliceTS
		}

		// Determine payload from expected ciphertext: payload = len(ct) - TagLen
		payloadLen := len(tm.data) - clatter.TagLen
		payload := make([]byte, payloadLen)
		// Generator payloads, recovered by decrypting the vector transport
		// ciphertexts with the replayed session keys (2026-06-11).
		switch idx {
		case 0:
			copy(payload, []byte("Scream without a sound"))
		case 1:
			copy(payload, []byte("Flying off the handle"))
		case 2:
			copy(payload, []byte("Eugene gene the dance machine"))
		}

		n, serr := sender.Send(payload[:payloadLen], sendBuf)
		if serr != nil {
			t.Fatalf("transport[%d] send: %v", idx, serr)
		}

		got := hex.EncodeToString(sendBuf[:n])
		want := hex.EncodeToString(tm.data)
		if got != want {
			t.Fatalf("transport[%d] ciphertext mismatch:\n  got:  %s\n  want: %s", idx, got, want)
		}

		m, rerr := receiver.Receive(sendBuf[:n], recvBuf)
		if rerr != nil {
			t.Fatalf("transport[%d] receive: %v", idx, rerr)
		}
		if m != payloadLen {
			t.Fatalf("transport[%d] payload length: got %d, want %d", idx, m, payloadLen)
		}
	}
}

// -----------------------------------------------------------------------
// TransportState tests
// -----------------------------------------------------------------------

func TestTransportState_OneWayViolation(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xAAAAAAAA))
	i, _ := clatter.NewNqHandshake(clatter.PatternN, true, suite,
		clatter.WithRemoteStatic(rKP.Public))
	r, _ := clatter.NewNqHandshake(clatter.PatternN, false, suite,
		clatter.WithStaticKey(rKP))

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	// Responder should not be able to send in one-way
	_, err := rTS.Send([]byte("test"), buf)
	if !errors.Is(err, clatter.ErrOneWayViolation) {
		t.Fatalf("responder send should fail with OneWayViolation, got: %v", err)
	}

	// Initiator should not be able to receive in one-way
	_, err = iTS.Receive(buf[:32], payloadBuf)
	if !errors.Is(err, clatter.ErrOneWayViolation) {
		t.Fatalf("initiator receive should fail with OneWayViolation, got: %v", err)
	}
}

func TestTransportState_Rekey(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	// Send a message pre-rekey
	msg := []byte("before rekey")
	n, _ = iTS.Send(msg, buf)
	rTS.Receive(buf[:n], payloadBuf)

	// Rekey both sides
	if err := iTS.RekeySender(); err != nil {
		t.Fatalf("rekey sender: %v", err)
	}
	if err := rTS.RekeyReceiver(); err != nil {
		t.Fatalf("rekey receiver: %v", err)
	}

	// Nonce should NOT have reset
	if iTS.SendingNonce() == 0 {
		t.Fatal("nonce should not reset after rekey")
	}

	// Send after rekey should work
	msg2 := []byte("after rekey")
	n, err := iTS.Send(msg2, buf)
	if err != nil {
		t.Fatalf("send after rekey: %v", err)
	}
	m, err := rTS.Receive(buf[:n], payloadBuf)
	if err != nil {
		t.Fatalf("receive after rekey: %v", err)
	}
	if string(payloadBuf[:m]) != string(msg2) {
		t.Fatalf("payload mismatch after rekey")
	}
}

func TestTransportState_NonceManagement(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	// Initial nonces = 0
	if iTS.SendingNonce() != 0 || iTS.ReceivingNonce() != 0 {
		t.Fatal("initial nonces should be 0")
	}

	// Send increments sending nonce
	msg := []byte("test")
	n, _ = iTS.Send(msg, buf)
	rTS.Receive(buf[:n], payloadBuf)

	if iTS.SendingNonce() != 1 {
		t.Fatalf("sending nonce should be 1, got %d", iTS.SendingNonce())
	}
	if rTS.ReceivingNonce() != 1 {
		t.Fatalf("receiving nonce should be 1, got %d", rTS.ReceivingNonce())
	}

	// SetReceivingNonce
	iTS.SetReceivingNonce(42)
	if iTS.ReceivingNonce() != 42 {
		t.Fatalf("receiving nonce should be 42, got %d", iTS.ReceivingNonce())
	}
}

func TestTransportState_Destroy(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	ts, _ := i.Finalize()

	ts.Destroy()

	if !ts.IsDestroyed() {
		t.Fatal("should be destroyed")
	}
	_, err := ts.Send([]byte("test"), buf)
	if !errors.Is(err, clatter.ErrDestroyed) {
		t.Fatalf("send after destroy should return ErrDestroyed, got: %v", err)
	}
}

func TestTransportState_Take(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	ts, _ := i.Finalize()

	i2r, r2i := ts.Take()
	if i2r == nil || r2i == nil {
		t.Fatal("Take() should return non-nil CipherStates")
	}
	if !ts.IsDestroyed() {
		t.Fatal("Take() should mark TransportState as destroyed")
	}

	// Clean up
	i2r.Destroy()
	r2i.Destroy()
}

func TestTransportState_SendInPlace(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	// SendInPlace
	msg := []byte("Hello in-place!")
	inPlaceBuf := make([]byte, 2048)
	copy(inPlaceBuf, msg)

	n, err := iTS.SendInPlace(inPlaceBuf, len(msg))
	if err != nil {
		t.Fatalf("send in-place: %v", err)
	}

	// Receive
	recvBuf := make([]byte, 2048)
	m, err := rTS.Receive(inPlaceBuf[:n], recvBuf)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if string(recvBuf[:m]) != string(msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recvBuf[:m], msg)
	}
}

func TestTransportState_ReceiveInPlace(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	// Send normally
	msg := []byte("Hello in-place receive!")
	sendBuf := make([]byte, 2048)
	n, _ = iTS.Send(msg, sendBuf)

	// ReceiveInPlace
	recvBuf := make([]byte, 2048)
	copy(recvBuf, sendBuf[:n])
	m, err := rTS.ReceiveInPlace(recvBuf, n)
	if err != nil {
		t.Fatalf("receive in-place: %v", err)
	}
	if string(recvBuf[:m]) != string(msg) {
		t.Fatalf("payload mismatch: got %q, want %q", recvBuf[:m], msg)
	}
}

func TestTransportState_HandshakeHash(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()
	rTS, _ := r.Finalize()
	defer rTS.Destroy()

	iH := iTS.GetHandshakeHash()
	rH := rTS.GetHandshakeHash()

	if iH == nil || rH == nil {
		t.Fatal("handshake hash should not be nil")
	}
	if hex.EncodeToString(iH) != hex.EncodeToString(rH) {
		t.Fatal("handshake hashes should match between initiator and responder")
	}
}

// -----------------------------------------------------------------------
// DualLayer PushPSK error test
// -----------------------------------------------------------------------

func TestDualLayerHandshake_PushPSK_Error(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	outerI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	innerI, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite)
	dl, _ := clatter.NewDualLayerHandshake(outerI, innerI, 8192)
	defer dl.Destroy()

	err := dl.PushPSK(make([]byte, 32))
	if err == nil {
		t.Fatal("PushPSK should return error for dual-layer")
	}
}

func TestDualLayerHandshake_DoubleFinalize(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	iSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x11111111))
	rSKEM, _ := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(0x22222222))

	outerI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	outerR, _ := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)
	innerI, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite,
		clatter.WithStaticKey(iSKEM))
	innerR, _ := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuite,
		clatter.WithStaticKey(rSKEM))

	alice, _ := clatter.NewDualLayerHandshake(outerI, innerI, 8192)
	bob, _ := clatter.NewDualLayerHandshake(outerR, innerR, 8192)

	buf := make([]byte, 16384)
	payloadBuf := make([]byte, 8192)

	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, _ := alice.WriteMessage(nil, buf)
			bob.ReadMessage(buf[:n], payloadBuf)
		} else {
			n, _ := bob.WriteMessage(nil, buf)
			alice.ReadMessage(buf[:n], payloadBuf)
		}
	}

	// First finalize should succeed
	ts, err := alice.Finalize()
	if err != nil {
		t.Fatalf("first finalize: %v", err)
	}
	defer ts.Destroy()

	// Second finalize should return ErrAlreadyFinished
	_, err = alice.Finalize()
	if !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("second finalize should return ErrAlreadyFinished, got: %v", err)
	}
}

func TestDualLayerHandshake_WriteAfterDestroy(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	outerI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	innerI, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuite)
	dl, _ := clatter.NewDualLayerHandshake(outerI, innerI, 8192)

	dl.Destroy()

	buf := make([]byte, 8192)
	_, err := dl.WriteMessage(nil, buf)
	if !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("WriteMessage after Destroy should return ErrAlreadyFinished, got: %v", err)
	}
	_, err = dl.ReadMessage(buf[:32], buf)
	if !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("ReadMessage after Destroy should return ErrAlreadyFinished, got: %v", err)
	}
}

func TestDualLayerHandshake_MismatchedRoles(t *testing.T) {
	nqSuite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	// Both initiator = OK
	outerI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	innerI, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)
	_, err := clatter.NewDualLayerHandshake(outerI, innerI, 8192)
	if err != nil {
		t.Fatalf("same role should succeed: %v", err)
	}

	// Mismatched: outer=initiator, inner=responder
	outerI2, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	innerR, _ := clatter.NewPqHandshake(clatter.PatternPqNN, false, pqSuite)
	_, err = clatter.NewDualLayerHandshake(outerI2, innerR, 8192)
	if err == nil {
		t.Fatal("mismatched roles should fail")
	}
}

func TestDualLayerHandshake_OneWayOuterRejected(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
	pqSuite := clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}

	rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xAAAAAAAA))
	outerN, _ := clatter.NewNqHandshake(clatter.PatternN, true, suite,
		clatter.WithRemoteStatic(rKP.Public))
	innerNN, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)

	_, err := clatter.NewDualLayerHandshake(outerN, innerNN, 8192)
	if err == nil {
		t.Fatal("one-way outer pattern should be rejected")
	}
}

func TestTransportState_SendBufferTooSmall(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	i, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	r, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 8192)
	payloadBuf := make([]byte, 8192)

	n, _ := i.WriteMessage(nil, buf)
	r.ReadMessage(buf[:n], payloadBuf)
	n, _ = r.WriteMessage(nil, buf)
	i.ReadMessage(buf[:n], payloadBuf)

	iTS, _ := i.Finalize()
	defer iTS.Destroy()

	// Buffer too small for message + tag
	msg := []byte("test message that needs space")
	tinyBuf := make([]byte, 5)
	_, err := iTS.Send(msg, tinyBuf)
	if !errors.Is(err, clatter.ErrBufferTooSmall) {
		t.Fatalf("should return ErrBufferTooSmall, got: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
