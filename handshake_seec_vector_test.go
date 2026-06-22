package clatter_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// SEEC-on pinned transcripts. Every byte is hand-derivable from:
// DummyRng(0xdeadbeef) shared by both sides, the fixed SEEC secret
// 0x01..0x20 through SEECPRF(SHA-256) shared by both sides, FIPS 203
// derandomized encapsulation via the PRODUCTION adapters'
// EncapsulateWithCoins, and the recipe in setupSeecVectorPair. There is
// no cross-implementation source for these vectors (nyquist's SEEC
// variant is TupleHash-based and untested upstream; Rust Clatter has no
// SEEC); they are self-generated pins, frozen with the SEEC wiring.
//
// Regenerate ONLY for a deliberate, documented construction change:
//
//	GO_CLATTER_GEN_SEEC_VECTORS=1 go test -run TestGenerateSEECVectors -v
//
// A mismatch on unchanged files means the WIRING changed - fix the code,
// do not regenerate the pins.

// seecVectorPSK is the PSK for the psk-pattern vector (32 bytes, the
// repository's standard fuzz/test PSK).
var seecVectorPSK = []byte("Trapped inside this Octavarium!!")

var seecVectorTransportPayloads = []string{
	"Scream without a sound",
	"Flying off the handle",
	"Eugene gene the dance machine",
}

// setupSeecVectorPair builds the deterministic SEEC-on handshake pair for
// a vector scenario. ONE DummyRng and ONE SEECPRF are shared by both
// sides; statics (when the pattern uses them) are drawn from the shared
// rng in the order alice-then-bob (DH before KEM for hybrid), matching
// the existing vector-generation convention.
func setupSeecVectorPair(t *testing.T, family, patternName string, secret []byte) (clatter.Handshaker, clatter.Handshaker) {
	t.Helper()

	sharedRng := clatter.NewDummyRng(0xdeadbeef)
	seec, err := clatter.NewSEECPRF(hash.NewSha256(), secret)
	if err != nil {
		t.Fatalf("NewSEECPRF: %v", err)
	}

	pattern := lookupPattern(t, patternName)

	switch family {
	case "pq":
		suite := clatter.CipherSuite{
			EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
			Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		}
		iOpts := []clatter.Option{clatter.WithRNG(sharedRng), clatter.WithSEEC(seec)}
		rOpts := []clatter.Option{clatter.WithRNG(sharedRng), clatter.WithSEEC(seec)}
		switch patternName {
		case "pqXX":
			aS, err := suite.SKEM.GenerateKeypair(sharedRng)
			if err != nil {
				t.Fatal(err)
			}
			bS, err := suite.SKEM.GenerateKeypair(sharedRng)
			if err != nil {
				t.Fatal(err)
			}
			iOpts = append(iOpts, clatter.WithStaticKey(aS))
			rOpts = append(rOpts, clatter.WithStaticKey(bS))
		case "pqNNpsk2":
			// No statics; PSKs pushed after construction.
		default:
			t.Fatalf("no SEEC vector recipe for pattern %s", patternName)
		}
		a, err := clatter.NewPqHandshake(pattern, true, suite, iOpts...)
		if err != nil {
			t.Fatal(err)
		}
		b, err := clatter.NewPqHandshake(pattern, false, suite, rOpts...)
		if err != nil {
			t.Fatal(err)
		}
		if pattern.HasPSK() {
			if err := a.PushPSK(seecVectorPSK); err != nil {
				t.Fatal(err)
			}
			if err := b.PushPSK(seecVectorPSK); err != nil {
				t.Fatal(err)
			}
		}
		return a, b

	case "hybrid":
		suite := clatter.CipherSuite{
			DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
			Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
		}
		if patternName != "hybridXX" {
			t.Fatalf("no SEEC vector recipe for pattern %s", patternName)
		}
		aDH, err := suite.DH.GenerateKeypair(sharedRng)
		if err != nil {
			t.Fatal(err)
		}
		bDH, err := suite.DH.GenerateKeypair(sharedRng)
		if err != nil {
			t.Fatal(err)
		}
		aKEM, err := suite.SKEM.GenerateKeypair(sharedRng)
		if err != nil {
			t.Fatal(err)
		}
		bKEM, err := suite.SKEM.GenerateKeypair(sharedRng)
		if err != nil {
			t.Fatal(err)
		}
		a, err := clatter.NewHybridHandshake(pattern, true, suite,
			clatter.WithStaticKey(aDH), clatter.WithStaticKEMKey(aKEM),
			clatter.WithRNG(sharedRng), clatter.WithSEEC(seec))
		if err != nil {
			t.Fatal(err)
		}
		b, err := clatter.NewHybridHandshake(pattern, false, suite,
			clatter.WithStaticKey(bDH), clatter.WithStaticKEMKey(bKEM),
			clatter.WithRNG(sharedRng), clatter.WithSEEC(seec))
		if err != nil {
			t.Fatal(err)
		}
		return a, b
	}
	t.Fatalf("unknown family %s", family)
	return nil, nil
}

type seecVectorScenario struct {
	path     string
	family   string
	pattern  string
	wantMsgs int
}

var seecVectorScenarios = []seecVectorScenario{
	{"vectors/seec_pq_xx_mlkem768_chacha_sha256.txt", "pq", "pqXX", 4},
	{"vectors/seec_pq_nnpsk2_mlkem768_chacha_sha256.txt", "pq", "pqNNpsk2", 2},
	{"vectors/seec_hybrid_xx_x25519_mlkem768_chacha_sha256.txt", "hybrid", "hybridXX", 4},
}

func TestSEECVector_PqXX(t *testing.T) {
	runSeecVectorTest(t, seecVectorScenarios[0])
}

func TestSEECVector_PqNNpsk2(t *testing.T) {
	runSeecVectorTest(t, seecVectorScenarios[1])
}

func TestSEECVector_HybridXX(t *testing.T) {
	runSeecVectorTest(t, seecVectorScenarios[2])
}

func runSeecVectorTest(t *testing.T, sc seecVectorScenario) {
	t.Helper()
	v := parseVectorFile(t, sc.path)
	assertVectorShape(t, sc.path, v, sc.wantMsgs)
	if v.pattern != sc.pattern {
		t.Fatalf("%s: pattern %s, want %s", sc.path, v.pattern, sc.pattern)
	}

	// Honor the file's declared SEEC parameters (load-bearing: editing
	// seec_secret_hex/seec_hash in the file changes the handshake and
	// fails the pins). The recipe currently fixes SHA-256 and the 32-byte
	// 0x01..0x20 secret; assert the file agrees before using its values.
	if v.seecHash != "SHA256" {
		t.Fatalf("%s: seec_hash %q, want SHA256", sc.path, v.seecHash)
	}
	if !bytes.Equal(v.seecSecret, seecTestSecret()) {
		t.Fatalf("%s: seec_secret_hex does not match the test secret", sc.path)
	}

	initiator, responder := setupSeecVectorPair(t, sc.family, sc.pattern, v.seecSecret)

	buf := make([]byte, clatter.MaxMessageLen)
	payloadBuf := make([]byte, clatter.MaxMessageLen)

	for _, vm := range v.messages {
		var writer, reader clatter.Handshaker
		if vm.sender == "initiator" {
			writer, reader = initiator, responder
		} else {
			writer, reader = responder, initiator
		}

		n, err := writer.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("msg[%d] %s write: %v", vm.index, vm.sender, err)
		}
		if got, want := hex.EncodeToString(buf[:n]), hex.EncodeToString(vm.msgHex); got != want {
			t.Fatalf("msg[%d] mismatch:\n  got:  %s\n  want: %s", vm.index, got, want)
		}
		if _, err := reader.ReadMessage(buf[:n], payloadBuf); err != nil {
			t.Fatalf("msg[%d] %s read: %v", vm.index, vm.sender, err)
		}

		wantHash := hex.EncodeToString(vm.hashHex)
		if got := hex.EncodeToString(writer.GetHandshakeHash()); got != wantHash {
			t.Fatalf("h[%d] writer mismatch:\n  got:  %s\n  want: %s", vm.index, got, wantHash)
		}
		if got := hex.EncodeToString(reader.GetHandshakeHash()); got != wantHash {
			t.Fatalf("h[%d] reader mismatch:\n  got:  %s\n  want: %s", vm.index, got, wantHash)
		}
	}

	if got, want := hex.EncodeToString(initiator.GetHandshakeHash()), hex.EncodeToString(v.hsHash); got != want {
		t.Fatalf("final hash mismatch:\n  got:  %s\n  want: %s", got, want)
	}

	tsI, err := initiator.Finalize()
	if err != nil {
		t.Fatalf("initiator Finalize: %v", err)
	}
	tsR, err := responder.Finalize()
	if err != nil {
		t.Fatalf("responder Finalize: %v", err)
	}
	defer tsI.Destroy()
	defer tsR.Destroy()

	for _, vt := range v.transports {
		var sender, receiver *clatter.TransportState
		if vt.sender == "initiator" {
			sender, receiver = tsI, tsR
		} else {
			sender, receiver = tsR, tsI
		}
		payload := []byte(seecVectorTransportPayloads[vt.index])

		n, err := sender.Send(payload, buf)
		if err != nil {
			t.Fatalf("transport[%d] send: %v", vt.index, err)
		}
		if got, want := hex.EncodeToString(buf[:n]), hex.EncodeToString(vt.data); got != want {
			t.Fatalf("transport[%d] mismatch:\n  got:  %s\n  want: %s", vt.index, got, want)
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

// TestGenerateSEECVectors regenerates the SEEC-on vector files. Inert
// unless GO_CLATTER_GEN_SEEC_VECTORS=1. The emitted files pin the frozen
// construction; regenerate only for a deliberate, documented change.
func TestGenerateSEECVectors(t *testing.T) {
	if os.Getenv("GO_CLATTER_GEN_SEEC_VECTORS") != "1" {
		t.Skip("set GO_CLATTER_GEN_SEEC_VECTORS=1 to regenerate SEEC vector files")
	}

	for _, sc := range seecVectorScenarios {
		initiator, responder := setupSeecVectorPair(t, sc.family, sc.pattern, seecTestSecret())

		var sb strings.Builder
		base := strings.TrimSuffix(strings.TrimPrefix(sc.path, "vectors/"), ".txt")
		fmt.Fprintf(&sb, "# Vector: %s\n", base)
		fmt.Fprintf(&sb, "# SEEC-on pinned transcript. Recipe: shared DummyRng(0xdeadbeef),\n")
		fmt.Fprintf(&sb, "# shared SEECPRF(SHA-256, secret 0x01..0x20), production ML-KEM-768\n")
		fmt.Fprintf(&sb, "# adapters (coins via EncapsulateWithCoins). See handshake_seec_vector_test.go.\n")
		fmt.Fprintf(&sb, "pattern: %s\n", sc.pattern)
		if sc.family == "hybrid" {
			fmt.Fprintf(&sb, "dh: 25519\n")
		}
		fmt.Fprintf(&sb, "kem: MlKem768\n")
		fmt.Fprintf(&sb, "cipher: ChaChaPoly\n")
		fmt.Fprintf(&sb, "hash: SHA256\n")
		fmt.Fprintf(&sb, "seec_hash: SHA256\n")
		fmt.Fprintf(&sb, "seec_secret_hex: %s\n", hex.EncodeToString(seecTestSecret()))
		fmt.Fprintf(&sb, "---\n")

		buf := make([]byte, clatter.MaxMessageLen)
		out := make([]byte, clatter.MaxMessageLen)
		idx := 0
		for !initiator.IsFinished() || !responder.IsFinished() {
			var w, r clatter.Handshaker
			var sender string
			if initiator.IsWriteTurn() {
				w, r, sender = initiator, responder, "initiator"
			} else {
				w, r, sender = responder, initiator, "responder"
			}
			n, err := w.WriteMessage(nil, buf)
			if err != nil {
				t.Fatalf("%s write: %v", sc.path, err)
			}
			fmt.Fprintf(&sb, "msg[%d] %s: %s\n", idx, sender, hex.EncodeToString(buf[:n]))
			if _, err := r.ReadMessage(buf[:n], out); err != nil {
				t.Fatalf("%s read: %v", sc.path, err)
			}
			fmt.Fprintf(&sb, "h[%d]: %s\n", idx, hex.EncodeToString(w.GetHandshakeHash()))
			idx++
		}

		fmt.Fprintf(&sb, "---\n")
		fmt.Fprintf(&sb, "handshake_hash: %s\n", hex.EncodeToString(initiator.GetHandshakeHash()))

		tsI, err := initiator.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		tsR, err := responder.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		senders := []struct {
			ts   *clatter.TransportState
			name string
		}{{tsI, "initiator"}, {tsR, "responder"}, {tsI, "initiator"}}
		for i, s := range senders {
			n, err := s.ts.Send([]byte(seecVectorTransportPayloads[i]), buf)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&sb, "transport[%d] %s: %s\n", i, s.name, hex.EncodeToString(buf[:n]))
		}
		tsI.Destroy()
		tsR.Destroy()

		if err := os.WriteFile(sc.path, []byte(sb.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d messages)", sc.path, idx)
	}
}
