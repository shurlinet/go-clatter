package clatter_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// --- shared helpers ---

// seecTestSecret returns the fixed 32-byte secret 0x01..0x20 used by every
// deterministic SEEC handshake test (same byte pattern as the frozen
// SEECPRF regression vectors).
func seecTestSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

func mustTestSEEC(t *testing.T) *clatter.SEECPRF {
	t.Helper()
	s, err := clatter.NewSEECPRF(hash.NewSha256(), seecTestSecret())
	if err != nil {
		t.Fatalf("NewSEECPRF: %v", err)
	}
	return s
}

// spyRng records the width of every Read call and delegates.
type spyRng struct {
	inner io.Reader
	calls []int
}

func (s *spyRng) Read(p []byte) (int, error) {
	s.calls = append(s.calls, len(p))
	return s.inner.Read(p)
}

// zeroRng is a dead rng: endless zero bytes. The worst-case rng SEEC is
// designed around.
type zeroRng struct{}

func (zeroRng) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// runHandshakeRecorded drives a handshake pair to completion with nil
// payloads, returning message lengths, per-message SHA-256 digests, and
// the final handshake hash.
func runHandshakeRecorded(t *testing.T, a, b clatter.Handshaker) (lens []int, digests []string, finalHash string) {
	t.Helper()
	buf := make([]byte, clatter.MaxMessageLen)
	out := make([]byte, clatter.MaxMessageLen)

	for !a.IsFinished() || !b.IsFinished() {
		var w, r clatter.Handshaker
		if a.IsWriteTurn() {
			w, r = a, b
		} else {
			w, r = b, a
		}
		n, err := w.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		sum := sha256.Sum256(buf[:n])
		lens = append(lens, n)
		digests = append(digests, hex.EncodeToString(sum[:]))
		if _, err := r.ReadMessage(buf[:n], out); err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	return lens, digests, hex.EncodeToString(a.GetHandshakeHash())
}

// completeAndVerifyTransport finalizes both sides and proves transport
// messages flow in both directions.
func completeAndVerifyTransport(t *testing.T, a, b clatter.Handshaker) {
	t.Helper()
	tsA, err := a.Finalize()
	if err != nil {
		t.Fatalf("finalize a: %v", err)
	}
	tsB, err := b.Finalize()
	if err != nil {
		t.Fatalf("finalize b: %v", err)
	}
	defer tsA.Destroy()
	defer tsB.Destroy()

	buf := make([]byte, 4096)
	out := make([]byte, 4096)
	for i, m := range []struct {
		s, r    *clatter.TransportState
		payload string
	}{
		{tsA, tsB, "Scream without a sound"},
		{tsB, tsA, "Flying off the handle"},
	} {
		n, err := m.s.Send([]byte(m.payload), buf)
		if err != nil {
			t.Fatalf("transport[%d] send: %v", i, err)
		}
		pn, err := m.r.Receive(buf[:n], out)
		if err != nil {
			t.Fatalf("transport[%d] receive: %v", i, err)
		}
		if string(out[:pn]) != m.payload {
			t.Fatalf("transport[%d] payload mismatch", i)
		}
	}
}

// --- v0.5.0 bit-identity pins (C-10i/C-10ii/C-17) ---

// The expected values below were generated from the v0.5.0 TAG CHECKOUT
// (git worktree at addfac1) BEFORE any Batch 2 edit existed, so they
// cannot be circular. They pin, for one handshake per family with SEEC
// ABSENT: the exact rng draw-width sequence (catches accidental rng
// wrapping that transcript pins structurally cannot), every message
// length and SHA-256, and the final handshake hash.
//
// Recipe: shared spy DummyRng(0xdeadbeef) for both sides; statics from
// DummyRng(1)/DummyRng(2) (and DummyRng(3)/DummyRng(4) for hybrid KEM
// statics); ChaChaPoly+SHA256; testing-mode ML-KEM-768; XX pattern; nil
// payloads.
//
// Draw-order notes (verified against the pattern definitions): pqXX's
// responder never generates an ephemeral (its message 2 starts with Ekem),
// and hybridXX's responder message is {Ekem, E, ...}, so its encaps draw
// (32) precedes its keygens (32 DH + 64 KEM).
func TestSEEC_OffBitIdentityV050(t *testing.T) {
	type pin struct {
		name      string
		draws     []int
		lens      []int
		digests   []string
		finalHash string
	}

	pins := []pin{
		{
			name:  "NQ_XX",
			draws: []int{32, 32},
			lens:  []int{32, 96, 64},
			digests: []string{
				"7cee2a2ebd8a290765aad70aaad1c6595815184298ddae2bea94e57814ddad6a",
				"7f494d5518ee7f6ab7d1799a2119cf2992eb2bbd37ef758b0db50a483c1691fb",
				"80eaa577d4883e29b2cf87940f7ed52a1d4eb7723d8c95091203f3a001a9b45a",
			},
			finalHash: "b1cbbb0d9f19734b7bf1fe85ff76e071254b8ff1ba3029ee0bf5da8623aae597",
		},
		{
			name:  "PQ_XX",
			draws: []int{64, 32, 32, 32},
			lens:  []int{1184, 2304, 2320, 1120},
			digests: []string{
				"62c5ff7440a8a0716a04faea8eeb67785887659c71560cc7234dd1c538c3e152",
				"5557eb85541e747d638034a07c17ca22c37a296e31fe3f066e1c41aa8d0e8ae0",
				"47e8c4498c95dcf149a695fd07ff1d388702cb97d44462241efa9c82173670dc",
				"2ddfd305c995079d9efbdcecfb7ed0c09cea6ba64dcce9ab5525d84f96efd2a9",
			},
			finalHash: "4cd757e8630494249ff21dbd90a353b1547a120208de12190504725387b18591",
		},
		{
			name:  "HYBRID_XX",
			draws: []int{32, 64, 32, 32, 64, 32, 32},
			lens:  []int{1216, 3568, 2368, 1120},
			digests: []string{
				"dee74bba4c4b358d3575d4d434fe9620280a90e991e38d0a5b2c8dc410f09e6a",
				"b997abd68986a96512ff714d3782e22fd6291c3ecd95cd645cc7ee4f6399e8bb",
				"02abe051b537613045ae87f5fe21662e28ec46388a434ac3008ecf335cc58346",
				"58c01edc0bffbe8f05d38c0598f65708a36fa9e92ec711f15c7dac20be1af847",
			},
			finalHash: "c79589f752fa82098b5d08a716ea5e0f0451340f1e34c62d03a6fcde8a3fcdf4",
		},
	}

	nqSuiteV := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqSuiteV := clatter.CipherSuite{EKEM: kem.NewMlKem768Testing(), SKEM: kem.NewMlKem768Testing(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hySuiteV := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768Testing(), SKEM: kem.NewMlKem768Testing(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	builders := map[string]func(spy *spyRng) (clatter.Handshaker, clatter.Handshaker){
		"NQ_XX": func(spy *spyRng) (clatter.Handshaker, clatter.Handshaker) {
			aS, _ := nqSuiteV.DH.GenerateKeypair(clatter.NewDummyRng(1))
			bS, _ := nqSuiteV.DH.GenerateKeypair(clatter.NewDummyRng(2))
			a, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqSuiteV,
				clatter.WithStaticKey(aS), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			b, err := clatter.NewNqHandshake(clatter.PatternXX, false, nqSuiteV,
				clatter.WithStaticKey(bS), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		},
		"PQ_XX": func(spy *spyRng) (clatter.Handshaker, clatter.Handshaker) {
			aS, _ := pqSuiteV.SKEM.GenerateKeypair(clatter.NewDummyRng(1))
			bS, _ := pqSuiteV.SKEM.GenerateKeypair(clatter.NewDummyRng(2))
			a, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqSuiteV,
				clatter.WithStaticKey(aS), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			b, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, pqSuiteV,
				clatter.WithStaticKey(bS), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		},
		"HYBRID_XX": func(spy *spyRng) (clatter.Handshaker, clatter.Handshaker) {
			aDH, _ := hySuiteV.DH.GenerateKeypair(clatter.NewDummyRng(1))
			bDH, _ := hySuiteV.DH.GenerateKeypair(clatter.NewDummyRng(2))
			aKEM, _ := hySuiteV.SKEM.GenerateKeypair(clatter.NewDummyRng(3))
			bKEM, _ := hySuiteV.SKEM.GenerateKeypair(clatter.NewDummyRng(4))
			a, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hySuiteV,
				clatter.WithStaticKey(aDH), clatter.WithStaticKEMKey(aKEM), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			b, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, false, hySuiteV,
				clatter.WithStaticKey(bDH), clatter.WithStaticKEMKey(bKEM), clatter.WithRNG(spy))
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		},
	}

	for _, p := range pins {
		t.Run(p.name, func(t *testing.T) {
			spy := &spyRng{inner: clatter.NewDummyRng(0xdeadbeef)}
			a, b := builders[p.name](spy)

			lens, digests, finalHash := runHandshakeRecorded(t, a, b)

			if len(spy.calls) != len(p.draws) {
				t.Fatalf("rng draw sequence %v, want v0.5.0's %v", spy.calls, p.draws)
			}
			for i := range p.draws {
				if spy.calls[i] != p.draws[i] {
					t.Fatalf("rng draw sequence %v, want v0.5.0's %v", spy.calls, p.draws)
				}
			}
			for i := range p.lens {
				if i >= len(lens) || lens[i] != p.lens[i] {
					t.Fatalf("message lengths %v, want v0.5.0's %v", lens, p.lens)
				}
				if digests[i] != p.digests[i] {
					t.Fatalf("msg[%d] SHA-256 %s, want v0.5.0's %s", i, digests[i], p.digests[i])
				}
			}
			if finalHash != p.finalHash {
				t.Fatalf("final handshake hash %s, want v0.5.0's %s", finalHash, p.finalHash)
			}
		})
	}
}

// TestSEEC_OnChangesCoins makes the central claim explicit rather than
// inferred: with the SAME rng stream, turning SEEC ON changes the
// generated coins (and therefore the wire bytes). Two pqNN initiators
// share the same DummyRng seed; the first message (the ephemeral KEM
// public key, whose 64-byte seed is keygen entropy) must differ between
// SEEC-off (seed = 64 raw rng bytes) and SEEC-on (seed = HKDF of the
// secret and 32 fresh rng bytes). Without this, "SEEC changes the coins"
// holds only by inference from the SEEC-on vectors being reproducible.
func TestSEEC_OnChangesCoins(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}

	writeFirst := func(opts ...clatter.Option) []byte {
		a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, opts...)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, clatter.MaxMessageLen)
		n, err := a.WriteMessage(nil, buf)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out
	}

	off := writeFirst(clatter.WithRNG(clatter.NewDummyRng(0xdeadbeef)))
	on := writeFirst(clatter.WithRNG(clatter.NewDummyRng(0xdeadbeef)), clatter.WithSEEC(mustTestSEEC(t)))

	if len(off) != len(on) {
		t.Fatalf("SEEC changed the message LENGTH (%d vs %d): SEEC must be wire-invisible in framing", len(off), len(on))
	}
	if bytes.Equal(off, on) {
		t.Fatal("SEEC-on produced the same first message as SEEC-off under the same rng: SEEC is not actually hedging the keygen coins")
	}
}

// --- SEEC-on <-> SEEC-off interop (D-6, SEEC-27 transcript invisibility) ---

// TestSEEC_InteropWithNonSEECPeer proves SEEC is fully hidden from the
// peer: a SEEC-enabled party completes a production pqXX handshake with a
// SEEC-less peer in both role assignments, hashes match, transport flows.
func TestSEEC_InteropWithNonSEECPeer(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	s := mustTestSEEC(t)

	for _, tc := range []struct {
		name                         string
		initiatorSEEC, responderSEEC bool
	}{
		{"seec-initiator", true, false},
		{"seec-responder", false, true},
		{"seec-both", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aS, err := suite.SKEM.GenerateKeypair(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bS, err := suite.SKEM.GenerateKeypair(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			iOpts := []clatter.Option{clatter.WithStaticKey(aS)}
			rOpts := []clatter.Option{clatter.WithStaticKey(bS)}
			if tc.initiatorSEEC {
				iOpts = append(iOpts, clatter.WithSEEC(s))
			}
			if tc.responderSEEC {
				rOpts = append(rOpts, clatter.WithSEEC(s))
			}

			a, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, iOpts...)
			if err != nil {
				t.Fatalf("initiator: %v", err)
			}
			b, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite, rOpts...)
			if err != nil {
				t.Fatalf("responder: %v", err)
			}

			_, _, _ = runHandshakeRecorded(t, a, b)
			if !bytes.Equal(a.GetHandshakeHash(), b.GetHandshakeHash()) {
				t.Fatal("handshake hashes diverge between SEEC and non-SEEC peer")
			}
			completeAndVerifyTransport(t, a, b)
		})
	}
}

// --- constructor validation ---

func TestWithSEEC_NilRejected(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqS := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyS := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	for _, tc := range []struct {
		name string
		opt  clatter.Option
	}{
		{"untyped-nil", clatter.WithSEEC(nil)},
		{"typed-nil", clatter.WithSEEC((*clatter.SEECPRF)(nil))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, tc.opt); !errors.Is(err, clatter.ErrSEEC) {
				t.Fatalf("NQ constructor: want ErrSEEC, got %v", err)
			}
			if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS, tc.opt); !errors.Is(err, clatter.ErrSEEC) {
				t.Fatalf("PQ constructor: want ErrSEEC, got %v", err)
			}
			if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, tc.opt); !errors.Is(err, clatter.ErrSEEC) {
				t.Fatalf("Hybrid constructor: want ErrSEEC, got %v", err)
			}
		})
	}
}

// plainKEM wraps a KEM and exposes ONLY the KEM methods, hiding any
// CoinsEncapsulator capability of the wrapped value.
type plainKEM struct{ inner clatter.KEM }

func (p plainKEM) Name() string { return p.inner.Name() }
func (p plainKEM) GenerateKeypair(rng clatter.RNG) (clatter.KeyPair, error) {
	return p.inner.GenerateKeypair(rng)
}
func (p plainKEM) Encapsulate(pk []byte, rng clatter.RNG) (ct, ss []byte, err error) {
	return p.inner.Encapsulate(pk, rng)
}
func (p plainKEM) Decapsulate(ct, sk []byte) ([]byte, error) { return p.inner.Decapsulate(ct, sk) }
func (p plainKEM) PubKeyLen() int                            { return p.inner.PubKeyLen() }
func (p plainKEM) SecretKeyLen() int                         { return p.inner.SecretKeyLen() }
func (p plainKEM) CiphertextLen() int                        { return p.inner.CiphertextLen() }
func (p plainKEM) SharedSecretLen() int                      { return p.inner.SharedSecretLen() }

// TestWithSEEC_IncapableKEMRejected pins PQF-2c: a KEM without
// CoinsEncapsulator combined with WithSEEC is a constructor error naming
// the KEM - never a silent keygen-only downgrade.
func TestWithSEEC_IncapableKEMRejected(t *testing.T) {
	s := mustTestSEEC(t)
	plain := plainKEM{inner: kem.NewMlKem768()}

	pqS := clatter.CipherSuite{EKEM: plain, SKEM: plain, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	_, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS, clatter.WithSEEC(s))
	if !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("PQ constructor with incapable KEM: want ErrSEEC, got %v", err)
	}

	hyS := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: plain, SKEM: plain, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	_, err = clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, clatter.WithSEEC(s))
	if !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("Hybrid constructor with incapable KEM: want ErrSEEC, got %v", err)
	}

	// Without WithSEEC the same suite constructs fine (the capability is
	// only required when SEEC is on).
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS); err != nil {
		t.Fatalf("PQ constructor without SEEC must accept a plain KEM: %v", err)
	}
}

// TestWithSEEC_DualLayerRejected pins C-3/C-17: dual-layer constructors
// reject WithSEEC instead of silently ignoring it.
func TestWithSEEC_DualLayerRejected(t *testing.T) {
	s := mustTestSEEC(t)
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	mkLayers := func() (clatter.Handshaker, clatter.Handshaker) {
		outer, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
		if err != nil {
			t.Fatal(err)
		}
		return outer, inner
	}

	outer, inner := mkLayers()
	if _, err := clatter.NewDualLayerHandshake(outer, inner, 8192, clatter.WithSEEC(s)); !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("DualLayer with WithSEEC: want ErrSEEC, got %v", err)
	}
	outer, inner = mkLayers()
	if _, err := clatter.NewHybridDualLayerHandshake(outer, inner, 8192, clatter.WithSEEC(s)); !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("HybridDualLayer with WithSEEC: want ErrSEEC, got %v", err)
	}

	// Per-layer SEEC is the supported composition: layers constructed
	// with their own WithSEEC compose into a working dual-layer handshake.
	aOuter, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS, clatter.WithSEEC(s))
	if err != nil {
		t.Fatal(err)
	}
	aInner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatal(err)
	}
	a, err := clatter.NewHybridDualLayerHandshake(aOuter, aInner, 8192)
	if err != nil {
		t.Fatalf("per-layer SEEC dual-layer: %v", err)
	}
	bOuter, err := clatter.NewNqHandshake(clatter.PatternNN, false, nqS)
	if err != nil {
		t.Fatal(err)
	}
	bInner, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}
	b, err := clatter.NewHybridDualLayerHandshake(bOuter, bInner, 8192)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = runHandshakeRecorded(t, a, b)
	completeAndVerifyTransport(t, a, b)
}

// --- failure modes ---

// failingRng errors on every read.
type failingRng struct{}

func (failingRng) Read(_ []byte) (int, error) { return 0, errors.New("rng device failed") }

// TestSEEC_FailingRngMidHandshake pins SEEC-31/SEEC-16: an rng failure
// during a SEEC-on handshake fails CLOSED mid-handshake - StatusError,
// state zeroed, no fallback to secret-only coins.
func TestSEEC_FailingRngMidHandshake(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite,
		clatter.WithSEEC(mustTestSEEC(t)), clatter.WithRNG(failingRng{}))
	if err != nil {
		t.Fatalf("constructor must succeed (no construction-time entropy reads): %v", err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	_, err = a.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("WriteMessage with failing rng must error")
	}
	if !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("error must be errors.Is-reachable to ErrSEEC, got: %v", err)
	}

	// Sticky error state, zeroed handshake state.
	if _, err := a.WriteMessage(nil, buf); !errors.Is(err, clatter.ErrErrorState) {
		t.Fatalf("subsequent WriteMessage: want ErrErrorState, got %v", err)
	}
	if h := a.GetHandshakeHash(); h != nil {
		t.Fatal("handshake hash readable after error: state not zeroed")
	}
}

// TestSEEC_HandshakeErrorSentinelReachability pins B1-24: an inner io
// sentinel from an entropy-exhausted keygen stays errors.Is-reachable
// through the handshake wrap chain (the %w: ...: %w multi-wrap).
func TestSEEC_HandshakeErrorSentinelReachability(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	// 16 bytes then EOF: keygen needs 32.
	a, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS,
		clatter.WithRNG(bytes.NewReader(make([]byte, 16))))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, clatter.MaxMessageLen)
	_, err = a.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("WriteMessage with exhausted rng must error")
	}
	if !errors.Is(err, clatter.ErrDH) {
		t.Fatalf("want ErrDH in chain, got: %v", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("inner io.EOF flattened by the handshake wrap (B1-24 regression): %v", err)
	}
}

// hostileSEEC returns the wrong number of bytes through the handshake path.
type hostileSEEC struct{}

func (hostileSEEC) GenRand(_ io.Reader, _ clatter.SEECPurpose, n int) ([]byte, error) {
	return make([]byte, n-1), nil
}

// TestSEEC_HostileImplThroughHandshake drives a short-returning SEEC
// implementation through a real handshake: fail closed with ErrSEEC,
// never a partially seeded key.
func TestSEEC_HostileImplThroughHandshake(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(hostileSEEC{}))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, clatter.MaxMessageLen)
	if _, err := a.WriteMessage(nil, buf); !errors.Is(err, clatter.ErrSEEC) {
		t.Fatalf("hostile SEEC through handshake: want ErrSEEC, got %v", err)
	}
}

// TestSEEC_DestroyMidHandshake pins D-4: destroying the shared SEEC
// instance mid-handshake fails the affected handshake closed on its next
// draw, with both ErrSEEC and ErrDestroyed reachable.
func TestSEEC_DestroyMidHandshake(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	s := mustTestSEEC(t)

	a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatal(err)
	}
	b, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	out := make([]byte, clatter.MaxMessageLen)
	n, err := a.WriteMessage(nil, buf) // initiator ekem keygen draws fine
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReadMessage(buf[:n], out); err != nil {
		t.Fatal(err)
	}

	s.Destroy()

	// Responder's next write needs an encaps draw - must fail closed.
	_, err = b.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("WriteMessage after SEEC Destroy must fail")
	}
	if !errors.Is(err, clatter.ErrSEEC) || !errors.Is(err, clatter.ErrDestroyed) {
		t.Fatalf("want both ErrSEEC and ErrDestroyed reachable, got: %v", err)
	}

	// And the KEYGEN composition (drawer -> entropy.Fill -> adapter ->
	// handshake): a fresh handshake on the destroyed instance fails at
	// its FIRST write (ephemeral keygen draw) with both sentinels - pins
	// the longer wrap chain independently of the encaps path above.
	c, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("keygen draw on a destroyed SEEC instance must fail")
	}
	if !errors.Is(err, clatter.ErrSEEC) || !errors.Is(err, clatter.ErrDestroyed) || !errors.Is(err, clatter.ErrKEM) {
		t.Fatalf("keygen path must surface ErrKEM, ErrSEEC, and ErrDestroyed, got: %v", err)
	}
}

// TestSEEC_ConstantRngRepeatsCoins documents the model boundary (H-10,
// SEEC-29): SEEC hedges coin SECRECY, never coin FRESHNESS. Under a dead
// rng with the same secret, two fresh handshakes produce IDENTICAL first
// messages - by design, not by defect.
func TestSEEC_ConstantRngRepeatsCoins(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	s := mustTestSEEC(t)

	write1 := func() []byte {
		a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite,
			clatter.WithSEEC(s), clatter.WithRNG(zeroRng{}))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, clatter.MaxMessageLen)
		n, err := a.WriteMessage(nil, buf)
		if err != nil {
			t.Fatal(err)
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		a.Destroy()
		return msg
	}

	m1 := write1()
	m2 := write1()
	if !bytes.Equal(m1, m2) {
		t.Fatal("dead rng + same secret produced different coins: the construction is consuming hidden entropy (breaks the documented model)")
	}
}

// --- concurrency ---

// TestSEEC_SharedInstanceHandshakeHammer runs 64 goroutines, each
// completing a full production pqNN handshake pair, all sharing ONE
// SEECPRF instance. Race-clean under -race, every handshake completes.
func TestSEEC_SharedInstanceHandshakeHammer(t *testing.T) {
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	s := mustTestSEEC(t)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(s))
			if err != nil {
				errs <- err
				return
			}
			b, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite, clatter.WithSEEC(s))
			if err != nil {
				errs <- err
				return
			}
			buf := make([]byte, clatter.MaxMessageLen)
			out := make([]byte, clatter.MaxMessageLen)
			for !a.IsFinished() || !b.IsFinished() {
				var w, r clatter.Handshaker
				if a.IsWriteTurn() {
					w, r = a, b
				} else {
					w, r = b, a
				}
				n, err := w.WriteMessage(nil, buf)
				if err != nil {
					errs <- err
					return
				}
				if _, err := r.ReadMessage(buf[:n], out); err != nil {
					errs <- err
					return
				}
			}
			tsA, err := a.Finalize()
			if err != nil {
				errs <- err
				return
			}
			tsB, err := b.Finalize()
			if err != nil {
				errs <- err
				return
			}
			tsA.Destroy()
			tsB.Destroy()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("hammer handshake failed: %v", err)
	}
}

// --- SEEC-36 role-asymmetric draw counts + reduced smoke sweep ---

// countingSEEC counts GenRand calls per purpose, delegating to an inner SEEC.
type countingSEEC struct {
	inner  clatter.SEEC
	keygen int
	encaps int
	other  int
}

func (c *countingSEEC) GenRand(rng io.Reader, purpose clatter.SEECPurpose, n int) ([]byte, error) {
	switch purpose {
	case clatter.SEECKeygen:
		c.keygen++
	case clatter.SEECEncaps:
		c.encaps++
	default:
		c.other++
	}
	return c.inner.GenRand(rng, purpose, n)
}

// expectedSEECDraws computes the per-role SEEC draw counts for a pattern
// directly from its token sequences: each written E token costs one
// keygen draw (two for Hybrid: DH + KEM), each written Ekem or Skem token
// costs one encaps draw. Receivers of one-way patterns draw nothing.
func expectedSEECDraws(p *clatter.HandshakePattern, family string, initiatorSide bool) (keygen, encaps int) {
	var msgs [][]clatter.Token
	if initiatorSide {
		for i := 0; i < p.NumInitiatorMessages(); i++ {
			msgs = append(msgs, p.InitiatorMessage(i))
		}
	} else {
		for i := 0; i < p.NumResponderMessages(); i++ {
			msgs = append(msgs, p.ResponderMessage(i))
		}
	}
	for _, tokens := range msgs {
		for _, tok := range tokens {
			switch tok {
			case clatter.TokenE:
				if family == "hybrid" {
					keygen += 2
				} else {
					keygen++
				}
			case clatter.TokenEkem, clatter.TokenSkem:
				encaps++
			}
		}
	}
	return keygen, encaps
}

// TestSEEC_DrawCountSweep is the reduced SEEC-on smoke sweep: all 12 PQ
// and 12 Hybrid base patterns, NQ XX, and the NQ one-ways N/K/X, each run
// to completion with SEEC on BOTH sides through production ML-KEM-768
// adapters. For every (pattern, role) the observed GenRand call counts
// are pinned against the table computed from the pattern definition
// (SEEC-36 role asymmetry: e.g. the pqXX responder draws zero keygens,
// one-way receivers draw nothing at all).
func TestSEEC_DrawCountSweep(t *testing.T) {
	pqSuiteP := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	hySuiteP := clatter.CipherSuite{
		DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(),
	}
	nqSuiteP := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	inner := mustTestSEEC(t)

	type scenario struct {
		family  string
		pattern *clatter.HandshakePattern
	}
	var scenarios []scenario
	for _, p := range []*clatter.HandshakePattern{
		clatter.PatternPqNN, clatter.PatternPqNK, clatter.PatternPqNX,
		clatter.PatternPqKN, clatter.PatternPqKK, clatter.PatternPqKX,
		clatter.PatternPqXN, clatter.PatternPqXK, clatter.PatternPqXX,
		clatter.PatternPqIN, clatter.PatternPqIK, clatter.PatternPqIX,
	} {
		scenarios = append(scenarios, scenario{"pq", p})
	}
	for _, p := range []*clatter.HandshakePattern{
		clatter.PatternHybridNN, clatter.PatternHybridNK, clatter.PatternHybridNX,
		clatter.PatternHybridKN, clatter.PatternHybridKK, clatter.PatternHybridKX,
		clatter.PatternHybridXN, clatter.PatternHybridXK, clatter.PatternHybridXX,
		clatter.PatternHybridIN, clatter.PatternHybridIK, clatter.PatternHybridIX,
	} {
		scenarios = append(scenarios, scenario{"hybrid", p})
	}
	scenarios = append(scenarios,
		scenario{"nq", clatter.PatternXX},
		scenario{"nq", clatter.PatternN},
		scenario{"nq", clatter.PatternK},
		scenario{"nq", clatter.PatternX},
	)

	for _, sc := range scenarios {
		t.Run(sc.family+"/"+sc.pattern.Name(), func(t *testing.T) {
			iCount := &countingSEEC{inner: inner}
			rCount := &countingSEEC{inner: inner}

			var a, b clatter.Handshaker
			var err error
			switch sc.family {
			case "pq":
				aS, e1 := pqSuiteP.SKEM.GenerateKeypair(rand.Reader)
				bS, e2 := pqSuiteP.SKEM.GenerateKeypair(rand.Reader)
				if e1 != nil || e2 != nil {
					t.Fatal(e1, e2)
				}
				a, err = clatter.NewPqHandshake(sc.pattern, true, pqSuiteP,
					clatter.WithStaticKey(aS), clatter.WithRemoteStatic(bS.Public), clatter.WithSEEC(iCount))
				if err != nil {
					t.Fatal(err)
				}
				b, err = clatter.NewPqHandshake(sc.pattern, false, pqSuiteP,
					clatter.WithStaticKey(bS), clatter.WithRemoteStatic(aS.Public), clatter.WithSEEC(rCount))
				if err != nil {
					t.Fatal(err)
				}
			case "hybrid":
				aDH, e1 := hySuiteP.DH.GenerateKeypair(rand.Reader)
				bDH, e2 := hySuiteP.DH.GenerateKeypair(rand.Reader)
				aKEM, e3 := hySuiteP.SKEM.GenerateKeypair(rand.Reader)
				bKEM, e4 := hySuiteP.SKEM.GenerateKeypair(rand.Reader)
				if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
					t.Fatal(e1, e2, e3, e4)
				}
				a, err = clatter.NewHybridHandshake(sc.pattern, true, hySuiteP,
					clatter.WithStaticKey(aDH), clatter.WithRemoteStatic(bDH.Public),
					clatter.WithStaticKEMKey(aKEM), clatter.WithRemoteStaticKEMKey(bKEM.Public),
					clatter.WithSEEC(iCount))
				if err != nil {
					t.Fatal(err)
				}
				b, err = clatter.NewHybridHandshake(sc.pattern, false, hySuiteP,
					clatter.WithStaticKey(bDH), clatter.WithRemoteStatic(aDH.Public),
					clatter.WithStaticKEMKey(bKEM), clatter.WithRemoteStaticKEMKey(aKEM.Public),
					clatter.WithSEEC(rCount))
				if err != nil {
					t.Fatal(err)
				}
			case "nq":
				aS, e1 := nqSuiteP.DH.GenerateKeypair(rand.Reader)
				bS, e2 := nqSuiteP.DH.GenerateKeypair(rand.Reader)
				if e1 != nil || e2 != nil {
					t.Fatal(e1, e2)
				}
				a, err = clatter.NewNqHandshake(sc.pattern, true, nqSuiteP,
					clatter.WithStaticKey(aS), clatter.WithRemoteStatic(bS.Public), clatter.WithSEEC(iCount))
				if err != nil {
					t.Fatal(err)
				}
				b, err = clatter.NewNqHandshake(sc.pattern, false, nqSuiteP,
					clatter.WithStaticKey(bS), clatter.WithRemoteStatic(aS.Public), clatter.WithSEEC(rCount))
				if err != nil {
					t.Fatal(err)
				}
			}

			// Run to completion (one-way patterns: single message).
			buf := make([]byte, clatter.MaxMessageLen)
			out := make([]byte, clatter.MaxMessageLen)
			for !a.IsFinished() || !b.IsFinished() {
				var w, r clatter.Handshaker
				if a.IsWriteTurn() {
					w, r = a, b
				} else {
					w, r = b, a
				}
				n, err := w.WriteMessage(nil, buf)
				if err != nil {
					t.Fatalf("write: %v", err)
				}
				if _, err := r.ReadMessage(buf[:n], out); err != nil {
					t.Fatalf("read: %v", err)
				}
			}

			wantIK, wantIE := expectedSEECDraws(sc.pattern, sc.family, true)
			wantRK, wantRE := expectedSEECDraws(sc.pattern, sc.family, false)
			if iCount.keygen != wantIK || iCount.encaps != wantIE || iCount.other != 0 {
				t.Fatalf("initiator draws keygen=%d encaps=%d other=%d, want keygen=%d encaps=%d other=0",
					iCount.keygen, iCount.encaps, iCount.other, wantIK, wantIE)
			}
			if rCount.keygen != wantRK || rCount.encaps != wantRE || rCount.other != 0 {
				t.Fatalf("responder draws keygen=%d encaps=%d other=%d, want keygen=%d encaps=%d other=0",
					rCount.keygen, rCount.encaps, rCount.other, wantRK, wantRE)
			}

			// Transport proof for two-way patterns.
			if !sc.pattern.IsOneWay() {
				completeAndVerifyTransport(t, a, b)
			}
		})
	}
}
