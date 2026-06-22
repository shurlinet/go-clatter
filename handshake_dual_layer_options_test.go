package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// The dual-layer wrap-constructors take pre-built inner and outer
// Handshakers, so only WithObserver and WithMaxMessageLen apply at the wrap
// layer. Every other option (keys, prologue, rng, SEEC) is rejected with
// ErrInvalidOption rather than silently dropped (a silent drop would let a
// caller believe an option took effect when it did not).

func nqSuiteDualLayer() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func pqSuiteDualLayer() clatter.CipherSuite {
	return clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}
}

// TestDualLayer_InapplicableOptionsRejected pins that both wrap-constructors
// reject every inapplicable option with ErrInvalidOption.
func TestDualLayer_InapplicableOptionsRejected(t *testing.T) {
	nqSuite := nqSuiteDualLayer()
	pqSuite := pqSuiteDualLayer()

	dhKP, err := nqSuite.DH.GenerateKeypair(clatter.NewDummyRng(1))
	if err != nil {
		t.Fatalf("gen DH keypair: %v", err)
	}
	kemKP, err := pqSuite.SKEM.GenerateKeypair(clatter.NewDummyRng(2))
	if err != nil {
		t.Fatalf("gen KEM keypair: %v", err)
	}
	seec := mustTestSEEC(t)

	cases := []struct {
		name string
		opt  clatter.Option
	}{
		{"WithPrologue", clatter.WithPrologue([]byte("nope"))},
		{"WithRNG", clatter.WithRNG(clatter.NewDummyRng(3))},
		{"WithStaticKey", clatter.WithStaticKey(dhKP)},
		{"WithEphemeralKey", clatter.WithEphemeralKey(dhKP)},
		{"WithEphemeralKEMKey", clatter.WithEphemeralKEMKey(kemKP)},
		{"WithStaticKEMKey", clatter.WithStaticKEMKey(kemKP)},
		{"WithRemoteStatic", clatter.WithRemoteStatic(dhKP.Public)},
		{"WithRemoteStaticKEMKey", clatter.WithRemoteStaticKEMKey(kemKP.Public)},
		{"WithSEEC", clatter.WithSEEC(seec)},
	}

	// Returns only the error so a typed-nil *DualLayerHandshake never becomes a
	// non-nil interface value (the classic Go nil-interface trap).
	ctors := []struct {
		name string
		try  func(outer, inner clatter.Handshaker, opt clatter.Option) error
	}{
		{"NewDualLayerHandshake", func(o, i clatter.Handshaker, opt clatter.Option) error {
			_, err := clatter.NewDualLayerHandshake(o, i, 8192, opt)
			return err
		}},
		{"NewHybridDualLayerHandshake", func(o, i clatter.Handshaker, opt clatter.Option) error {
			_, err := clatter.NewHybridDualLayerHandshake(o, i, 8192, opt)
			return err
		}},
	}

	for _, c := range ctors {
		for _, tc := range cases {
			t.Run(c.name+"/"+tc.name, func(t *testing.T) {
				// Fresh layers each time: a rejected constructor does not consume
				// the Handshakers, but fresh ones keep the cases independent.
				outer, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
				if err != nil {
					t.Fatalf("outer: %v", err)
				}
				inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)
				if err != nil {
					t.Fatalf("inner: %v", err)
				}
				if err := c.try(outer, inner, tc.opt); !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("%s with %s: want ErrInvalidOption, got %v", c.name, tc.name, err)
				}
			})
		}
	}
}

// TestDualLayer_StructuralChecksPrecedeOptionReject pins the precedence
// invariant: the structural checks (bufSize, role parity, one-way outer) run
// BEFORE the inapplicable-option reject. A one-way outer combined with an
// inapplicable option returns ErrInvalidPattern (the structural error), never
// ErrInvalidOption.
func TestDualLayer_StructuralChecksPrecedeOptionReject(t *testing.T) {
	suite := nqSuiteDualLayer()
	rKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(7))
	if err != nil {
		t.Fatalf("gen keypair: %v", err)
	}
	// PatternN is a one-way pattern (invalid as a dual-layer outer); its
	// initiator needs the responder's static, supplied via WithRemoteStatic on
	// the inner NQ constructor (a per-layer option, valid there).
	outer, err := clatter.NewNqHandshake(clatter.PatternN, true, suite, clatter.WithRemoteStatic(rKP.Public))
	if err != nil {
		t.Fatalf("outer: %v", err)
	}
	inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuiteDualLayer())
	if err != nil {
		t.Fatalf("inner: %v", err)
	}
	// WithPrologue is inapplicable at the wrap layer, but the one-way structural
	// check must fire first.
	if _, err := clatter.NewDualLayerHandshake(outer, inner, 8192, clatter.WithPrologue([]byte("x"))); !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("one-way outer + inapplicable option: want ErrInvalidPattern, got %v", err)
	} else if errors.Is(err, clatter.ErrInvalidOption) {
		t.Fatalf("structural check must take precedence, but got ErrInvalidOption: %v", err)
	}
}

// TestDualLayer_WithObserverAndMaxMessageLen pins that the two applicable
// options work together: construction succeeds, the handshake completes, and
// the observer fires. The inner layer is sized so inner.maxMsgLen + outer tag
// fits within the dual-layer limit (otherwise the inner-max-fit guard correctly
// rejects construction with ErrInvalidPattern).
func TestDualLayer_WithObserverAndMaxMessageLen(t *testing.T) {
	nqSuite := nqSuiteDualLayer()
	pqSuite := pqSuiteDualLayer()

	mkOuter := func(initiator bool) clatter.Handshaker {
		o, err := clatter.NewNqHandshake(clatter.PatternNN, initiator, nqSuite)
		if err != nil {
			t.Fatalf("outer: %v", err)
		}
		return o
	}
	mkInner := func(initiator bool) clatter.Handshaker {
		i, err := clatter.NewPqHandshake(clatter.PatternPqNN, initiator, pqSuite,
			clatter.WithMaxMessageLen(4096))
		if err != nil {
			t.Fatalf("inner: %v", err)
		}
		return i
	}

	for _, hybrid := range []bool{false, true} {
		name := "DualLayer"
		if hybrid {
			name = "HybridDualLayer"
		}
		t.Run(name, func(t *testing.T) {
			obsA := &recordingObserver{}
			obsB := &recordingObserver{}

			mk := func(initiator bool, obs *recordingObserver) (clatter.Handshaker, error) {
				if hybrid {
					return clatter.NewHybridDualLayerHandshake(mkOuter(initiator), mkInner(initiator), 8192,
						clatter.WithObserver(obs), clatter.WithMaxMessageLen(8192))
				}
				return clatter.NewDualLayerHandshake(mkOuter(initiator), mkInner(initiator), 8192,
					clatter.WithObserver(obs), clatter.WithMaxMessageLen(8192))
			}

			alice, err := mk(true, obsA)
			if err != nil {
				t.Fatalf("alice construct: %v", err)
			}
			defer alice.Destroy()
			bob, err := mk(false, obsB)
			if err != nil {
				t.Fatalf("bob construct: %v", err)
			}
			defer bob.Destroy()

			buf := make([]byte, 16384)
			payloadBuf := make([]byte, 8192)
			for !alice.IsFinished() && !bob.IsFinished() {
				switch {
				case alice.IsWriteTurn():
					n, werr := alice.WriteMessage(nil, buf)
					if werr != nil {
						t.Fatalf("alice write: %v", werr)
					}
					if _, rerr := bob.ReadMessage(buf[:n], payloadBuf); rerr != nil {
						t.Fatalf("bob read: %v", rerr)
					}
				case bob.IsWriteTurn():
					n, werr := bob.WriteMessage(nil, buf)
					if werr != nil {
						t.Fatalf("bob write: %v", werr)
					}
					if _, rerr := alice.ReadMessage(buf[:n], payloadBuf); rerr != nil {
						t.Fatalf("alice read: %v", rerr)
					}
				default:
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

			if len(obsA.getEvents()) == 0 {
				t.Fatal("WithObserver: observer recorded no events")
			}
			if mml := aliceTS.MaxMessageLen(); mml != 8192 {
				t.Fatalf("WithMaxMessageLen: transport limit = %d, want 8192", mml)
			}
		})
	}
}
