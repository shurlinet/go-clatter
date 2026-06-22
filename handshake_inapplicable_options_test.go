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

// Uniform loud-rejection of inapplicable ephemeral options. A pre-set
// ephemeral is only consumed by a party that emits Token::E; presetting one for
// a party that emits none is a silent no-op, so the constructors reject it with
// ErrInvalidOption. These tests pin the new rejects and prove the role/pattern
// accuracy (a custom pattern whose responder DOES emit Token::E still honors it).

func nqSuiteInapplicable() clatter.CipherSuite {
	return clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
}

// TestInapplicableOptions_PqRejectsWithEphemeralKey verifies PQ (KEM-only) loudly rejects the
// DH-ephemeral option on BOTH roles and regardless of pattern: PQ has no DH
// ephemeral, so a silent drop would hide a misconfiguration. The rejected key
// length is irrelevant (the reject precedes length validation), so a dummy
// keypair suffices.
func TestInapplicableOptions_PqRejectsWithEphemeralKey(t *testing.T) {
	suite := pqSuiteProd()
	dhKP := clatter.NewKeyPair(make([]byte, 32), make([]byte, 32))

	for _, initiator := range []bool{true, false} {
		role := "responder"
		if initiator {
			role = "initiator"
		}
		for _, pat := range []*clatter.HandshakePattern{clatter.PatternPqNN, clatter.PatternPqXX, clatter.PatternPqIK} {
			t.Run(role+"/"+pat.Name(), func(t *testing.T) {
				hs, err := clatter.NewPqHandshake(pat, initiator, suite, clatter.WithEphemeralKey(dhKP))
				if !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("PQ WithEphemeralKey: want ErrInvalidOption, got %v", err)
				}
				if hs != nil {
					t.Fatal("constructor must return nil handshake on rejected option")
				}
			})
		}
	}
}

// TestInapplicableOptions_PqResponderRejectsWithEphemeralKEMKey verifies a PQ responder
// rejects WithEphemeralKEMKey: in every built-in PQ pattern the responder sends
// no Token::E (it only encapsulates to the initiator's ephemeral), so the preset
// would be a silent no-op. The initiator, which DOES send Token::E, still
// accepts it.
func TestInapplicableOptions_PqResponderRejectsWithEphemeralKEMKey(t *testing.T) {
	suite := pqSuiteProd()
	ekp, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0x71))
	if err != nil {
		t.Fatalf("gen ephemeral: %v", err)
	}

	for _, pat := range []*clatter.HandshakePattern{clatter.PatternPqNN, clatter.PatternPqXX, clatter.PatternPqIK} {
		t.Run(pat.Name()+"/responder_rejected", func(t *testing.T) {
			hs, err := clatter.NewPqHandshake(pat, false, suite, clatter.WithEphemeralKEMKey(ekp))
			if !errors.Is(err, clatter.ErrInvalidOption) {
				t.Fatalf("PQ responder WithEphemeralKEMKey: want ErrInvalidOption, got %v", err)
			}
			if hs != nil {
				t.Fatal("constructor must return nil handshake on rejected option")
			}
		})
		t.Run(pat.Name()+"/initiator_accepted", func(t *testing.T) {
			// The initiator emits Token::E, so the preset must NOT be rejected as
			// inapplicable. (A pattern with a pre-message static, e.g. pqIK, still
			// needs that static to fully construct; that unrelated error is fine -
			// we only assert this does not reject the ephemeral option.)
			hs, err := clatter.NewPqHandshake(pat, true, suite, clatter.WithEphemeralKEMKey(ekp))
			if errors.Is(err, clatter.ErrInvalidOption) {
				t.Fatalf("PQ initiator WithEphemeralKEMKey must not be rejected as inapplicable, got %v", err)
			}
			if hs != nil {
				hs.Destroy()
			}
		})
	}
}

// TestInapplicableOptions_NqOneWayResponderRejectsWithEphemeralKey verifies a one-way pattern
// (N/K/X) responder rejects WithEphemeralKey: a one-way responder writes no
// messages and emits no Token::E, so the preset would be a silent no-op. The
// one-way INITIATOR (which emits Token::E) and an interactive responder still
// accept it.
func TestInapplicableOptions_NqOneWayResponderRejectsWithEphemeralKey(t *testing.T) {
	suite := nqSuiteInapplicable()
	dhKP, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x72))
	if err != nil {
		t.Fatalf("gen ephemeral: %v", err)
	}

	for _, pat := range []*clatter.HandshakePattern{clatter.PatternN, clatter.PatternK, clatter.PatternX} {
		t.Run(pat.Name()+"/responder_rejected", func(t *testing.T) {
			hs, err := clatter.NewNqHandshake(pat, false, suite, clatter.WithEphemeralKey(dhKP))
			if !errors.Is(err, clatter.ErrInvalidOption) {
				t.Fatalf("NQ one-way responder WithEphemeralKey: want ErrInvalidOption, got %v", err)
			}
			if hs != nil {
				t.Fatal("constructor must return nil handshake on rejected option")
			}
		})
		t.Run(pat.Name()+"/initiator_accepted", func(t *testing.T) {
			// The one-way initiator emits Token::E, so the preset must NOT be
			// rejected as inapplicable. (K/X carry a pre-message static the bare
			// constructor lacks; that unrelated error is fine here.)
			hs, err := clatter.NewNqHandshake(pat, true, suite, clatter.WithEphemeralKey(dhKP))
			if errors.Is(err, clatter.ErrInvalidOption) {
				t.Fatalf("NQ one-way initiator WithEphemeralKey must not be rejected as inapplicable, got %v", err)
			}
			if hs != nil {
				hs.Destroy()
			}
		})
	}

	// An interactive pattern's responder DOES emit Token::E -> still accepted.
	t.Run("NN/responder_accepted", func(t *testing.T) {
		hs, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite, clatter.WithEphemeralKey(dhKP))
		if err != nil {
			t.Fatalf("interactive responder WithEphemeralKey must be accepted, got %v", err)
		}
		hs.Destroy()
	})
}

// TestInapplicableOptions_CustomPqMutualEphemeral_ResponderPresetAccepted is the role/pattern
// accuracy proof: a custom PQ pattern whose RESPONDER emits Token::E (a mutual-
// ephemeral handshake) is constructible via the public NewPattern API, and a
// responder-side WithEphemeralKEMKey is ACCEPTED and consumed end-to-end. A
// blanket "!initiator" reject would wrongly break this; the sendsLocalEphemeral
// helper handles it correctly.
func TestInapplicableOptions_CustomPqMutualEphemeral_ResponderPresetAccepted(t *testing.T) {
	suite := pqSuiteProd()

	// -> e ; <- ekem, e ; -> ekem   (both parties send their own KEM ephemeral)
	pat, err := clatter.NewPattern("pqMutualE",
		[][]clatter.Token{{clatter.TokenE}, {clatter.TokenEkem}},
		[][]clatter.Token{{clatter.TokenEkem, clatter.TokenE}},
		nil, nil)
	if err != nil {
		t.Fatalf("NewPattern(pqMutualE) must be accepted, got %v", err)
	}
	if pat.Type() != clatter.PatternTypeKEM {
		t.Fatalf("pqMutualE must be a KEM pattern, got type %d", pat.Type())
	}

	rEkp, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0x73))
	if err != nil {
		t.Fatalf("gen responder ephemeral: %v", err)
	}

	// The responder emits Token::E here, so its preset MUST be accepted.
	i, err := clatter.NewPqHandshake(pat, true, suite)
	if err != nil {
		t.Fatalf("initiator: %v", err)
	}
	r, err := clatter.NewPqHandshake(pat, false, suite, clatter.WithEphemeralKEMKey(rEkp))
	if err != nil {
		t.Fatalf("responder WithEphemeralKEMKey on a mutual-ephemeral PQ pattern must be accepted, got %v", err)
	}

	verifyHandshake(t, i, r, "pqMutualE_responderPreset")
}

// TestInapplicableOptions_PreMessageEphemeral_PresetAccepted covers the helper's pre-message
// branch: a pattern whose party emits its Token::E only as a PRE-MESSAGE (the
// ephemeral is pre-shared) still consumes a preset, so sendsLocalEphemeral must
// report true and the constructor must accept the preset. Without the
// pre-message scan this would be a false reject.
func TestInapplicableOptions_PreMessageEphemeral_PresetAccepted(t *testing.T) {
	suite := nqSuiteInapplicable()

	// Initiator's e is pre-shared (pre-message E); its message body is empty and
	// the responder emits its own Token::E before the ee consumes both ephemerals.
	// This is the well-formed pre-message-E pattern (runnable); the prior
	// {{ee}}/{{e,ee}} form had the responder consume ee before emitting Token::E,
	// which is un-runnable and now rejected by the precedence rule.
	pat, err := clatter.NewPattern("customPreMessageE",
		[][]clatter.Token{{}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		[]clatter.Token{clatter.TokenE}, nil)
	if err != nil {
		t.Fatalf("NewPattern(customPreMessageE) must be accepted, got %v", err)
	}

	kp, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x76))
	if err != nil {
		t.Fatalf("gen ephemeral: %v", err)
	}

	// The initiator emits Token::E via the pre-message, so its preset must be
	// accepted (and processPreMessages consumes it, so construction succeeds).
	// This pins construction + initiator-preset acceptance only (not an
	// end-to-end verifyHandshake): there is no public option to inject the
	// responder's/remote pre-message ephemeral, so the pre-message-E path is
	// preset-verified by design, exactly as this test was before the swap.
	hs, err := clatter.NewNqHandshake(pat, true, suite, clatter.WithEphemeralKey(kp))
	if err != nil {
		t.Fatalf("pre-message-E initiator preset must be accepted, got %v", err)
	}
	hs.Destroy()
}

// TestInapplicableOptions_HybridStillAcceptsRolePresets is a regression guard: the Hybrid
// role-rejects must NEVER fire for a built-in Hybrid pattern (both roles emit
// Token::E). Presetting both ephemeral options on BOTH roles stays accepted.
func TestInapplicableOptions_HybridStillAcceptsRolePresets(t *testing.T) {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	for _, initiator := range []bool{true, false} {
		role := "responder"
		if initiator {
			role = "initiator"
		}
		dhE, err := suite.DH.GenerateKeypair(clatter.NewDummyRng(0x74))
		if err != nil {
			t.Fatalf("gen dh ephemeral: %v", err)
		}
		kemE, err := suite.EKEM.GenerateKeypair(clatter.NewDummyRng(0x75))
		if err != nil {
			t.Fatalf("gen kem ephemeral: %v", err)
		}
		t.Run(role, func(t *testing.T) {
			hs, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, initiator, suite,
				clatter.WithEphemeralKey(dhE),
				clatter.WithEphemeralKEMKey(kemE))
			if err != nil {
				t.Fatalf("Hybrid %s preset must be accepted, got %v", role, err)
			}
			hs.Destroy()
		})
	}
}
