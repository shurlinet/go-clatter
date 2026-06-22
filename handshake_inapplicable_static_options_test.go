package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// Uniform loud-rejection of inapplicable static-key options. A static a role
// never transmits (WithStaticKey on a no-static role), or a remote static the
// peer never pre-shares (WithRemoteStatic when the static is instead learned
// in-band and overwrites the preset), is a silent no-op; the constructors reject
// it with ErrInvalidOption. These tests pin the rejects and the role/pattern
// accuracy (a static-using role still accepts the option).

func TestStaticNoOp_NqRejectsInapplicable(t *testing.T) {
	suite := suiteChachaSha256()
	kp, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(1))

	// NN: neither role transmits a static and neither pre-shares one.
	for _, initiator := range []bool{true, false} {
		role := map[bool]string{true: "initiator", false: "responder"}[initiator]
		t.Run("NN/"+role+"/WithStaticKey", func(t *testing.T) {
			hs, err := clatter.NewNqHandshake(clatter.PatternNN, initiator, suite, clatter.WithStaticKey(kp))
			if !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
				t.Fatalf("want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
			}
		})
		t.Run("NN/"+role+"/WithRemoteStatic", func(t *testing.T) {
			hs, err := clatter.NewNqHandshake(clatter.PatternNN, initiator, suite, clatter.WithRemoteStatic(kp.Public))
			if !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
				t.Fatalf("want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
			}
		})
	}

	// NX: the initiator is anonymous (no own static) and the responder's static
	// is transmitted in-band (no pre-message), so WithStaticKey on the initiator
	// and WithRemoteStatic on the responder are both no-ops.
	if hs, err := clatter.NewNqHandshake(clatter.PatternNX, true, suite, clatter.WithStaticKey(kp)); !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
		t.Fatalf("NX initiator WithStaticKey: want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
	}
	if hs, err := clatter.NewNqHandshake(clatter.PatternNX, false, suite, clatter.WithRemoteStatic(kp.Public)); !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
		t.Fatalf("NX responder WithRemoteStatic: want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
	}
}

// TestStaticNoOp_NqInBandRemoteStaticRejected pins the in-band reasoning: XX
// transmits both statics during the handshake (no pre-message), so a pre-set
// WithRemoteStatic is overwritten by readTokenS before use - a no-op, rejected.
// The local WithStaticKey (which XX DOES transmit) stays accepted.
func TestStaticNoOp_NqInBandRemoteStaticRejected(t *testing.T) {
	suite := suiteChachaSha256()
	kp, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(2))

	if hs, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite, clatter.WithRemoteStatic(kp.Public)); !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
		t.Fatalf("XX initiator WithRemoteStatic (in-band): want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
	}
	// WithStaticKey on XX IS applicable (XX transmits its static).
	hs, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite, clatter.WithStaticKey(kp))
	if err != nil {
		t.Fatalf("XX initiator WithStaticKey must be accepted, got %v", err)
	}
	hs.Destroy()
}

func TestStaticNoOp_PqRejectsInapplicable(t *testing.T) {
	suite := pqSuiteProd()
	kp, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(3))

	for _, initiator := range []bool{true, false} {
		role := map[bool]string{true: "initiator", false: "responder"}[initiator]
		t.Run("pqNN/"+role+"/WithStaticKey", func(t *testing.T) {
			hs, err := clatter.NewPqHandshake(clatter.PatternPqNN, initiator, suite, clatter.WithStaticKey(kp))
			if !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
				t.Fatalf("want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
			}
		})
		t.Run("pqNN/"+role+"/WithRemoteStatic", func(t *testing.T) {
			hs, err := clatter.NewPqHandshake(clatter.PatternPqNN, initiator, suite, clatter.WithRemoteStatic(kp.Public))
			if !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
				t.Fatalf("want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
			}
		})
	}
}

// TestStaticNoOp_HybridRejectsAllFour verifies a Hybrid no-static pattern
// (hybridNN) rejects ALL four static options on BOTH roles, since Hybrid
// Token::S carries the DH and KEM static together.
func TestStaticNoOp_HybridRejectsAllFour(t *testing.T) {
	suite := hybridSuiteProd()
	dhKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(4))
	kemKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(5))

	for _, initiator := range []bool{true, false} {
		role := map[bool]string{true: "initiator", false: "responder"}[initiator]
		opts := []struct {
			name string
			opt  clatter.Option
		}{
			{"WithStaticKey", clatter.WithStaticKey(dhKP)},
			{"WithStaticKEMKey", clatter.WithStaticKEMKey(kemKP)},
			{"WithRemoteStatic", clatter.WithRemoteStatic(dhKP.Public)},
			{"WithRemoteStaticKEMKey", clatter.WithRemoteStaticKEMKey(kemKP.Public)},
		}
		for _, o := range opts {
			t.Run("hybridNN/"+role+"/"+o.name, func(t *testing.T) {
				hs, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, initiator, suite, o.opt)
				if !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
					t.Fatalf("want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
				}
			})
		}
	}
}

// TestStaticNoOp_CustomPatternRoleAccuracy proves usesLocalStatic/usesRemoteStatic
// are per-role accurate on CATALOG-ABSENT patterns (parity with the ephemeral
// suite's custom-pattern test) - not a blanket initiator-only assumption. A
// custom pattern whose RESPONDER transmits a static (initiator anonymous) accepts
// WithStaticKey on the responder and rejects it on the initiator; the mirror
// (initiator pre-shares a static) flips the applicable role for WithRemoteStatic.
func TestStaticNoOp_CustomPatternRoleAccuracy(t *testing.T) {
	suite := suiteChachaSha256()
	kp, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(20))

	// Custom 1: responder transmits a static (Token::S); initiator anonymous. Not
	// in the predefined catalog (NX adds an es; this omits it).
	respStatic, err := clatter.NewPattern("customRespStatic",
		[][]clatter.Token{{clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE, clatter.TokenS}},
		nil, nil)
	if err != nil {
		t.Fatalf("NewPattern(customRespStatic): %v", err)
	}
	if hs, err := clatter.NewNqHandshake(respStatic, true, suite, clatter.WithStaticKey(kp)); !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
		t.Fatalf("custom anonymous initiator WithStaticKey: want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
	}
	rs, err := clatter.NewNqHandshake(respStatic, false, suite, clatter.WithStaticKey(kp))
	if err != nil {
		t.Fatalf("custom static-transmitting responder WithStaticKey must be accepted, got %v", err)
	}
	rs.Destroy()

	// Custom 2: initiator pre-shares its static (pre-message S). The responder's
	// WithRemoteStatic is applicable (peer pre-shares); the initiator's is not.
	preInitStatic, err := clatter.NewPattern("customPreInitStatic",
		[][]clatter.Token{{clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		[]clatter.Token{clatter.TokenS}, nil)
	if err != nil {
		t.Fatalf("NewPattern(customPreInitStatic): %v", err)
	}
	r, err := clatter.NewNqHandshake(preInitStatic, false, suite, clatter.WithRemoteStatic(kp.Public))
	if err != nil {
		t.Fatalf("custom responder WithRemoteStatic (peer pre-shares) must be accepted, got %v", err)
	}
	r.Destroy()
	if hs, err := clatter.NewNqHandshake(preInitStatic, true, suite, clatter.WithRemoteStatic(kp.Public)); !errors.Is(err, clatter.ErrInvalidOption) || hs != nil {
		t.Fatalf("custom initiator WithRemoteStatic (no peer pre-share): want (nil, ErrInvalidOption), got (%v, %v)", hs, err)
	}
}

// TestStaticNoOp_ApplicableStaticsAccepted is the role/pattern accuracy guard:
// a static-using (pattern, role) must NOT reject the option. Covers all three
// families with the canonical static patterns and end-to-end round-trips.
func TestStaticNoOp_ApplicableStaticsAccepted(t *testing.T) {
	t.Run("nqXX", func(t *testing.T) {
		suite := suiteChachaSha256()
		iKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(10))
		rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(11))
		i, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite, clatter.WithStaticKey(iKP))
		if err != nil {
			t.Fatalf("XX initiator WithStaticKey: %v", err)
		}
		r, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite, clatter.WithStaticKey(rKP))
		if err != nil {
			t.Fatalf("XX responder WithStaticKey: %v", err)
		}
		verifyHandshake(t, i, r, "nqXX_static")
	})

	t.Run("nqIK_premessage_remote", func(t *testing.T) {
		suite := suiteChachaSha256()
		iKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(12))
		rKP, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(13))
		// IK: responder pre-shares its static, so the initiator's WithRemoteStatic
		// IS applicable (and required).
		i, err := clatter.NewNqHandshake(clatter.PatternIK, true, suite,
			clatter.WithStaticKey(iKP), clatter.WithRemoteStatic(rKP.Public))
		if err != nil {
			t.Fatalf("IK initiator: %v", err)
		}
		r, err := clatter.NewNqHandshake(clatter.PatternIK, false, suite, clatter.WithStaticKey(rKP))
		if err != nil {
			t.Fatalf("IK responder: %v", err)
		}
		verifyHandshake(t, i, r, "nqIK_static")
	})

	t.Run("pqIK_premessage_remote", func(t *testing.T) {
		suite := pqSuiteProd()
		iKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(14))
		rKP, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(15))
		i, err := clatter.NewPqHandshake(clatter.PatternPqIK, true, suite,
			clatter.WithStaticKey(iKP), clatter.WithRemoteStatic(rKP.Public))
		if err != nil {
			t.Fatalf("pqIK initiator: %v", err)
		}
		r, err := clatter.NewPqHandshake(clatter.PatternPqIK, false, suite, clatter.WithStaticKey(rKP))
		if err != nil {
			t.Fatalf("pqIK responder: %v", err)
		}
		verifyHandshake(t, i, r, "pqIK_static")
	})

	t.Run("hybridIK_all_four", func(t *testing.T) {
		suite := hybridSuiteProd()
		iDH, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(16))
		rDH, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(17))
		iKEM, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(18))
		rKEM, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(19))
		// hybridIK: responder pre-shares both statics, so the initiator's remote
		// options are applicable; both transmit their own statics.
		i, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, true, suite,
			clatter.WithStaticKey(iDH), clatter.WithRemoteStatic(rDH.Public),
			clatter.WithStaticKEMKey(iKEM), clatter.WithRemoteStaticKEMKey(rKEM.Public))
		if err != nil {
			t.Fatalf("hybridIK initiator: %v", err)
		}
		r, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, false, suite,
			clatter.WithStaticKey(rDH), clatter.WithStaticKEMKey(rKEM))
		if err != nil {
			t.Fatalf("hybridIK responder: %v", err)
		}
		verifyHandshake(t, i, r, "hybridIK_static")
	})
}
