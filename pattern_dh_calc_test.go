package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the construction-time DH-calculation-count rule
// (validateDHCalcAtMostOnce): Noise section 7.3 requires that no DH calculation is
// performed more than once per handshake - "there must be no more than one
// occurrence of ee, es, se, or ss per handshake." A custom pattern that repeats a
// DH calculation re-mixes a shared secret already in the chaining key and is
// rejected at NewPattern. The KEM tokens ekem/skem are deliberately exempt (PQNoise
// repeats skem by design); TestDHCalcRule_AllPredefinedValidate guards that by
// exercising every built-in, including the PQ/Hybrid skem-twice patterns.
//
// WIRING: removing the validateDHCalcAtMostOnce call from NewPattern makes every
// reject case below return nil (failing the errors.Is check), and the all-90
// direct-call guard still exercises the validator itself - two independent guards.

// dhCalcMarker is the substring unique to the DH-calculation-count validator's
// error (distinct from the per-party rule's "must appear at most once per party").
const dhCalcMarker = "must occur at most once per handshake"

func TestNewPattern_RejectsRepeatedDHCalc(t *testing.T) {
	// Each pattern is well-formed under every OTHER rule (PSK position, PQ token
	// order, e/s at-most-once per party, and both precedence rules), so the doubled
	// DH token is the sole defect and the rejection provably comes from the
	// DH-calculation-count rule. All four are accepted by NewPattern when the
	// validator call is removed (the WIRING note above).
	cases := []struct {
		name       string
		init, resp [][]Token
		preI, preR []Token
	}{
		// ee twice: the responder performs the e<->e DH calculation two times.
		{"double_ee", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, TokenEE}}, nil, nil},
		// es twice: the initiator reads the (pre-shared) responder static twice.
		{"double_es", [][]Token{{TokenE, TokenES, TokenES}}, nil, nil, []Token{TokenS}},
		// se twice: the responder reads the initiator static (transmitted in msg0) twice.
		{"double_se", [][]Token{{TokenE, TokenS}}, [][]Token{{TokenE, TokenEE, TokenSE, TokenSE}}, nil, nil},
		// ss twice: the initiator performs the static<->static DH twice (both pre-shared).
		{"double_ss", [][]Token{{TokenE, TokenSS, TokenSS}}, [][]Token{{TokenE, TokenEE}}, []Token{TokenS}, []Token{TokenS}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), dhCalcMarker) {
				t.Fatalf("rejection did not come from the DH-calculation-count validator (missing %q): %v",
					dhCalcMarker, err)
			}
		})
	}
}

// TestNewPattern_RepeatedDHCalc_AcceptsSingleUse pins that a well-formed pattern
// performing each DH calculation exactly once (XX: e, ee, s, es, se) is accepted -
// the validator must not over-reject.
func TestNewPattern_RepeatedDHCalc_AcceptsSingleUse(t *testing.T) {
	if _, err := NewPattern("okXX",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil); err != nil {
		t.Fatalf("well-formed single-use-per-DH-calc pattern wrongly rejected: %v", err)
	}
}

// TestDHCalcRule_AllPredefinedValidate invokes validateDHCalcAtMostOnce DIRECTLY on
// every predefined pattern, asserting acceptance. The 90 built-ins are constructed
// at package init via mustNewPattern, so a violation would panic init; this guard
// additionally exercises the validator as a genuine (non-vacuous) check on all 90 -
// including the PQ/Hybrid patterns that repeat skem (e.g. pqXX, hybridXX), proving
// the KEM exemption (only ee/es/se/ss are capped, never ekem/skem).
func TestDHCalcRule_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateDHCalcAtMostOnce(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by DH-calculation-count validator: %v", p.Name(), err)
		}
	}
}
