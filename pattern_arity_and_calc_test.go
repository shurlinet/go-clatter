package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the two construction-time well-formedness validators added
// alongside the derived one-way bit:
//
//   - validatePatternArity: a Noise handshake strictly alternates messages
//     starting with the initiator, so the only valid message-count shapes have
//     numResponder <= numInitiator <= numResponder+1 with at least one message.
//   - validateHasCryptographicCalc: a handshake must perform at least one DH or
//     KEM key agreement (a pattern with no ee/es/se/ss/ekem/skem negotiates no
//     shared secret).
//
// Each reject case asserts errors.Is(ErrInvalidPattern) AND the marker unique to
// the offending validator, so the rejection provably comes from THAT validator.
// Two independent brute-force / direct-call guards make the wiring non-vacuous:
// removing either validator call from NewPattern fails this file.

const (
	arityZeroMarker      = "pattern has no handshake messages"
	arityRespFirstMarker = "alternates messages starting with the initiator"
	arityOneWayMarker    = "a one-way pattern is a single message"
	aritySkewMarker      = "the initiator may lead by at most one"
	noCalcMarker         = "no DH or KEM key agreement"
)

// arityValid is an INDEPENDENT transcription of the alternation invariant, kept
// separate from validatePatternArity so a divergence (or a silent removal of the
// NewPattern call) is caught by the brute force below.
func arityValid(ni, nr int) bool {
	return ni+nr >= 1 && nr <= ni && ni <= nr+1
}

func TestPatternArity_Rejects(t *testing.T) {
	cases := []struct {
		name       string
		init, resp [][]Token
		marker     string
	}{
		// Zero messages: no handshake at all.
		{"zero_message", nil, nil, arityZeroMarker},
		// Responder writes the first message (no initiator message): ni < nr.
		{"responder_first", nil, [][]Token{{TokenE, TokenEE}}, arityRespFirstMarker},
		// Responder-heavy (ni=1, nr=2): ni < nr. A shape the runtime status machine
		// (strict Send/Receive toggle) cannot drive without overflowing.
		{"responder_heavy", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE}, {TokenSE}}, arityRespFirstMarker},
		// One-way (responder silent) with more than one initiator message: nr==0,
		// ni>1. A one-way pattern is a single message (Noise section 7.4).
		{"oneway_multi_message", [][]Token{{TokenE}, {TokenES}}, nil, arityOneWayMarker},
		// Message-count skew with a non-silent responder: ni > nr+1.
		{"skew_init_3_resp_1", [][]Token{{TokenE}, {TokenES}, {TokenS}}, [][]Token{{TokenEE}}, aritySkewMarker},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, nil, nil)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), c.marker) {
				t.Fatalf("rejection did not come from the arity validator (missing %q): %v", c.marker, err)
			}
		})
	}
}

// TestPatternArity_BruteForceMatchesInvariant enumerates every (numInitiator,
// numResponder) shape in a small grid and asserts: an arity-INVALID shape is
// rejected by NewPattern WITH an arity marker, and an arity-VALID shape is NEVER
// rejected with an arity marker (it may still be rejected by a LATER validator,
// but not by arity). validatePatternArity runs first, so this cleanly isolates
// it. Removing the validatePatternArity call makes the invalid shapes lose their
// arity marker, failing here.
func TestPatternArity_BruteForceMatchesInvariant(t *testing.T) {
	hasArityMarker := func(err error) bool {
		if err == nil {
			return false
		}
		s := err.Error()
		return strings.Contains(s, arityZeroMarker) ||
			strings.Contains(s, arityRespFirstMarker) ||
			strings.Contains(s, arityOneWayMarker) ||
			strings.Contains(s, aritySkewMarker)
	}
	repeat := func(n int) [][]Token {
		out := make([][]Token, n)
		for i := range out {
			out[i] = []Token{TokenE} // simple non-empty body; arity is count-only
		}
		return out
	}
	checked := 0
	for ni := 0; ni <= 4; ni++ {
		for nr := 0; nr <= 4; nr++ {
			_, err := NewPattern("grid", repeat(ni), repeat(nr), nil, nil)
			valid := arityValid(ni, nr)
			marked := hasArityMarker(err)
			if valid && marked {
				t.Fatalf("arity wrongly rejected a valid shape ni=%d nr=%d: %v", ni, nr, err)
			}
			if !valid && !marked {
				t.Fatalf("arity did not reject an invalid shape ni=%d nr=%d (err=%v)", ni, nr, err)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("grid checked zero shapes")
	}
}

func TestHasCryptographicCalc_Rejects(t *testing.T) {
	cases := []struct {
		name       string
		init, resp [][]Token
		preI, preR []Token
	}{
		// Bare ephemerals, no DH/KEM: no shared secret.
		{"ephemerals_no_dh", [][]Token{{TokenE}}, [][]Token{{TokenE}}, nil, nil},
		// PSK present but no DH/KEM: a PSK is NOT counted as key agreement.
		{"psk_no_dh", [][]Token{{TokenE, TokenPsk}}, [][]Token{{TokenE}}, nil, nil},
		// Public keys only (e + s), no DH/KEM.
		{"keys_only_no_dh", [][]Token{{TokenE, TokenS}}, [][]Token{{TokenE, TokenS}}, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), noCalcMarker) {
				t.Fatalf("rejection did not come from the cryptographic-calc validator (missing %q): %v", noCalcMarker, err)
			}
		})
	}
}

// TestHasCryptographicCalc_AllPredefinedHaveCalc invokes the validator DIRECTLY
// on every predefined pattern, asserting acceptance (a non-vacuous guard: all 90
// built-ins perform a key agreement, so a regression that over-rejects is caught
// here independently of the reject cases above).
func TestHasCryptographicCalc_AllPredefinedHaveCalc(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateHasCryptographicCalc(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by cryptographic-calc validator: %v", p.Name(), err)
		}
	}
}

// TestDerivedOneWay_MatchesStructure confirms the derived isOneWay bit equals
// (numResponder == 0) for every predefined pattern, and that a custom single-
// message responder-silent pattern (the PQ Skem-to-pre-shared-static shape, which
// a prior test mislabeled non-one-way) is now correctly reported one-way. The bit
// is derived from structure, never caller-asserted, so it can never disagree with
// the message counts that drive the transport one-way gating.
func TestDerivedOneWay_MatchesStructure(t *testing.T) {
	for _, p := range AllPatterns() {
		if want := p.NumResponderMessages() == 0; p.IsOneWay() != want {
			t.Fatalf("pattern %q: IsOneWay()=%v, want %v (numResponder=%d)",
				p.Name(), p.IsOneWay(), want, p.NumResponderMessages())
		}
	}
	// A responder-silent PQ pattern: the initiator encapsulates to the
	// responder's pre-shared static. numResponder==0, so it is one-way.
	p, err := NewPattern("skemOneWay", [][]Token{{TokenSkem}}, nil, nil, []Token{TokenS})
	if err != nil {
		t.Fatalf("responder-silent skem pattern wrongly rejected: %v", err)
	}
	if !p.IsOneWay() {
		t.Fatal("responder-silent pattern should be derived one-way")
	}
}
