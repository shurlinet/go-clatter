package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the construction-time static-precedence rule
// (validateStaticAvailableBeforeUse): a pattern in which a token reads a REMOTE
// static (DH es/se/ss or a KEM skem-encap) before that static's owner has
// transmitted it (Token::S) or pre-shared it (pre-message) can never complete a
// handshake and is rejected at NewPattern. This is the static analogue of the
// ephemeral-precedence suite; the patterns here keep the EPHEMERAL side
// well-formed so any rejection provably comes from the static validator.
//
// Each reject case asserts errors.Is(ErrInvalidPattern) AND the static-specific
// marker AND that the error localizes the offending message.
//
// WIRING: removing the validateStaticAvailableBeforeUse call from NewPattern
// makes every reject case below return nil (failing the errors.Is check) AND
// makes TestStaticPrecedence_BruteForceMatchesReference fail on the first broken
// pattern - two independent test functions guard the wiring.

// staticPrecedenceMarker is the substring unique to the static validator's error.
const staticPrecedenceMarker = "transmitted or pre-shared"

type staticPrecedenceCase struct {
	name       string
	init, resp [][]Token
	preI, preR []Token
}

func TestStaticPrecedence_Rejects(t *testing.T) {
	cases := []staticPrecedenceCase{
		// R1: initiator es=DH(e,rs) reads the responder static before the
		// responder transmits it (responder's Token::S is never sent).
		{"init_es_no_remote_s", [][]Token{{TokenE, TokenES}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// R2: responder se=DH(e,rs) reads the initiator static before the
		// initiator transmits it.
		{"resp_se_no_remote_s", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, TokenSE}}, nil, nil},
		// R3: ss reads BOTH statics; the responder leg is untransmitted (the
		// initiator transmits its own S in the same message before the ss).
		{"ss_responder_leg_untransmitted", [][]Token{{TokenE, TokenS, TokenSS}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// R4: PQ skem-encap to the responder static before the responder
		// transmits it (skem owner = writer.other() = responder).
		{"skem_encap_no_remote_s", [][]Token{{TokenE, TokenSkem}}, [][]Token{{TokenEkem}}, nil, nil},
		// R5: one-way pattern, initiator es with no responder pre-message static
		// and no responder messages to transmit one.
		{"oneway_es_no_remote_s", [][]Token{{TokenE, TokenES}}, nil, nil, nil},
		// R6: hybrid (DH+KEM), initiator es reads the responder static before it
		// is transmitted (ekem keeps it a Hybrid pattern; ee/E keep the
		// ephemeral-precedence rule happy).
		{"hybrid_es_no_remote_s", [][]Token{{TokenE, TokenES}}, [][]Token{{TokenEkem, TokenE, TokenEE}}, nil, nil},
		// R7: initiator-heavy asymmetry (init 2, resp 1) - the offending se sits in
		// the trailing INITIATOR message reached via the toggle; se reads the
		// initiator's own remote static, which the initiator never transmits (no
		// Token::S, no pre-message). Mirror of A7. (A responder-heavy ni<nr shape
		// would be rejected earlier by validatePatternArity, not this rule.)
		{"init_heavy_trailing_se_no_local_s", [][]Token{{TokenE}, {TokenSE}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// R8: HYBRID skem-encap reads the responder static before it is
		// transmitted (distinct from R4's pure-PQ skem; ee/E keep the ephemeral
		// validator happy, so the rejection comes from the static rule).
		{"hybrid_skem_encap_no_remote_s", [][]Token{{TokenE, TokenSkem}}, [][]Token{{TokenEkem, TokenE, TokenEE}}, nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), staticPrecedenceMarker) {
				t.Fatalf("rejection did not come from the static-precedence validator (missing %q): %v",
					staticPrecedenceMarker, err)
			}
			if !strings.Contains(err.Error(), "message ") {
				t.Fatalf("reject error must localize the offending message (parity with the ephemeral validator): %v", err)
			}
		})
	}
}

func TestStaticPrecedence_Accepts(t *testing.T) {
	cases := []staticPrecedenceCase{
		// A1: NK shape - responder pre-shares its static, so the initiator's es
		// reads an available remote static.
		{"premessage_remote_s_es", [][]Token{{TokenE, TokenES}}, [][]Token{{TokenE, TokenEE}}, nil, []Token{TokenS}},
		// A2: XX shape - the responder transmits S then immediately reads it via
		// es in the SAME message (just-in-time).
		{"xx_just_in_time_es", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, TokenS, TokenES}}, nil, nil},
		// A3: real KK shape - ss with both statics pre-shared, carrying the es/se
		// complements that give the ss-keyed payload forward secrecy (a bare ss
		// with no ephemeral DH cannot satisfy the forward-secrecy rule). Still
		// exercises the static validator's ss-reads-both-pre-shared-statics path.
		{"ss_both_premessage", [][]Token{{TokenE, TokenES, TokenSS}}, [][]Token{{TokenE, TokenEE, TokenSE}}, []Token{TokenS}, []Token{TokenS}},
		// A4: pqNK shape - skem-encap to a pre-shared responder static.
		{"skem_premessage_remote_s", [][]Token{{TokenSkem, TokenE}}, [][]Token{{TokenEkem}}, nil, []Token{TokenS}},
		// A5: pure ephemeral, no static token at all - the static-precedence
		// validator must NOT fire (the reverse fence of the ephemeral-vs-static
		// validator boundary).
		{"ephemeral_only", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// A6: hybrid just-in-time - responder transmits S then es reads it (hybrid
		// because ekem is present).
		{"hybrid_just_in_time_es", [][]Token{{TokenE}}, [][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}}, nil, nil},
		// A7: XN shape - initiator transmits S then se reads it in the SAME
		// trailing message; well-formed asymmetric mirror of R7.
		{"xn_just_in_time_se", [][]Token{{TokenE}, {TokenS, TokenSE}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR); err != nil {
				t.Fatalf("well-formed pattern wrongly rejected: %v", err)
			}
		})
	}
}

// TestStaticPrecedence_AllPredefinedValidate invokes the validator DIRECTLY on
// every predefined pattern, asserting acceptance. The predefined patterns are
// built at package init via mustNewPattern, so a precedence violation would panic
// init; this guard additionally exercises validateStaticAvailableBeforeUse as a
// genuine (non-vacuous) check on all 90 patterns rather than relying on init
// survival alone.
func TestStaticPrecedence_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateStaticAvailableBeforeUse(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by static-precedence validator: %v", p.Name(), err)
		}
	}
}

// referenceStaticUseBeforeTransmit is an INDEPENDENT re-derivation of the static
// precedence rule used to cross-check NewPattern. It transcribes the interleave
// toggle and the transmit-before-use logic separately from the production
// walkInterleaved / validateStaticAvailableBeforeUse, so a bug in the shared
// walker's toggle or a silent removal of the NewPattern call is caught by
// disagreement. true means the pattern reads some party's remote static before
// that party transmits or pre-shares it.
func referenceStaticUseBeforeTransmit(init, resp [][]Token, preI, preR []Token) bool {
	contains := func(toks []Token, want Token) bool {
		for _, t := range toks {
			if t == want {
				return true
			}
		}
		return false
	}
	// transmitted keyed by "is initiator".
	transmitted := map[bool]bool{true: contains(preI, TokenS), false: contains(preR, TokenS)}

	ii, ri := 0, 0
	initTurn := true
	for ii < len(init) || ri < len(resp) {
		var tokens []Token
		var writerInit bool
		switch {
		case initTurn && ii < len(init):
			tokens, writerInit = init[ii], true
			ii++
		case !initTurn && ri < len(resp):
			tokens, writerInit = resp[ri], false
			ri++
		default:
			initTurn = !initTurn
			continue
		}
		for _, tk := range tokens {
			var owners []bool // keyed by "is initiator"
			switch tk {
			case TokenES:
				owners = []bool{false} // responder static
			case TokenSE:
				owners = []bool{true} // initiator static
			case TokenSS:
				owners = []bool{true, false}
			case TokenSkem:
				owners = []bool{!writerInit} // reader = writer.other()
			}
			for _, o := range owners {
				if !transmitted[o] {
					return true
				}
			}
			if tk == TokenS {
				transmitted[writerInit] = true
			}
		}
		initTurn = !initTurn
	}
	return false
}

// TestStaticPrecedence_BruteForceMatchesReference enumerates DH patterns over
// {E, S, ES, SE, SS} and asserts NewPattern's accept/reject matches the
// independent reference for every EPHEMERAL-well-formed pattern (so the static
// validator is the sole discriminator; patterns the ephemeral validator would
// reject are skipped via the ephemeral-precedence reference). This is the second, independent
// wiring guard: removing the validator call from NewPattern makes NewPattern
// accept a static-broken pattern the reference flags, failing here.
func TestStaticPrecedence_BruteForceMatchesReference(t *testing.T) {
	alphabet := []Token{TokenE, TokenS, TokenES, TokenSE, TokenSS}

	msgs := [][]Token{{}}
	msgs = append(msgs, singles(alphabet)...)
	msgs = append(msgs, pairs(alphabet)...)
	var messageLists [][][]Token
	for _, m1 := range msgs {
		messageLists = append(messageLists, [][]Token{m1})
		for _, m2 := range msgs {
			messageLists = append(messageLists, [][]Token{m1, m2})
		}
	}

	countTok := func(want Token, lists ...[][]Token) int {
		n := 0
		for _, l := range lists {
			for _, m := range l {
				for _, tk := range m {
					if tk == want {
						n++
					}
				}
			}
		}
		return n
	}

	checked := 0
	for _, init := range messageLists {
		for _, resp := range messageLists {
			// validatePatternArity (a SEPARATE, earlier validator) rejects any
			// non-alternating shape (zero messages, responder-heavy ni<nr, or skew
			// ni>nr+1). Exclude them so the static rule stays the sole discriminator.
			ni, nr := len(init), len(resp)
			if ni+nr == 0 || nr > ni || ni > nr+1 {
				continue
			}
			// Exclude patterns an EARLIER validator would reject so the static
			// validator is the only discriminator: >1 Token::E or >1 Token::S
			// per party (Noise rule 2), and any ephemeral-precedence violation
			// (reuse the ephemeral-precedence reference).
			if countTok(TokenE, init) > 1 || countTok(TokenE, resp) > 1 {
				continue
			}
			if countTok(TokenS, init) > 1 || countTok(TokenS, resp) > 1 {
				continue
			}
			// validateHasCryptographicCalc (a SEPARATE validator) rejects a pattern
			// with no DH/KEM token at all. This alphabet's key-agreement tokens are
			// es/se/ss, so exclude patterns carrying none (the reference models only
			// the static rule and would accept them).
			if countTok(TokenES, init, resp)+countTok(TokenSE, init, resp)+countTok(TokenSS, init, resp) == 0 {
				continue
			}
			if referencePrecedenceBroken(init, resp, nil, nil) {
				continue
			}
			// Noise section 7.3 rule 3 (validateDHCalcAtMostOnce): each of
			// ee/es/se/ss occurs at most once PER HANDSHAKE (init + resp combined).
			// That is a separate validator from the static-precedence rule under
			// test here, so exclude double-DH patterns to keep the static validator
			// the sole discriminator (mirrors the rule-1/rule-2 exclusions above).
			if countTok(TokenEE, init, resp) > 1 || countTok(TokenES, init, resp) > 1 ||
				countTok(TokenSE, init, resp) > 1 || countTok(TokenSS, init, resp) > 1 {
				continue
			}
			// Noise section 7.3 forward secrecy (validateStaticDHComplement-
			// BeforeEncrypt): exclude encrypt-after-static-DH-without-ephemeral
			// shapes so the static-precedence rule under test stays the sole
			// discriminator (mirrors the rule-1/rule-2/rule-3 exclusions above).
			if referenceForwardSecrecyDHBroken(init, resp) {
				continue
			}

			_, err := NewPattern("bruteforce", init, resp, nil, nil)
			gotReject := errors.Is(err, ErrInvalidPattern)
			wantReject := referenceStaticUseBeforeTransmit(init, resp, nil, nil)
			if gotReject != wantReject {
				t.Fatalf("mismatch init=%v resp=%v: NewPattern reject=%v (%v), reference reject=%v",
					init, resp, gotReject, err, wantReject)
			}
			if gotReject && !strings.Contains(err.Error(), staticPrecedenceMarker) {
				t.Fatalf("reject for init=%v resp=%v not from static-precedence validator: %v", init, resp, err)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("brute force checked zero patterns")
	}
	t.Logf("brute force cross-checked %d patterns against the independent reference", checked)
}
