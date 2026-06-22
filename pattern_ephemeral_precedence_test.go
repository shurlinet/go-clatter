package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the construction-time precedence rule
// (validateEphemeralEmittedBeforeUse): a pattern in which a party consumes an
// ephemeral (a DH or KEM-decap that reads its local ephemeral) before emitting
// its Token::E can never complete a handshake and is rejected at NewPattern.
//
// Each reject case asserts errors.Is(ErrInvalidPattern) AND the precedence-
// specific marker AND that the error localizes the offending message, so the
// rejection provably comes from THIS validator (not an earlier one) and carries
// the message index. The cases are built to pass the earlier validators (PSK
// position, PQ token order, <=1-E cap).
//
// WIRING: removing the validateEphemeralEmittedBeforeUse call from NewPattern
// makes every reject case below return nil (failing the errors.Is check) AND
// makes TestEphemeralPrecedence_BruteForceMatchesReference fail on the first
// broken pattern - two independent test functions guard the wiring, so an
// accidental revert of the call cannot pass undetected.

// precedenceMarker is the substring unique to the precedence validator's error.
const precedenceMarker = "Token::E must precede use"

type precedenceCase struct {
	name       string
	init, resp [][]Token
	preI, preR []Token
}

func TestEphemeralPrecedence_Rejects(t *testing.T) {
	cases := []precedenceCase{
		// R1: initiator does es=DH(e,rs) but never emits Token::E.
		{"init_es_no_e", [][]Token{{TokenES}}, [][]Token{{TokenE}}, nil, nil},
		// R2: responder does ee=DH(e,re) but never emits Token::E.
		{"resp_ee_no_e", [][]Token{{TokenE}}, [][]Token{{TokenEE}}, nil, nil},
		// R3: responder does se=DH(e,rs) but never emits Token::E.
		{"resp_se_no_e", [][]Token{{TokenE, TokenS}}, [][]Token{{TokenSE}}, nil, nil},
		// R4: PQ initiator reads ekem (decap with local e) but never emits Token::E.
		{"pq_init_ekem_no_e", [][]Token{{}}, [][]Token{{TokenEkem}}, nil, nil},
		// R5: consume-before-emit WITHIN one message: ee precedes its own e.
		{"consume_before_emit_same_msg", [][]Token{{TokenEE, TokenE}}, [][]Token{{TokenE}}, nil, nil},
		// R6: one-way pattern, initiator es with no Token::E (responder writes nothing).
		{"oneway_init_es_no_e", [][]Token{{TokenES}}, nil, nil, []Token{TokenS}},
		// R7: hybrid (DH+KEM), initiator reads ekem before emitting Token::E.
		{"hybrid_init_ekem_no_e", [][]Token{{}}, [][]Token{{TokenEkem, TokenE, TokenEE}}, nil, nil},
		// R8: initiator-heavy asymmetry (init 2, resp 1) - the offending se sits in
		// the trailing INITIATOR message reached via the interleave toggle, and the
		// responder (its single message is empty) never emits Token::E, so se reads
		// an un-emitted responder ephemeral. Mirror of A6. (A responder-heavy ni<nr
		// shape would be rejected earlier by validatePatternArity, not this rule.)
		{"init_heavy_trailing_se_no_resp_e", [][]Token{{TokenE}, {TokenSE}}, [][]Token{{}}, nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), precedenceMarker) {
				t.Fatalf("rejection did not come from the precedence validator (missing %q): %v",
					precedenceMarker, err)
			}
			if !strings.Contains(err.Error(), "message ") {
				t.Fatalf("reject error must localize the offending message (parity with maxMsgLen): %v", err)
			}
		})
	}
}

func TestEphemeralPrecedence_Accepts(t *testing.T) {
	cases := []precedenceCase{
		// A2: PQ mutual-ephemeral - both parties emit Token::E; each ekem-read
		// follows that party's emission.
		{"pq_mutual_ephemeral", [][]Token{{TokenE}, {TokenEkem}}, [][]Token{{TokenEkem, TokenE}}, nil, nil},
		// A3: initiator emits Token::E only via a pre-message; its body is empty.
		{"premessage_e_initiator", [][]Token{{}}, [][]Token{{TokenE, TokenEE}}, []Token{TokenE}, nil},
		// A4: hybrid mixing ee (both) and ekem (reader) in one walk, well-formed
		// (hybridNN shape: -> e, <- ekem, e, ee).
		{"hybrid_ee_and_ekem", [][]Token{{TokenE}}, [][]Token{{TokenEkem, TokenE, TokenEE}}, nil, nil},
		// A5: one-way pattern, well-formed (N shape: -> e, es).
		{"oneway_well_formed", [][]Token{{TokenE, TokenES}}, nil, nil, []Token{TokenS}},
		// A6: asymmetric message counts (init 2, resp 1) with a responder-ephemeral
		// consumer (se) in the trailing initiator message - exercises the
		// interleave toggle as a precedence guard (XN shape).
		{"asymmetric_counts_trailing_consumer", [][]Token{{TokenE}, {TokenS, TokenSE}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// A7: static-bearing AND carrying a real key agreement (NX shape: a
		// responder Token::S alongside ee/es) - the EPHEMERAL validator must NOT
		// fire on the Token::S (statics are not ephemeral consumers). It carries a
		// DH so validateHasCryptographicCalc passes (a statics-only pattern with no
		// DH/KEM is correctly rejected as a non-handshake by that separate rule);
		// the all-90 direct-call guard below additionally exercises the ephemeral
		// validator ignoring ss (every K/I pattern carries one).
		{"statics_present_with_keyagreement", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, TokenS, TokenES}}, nil, nil},
		// A8: responder emits Token::E only via a pre-message; a later ee consumes
		// it - pins the emitted[responder] pre-message seed path.
		{"premessage_e_responder", [][]Token{{TokenE}}, [][]Token{{TokenEE}}, nil, []Token{TokenE}},
		// (The former responder-heavy ni=1/nr=2 toggle-accept "A9" is unconstructible
		// now - validatePatternArity requires numResponder <= numInitiator - and the
		// initiator-heavy toggle-accept it mirrored is already covered by A6, so it is
		// not re-added here.)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR); err != nil {
				t.Fatalf("well-formed pattern wrongly rejected: %v", err)
			}
		})
	}
}

// TestEphemeralPrecedence_AllPredefinedValidate invokes the validator DIRECTLY on
// every predefined pattern, asserting acceptance. The predefined patterns are
// built at package init via mustNewPattern, so a precedence violation would panic
// init; this guard additionally exercises validateEphemeralEmittedBeforeUse as a
// genuine (non-vacuous) check on all 90 patterns rather than relying on init
// survival alone.
func TestEphemeralPrecedence_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateEphemeralEmittedBeforeUse(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by precedence validator: %v", p.Name(), err)
		}
	}
}

// referencePrecedenceBroken is an INDEPENDENT re-derivation of the precedence
// rule used to cross-check NewPattern. It transcribes the interleave toggle and
// the emitted-before-use logic separately from the production walkInterleaved /
// validateEphemeralEmittedBeforeUse, so a bug in the shared walker's toggle or a
// silent removal of the NewPattern call is caught by disagreement. true means the
// pattern consumes some party's ephemeral before that party emits Token::E.
func referencePrecedenceBroken(init, resp [][]Token, preI, preR []Token) bool {
	contains := func(toks []Token, want Token) bool {
		for _, t := range toks {
			if t == want {
				return true
			}
		}
		return false
	}
	// emitted keyed by "is initiator".
	emitted := map[bool]bool{true: contains(preI, TokenE), false: contains(preR, TokenE)}

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
		reader := !writerInit
		for _, tk := range tokens {
			var consumers []bool // keyed by "is initiator"
			switch tk {
			case TokenEE:
				consumers = []bool{true, false}
			case TokenES:
				consumers = []bool{true}
			case TokenSE:
				consumers = []bool{false}
			case TokenEkem:
				consumers = []bool{reader}
			}
			for _, c := range consumers {
				if !emitted[c] {
					return true
				}
			}
			if tk == TokenE {
				emitted[writerInit] = true
			}
		}
		initTurn = !initTurn
	}
	return false
}

// referenceForwardSecrecyDHBroken is an INDEPENDENT re-derivation of the DH
// forward-secrecy rule (Noise section 7.3) used to EXCLUDE rule-violating shapes
// from the precedence brute-forces, so the precedence rule under test stays the
// sole discriminator (the analogue of the per-handshake DH-calc exclusion). It
// transcribes the interleave toggle and the encrypt-after-static-DH check
// separately from the production walkInterleaved /
// validateStaticDHComplementBeforeEncrypt. true means the pattern encrypts after
// a static-key DH with no ephemeral-DH complement - which NewPattern rejects via
// the LAST validator, NOT the precedence rule. Pre-messages carry no DH tokens,
// so they cannot affect the mixed-DH set and are not consulted.
func referenceForwardSecrecyDHBroken(init, resp [][]Token) bool {
	var mixedEE, mixedES, mixedSE, mixedSS bool
	broken := func(writerInit bool) bool {
		if writerInit {
			return (mixedSE && !mixedEE) || (mixedSS && !mixedES)
		}
		return (mixedES && !mixedEE) || (mixedSS && !mixedSE)
	}
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
			switch tk {
			case TokenS:
				if broken(writerInit) {
					return true
				}
			case TokenEE:
				mixedEE = true
			case TokenES:
				mixedES = true
			case TokenSE:
				mixedSE = true
			case TokenSS:
				mixedSS = true
			}
		}
		if broken(writerInit) {
			return true
		}
		initTurn = !initTurn
	}
	return false
}

// TestEphemeralPrecedence_BruteForceMatchesReference enumerates DH-only patterns
// over {E, EE, ES, SE} (no PSK / KEM / >1-E, so the ONLY rejecting validator is
// the precedence rule) and asserts NewPattern's accept/reject matches the
// independent reference for every one. This is the second, independent wiring
// guard: if the validator call were removed from NewPattern, NewPattern would
// accept a broken pattern the reference flags, failing here.
func TestEphemeralPrecedence_BruteForceMatchesReference(t *testing.T) {
	alphabet := []Token{TokenE, TokenEE, TokenES, TokenSE}

	// messages enumerates message lists: each list has 1..2 messages, each
	// message 0..2 tokens drawn from the alphabet.
	var messageLists [][][]Token
	msgs := [][]Token{{}}
	msgs = append(msgs, singles(alphabet)...)
	msgs = append(msgs, pairs(alphabet)...)
	for _, m1 := range msgs {
		messageLists = append(messageLists, [][]Token{m1})
		for _, m2 := range msgs {
			messageLists = append(messageLists, [][]Token{m1, m2})
		}
	}

	countE := func(lists ...[][]Token) int {
		n := 0
		for _, l := range lists {
			for _, m := range l {
				for _, tk := range m {
					if tk == TokenE {
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
			// non-alternating shape: zero messages, responder-heavy (ni<nr), or
			// message-count skew (ni>nr+1). Exclude them so the precedence rule
			// stays the sole discriminator (the reference models only precedence).
			ni, nr := len(init), len(resp)
			if ni+nr == 0 || nr > ni || ni > nr+1 {
				continue
			}
			// Keep the IFF clean: exclude patterns that an EARLIER validator
			// would reject (>1 Token::E per party). With this alphabet there are
			// no PSK or KEM tokens. Both parties pre-share a static (pre-message S)
			// so the es/se/ss static reads are always available - this isolates the
			// ephemeral-precedence rule from the static-precedence rule (the
			// alphabet has no Token::S, so the pre-message is the sole static and
			// no party double-sends).
			if countE(init) > 1 || countE(resp) > 1 {
				continue
			}
			// Noise section 7.3 rule 3 (validateDHCalcAtMostOnce): each of
			// ee/es/se/ss occurs at most once PER HANDSHAKE (init + resp combined).
			// That is a separate validator from the ephemeral-precedence rule under
			// test here, so exclude double-DH patterns to keep the precedence
			// validator the sole discriminator (mirrors the countE>1 exclusion).
			countDH := func(want Token) int {
				n := 0
				for _, l := range [][][]Token{init, resp} {
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
			if countDH(TokenEE) > 1 || countDH(TokenES) > 1 || countDH(TokenSE) > 1 || countDH(TokenSS) > 1 {
				continue
			}
			// validateHasCryptographicCalc (a SEPARATE validator) rejects a pattern
			// with no DH/KEM token at all. This alphabet's only key-agreement tokens
			// are ee/es/se, so exclude patterns carrying none (all-empty or
			// Token::E-only) - the reference models only precedence and would accept
			// them.
			if countDH(TokenEE)+countDH(TokenES)+countDH(TokenSE) == 0 {
				continue
			}
			// Noise section 7.3 forward secrecy (validateStaticDHComplement-
			// BeforeEncrypt): a static-key DH encrypted-after with no ephemeral-DH
			// complement is rejected by the LAST validator, not the precedence rule
			// under test. Exclude those shapes so the precedence rule stays the sole
			// discriminator (mirrors the DH-calc exclusion above).
			if referenceForwardSecrecyDHBroken(init, resp) {
				continue
			}
			preS := []Token{TokenS}
			_, err := NewPattern("bruteforce", init, resp, preS, preS)
			gotReject := errors.Is(err, ErrInvalidPattern)
			wantReject := referencePrecedenceBroken(init, resp, preS, preS)
			if gotReject != wantReject {
				t.Fatalf("mismatch init=%v resp=%v: NewPattern reject=%v (%v), reference reject=%v",
					init, resp, gotReject, err, wantReject)
			}
			if gotReject && !strings.Contains(err.Error(), precedenceMarker) {
				t.Fatalf("reject for init=%v resp=%v not from precedence validator: %v", init, resp, err)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("brute force checked zero patterns")
	}
	t.Logf("brute force cross-checked %d patterns against the independent reference", checked)
}

// singles returns each alphabet token as a one-token message.
func singles(alphabet []Token) [][]Token {
	out := make([][]Token, 0, len(alphabet))
	for _, a := range alphabet {
		out = append(out, []Token{a})
	}
	return out
}

// pairs returns every ordered two-token message over the alphabet.
func pairs(alphabet []Token) [][]Token {
	out := make([][]Token, 0, len(alphabet)*len(alphabet))
	for _, a := range alphabet {
		for _, b := range alphabet {
			out = append(out, []Token{a, b})
		}
	}
	return out
}
