package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the construction-time token-domain rule
// (validateTokenDomain): a pre-message may carry only Token::E or Token::S
// (Noise section 7.1), and a message body may carry only a defined token value
// (TokenE..TokenSkem). NewPattern rejects violations up front rather than
// letting them fail late in the runtime token handlers (processPreMessages /
// processWriteToken / processReadToken).
//
// Each reject case asserts errors.Is(ErrInvalidPattern) AND the marker unique to
// the offending rule, so the rejection provably comes from this validator.
//
// WIRING: removing the validateTokenDomain call from NewPattern flips every
// NewPattern reject case below to accept (failing the errors.Is/marker checks);
// the all-90 direct-call guard and the brute-force cross-check additionally
// exercise the validator itself - independent guards against an accidental
// unwiring.

const (
	preMessageDomainMarker = "pre-message tokens may be only e or s"
	bodyDomainMarker       = "carries unknown token value"
)

func TestNewPattern_RejectsUnknownBodyToken(t *testing.T) {
	cases := []struct {
		name       string
		init, resp [][]Token
		wantRole   string // the offending party named in the error
	}{
		{"init_body_99", [][]Token{{TokenE, Token(99)}}, [][]Token{{TokenE, TokenEE}}, "initiator"},
		{"resp_body_200", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, Token(200)}}, "responder"},
		{"resp_body_255", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE, Token(255)}}, "responder"},
		// KEM-shaped body carrying an out-of-domain value.
		{"pq_body_99", [][]Token{{TokenE, Token(99)}}, [][]Token{{TokenEkem}}, "initiator"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, nil, nil)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), bodyDomainMarker) {
				t.Fatalf("rejection did not come from the body token-domain check (missing %q): %v", bodyDomainMarker, err)
			}
			// Pin the offending party so a future role-swap cannot ship green.
			if !strings.Contains(err.Error(), c.wantRole+" message") {
				t.Fatalf("body reject must name the offending party (%q): %v", c.wantRole+" message", err)
			}
		})
	}
}

func TestNewPattern_RejectsNonEphemeralStaticPreMessage(t *testing.T) {
	bad := []Token{TokenEE, TokenES, TokenSE, TokenSS, TokenPsk, TokenEkem, TokenSkem, Token(99)}
	for _, tok := range bad {
		tok := tok
		t.Run("preI_"+tokenString(tok), func(t *testing.T) {
			_, err := NewPattern("preI", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE}}, []Token{tok}, nil)
			requirePreMessageDomainReject(t, err, "initiator")
		})
		t.Run("preR_"+tokenString(tok), func(t *testing.T) {
			_, err := NewPattern("preR", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE}}, nil, []Token{tok})
			requirePreMessageDomainReject(t, err, "responder")
		})
	}
}

// A valid token next to an invalid one in the same pre-message is rejected on
// the invalid one regardless of order.
func TestNewPattern_RejectsMixedPreMessage(t *testing.T) {
	cases := []struct {
		name string
		preI []Token
	}{
		{"valid_then_invalid", []Token{TokenE, Token(99)}},
		{"invalid_then_valid", []Token{Token(99), TokenE}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, [][]Token{{}}, [][]Token{{TokenE, TokenEE}}, c.preI, nil)
			requirePreMessageDomainReject(t, err, "initiator")
		})
	}
}

// An out-of-domain token in a PRE-MESSAGE is reported by the pre-message rule
// (which subsumes the body domain check for pre-messages), not the body rule.
func TestNewPattern_OutOfDomainInPreMessageUsesPreMessageMarker(t *testing.T) {
	_, err := NewPattern("preI_99", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenEE}}, []Token{Token(99)}, nil)
	if !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("want ErrInvalidPattern, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), preMessageDomainMarker) {
		t.Fatalf("out-of-domain pre-message token must use the pre-message marker, got: %v", err)
	}
	if strings.Contains(err.Error(), bodyDomainMarker) {
		t.Fatalf("pre-message rejection must not use the body marker: %v", err)
	}
	if !strings.Contains(err.Error(), "initiator pre-message") {
		t.Fatalf("pre-message reject must name the offending party: %v", err)
	}
}

// A body-token rejection reports the message's interleaved (wire-order) index,
// consistent with every other position-naming validator (all share
// walkInterleaved). The offending token here sits in the initiator's second
// message, whose interleaved position is 2 (initiator msg 0, responder msg 0,
// initiator msg 1) - not the per-role index 1.
func TestNewPattern_BodyRejectUsesInterleavedMessageIndex(t *testing.T) {
	_, err := NewPattern("interleaved",
		[][]Token{{TokenE}, {TokenSE, Token(99)}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil)
	if !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("want ErrInvalidPattern, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), bodyDomainMarker) {
		t.Fatalf("want body domain marker, got %v", err)
	}
	if !strings.Contains(err.Error(), "initiator message 2") {
		t.Fatalf("body reject must report role + interleaved message index (initiator message 2), got: %v", err)
	}
}

func requirePreMessageDomainReject(t *testing.T, err error, wantRole string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("want ErrInvalidPattern, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), preMessageDomainMarker) {
		t.Fatalf("rejection did not come from the pre-message token-domain check (missing %q): %v", preMessageDomainMarker, err)
	}
	// Pin the offending party so a future role-swap cannot ship green.
	if !strings.Contains(err.Error(), wantRole+" pre-message") {
		t.Fatalf("pre-message reject must name the offending party (%q): %v", wantRole+" pre-message", err)
	}
}

func TestNewPattern_AcceptsValidTokenDomain(t *testing.T) {
	cases := []struct {
		name       string
		init, resp [][]Token
		preI, preR []Token
	}{
		// Pre-shared ephemeral (Token::E in a pre-message) with an empty body so
		// the party does not also emit its ephemeral.
		{"pre_message_e", [][]Token{{}}, [][]Token{{TokenE, TokenEE}}, []Token{TokenE}, nil},
		// Pre-shared static (NK shape).
		{"pre_message_s", [][]Token{{TokenE, TokenES}}, [][]Token{{TokenE, TokenEE}}, nil, []Token{TokenS}},
		// PSK token in a body is a defined value (NNpsk0 shape).
		{"psk_in_body", [][]Token{{TokenPsk, TokenE}}, [][]Token{{TokenE, TokenEE}}, nil, nil},
		// KEM tokens in a body are defined values (pqNK shape).
		{"kem_in_body", [][]Token{{TokenSkem, TokenE}}, [][]Token{{TokenEkem}}, nil, []Token{TokenS}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR); err != nil {
				t.Fatalf("valid-domain pattern wrongly rejected: %v", err)
			}
		})
	}
}

// TestTokenDomain_AllPredefinedValidate invokes the validator directly on every
// predefined pattern, asserting acceptance - a non-vacuous all-90 guard.
func TestTokenDomain_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateTokenDomain(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by token-domain validator: %v", p.Name(), err)
		}
	}
}

// A message body containing all nine defined tokens is domain-valid: the domain
// check must accept it even though other validators reject it for position/order
// reasons. Exercised directly via buildPatternForTest.
func TestValidateTokenDomain_AcceptsAllNineDefinedTokensInOneBody(t *testing.T) {
	p := buildPatternForTest(
		[][]Token{{TokenE, TokenS, TokenEE, TokenES, TokenSE, TokenSS, TokenPsk, TokenEkem, TokenSkem}},
		nil, nil, nil)
	if err := validateTokenDomain(p); err != nil {
		t.Fatalf("a body of all nine defined tokens must pass the domain check: %v", err)
	}
}

// referenceTokenDomainRejects is an independent re-derivation of the rule used to
// cross-check the production validator: reject iff any pre-message token is not
// e/s, or any body token is not a defined value.
func referenceTokenDomainRejects(init, resp [][]Token, preI, preR []Token) bool {
	defined := map[Token]bool{
		TokenE: true, TokenS: true, TokenEE: true, TokenES: true, TokenSE: true,
		TokenSS: true, TokenPsk: true, TokenEkem: true, TokenSkem: true,
	}
	for _, t := range preI {
		if t != TokenE && t != TokenS {
			return true
		}
	}
	for _, t := range preR {
		if t != TokenE && t != TokenS {
			return true
		}
	}
	for _, lists := range [][][]Token{init, resp} {
		for _, m := range lists {
			for _, t := range m {
				if !defined[t] {
					return true
				}
			}
		}
	}
	return false
}

// TestTokenDomain_BruteForceMatchesReference enumerates one-message bodies over
// an alphabet that INCLUDES an out-of-domain value, with pre-message variants
// that include a non-e/s and an out-of-domain token, and asserts the production
// validator agrees with the independent reference on every one. Built directly
// via buildPatternForTest so the domain validator is exercised in isolation.
func TestTokenDomain_BruteForceMatchesReference(t *testing.T) {
	alphabet := []Token{TokenE, TokenS, TokenEE, TokenSkem, Token(99)}
	msgs := [][]Token{{}}
	msgs = append(msgs, singles(alphabet)...)
	msgs = append(msgs, pairs(alphabet)...)
	preOpts := [][]Token{nil, {TokenE}, {TokenS}, {TokenPsk}, {Token(99)}}

	checked := 0
	for _, init := range msgs {
		for _, resp := range msgs {
			for _, preI := range preOpts {
				for _, preR := range preOpts {
					p := buildPatternForTest([][]Token{init}, [][]Token{resp}, preI, preR)
					got := validateTokenDomain(p) != nil
					want := referenceTokenDomainRejects([][]Token{init}, [][]Token{resp}, preI, preR)
					if got != want {
						t.Fatalf("mismatch init=%v resp=%v preI=%v preR=%v: validator reject=%v, reference reject=%v",
							init, resp, preI, preR, got, want)
					}
					checked++
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("brute force checked zero patterns")
	}
	t.Logf("token-domain brute force cross-checked %d patterns against the independent reference", checked)
}
