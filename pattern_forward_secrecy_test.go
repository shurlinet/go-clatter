package clatter

import (
	"errors"
	"strings"
	"testing"
)

// Regression suite for the two construction-time forward-secrecy rules
// (Noise section 7.3): a party must not ENCRYPT() after a static-key DH without
// the local-ephemeral DH that protects it (validateStaticDHComplementBeforeEncrypt),
// and the post-quantum analogue for a static-KEM seal
// (validateStaticKEMSealHasComplement). Both are wired LAST in NewPattern and
// accept all 90 predefined patterns; they reject only malformed custom patterns.
//
// WIRING: removing either validator's call from NewPattern flips its Rejects
// cases to accept (failing the errors.Is + marker checks); the all-90 direct-call
// guards and the brute-forces additionally exercise each validator as a genuine
// (non-vacuous) check - independent guards against an accidental unwiring.

// dhFSMarker / kemFSMarker are the substrings unique to each forward-secrecy
// validator's error, distinct from every other validator's marker.
const (
	dhFSMarker  = "ephemeral DH that protects it"
	kemFSMarker = "ephemeral KEM that protects it"
)

type fsCase struct {
	name       string
	init, resp [][]Token
	preI, preR []Token
}

// ---------------------------------------------------------------------------
// DH forward-secrecy triad
// ---------------------------------------------------------------------------

func TestForwardSecrecyDH_Rejects(t *testing.T) {
	// Each pattern is well-formed under every OTHER validator (PSK, PQ order,
	// e/s at-most-once, DH-calc-at-most-once, both precedence rules), so the
	// missing ephemeral-DH complement is the sole defect and the rejection
	// provably comes from the DH forward-secrecy rule. The four cases cover all
	// four role/operand branches.
	cases := []fsCase{
		// initiator se (s . remote-e) with no ee complement (XN shape minus ee).
		{"init_se_without_ee", [][]Token{{TokenE}, {TokenS, TokenSE}}, [][]Token{{TokenE}}, nil, nil},
		// responder es (s . remote-e) with no ee complement (NX shape minus ee).
		{"resp_es_without_ee", [][]Token{{TokenE}}, [][]Token{{TokenE, TokenS, TokenES}}, nil, nil},
		// initiator ss (s . remote-s) with no es complement (KK shape minus es).
		{"init_ss_without_es", [][]Token{{TokenE, TokenSS}}, [][]Token{{TokenE, TokenEE}}, []Token{TokenS}, []Token{TokenS}},
		// responder ss with no se complement (the ss sits in the responder message).
		{"resp_ss_without_se", [][]Token{{TokenE, TokenES}}, [][]Token{{TokenE, TokenEE, TokenSS}}, []Token{TokenS}, []Token{TokenS}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), dhFSMarker) {
				t.Fatalf("rejection did not come from the DH forward-secrecy validator (missing %q): %v", dhFSMarker, err)
			}
			if !strings.Contains(err.Error(), "message ") {
				t.Fatalf("reject error must localize the offending message: %v", err)
			}
		})
	}
}

// TestForwardSecrecyDH_AcceptsSingle pins that the canonical forward-secret DH
// pattern (XX: each static-key DH is complemented by an ephemeral DH before the
// encrypt) is accepted - the validator must not over-reject.
func TestForwardSecrecyDH_AcceptsSingle(t *testing.T) {
	if _, err := NewPattern("okXX",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil); err != nil {
		t.Fatalf("well-formed XX wrongly rejected by the DH forward-secrecy rule: %v", err)
	}
}

// TestForwardSecrecyDH_AllPredefinedValidate invokes the DH forward-secrecy
// validator DIRECTLY on every predefined pattern, asserting acceptance - the
// direct-call 0/90 proof (the package-init mustNewPattern proof is implicit).
func TestForwardSecrecyDH_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateStaticDHComplementBeforeEncrypt(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by DH forward-secrecy validator: %v", p.Name(), err)
		}
	}
}

// TestForwardSecrecyDH_BruteForceMatchesReference enumerates DH patterns over
// {E, EE, ES, SE, SS} with both statics pre-shared, excludes every shape an
// EARLIER validator would reject (so the DH forward-secrecy rule is the sole
// discriminator), and asserts the production validator's verdict matches the
// independent referenceForwardSecrecyDHBroken for every one. The pattern struct
// is built directly so the validator is exercised in isolation.
func TestForwardSecrecyDH_BruteForceMatchesReference(t *testing.T) {
	alphabet := []Token{TokenE, TokenEE, TokenES, TokenSE, TokenSS}
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

	count := func(want Token, lists ...[][]Token) int {
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

	preS := []Token{TokenS}
	checked := 0
	for _, init := range messageLists {
		for _, resp := range messageLists {
			// Exclude rule-2 (>1 E/party) and rule-3 (>1 DH-calc/handshake), and
			// any ephemeral-precedence violation - the only remaining discriminator
			// is the DH forward-secrecy rule. Statics are pre-shared so the static
			// precedence rule never fires (no Token::S in the alphabet).
			if count(TokenE, init) > 1 || count(TokenE, resp) > 1 {
				continue
			}
			if count(TokenEE, init, resp) > 1 || count(TokenES, init, resp) > 1 ||
				count(TokenSE, init, resp) > 1 || count(TokenSS, init, resp) > 1 {
				continue
			}
			if referencePrecedenceBroken(init, resp, preS, preS) {
				continue
			}
			p := buildPatternForTest(init, resp, preS, preS)
			gotReject := validateStaticDHComplementBeforeEncrypt(p) != nil
			wantReject := referenceForwardSecrecyDHBroken(init, resp)
			if gotReject != wantReject {
				t.Fatalf("DH FS mismatch init=%v resp=%v: validator reject=%v, reference reject=%v",
					init, resp, gotReject, wantReject)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("DH forward-secrecy brute force checked zero patterns")
	}
	t.Logf("DH forward-secrecy brute force cross-checked %d patterns against the independent reference", checked)
}

// ---------------------------------------------------------------------------
// KEM forward-secrecy triad
// ---------------------------------------------------------------------------

func TestForwardSecrecyKEM_Rejects(t *testing.T) {
	// Each pattern is well-formed under every other validator, so the missing
	// achievable ephemeral-KEM complement is the sole defect.
	cases := []fsCase{
		// Pattern S (the reply-suppliable class): the responder seals a static-KEM
		// to the initiator's static, but the initiator emitted Token::E earlier and
		// could have ephemeral-KEM-encapsulated to it on the reply - omitted.
		{"reply_suppliable_skem", [][]Token{{}, {TokenS}}, [][]Token{{TokenE}, {TokenSkem}}, nil, nil},
		// The responder decapsulates the initiator's static-KEM, then seals an
		// (empty) payload with no reply ephemeral-KEM, though the initiator's
		// Token::E made one achievable (pqNK with the reply ekem deleted).
		{"decap_no_reply_ekem", [][]Token{{TokenSkem, TokenE}}, [][]Token{{}}, nil, []Token{TokenS}},
		// The responder encapsulates a static-KEM when the initiator's prior
		// Token::E made an ephemeral-KEM encapsulation achievable - omitted.
		{"encaps_skem_when_ekem_available", [][]Token{{TokenE, TokenS}}, [][]Token{{TokenSkem}}, nil, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR)
			if !errors.Is(err, ErrInvalidPattern) {
				t.Fatalf("want ErrInvalidPattern, got %v", err)
			}
			if err == nil || !strings.Contains(err.Error(), kemFSMarker) {
				t.Fatalf("rejection did not come from the KEM forward-secrecy validator (missing %q): %v", kemFSMarker, err)
			}
			if !strings.Contains(err.Error(), "message ") {
				t.Fatalf("reject error must localize the offending message: %v", err)
			}
		})
	}
}

func TestForwardSecrecyKEM_Accepts(t *testing.T) {
	cases := []fsCase{
		// pqNK: the initiator seals a static-KEM at time zero (the responder has
		// emitted no prior Token::E, so an ephemeral-KEM is impossible by necessity
		// - the N-pattern analogue), the responder replies with the ephemeral-KEM.
		{"pqNK", [][]Token{{TokenSkem, TokenE}}, [][]Token{{TokenEkem}}, nil, []Token{TokenS}},
		// hybridKK: both parties pre-share statics; every static-KEM seal follows
		// an ephemeral-KEM in the transcript.
		{"hybridKK",
			[][]Token{{TokenSkem, TokenE, TokenES, TokenSS}},
			[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
			[]Token{TokenS}, []Token{TokenS}},
		// The pre-shared-ephemeral witness: the initiator's own pre-shared Token::E
		// does NOT make an ephemeral-KEM achievable for its OWN time-zero static-KEM
		// seal (the responder, its remote, has emitted no Token::E). The precise
		// gate accepts this; a coarse "either party emitted E" gate would wrongly
		// reject it (see TestForwardSecrecyKEM_PreciseGateAcceptsPreSharedEphemeral).
		{"pre_shared_ephemeral_skem",
			[][]Token{{TokenS, TokenSkem}},
			[][]Token{{TokenE, TokenEkem}},
			[]Token{TokenE}, []Token{TokenS}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewPattern(c.name, c.init, c.resp, c.preI, c.preR); err != nil {
				t.Fatalf("well-formed pattern wrongly rejected: %v", err)
			}
		})
	}
}

// TestForwardSecrecyKEM_AllPredefinedValidate invokes the KEM forward-secrecy
// validator DIRECTLY on every predefined pattern, asserting acceptance.
func TestForwardSecrecyKEM_AllPredefinedValidate(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		if err := validateStaticKEMSealHasComplement(p); err != nil {
			t.Fatalf("predefined pattern %q rejected by KEM forward-secrecy validator: %v", p.Name(), err)
		}
	}
}

// TestForwardSecrecy_AllPredefinedReconstructViaNewPattern re-feeds every
// predefined pattern through the FULL public NewPattern constructor (both new
// validators wired), proving the 0/90 acceptance end-to-end and not just via the
// direct validator calls.
func TestForwardSecrecy_AllPredefinedReconstructViaNewPattern(t *testing.T) {
	all := AllPatterns()
	if len(all) != 90 {
		t.Fatalf("expected 90 predefined patterns, got %d", len(all))
	}
	for _, p := range all {
		init := make([][]Token, p.NumInitiatorMessages())
		for i := range init {
			init[i] = p.InitiatorMessage(i)
		}
		resp := make([][]Token, p.NumResponderMessages())
		for i := range resp {
			resp[i] = p.ResponderMessage(i)
		}
		if _, err := NewPattern(p.Name(), init, resp, p.PreInitiator(), p.PreResponder()); err != nil {
			t.Fatalf("predefined pattern %q rejected on NewPattern re-feed: %v", p.Name(), err)
		}
	}
}

// TestForwardSecrecyKEM_PreciseGateAcceptsPreSharedEphemeral is the load-bearing
// precision test: it pins that the precise achievability gate accepts the
// pre-shared-ephemeral witness that a coarse "either party emitted Token::E"
// disjunction would wrongly reject. coarseKEMSealRejects reimplements that coarse
// gate independently; the witness is exactly where the two diverge (in the accept
// direction), proving the precise gate is not an over-approximation.
func TestForwardSecrecyKEM_PreciseGateAcceptsPreSharedEphemeral(t *testing.T) {
	witness := buildPatternForTest(
		[][]Token{{TokenS, TokenSkem}},
		[][]Token{{TokenE, TokenEkem}},
		[]Token{TokenE}, []Token{TokenS})

	if err := validateStaticKEMSealHasComplement(witness); err != nil {
		t.Fatalf("precise gate wrongly rejected the pre-shared-ephemeral witness: %v", err)
	}
	if !coarseKEMSealRejects(witness) {
		t.Fatal("the coarse gate must reject the witness - otherwise it does not distinguish precise from coarse and the broadening would be dead code")
	}
}

// TestForwardSecrecyKEM_BruteForceMatchesOracle enumerates KEM token sequences
// over {E, S, Ekem, Skem} (including pre-message variants) and asserts the
// production validator agrees with kemSealLacksAchievableEkem on EVERY enumerated
// pattern: 0 miss + 0 over-reject in both directions. The oracle is an
// independent ALGORITHM (a per-encrypt-point prefix rescan with explicit
// ekem-insertion-position enumeration, vs the gate's one-pass running bools); it
// must compute the same spec predicate to agree, so this guards against
// transcription and implementation drift in the gate's incremental bookkeeping,
// not against a flaw in the shared achievability premise itself - that premise is
// pinned by the dedicated reject/accept/precision cases and the e2e handshakes.
// The pattern struct is built directly, so the comparison isolates the KEM
// forward-secrecy validator from every other validator (no PQ-order or precedence
// exclusion is needed: both implementations process any token sequence).
func TestForwardSecrecyKEM_BruteForceMatchesOracle(t *testing.T) {
	alphabet := []Token{TokenE, TokenS, TokenEkem, TokenSkem}
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
	preOpts := [][]Token{nil, {TokenE}, {TokenS}}

	missing, overReject, checked := 0, 0, 0
	for _, init := range messageLists {
		for _, resp := range messageLists {
			for _, preI := range preOpts {
				for _, preR := range preOpts {
					p := buildPatternForTest(init, resp, preI, preR)
					gotReject := validateStaticKEMSealHasComplement(p) != nil
					wantReject := kemSealLacksAchievableEkem(p)
					switch {
					case wantReject && !gotReject:
						missing++
						t.Errorf("MISS init=%v resp=%v preI=%v preR=%v: oracle rejects, validator accepts", init, resp, preI, preR)
					case !wantReject && gotReject:
						overReject++
						t.Errorf("OVER-REJECT init=%v resp=%v preI=%v preR=%v: validator rejects, oracle accepts", init, resp, preI, preR)
					}
					checked++
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("KEM forward-secrecy brute force checked zero patterns")
	}
	if missing != 0 || overReject != 0 {
		t.Fatalf("KEM forward-secrecy gate diverged from the independent oracle: %d misses, %d over-rejects (of %d)", missing, overReject, checked)
	}
	t.Logf("KEM forward-secrecy brute force cross-checked %d patterns against the independent slot-insertion oracle (0 miss, 0 over-reject)", checked)
}

// ---------------------------------------------------------------------------
// Independent references and helpers (no production code shared)
// ---------------------------------------------------------------------------

// buildPatternForTest populates a HandshakePattern struct directly, WITHOUT
// running any validator, so a single validator (or the oracle) can be exercised
// in isolation on arbitrary - including malformed - token sequences. It enforces
// the same array bounds NewPattern does (<=5 messages, <=10 tokens per message,
// <=2 pre-message tokens) and panics with a clear message on a violation, so an
// over-sized test input fails loudly here rather than as an opaque slice-bounds
// panic deep inside a validator that reads tokens[:count].
func buildPatternForTest(init, resp [][]Token, preI, preR []Token) *HandshakePattern {
	if len(init) > 5 || len(resp) > 5 {
		panic("buildPatternForTest: more than 5 messages")
	}
	if len(preI) > 2 || len(preR) > 2 {
		panic("buildPatternForTest: more than 2 pre-message tokens")
	}
	p := &HandshakePattern{
		numInitiator: len(init),
		numResponder: len(resp),
		numPreInit:   len(preI),
		numPreResp:   len(preR),
	}
	for i, m := range init {
		if len(m) > 10 {
			panic("buildPatternForTest: initiator message exceeds 10 tokens")
		}
		p.initiatorMsgs[i].count = len(m)
		copy(p.initiatorMsgs[i].tokens[:], m)
	}
	for i, m := range resp {
		if len(m) > 10 {
			panic("buildPatternForTest: responder message exceeds 10 tokens")
		}
		p.responderMsgs[i].count = len(m)
		copy(p.responderMsgs[i].tokens[:], m)
	}
	copy(p.preInitiator[:], preI)
	copy(p.preResponder[:], preR)
	return p
}

// coarseKEMSealRejects reimplements the rejected COARSE achievability gate (an
// ephemeral-KEM is "achievable" iff EITHER party emitted Token::E in a prior
// message) used only to prove the precise gate diverges from it on the
// pre-shared-ephemeral witness. It is deliberately NOT the production rule.
func coarseKEMSealRejects(p *HandshakePattern) bool {
	var emittedE [2]bool
	emittedE[roleInitiator] = patternContainsToken(p.preInitiator[:p.numPreInit], TokenE)
	emittedE[roleResponder] = patternContainsToken(p.preResponder[:p.numPreResp], TokenE)
	var skemMixed [2]bool
	var anyEkemMixed, coarseAchievable bool

	rejected := false
	_ = p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		if emittedE[roleInitiator] || emittedE[roleResponder] {
			coarseAchievable = true
		}
		seal := func() {
			if skemMixed[writer] && !anyEkemMixed && coarseAchievable {
				rejected = true
			}
		}
		for _, tok := range tokens {
			switch tok {
			case TokenS:
				seal()
			case TokenSkem:
				skemMixed[writer] = true
				skemMixed[writer.other()] = true
				seal()
			case TokenEkem:
				anyEkemMixed = true
			}
		}
		seal()
		for _, tok := range tokens {
			if tok == TokenE {
				emittedE[writer] = true
			}
		}
		return nil
	})
	return rejected
}

// kemSealLacksAchievableEkem re-derives the KEM forward-secrecy verdict with an
// algorithm that shares no code or bookkeeping with
// validateStaticKEMSealHasComplement (it necessarily computes the same spec
// predicate - that is what makes the cross-check meaningful - so it catches
// transcription/implementation drift in the gate, not a flaw in the shared
// premise). Where the gate accumulates running monotonic bools in one pass, this
// oracle flattens the pattern into interleaved slots and, for EACH writer ENCRYPT
// point, RE-DERIVES the verdict from scratch by scanning the prefix of slots up
// to that point:
//   - a static-KEM secret has been folded (any Skem in the prefix - both the
//     encapsulator and the decapsulator fold the same static-bound secret),
//   - no ephemeral-KEM has been folded yet in the prefix, and
//   - an ephemeral-KEM encapsulation was INSERTABLE in the prefix: it enumerates
//     every (slot j, writer of j) position and asks whether j's writer's remote
//     had transmitted Token::E strictly before slot j (pre-messages count as
//     before slot 0).
//
// Returns true iff some seal is malformed (NewPattern must reject the pattern).
func kemSealLacksAchievableEkem(p *HandshakePattern) bool {
	type slot struct {
		writerInit bool
		tokens     []Token
	}
	var slots []slot
	ii, ri := 0, 0
	initTurn := true
	for ii < p.numInitiator || ri < p.numResponder {
		switch {
		case initTurn && ii < p.numInitiator:
			m := &p.initiatorMsgs[ii]
			slots = append(slots, slot{true, m.tokens[:m.count]})
			ii++
		case !initTurn && ri < p.numResponder:
			m := &p.responderMsgs[ri]
			slots = append(slots, slot{false, m.tokens[:m.count]})
			ri++
		default:
			initTurn = !initTurn
			continue
		}
		initTurn = !initTurn
	}

	has := func(toks []Token, want Token) bool {
		for _, tk := range toks {
			if tk == want {
				return true
			}
		}
		return false
	}
	preInitE := has(p.preInitiator[:p.numPreInit], TokenE)
	preRespE := has(p.preResponder[:p.numPreResp], TokenE)

	// emittedEBefore reports whether the given party transmitted Token::E strictly
	// before slotIdx (pre-messages count as before slot 0).
	emittedEBefore := func(slotIdx int, init bool) bool {
		if init {
			if preInitE {
				return true
			}
		} else if preRespE {
			return true
		}
		for j := 0; j < slotIdx; j++ {
			if slots[j].writerInit == init && has(slots[j].tokens, TokenE) {
				return true
			}
		}
		return false
	}
	// ekemInsertableBy reports whether an ephemeral-KEM encapsulation could have
	// been inserted into some slot j < prefixLen: j's writer encapsulates to its
	// remote's ephemeral, available iff that remote emitted Token::E before j.
	ekemInsertableBy := func(prefixLen int) bool {
		for j := 0; j < prefixLen; j++ {
			if emittedEBefore(j, !slots[j].writerInit) {
				return true
			}
		}
		return false
	}
	priorHas := func(k int, want Token) bool {
		for j := 0; j < k; j++ {
			if has(slots[j].tokens, want) {
				return true
			}
		}
		return false
	}

	for k := range slots {
		constructible := ekemInsertableBy(k + 1)
		priorSkem := priorHas(k, TokenSkem)
		priorEkem := priorHas(k, TokenEkem)
		wSkem, wEkem := false, false
		bad := func() bool {
			return (priorSkem || wSkem) && !(priorEkem || wEkem) && constructible
		}
		for _, tk := range slots[k].tokens {
			switch tk {
			case TokenS:
				if bad() {
					return true
				}
			case TokenSkem:
				wSkem = true // recorded before the seal, mirroring the gate
				if bad() {
					return true
				}
			case TokenEkem:
				wEkem = true
			}
		}
		if bad() { // end-of-message payload
			return true
		}
	}
	return false
}
