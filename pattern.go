package clatter

import "fmt"

// Token represents a single operation in a Noise handshake pattern message.
// Matches Rust Clatter's Token enum exactly.
type Token uint8

const (
	TokenE    Token = iota // Generate/receive ephemeral key
	TokenS                 // Send/receive static key
	TokenEE                // DH: ee
	TokenES                // DH: es
	TokenSE                // DH: se
	TokenSS                // DH: ss
	TokenPsk               // Mix in pre-shared key
	TokenEkem              // KEM: ephemeral encapsulate/decapsulate
	TokenSkem              // KEM: static encapsulate/decapsulate
)

// tokenString returns the display name for a token (used in pattern naming).
func tokenString(t Token) string {
	switch t {
	case TokenE:
		return "e"
	case TokenS:
		return "s"
	case TokenEE:
		return "ee"
	case TokenES:
		return "es"
	case TokenSE:
		return "se"
	case TokenSS:
		return "ss"
	case TokenPsk:
		return "psk"
	case TokenEkem:
		return "ekem"
	case TokenSkem:
		return "skem"
	default:
		return "?"
	}
}

// PatternType indicates the cryptographic category of a handshake pattern.
// Auto-detected from tokens at construction time.
type PatternType uint8

const (
	PatternTypeDH     PatternType = iota // NQ: classical DH only
	PatternTypeKEM                       // PQ: KEM only
	PatternTypeHybrid                    // Hybrid: DH + KEM
)

// HandshakePattern defines the structure of a Noise handshake.
// Value type with fixed arrays (not slices) to avoid heap allocation.
// hasPSK is cached at construction from a token scan.
type HandshakePattern struct {
	name string // e.g., "NN", "XX", "IK", "pqXX", "hybridXX"

	// Message patterns: each entry is a list of tokens for one message.
	// Fixed max: 5 messages (no Noise pattern exceeds this), max 10 tokens per message.
	initiatorMsgs [5]patternMessage
	responderMsgs [5]patternMessage
	numInitiator  int
	numResponder  int

	// Pre-message patterns (static keys known ahead of time)
	preInitiator [2]Token // max 2 pre-message tokens (e, s)
	preResponder [2]Token
	numPreInit   int
	numPreResp   int

	patternType PatternType // auto-detected from tokens
	hasPSK      bool        // cached from token scan

	isOneWay bool // derived at construction: true iff the responder writes no message (one-way patterns N, K, X)
}

// patternMessage holds tokens for a single handshake message.
// Fixed array avoids heap allocation. Max 10 tokens covers the largest
// hybrid PSK patterns (e.g., hybridKXpsk2 responder: 9 tokens).
type patternMessage struct {
	tokens [10]Token
	count  int
}

// Name returns the pattern name (e.g., "NN", "XX", "pqIK").
func (p *HandshakePattern) Name() string {
	return p.name
}

// Type returns the pattern type (DH, KEM, or Hybrid).
func (p *HandshakePattern) Type() PatternType {
	return p.patternType
}

// HasPSK returns true if the pattern uses pre-shared keys.
func (p *HandshakePattern) HasPSK() bool {
	return p.hasPSK
}

// IsOneWay reports whether this is a one-way pattern (the built-in N, K, X and
// their PSK variants). The value is derived from structure at construction - a
// pattern is one-way exactly when its responder writes no handshake message
// (Noise section 7.4) - so it can never disagree with the message counts that
// drive the runtime status machine and the transport one-way send/receive gating.
func (p *HandshakePattern) IsOneWay() bool {
	return p.isOneWay
}

// NumInitiatorMessages returns the number of initiator messages.
func (p *HandshakePattern) NumInitiatorMessages() int {
	return p.numInitiator
}

// NumResponderMessages returns the number of responder messages.
func (p *HandshakePattern) NumResponderMessages() int {
	return p.numResponder
}

// InitiatorMessage returns a copy of the tokens for the nth initiator message (0-indexed).
// Returns a copy to prevent external mutation of the pattern's internal state.
func (p *HandshakePattern) InitiatorMessage(n int) []Token {
	if n < 0 || n >= p.numInitiator {
		return nil
	}
	msg := &p.initiatorMsgs[n]
	out := make([]Token, msg.count)
	copy(out, msg.tokens[:msg.count])
	return out
}

// ResponderMessage returns a copy of the tokens for the nth responder message (0-indexed).
// Returns a copy to prevent external mutation of the pattern's internal state.
func (p *HandshakePattern) ResponderMessage(n int) []Token {
	if n < 0 || n >= p.numResponder {
		return nil
	}
	msg := &p.responderMsgs[n]
	out := make([]Token, msg.count)
	copy(out, msg.tokens[:msg.count])
	return out
}

// PreInitiator returns a copy of pre-message tokens for the initiator.
func (p *HandshakePattern) PreInitiator() []Token {
	out := make([]Token, p.numPreInit)
	copy(out, p.preInitiator[:p.numPreInit])
	return out
}

// PreResponder returns a copy of pre-message tokens for the responder.
func (p *HandshakePattern) PreResponder() []Token {
	out := make([]Token, p.numPreResp)
	copy(out, p.preResponder[:p.numPreResp])
	return out
}

// TotalMessages returns the total number of messages in the handshake
// (initiator messages + responder messages, interleaved).
func (p *HandshakePattern) TotalMessages() int {
	return p.numInitiator + p.numResponder
}

// NewPattern creates a HandshakePattern with validation.
// Returns a wrapped ErrInvalidPattern for invalid patterns. Use mustNewPattern
// for predefined patterns.
//
// Validates, in order: message/token/pre-message count limits; message-shape
// arity (strict initiator-first alternation - at least one message, and the
// responder writes either as many messages as the initiator or one fewer per
// Noise section 7.4), checked first because it is pure structure and every
// later wire-order validator assumes a well-shaped, initiator-first pattern;
// token domain (a pre-message carries only Token::E or Token::S per Noise
// section 7.1, and a message body carries only a defined token value), checked
// before any downstream logic because detectPatternType and scanForPSK switch
// on known tokens and silently ignore an unknown one; that the pattern performs
// at least one DH or KEM key agreement (a handshake with no ee/es/se/ss/ekem/skem
// negotiates no shared secret); PSK position
// rules (first or last in a message); PQ token ordering (Ekem before Skem within
// a message); that each party emits Token::E at most once and sends its static
// (Token::S) at most once, pre-messages included (Noise section 7.3); that no
// classical-DH calculation (ee/es/se/ss) is performed more than once per handshake
// (Noise section 7.3 - the KEM tokens ekem/skem are exempt, since PQNoise repeats
// skem by design); that no party consumes an ephemeral (DH ee/es/se or a KEM
// ekem-decap that reads its local ephemeral) before emitting its Token::E; and that
// no token reads a remote static (DH es/se/ss or a KEM skem-encap) before that
// static's owner has transmitted it via Token::S or pre-shared it via a pre-message
// - a pattern that violates either precedence rule cannot complete a handshake;
// that no party calls ENCRYPT() after a static-key DH without also performing the
// local-ephemeral DH that gives it forward secrecy (Noise section 7.3); and that
// no party calls ENCRYPT() after a static-key KEM encapsulation (skem) when an
// ephemeral-KEM (ekem) that would protect it was already achievable - the
// post-quantum analogue of the same forward-secrecy requirement, which the DH
// rule leaves to this check because a Skem's forward secrecy comes from an ekem,
// not a DH. Auto-detects pattern type from tokens (DH, KEM, or Hybrid) and caches
// hasPSK from a token scan.
func NewPattern(name string, initiatorMsgs, responderMsgs [][]Token,
	preInit, preResp []Token) (*HandshakePattern, error) {

	if len(initiatorMsgs) > 5 || len(responderMsgs) > 5 {
		return nil, fmt.Errorf("%w: too many messages", ErrInvalidPattern)
	}
	if len(preInit) > 2 || len(preResp) > 2 {
		return nil, fmt.Errorf("%w: too many pre-message tokens", ErrInvalidPattern)
	}

	// One-way is DERIVED from structure, never caller-asserted: a one-way Noise
	// pattern is exactly one whose responder writes no handshake message (Noise
	// section 7.4). Deriving the bit (rather than taking a parameter) makes it
	// impossible to disagree with the message counts that drive the runtime
	// status machine and the transport one-way gating - a mislabel cannot be
	// expressed through the API. validatePatternArity (below) guarantees the only
	// surviving numResponder==0 patterns have exactly one initiator message, so
	// the derived bit is always the spec-correct single-message one-way pattern.
	p := &HandshakePattern{
		name:         name,
		numInitiator: len(initiatorMsgs),
		numResponder: len(responderMsgs),
		numPreInit:   len(preInit),
		numPreResp:   len(preResp),
		isOneWay:     len(responderMsgs) == 0,
	}

	for i, msg := range initiatorMsgs {
		if len(msg) > 10 {
			return nil, fmt.Errorf("%w: message %d has too many tokens", ErrInvalidPattern, i)
		}
		p.initiatorMsgs[i].count = len(msg)
		copy(p.initiatorMsgs[i].tokens[:], msg)
	}
	for i, msg := range responderMsgs {
		if len(msg) > 10 {
			return nil, fmt.Errorf("%w: responder message %d has too many tokens", ErrInvalidPattern, i)
		}
		p.responderMsgs[i].count = len(msg)
		copy(p.responderMsgs[i].tokens[:], msg)
	}
	copy(p.preInitiator[:], preInit)
	copy(p.preResponder[:], preResp)

	// Reject malformed message-shape arity (zero-message, responder-first,
	// excessive one-way messages, message-count skew) FIRST: it is pure
	// structure, gives the clearest error, and every wire-order validator below
	// assumes a well-shaped, strictly-alternating initiator-first pattern.
	if err := validatePatternArity(p); err != nil {
		return nil, err
	}

	// Reject undefined token values and non-e/s pre-message tokens before any
	// downstream logic: detectPatternType and scanForPSK switch on known tokens
	// with no default and would silently misclassify an unknown one.
	if err := validateTokenDomain(p); err != nil {
		return nil, err
	}

	// Reject a pattern that performs no DH or KEM key agreement at all: it
	// negotiates no shared secret (a degenerate non-handshake). Runs right after
	// the token domain is known to be clean and before the PSK/PQ token-semantic
	// validators (it is independent of detectPatternType, whose default branch
	// would otherwise mislabel such a pattern as DH).
	if err := validateHasCryptographicCalc(p); err != nil {
		return nil, err
	}

	// Auto-detect pattern type from tokens
	p.patternType = detectPatternType(p)

	// Scan for PSK tokens
	p.hasPSK = scanForPSK(p)

	// Validate PSK and PQ rules
	if err := validatePSKRules(p); err != nil {
		return nil, err
	}
	if err := validatePQTokenOrder(p); err != nil {
		return nil, err
	}
	if err := validateEphemeralTokenRules(p); err != nil {
		return nil, err
	}
	if err := validateStaticTokenRules(p); err != nil {
		return nil, err
	}
	if err := validateDHCalcAtMostOnce(p); err != nil {
		return nil, err
	}
	if err := validateEphemeralEmittedBeforeUse(p); err != nil {
		return nil, err
	}
	if err := validateStaticAvailableBeforeUse(p); err != nil {
		return nil, err
	}
	if err := validateStaticDHComplementBeforeEncrypt(p); err != nil {
		return nil, err
	}
	if err := validateStaticKEMSealHasComplement(p); err != nil {
		return nil, err
	}

	return p, nil
}

// hsRole identifies one of the two handshake parties. It indexes the per-role
// arrays in the construction-time validators and renders itself in their errors.
type hsRole int

const (
	roleInitiator hsRole = iota
	roleResponder
)

// String renders the role name used in pattern-validation error messages.
func (r hsRole) String() string {
	if r == roleInitiator {
		return "initiator"
	}
	return "responder"
}

// other returns the opposite role (the reader of a message the receiver writes).
func (r hsRole) other() hsRole {
	if r == roleInitiator {
		return roleResponder
	}
	return roleInitiator
}

// walkInterleaved calls visit once per handshake message in true wire order:
// initiator first, strict Send/Receive alternation, handling unequal initiator/
// responder message counts (the toggle skips a side that has run out). It passes
// the writing role, the 0-based position in the interleaved sequence, and the
// message tokens. visit may return an error to stop the walk early, which is
// returned to the caller.
//
// This is the SINGLE source of truth for the handshake message ordering - the
// same order the runtime state machine drives (see determineInitialStatus /
// updateStatus / getNextMessage). Every construction-time validator that reasons
// in wire order shares it so the load-bearing alternation invariant is
// transcribed exactly once: validatePatternMaxMsgLen, validateEphemeralEmittedBeforeUse,
// validateStaticAvailableBeforeUse, validateStaticDHComplementBeforeEncrypt, and
// validateStaticKEMSealHasComplement.
func (p *HandshakePattern) walkInterleaved(visit func(writer hsRole, msgIdx int, tokens []Token) error) error {
	initIdx, respIdx, msgIdx := 0, 0, 0
	initiatorTurn := true

	for initIdx < p.numInitiator || respIdx < p.numResponder {
		var writer hsRole
		var tokens []Token

		if initiatorTurn && initIdx < p.numInitiator {
			msg := &p.initiatorMsgs[initIdx]
			writer, tokens = roleInitiator, msg.tokens[:msg.count]
			initIdx++
		} else if !initiatorTurn && respIdx < p.numResponder {
			msg := &p.responderMsgs[respIdx]
			writer, tokens = roleResponder, msg.tokens[:msg.count]
			respIdx++
		} else {
			// One side is exhausted while the other still has messages: skip
			// this turn without consuming a message.
			initiatorTurn = !initiatorTurn
			continue
		}

		if err := visit(writer, msgIdx, tokens); err != nil {
			return err
		}
		msgIdx++
		initiatorTurn = !initiatorTurn
	}
	return nil
}

// patternContainsToken reports whether want appears in tokens.
func patternContainsToken(tokens []Token, want Token) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}

// validateEphemeralEmittedBeforeUse rejects patterns in which a party consumes
// an ephemeral (does a DH or KEM-decap that reads a local ephemeral) before that
// party has emitted its Token::E. Such a pattern can never complete a handshake:
// the consuming operation reads a key that does not yet exist.
//
// validateEphemeralTokenRules only caps Token::E count at <=1 per party; it does
// not check that emission precedes use. This walks the handshake in true
// interleaved order (via walkInterleaved) and, per ephemeral-consuming token,
// verifies every party whose LOCAL ephemeral the token reads has already emitted
// Token::E.
//
// Token -> local-ephemeral consumers:
//   - ee:   {initiator, responder} (doDH(hs.e, hs.re) on both sides).
//   - es:   {initiator}            (uses the initiator's local e; responder uses hs.s).
//   - se:   {responder}            (uses the responder's local e; initiator uses hs.s).
//   - ekem: {reader}               (readTokenEkem decaps with the reader's local hs.e/hs.kemE).
//
// skem/ss/s touch only statics, so they carry no ephemeral precondition. A
// hybrid Token::E emits BOTH the DH (hs.e) and KEM (hs.kemE) local ephemeral, so
// one emitted bool per party covers both. Token::E flips the writer's emitted
// bit AFTER the consume check, so a message like {ee, e} is correctly rejected
// (the ee consumes before the e in the same message emits).
//
// This LOCAL-emission rule is complete: it also subsumes every "remote ephemeral
// not yet received" defect, because every ephemeral-consuming token reads SOME
// party's local ephemeral, and the remote side's availability is implied by that
// party's checked local emission.
func validateEphemeralEmittedBeforeUse(p *HandshakePattern) error {
	var emitted [2]bool
	emitted[roleInitiator] = patternContainsToken(p.preInitiator[:p.numPreInit], TokenE)
	emitted[roleResponder] = patternContainsToken(p.preResponder[:p.numPreResp], TokenE)

	return p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		reader := writer.other()

		// requireEmitted rejects token t (in this message) if party has not yet
		// emitted its Token::E. Closes over writer/msgIdx for a fully localized
		// error, matching validatePatternMaxMsgLen's "<role> message <n>" form.
		requireEmitted := func(t Token, party hsRole) error {
			if emitted[party] {
				return nil
			}
			return fmt.Errorf("%w: token %q in %s message %d consumes the %s ephemeral before it is emitted (Token::E must precede use)",
				ErrInvalidPattern, tokenString(t), writer, msgIdx, party)
		}

		for _, t := range tokens {
			var err error
			switch t {
			case TokenEE:
				if err = requireEmitted(t, roleInitiator); err == nil {
					err = requireEmitted(t, roleResponder)
				}
			case TokenES:
				err = requireEmitted(t, roleInitiator)
			case TokenSE:
				err = requireEmitted(t, roleResponder)
			case TokenEkem:
				err = requireEmitted(t, reader)
			}
			if err != nil {
				return err
			}
			if t == TokenE {
				emitted[writer] = true
			}
		}
		return nil
	})
}

// validateStaticAvailableBeforeUse rejects patterns in which a token uses a
// REMOTE static (a DH or a KEM encapsulation that operates on the other party's
// static)
// before that static's owner has made it available. Per the Noise spec (section
// 7.3, rule 1: "Parties can only perform DH between private keys and public keys
// they possess"), a remote static is possessed only after its owner has
// transmitted it via Token::S or pre-shared it via a pre-message. A pattern that
// reads it earlier can never complete: the consuming party holds no such key.
//
// This is the static analogue of validateEphemeralEmittedBeforeUse and shares
// walkInterleaved with it. The asymmetry between the two is intrinsic to Noise:
// an ephemeral is CREATED mid-handshake (Token::E), so the validator tracks the
// owner's LOCAL emission; a static is the owner's own pre-existing key, so the
// only precedence dimension a pattern can express is whether the owner has
// TRANSMITTED it to the peer before a remote-reading token. A party's use of its
// OWN local static (Token::S emit, es-as-responder, se-as-initiator, the local
// leg of ss, a skem decapsulation) carries no pattern-level precondition - the
// local static is supplied at construction via WithStaticKey, invisible to
// NewPattern; its absence is a runtime ErrMissingKey, not a malformed pattern.
//
// Token -> remote-static reader (owner whose transmission is required):
//   - es:   the responder's static (es = DH(initiator e, responder s); role-keyed).
//   - se:   the initiator's static (se = DH(initiator s, responder e); role-keyed).
//   - ss:   BOTH statics.
//   - skem: the reader's static (skem encapsulates to the peer; the encapsulating
//     WRITER needs the reader = writer.other() to have transmitted it).
//
// Token::S flips the writer's transmitted bit AFTER the consume check at that
// token's position, so a message like {s, ss} or XX's {e, ee, s, es} - the static
// sent and then immediately read within one message - is accepted just-in-time.
func validateStaticAvailableBeforeUse(p *HandshakePattern) error {
	var transmitted [2]bool
	transmitted[roleInitiator] = patternContainsToken(p.preInitiator[:p.numPreInit], TokenS)
	transmitted[roleResponder] = patternContainsToken(p.preResponder[:p.numPreResp], TokenS)

	return p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		// requireTransmitted rejects token t (in this message) if owner has not
		// yet transmitted or pre-shared its static. Closes over writer/msgIdx for
		// a localized error matching the ephemeral-precedence validator's form.
		requireTransmitted := func(t Token, owner hsRole) error {
			if transmitted[owner] {
				return nil
			}
			return fmt.Errorf("%w: token %q in %s message %d uses the %s static before it is transmitted or pre-shared (Token::S or a pre-message static must precede use)",
				ErrInvalidPattern, tokenString(t), writer, msgIdx, owner)
		}

		for _, t := range tokens {
			var err error
			switch t {
			case TokenES:
				err = requireTransmitted(t, roleResponder)
			case TokenSE:
				err = requireTransmitted(t, roleInitiator)
			case TokenSS:
				if err = requireTransmitted(t, roleInitiator); err == nil {
					err = requireTransmitted(t, roleResponder)
				}
			case TokenSkem:
				err = requireTransmitted(t, writer.other())
			}
			if err != nil {
				return err
			}
			if t == TokenS {
				transmitted[writer] = true
			}
		}
		return nil
	})
}

// errStaticDHForwardSecrecy builds the forward-secrecy rejection for a
// static-key DH that reaches an ENCRYPT() with no ephemeral-DH complement. The
// message is localized to the writing role and message index, matching the
// precedence validators' form.
func errStaticDHForwardSecrecy(writer hsRole, msgIdx int, trigger, complement Token) error {
	return fmt.Errorf("%w: %s message %d encrypts after the %q static-key DH without the %q ephemeral DH that protects it (forward secrecy, Noise section 7.3)",
		ErrInvalidPattern, writer, msgIdx, tokenString(trigger), tokenString(complement))
}

// validateStaticDHComplementBeforeEncrypt enforces the forward-secrecy
// requirement of Noise section 7.3: "After performing a DH between a remote
// public key (either static or ephemeral) and the local static key, the local
// party must not call ENCRYPT() unless it has also performed a DH between its
// local ephemeral key and the remote public key." A payload (or static-key
// transmission) encrypted after a static-key DH that has no ephemeral DH over
// the same remote key lacks forward secrecy and is rejected at construction.
//
// The walk (walkInterleaved) accumulates the mixed DH set in true wire order -
// both parties mix every DH token at the same transcript position, so a single
// bool per token is the shared chaining-key state. At each point the WRITER
// calls ENCRYPT() - a Token::S it transmits (writeTokenS EncryptAndHash's the
// static public key) and the always-present end-of-message payload - every
// static-key DH already mixed must have its local-ephemeral complement mixed
// too. The static-key DH operands are role-keyed (processWriteToken /
// processReadToken):
//
//   - initiator's local-static DHs: se (s . remote-e) needs ee; ss (s . remote-s)
//     needs es (the initiator's e . remote-s).
//   - responder's local-static DHs: es (s . remote-e) needs ee; ss needs se (the
//     responder's e . remote-s).
//
// Token::Skem is deliberately NOT an encrypt point here: a Skem ciphertext's
// forward secrecy comes from a KEM ephemeral (Ekem), not a DH, so a hybrid
// pattern whose Skem precedes its ee (e.g. hybridKK, hybridIK) must not be
// rejected by this rule - validateStaticKEMSealHasComplement owns the Skem seal.
// The two validators are independent and compose; a missing DH complement is not
// cured by an Ekem, nor vice versa (forward secrecy is per-primitive).
//
// All 90 predefined patterns satisfy this rule by construction; it rejects only
// malformed custom patterns built via NewPattern. It assumes the at-most-once DH
// rule (validateDHCalcAtMostOnce) already holds, so one bool per DH token
// suffices, and runs last in the NewPattern chain.
func validateStaticDHComplementBeforeEncrypt(p *HandshakePattern) error {
	var mixedEE, mixedES, mixedSE, mixedSS bool

	requireComplement := func(writer hsRole, msgIdx int) error {
		if writer == roleInitiator {
			if mixedSE && !mixedEE {
				return errStaticDHForwardSecrecy(writer, msgIdx, TokenSE, TokenEE)
			}
			if mixedSS && !mixedES {
				return errStaticDHForwardSecrecy(writer, msgIdx, TokenSS, TokenES)
			}
			return nil
		}
		if mixedES && !mixedEE {
			return errStaticDHForwardSecrecy(writer, msgIdx, TokenES, TokenEE)
		}
		if mixedSS && !mixedSE {
			return errStaticDHForwardSecrecy(writer, msgIdx, TokenSS, TokenSE)
		}
		return nil
	}

	return p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		for _, t := range tokens {
			switch t {
			case TokenS:
				// Token::S transmits the static, EncryptAndHash'd: an ENCRYPT()
				// point. The DH tokens later in this same message have not mixed
				// yet (they follow S in the stream), matching the runtime order.
				if err := requireComplement(writer, msgIdx); err != nil {
					return err
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
		// End-of-message payload is always EncryptAndHash'd: an ENCRYPT() point.
		return requireComplement(writer, msgIdx)
	})
}

// errStaticKEMSealForwardSecrecy builds the forward-secrecy rejection for a
// static-KEM seal that reaches an ENCRYPT() while an ephemeral-KEM that would
// protect it was achievable but omitted.
func errStaticKEMSealForwardSecrecy(writer hsRole, msgIdx int) error {
	return fmt.Errorf("%w: %s message %d encrypts after a static-key KEM encapsulation without the %q ephemeral KEM that protects it (forward secrecy, Noise section 7.3)",
		ErrInvalidPattern, writer, msgIdx, tokenString(TokenEkem))
}

// validateStaticKEMSealHasComplement enforces the post-quantum/hybrid analogue of
// the Noise section 7.3 forward-secrecy requirement. A static-KEM operation
// (Token::Skem) binds a shared secret to a long-lived static key with no
// ephemeral contribution: the writer encapsulates to the remote static
// (writeTokenSkem) and the remote decapsulates with its local static
// (readTokenSkem), so BOTH parties fold the same non-forward-secret secret. The
// forward-secrecy complement is any ephemeral-KEM operation (Token::Ekem), which
// encapsulates to a key that is discarded after the handshake.
//
// Unlike classical DH - where the initiator can supply its own ephemeral DH
// non-interactively at time zero - a KEM ephemeral needs a round trip: an Ekem
// can only encapsulate to an ephemeral the remote has already transmitted via
// Token::E. So the obligation attaches only once an Ekem was actually
// constructible. At the start of each message, if the writing party's remote has
// already emitted Token::E in a PRIOR message, an Ekem-encapsulation was
// insertable, and the requirement latches on monotonically from then on (it also
// covers the reply-suppliable case: a later party can encapsulate to an
// ephemeral an earlier party emitted). This legitimately permits the one-way
// "encapsulate to a known static at time zero" case - pqNK's initiator message,
// the N-pattern analogue - whose forward secrecy is impossible by necessity, not
// by omission.
//
// At each point the WRITER calls ENCRYPT() - a Token::S, a Token::Skem (the Skem
// ciphertext is itself EncryptAndHash'd), and the end-of-message payload - the
// pattern is rejected when a static-KEM secret has been mixed for the writer, no
// ephemeral-KEM has been mixed anywhere in the transcript, and an Ekem was
// constructible by now. Token::E emission is recorded at end-of-message so a
// within-message own-E does not retroactively excuse that message's own seals
// (the reply Ekem can only arrive later). A Token::Skem whose symmetric state is
// not yet keyed copies its ciphertext verbatim rather than AEAD-sealing it, but
// every such first-message Skem has its obligation un-attached (no prior remote
// Token::E), so the conservative treatment of Skem as an encrypt point is
// benign for all 90 built-ins.
//
// All 90 predefined patterns satisfy this rule (the post-quantum K-patterns seal
// their Skem in the first message, where no prior remote Token::E exists); it
// rejects only custom patterns that seal a static-KEM without an achievable
// ephemeral-KEM complement. This is per-primitive (strict hybrid): a hybrid Skem
// is NOT excused by a classical ephemeral DH (ee) in the transcript, because a
// classical ephemeral provides no forward secrecy against a quantum adversary -
// the exact threat the KEM layer exists to defend - so its Skem leg requires its
// own ephemeral KEM. (Symmetrically, validateStaticDHComplementBeforeEncrypt is
// not excused by an ekem.) The two validators are independent - that rule never
// treats a Skem as an encrypt point, this one owns the Skem seal - and compose
// without either excusing the other.
func validateStaticKEMSealHasComplement(p *HandshakePattern) error {
	var emittedE [2]bool
	emittedE[roleInitiator] = patternContainsToken(p.preInitiator[:p.numPreInit], TokenE)
	emittedE[roleResponder] = patternContainsToken(p.preResponder[:p.numPreResp], TokenE)

	var skemMixed [2]bool
	var anyEkemMixed bool
	var ekemConstructible bool

	return p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		// An Ekem-encapsulation was insertable by now iff the writer's remote had
		// already emitted Token::E in a PRIOR message. Latch monotonically.
		if emittedE[writer.other()] {
			ekemConstructible = true
		}

		seal := func() error {
			if skemMixed[writer] && !anyEkemMixed && ekemConstructible {
				return errStaticKEMSealForwardSecrecy(writer, msgIdx)
			}
			return nil
		}

		for _, t := range tokens {
			switch t {
			case TokenS:
				if err := seal(); err != nil {
					return err
				}
			case TokenSkem:
				// Encapsulation by the writer, decapsulation by the remote: both
				// fold the same static-bound secret. Record before the seal check -
				// the Skem ciphertext is itself an ENCRYPT() point.
				skemMixed[writer] = true
				skemMixed[writer.other()] = true
				if err := seal(); err != nil {
					return err
				}
			case TokenEkem:
				anyEkemMixed = true
			}
		}

		if err := seal(); err != nil {
			return err
		}

		// Record Token::E emission at end-of-message (see the doc comment).
		for _, t := range tokens {
			if t == TokenE {
				emittedE[writer] = true
			}
		}
		return nil
	})
}

// mustNewPattern creates a pattern, panicking on invalid input.
// Used for predefined patterns (like template.Must).
func mustNewPattern(name string, initiatorMsgs, responderMsgs [][]Token,
	preInit, preResp []Token) *HandshakePattern {
	p, err := NewPattern(name, initiatorMsgs, responderMsgs, preInit, preResp)
	if err != nil {
		panic(fmt.Sprintf("invalid predefined pattern %q: %v", name, err))
	}
	return p
}

// detectPatternType determines whether a pattern is DH, KEM, or Hybrid.
// Both DH and KEM tokens = HYBRID. Only KEM = KEM. Only DH = DH.
func detectPatternType(p *HandshakePattern) PatternType {
	hasDH := false
	hasKEM := false

	scanTokens := func(tokens []Token) {
		for _, t := range tokens {
			switch t {
			case TokenEE, TokenES, TokenSE, TokenSS:
				hasDH = true
			case TokenEkem, TokenSkem:
				hasKEM = true
			}
		}
	}

	for i := 0; i < p.numInitiator; i++ {
		scanTokens(p.initiatorMsgs[i].tokens[:p.initiatorMsgs[i].count])
	}
	for i := 0; i < p.numResponder; i++ {
		scanTokens(p.responderMsgs[i].tokens[:p.responderMsgs[i].count])
	}

	if hasDH && hasKEM {
		return PatternTypeHybrid
	}
	if hasKEM {
		return PatternTypeKEM
	}
	return PatternTypeDH
}

// scanForPSK returns true if any message contains a PSK token.
// Result is cached at construction time.
func scanForPSK(p *HandshakePattern) bool {
	for i := 0; i < p.numInitiator; i++ {
		for j := 0; j < p.initiatorMsgs[i].count; j++ {
			if p.initiatorMsgs[i].tokens[j] == TokenPsk {
				return true
			}
		}
	}
	for i := 0; i < p.numResponder; i++ {
		for j := 0; j < p.responderMsgs[i].count; j++ {
			if p.responderMsgs[i].tokens[j] == TokenPsk {
				return true
			}
		}
	}
	return false
}

// validateTokenDomain rejects tokens that are not allowed in their position: a
// pre-message may carry only Token::E or Token::S (Noise section 7.1 - a
// pre-message declares a pre-shared ephemeral or static public key), and a
// message body may carry only a defined token value (TokenE..TokenSkem). Both
// are construction-time fail-early checks for the same class the runtime
// otherwise catches late (processPreMessages / processWriteToken /
// processReadToken). It runs before detectPatternType and scanForPSK (the first
// token-semantic validators) because they switch on known tokens with no default
// and would otherwise misclassify an unknown one. Token position and order WITHIN a valid domain are
// enforced by validatePSKRules / validatePQTokenOrder, not duplicated here. The
// body check is an explicit token list rather than a numeric bound so a token
// added to the enum in future fails closed until it is handled. All 90
// predefined patterns satisfy both rules; this rejects only malformed custom
// patterns built via NewPattern.
//
// NewPattern is the only constructor of a HandshakePattern (its fields are
// unexported), so gating here covers every pattern the rest of the package ever
// sees, including the no-default token switches in detectPatternType, scanForPSK
// and the per-message overhead helpers. Any future pattern factory (for example
// a deserializer) must route through here too, or those switches reopen.
func validateTokenDomain(p *HandshakePattern) error {
	// Pre-messages may declare only a pre-shared ephemeral or static public key.
	checkPre := func(tokens []Token, who hsRole) error {
		for _, t := range tokens {
			if t != TokenE && t != TokenS {
				return fmt.Errorf("%w: %s pre-message token value %d is not allowed (pre-message tokens may be only e or s)", ErrInvalidPattern, who, t)
			}
		}
		return nil
	}
	if err := checkPre(p.preInitiator[:p.numPreInit], roleInitiator); err != nil {
		return err
	}
	if err := checkPre(p.preResponder[:p.numPreResp], roleResponder); err != nil {
		return err
	}

	// Message bodies may carry only a defined token value. Walk them in true wire
	// order (walkInterleaved, the shared single source of truth for message
	// ordering) so the reported message index matches every other validator.
	return p.walkInterleaved(func(writer hsRole, msgIdx int, tokens []Token) error {
		for _, t := range tokens {
			switch t {
			case TokenE, TokenS, TokenEE, TokenES, TokenSE, TokenSS, TokenPsk, TokenEkem, TokenSkem:
				// defined token value; position and order are checked by
				// validatePSKRules / validatePQTokenOrder
			default:
				return fmt.Errorf("%w: %s message %d carries unknown token value %d", ErrInvalidPattern, writer, msgIdx, t)
			}
		}
		return nil
	})
}

// validatePatternArity rejects a pattern whose message counts cannot form a
// well-shaped Noise handshake. A Noise handshake strictly alternates messages
// starting with the initiator (the initiator writes the first message, Noise
// section 7.1), so the only valid shapes have the responder writing either as
// many messages as the initiator (the last message is the responder's) or one
// fewer (the last message is the initiator's): numResponder <= numInitiator <=
// numResponder+1, with at least one message total. This single invariant
// subsumes every message-count malformation: zero messages (no handshake);
// responder-first / responder-heavy (numInitiator < numResponder, which the
// runtime status machine - a strict Send/Receive toggle - cannot drive without
// overflowing a message index); a one-way pattern with more than one message
// (numResponder==0 forces numInitiator==1, the single-message form Noise
// section 7.4 requires); and message-count skew (numInitiator > numResponder+1,
// two consecutive same-party messages with no reply between, breaking strict
// alternation). All 90 predefined patterns satisfy the invariant; this rejects
// only malformed custom patterns built via NewPattern. It runs first because it
// is pure structure and every later wire-order validator (which interleaves the
// two message arrays via walkInterleaved) assumes a well-shaped pattern.
func validatePatternArity(p *HandshakePattern) error {
	ni, nr := p.numInitiator, p.numResponder
	if ni+nr == 0 {
		return fmt.Errorf("%w: pattern has no handshake messages", ErrInvalidPattern)
	}
	if ni < nr {
		return fmt.Errorf("%w: responder writes %d messages but the initiator only %d; a Noise handshake alternates messages starting with the initiator (Noise section 7.1)",
			ErrInvalidPattern, nr, ni)
	}
	if ni > nr+1 {
		if nr == 0 {
			return fmt.Errorf("%w: one-way pattern (the responder writes no message) sends %d initiator messages; a one-way pattern is a single message (Noise section 7.4)",
				ErrInvalidPattern, ni)
		}
		return fmt.Errorf("%w: pattern has %d initiator and %d responder messages; Noise messages strictly alternate initiator-first, so the initiator may lead by at most one (Noise section 7.4)",
			ErrInvalidPattern, ni, nr)
	}
	return nil
}

// validateHasCryptographicCalc rejects a pattern that performs no DH or KEM key
// agreement: with no ee/es/se/ss (DH) and no ekem/skem (KEM) token, the parties
// negotiate no shared secret, so the transport keys would derive entirely from
// public key material - a degenerate non-handshake (nyquist calls it "valid but
// nonsensical"). A PSK is deliberately NOT counted: a PSK authenticates but
// agrees no fresh secret, and Noise defines no pure-PSK pattern (its minimal PSK
// patterns always carry a DH/KEM). The count reuses tokenCountForParty (which
// includes pre-messages, but validateTokenDomain has already restricted those to
// e/s, so they contribute zero). All 90 predefined patterns perform at least one
// key agreement; this rejects only malformed custom patterns built via NewPattern.
func validateHasCryptographicCalc(p *HandshakePattern) error {
	for _, tok := range [...]Token{TokenEE, TokenES, TokenSE, TokenSS, TokenEkem, TokenSkem} {
		if tokenCountForParty(p, tok, true)+tokenCountForParty(p, tok, false) > 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: pattern performs no DH or KEM key agreement (no ee/es/se/ss/ekem/skem token); it negotiates no shared secret", ErrInvalidPattern)
}

// validatePSKRules validates PSK position rules per Noise spec.
// PSK validation scans ACROSS messages (psk_sent persists).
// The own_randomness_applied check (PSK before first S) is enforced at
// RUNTIME in the handshake state machine, not here at construction.
// This function validates structural placement only.
//
// Rule: PSK token can only appear at position 0 or after all other tokens in a message.
//
// This is intentionally stricter than nyquist's IsValid, which performs no PSK
// position check at all: the Noise pskN modifier only ever emits a psk at the
// start of a message (psk0) or at its end, so a mid-message psk is not
// expressible by any standard pattern and is rejected here as malformed.
func validatePSKRules(p *HandshakePattern) error {
	if !p.hasPSK {
		return nil
	}

	// Validate PSK position: must be first or last in each message
	validatePositions := func(msgs [5]patternMessage, count int) error {
		for i := 0; i < count; i++ {
			msg := &msgs[i]
			for j := 0; j < msg.count; j++ {
				if msg.tokens[j] == TokenPsk {
					if j != 0 && j != msg.count-1 {
						return fmt.Errorf("%w: PSK must be first or last token in message",
							ErrInvalidPattern)
					}
				}
			}
		}
		return nil
	}

	if err := validatePositions(p.initiatorMsgs, p.numInitiator); err != nil {
		return err
	}
	return validatePositions(p.responderMsgs, p.numResponder)
}

// validatePQTokenOrder validates PQ-specific token ordering rules.
// PQ order validation is PER message (reset per message).
//
// In PQ patterns, Ekem and Skem can appear in messages independently.
// Ekem encapsulates to the remote's E (from a prior message).
// Skem encapsulates to the remote's S (from a prior message or pre-message).
// Within a single message, if both appear, Ekem must come before Skem.
func validatePQTokenOrder(p *HandshakePattern) error {
	if p.patternType == PatternTypeDH {
		return nil // NQ patterns have no KEM tokens
	}

	validateMsg := func(tokens []Token) error {
		skemSeen := false
		for _, t := range tokens {
			switch t {
			case TokenEkem:
				if skemSeen {
					return fmt.Errorf("%w: Ekem must come before Skem in same message", ErrInvalidPattern)
				}
			case TokenSkem:
				skemSeen = true
			}
		}
		return nil
	}

	for i := 0; i < p.numInitiator; i++ {
		msg := &p.initiatorMsgs[i]
		if err := validateMsg(msg.tokens[:msg.count]); err != nil {
			return err
		}
	}
	for i := 0; i < p.numResponder; i++ {
		msg := &p.responderMsgs[i]
		if err := validateMsg(msg.tokens[:msg.count]); err != nil {
			return err
		}
	}
	return nil
}

// tokenCountForParty returns how many times tok appears across the given party's
// pre-message and its own messages (the initiator writes initiatorMsgs, the
// responder writes responderMsgs).
func tokenCountForParty(p *HandshakePattern, tok Token, initiator bool) int {
	count := func(tokens []Token) int {
		n := 0
		for _, t := range tokens {
			if t == tok {
				n++
			}
		}
		return n
	}
	if initiator {
		n := count(p.preInitiator[:p.numPreInit])
		for i := 0; i < p.numInitiator; i++ {
			n += count(p.initiatorMsgs[i].tokens[:p.initiatorMsgs[i].count])
		}
		return n
	}
	n := count(p.preResponder[:p.numPreResp])
	for i := 0; i < p.numResponder; i++ {
		n += count(p.responderMsgs[i].tokens[:p.responderMsgs[i].count])
	}
	return n
}

// validateTokenAtMostOncePerParty rejects a pattern in which either party sets
// the given key token more than once across its pre-message and its messages.
// The Noise spec (section 7.3) requires each party to send its ephemeral ("e")
// and its static ("s") at most once per handshake, INCLUDING pre-messages: "there
// must be no more than one occurrence of e, and one occurrence of s, in the
// messages sent by any party." noun/tokenLabel render the error per kind. This is
// the per-PARTY key-emission rule; the separate per-HANDSHAKE DH-calculation rule
// (ee/es/se/ss at most once total) is validateDHCalcAtMostOnce.
func validateTokenAtMostOncePerParty(p *HandshakePattern, tok Token, noun, tokenLabel string) error {
	if n := tokenCountForParty(p, tok, true); n > 1 {
		return fmt.Errorf("%w: initiator sets its %s %d times (%s must appear at most once per party)", ErrInvalidPattern, noun, n, tokenLabel)
	}
	if n := tokenCountForParty(p, tok, false); n > 1 {
		return fmt.Errorf("%w: responder sets its %s %d times (%s must appear at most once per party)", ErrInvalidPattern, noun, n, tokenLabel)
	}
	return nil
}

// validateEphemeralTokenRules rejects patterns in which a party would set its
// own ephemeral (hs.e) more than once. A party's ephemeral comes from either a
// pre-message E (pre-shared ephemeral) or a message-body Token::E (freshly
// generated / pre-set via WithEphemeralKey/WithEphemeralKEMKey) - never both,
// and never twice. Until v0.6.0 the message-body writeTokenE caught a second
// Token::E at runtime ("ephemeral already set"); that guard was removed so a
// pre-set ephemeral is legal, so the well-formedness rule is enforced here at
// construction instead. The 90 predefined patterns all emit Token::E exactly
// once per party; this only rejects malformed custom patterns built via
// NewPattern.
func validateEphemeralTokenRules(p *HandshakePattern) error {
	return validateTokenAtMostOncePerParty(p, TokenE, "ephemeral", "Token::E")
}

// validateStaticTokenRules rejects patterns in which a party would send its own
// static (Token::S) more than once, or both pre-share it (pre-message S) and send
// it. This is the static counterpart of validateEphemeralTokenRules and the same
// Noise section 7.3 rule. writeTokenS transmits hs.s once; a party that sends it
// twice (or pre-shares and re-sends it) produces a malformed, non-completing
// transcript. The 90 predefined patterns send each party's static at most once;
// this only rejects malformed custom patterns built via NewPattern.
func validateStaticTokenRules(p *HandshakePattern) error {
	return validateTokenAtMostOncePerParty(p, TokenS, "static", "Token::S")
}

// validateDHCalcAtMostOnce rejects a pattern that performs the same classical-DH
// calculation more than once. Per the Noise spec (section 7.3): "Parties must not
// perform a DH calculation more than once per handshake (i.e. there must be no more
// than one occurrence of ee, es, se, or ss per handshake)." This is a PER-HANDSHAKE
// cap (a DH calculation produces one shared secret for both parties, so each token
// appears in exactly one message of a well-formed transcript), distinct from the
// per-PARTY caps of validateEphemeral/StaticTokenRules - the spec's "e"/"s" rule
// says "sent by any party" while the DH-calculation rule omits that qualifier. The
// per-party caps do NOT subsume this: a pattern can list the same DH token twice
// without emitting "e"/"s" twice. The KEM tokens ekem/skem are deliberately exempt:
// PQNoise replaces the single ss DH with two skem operations (one per direction,
// distinct ciphertexts and shared secrets), so a bidirectional PQ/Hybrid pattern
// legitimately repeats skem (e.g. pqXX, hybridXX). The count reuses
// tokenCountForParty (which includes pre-messages); valid patterns never carry a DH
// token in a pre-message, so the pre-message contribution is zero for every
// constructible pattern. The 90 predefined patterns perform each DH calculation at
// most once; this only rejects malformed custom patterns built via NewPattern.
func validateDHCalcAtMostOnce(p *HandshakePattern) error {
	for _, tok := range [...]Token{TokenEE, TokenES, TokenSE, TokenSS} {
		if n := tokenCountForParty(p, tok, true) + tokenCountForParty(p, tok, false); n > 1 {
			return fmt.Errorf("%w: DH calculation %q occurs %d times (each of ee/es/se/ss must occur at most once per handshake)",
				ErrInvalidPattern, tokenString(tok), n)
		}
	}
	return nil
}

// sendsLocalEphemeral reports whether the party in the given role emits its own
// Token::E somewhere in this pattern - either as a pre-message token or in a
// message it writes (the initiator writes initiatorMsgs, the responder writes
// responderMsgs). A party that emits no Token::E never generates or pre-sets a
// local ephemeral, so a pre-set ephemeral option for that party is a silent
// no-op. Constructors use this to reject such no-op presets loudly.
//
// validateEphemeralTokenRules guarantees a party emits Token::E at most once, so
// this is a clean 0/1 predicate. It is role- and pattern-accurate rather than a
// blanket "initiator only" assumption: a custom pattern whose responder emits
// Token::E (a mutual-ephemeral handshake) correctly reports true.
//
// This keys on Token::E emission, which is equivalent to consuming the local
// ephemeral: a party must emit its Token::E before any later token can use that
// ephemeral (ee/es/se, or decapsulating the ekem reply to its own e).
// validateEphemeralEmittedBeforeUse enforces exactly that at construction, so
// every pattern NewPattern accepts satisfies the equivalence - keying on
// emission is therefore correct for every constructible pattern, not merely for
// well-formed ones by assumption.
func (p *HandshakePattern) sendsLocalEphemeral(initiator bool) bool {
	if initiator {
		for _, t := range p.preInitiator[:p.numPreInit] {
			if t == TokenE {
				return true
			}
		}
		for i := 0; i < p.numInitiator; i++ {
			for j := 0; j < p.initiatorMsgs[i].count; j++ {
				if p.initiatorMsgs[i].tokens[j] == TokenE {
					return true
				}
			}
		}
		return false
	}
	for _, t := range p.preResponder[:p.numPreResp] {
		if t == TokenE {
			return true
		}
	}
	for i := 0; i < p.numResponder; i++ {
		for j := 0; j < p.responderMsgs[i].count; j++ {
			if p.responderMsgs[i].tokens[j] == TokenE {
				return true
			}
		}
	}
	return false
}

// usesLocalStatic reports whether the party in the given role uses its own
// static key anywhere in this pattern. A static is used iff the party transmits
// it (a Token::S it writes) or pre-shares it (its own pre-message Token::S);
// every static-consuming operation - a Token::S send, an es-as-responder /
// se-as-initiator / ss DH, or a skem decapsulation - requires the static to have
// been communicated to the peer, so emission is equivalent to consumption.
// Constructors use this to reject a no-op WithStaticKey loudly: a party that
// uses no local static would silently ignore the preset.
//
// The emission-equivalence holds for every pattern NewPattern accepts because
// validateStaticAvailableBeforeUse rejects any pattern in which a static is read
// before its owner transmits it; this is the static counterpart of how
// validateEphemeralEmittedBeforeUse underwrites sendsLocalEphemeral. Outside that
// guarantee (a hypothetical pattern that consumes a static never transmitted) the
// equivalence would not hold, which is exactly why validateStaticAvailableBeforeUse
// runs before this predicate is ever consulted (it is the last validator in
// NewPattern, and the constructors call this predicate only on a built pattern).
func (p *HandshakePattern) usesLocalStatic(initiator bool) bool {
	if initiator {
		if patternContainsToken(p.preInitiator[:p.numPreInit], TokenS) {
			return true
		}
		for i := 0; i < p.numInitiator; i++ {
			if patternContainsToken(p.initiatorMsgs[i].tokens[:p.initiatorMsgs[i].count], TokenS) {
				return true
			}
		}
		return false
	}
	if patternContainsToken(p.preResponder[:p.numPreResp], TokenS) {
		return true
	}
	for i := 0; i < p.numResponder; i++ {
		if patternContainsToken(p.responderMsgs[i].tokens[:p.responderMsgs[i].count], TokenS) {
			return true
		}
	}
	return false
}

// usesRemoteStatic reports whether a pre-set remote static (WithRemoteStatic /
// WithRemoteStaticKEMKey) has any effect for the party in the given role, which
// is true iff the OTHER party pre-shares its static (its pre-message contains
// Token::S). When the remote static is instead transmitted in-band, readTokenS
// learns it from the wire and overwrites any pre-set value before any consuming
// token runs, so the option is a no-op. Constructors use this to reject a no-op
// remote-static option loudly.
//
// This relies on validateStaticAvailableBeforeUse having already rejected
// patterns in which a remote static is read before it is transmitted: in such a
// malformed pattern a pre-set remote static would be load-bearing rather than
// overwritten, so the no-op equivalence would not hold. That validator is the
// last one in NewPattern, so every constructible pattern satisfies it before any
// constructor consults this predicate.
func (p *HandshakePattern) usesRemoteStatic(initiator bool) bool {
	if initiator {
		return patternContainsToken(p.preResponder[:p.numPreResp], TokenS)
	}
	return patternContainsToken(p.preInitiator[:p.numPreInit], TokenS)
}

// ============================================================================
// Predefined NQ (Classical DH) Patterns
// ============================================================================

// One-way patterns (NQ-only; no PQ or Hybrid one-way patterns exist)
var (
	PatternN = mustNewPattern("N",
		[][]Token{{TokenE, TokenES}},
		nil,
		nil, []Token{TokenS})

	PatternK = mustNewPattern("K",
		[][]Token{{TokenE, TokenES, TokenSS}},
		nil,
		[]Token{TokenS}, []Token{TokenS})

	PatternX = mustNewPattern("X",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		nil,
		nil, []Token{TokenS})
)

// Interactive NQ base patterns
var (
	PatternNN = mustNewPattern("NN",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil)

	PatternNK = mustNewPattern("NK",
		[][]Token{{TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS})

	PatternNX = mustNewPattern("NX",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil)

	PatternKN = mustNewPattern("KN",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil)

	PatternKK = mustNewPattern("KK",
		[][]Token{{TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS})

	PatternKX = mustNewPattern("KX",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		[]Token{TokenS}, nil)

	PatternXN = mustNewPattern("XN",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil)

	PatternXK = mustNewPattern("XK",
		[][]Token{{TokenE, TokenES}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS})

	PatternXX = mustNewPattern("XX",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil)

	PatternIN = mustNewPattern("IN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, nil)

	PatternIK = mustNewPattern("IK",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS})

	PatternIX = mustNewPattern("IX",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		nil, nil)
)

// ============================================================================
// NQ PSK Patterns
// ============================================================================

var (
	PatternNNpsk0 = mustNewPattern("NNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil)

	PatternNNpsk2 = mustNewPattern("NNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenPsk}},
		nil, nil)

	PatternNKpsk0 = mustNewPattern("NKpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS})

	PatternNKpsk2 = mustNewPattern("NKpsk2",
		[][]Token{{TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE, TokenPsk}},
		nil, []Token{TokenS})

	PatternNXpsk2 = mustNewPattern("NXpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES, TokenPsk}},
		nil, nil)

	PatternKNpsk0 = mustNewPattern("KNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil)

	PatternKNpsk2 = mustNewPattern("KNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, nil)

	PatternKKpsk0 = mustNewPattern("KKpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS})

	PatternKKpsk2 = mustNewPattern("KKpsk2",
		[][]Token{{TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS})

	PatternKXpsk2 = mustNewPattern("KXpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		[]Token{TokenS}, nil)

	PatternXNpsk3 = mustNewPattern("XNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil)

	PatternXKpsk3 = mustNewPattern("XKpsk3",
		[][]Token{{TokenE, TokenES}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS})

	PatternXXpsk3 = mustNewPattern("XXpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil)

	PatternINpsk1 = mustNewPattern("INpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, nil)

	PatternINpsk2 = mustNewPattern("INpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, nil)

	PatternIKpsk1 = mustNewPattern("IKpsk1",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS})

	PatternIKpsk2 = mustNewPattern("IKpsk2",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, []Token{TokenS})

	PatternIXpsk2 = mustNewPattern("IXpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		nil, nil)

	PatternNpsk0 = mustNewPattern("Npsk0",
		[][]Token{{TokenPsk, TokenE, TokenES}},
		nil,
		nil, []Token{TokenS})

	PatternKpsk0 = mustNewPattern("Kpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES, TokenSS}},
		nil,
		[]Token{TokenS}, []Token{TokenS})

	PatternXpsk1 = mustNewPattern("Xpsk1",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		nil,
		nil, []Token{TokenS})
)

// ============================================================================
// PQ (KEM-only) Patterns
// No one-way PQ patterns (N/K/X are NQ-only). PQ starts at NN.
// ============================================================================

var (
	// pqNN: -> e, <- ekem
	PatternPqNN = mustNewPattern("pqNN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem}},
		nil, nil)

	// pqNK: <- s, ..., -> skem, e, <- ekem
	PatternPqNK = mustNewPattern("pqNK",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem}},
		nil, []Token{TokenS})

	// pqNX: -> e, <- ekem, s, -> skem
	PatternPqNX = mustNewPattern("pqNX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenS}},
		nil, nil)

	// pqKN: -> s, ..., -> e, <- ekem, skem
	//
	// Token order verified against the PQNoise paper (eprint 2022/539,
	// Figure 2). Deliberate naming deviation from Rust Clatter: Rust's
	// noise_pqkn() builds these same tokens but mislabels the pattern
	// "pqNK", shipping two distinct patterns under one name. go-clatter
	// follows the paper and keeps pqKN and pqNK separate.
	PatternPqKN = mustNewPattern("pqKN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem}},
		[]Token{TokenS}, nil)

	// pqKK: -> s, <- s, ..., -> skem, e, <- ekem, skem
	PatternPqKK = mustNewPattern("pqKK",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenSkem}},
		[]Token{TokenS}, []Token{TokenS})

	// pqKX: -> s, ..., -> e, <- ekem, skem, s, -> skem
	PatternPqKX = mustNewPattern("pqKX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS}},
		[]Token{TokenS}, nil)

	// pqXN: -> e, <- ekem, -> s, <- skem
	PatternPqXN = mustNewPattern("pqXN",
		[][]Token{{TokenE}, {TokenS}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, nil)

	// pqXK: <- s, ..., -> skem, e, <- ekem, -> s, <- skem
	PatternPqXK = mustNewPattern("pqXK",
		[][]Token{{TokenSkem, TokenE}, {TokenS}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, []Token{TokenS})

	// pqXX: -> e, <- ekem, s, -> skem, s, <- skem
	PatternPqXX = mustNewPattern("pqXX",
		[][]Token{{TokenE}, {TokenSkem, TokenS}},
		[][]Token{{TokenEkem, TokenS}, {TokenSkem}},
		nil, nil)

	// pqIN: -> e, s, <- ekem, skem
	PatternPqIN = mustNewPattern("pqIN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, nil)

	// pqIK: <- s, ..., -> skem, e, s, <- ekem, skem
	PatternPqIK = mustNewPattern("pqIK",
		[][]Token{{TokenSkem, TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, []Token{TokenS})

	// pqIX: -> e, s, <- ekem, skem, s, -> skem
	PatternPqIX = mustNewPattern("pqIX",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS}},
		nil, nil)
)

// ============================================================================
// PQ PSK Patterns
// Derived from Clatter add_psks() on corrected base patterns.
// pskN = PSK appended at end of Nth message (0-indexed across both sides).
// ============================================================================

var (
	// pqNNpsk2: -> e, <- ekem, psk
	PatternPqNNpsk2 = mustNewPattern("pqNNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenPsk}},
		nil, nil)

	// pqNKpsk2: <- s, ..., -> skem, e, <- ekem, psk
	PatternPqNKpsk2 = mustNewPattern("pqNKpsk2",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenPsk}},
		nil, []Token{TokenS})

	// pqNXpsk2: -> e, <- ekem, s, psk, -> skem
	PatternPqNXpsk2 = mustNewPattern("pqNXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenS, TokenPsk}},
		nil, nil)

	// pqKNpsk2: -> s, ..., -> e, <- ekem, skem, psk
	PatternPqKNpsk2 = mustNewPattern("pqKNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		[]Token{TokenS}, nil)

	// pqKKpsk2: -> s, <- s, ..., -> skem, e, <- ekem, skem, psk
	PatternPqKKpsk2 = mustNewPattern("pqKKpsk2",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS})

	// pqKXpsk2: -> s, ..., -> e, <- ekem, skem, s, psk, -> skem
	PatternPqKXpsk2 = mustNewPattern("pqKXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS, TokenPsk}},
		[]Token{TokenS}, nil)

	// pqXNpsk3: -> e, <- ekem, -> s, psk, <- skem
	PatternPqXNpsk3 = mustNewPattern("pqXNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenPsk}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, nil)

	// pqXKpsk3: <- s, ..., -> skem, e, <- ekem, -> s, psk, <- skem
	PatternPqXKpsk3 = mustNewPattern("pqXKpsk3",
		[][]Token{{TokenSkem, TokenE}, {TokenS, TokenPsk}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, []Token{TokenS})

	// pqXXpsk3: -> e, <- ekem, s, -> skem, s, psk, <- skem
	PatternPqXXpsk3 = mustNewPattern("pqXXpsk3",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenS}, {TokenSkem}},
		nil, nil)

	// pqINpsk1: -> e, s, psk, <- ekem, skem
	PatternPqINpsk1 = mustNewPattern("pqINpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, nil)

	// pqINpsk2: -> e, s, <- ekem, skem, psk
	PatternPqINpsk2 = mustNewPattern("pqINpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		nil, nil)

	// pqIKpsk1: <- s, ..., -> skem, e, s, psk, <- ekem, skem
	PatternPqIKpsk1 = mustNewPattern("pqIKpsk1",
		[][]Token{{TokenSkem, TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, []Token{TokenS})

	// pqIKpsk2: <- s, ..., -> skem, e, s, <- ekem, skem, psk
	PatternPqIKpsk2 = mustNewPattern("pqIKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		nil, []Token{TokenS})

	// pqIXpsk2: -> e, s, <- ekem, skem, s, psk, -> skem
	PatternPqIXpsk2 = mustNewPattern("pqIXpsk2",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS, TokenPsk}},
		nil, nil)
)

// ============================================================================
// Hybrid (DH+KEM) Patterns
// No one-way hybrid patterns. Hybrid starts at NN.
//
// Corrected from Clatter src/handshakepattern.rs.
// Ekem/Skem tokens appear in the OPPOSING party's message, not grouped with E.
// ============================================================================

var (
	// hybridNN: -> e, <- ekem, e, ee
	PatternHybridNN = mustNewPattern("hybridNN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}},
		nil, nil)

	// hybridNK: <- s, ..., -> skem, e, es, <- ekem, e, ee
	PatternHybridNK = mustNewPattern("hybridNK",
		[][]Token{{TokenSkem, TokenE, TokenES}},
		[][]Token{{TokenEkem, TokenE, TokenEE}},
		nil, []Token{TokenS})

	// hybridNX: -> e, <- ekem, e, ee, s, es, -> skem
	PatternHybridNX = mustNewPattern("hybridNX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}},
		nil, nil)

	// hybridKN: -> s, ..., -> e, <- ekem, skem, e, ee, se
	PatternHybridKN = mustNewPattern("hybridKN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil)

	// hybridKK: -> s, <- s, ..., -> skem, e, es, ss, <- ekem, skem, e, ee, se
	PatternHybridKK = mustNewPattern("hybridKK",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS})

	// hybridKX: -> s, ..., -> e, <- ekem, skem, e, ee, se, s, es, -> skem
	PatternHybridKX = mustNewPattern("hybridKX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		[]Token{TokenS}, nil)

	// hybridXN: -> e, <- ekem, e, ee, -> s, se, <- skem
	PatternHybridXN = mustNewPattern("hybridXN",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, nil)

	// hybridXK: <- s, ..., -> skem, e, es, <- ekem, e, ee, -> s, se, <- skem
	PatternHybridXK = mustNewPattern("hybridXK",
		[][]Token{{TokenSkem, TokenE, TokenES}, {TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, []Token{TokenS})

	// hybridXX: -> e, <- ekem, e, ee, s, es, -> skem, s, se, <- skem
	PatternHybridXX = mustNewPattern("hybridXX",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}, {TokenSkem}},
		nil, nil)

	// hybridIN: -> e, s, <- ekem, skem, e, ee, se
	PatternHybridIN = mustNewPattern("hybridIN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, nil)

	// hybridIK: <- s, ..., -> skem, e, es, s, ss, <- ekem, skem, e, ee, se
	PatternHybridIK = mustNewPattern("hybridIK",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS})

	// hybridIX: -> e, s, <- ekem, skem, e, ee, se, s, es, -> skem
	PatternHybridIX = mustNewPattern("hybridIX",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		nil, nil)
)

// ============================================================================
// Hybrid PSK Patterns
// Derived from Clatter add_psks() on corrected base patterns.
// ============================================================================

var (
	// hybridNNpsk0: -> psk, e, <- ekem, e, ee
	PatternHybridNNpsk0 = mustNewPattern("hybridNNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}},
		nil, nil)

	// hybridNNpsk2: -> e, <- ekem, e, ee, psk
	PatternHybridNNpsk2 = mustNewPattern("hybridNNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenPsk}},
		nil, nil)

	// hybridNKpsk2: <- s, ..., -> skem, e, es, <- ekem, e, ee, psk
	PatternHybridNKpsk2 = mustNewPattern("hybridNKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenPsk}},
		nil, []Token{TokenS})

	// hybridNXpsk2: -> e, <- ekem, e, ee, s, es, psk, -> skem
	PatternHybridNXpsk2 = mustNewPattern("hybridNXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES, TokenPsk}},
		nil, nil)

	// hybridKNpsk0: -> s, ..., -> psk, e, <- ekem, skem, e, ee, se
	PatternHybridKNpsk0 = mustNewPattern("hybridKNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil)

	// hybridKNpsk2: -> s, ..., -> e, <- ekem, skem, e, ee, se, psk
	PatternHybridKNpsk2 = mustNewPattern("hybridKNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, nil)

	// hybridKKpsk2: -> s, <- s, ..., -> skem, e, es, ss, <- ekem, skem, e, ee, se, psk
	PatternHybridKKpsk2 = mustNewPattern("hybridKKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS})

	// hybridKXpsk2: -> s, ..., -> e, <- ekem, skem, e, ee, se, s, es, psk, -> skem
	PatternHybridKXpsk2 = mustNewPattern("hybridKXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		[]Token{TokenS}, nil)

	// hybridXNpsk3: -> e, <- ekem, e, ee, -> s, se, psk, <- skem
	PatternHybridXNpsk3 = mustNewPattern("hybridXNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, nil)

	// hybridXKpsk3: <- s, ..., -> skem, e, es, <- ekem, e, ee, -> s, se, psk, <- skem
	PatternHybridXKpsk3 = mustNewPattern("hybridXKpsk3",
		[][]Token{{TokenSkem, TokenE, TokenES}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, []Token{TokenS})

	// hybridXXpsk3: -> e, <- ekem, e, ee, s, es, -> skem, s, se, psk, <- skem
	PatternHybridXXpsk3 = mustNewPattern("hybridXXpsk3",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}, {TokenSkem}},
		nil, nil)

	// hybridINpsk1: -> e, s, psk, <- ekem, skem, e, ee, se
	PatternHybridINpsk1 = mustNewPattern("hybridINpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, nil)

	// hybridINpsk2: -> e, s, <- ekem, skem, e, ee, se, psk
	PatternHybridINpsk2 = mustNewPattern("hybridINpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, nil)

	// hybridIKpsk1: <- s, ..., -> skem, e, es, s, ss, psk, <- ekem, skem, e, ee, se
	PatternHybridIKpsk1 = mustNewPattern("hybridIKpsk1",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS})

	// hybridIKpsk2: <- s, ..., -> skem, e, es, s, ss, <- ekem, skem, e, ee, se, psk
	PatternHybridIKpsk2 = mustNewPattern("hybridIKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, []Token{TokenS})

	// hybridIXpsk2: -> e, s, <- ekem, skem, e, ee, se, s, es, psk, -> skem
	PatternHybridIXpsk2 = mustNewPattern("hybridIXpsk2",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		nil, nil)
)

// AllPatterns returns all 90 predefined patterns for enumeration/testing.
// NQ=36 (3 one-way + 12 base + 21 PSK) + PQ=26 (12 base + 14 PSK) + Hybrid=28 (12 base + 16 PSK) = 90.
func AllPatterns() []*HandshakePattern {
	return []*HandshakePattern{
		// NQ one-way (3)
		PatternN, PatternK, PatternX,
		// NQ interactive (12)
		PatternNN, PatternNK, PatternNX,
		PatternKN, PatternKK, PatternKX,
		PatternXN, PatternXK, PatternXX,
		PatternIN, PatternIK, PatternIX,
		// NQ PSK (21)
		PatternNNpsk0, PatternNNpsk2,
		PatternNKpsk0, PatternNKpsk2,
		PatternNXpsk2,
		PatternKNpsk0, PatternKNpsk2,
		PatternKKpsk0, PatternKKpsk2,
		PatternKXpsk2,
		PatternXNpsk3, PatternXKpsk3, PatternXXpsk3,
		PatternINpsk1, PatternINpsk2,
		PatternIKpsk1, PatternIKpsk2,
		PatternIXpsk2,
		PatternNpsk0, PatternKpsk0, PatternXpsk1,
		// PQ (12)
		PatternPqNN, PatternPqNK, PatternPqNX,
		PatternPqKN, PatternPqKK, PatternPqKX,
		PatternPqXN, PatternPqXK, PatternPqXX,
		PatternPqIN, PatternPqIK, PatternPqIX,
		// PQ PSK (14)
		PatternPqNNpsk2,
		PatternPqNKpsk2,
		PatternPqNXpsk2,
		PatternPqKNpsk2,
		PatternPqKKpsk2,
		PatternPqKXpsk2,
		PatternPqXNpsk3, PatternPqXKpsk3, PatternPqXXpsk3,
		PatternPqINpsk1, PatternPqINpsk2,
		PatternPqIKpsk1, PatternPqIKpsk2,
		PatternPqIXpsk2,
		// Hybrid (12)
		PatternHybridNN, PatternHybridNK, PatternHybridNX,
		PatternHybridKN, PatternHybridKK, PatternHybridKX,
		PatternHybridXN, PatternHybridXK, PatternHybridXX,
		PatternHybridIN, PatternHybridIK, PatternHybridIX,
		// Hybrid PSK (16)
		PatternHybridNNpsk0, PatternHybridNNpsk2,
		PatternHybridNKpsk2,
		PatternHybridNXpsk2,
		PatternHybridKNpsk0, PatternHybridKNpsk2,
		PatternHybridKKpsk2,
		PatternHybridKXpsk2,
		PatternHybridXNpsk3, PatternHybridXKpsk3, PatternHybridXXpsk3,
		PatternHybridINpsk1, PatternHybridINpsk2,
		PatternHybridIKpsk1, PatternHybridIKpsk2,
		PatternHybridIXpsk2,
	}
}
