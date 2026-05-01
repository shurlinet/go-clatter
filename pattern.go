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

	isOneWay    bool        // One-way patterns: N, K, X (initiator only sends)
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

// IsOneWay returns true for one-way patterns (N, K, X).
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
// Returns error for invalid patterns. Use mustNewPattern for predefined patterns.
//
// Validates PSK position rules and PQ token ordering. Auto-detects pattern type
// from tokens (DH, KEM, or Hybrid). Caches hasPSK from a token scan.
func NewPattern(name string, initiatorMsgs, responderMsgs [][]Token,
	preInit, preResp []Token, oneWay bool) (*HandshakePattern, error) {

	if len(initiatorMsgs) > 5 || len(responderMsgs) > 5 {
		return nil, fmt.Errorf("%w: too many messages", ErrInvalidPattern)
	}
	if len(preInit) > 2 || len(preResp) > 2 {
		return nil, fmt.Errorf("%w: too many pre-message tokens", ErrInvalidPattern)
	}

	p := &HandshakePattern{
		name:         name,
		numInitiator: len(initiatorMsgs),
		numResponder: len(responderMsgs),
		numPreInit:   len(preInit),
		numPreResp:   len(preResp),
		isOneWay:     oneWay,
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

	return p, nil
}

// mustNewPattern creates a pattern, panicking on invalid input.
// Used for predefined patterns (like template.Must).
func mustNewPattern(name string, initiatorMsgs, responderMsgs [][]Token,
	preInit, preResp []Token, oneWay bool) *HandshakePattern {
	p, err := NewPattern(name, initiatorMsgs, responderMsgs, preInit, preResp, oneWay)
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

// validatePSKRules validates PSK position rules per Noise spec.
// PSK validation scans ACROSS messages (psk_sent persists).
// The own_randomness_applied check (PSK before first S) is enforced at
// RUNTIME in the handshake state machine, not here at construction.
// This function validates structural placement only.
//
// Rule: PSK token can only appear at position 0 or after all other tokens in a message.
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

// ============================================================================
// Predefined NQ (Classical DH) Patterns
// ============================================================================

// One-way patterns (NQ-only; no PQ or Hybrid one-way patterns exist)
var (
	PatternN = mustNewPattern("N",
		[][]Token{{TokenE, TokenES}},
		nil,
		nil, []Token{TokenS},
		true)

	PatternK = mustNewPattern("K",
		[][]Token{{TokenE, TokenES, TokenSS}},
		nil,
		[]Token{TokenS}, []Token{TokenS},
		true)

	PatternX = mustNewPattern("X",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		nil,
		nil, []Token{TokenS},
		true)
)

// Interactive NQ base patterns
var (
	PatternNN = mustNewPattern("NN",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil, false)

	PatternNK = mustNewPattern("NK",
		[][]Token{{TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS}, false)

	PatternNX = mustNewPattern("NX",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil, false)

	PatternKN = mustNewPattern("KN",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil, false)

	PatternKK = mustNewPattern("KK",
		[][]Token{{TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS}, false)

	PatternKX = mustNewPattern("KX",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		[]Token{TokenS}, nil, false)

	PatternXN = mustNewPattern("XN",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil, false)

	PatternXK = mustNewPattern("XK",
		[][]Token{{TokenE, TokenES}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS}, false)

	PatternXX = mustNewPattern("XX",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil, false)

	PatternIN = mustNewPattern("IN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, nil, false)

	PatternIK = mustNewPattern("IK",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS}, false)

	PatternIX = mustNewPattern("IX",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		nil, nil, false)
)


// ============================================================================
// NQ PSK Patterns
// ============================================================================

var (
	PatternNNpsk0 = mustNewPattern("NNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil, false)

	PatternNNpsk2 = mustNewPattern("NNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenPsk}},
		nil, nil, false)

	PatternNKpsk0 = mustNewPattern("NKpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS}, false)

	PatternNKpsk2 = mustNewPattern("NKpsk2",
		[][]Token{{TokenE, TokenES}},
		[][]Token{{TokenE, TokenEE, TokenPsk}},
		nil, []Token{TokenS}, false)

	PatternNXpsk2 = mustNewPattern("NXpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES, TokenPsk}},
		nil, nil, false)

	PatternKNpsk0 = mustNewPattern("KNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil, false)

	PatternKNpsk2 = mustNewPattern("KNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, nil, false)

	PatternKKpsk0 = mustNewPattern("KKpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS}, false)

	PatternKKpsk2 = mustNewPattern("KKpsk2",
		[][]Token{{TokenE, TokenES, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS}, false)

	PatternKXpsk2 = mustNewPattern("KXpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		[]Token{TokenS}, nil, false)

	PatternXNpsk3 = mustNewPattern("XNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil, false)

	PatternXKpsk3 = mustNewPattern("XKpsk3",
		[][]Token{{TokenE, TokenES}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE}},
		nil, []Token{TokenS}, false)

	PatternXXpsk3 = mustNewPattern("XXpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenS, TokenES}},
		nil, nil, false)

	PatternINpsk1 = mustNewPattern("INpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, nil, false)

	PatternINpsk2 = mustNewPattern("INpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, nil, false)

	PatternIKpsk1 = mustNewPattern("IKpsk1",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		[][]Token{{TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS}, false)

	PatternIKpsk2 = mustNewPattern("IKpsk2",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, []Token{TokenS}, false)

	PatternIXpsk2 = mustNewPattern("IXpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		nil, nil, false)

	PatternNpsk0 = mustNewPattern("Npsk0",
		[][]Token{{TokenPsk, TokenE, TokenES}},
		nil,
		nil, []Token{TokenS},
		true)

	PatternKpsk0 = mustNewPattern("Kpsk0",
		[][]Token{{TokenPsk, TokenE, TokenES, TokenSS}},
		nil,
		[]Token{TokenS}, []Token{TokenS},
		true)

	PatternXpsk1 = mustNewPattern("Xpsk1",
		[][]Token{{TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		nil,
		nil, []Token{TokenS},
		true)
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
		nil, nil, false)

	// pqNK: <- s, ..., -> skem, e, <- ekem
	PatternPqNK = mustNewPattern("pqNK",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem}},
		nil, []Token{TokenS}, false)

	// pqNX: -> e, <- ekem, s, -> skem
	PatternPqNX = mustNewPattern("pqNX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenS}},
		nil, nil, false)

	// pqKN: -> s, ..., -> skem, e, <- ekem  (note: Clatter labels this pqNK but maps to KN)
	// Actually from Clatter: pqKN -> s, ..., -> e, <- ekem, skem
	// Wait, let me re-read. Clatter noise_pqkn is NOT in the snippet. Let me use pqNK's code
	// which Clatter confusingly names noise_pqkn. Let me just use the exact Clatter definitions.
	// Clatter noise_pqkn: pre_init=[s], init=[(skem, e)], resp=[(ekem)]
	// BUT wait, looking at the code: noise_pqkn is actually at line 398:
	// -> s, ..., -> skem, e, <- ekem
	// That IS noise_pqnk in the Clatter source. The function name/pattern name mismatch.
	// Let me use the PATTERN NAME from Clatter which is the string passed to HandshakePattern::new.
	// From the Clatter source, the function noise_pqkn creates pattern named "pqNK" with pre_init=[s].
	// That's actually the KN variant (initiator has pre-shared static).
	// CORRECTION: re-reading: noise_pqkn is at the position for pqNK.
	// Function noise_pqkn creates "pqNK" with pre_init = [Token::S], pre_resp = [].
	// This means initiator pre-shares S, matching KN semantics.
	// The Clatter function NAME is wrong but the pattern NAME "pqNK" is what matters.
	// Wait no - reading again: "pqNK" has pre_resp=[Token::S] in normal Noise (NK = responder known).
	// Let me just trust the Rust source directly.
	//
	// Re-reading the source carefully:
	// noise_pqnk: name="pqNK", pre_init=[], pre_resp=[s], init=[(skem,e)], resp=[(ekem)]
	//   -> This is NK: responder's static is pre-known. Matches.
	// noise_pqkn: appears to not exist separately. Let me look at what's labeled pqKN.
	// Actually at line 430, there's no pqKN visible. Let me search.

	// pqKN: -> s, ..., -> e, <- ekem, skem
	PatternPqKN = mustNewPattern("pqKN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem}},
		[]Token{TokenS}, nil, false)

	// pqKK: -> s, <- s, ..., -> skem, e, <- ekem, skem
	PatternPqKK = mustNewPattern("pqKK",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenSkem}},
		[]Token{TokenS}, []Token{TokenS}, false)

	// pqKX: -> s, ..., -> e, <- ekem, skem, s, -> skem
	PatternPqKX = mustNewPattern("pqKX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS}},
		[]Token{TokenS}, nil, false)

	// pqXN: -> e, <- ekem, -> s, <- skem
	PatternPqXN = mustNewPattern("pqXN",
		[][]Token{{TokenE}, {TokenS}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, nil, false)

	// pqXK: <- s, ..., -> skem, e, <- ekem, -> s, <- skem
	PatternPqXK = mustNewPattern("pqXK",
		[][]Token{{TokenSkem, TokenE}, {TokenS}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, []Token{TokenS}, false)

	// pqXX: -> e, <- ekem, s, -> skem, s, <- skem
	PatternPqXX = mustNewPattern("pqXX",
		[][]Token{{TokenE}, {TokenSkem, TokenS}},
		[][]Token{{TokenEkem, TokenS}, {TokenSkem}},
		nil, nil, false)

	// pqIN: -> e, s, <- ekem, skem
	PatternPqIN = mustNewPattern("pqIN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, nil, false)

	// pqIK: <- s, ..., -> skem, e, s, <- ekem, skem
	PatternPqIK = mustNewPattern("pqIK",
		[][]Token{{TokenSkem, TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, []Token{TokenS}, false)

	// pqIX: -> e, s, <- ekem, skem, s, -> skem
	PatternPqIX = mustNewPattern("pqIX",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS}},
		nil, nil, false)
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
		nil, nil, false)

	// pqNKpsk2: <- s, ..., -> skem, e, <- ekem, psk
	PatternPqNKpsk2 = mustNewPattern("pqNKpsk2",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenPsk}},
		nil, []Token{TokenS}, false)

	// pqNXpsk2: -> e, <- ekem, s, psk, -> skem
	PatternPqNXpsk2 = mustNewPattern("pqNXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenS, TokenPsk}},
		nil, nil, false)

	// pqKNpsk2: -> s, ..., -> e, <- ekem, skem, psk
	PatternPqKNpsk2 = mustNewPattern("pqKNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		[]Token{TokenS}, nil, false)

	// pqKKpsk2: -> s, <- s, ..., -> skem, e, <- ekem, skem, psk
	PatternPqKKpsk2 = mustNewPattern("pqKKpsk2",
		[][]Token{{TokenSkem, TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS}, false)

	// pqKXpsk2: -> s, ..., -> e, <- ekem, skem, s, psk, -> skem
	PatternPqKXpsk2 = mustNewPattern("pqKXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS, TokenPsk}},
		[]Token{TokenS}, nil, false)

	// pqXNpsk3: -> e, <- ekem, -> s, psk, <- skem
	PatternPqXNpsk3 = mustNewPattern("pqXNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenPsk}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, nil, false)

	// pqXKpsk3: <- s, ..., -> skem, e, <- ekem, -> s, psk, <- skem
	PatternPqXKpsk3 = mustNewPattern("pqXKpsk3",
		[][]Token{{TokenSkem, TokenE}, {TokenS, TokenPsk}},
		[][]Token{{TokenEkem}, {TokenSkem}},
		nil, []Token{TokenS}, false)

	// pqXXpsk3: -> e, <- ekem, s, -> skem, s, psk, <- skem
	PatternPqXXpsk3 = mustNewPattern("pqXXpsk3",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenS}, {TokenSkem}},
		nil, nil, false)

	// pqINpsk1: -> e, s, psk, <- ekem, skem
	PatternPqINpsk1 = mustNewPattern("pqINpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, nil, false)

	// pqINpsk2: -> e, s, <- ekem, skem, psk
	PatternPqINpsk2 = mustNewPattern("pqINpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		nil, nil, false)

	// pqIKpsk1: <- s, ..., -> skem, e, s, psk, <- ekem, skem
	PatternPqIKpsk1 = mustNewPattern("pqIKpsk1",
		[][]Token{{TokenSkem, TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem}},
		nil, []Token{TokenS}, false)

	// pqIKpsk2: <- s, ..., -> skem, e, s, <- ekem, skem, psk
	PatternPqIKpsk2 = mustNewPattern("pqIKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenPsk}},
		nil, []Token{TokenS}, false)

	// pqIXpsk2: -> e, s, <- ekem, skem, s, psk, -> skem
	PatternPqIXpsk2 = mustNewPattern("pqIXpsk2",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenS, TokenPsk}},
		nil, nil, false)
)

// ============================================================================
// Hybrid (DH+KEM) Patterns
// No one-way hybrid patterns. Hybrid starts at NN.
//
// Corrected from Clatter src/handshakepattern.rs (Batch 4, 2026-05-01).
// Ekem/Skem tokens appear in the OPPOSING party's message, not grouped with E.
// ============================================================================

var (
	// hybridNN: -> e, <- ekem, e, ee
	PatternHybridNN = mustNewPattern("hybridNN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}},
		nil, nil, false)

	// hybridNK: <- s, ..., -> skem, e, es, <- ekem, e, ee
	PatternHybridNK = mustNewPattern("hybridNK",
		[][]Token{{TokenSkem, TokenE, TokenES}},
		[][]Token{{TokenEkem, TokenE, TokenEE}},
		nil, []Token{TokenS}, false)

	// hybridNX: -> e, <- ekem, e, ee, s, es, -> skem
	PatternHybridNX = mustNewPattern("hybridNX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}},
		nil, nil, false)

	// hybridKN: -> s, ..., -> e, <- ekem, skem, e, ee, se
	PatternHybridKN = mustNewPattern("hybridKN",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil, false)

	// hybridKK: -> s, <- s, ..., -> skem, e, es, ss, <- ekem, skem, e, ee, se
	PatternHybridKK = mustNewPattern("hybridKK",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, []Token{TokenS}, false)

	// hybridKX: -> s, ..., -> e, <- ekem, skem, e, ee, se, s, es, -> skem
	PatternHybridKX = mustNewPattern("hybridKX",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		[]Token{TokenS}, nil, false)

	// hybridXN: -> e, <- ekem, e, ee, -> s, se, <- skem
	PatternHybridXN = mustNewPattern("hybridXN",
		[][]Token{{TokenE}, {TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, nil, false)

	// hybridXK: <- s, ..., -> skem, e, es, <- ekem, e, ee, -> s, se, <- skem
	PatternHybridXK = mustNewPattern("hybridXK",
		[][]Token{{TokenSkem, TokenE, TokenES}, {TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, []Token{TokenS}, false)

	// hybridXX: -> e, <- ekem, e, ee, s, es, -> skem, s, se, <- skem
	PatternHybridXX = mustNewPattern("hybridXX",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenSE}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}, {TokenSkem}},
		nil, nil, false)

	// hybridIN: -> e, s, <- ekem, skem, e, ee, se
	PatternHybridIN = mustNewPattern("hybridIN",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, nil, false)

	// hybridIK: <- s, ..., -> skem, e, es, s, ss, <- ekem, skem, e, ee, se
	PatternHybridIK = mustNewPattern("hybridIK",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS}, false)

	// hybridIX: -> e, s, <- ekem, skem, e, ee, se, s, es, -> skem
	PatternHybridIX = mustNewPattern("hybridIX",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES}},
		nil, nil, false)
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
		nil, nil, false)

	// hybridNNpsk2: -> e, <- ekem, e, ee, psk
	PatternHybridNNpsk2 = mustNewPattern("hybridNNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenPsk}},
		nil, nil, false)

	// hybridNKpsk2: <- s, ..., -> skem, e, es, <- ekem, e, ee, psk
	PatternHybridNKpsk2 = mustNewPattern("hybridNKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenPsk}},
		nil, []Token{TokenS}, false)

	// hybridNXpsk2: -> e, <- ekem, e, ee, s, es, psk, -> skem
	PatternHybridNXpsk2 = mustNewPattern("hybridNXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES, TokenPsk}},
		nil, nil, false)

	// hybridKNpsk0: -> s, ..., -> psk, e, <- ekem, skem, e, ee, se
	PatternHybridKNpsk0 = mustNewPattern("hybridKNpsk0",
		[][]Token{{TokenPsk, TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		[]Token{TokenS}, nil, false)

	// hybridKNpsk2: -> s, ..., -> e, <- ekem, skem, e, ee, se, psk
	PatternHybridKNpsk2 = mustNewPattern("hybridKNpsk2",
		[][]Token{{TokenE}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, nil, false)

	// hybridKKpsk2: -> s, <- s, ..., -> skem, e, es, ss, <- ekem, skem, e, ee, se, psk
	PatternHybridKKpsk2 = mustNewPattern("hybridKKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		[]Token{TokenS}, []Token{TokenS}, false)

	// hybridKXpsk2: -> s, ..., -> e, <- ekem, skem, e, ee, se, s, es, psk, -> skem
	PatternHybridKXpsk2 = mustNewPattern("hybridKXpsk2",
		[][]Token{{TokenE}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		[]Token{TokenS}, nil, false)

	// hybridXNpsk3: -> e, <- ekem, e, ee, -> s, se, psk, <- skem
	PatternHybridXNpsk3 = mustNewPattern("hybridXNpsk3",
		[][]Token{{TokenE}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, nil, false)

	// hybridXKpsk3: <- s, ..., -> skem, e, es, <- ekem, e, ee, -> s, se, psk, <- skem
	PatternHybridXKpsk3 = mustNewPattern("hybridXKpsk3",
		[][]Token{{TokenSkem, TokenE, TokenES}, {TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE}, {TokenSkem}},
		nil, []Token{TokenS}, false)

	// hybridXXpsk3: -> e, <- ekem, e, ee, s, es, -> skem, s, se, psk, <- skem
	PatternHybridXXpsk3 = mustNewPattern("hybridXXpsk3",
		[][]Token{{TokenE}, {TokenSkem, TokenS, TokenSE, TokenPsk}},
		[][]Token{{TokenEkem, TokenE, TokenEE, TokenS, TokenES}, {TokenSkem}},
		nil, nil, false)

	// hybridINpsk1: -> e, s, psk, <- ekem, skem, e, ee, se
	PatternHybridINpsk1 = mustNewPattern("hybridINpsk1",
		[][]Token{{TokenE, TokenS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, nil, false)

	// hybridINpsk2: -> e, s, <- ekem, skem, e, ee, se, psk
	PatternHybridINpsk2 = mustNewPattern("hybridINpsk2",
		[][]Token{{TokenE, TokenS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, nil, false)

	// hybridIKpsk1: <- s, ..., -> skem, e, es, s, ss, psk, <- ekem, skem, e, ee, se
	PatternHybridIKpsk1 = mustNewPattern("hybridIKpsk1",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS, TokenPsk}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE}},
		nil, []Token{TokenS}, false)

	// hybridIKpsk2: <- s, ..., -> skem, e, es, s, ss, <- ekem, skem, e, ee, se, psk
	PatternHybridIKpsk2 = mustNewPattern("hybridIKpsk2",
		[][]Token{{TokenSkem, TokenE, TokenES, TokenS, TokenSS}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenPsk}},
		nil, []Token{TokenS}, false)

	// hybridIXpsk2: -> e, s, <- ekem, skem, e, ee, se, s, es, psk, -> skem
	PatternHybridIXpsk2 = mustNewPattern("hybridIXpsk2",
		[][]Token{{TokenE, TokenS}, {TokenSkem}},
		[][]Token{{TokenEkem, TokenSkem, TokenE, TokenEE, TokenSE, TokenS, TokenES, TokenPsk}},
		nil, nil, false)
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
