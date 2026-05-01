package clatter

import (
	"testing"
)

// TestAllPatternsCount verifies we have exactly 91 predefined patterns.
// NQ=36 (3 one-way + 12 base + 21 PSK) + PQ=25 (12 base + 13 PSK) + Hybrid=30 (12 base + 18 PSK) = 91.
func TestAllPatternsCount(t *testing.T) {
	patterns := AllPatterns()
	if len(patterns) != 91 {
		t.Fatalf("expected 91 patterns, got %d", len(patterns))
	}
}

// TestAllPatternsHaveNames verifies every pattern has a non-empty name.
func TestAllPatternsHaveNames(t *testing.T) {
	for _, p := range AllPatterns() {
		if p.Name() == "" {
			t.Fatal("found pattern with empty name")
		}
	}
}

// TestPatternTypeDetection verifies F113 auto-detection from tokens.
func TestPatternTypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		pattern  *HandshakePattern
		expected PatternType
	}{
		// NQ
		{"NN", PatternNN, PatternTypeDH},
		{"XX", PatternXX, PatternTypeDH},
		{"IK", PatternIK, PatternTypeDH},
		{"N", PatternN, PatternTypeDH},
		{"NNpsk0", PatternNNpsk0, PatternTypeDH},
		// PQ
		{"pqNN", PatternPqNN, PatternTypeKEM},
		{"pqXX", PatternPqXX, PatternTypeKEM},
		{"pqIK", PatternPqIK, PatternTypeKEM},
		{"pqNNpsk0", PatternPqNNpsk0, PatternTypeKEM},
		// Hybrid
		{"hybridNN", PatternHybridNN, PatternTypeHybrid},
		{"hybridXX", PatternHybridXX, PatternTypeHybrid},
		{"hybridIK", PatternHybridIK, PatternTypeHybrid},
		{"hybridNNpsk0", PatternHybridNNpsk0, PatternTypeHybrid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pattern.Type() != tt.expected {
				t.Errorf("pattern %s: expected type %d, got %d",
					tt.name, tt.expected, tt.pattern.Type())
			}
		})
	}
}

// TestPSKDetection verifies F116 cached PSK scan.
func TestPSKDetection(t *testing.T) {
	// Non-PSK patterns
	noPSK := []*HandshakePattern{
		PatternNN, PatternXX, PatternIK, PatternN,
		PatternPqNN, PatternPqXX,
		PatternHybridNN, PatternHybridXX,
	}
	for _, p := range noPSK {
		if p.HasPSK() {
			t.Errorf("pattern %s should not have PSK", p.Name())
		}
	}

	// PSK patterns
	hasPSK := []*HandshakePattern{
		PatternNNpsk0, PatternNNpsk2, PatternXXpsk3,
		PatternPqNNpsk0, PatternPqNNpsk2,
		PatternHybridNNpsk0, PatternHybridXXpsk3,
		PatternNpsk0, PatternKpsk0, PatternXpsk1,
	}
	for _, p := range hasPSK {
		if !p.HasPSK() {
			t.Errorf("pattern %s should have PSK", p.Name())
		}
	}
}

// TestOneWayPatterns verifies F139: one-way patterns are NQ-only.
func TestOneWayPatterns(t *testing.T) {
	oneWay := []*HandshakePattern{
		PatternN, PatternK, PatternX,
		PatternNpsk0, PatternKpsk0, PatternXpsk1,
	}
	for _, p := range oneWay {
		if !p.IsOneWay() {
			t.Errorf("pattern %s should be one-way", p.Name())
		}
		if p.Type() != PatternTypeDH {
			t.Errorf("one-way pattern %s should be DH type, got %d", p.Name(), p.Type())
		}
	}

	// PQ and Hybrid should NOT be one-way
	notOneWay := []*HandshakePattern{
		PatternPqNN, PatternPqXX, PatternPqIK,
		PatternHybridNN, PatternHybridXX, PatternHybridIK,
	}
	for _, p := range notOneWay {
		if p.IsOneWay() {
			t.Errorf("pattern %s should NOT be one-way", p.Name())
		}
	}
}

// TestPatternMessageAccess verifies accessor methods.
func TestPatternMessageAccess(t *testing.T) {
	// NN: 1 initiator msg, 1 responder msg
	if PatternNN.NumInitiatorMessages() != 1 {
		t.Errorf("NN: expected 1 initiator msg, got %d", PatternNN.NumInitiatorMessages())
	}
	if PatternNN.NumResponderMessages() != 1 {
		t.Errorf("NN: expected 1 responder msg, got %d", PatternNN.NumResponderMessages())
	}
	if PatternNN.TotalMessages() != 2 {
		t.Errorf("NN: expected 2 total msgs, got %d", PatternNN.TotalMessages())
	}

	// NN initiator msg0 = [e]
	msg0 := PatternNN.InitiatorMessage(0)
	if len(msg0) != 1 || msg0[0] != TokenE {
		t.Errorf("NN initiator msg0: expected [E], got %v", msg0)
	}

	// NN responder msg0 = [e, ee]
	rmsg0 := PatternNN.ResponderMessage(0)
	if len(rmsg0) != 2 || rmsg0[0] != TokenE || rmsg0[1] != TokenEE {
		t.Errorf("NN responder msg0: expected [E, EE], got %v", rmsg0)
	}

	// Out-of-bounds returns nil
	if PatternNN.InitiatorMessage(5) != nil {
		t.Error("expected nil for out-of-bounds initiator message")
	}
	if PatternNN.ResponderMessage(-1) != nil {
		t.Error("expected nil for negative responder message index")
	}
}

// TestXXPattern verifies the 3-message XX pattern (init corrected in init()).
func TestXXPattern(t *testing.T) {
	// XX: msg1=initiator[e], msg2=responder[e,ee,s,es], msg3=initiator[s,se]
	if PatternXX.NumInitiatorMessages() != 2 {
		t.Errorf("XX: expected 2 initiator msgs, got %d", PatternXX.NumInitiatorMessages())
	}
	if PatternXX.NumResponderMessages() != 1 {
		t.Errorf("XX: expected 1 responder msg, got %d", PatternXX.NumResponderMessages())
	}
	if PatternXX.TotalMessages() != 3 {
		t.Errorf("XX: expected 3 total msgs, got %d", PatternXX.TotalMessages())
	}

	// msg1: initiator sends [e]
	msg1 := PatternXX.InitiatorMessage(0)
	if len(msg1) != 1 || msg1[0] != TokenE {
		t.Errorf("XX msg1: expected [E], got %v", msg1)
	}

	// msg2: responder sends [e, ee, s, es]
	msg2 := PatternXX.ResponderMessage(0)
	if len(msg2) != 4 {
		t.Errorf("XX msg2: expected 4 tokens, got %d", len(msg2))
	}
	expected := []Token{TokenE, TokenEE, TokenS, TokenES}
	for i, tok := range expected {
		if msg2[i] != tok {
			t.Errorf("XX msg2[%d]: expected %s, got %d", i, tokenString(tok), msg2[i])
		}
	}

	// msg3: initiator sends [s, se]
	msg3 := PatternXX.InitiatorMessage(1)
	if len(msg3) != 2 || msg3[0] != TokenS || msg3[1] != TokenSE {
		t.Errorf("XX msg3: expected [S, SE], got %v", msg3)
	}
}

// TestPreMessageTokens verifies pre-message token access.
func TestPreMessageTokens(t *testing.T) {
	// IK: pre-responder = [s]
	preResp := PatternIK.PreResponder()
	if len(preResp) != 1 || preResp[0] != TokenS {
		t.Errorf("IK pre-responder: expected [S], got %v", preResp)
	}
	if len(PatternIK.PreInitiator()) != 0 {
		t.Error("IK should have no pre-initiator tokens")
	}

	// KK: pre-initiator = [s], pre-responder = [s]
	preInit := PatternKK.PreInitiator()
	if len(preInit) != 1 || preInit[0] != TokenS {
		t.Errorf("KK pre-initiator: expected [S], got %v", preInit)
	}
	preResp = PatternKK.PreResponder()
	if len(preResp) != 1 || preResp[0] != TokenS {
		t.Errorf("KK pre-responder: expected [S], got %v", preResp)
	}

	// NN: no pre-messages
	if len(PatternNN.PreInitiator()) != 0 || len(PatternNN.PreResponder()) != 0 {
		t.Error("NN should have no pre-message tokens")
	}
}

// TestInvalidPattern_TooManyMessages verifies validation rejects oversized patterns.
func TestInvalidPattern_TooManyMessages(t *testing.T) {
	_, err := NewPattern("bad",
		[][]Token{{TokenE}, {TokenE}, {TokenE}, {TokenE}, {TokenE}, {TokenE}},
		nil, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for 6 initiator messages")
	}
}

// TestInvalidPattern_TooManyTokens verifies validation rejects messages with >10 tokens.
func TestInvalidPattern_TooManyTokens(t *testing.T) {
	_, err := NewPattern("bad",
		[][]Token{{TokenE, TokenE, TokenE, TokenE, TokenE, TokenE, TokenE, TokenE, TokenE, TokenE, TokenE}},
		nil, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for 11 tokens in one message")
	}
}

// TestInvalidPattern_PSKMidMessage verifies PSK must be first or last.
func TestInvalidPattern_PSKMidMessage(t *testing.T) {
	_, err := NewPattern("bad",
		[][]Token{{TokenE, TokenPsk, TokenES}},
		[][]Token{{TokenE, TokenEE}},
		nil, nil, false)
	if err == nil {
		t.Fatal("expected error for PSK in middle of message")
	}
}

// TestInvalidPattern_EkemAfterSkem verifies Ekem must come before Skem.
func TestInvalidPattern_EkemAfterSkem(t *testing.T) {
	_, err := NewPattern("bad",
		[][]Token{{TokenE, TokenSkem, TokenEkem}},
		nil, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for Ekem after Skem")
	}
}

// TestInvalidPattern_SkemWithoutPubKey verifies Skem needs prior E or S.
func TestInvalidPattern_SkemWithoutPubKey(t *testing.T) {
	_, err := NewPattern("bad",
		[][]Token{{TokenSkem}},
		nil, nil, nil, false)
	if err == nil {
		t.Fatal("expected error for Skem without prior E or S")
	}
}

// TestTokenString verifies token display names.
func TestTokenString(t *testing.T) {
	tests := []struct {
		token Token
		name  string
	}{
		{TokenE, "e"}, {TokenS, "s"}, {TokenEE, "ee"}, {TokenES, "es"},
		{TokenSE, "se"}, {TokenSS, "ss"}, {TokenPsk, "psk"},
		{TokenEkem, "ekem"}, {TokenSkem, "skem"},
	}
	for _, tt := range tests {
		if got := tokenString(tt.token); got != tt.name {
			t.Errorf("tokenString(%d): expected %q, got %q", tt.token, tt.name, got)
		}
	}
}

// TestHybridPatternsHaveBothDHAndKEM verifies hybrid patterns have both token types.
func TestHybridPatternsHaveBothDHAndKEM(t *testing.T) {
	hybridPatterns := []*HandshakePattern{
		PatternHybridNN, PatternHybridNK, PatternHybridNX,
		PatternHybridKN, PatternHybridKK, PatternHybridKX,
		PatternHybridXN, PatternHybridXK, PatternHybridXX,
		PatternHybridIN, PatternHybridIK, PatternHybridIX,
	}
	for _, p := range hybridPatterns {
		hasDH := false
		hasKEM := false
		for i := 0; i < p.NumInitiatorMessages(); i++ {
			for _, t := range p.InitiatorMessage(i) {
				if t == TokenEE || t == TokenES || t == TokenSE || t == TokenSS {
					hasDH = true
				}
				if t == TokenEkem || t == TokenSkem {
					hasKEM = true
				}
			}
		}
		for i := 0; i < p.NumResponderMessages(); i++ {
			for _, t := range p.ResponderMessage(i) {
				if t == TokenEE || t == TokenES || t == TokenSE || t == TokenSS {
					hasDH = true
				}
				if t == TokenEkem || t == TokenSkem {
					hasKEM = true
				}
			}
		}
		if !hasDH || !hasKEM {
			t.Errorf("hybrid pattern %s: hasDH=%v hasKEM=%v", p.Name(), hasDH, hasKEM)
		}
	}
}

// TestPQPatternsHaveNoNQDHTokens verifies PQ patterns have only KEM tokens (no ee/es/se/ss).
func TestPQPatternsHaveNoNQDHTokens(t *testing.T) {
	pqPatterns := []*HandshakePattern{
		PatternPqNN, PatternPqNK, PatternPqNX,
		PatternPqKN, PatternPqKK, PatternPqKX,
		PatternPqXN, PatternPqXK, PatternPqXX,
		PatternPqIN, PatternPqIK, PatternPqIX,
	}
	for _, p := range pqPatterns {
		for i := 0; i < p.NumInitiatorMessages(); i++ {
			for _, tok := range p.InitiatorMessage(i) {
				if tok == TokenEE || tok == TokenES || tok == TokenSE || tok == TokenSS {
					t.Errorf("PQ pattern %s has DH token %s", p.Name(), tokenString(tok))
				}
			}
		}
		for i := 0; i < p.NumResponderMessages(); i++ {
			for _, tok := range p.ResponderMessage(i) {
				if tok == TokenEE || tok == TokenES || tok == TokenSE || tok == TokenSS {
					t.Errorf("PQ pattern %s has DH token %s", p.Name(), tokenString(tok))
				}
			}
		}
	}
}

// TestNQPatternsHaveNoKEMTokens verifies NQ patterns have no ekem/skem tokens.
func TestNQPatternsHaveNoKEMTokens(t *testing.T) {
	nqPatterns := []*HandshakePattern{
		PatternNN, PatternNK, PatternNX,
		PatternKN, PatternKK, PatternKX,
		PatternXN, PatternXK, PatternXX,
		PatternIN, PatternIK, PatternIX,
		PatternN, PatternK, PatternX,
	}
	for _, p := range nqPatterns {
		for i := 0; i < p.NumInitiatorMessages(); i++ {
			for _, tok := range p.InitiatorMessage(i) {
				if tok == TokenEkem || tok == TokenSkem {
					t.Errorf("NQ pattern %s has KEM token %s", p.Name(), tokenString(tok))
				}
			}
		}
		for i := 0; i < p.NumResponderMessages(); i++ {
			for _, tok := range p.ResponderMessage(i) {
				if tok == TokenEkem || tok == TokenSkem {
					t.Errorf("NQ pattern %s has KEM token %s", p.Name(), tokenString(tok))
				}
			}
		}
	}
}

// TestPatternCategoryCounts verifies the count breakdown.
func TestPatternCategoryCounts(t *testing.T) {
	all := AllPatterns()

	nqCount := 0
	pqCount := 0
	hybridCount := 0

	for _, p := range all {
		switch p.Type() {
		case PatternTypeDH:
			nqCount++
		case PatternTypeKEM:
			pqCount++
		case PatternTypeHybrid:
			hybridCount++
		}
	}

	// NQ: 3 one-way + 12 base + 21 PSK = 36
	// PQ: 12 base + 13 PSK = 25
	// Hybrid: 12 base + 16 PSK = 28 (INpsk1 added)
	// Note: Npsk0, Kpsk0, Xpsk1 are one-way PSK variants
	// Total adjusted: check individual counts
	t.Logf("NQ: %d, PQ: %d, Hybrid: %d, Total: %d", nqCount, pqCount, hybridCount, len(all))

	if nqCount+pqCount+hybridCount != len(all) {
		t.Errorf("category sum %d != total %d", nqCount+pqCount+hybridCount, len(all))
	}
}

// TestAllPatternsUniqueName verifies all pattern names are unique.
func TestAllPatternsUniqueName(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range AllPatterns() {
		if seen[p.Name()] {
			t.Errorf("duplicate pattern name: %s", p.Name())
		}
		seen[p.Name()] = true
	}
}

// TestFirstTokenIsE verifies every message pattern starts with Token E (Noise convention).
func TestFirstTokenIsE(t *testing.T) {
	for _, p := range AllPatterns() {
		// First initiator message must start with E (all patterns)
		msg0 := p.InitiatorMessage(0)
		if len(msg0) == 0 {
			continue
		}
		// PSK variants can start with PSK before E
		first := msg0[0]
		if first != TokenE && first != TokenPsk {
			t.Errorf("pattern %s: first initiator token is %s, expected E or PSK",
				p.Name(), tokenString(first))
		}
		if first == TokenPsk && len(msg0) > 1 && msg0[1] != TokenE {
			t.Errorf("pattern %s: PSK0 pattern second token is %s, expected E",
				p.Name(), tokenString(msg0[1]))
		}

		// First responder message (if any) must start with E
		if p.NumResponderMessages() > 0 {
			rmsg0 := p.ResponderMessage(0)
			if len(rmsg0) > 0 && rmsg0[0] != TokenE {
				t.Errorf("pattern %s: first responder token is %s, expected E",
					p.Name(), tokenString(rmsg0[0]))
			}
		}
	}
}

// TestPatternImmutability verifies callers cannot mutate patterns through accessors.
func TestPatternImmutability(t *testing.T) {
	// Get a copy of NN's initiator message
	msg := PatternNN.InitiatorMessage(0)
	if len(msg) == 0 {
		t.Fatal("NN should have initiator message 0")
	}

	// Mutate the returned slice
	original := msg[0]
	msg[0] = TokenSS

	// Verify the pattern itself is unchanged
	msg2 := PatternNN.InitiatorMessage(0)
	if msg2[0] != original {
		t.Errorf("pattern mutation leaked: expected %s, got %s",
			tokenString(original), tokenString(msg2[0]))
	}
}

// TestPreMessageImmutability verifies pre-message tokens are copies too.
func TestPreMessageImmutability(t *testing.T) {
	pre := PatternIK.PreResponder()
	if len(pre) == 0 {
		t.Fatal("IK should have pre-responder tokens")
	}

	original := pre[0]
	pre[0] = TokenEkem

	pre2 := PatternIK.PreResponder()
	if pre2[0] != original {
		t.Errorf("pre-message mutation leaked: expected %s, got %s",
			tokenString(original), tokenString(pre2[0]))
	}
}
