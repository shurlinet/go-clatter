package clatter_test

import (
	crand "crypto/rand"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// Hardcoded crypto primitive sizes for independent overhead calculation.
// These MUST match the CipherSuite used in the test (ML-KEM-768, X25519).
// Verified once at test start via sanity assertions.
const (
	nqDHPubLen      = 32   // X25519 public key
	pqEKEMPubLen    = 1184 // ML-KEM-768 encapsulation key (Token E in PQ)
	pqSKEMPubLen    = 1184 // ML-KEM-768 encapsulation key (Token S in PQ)
	pqEKEMCtLen     = 1088 // ML-KEM-768 ciphertext (Token Ekem)
	pqSKEMCtLen     = 1088 // ML-KEM-768 ciphertext (Token Skem)
	hybridDHPubLen  = 32   // X25519 public key (Token E DH part in Hybrid)
	hybridEKEMPubLen = 1184 // ML-KEM-768 encapsulation key (Token E KEM part in Hybrid)
	hybridSKEMPubLen = 1184 // ML-KEM-768 encapsulation key (Token S KEM part in Hybrid)
	hybridEKEMCtLen = 1088 // ML-KEM-768 ciphertext (Token Ekem in Hybrid)
	hybridSKEMCtLen = 1088 // ML-KEM-768 ciphertext (Token Skem in Hybrid)
	propTagLen      = 16   // AEAD tag length (both ChaChaPoly and AES-GCM)
)

// Hardcoded regression expectations. These values are empirically verified
// and will never change (FIPS constants + immutable pattern definitions).
var regressionExpectations = map[string]int{
	"NN":        48,
	"XX":        96,
	"pqIK":      3488,
	"hybridXX":  3568,
	"hybridKX":  4672,
}

// computeOverheadArray computes per-message wire overhead independently of
// go-clatter's validatePatternMaxMsgLen. Uses the public API (InitiatorMessage,
// ResponderMessage, PreInitiator, PreResponder) and hardcoded size constants
// instead of the CipherSuite method calls the production validator uses.
//
// Returns one overhead value per message in interleaved order matching the
// validator's walk: init[0], resp[0], init[1], resp[1], ... with toggle
// logic for patterns with unequal initiator/responder message counts (e.g.,
// XN has init=2, resp=1 producing order [init0, resp0, init1]).
//
// HasKey simulation tracks which tokens establish an encryption key (DH
// operations, KEM operations, PSK) and adjusts Token S and Token Skem
// overhead accordingly (encrypted pubkeys/ciphertexts gain AEAD tags).
// Hybrid Token S adds two tags (one per pubkey: DH + KEM).
func computeOverheadArray(p *clatter.HandshakePattern) []int {
	pt := p.Type()
	var result []int

	initIdx, respIdx := 0, 0
	initTurn := true
	hasKey := false

	// Pre-message HasKey scan: no predefined pattern has pre-message E,
	// but implement for correctness with custom patterns.
	if p.HasPSK() {
		for _, t := range p.PreInitiator() {
			if t == clatter.TokenE {
				hasKey = true
				break
			}
		}
		if !hasKey {
			for _, t := range p.PreResponder() {
				if t == clatter.TokenE {
					hasKey = true
					break
				}
			}
		}
	}

	for initIdx < p.NumInitiatorMessages() || respIdx < p.NumResponderMessages() {
		var tokens []clatter.Token

		if initTurn && initIdx < p.NumInitiatorMessages() {
			tokens = p.InitiatorMessage(initIdx)
			initIdx++
		} else if !initTurn && respIdx < p.NumResponderMessages() {
			tokens = p.ResponderMessage(respIdx)
			respIdx++
		} else {
			// Toggle for unequal message counts
			initTurn = !initTurn
			continue
		}

		overhead := 0
		simKey := hasKey

		for _, tok := range tokens {
			switch tok {
			case clatter.TokenE:
				switch pt {
				case clatter.PatternTypeDH:
					overhead += nqDHPubLen
				case clatter.PatternTypeKEM:
					overhead += pqEKEMPubLen
				case clatter.PatternTypeHybrid:
					overhead += hybridDHPubLen + hybridEKEMPubLen
				}
				if p.HasPSK() {
					simKey = true
				}
			case clatter.TokenS:
				switch pt {
				case clatter.PatternTypeDH:
					overhead += nqDHPubLen
					if simKey {
						overhead += propTagLen
					}
				case clatter.PatternTypeKEM:
					overhead += pqSKEMPubLen
					if simKey {
						overhead += propTagLen
					}
				case clatter.PatternTypeHybrid:
					overhead += hybridDHPubLen + hybridSKEMPubLen
					if simKey {
						overhead += propTagLen * 2 // one tag per pubkey
					}
				}
			case clatter.TokenEE, clatter.TokenES, clatter.TokenSE, clatter.TokenSS:
				simKey = true
			case clatter.TokenEkem:
				switch pt {
				case clatter.PatternTypeKEM:
					overhead += pqEKEMCtLen
				case clatter.PatternTypeHybrid:
					overhead += hybridEKEMCtLen
				}
				simKey = true
			case clatter.TokenSkem:
				switch pt {
				case clatter.PatternTypeKEM:
					overhead += pqSKEMCtLen
					if simKey {
						overhead += propTagLen
					}
				case clatter.PatternTypeHybrid:
					overhead += hybridSKEMCtLen
					if simKey {
						overhead += propTagLen
					}
				}
				simKey = true // set AFTER computing Skem cost
			case clatter.TokenPsk:
				simKey = true
			}
		}

		// Payload tag when key is established
		if simKey {
			overhead += propTagLen
		}

		result = append(result, overhead)
		hasKey = simKey
		initTurn = !initTurn
	}

	return result
}

// maxOf returns the largest value in arr, or 0 if arr is empty.
func maxOf(arr []int) int {
	m := 0
	for _, v := range arr {
		if v > m {
			m = v
		}
	}
	return m
}

// TestPropertyMaxMsgLen verifies the maxMsgLen constructor validator matches
// actual runtime behavior for all 90 predefined patterns (NQ, PQ, Hybrid).
//
// For each pattern, the test:
//  1. Computes per-message overhead independently using hardcoded size constants
//  2. Validates the computed max overhead is within Noise spec bounds
//  3. Constructs a handshake pair at the exact max overhead limit
//  4. Runs a full handshake, cross-checking each message against the independent
//     calculation via both GetNextMessageOverhead and actual WriteMessage byte count
//  5. Verifies the transport inherits the correct limit
//  6. Verifies constructor rejection at max overhead minus one (both sides)
//  7. Verifies transport Send/Receive boundary enforcement
//
// Three independent oracles verify each pattern:
//   - GetNextMessageOverhead (runtime prediction) == independent calculation
//   - WriteMessage return value (actual wire bytes) == independent calculation
//   - Constructor accepts maxOverhead, rejects maxOverhead-1
func TestPropertyMaxMsgLen(t *testing.T) {
	x := dh.NewX25519()
	k := kem.NewMlKem768()

	// Sanity: verify hardcoded constants match actual primitive sizes
	if x.PubKeyLen() != nqDHPubLen {
		t.Fatalf("DH PubKeyLen mismatch: got %d, hardcoded %d", x.PubKeyLen(), nqDHPubLen)
	}
	if k.PubKeyLen() != pqEKEMPubLen {
		t.Fatalf("KEM PubKeyLen mismatch: got %d, hardcoded %d", k.PubKeyLen(), pqEKEMPubLen)
	}
	if k.CiphertextLen() != pqEKEMCtLen {
		t.Fatalf("KEM CiphertextLen mismatch: got %d, hardcoded %d", k.CiphertextLen(), pqEKEMCtLen)
	}

	for _, p := range clatter.AllPatterns() {
		p := p // capture for subtest
		t.Run(p.Name(), func(t *testing.T) {
			// Step 1: Compute per-message overhead array independently
			ohArray := computeOverheadArray(p)
			maxOH := maxOf(ohArray)

			// Step 2: Sanity checks
			if maxOH == 0 {
				t.Fatal("pattern has zero max overhead, impossible")
			}
			if maxOH > clatter.MaxMessageLen {
				t.Fatalf("max overhead %d exceeds Noise spec ceiling %d", maxOH, clatter.MaxMessageLen)
			}
			if len(ohArray) == 0 {
				t.Fatal("pattern has zero messages")
			}

			// Regression expectations
			if expected, ok := regressionExpectations[p.Name()]; ok {
				if maxOH != expected {
					t.Fatalf("regression: %s maxOH=%d, expected %d", p.Name(), maxOH, expected)
				}
			}

			// Step 3: Construct alice+bob at exact maxOverhead
			alice, bob := constructPair(t, p, maxOH, x, k)
			defer alice.Destroy()
			defer bob.Destroy()

			// Push PSKs if needed (push 4 unconditionally for PSK patterns)
			if p.HasPSK() {
				pushPropertyPSKs(t, alice)
				pushPropertyPSKs(t, bob)
			}

			// Steps 4+5: Handshake loop with per-message cross-checks
			buf := make([]byte, maxOH)
			outBuf := make([]byte, maxOH)
			msgIdx := 0

			for !alice.IsFinished() || !bob.IsFinished() {
				var writer, reader clatter.Handshaker
				if alice.IsWriteTurn() && !bob.IsWriteTurn() {
					writer = alice
					reader = bob
				} else if !alice.IsWriteTurn() && bob.IsWriteTurn() {
					writer = bob
					reader = alice
				} else {
					t.Fatalf("handshake state issue at msgIdx=%d", msgIdx)
				}

				if msgIdx >= len(ohArray) {
					t.Fatalf("msgIdx %d exceeds overhead array length %d", msgIdx, len(ohArray))
				}

				// Cross-check: runtime overhead == independent calculation
				runtimeOH, err := writer.GetNextMessageOverhead()
				if err != nil {
					t.Fatalf("msg %d GetNextMessageOverhead: %v", msgIdx, err)
				}
				if runtimeOH != ohArray[msgIdx] {
					t.Fatalf("msg %d overhead divergence: runtime=%d, independent=%d",
						msgIdx, runtimeOH, ohArray[msgIdx])
				}

				// Write and verify actual bytes written == prediction
				n, err := writer.WriteMessage(nil, buf)
				if err != nil {
					t.Fatalf("msg %d WriteMessage: %v", msgIdx, err)
				}
				if n != ohArray[msgIdx] {
					t.Fatalf("msg %d actual bytes %d != predicted %d", msgIdx, n, ohArray[msgIdx])
				}

				// Reader processes the message
				_, err = reader.ReadMessage(buf[:n], outBuf)
				if err != nil {
					t.Fatalf("msg %d ReadMessage: %v", msgIdx, err)
				}

				msgIdx++
			}

			// Step 5 continued: verify message count matches
			if msgIdx != len(ohArray) {
				t.Fatalf("message count mismatch: processed %d, expected %d", msgIdx, len(ohArray))
			}

			// Step 6: Finalize and verify transport limit
			tsA, err := alice.Finalize()
			if err != nil {
				t.Fatalf("alice Finalize: %v", err)
			}
			defer tsA.Destroy()

			tsB, err := bob.Finalize()
			if err != nil {
				t.Fatalf("bob Finalize: %v", err)
			}
			defer tsB.Destroy()

			if tsA.MaxMessageLen() != maxOH {
				t.Fatalf("alice transport maxMsgLen=%d, want %d", tsA.MaxMessageLen(), maxOH)
			}
			if tsB.MaxMessageLen() != maxOH {
				t.Fatalf("bob transport maxMsgLen=%d, want %d", tsB.MaxMessageLen(), maxOH)
			}

			// Step 7: Constructor rejects at maxOverhead-1 (test both sides)
			switch p.Type() {
			case clatter.PatternTypeDH:
				s := clatter.CipherSuite{DH: x, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
				aliceS, _ := x.GenerateKeypair(crand.Reader)
				bobS, _ := x.GenerateKeypair(crand.Reader)
				_, err = clatter.NewNqHandshake(p, true, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("initiator at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
				_, err = clatter.NewNqHandshake(p, false, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("responder at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
			case clatter.PatternTypeKEM:
				s := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
				aliceS, _ := k.GenerateKeypair(crand.Reader)
				bobS, _ := k.GenerateKeypair(crand.Reader)
				_, err = clatter.NewPqHandshake(p, true, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("initiator at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
				_, err = clatter.NewPqHandshake(p, false, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("responder at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
			case clatter.PatternTypeHybrid:
				s := clatter.CipherSuite{DH: x, EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
				aliceDH, _ := x.GenerateKeypair(crand.Reader)
				bobDH, _ := x.GenerateKeypair(crand.Reader)
				aliceKEM, _ := k.GenerateKeypair(crand.Reader)
				bobKEM, _ := k.GenerateKeypair(crand.Reader)
				_, err = clatter.NewHybridHandshake(p, true, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(aliceDH), clatter.WithRemoteStatic(bobDH.Public),
					clatter.WithStaticKEMKey(aliceKEM), clatter.WithRemoteStaticKEMKey(bobKEM.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("initiator at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
				_, err = clatter.NewHybridHandshake(p, false, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(bobDH), clatter.WithRemoteStatic(aliceDH.Public),
					clatter.WithStaticKEMKey(bobKEM), clatter.WithRemoteStaticKEMKey(aliceKEM.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("responder at maxOH-1=%d: expected ErrInvalidPattern, got %v", maxOH-1, err)
				}
			}

			// Step 8: Transport Send/Receive boundary
			// For both one-way and interactive: initiator (tsA) sends, responder (tsB) receives.
			// One-way responder cannot send (ErrOneWayViolation), but the boundary
			// test only needs the initiator Send path which works for both.
			if maxOH < clatter.TagLen+1 {
				return // no room for any payload
			}

			maxPayload := maxOH - clatter.TagLen
			payload := make([]byte, maxPayload)
			sendBuf := make([]byte, maxOH)

			// At boundary: should succeed
			n, err := tsA.Send(payload, sendBuf)
			if err != nil {
				t.Fatalf("send at boundary failed: %v", err)
			}

			// Responder receives the boundary message
			recvBuf := make([]byte, maxOH)
			_, err = tsB.Receive(sendBuf[:n], recvBuf)
			if err != nil {
				t.Fatalf("receive at boundary failed: %v", err)
			}

			// One byte over: should fail
			overPayload := make([]byte, maxPayload+1)
			overBuf := make([]byte, maxOH+1)
			_, err = tsA.Send(overPayload, overBuf)
			if !errors.Is(err, clatter.ErrMessageTooLarge) {
				t.Fatalf("send over boundary: expected ErrMessageTooLarge, got %v", err)
			}
		})
	}
}

// constructPair creates alice (initiator) and bob (responder) handshakes
// with over-provisioned keys for the given pattern and maxMsgLen. Keys are
// generated for all roles regardless of whether the pattern requires them
// (unused keys are silently ignored by constructors).
func constructPair(t *testing.T, p *clatter.HandshakePattern, maxMsgLen int,
	x clatter.DH, k clatter.KEM) (clatter.Handshaker, clatter.Handshaker) {
	t.Helper()

	switch p.Type() {
	case clatter.PatternTypeDH:
		s := clatter.CipherSuite{DH: x, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
		aliceS, _ := x.GenerateKeypair(crand.Reader)
		bobS, _ := x.GenerateKeypair(crand.Reader)
		alice, err := clatter.NewNqHandshake(p, true, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
		if err != nil {
			t.Fatalf("NQ initiator construct: %v", err)
		}
		bob, err := clatter.NewNqHandshake(p, false, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
		if err != nil {
			t.Fatalf("NQ responder construct: %v", err)
		}
		return alice, bob

	case clatter.PatternTypeKEM:
		s := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
		aliceS, _ := k.GenerateKeypair(crand.Reader)
		bobS, _ := k.GenerateKeypair(crand.Reader)
		alice, err := clatter.NewPqHandshake(p, true, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
		if err != nil {
			t.Fatalf("PQ initiator construct: %v", err)
		}
		bob, err := clatter.NewPqHandshake(p, false, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
		if err != nil {
			t.Fatalf("PQ responder construct: %v", err)
		}
		return alice, bob

	case clatter.PatternTypeHybrid:
		s := clatter.CipherSuite{DH: x, EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
		aliceDH, _ := x.GenerateKeypair(crand.Reader)
		bobDH, _ := x.GenerateKeypair(crand.Reader)
		aliceKEM, _ := k.GenerateKeypair(crand.Reader)
		bobKEM, _ := k.GenerateKeypair(crand.Reader)
		alice, err := clatter.NewHybridHandshake(p, true, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(aliceDH), clatter.WithRemoteStatic(bobDH.Public),
			clatter.WithStaticKEMKey(aliceKEM), clatter.WithRemoteStaticKEMKey(bobKEM.Public))
		if err != nil {
			t.Fatalf("Hybrid initiator construct: %v", err)
		}
		bob, err := clatter.NewHybridHandshake(p, false, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(bobDH), clatter.WithRemoteStatic(aliceDH.Public),
			clatter.WithStaticKEMKey(bobKEM), clatter.WithRemoteStaticKEMKey(aliceKEM.Public))
		if err != nil {
			t.Fatalf("Hybrid responder construct: %v", err)
		}
		return alice, bob

	default:
		t.Fatalf("unknown pattern type %d", p.Type())
		return nil, nil
	}
}

// pushPropertyPSKs pushes 4 PSKs matching smoke test convention.
func pushPropertyPSKs(t *testing.T, hs clatter.Handshaker) {
	t.Helper()
	for i := 0; i < 4; i++ {
		var psk [32]byte
		for j := range psk {
			psk[j] = byte(i)
		}
		if err := hs.PushPSK(psk[:]); err != nil {
			t.Fatalf("PushPSK %d: %v", i, err)
		}
	}
}
