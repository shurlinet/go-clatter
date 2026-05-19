//go:build hqc

// Property test: overhead calculation for all 90 patterns with HQC-128.
// Catches arithmetic bugs in validatePatternMaxMsgLen with HQC's much larger
// PK/CT sizes compared to ML-KEM.

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
	"github.com/shurlinet/go-hqc"
)

// Hardcoded HQC-128 sizes for independent overhead calculation.
const (
	hqcEKEMPubLen    = hqc.PublicKeySize128    // 2241
	hqcSKEMPubLen    = hqc.PublicKeySize128    // 2241
	hqcEKEMCtLen     = hqc.CiphertextSize128   // 4433
	hqcSKEMCtLen     = hqc.CiphertextSize128   // 4433
	hqcHybDHPubLen   = 32                       // X25519 public key
	hqcHybEKEMPubLen = hqc.PublicKeySize128    // 2241
	hqcHybSKEMPubLen = hqc.PublicKeySize128    // 2241
	hqcHybEKEMCtLen  = hqc.CiphertextSize128   // 4433
	hqcHybSKEMCtLen  = hqc.CiphertextSize128   // 4433
	hqcTagLen        = 16
)

// computeHqcOverheadArray is the independent overhead calculator for HQC-128.
// Same structure as computeOverheadArray but with HQC-128 sizes.
func computeHqcOverheadArray(p *clatter.HandshakePattern) []int {
	pt := p.Type()
	var result []int

	initIdx, respIdx := 0, 0
	initTurn := true
	hasKey := false

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
					overhead += hqcEKEMPubLen
				case clatter.PatternTypeHybrid:
					overhead += hqcHybDHPubLen + hqcHybEKEMPubLen
				}
				if p.HasPSK() {
					simKey = true
				}
			case clatter.TokenS:
				switch pt {
				case clatter.PatternTypeDH:
					overhead += nqDHPubLen
					if simKey {
						overhead += hqcTagLen
					}
				case clatter.PatternTypeKEM:
					overhead += hqcSKEMPubLen
					if simKey {
						overhead += hqcTagLen
					}
				case clatter.PatternTypeHybrid:
					overhead += hqcHybDHPubLen + hqcHybSKEMPubLen
					if simKey {
						overhead += hqcTagLen * 2
					}
				}
			case clatter.TokenEE, clatter.TokenES, clatter.TokenSE, clatter.TokenSS:
				simKey = true
			case clatter.TokenEkem:
				switch pt {
				case clatter.PatternTypeKEM:
					overhead += hqcEKEMCtLen
				case clatter.PatternTypeHybrid:
					overhead += hqcHybEKEMCtLen
				}
				simKey = true
			case clatter.TokenSkem:
				switch pt {
				case clatter.PatternTypeKEM:
					overhead += hqcSKEMCtLen
					if simKey {
						overhead += hqcTagLen
					}
				case clatter.PatternTypeHybrid:
					overhead += hqcHybSKEMCtLen
					if simKey {
						overhead += hqcTagLen
					}
				}
				simKey = true
			case clatter.TokenPsk:
				simKey = true
			}
		}

		if simKey {
			overhead += hqcTagLen
		}

		result = append(result, overhead)
		hasKey = simKey
		initTurn = !initTurn
	}

	return result
}

// TestPropertyMaxMsgLenHqc runs the same property test as TestPropertyMaxMsgLen
// but with HQC-128 instead of ML-KEM-768. Covers all 90 predefined patterns.
func TestPropertyMaxMsgLenHqc(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)

	x := dh.NewX25519()
	k := kem.NewHqc128()

	// Sanity: verify hardcoded constants match actual primitive sizes
	if k.PubKeyLen() != hqcEKEMPubLen {
		t.Fatalf("HQC PubKeyLen mismatch: got %d, hardcoded %d", k.PubKeyLen(), hqcEKEMPubLen)
	}
	if k.CiphertextLen() != hqcEKEMCtLen {
		t.Fatalf("HQC CiphertextLen mismatch: got %d, hardcoded %d", k.CiphertextLen(), hqcEKEMCtLen)
	}

	for _, p := range clatter.AllPatterns() {
		p := p
		t.Run(p.Name(), func(t *testing.T) {
			ohArray := computeHqcOverheadArray(p)
			maxOH := maxOf(ohArray)

			if maxOH == 0 {
				t.Fatal("pattern has zero max overhead")
			}
			if maxOH > clatter.MaxMessageLen {
				t.Fatalf("max overhead %d exceeds Noise spec ceiling %d", maxOH, clatter.MaxMessageLen)
			}

			// NQ patterns don't use KEM at all. DH tests use the existing
			// ML-KEM property test. Skip NQ to avoid redoing X25519-only tests.
			if p.Type() == clatter.PatternTypeDH {
				// But still verify the independent calculation didn't break
				// (NQ overhead is DH-only, same regardless of KEM chosen)
				if maxOH != maxOf(computeOverheadArray(p)) {
					t.Fatal("NQ overhead diverges from ML-KEM calculator")
				}
				return
			}

			// Construct handshake pair at exact maxOverhead
			alice, bob := constructHqcPair(t, p, maxOH, x, k)
			defer alice.Destroy()
			defer bob.Destroy()

			if p.HasPSK() {
				pushPropertyPSKs(t, alice)
				pushPropertyPSKs(t, bob)
			}

			// Handshake with per-message cross-checks
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

				runtimeOH, err := writer.GetNextMessageOverhead()
				if err != nil {
					t.Fatalf("msg %d GetNextMessageOverhead: %v", msgIdx, err)
				}
				if runtimeOH != ohArray[msgIdx] {
					t.Fatalf("msg %d overhead divergence: runtime=%d, independent=%d",
						msgIdx, runtimeOH, ohArray[msgIdx])
				}

				n, err := writer.WriteMessage(nil, buf)
				if err != nil {
					t.Fatalf("msg %d WriteMessage: %v", msgIdx, err)
				}
				if n != ohArray[msgIdx] {
					t.Fatalf("msg %d actual bytes %d != predicted %d", msgIdx, n, ohArray[msgIdx])
				}

				_, err = reader.ReadMessage(buf[:n], outBuf)
				if err != nil {
					t.Fatalf("msg %d ReadMessage: %v", msgIdx, err)
				}

				msgIdx++
			}

			if msgIdx != len(ohArray) {
				t.Fatalf("message count mismatch: processed %d, expected %d", msgIdx, len(ohArray))
			}

			// Constructor rejection at maxOH-1
			switch p.Type() {
			case clatter.PatternTypeKEM:
				s := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(), Experimental: true}
				aliceS, _ := k.GenerateKeypair(crand.Reader)
				bobS, _ := k.GenerateKeypair(crand.Reader)
				_, err := clatter.NewPqHandshake(p, true, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("PQ initiator at maxOH-1: expected ErrInvalidPattern, got %v", err)
				}
			case clatter.PatternTypeHybrid:
				s := clatter.CipherSuite{DH: x, EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(), Experimental: true}
				aliceDH, _ := x.GenerateKeypair(crand.Reader)
				bobDH, _ := x.GenerateKeypair(crand.Reader)
				aliceKEM, _ := k.GenerateKeypair(crand.Reader)
				bobKEM, _ := k.GenerateKeypair(crand.Reader)
				_, err := clatter.NewHybridHandshake(p, true, s,
					clatter.WithMaxMessageLen(maxOH-1),
					clatter.WithStaticKey(aliceDH), clatter.WithRemoteStatic(bobDH.Public),
					clatter.WithStaticKEMKey(aliceKEM), clatter.WithRemoteStaticKEMKey(bobKEM.Public))
				if !errors.Is(err, clatter.ErrInvalidPattern) {
					t.Fatalf("Hybrid initiator at maxOH-1: expected ErrInvalidPattern, got %v", err)
				}
			}
		})
	}
}

// constructHqcPair creates alice+bob handshakes with HQC-128 KEM.
func constructHqcPair(t *testing.T, p *clatter.HandshakePattern, maxMsgLen int,
	x clatter.DH, k clatter.KEM) (clatter.Handshaker, clatter.Handshaker) {
	t.Helper()

	switch p.Type() {
	case clatter.PatternTypeDH:
		t.Fatal("constructHqcPair called for NQ pattern")
		return nil, nil

	case clatter.PatternTypeKEM:
		s := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(), Experimental: true}
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
		s := clatter.CipherSuite{DH: x, EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(), Experimental: true}
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
