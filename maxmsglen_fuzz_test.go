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

// FuzzMaxMessageLen verifies the maxMsgLen boundary is sharp for 3 patterns
// covering all message count shapes: NN (init=1/resp=1), XN (init=2/resp=1,
// hits toggle branch), pqXN (init=2/resp=2, PQ overhead).
//
// Invariant: for any maxMsgLen m in [1, 65535], either:
// (a) constructor succeeds AND handshake completes AND transport enforces m, OR
// (b) constructor fails with ErrInvalidPattern.
func FuzzMaxMessageLen(f *testing.F) {
	// 19 seed values covering all 3 pattern boundaries:
	// NN boundary at 48, XN boundary at 64, pqXN boundary at 1216
	f.Add(uint16(1))
	f.Add(uint16(16))
	f.Add(uint16(31))
	f.Add(uint16(32))
	f.Add(uint16(47))
	f.Add(uint16(48))
	f.Add(uint16(49))
	f.Add(uint16(63))
	f.Add(uint16(64))
	f.Add(uint16(65))
	f.Add(uint16(100))
	f.Add(uint16(200))
	f.Add(uint16(1000))
	f.Add(uint16(1215))
	f.Add(uint16(1216))
	f.Add(uint16(1217))
	f.Add(uint16(32767))
	f.Add(uint16(65534))
	f.Add(uint16(65535))

	x := dh.NewX25519()
	k := kem.NewMlKem768()

	f.Fuzz(func(t *testing.T, mRaw uint16) {
		m := int(mRaw)
		if m == 0 {
			return // 0 means default, tested separately in unit tests
		}

		// Pattern 1: NN (init=1, resp=1, NQ, no toggle)
		fuzzPattern(t, m, clatter.PatternNN, x, k)

		// Pattern 2: XN (init=2, resp=1, NQ, hits toggle branch)
		fuzzPattern(t, m, clatter.PatternXN, x, k)

		// Pattern 3: pqXN (init=2, resp=2, PQ overhead)
		fuzzPattern(t, m, clatter.PatternPqXN, x, k)
	})
}

// fuzzPattern tests a single pattern at the given maxMsgLen value.
// Verifies the binary invariant: construction either succeeds (handshake
// completes, transport enforces limit) or fails with ErrInvalidPattern.
// Also checks initiator/responder symmetry: if one side accepts a limit,
// the other must accept it too (same pattern, same overhead).
func fuzzPattern(t *testing.T, maxMsgLen int, p *clatter.HandshakePattern,
	x clatter.DH, k clatter.KEM) {
	t.Helper()

	var alice, bob clatter.Handshaker
	var err error

	switch p.Type() {
	case clatter.PatternTypeDH:
		s := clatter.CipherSuite{DH: x, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
		aliceS, _ := x.GenerateKeypair(crand.Reader)
		bobS, _ := x.GenerateKeypair(crand.Reader)
		var a *clatter.NqHandshake
		a, err = clatter.NewNqHandshake(p, true, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
		if err == nil {
			alice = a
			var b *clatter.NqHandshake
			b, err = clatter.NewNqHandshake(p, false, s,
				clatter.WithMaxMessageLen(maxMsgLen),
				clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
			if err != nil {
				a.Destroy()
				// If initiator succeeds but responder fails, that's a bug
				// (same pattern, same overhead, same limit)
				t.Fatalf("%s: initiator accepted maxMsgLen=%d but responder rejected: %v",
					p.Name(), maxMsgLen, err)
			}
			bob = b
		}
	case clatter.PatternTypeKEM:
		s := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
		aliceS, _ := k.GenerateKeypair(crand.Reader)
		bobS, _ := k.GenerateKeypair(crand.Reader)
		var a *clatter.PqHandshake
		a, err = clatter.NewPqHandshake(p, true, s,
			clatter.WithMaxMessageLen(maxMsgLen),
			clatter.WithStaticKey(aliceS), clatter.WithRemoteStatic(bobS.Public))
		if err == nil {
			alice = a
			var b *clatter.PqHandshake
			b, err = clatter.NewPqHandshake(p, false, s,
				clatter.WithMaxMessageLen(maxMsgLen),
				clatter.WithStaticKey(bobS), clatter.WithRemoteStatic(aliceS.Public))
			if err != nil {
				a.Destroy()
				t.Fatalf("%s: initiator accepted maxMsgLen=%d but responder rejected: %v",
					p.Name(), maxMsgLen, err)
			}
			bob = b
		}
	default:
		t.Fatalf("%s: unsupported pattern type %d in fuzz target", p.Name(), p.Type())
	}

	// Constructor rejected: verify it's ErrInvalidPattern
	if err != nil {
		if !errors.Is(err, clatter.ErrInvalidPattern) {
			t.Fatalf("%s: constructor rejected maxMsgLen=%d with unexpected error: %v",
				p.Name(), maxMsgLen, err)
		}
		return
	}

	// Constructor accepted: run full handshake
	defer alice.Destroy()
	defer bob.Destroy()

	// Push PSKs if needed
	if p.HasPSK() {
		for i := 0; i < 4; i++ {
			var psk [32]byte
			for j := range psk {
				psk[j] = byte(i)
			}
			_ = alice.PushPSK(psk[:])
			_ = bob.PushPSK(psk[:])
		}
	}

	buf := make([]byte, maxMsgLen)
	outBuf := make([]byte, maxMsgLen)

	for !alice.IsFinished() || !bob.IsFinished() {
		if alice.IsWriteTurn() && !bob.IsWriteTurn() {
			n, werr := alice.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("%s: alice write at maxMsgLen=%d: %v", p.Name(), maxMsgLen, werr)
			}
			_, rerr := bob.ReadMessage(buf[:n], outBuf)
			if rerr != nil {
				t.Fatalf("%s: bob read at maxMsgLen=%d: %v", p.Name(), maxMsgLen, rerr)
			}
		} else if !alice.IsWriteTurn() && bob.IsWriteTurn() {
			n, werr := bob.WriteMessage(nil, buf)
			if werr != nil {
				t.Fatalf("%s: bob write at maxMsgLen=%d: %v", p.Name(), maxMsgLen, werr)
			}
			_, rerr := alice.ReadMessage(buf[:n], outBuf)
			if rerr != nil {
				t.Fatalf("%s: alice read at maxMsgLen=%d: %v", p.Name(), maxMsgLen, rerr)
			}
		} else {
			t.Fatalf("%s: state issue at maxMsgLen=%d", p.Name(), maxMsgLen)
		}
	}

	tsA, ferr := alice.Finalize()
	if ferr != nil {
		t.Fatalf("%s: alice finalize: %v", p.Name(), ferr)
	}
	defer tsA.Destroy()

	tsB, ferr := bob.Finalize()
	if ferr != nil {
		t.Fatalf("%s: bob finalize: %v", p.Name(), ferr)
	}
	defer tsB.Destroy()

	// Transport boundary: verify enforcement
	if maxMsgLen > clatter.TagLen {
		maxPayload := maxMsgLen - clatter.TagLen
		payload := make([]byte, maxPayload)
		sendBuf := make([]byte, maxMsgLen)

		// At boundary: should succeed
		n, serr := tsA.Send(payload, sendBuf)
		if serr != nil {
			t.Fatalf("%s: send at boundary maxMsgLen=%d: %v", p.Name(), maxMsgLen, serr)
		}

		// Receive the boundary message
		recvBuf := make([]byte, maxMsgLen)
		_, rerr := tsB.Receive(sendBuf[:n], recvBuf)
		if rerr != nil {
			t.Fatalf("%s: receive at boundary maxMsgLen=%d: %v", p.Name(), maxMsgLen, rerr)
		}

		// One byte over: should fail
		overPayload := make([]byte, maxPayload+1)
		overBuf := make([]byte, maxMsgLen+1)
		_, serr = tsA.Send(overPayload, overBuf)
		if !errors.Is(serr, clatter.ErrMessageTooLarge) {
			t.Fatalf("%s: send over boundary maxMsgLen=%d: expected ErrMessageTooLarge, got %v",
				p.Name(), maxMsgLen, serr)
		}
	}
}
