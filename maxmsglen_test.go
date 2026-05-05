package clatter_test

import (
	"errors"
	"fmt"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func mmlNqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func mmlPqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func mmlHybridSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// TestDefaultMaxMessageLen verifies default (0 or unset) = 65535.
func TestDefaultMaxMessageLen(t *testing.T) {
	pattern := clatter.PatternNN
	alice, err := clatter.NewNqHandshake(pattern, true, mmlNqSuite())
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewNqHandshake(pattern, false, mmlNqSuite())
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bob.ReadMessage(buf[:n], buf)
	if err != nil {
		t.Fatal(err)
	}
	n, err = bob.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	_, err = alice.ReadMessage(buf[:n], buf)
	if err != nil {
		t.Fatal(err)
	}

	tsA, err := alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	tsB, err := bob.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	if tsA.MaxMessageLen() != clatter.MaxMessageLen {
		t.Fatalf("alice transport maxMsgLen = %d, want %d", tsA.MaxMessageLen(), clatter.MaxMessageLen)
	}
	if tsB.MaxMessageLen() != clatter.MaxMessageLen {
		t.Fatalf("bob transport maxMsgLen = %d, want %d", tsB.MaxMessageLen(), clatter.MaxMessageLen)
	}
}

// TestExplicit65535 verifies WithMaxMessageLen(65535) = same as default.
func TestExplicit65535(t *testing.T) {
	pattern := clatter.PatternNN
	alice, err := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(65535))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Destroy()

	bob, err := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(65535))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Destroy()

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	ts, err := alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if ts.MaxMessageLen() != 65535 {
		t.Fatalf("transport maxMsgLen = %d, want 65535", ts.MaxMessageLen())
	}
}

// TestCustomLimitEnforced verifies custom limit on transport Send.
func TestCustomLimitEnforced(t *testing.T) {
	limit := 200
	pattern := clatter.PatternNN
	alice, err := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()
	tsB, _ := bob.Finalize()

	if tsA.MaxMessageLen() != limit {
		t.Fatalf("transport maxMsgLen = %d, want %d", tsA.MaxMessageLen(), limit)
	}

	// Payload that fits: limit - TagLen = 184 bytes
	smallPayload := make([]byte, limit-clatter.TagLen)
	out := make([]byte, clatter.MaxMessageLen)
	_, err = tsA.Send(smallPayload, out)
	if err != nil {
		t.Fatalf("send within limit failed: %v", err)
	}

	// Payload one byte over: should fail
	bigPayload := make([]byte, limit-clatter.TagLen+1)
	_, err = tsA.Send(bigPayload, out)
	if !errors.Is(err, clatter.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}

	// Receive: message at limit passes
	ct := make([]byte, limit)
	n, _ = tsB.Send(smallPayload, ct)
	_, err = tsA.Receive(ct[:n], out)
	if err != nil {
		t.Fatalf("receive within limit failed: %v", err)
	}
}

// TestCustomLimitOnHandshakeWrite verifies limit during handshake.
func TestCustomLimitOnHandshakeWrite(t *testing.T) {
	// NN pattern: msg0 overhead = 32 (E pubkey), msg1 overhead = 32 (E) + 16 (tag) = 48.
	// Limit of 48 fits all messages exactly. Empty payload succeeds.
	limit := 48
	pattern := clatter.PatternNN
	alice, err := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)

	// Empty payload: msg0 is 32 bytes, fits in 48
	_, err = alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatalf("write with empty payload should succeed: %v", err)
	}
}

// TestTooSmallForPattern verifies the constructor rejects maxMsgLen values
// that are too small for the pattern's message overhead.
func TestTooSmallForPattern(t *testing.T) {
	// NN msg1 overhead: 32 (ephemeral DH pubkey). Limit of 20 is too small.
	_, err := clatter.NewNqHandshake(clatter.PatternNN, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(20))
	if err == nil {
		t.Fatal("expected constructor to reject maxMsgLen too small for pattern")
	}
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("expected ErrInvalidPattern, got %v", err)
	}

	// PQ patterns have much larger overhead - even 500 bytes is too small
	_, err = clatter.NewPqHandshake(clatter.PatternPqNN, true, mmlPqSuite(),
		clatter.WithMaxMessageLen(500))
	if err == nil {
		t.Fatal("expected PQ constructor to reject maxMsgLen too small for pattern")
	}

	// Hybrid patterns are even larger
	_, err = clatter.NewHybridHandshake(clatter.PatternHybridNN, true, mmlHybridSuite(),
		clatter.WithMaxMessageLen(500))
	if err == nil {
		t.Fatal("expected Hybrid constructor to reject maxMsgLen too small for pattern")
	}
}

// TestNegativeMaxMsgLen verifies negative values are rejected.
func TestNegativeMaxMsgLen(t *testing.T) {
	_, err := clatter.NewNqHandshake(clatter.PatternNN, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(-1))
	if err == nil {
		t.Fatal("expected error for negative maxMsgLen")
	}
}

// TestExceedsSpecMax verifies values > 65535 are rejected.
func TestExceedsSpecMax(t *testing.T) {
	_, err := clatter.NewNqHandshake(clatter.PatternNN, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(65536))
	if err == nil {
		t.Fatal("expected error for maxMsgLen > 65535")
	}
}

// TestCustomLimitOnReceive verifies receive rejects oversized messages.
func TestCustomLimitOnReceive(t *testing.T) {
	limit := 200
	pattern := clatter.PatternNN

	// Create a pair with custom limit
	alice, _ := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	bob, _ := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()

	// Fabricate an oversized message (limit+1 bytes)
	fakeMsg := make([]byte, limit+1)
	_, err := tsA.Receive(fakeMsg, buf)
	if !errors.Is(err, clatter.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge for oversized receive, got %v", err)
	}
}

// TestBoundaryExact verifies exact-size messages pass (len == limit).
func TestBoundaryExact(t *testing.T) {
	limit := 200
	pattern := clatter.PatternNN
	alice, _ := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	bob, _ := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()
	tsB, _ := bob.Finalize()

	// Exactly limit bytes: payload = limit - TagLen
	payload := make([]byte, limit-clatter.TagLen)
	out := make([]byte, limit)
	n, err := tsA.Send(payload, out)
	if err != nil {
		t.Fatalf("exact-size send failed: %v", err)
	}
	if n != limit {
		t.Fatalf("send returned %d bytes, want %d", n, limit)
	}

	// Receive the exact-size message
	recvBuf := make([]byte, limit)
	_, err = tsB.Receive(out[:n], recvBuf)
	if err != nil {
		t.Fatalf("exact-size receive failed: %v", err)
	}
}

// TestOneByteOver verifies limit+1 fails.
func TestOneByteOver(t *testing.T) {
	limit := 200
	pattern := clatter.PatternNN
	alice, _ := clatter.NewNqHandshake(pattern, true, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	bob, _ := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()

	// One byte over: payload = limit - TagLen + 1
	payload := make([]byte, limit-clatter.TagLen+1)
	out := make([]byte, clatter.MaxMessageLen)
	_, err := tsA.Send(payload, out)
	if !errors.Is(err, clatter.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge, got %v", err)
	}
}

// TestPQCustomLimit verifies PQ handshake respects custom limit.
func TestPQCustomLimit(t *testing.T) {
	pattern := clatter.PatternPqNN
	// PQ NN overhead is much larger (KEM pubkeys + ciphertexts)
	// Use a generous limit that fits
	limit := 10000
	alice, err := clatter.NewPqHandshake(pattern, true, mmlPqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewPqHandshake(pattern, false, mmlPqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()
	if tsA.MaxMessageLen() != limit {
		t.Fatalf("PQ transport maxMsgLen = %d, want %d", tsA.MaxMessageLen(), limit)
	}
}

// TestHybridCustomLimit verifies Hybrid handshake respects custom limit.
func TestHybridCustomLimit(t *testing.T) {
	pattern := clatter.PatternHybridNN
	limit := 10000
	alice, err := clatter.NewHybridHandshake(pattern, true, mmlHybridSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewHybridHandshake(pattern, false, mmlHybridSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	tsA, _ := alice.Finalize()
	if tsA.MaxMessageLen() != limit {
		t.Fatalf("Hybrid transport maxMsgLen = %d, want %d", tsA.MaxMessageLen(), limit)
	}
}

// TestDualLayerCustomLimit verifies DualLayer respects its own maxMsgLen
// and propagates it to the returned TransportState.
func TestDualLayerCustomLimit(t *testing.T) {
	suite := mmlNqSuite()
	limit := 500
	// Inner maxMsgLen must be <= limit - TagLen (484) so DualLayer validation passes.
	innerLimit := limit - clatter.TagLen

	outerA, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	outerB, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	innerA, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite,
		clatter.WithMaxMessageLen(innerLimit))
	innerB, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite,
		clatter.WithMaxMessageLen(innerLimit))

	dlA, err := clatter.NewDualLayerHandshake(outerA, innerA, clatter.MaxMessageLen,
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}
	dlB, err := clatter.NewDualLayerHandshake(outerB, innerB, clatter.MaxMessageLen,
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, clatter.MaxMessageLen)
	out := make([]byte, clatter.MaxMessageLen)

	// Run full handshake
	for !dlA.IsFinished() || !dlB.IsFinished() {
		if dlA.IsWriteTurn() {
			n, err := dlA.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			_, err = dlB.ReadMessage(buf[:n], out)
			if err != nil {
				t.Fatal(err)
			}
		}
		if dlB.IsWriteTurn() {
			n, err := dlB.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			_, err = dlA.ReadMessage(buf[:n], out)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	tsA, err := dlA.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if tsA.MaxMessageLen() != limit {
		t.Fatalf("DualLayer transport maxMsgLen = %d, want %d", tsA.MaxMessageLen(), limit)
	}
}

// TestTransportMaxMessageLenDestroyedNil verifies getter returns 0 for destroyed/nil.
func TestTransportMaxMessageLenDestroyedNil(t *testing.T) {
	pattern := clatter.PatternNN
	alice, _ := clatter.NewNqHandshake(pattern, true, mmlNqSuite())
	bob, _ := clatter.NewNqHandshake(pattern, false, mmlNqSuite())

	buf := make([]byte, clatter.MaxMessageLen)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	ts, _ := alice.Finalize()
	ts.Destroy()
	if ts.MaxMessageLen() != 0 {
		t.Fatalf("destroyed transport maxMsgLen = %d, want 0", ts.MaxMessageLen())
	}

	// Nil receiver
	var nilTS *clatter.TransportState
	if nilTS.MaxMessageLen() != 0 {
		t.Fatalf("nil transport maxMsgLen = %d, want 0", nilTS.MaxMessageLen())
	}
}

// TestReadMessageRejectsOversized verifies handshake ReadMessage rejects
// messages exceeding the custom limit.
func TestReadMessageRejectsOversized(t *testing.T) {
	limit := 100
	pattern := clatter.PatternNN
	bob, err := clatter.NewNqHandshake(pattern, false, mmlNqSuite(),
		clatter.WithMaxMessageLen(limit))
	if err != nil {
		t.Fatal(err)
	}

	// Fabricate oversized message
	fakeMsg := make([]byte, limit+1)
	out := make([]byte, clatter.MaxMessageLen)
	_, err = bob.ReadMessage(fakeMsg, out)
	if !errors.Is(err, clatter.ErrMessageTooLarge) {
		t.Fatalf("expected ErrMessageTooLarge for oversized read, got %v", err)
	}
}

// ExampleWithMaxMessageLen demonstrates configuring a per-session message
// length limit for constrained environments.
func ExampleWithMaxMessageLen() {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	// Limit all messages (handshake and transport) to 200 bytes.
	// The constructor validates that NN pattern overhead fits within 200.
	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite,
		clatter.WithMaxMessageLen(200))
	if err != nil {
		fmt.Println("construction failed:", err)
		return
	}
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite,
		clatter.WithMaxMessageLen(200))
	if err != nil {
		fmt.Println("construction failed:", err)
		return
	}

	// Complete the handshake
	buf := make([]byte, 200)
	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], buf)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], buf)

	ts, _ := alice.Finalize()
	bob.Finalize()

	// TransportState inherits the limit
	fmt.Println("transport limit:", ts.MaxMessageLen())

	// Sending within limit succeeds
	payload := make([]byte, 200-clatter.TagLen) // max payload = limit - 16
	_, err = ts.Send(payload, buf)
	fmt.Println("send at limit:", err)

	// Sending over limit fails
	oversized := make([]byte, 200-clatter.TagLen+1)
	_, err = ts.Send(oversized, buf)
	fmt.Println("send over limit:", errors.Is(err, clatter.ErrMessageTooLarge))

	// Output:
	// transport limit: 200
	// send at limit: <nil>
	// send over limit: true
}
