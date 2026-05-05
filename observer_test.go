package clatter_test

import (
	crand "crypto/rand"
	"sync"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// recordingObserver captures all events for test assertions.
type recordingObserver struct {
	mu     sync.Mutex
	events []clatter.HandshakeEvent
	errors []clatter.HandshakeErrorEvent
}

func (r *recordingObserver) OnMessage(e clatter.HandshakeEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recordingObserver) OnError(e clatter.HandshakeErrorEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, e)
}

func (r *recordingObserver) getEvents() []clatter.HandshakeEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]clatter.HandshakeEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recordingObserver) getErrors() []clatter.HandshakeErrorEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]clatter.HandshakeErrorEvent, len(r.errors))
	copy(out, r.errors)
	return out
}

func obsNqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

func obsPqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}
}

func obsHybridSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
	}
}

// TestObserver_NQ_XX verifies correct event sequence for a full NQ XX handshake.
func TestObserver_NQ_XX(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithObserver(obs),
		clatter.WithStaticKey(mustKeypair(t, suite.DH)))
	if err != nil {
		t.Fatal(err)
	}

	bob, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(mustKeypair(t, suite.DH)))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// XX: 3 messages (alice->bob->alice)
	// Msg 1: alice writes
	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}

	// Msg 2: bob writes
	n, err = bob.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}

	// Msg 3: alice writes
	n, err = alice.WriteMessage([]byte("hello"), buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}

	// Finalize
	_, err = alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()

	// XX has 3 messages (2 writes + 1 read for alice) + 1 Finalize = 4 events
	// Alice: Write(0), Read(1), Write(2), Finalize(3)
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// Verify message indices are sequential
	for i, e := range events {
		if e.MessageIndex != i {
			t.Errorf("event %d: MessageIndex=%d, want %d", i, e.MessageIndex, i)
		}
	}

	// First event: Write, TypeNQ, Sent
	if events[0].Direction != clatter.Sent {
		t.Errorf("event 0: Direction=%v, want Sent", events[0].Direction)
	}
	if events[0].HandshakeType != clatter.TypeNQ {
		t.Errorf("event 0: HandshakeType=%v, want TypeNQ", events[0].HandshakeType)
	}
	if events[0].IsInitiator != true {
		t.Error("event 0: IsInitiator should be true")
	}
	if events[0].Phase != clatter.SinglePhase {
		t.Errorf("event 0: Phase=%v, want SinglePhase", events[0].Phase)
	}
	if events[0].ProtocolName == "" {
		t.Error("event 0: ProtocolName should not be empty")
	}

	// Second event: Read, should have learned remote keys
	if events[1].Direction != clatter.Received {
		t.Errorf("event 1: Direction=%v, want Received", events[1].Direction)
	}
	// XX msg 2 from bob carries bob's static key
	if events[1].RemoteStaticDH == nil {
		t.Error("event 1: RemoteStaticDH should be non-nil (learned bob's static)")
	}

	// Last event: Finalize
	if !events[3].IsComplete {
		t.Error("last event should have IsComplete=true")
	}

	// HandshakeHash should be non-nil on ALL events (including IsComplete)
	for i, e := range events {
		if e.HandshakeHash == nil {
			t.Errorf("event %d: HandshakeHash is nil", i)
		}
	}
}

// TestObserver_NilObserver verifies nil observer causes no crash or allocation.
func TestObserver_NilObserver(t *testing.T) {
	suite := obsNqSuite()

	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// NN: 2 messages
	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}
	n, err = bob.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}

	if _, err := alice.Finalize(); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Finalize(); err != nil {
		t.Fatal(err)
	}
}

// TestObserver_PanickingObserver verifies that a panicking observer doesn't crash.
func TestObserver_PanickingObserver(t *testing.T) {
	panicObs := &panickingObserver{}
	suite := obsNqSuite()

	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite, clatter.WithObserver(panicObs))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// Should not panic despite observer panicking
	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}
	n, err = bob.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(); err != nil {
		t.Fatal(err)
	}
}

type panickingObserver struct{}

func (p *panickingObserver) OnMessage(_ clatter.HandshakeEvent) { panic("test panic") }
func (p *panickingObserver) OnError(_ clatter.HandshakeErrorEvent) { panic("error panic too") }

// TestObserver_EventDataAreCopies verifies mutating event data doesn't affect handshake.
func TestObserver_EventDataAreCopies(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite, clatter.WithObserver(obs))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}

	// Mutate the event's HandshakeHash
	events := obs.getEvents()
	if len(events) == 0 {
		t.Fatal("expected at least 1 event")
	}
	if events[0].HandshakeHash != nil {
		events[0].HandshakeHash[0] ^= 0xFF
	}

	// Continue handshake - should work fine
	n, err = bob.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Finalize(); err != nil {
		t.Fatal(err)
	}
}

// TestObserver_ErrorEvent verifies observer receives error events.
func TestObserver_ErrorEvent(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	alice, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite, clatter.WithObserver(obs))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)

	// Write first message successfully
	n, err := alice.WriteMessage(nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = n

	// Now alice expects to read, but give it garbage
	_, err = alice.ReadMessage([]byte("garbage data that is too short"), buf)
	if err == nil {
		t.Fatal("expected error on invalid message")
	}

	errors := obs.getErrors()
	if len(errors) == 0 {
		t.Fatal("expected at least 1 error event")
	}
	if errors[0].Err == nil {
		t.Error("error event should have non-nil Err")
	}
	if errors[0].Direction != clatter.Received {
		t.Errorf("error Direction=%v, want Received", errors[0].Direction)
	}
	if errors[0].HandshakeType != clatter.TypeNQ {
		t.Errorf("error HandshakeType=%v, want TypeNQ", errors[0].HandshakeType)
	}
	if !errors[0].IsInitiator {
		t.Error("error IsInitiator should be true")
	}
}

// TestObserver_PQ_XX verifies PQ handshake observer reports KEM keys.
func TestObserver_PQ_XX(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsPqSuite()

	aliceStatic, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	bobStatic, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	alice, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
		clatter.WithObserver(obs),
		clatter.WithStaticKey(aliceStatic))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite,
		clatter.WithStaticKey(bobStatic))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// Drive handshake to completion
	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, err := alice.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		} else {
			n, err := bob.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		}
	}

	_, err = alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()
	if len(events) == 0 {
		t.Fatal("expected events")
	}

	// Check that at least one Read event has KEM keys
	foundKEM := false
	for _, e := range events {
		if e.RemoteEphemeralKEM != nil || e.RemoteStaticKEM != nil {
			foundKEM = true
			break
		}
	}
	if !foundKEM {
		t.Error("expected at least one event with RemoteEphemeralKEM or RemoteStaticKEM")
	}

	// Last event should be IsComplete
	if !events[len(events)-1].IsComplete {
		t.Error("last event should be IsComplete")
	}
	if events[len(events)-1].HandshakeType != clatter.TypePQ {
		t.Errorf("last event type=%v, want TypePQ", events[len(events)-1].HandshakeType)
	}
}

// TestObserver_DualLayer verifies DualLayer observer fires on both phases.
func TestObserver_DualLayer(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	outerAlice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	innerAlice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	outerBob, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	innerBob, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	alice, err := clatter.NewDualLayerHandshake(outerAlice, innerAlice, 65535, clatter.WithObserver(obs))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewDualLayerHandshake(outerBob, innerBob, 65535)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// Drive handshake to completion
	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, err := alice.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		} else {
			n, err := bob.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		}
	}

	_, err = alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()

	// Should have events from both outer and inner phases
	hasOuter := false
	hasInner := false
	for _, e := range events {
		if e.Phase == clatter.OuterPhase {
			hasOuter = true
		}
		if e.Phase == clatter.InnerPhase {
			hasInner = true
		}
	}
	if !hasOuter {
		t.Error("expected events with OuterPhase")
	}
	if !hasInner {
		t.Error("expected events with InnerPhase")
	}

	// Last event should be IsComplete with HandshakeHash
	last := events[len(events)-1]
	if !last.IsComplete {
		t.Error("last event should be IsComplete")
	}
	if last.HandshakeType != clatter.TypeDualLayer {
		t.Errorf("last event type=%v, want TypeDualLayer", last.HandshakeType)
	}
	if last.HandshakeHash == nil {
		t.Error("IsComplete event should have non-nil HandshakeHash")
	}

	// ProtocolName should be empty for DualLayer events
	for _, e := range events {
		if e.ProtocolName != "" {
			t.Errorf("DualLayer event should have empty ProtocolName, got %q", e.ProtocolName)
		}
	}

	// MessageIndex should be continuous
	for i, e := range events {
		if e.MessageIndex != i {
			t.Errorf("event %d: MessageIndex=%d, want %d", i, e.MessageIndex, i)
		}
	}
}

// TestObserver_NotCalledAfterFinalize verifies no events after Finalize.
func TestObserver_NotCalledAfterFinalize(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	alice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite, clatter.WithObserver(obs))
	bob, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	n, _ := alice.WriteMessage(nil, buf)
	bob.ReadMessage(buf[:n], payload)
	n, _ = bob.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:n], payload)
	alice.Finalize()

	countBefore := len(obs.getEvents())

	// Subsequent calls should error but NOT fire observer
	alice.WriteMessage(nil, buf)
	alice.ReadMessage(buf[:1], payload)

	countAfter := len(obs.getEvents())
	if countAfter != countBefore {
		t.Errorf("events fired after Finalize: before=%d, after=%d", countBefore, countAfter)
	}
}

// TestObserver_Hybrid_XX verifies Hybrid handshake reports both DH and KEM keys.
func TestObserver_Hybrid_XX(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsHybridSuite()

	aliceDH := mustKeypair(t, suite.DH)
	bobDH := mustKeypair(t, suite.DH)
	aliceKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	bobKEM, _ := suite.SKEM.GenerateKeypair(crand.Reader)

	alice, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, suite,
		clatter.WithObserver(obs),
		clatter.WithStaticKey(aliceDH),
		clatter.WithStaticKEMKey(aliceKEM))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, false, suite,
		clatter.WithStaticKey(bobDH),
		clatter.WithStaticKEMKey(bobKEM))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// Drive handshake to completion
	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, err := alice.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		} else {
			n, err := bob.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		}
	}

	_, err = alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()
	if len(events) == 0 {
		t.Fatal("expected events")
	}

	// Hybrid Read events should report both DH and KEM remote keys
	foundDH := false
	foundKEM := false
	for _, e := range events {
		if e.RemoteEphemeralDH != nil || e.RemoteStaticDH != nil {
			foundDH = true
		}
		if e.RemoteEphemeralKEM != nil || e.RemoteStaticKEM != nil {
			foundKEM = true
		}
	}
	if !foundDH {
		t.Error("expected at least one event with RemoteEphemeralDH or RemoteStaticDH")
	}
	if !foundKEM {
		t.Error("expected at least one event with RemoteEphemeralKEM or RemoteStaticKEM")
	}

	// All events should be TypeHybrid
	for i, e := range events {
		if e.HandshakeType != clatter.TypeHybrid {
			t.Errorf("event %d: type=%v, want TypeHybrid", i, e.HandshakeType)
		}
	}

	// Last event should be IsComplete
	if !events[len(events)-1].IsComplete {
		t.Error("last event should be IsComplete")
	}
}

// TestObserver_Responder verifies observer works correctly on the responder side.
func TestObserver_Responder(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	alice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	bob, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite, clatter.WithObserver(obs))
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	// NN: alice writes first, bob reads
	n, _ := alice.WriteMessage(nil, buf)
	_, err = bob.ReadMessage(buf[:n], payload)
	if err != nil {
		t.Fatal(err)
	}

	// bob writes, alice reads
	n, _ = bob.WriteMessage(nil, buf)
	_, err = alice.ReadMessage(buf[:n], payload)
	if err != nil {
		t.Fatal(err)
	}

	_, err = bob.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()
	// Bob: Read(0), Write(1), Finalize(2) = 3 events
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// First event: bob read alice's message
	if events[0].Direction != clatter.Received {
		t.Errorf("event 0: Direction=%v, want Received", events[0].Direction)
	}
	if events[0].IsInitiator {
		t.Error("event 0: IsInitiator should be false for responder")
	}

	// Second event: bob wrote
	if events[1].Direction != clatter.Sent {
		t.Errorf("event 1: Direction=%v, want Sent", events[1].Direction)
	}

	// Last: Finalize
	if !events[2].IsComplete {
		t.Error("event 2: should be IsComplete")
	}
	if events[2].HandshakeHash == nil {
		t.Error("Finalize event should have non-nil HandshakeHash")
	}
}

// TestObserver_HybridDualLayer verifies HybridDualLayer observer fires correctly.
func TestObserver_HybridDualLayer(t *testing.T) {
	obs := &recordingObserver{}
	suite := obsNqSuite()

	outerAlice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	innerAlice, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	outerBob, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	innerBob, _ := clatter.NewNqHandshake(clatter.PatternNN, false, suite)

	alice, err := clatter.NewHybridDualLayerHandshake(outerAlice, innerAlice, 65535, clatter.WithObserver(obs))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := clatter.NewHybridDualLayerHandshake(outerBob, innerBob, 65535)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 65535)
	payload := make([]byte, 65535)

	for !alice.IsFinished() && !bob.IsFinished() {
		if alice.IsWriteTurn() {
			n, err := alice.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bob.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		} else {
			n, err := bob.WriteMessage(nil, buf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := alice.ReadMessage(buf[:n], payload); err != nil {
				t.Fatal(err)
			}
		}
	}

	_, err = alice.Finalize()
	if err != nil {
		t.Fatal(err)
	}

	events := obs.getEvents()

	// Should have outer + inner phase events
	hasOuter := false
	hasInner := false
	for _, e := range events {
		if e.Phase == clatter.OuterPhase {
			hasOuter = true
		}
		if e.Phase == clatter.InnerPhase {
			hasInner = true
		}
	}
	if !hasOuter {
		t.Error("expected OuterPhase events")
	}
	if !hasInner {
		t.Error("expected InnerPhase events")
	}

	// All events should be TypeHybridDualLayer
	for i, e := range events {
		if e.HandshakeType != clatter.TypeHybridDualLayer {
			t.Errorf("event %d: type=%v, want TypeHybridDualLayer", i, e.HandshakeType)
		}
	}

	// Last event: IsComplete with HandshakeHash
	last := events[len(events)-1]
	if !last.IsComplete {
		t.Error("last event should be IsComplete")
	}
	if last.HandshakeHash == nil {
		t.Error("IsComplete event should have non-nil HandshakeHash")
	}

	// Continuous msgIndex
	for i, e := range events {
		if e.MessageIndex != i {
			t.Errorf("event %d: MessageIndex=%d, want %d", i, e.MessageIndex, i)
		}
	}
}

// TestObserver_StringMethods verifies String() methods on enum types.
func TestObserver_StringMethods(t *testing.T) {
	if clatter.Sent.String() != "Sent" {
		t.Errorf("Sent.String()=%q", clatter.Sent.String())
	}
	if clatter.Received.String() != "Received" {
		t.Errorf("Received.String()=%q", clatter.Received.String())
	}
	if clatter.TypeNQ.String() != "NQ" {
		t.Errorf("TypeNQ.String()=%q", clatter.TypeNQ.String())
	}
	if clatter.TypeHybridDualLayer.String() != "HybridDualLayer" {
		t.Errorf("TypeHybridDualLayer.String()=%q", clatter.TypeHybridDualLayer.String())
	}
	if clatter.SinglePhase.String() != "Single" {
		t.Errorf("SinglePhase.String()=%q", clatter.SinglePhase.String())
	}
	if clatter.OuterPhase.String() != "Outer" {
		t.Errorf("OuterPhase.String()=%q", clatter.OuterPhase.String())
	}
	if clatter.Direction(99).String() != "Unknown" {
		t.Errorf("invalid Direction.String()=%q", clatter.Direction(99).String())
	}
}

func mustKeypair(t *testing.T, d clatter.DH) clatter.KeyPair {
	t.Helper()
	kp, err := d.GenerateKeypair(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return kp
}
