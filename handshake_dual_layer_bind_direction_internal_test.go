package clatter

import (
	"errors"
	"testing"
)

// These tests pin that the hybrid dual-layer reports HandshakeErrorEvent.Direction
// accurately on the inner-BIND failure path (failInnerBind), reached from
// updateOuterState after BOTH WriteMessage and ReadMessage. The bind path needs
// an inner that implements the unexported outerBindable with a failing
// bindOuterTransport, so these tests live in package clatter (an external test
// cannot implement outerBindable).

// finalizeOKStubHandshaker is an in-package Handshaker whose outer Finalize
// SUCCEEDS (returning a caller-supplied transport), so the hybrid dual-layer
// proceeds past the outer transition into the inner-binding step, where the
// bind is then forced to fail.
type finalizeOKStubHandshaker struct {
	initiator bool
	ts        *TransportState
}

func (m *finalizeOKStubHandshaker) WriteMessage(payload, out []byte) (int, error) { return 0, nil }
func (m *finalizeOKStubHandshaker) ReadMessage(message, out []byte) (int, error)  { return 0, nil }
func (m *finalizeOKStubHandshaker) IsFinished() bool                              { return true }
func (m *finalizeOKStubHandshaker) IsWriteTurn() bool                             { return m.initiator }
func (m *finalizeOKStubHandshaker) Finalize() (*TransportState, error)            { return m.ts, nil }
func (m *finalizeOKStubHandshaker) GetNextMessageOverhead() (int, error)          { return 0, nil }
func (m *finalizeOKStubHandshaker) PushPSK(psk []byte) error                      { return nil }
func (m *finalizeOKStubHandshaker) GetHandshakeHash() []byte                      { return nil }
func (m *finalizeOKStubHandshaker) IsInitiator() bool                             { return m.initiator }
func (m *finalizeOKStubHandshaker) IsOneWay() bool                                { return false }
func (m *finalizeOKStubHandshaker) MaxMessageLen() int                            { return MaxMessageLen }
func (m *finalizeOKStubHandshaker) Destroy()                                      {}

// failingBindInner is an in-package Handshaker that also implements the
// unexported outerBindable, with a bindOuterTransport that always fails. This
// is the only way to deterministically reach the failInnerBind path (a real
// inner's bind fails only on already-destroyed symmetric state).
type failingBindInner struct {
	initiator bool
	destroyed bool
}

func (m *failingBindInner) WriteMessage(payload, out []byte) (int, error)     { return 0, nil }
func (m *failingBindInner) ReadMessage(message, out []byte) (int, error)      { return 0, nil }
func (m *failingBindInner) IsFinished() bool                                  { return false }
func (m *failingBindInner) IsWriteTurn() bool                                 { return m.initiator }
func (m *failingBindInner) Finalize() (*TransportState, error)                { return nil, nil }
func (m *failingBindInner) GetNextMessageOverhead() (int, error)              { return 0, nil }
func (m *failingBindInner) PushPSK(psk []byte) error                          { return nil }
func (m *failingBindInner) GetHandshakeHash() []byte                          { return nil }
func (m *failingBindInner) IsInitiator() bool                                 { return m.initiator }
func (m *failingBindInner) IsOneWay() bool                                    { return false }
func (m *failingBindInner) MaxMessageLen() int                                { return MaxMessageLen }
func (m *failingBindInner) Destroy()                                          { m.destroyed = true }
func (m *failingBindInner) bindOuterTransport(domain, outerHash []byte) error { return ErrInvalidState }

// errorDirectionRecorder is a minimal in-package Observer capturing error events.
type errorDirectionRecorder struct {
	errs []HandshakeErrorEvent
}

func (r *errorDirectionRecorder) OnMessage(HandshakeEvent)      {}
func (r *errorDirectionRecorder) OnError(e HandshakeErrorEvent) { r.errs = append(r.errs, e) }

// newBindTestTransport fabricates a usable outer TransportState (its
// GetHandshakeHash returns 32 zero bytes), so the hybrid transition reaches the
// bind step with a live outer transport.
func newBindTestTransport(t *testing.T) *TransportState {
	t.Helper()
	cs1, err := NewCipherState(&testCipher{}, make([]byte, KeyLen))
	if err != nil {
		t.Fatalf("cs1: %v", err)
	}
	cs2, err := NewCipherState(&testCipher{}, make([]byte, KeyLen))
	if err != nil {
		t.Fatalf("cs2: %v", err)
	}
	return newTransportState(cs1, cs2, PatternNN, make([]byte, 32), true, MaxMessageLen)
}

func TestHybridDualLayerObserver_ReadTriggeredBindError_ReportsReceived(t *testing.T) {
	obs := &errorDirectionRecorder{}
	outer := &finalizeOKStubHandshaker{initiator: false, ts: newBindTestTransport(t)}
	inner := &failingBindInner{initiator: false}
	hdl, err := NewHybridDualLayerHandshake(outer, inner, 4096, WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer hdl.Destroy()

	if _, err := hdl.ReadMessage(make([]byte, 64), make([]byte, 4096)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("ReadMessage: got %v, want ErrInvalidState (bind failure)", err)
	}

	if len(obs.errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(obs.errs))
	}
	if obs.errs[0].Direction != Received {
		t.Errorf("Direction=%v, want Received (read-triggered bind error)", obs.errs[0].Direction)
	}
	if obs.errs[0].Phase != InnerPhase {
		t.Errorf("Phase=%v, want InnerPhase", obs.errs[0].Phase)
	}
	if obs.errs[0].HandshakeType != TypeHybridDualLayer {
		t.Errorf("HandshakeType=%v, want TypeHybridDualLayer", obs.errs[0].HandshakeType)
	}
	// The bind-failure path must zero the inner (zero-secrets-on-error) via
	// failTransition, and finalize so reuse fails closed rather than panicking.
	if !inner.destroyed {
		t.Error("inner must be destroyed (zero-secrets-on-error) after a bind failure")
	}
	if _, err := hdl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, ErrAlreadyFinished) {
		t.Fatalf("write after bind error: got %v, want ErrAlreadyFinished (no panic)", err)
	}
}

func TestHybridDualLayerObserver_WriteTriggeredBindError_ReportsSent(t *testing.T) {
	obs := &errorDirectionRecorder{}
	outer := &finalizeOKStubHandshaker{initiator: true, ts: newBindTestTransport(t)}
	inner := &failingBindInner{initiator: true}
	hdl, err := NewHybridDualLayerHandshake(outer, inner, 4096, WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer hdl.Destroy()

	if _, err := hdl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("WriteMessage: got %v, want ErrInvalidState (bind failure)", err)
	}

	if len(obs.errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(obs.errs))
	}
	if obs.errs[0].Direction != Sent {
		t.Errorf("Direction=%v, want Sent (write-triggered bind error)", obs.errs[0].Direction)
	}
}

// innerFinalizeErrStub is an inner whose Finalize fails while reporting
// IsFinished, exercising the dual-layer Finalize inner-error path.
type innerFinalizeErrStub struct{ initiator bool }

func (m *innerFinalizeErrStub) WriteMessage(p, o []byte) (int, error)  { return 0, nil }
func (m *innerFinalizeErrStub) ReadMessage(msg, o []byte) (int, error) { return 0, nil }
func (m *innerFinalizeErrStub) IsFinished() bool                       { return true }
func (m *innerFinalizeErrStub) IsWriteTurn() bool                      { return m.initiator }
func (m *innerFinalizeErrStub) Finalize() (*TransportState, error) {
	return nil, errors.New("inner finalize failure")
}
func (m *innerFinalizeErrStub) GetNextMessageOverhead() (int, error) { return 0, nil }
func (m *innerFinalizeErrStub) PushPSK(psk []byte) error             { return nil }
func (m *innerFinalizeErrStub) GetHandshakeHash() []byte             { return nil }
func (m *innerFinalizeErrStub) IsInitiator() bool                    { return m.initiator }
func (m *innerFinalizeErrStub) IsOneWay() bool                       { return false }
func (m *innerFinalizeErrStub) MaxMessageLen() int                   { return MaxMessageLen }
func (m *innerFinalizeErrStub) Destroy()                             {}

// innerWriteErrStub is an inner whose WriteMessage fails mid-handshake,
// exercising the dual-layer inner-phase write-error path.
type innerWriteErrStub struct{ initiator bool }

func (m *innerWriteErrStub) WriteMessage(p, o []byte) (int, error) {
	return 0, errors.New("inner write failure")
}
func (m *innerWriteErrStub) ReadMessage(msg, o []byte) (int, error) { return 0, nil }
func (m *innerWriteErrStub) IsFinished() bool                       { return false }
func (m *innerWriteErrStub) IsWriteTurn() bool                      { return m.initiator }
func (m *innerWriteErrStub) Finalize() (*TransportState, error)     { return nil, nil }
func (m *innerWriteErrStub) GetNextMessageOverhead() (int, error)   { return 0, nil }
func (m *innerWriteErrStub) PushPSK(psk []byte) error               { return nil }
func (m *innerWriteErrStub) GetHandshakeHash() []byte               { return nil }
func (m *innerWriteErrStub) IsInitiator() bool                      { return m.initiator }
func (m *innerWriteErrStub) IsOneWay() bool                         { return false }
func (m *innerWriteErrStub) MaxMessageLen() int                     { return MaxMessageLen }
func (m *innerWriteErrStub) Destroy()                               {}

// TestDualLayerHandshake_FinalizeInnerError_ZeroesOuterTransport pins the
// zero-secrets-on-error invariant on the Finalize inner-error path: the live
// outer transport session keys must be zeroed immediately (not leaked until a
// later Destroy), and reuse must fail closed.
func TestDualLayerHandshake_FinalizeInnerError_ZeroesOuterTransport(t *testing.T) {
	ts := newBindTestTransport(t)
	dl := &DualLayerHandshake{
		inner:          &innerFinalizeErrStub{initiator: true},
		outerTransport: ts,
		outerFinished:  true,
		initiator:      true,
		maxMsgLen:      MaxMessageLen,
		outerRecvBuf:   make([]byte, 4096),
	}
	if _, err := dl.Finalize(); err == nil {
		t.Fatal("expected inner finalize error")
	}
	if !ts.IsDestroyed() {
		t.Error("live outer transport keys must be zeroed on inner-finalize error (no leak until caller Destroy)")
	}
	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, ErrAlreadyFinished) {
		t.Fatalf("reuse after error: got %v, want ErrAlreadyFinished (no panic/leak)", err)
	}
}

// TestDualLayerHandshake_InnerPhaseWriteError_ZeroesOuterTransport pins the same
// invariant on the inner-phase write-error path.
func TestDualLayerHandshake_InnerPhaseWriteError_ZeroesOuterTransport(t *testing.T) {
	ts := newBindTestTransport(t)
	dl := &DualLayerHandshake{
		inner:          &innerWriteErrStub{initiator: true},
		outerTransport: ts,
		outerFinished:  true,
		initiator:      true,
		maxMsgLen:      MaxMessageLen,
		outerRecvBuf:   make([]byte, 4096),
	}
	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); err == nil {
		t.Fatal("expected inner-phase write error")
	}
	if !ts.IsDestroyed() {
		t.Error("live outer transport keys must be zeroed on inner-phase write error (no leak until caller Destroy)")
	}
	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, ErrAlreadyFinished) {
		t.Fatalf("reuse after error: got %v, want ErrAlreadyFinished (no panic/leak)", err)
	}
}
