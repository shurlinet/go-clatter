package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// These tests pin that a dual-layer handshake reports HandshakeErrorEvent.Direction
// accurately on the outer-to-inner TRANSITION error path. updateOuterState runs
// after BOTH WriteMessage and ReadMessage, so an outer-finalize failure must be
// reported with the direction of the operation that drove the transition
// (Sent from a write, Received from a read) - matching the single-layer
// setError contract, where the observer godoc promises Direction "indicates
// which operation failed".

// finalizeStubHandshaker is a minimal external Handshaker whose IsFinished and
// Finalize results are configurable. It drives a dual-layer to the outer
// transition on either the write or the read path (its WriteMessage/ReadMessage
// answer with success) and forces the outer Finalize to fail, exercising the
// updateOuterState finalize-error event. The protocol methods are inert stubs:
// the transition is reached purely through IsFinished()/Finalize().
type finalizeStubHandshaker struct {
	initiator   bool
	finished    bool
	finalizeErr error
	destroyed   bool
}

func (m *finalizeStubHandshaker) WriteMessage(payload, out []byte) (int, error) { return 0, nil }
func (m *finalizeStubHandshaker) ReadMessage(message, out []byte) (int, error)  { return 0, nil }
func (m *finalizeStubHandshaker) IsFinished() bool                              { return m.finished }
func (m *finalizeStubHandshaker) IsWriteTurn() bool                             { return m.initiator }
func (m *finalizeStubHandshaker) Finalize() (*clatter.TransportState, error) {
	return nil, m.finalizeErr
}
func (m *finalizeStubHandshaker) GetNextMessageOverhead() (int, error) { return 0, nil }
func (m *finalizeStubHandshaker) PushPSK(psk []byte) error             { return nil }
func (m *finalizeStubHandshaker) GetHandshakeHash() []byte             { return nil }
func (m *finalizeStubHandshaker) IsInitiator() bool                    { return m.initiator }
func (m *finalizeStubHandshaker) IsOneWay() bool                       { return false }
func (m *finalizeStubHandshaker) MaxMessageLen() int                   { return clatter.MaxMessageLen }
func (m *finalizeStubHandshaker) Destroy()                             { m.destroyed = true }

var errStubOuterFinalize = errors.New("stub outer finalize failure")

func TestDualLayerObserver_ReadTriggeredOuterFinalizeError_ReportsReceived(t *testing.T) {
	obs := &recordingObserver{}
	outer := &finalizeStubHandshaker{initiator: false, finished: true, finalizeErr: errStubOuterFinalize}
	inner := &finalizeStubHandshaker{initiator: false}
	dl, err := clatter.NewDualLayerHandshake(outer, inner, 4096, clatter.WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer dl.Destroy()

	if _, err := dl.ReadMessage(make([]byte, 64), make([]byte, 4096)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("ReadMessage: got %v, want errStubOuterFinalize", err)
	}

	errs := obs.getErrors()
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(errs))
	}
	if errs[0].Direction != clatter.Received {
		t.Errorf("Direction=%v, want Received (read-triggered outer finalize error)", errs[0].Direction)
	}
	if errs[0].Phase != clatter.OuterPhase {
		t.Errorf("Phase=%v, want OuterPhase", errs[0].Phase)
	}
	if errs[0].HandshakeType != clatter.TypeDualLayer {
		t.Errorf("HandshakeType=%v, want TypeDualLayer", errs[0].HandshakeType)
	}
}

func TestDualLayerObserver_WriteTriggeredOuterFinalizeError_ReportsSent(t *testing.T) {
	obs := &recordingObserver{}
	outer := &finalizeStubHandshaker{initiator: true, finished: true, finalizeErr: errStubOuterFinalize}
	inner := &finalizeStubHandshaker{initiator: true}
	dl, err := clatter.NewDualLayerHandshake(outer, inner, 4096, clatter.WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer dl.Destroy()

	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("WriteMessage: got %v, want errStubOuterFinalize", err)
	}

	errs := obs.getErrors()
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(errs))
	}
	if errs[0].Direction != clatter.Sent {
		t.Errorf("Direction=%v, want Sent (write-triggered outer finalize error)", errs[0].Direction)
	}
}

// TestDualLayerObserver_OuterFinalizeError_ZeroesInnerAndPreventsReuse pins the
// security invariant on the outer-finalize error path: a fatal transition error
// must zero the inner handshake's secrets (zero-secrets-on-error) and finalize
// the dual-layer, so a subsequent call returns ErrAlreadyFinished rather than
// dereferencing the now-nil outer handshake (a nil-pointer panic / DoS).
func TestDualLayerObserver_OuterFinalizeError_ZeroesInnerAndPreventsReuse(t *testing.T) {
	outer := &finalizeStubHandshaker{initiator: true, finished: true, finalizeErr: errStubOuterFinalize}
	inner := &finalizeStubHandshaker{initiator: true}
	dl, err := clatter.NewDualLayerHandshake(outer, inner, 4096)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("first write: got %v, want errStubOuterFinalize", err)
	}
	if !inner.destroyed {
		t.Error("inner must be destroyed (zero-secrets-on-error) after a fatal outer-finalize error")
	}
	// Reuse must fail closed, not panic on the nil outer.
	if _, err := dl.WriteMessage(nil, make([]byte, 4096)); !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("write after error: got %v, want ErrAlreadyFinished (no panic)", err)
	}
	if _, err := dl.ReadMessage(make([]byte, 64), make([]byte, 4096)); !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("read after error: got %v, want ErrAlreadyFinished (no panic)", err)
	}
}

// TestHybridDualLayerObserver_OuterFinalizeError_PreventsReuse is the hybrid
// counterpart: after a fatal outer-finalize error, reuse must return
// ErrAlreadyFinished rather than panic on the nil outer.
func TestHybridDualLayerObserver_OuterFinalizeError_PreventsReuse(t *testing.T) {
	outer := &finalizeStubHandshaker{initiator: true, finished: true, finalizeErr: errStubOuterFinalize}
	inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, obsPqSuite())
	if err != nil {
		t.Fatalf("inner pqNN: %v", err)
	}
	hdl, err := clatter.NewHybridDualLayerHandshake(outer, inner, 8192)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, err := hdl.WriteMessage(nil, make([]byte, 8192)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("first write: got %v, want errStubOuterFinalize", err)
	}
	if _, err := hdl.WriteMessage(nil, make([]byte, 8192)); !errors.Is(err, clatter.ErrAlreadyFinished) {
		t.Fatalf("write after error: got %v, want ErrAlreadyFinished (no panic)", err)
	}
}

func TestHybridDualLayerObserver_ReadTriggeredOuterFinalizeError_ReportsReceived(t *testing.T) {
	obs := &recordingObserver{}
	outer := &finalizeStubHandshaker{initiator: false, finished: true, finalizeErr: errStubOuterFinalize}
	// Hybrid requires a built-in (outer-bindable) inner; it is never reached on
	// the outer-finalize-error path (the error returns before binding).
	inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, obsPqSuite())
	if err != nil {
		t.Fatalf("inner pqNN: %v", err)
	}
	hdl, err := clatter.NewHybridDualLayerHandshake(outer, inner, 8192, clatter.WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer hdl.Destroy()

	if _, err := hdl.ReadMessage(make([]byte, 64), make([]byte, 8192)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("ReadMessage: got %v, want errStubOuterFinalize", err)
	}

	errs := obs.getErrors()
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(errs))
	}
	if errs[0].Direction != clatter.Received {
		t.Errorf("Direction=%v, want Received (read-triggered outer finalize error)", errs[0].Direction)
	}
	if errs[0].HandshakeType != clatter.TypeHybridDualLayer {
		t.Errorf("HandshakeType=%v, want TypeHybridDualLayer", errs[0].HandshakeType)
	}
}

func TestHybridDualLayerObserver_WriteTriggeredOuterFinalizeError_ReportsSent(t *testing.T) {
	obs := &recordingObserver{}
	outer := &finalizeStubHandshaker{initiator: true, finished: true, finalizeErr: errStubOuterFinalize}
	inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, obsPqSuite())
	if err != nil {
		t.Fatalf("inner pqNN: %v", err)
	}
	hdl, err := clatter.NewHybridDualLayerHandshake(outer, inner, 8192, clatter.WithObserver(obs))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	defer hdl.Destroy()

	if _, err := hdl.WriteMessage(nil, make([]byte, 8192)); !errors.Is(err, errStubOuterFinalize) {
		t.Fatalf("WriteMessage: got %v, want errStubOuterFinalize", err)
	}

	errs := obs.getErrors()
	if len(errs) != 1 {
		t.Fatalf("got %d error events, want 1", len(errs))
	}
	if errs[0].Direction != clatter.Sent {
		t.Errorf("Direction=%v, want Sent (write-triggered outer finalize error)", errs[0].Direction)
	}
}
