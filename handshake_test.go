package clatter

import (
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
)

// TestHandshakeInternals_InitialStatus verifies initial status determination.
func TestHandshakeInternals_InitialStatus(t *testing.T) {
	h := &HandshakeInternals{
		pattern:   PatternNN,
		initiator: true,
	}
	h.determineInitialStatus()
	if h.status != StatusSend {
		t.Errorf("initiator should start with StatusSend, got %d", h.status)
	}

	h2 := &HandshakeInternals{
		pattern:   PatternNN,
		initiator: false,
	}
	h2.determineInitialStatus()
	if h2.status != StatusReceive {
		t.Errorf("responder should start with StatusReceive, got %d", h2.status)
	}
}

// TestHandshakeInternals_GetNextMessage_4WayDispatch verifies F129.
func TestHandshakeInternals_GetNextMessage_4WayDispatch(t *testing.T) {
	// XX pattern: initiator sends 2, responder sends 1
	// initiator: msg0=[e], msg1=[s,se]
	// responder: msg0=[e,ee,s,es]

	// Case 1: Initiator writing (StatusSend)
	h := &HandshakeInternals{
		pattern:   PatternXX,
		initiator: true,
		status:    StatusSend,
	}
	tokens, err := h.getNextMessage()
	if err != nil {
		t.Fatalf("getNextMessage failed: %v", err)
	}
	if len(tokens) != 1 || tokens[0] != TokenE {
		t.Errorf("expected [E], got %v", tokens)
	}
	if h.initIdx != 1 { // F66: index incremented before processing
		t.Errorf("expected initIdx=1, got %d", h.initIdx)
	}

	// Case 2: Initiator reading (StatusReceive) - reads responder pattern (F88)
	h.status = StatusReceive
	tokens, err = h.getNextMessage()
	if err != nil {
		t.Fatalf("getNextMessage failed: %v", err)
	}
	if len(tokens) != 4 { // [e, ee, s, es]
		t.Errorf("expected 4 tokens from responder, got %d", len(tokens))
	}
	if h.respIdx != 1 {
		t.Errorf("expected respIdx=1, got %d", h.respIdx)
	}

	// Case 3: Initiator writing second message
	h.status = StatusSend
	tokens, err = h.getNextMessage()
	if err != nil {
		t.Fatalf("getNextMessage failed: %v", err)
	}
	if len(tokens) != 2 { // [s, se]
		t.Errorf("expected 2 tokens for msg3, got %d", len(tokens))
	}
	if tokens[0] != TokenS || tokens[1] != TokenSE {
		t.Errorf("expected [S, SE], got %v", tokens)
	}

	// Case 4: Responder perspective
	h2 := &HandshakeInternals{
		pattern:   PatternXX,
		initiator: false,
		status:    StatusReceive,
	}
	// Responder reading = reads initiator pattern (F88)
	tokens, err = h2.getNextMessage()
	if err != nil {
		t.Fatalf("responder read failed: %v", err)
	}
	if len(tokens) != 1 || tokens[0] != TokenE {
		t.Errorf("responder read: expected [E], got %v", tokens)
	}

	// Responder writing
	h2.status = StatusSend
	tokens, err = h2.getNextMessage()
	if err != nil {
		t.Fatalf("responder write failed: %v", err)
	}
	if len(tokens) != 4 { // [e, ee, s, es]
		t.Errorf("responder write: expected 4 tokens, got %d", len(tokens))
	}
}

// TestHandshakeInternals_IndexOverflow verifies error on index overflow.
func TestHandshakeInternals_IndexOverflow(t *testing.T) {
	h := &HandshakeInternals{
		pattern:   PatternNN,
		initiator: true,
		status:    StatusSend,
		initIdx:   1, // Already at max for NN (1 initiator msg)
	}
	_, err := h.getNextMessage()
	if err == nil {
		t.Fatal("expected error on index overflow")
	}
}

// TestHandshakeInternals_UpdateStatus verifies F87: both indices must match.
func TestHandshakeInternals_UpdateStatus(t *testing.T) {
	h := &HandshakeInternals{
		pattern:   PatternNN,
		initiator: true,
		status:    StatusSend,
		initIdx:   1, // all initiator messages consumed
		respIdx:   1, // all responder messages consumed
	}
	h.updateStatus()
	if h.status != StatusReady {
		t.Errorf("expected StatusReady, got %d", h.status)
	}

	// Partial completion: only initiator done
	h2 := &HandshakeInternals{
		pattern:   PatternXX,
		initiator: true,
		status:    StatusSend,
		initIdx:   2, // all 2 initiator messages consumed
		respIdx:   0, // responder not yet consumed
	}
	h2.updateStatus()
	if h2.status == StatusReady {
		t.Error("should NOT be Ready when responder messages remain")
	}
}

// TestHandshakeInternals_StatusToggle verifies send/receive alternation.
func TestHandshakeInternals_StatusToggle(t *testing.T) {
	h := &HandshakeInternals{
		pattern:   PatternXX,
		initiator: true,
		status:    StatusSend,
		initIdx:   1, // consumed one initiator msg
		respIdx:   0, // responder not consumed yet
	}
	h.updateStatus()
	if h.status != StatusReceive {
		t.Errorf("expected toggle to StatusReceive, got %d", h.status)
	}

	h.initIdx = 1
	h.respIdx = 1
	h.status = StatusReceive
	h.updateStatus()
	// Now both consumed but XX has 2 init + 1 resp, so respIdx==1 meets pattern limit
	// initIdx=1 < numInitiator=2, so not Ready yet
	if h.status == StatusReady {
		t.Error("should not be ready, initIdx < numInitiator")
	}
}

// TestHandshakeInternals_SetError verifies F63/F164.
func TestHandshakeInternals_SetError(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "test_protocol")
	kp := NewKeyPair([]byte{1, 2, 3}, []byte{4, 5, 6})
	h := &HandshakeInternals{
		symmetricState: ss,
		s:              &kp,
		status:         StatusSend,
	}

	h.setError(ErrCipher)
	if h.status != StatusError {
		t.Error("status should be Error after setError")
	}
}

// TestHandshakeInternals_Destroy verifies F128 and nil-on-destroy.
func TestHandshakeInternals_Destroy(t *testing.T) {
	ss := InitializeSymmetric(&testSha256{}, &testCipher{}, "destroy_test")
	kp := NewKeyPair(make([]byte, 32), make([]byte, 32))
	ekp := NewKeyPair(make([]byte, 32), make([]byte, 32))
	h := &HandshakeInternals{
		symmetricState: ss,
		s:              &kp,
		e:              &ekp,
		status:         StatusSend,
		initIdx:        5,
		respIdx:        3,
		rng:            rand.Reader,
	}

	h.Destroy()

	if h.status != StatusError {
		t.Error("status should be Error after Destroy")
	}
	if h.initIdx != 0 || h.respIdx != 0 {
		t.Error("indices should be zeroed after Destroy")
	}
	if h.rng != nil {
		t.Error("rng should be nil after Destroy")
	}
	if h.symmetricState != nil {
		t.Error("symmetricState should be nil after Destroy")
	}
	if h.s != nil {
		t.Error("s should be nil after Destroy")
	}
	if h.e != nil {
		t.Error("e should be nil after Destroy")
	}
	// GetHandshakeHash should return nil, not panic or return zeros
	if hash := h.GetHandshakeHash(); hash != nil {
		t.Errorf("GetHandshakeHash after Destroy should be nil, got %v", hash)
	}
}

// TestHandshakeInternals_ConcurrentUse verifies F36 atomic guard.
func TestHandshakeInternals_ConcurrentUse(t *testing.T) {
	h := &HandshakeInternals{}

	// First acquire succeeds
	if err := h.acquireUse(); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// Second acquire fails (concurrent use)
	if err := h.acquireUse(); err != ErrConcurrentUse {
		t.Errorf("expected ErrConcurrentUse, got %v", err)
	}

	// Release and re-acquire succeeds
	h.releaseUse()
	if err := h.acquireUse(); err != nil {
		t.Fatalf("re-acquire after release failed: %v", err)
	}
	h.releaseUse()
}

// TestHandshakeInternals_ConcurrentUseRace uses goroutines to exercise the atomic.
func TestHandshakeInternals_ConcurrentUseRace(t *testing.T) {
	h := &HandshakeInternals{}
	var conflicts atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.acquireUse(); err != nil {
				conflicts.Add(1)
				return
			}
			// Simulate brief work
			h.releaseUse()
		}()
	}
	wg.Wait()

	// With 100 goroutines racing, most should see conflicts
	if conflicts.Load() == 0 {
		t.Error("expected at least some concurrent use conflicts")
	}
}

// TestHandshakeInternals_CheckState verifies state checks.
func TestHandshakeInternals_CheckState(t *testing.T) {
	h := &HandshakeInternals{status: StatusSend}
	if err := h.checkState(); err != nil {
		t.Errorf("valid state should not error: %v", err)
	}

	h.status = StatusError
	if err := h.checkState(); err != ErrErrorState {
		t.Errorf("error state should return ErrErrorState, got %v", err)
	}

	h.status = StatusSend
	h.finalized = true
	if err := h.checkState(); err != ErrAlreadyFinished {
		t.Errorf("finalized state should return ErrAlreadyFinished, got %v", err)
	}
}

// TestMessageReader verifies F160 stateful message parsing.
func TestMessageReader(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	r := newMessageReader(data)

	if r.remaining() != 8 {
		t.Errorf("expected 8 remaining, got %d", r.remaining())
	}

	// Read 3 bytes
	chunk, err := r.read(3)
	if err != nil {
		t.Fatalf("read(3) failed: %v", err)
	}
	if len(chunk) != 3 || chunk[0] != 0x01 || chunk[2] != 0x03 {
		t.Errorf("read(3): unexpected result %v", chunk)
	}
	if r.remaining() != 5 {
		t.Errorf("expected 5 remaining, got %d", r.remaining())
	}

	// Read 5 bytes
	chunk, err = r.read(5)
	if err != nil {
		t.Fatalf("read(5) failed: %v", err)
	}
	if len(chunk) != 5 || chunk[0] != 0x04 || chunk[4] != 0x08 {
		t.Errorf("read(5): unexpected result %v", chunk)
	}
	if r.remaining() != 0 {
		t.Errorf("expected 0 remaining, got %d", r.remaining())
	}

	// Read beyond end
	_, err = r.read(1)
	if err == nil {
		t.Fatal("expected error reading beyond end")
	}
}

// TestMessageReader_Rest verifies rest() returns remaining bytes.
func TestMessageReader_Rest(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	r := newMessageReader(data)

	r.read(2) //nolint: errcheck
	rest := r.rest()
	if len(rest) != 2 || rest[0] != 0xCC || rest[1] != 0xDD {
		t.Errorf("rest(): expected [CC DD], got %v", rest)
	}
}

// TestCipherSuite_Fields verifies CipherSuite holds all required fields.
func TestCipherSuite_Fields(t *testing.T) {
	cs := CipherSuite{
		DH:     nil,
		Cipher: nil,
		Hash:   nil,
		EKEM:   nil,
		SKEM:   nil,
	}
	// Just verify the struct compiles with all fields accessible.
	_ = cs.DH
	_ = cs.Cipher
	_ = cs.Hash
	_ = cs.EKEM
	_ = cs.SKEM
}

// TestOptions verifies functional options work correctly.
func TestOptions(t *testing.T) {
	kp := NewKeyPair([]byte{1, 2, 3}, []byte{4, 5, 6})
	remotePub := []byte{7, 8, 9}
	prologue := []byte("test prologue")
	rng := NewDummyRng(0xdeadbeef)

	opts := applyOptions([]Option{
		WithStaticKey(kp),
		WithRemoteStatic(remotePub),
		WithPrologue(prologue),
		WithRNG(rng),
	})

	if opts.staticKey == nil {
		t.Fatal("staticKey should be set")
	}
	if opts.remoteStatic == nil || len(opts.remoteStatic) != 3 {
		t.Fatal("remoteStatic should be set")
	}
	if opts.prologue == nil || string(opts.prologue) != "test prologue" {
		t.Fatal("prologue should be set")
	}
	if opts.rng == nil {
		t.Fatal("rng should be set")
	}

	// Verify deep copy: modifying original doesn't affect option
	kp.Destroy()
	if opts.staticKey.SecretSlice() == nil {
		t.Error("option staticKey should be independent copy")
	}
}

// TestPushPSK verifies PSK queueing through HandshakeInternals.
func TestPushPSK(t *testing.T) {
	h := &HandshakeInternals{}

	psk := make([]byte, PSKLen)
	for i := range psk {
		psk[i] = byte(i)
	}

	if err := h.PushPSK(psk); err != nil {
		t.Fatalf("PushPSK failed: %v", err)
	}

	// Wrong length
	if err := h.PushPSK([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for wrong PSK length")
	}

	// Fill queue
	for i := 0; i < 3; i++ {
		if err := h.PushPSK(psk); err != nil {
			t.Fatalf("PushPSK %d failed: %v", i, err)
		}
	}

	// Queue full
	if err := h.PushPSK(psk); err == nil {
		t.Fatal("expected error for full PSK queue")
	}
}

// TestIsFinished_IsWriteTurn verifies accessor methods.
func TestIsFinished_IsWriteTurn(t *testing.T) {
	h := &HandshakeInternals{status: StatusReady}
	if !h.IsFinished() {
		t.Error("StatusReady should be finished")
	}
	if h.IsWriteTurn() {
		t.Error("StatusReady should not be write turn")
	}

	h.status = StatusSend
	if h.IsFinished() {
		t.Error("StatusSend should not be finished")
	}
	if !h.IsWriteTurn() {
		t.Error("StatusSend should be write turn")
	}

	h.status = StatusReceive
	if h.IsWriteTurn() {
		t.Error("StatusReceive should not be write turn")
	}
}
