package clatter

import "fmt"

// hybridDualLayerDomain is the domain separator mixed into the inner handshake
// after the outer handshake completes. Exact bytes from Rust Clatter constants.rs.
// Any deviation produces silent incompatibility.
// Unexported to prevent external mutation of the shared slice.
var hybridDualLayerDomain = []byte("clatter.hybrid_dual_layer.outer")

// DualLayerHandshake wraps two independent handshakers: outer completes first,
// then inner runs with all messages encrypted by the outer's transport keys.
// Port of Rust Clatter's dual_layer.rs.
//
// WARNING: This is a naive approach which does NOT cryptographically bind
// the layers together. Use HybridDualLayerHandshake for bound layers.
//
// The buffer is sized at runtime from the inner handshake max message.
// During inner phase, overhead includes the outer transport tag.
// Two consecutive writes are possible (always use IsWriteTurn).
// go-clatter adds the outer tag to overhead, which differs from Clatter
// upstream (which may undercount).
type DualLayerHandshake struct {
	outer          Handshaker
	inner          Handshaker
	outerTransport *TransportState
	outerFinished  bool
	finalized      bool   // guards against double-finalize
	outerRecvBuf   []byte // sized to max inner message
	initiator      bool
}

// NewDualLayerHandshake creates a dual-layer handshake.
// outer completes first, then inner benefits from outer's transport encryption.
// bufSize is the intermediate decrypt buffer size. Must be large enough for
// all inner handshake messages (calculated at runtime).
//
// Returns error if:
// - outer and inner have different roles (both must be initiator or both responder)
// - outer is a one-way pattern (Rust asserts this)
func NewDualLayerHandshake(outer, inner Handshaker, bufSize int) (*DualLayerHandshake, error) {
	return newDualLayerGeneric(outer, inner, bufSize)
}

// newDualLayerGeneric creates a dual-layer handshake validating role parity and one-way.
func newDualLayerGeneric(outer, inner Handshaker, bufSize int) (*DualLayerHandshake, error) {
	outerInit := getInitiator(outer)
	innerInit := getInitiator(inner)

	if outerInit != innerInit {
		return nil, fmt.Errorf("%w: outer and inner must have same role", ErrInvalidPattern)
	}

	// Rust: assert!(!outer.get_pattern().is_one_way())
	if outerPattern := getPattern(outer); outerPattern != nil && outerPattern.IsOneWay() {
		return nil, fmt.Errorf("%w: outer handshake must not be a one-way pattern", ErrInvalidPattern)
	}

	return &DualLayerHandshake{
		outer:        outer,
		inner:        inner,
		outerRecvBuf: make([]byte, bufSize),
		initiator:    outerInit,
	}, nil
}

// getInitiator extracts the initiator flag from any Handshaker.
func getInitiator(h Handshaker) bool {
	switch hs := h.(type) {
	case *NqHandshake:
		return hs.initiator
	case *PqHandshake:
		return hs.initiator
	case *HybridHandshake:
		return hs.initiator
	default:
		// Infer from status: initiator starts in Send state
		return h.IsWriteTurn()
	}
}

// getPattern extracts the HandshakePattern from any Handshaker.
func getPattern(h Handshaker) *HandshakePattern {
	switch hs := h.(type) {
	case *NqHandshake:
		return hs.pattern
	case *PqHandshake:
		return hs.pattern
	case *HybridHandshake:
		return hs.pattern
	default:
		return nil
	}
}

// OuterCompleted returns true when the outer handshake has finished.
func (dl *DualLayerHandshake) OuterCompleted() bool {
	return dl.outerFinished
}

// updateOuterState checks if the outer handshake finished and transitions.
// Called after BOTH write and read operations.
// Plain DualLayer: no domain binding (outer finalized, transport stored).
func (dl *DualLayerHandshake) updateOuterState() error {
	if dl.outer != nil && dl.outer.IsFinished() {
		ts, err := dl.outer.Finalize()
		// Nil outer regardless of error - Finalize zeroed its state (Rust move semantics).
		// Keeping a reference to a poisoned handshaker causes confusion.
		dl.outer = nil
		if err != nil {
			return err
		}
		dl.outerTransport = ts
		dl.outerFinished = true
	}
	return nil
}

// WriteMessage writes the next handshake message.
// During outer phase: delegates to outer handshaker.
// During inner phase: inner writes to out, then outer transport encrypts in-place.
// Buffer must account for inner message + outer transport tag.
// MaxMessageLen checked at this layer (Rust traits.rs wrapper does the same).
func (dl *DualLayerHandshake) WriteMessage(payload, out []byte) (int, error) {
	if dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if dl.outerFinished {
		// Check total output won't exceed MaxMessageLen
		overhead, err := dl.GetNextMessageOverhead()
		if err != nil {
			return 0, err
		}
		totalNeeded := len(payload) + overhead
		if totalNeeded > MaxMessageLen {
			return 0, ErrMessageTooLarge
		}
		// Check output buffer can hold inner message + outer transport tag
		if len(out) < totalNeeded {
			return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, totalNeeded, len(out))
		}

		// Inner phase: inner writes, outer encrypts in-place
		n, err := dl.inner.WriteMessage(payload, out)
		if err != nil {
			return 0, err
		}
		// Bounds check before SendInPlace
		n, err = dl.outerTransport.SendInPlace(out, n)
		if err != nil {
			return 0, err
		}
		return n, nil
	}

	// Outer phase: delegate to outer
	n, err := dl.outer.WriteMessage(payload, out)
	if err != nil {
		return 0, err
	}
	// updateOuterState after write
	if err := dl.updateOuterState(); err != nil {
		return 0, err
	}
	return n, nil
}

// ReadMessage reads and processes an incoming handshake message.
// During outer phase: delegates to outer handshaker.
// During inner phase: outer transport decrypts into outerRecvBuf, then inner reads.
func (dl *DualLayerHandshake) ReadMessage(message, out []byte) (int, error) {
	if dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if dl.outerFinished {
		// Inner phase: outer decrypts, inner reads
		n, err := dl.outerTransport.Receive(message, dl.outerRecvBuf)
		if err != nil {
			return 0, err
		}
		payloadN, readErr := dl.inner.ReadMessage(dl.outerRecvBuf[:n], out)
		// Zero decrypted inner message from buffer immediately after inner reads
		zeroSlice(dl.outerRecvBuf[:n])
		if readErr != nil {
			return 0, readErr
		}
		return payloadN, nil
	}

	// Outer phase: delegate to outer
	n, err := dl.outer.ReadMessage(message, out)
	if err != nil {
		return 0, err
	}
	// updateOuterState after read
	if err := dl.updateOuterState(); err != nil {
		return 0, err
	}
	return n, nil
}

// IsFinished returns true when the inner handshake is complete.
func (dl *DualLayerHandshake) IsFinished() bool {
	if dl.outerFinished {
		if dl.inner == nil {
			return false
		}
		return dl.inner.IsFinished()
	}
	if dl.outer != nil {
		return dl.outer.IsFinished()
	}
	return false
}

// IsWriteTurn returns true when it's our turn to send a message.
// Always check this - two consecutive writes are possible.
func (dl *DualLayerHandshake) IsWriteTurn() bool {
	if dl.outerFinished {
		if dl.inner == nil {
			return false
		}
		return dl.inner.IsWriteTurn()
	}
	if dl.outer != nil {
		return dl.outer.IsWriteTurn()
	}
	return false
}

// Finalize extracts the INNER transport state and destroys the outer.
// Guards against double-finalize.
func (dl *DualLayerHandshake) Finalize() (*TransportState, error) {
	if dl.finalized {
		return nil, ErrAlreadyFinished
	}
	if dl.inner == nil || !dl.inner.IsFinished() {
		return nil, ErrNotFinished
	}

	ts, err := dl.inner.Finalize()
	if err != nil {
		return nil, err
	}

	// Destroy outer transport (secrets zeroed)
	if dl.outerTransport != nil {
		dl.outerTransport.Destroy()
		dl.outerTransport = nil
	}

	// Zero receive buffer
	zeroSlice(dl.outerRecvBuf)

	dl.finalized = true
	return ts, nil
}

// GetNextMessageOverhead returns the byte overhead for the next message.
// When inner phase is active, includes the outer transport tag.
// This differs from Clatter upstream which may undercount.
func (dl *DualLayerHandshake) GetNextMessageOverhead() (int, error) {
	if dl.outerFinished {
		overhead, err := dl.inner.GetNextMessageOverhead()
		if err != nil {
			return 0, err
		}
		// Add outer transport tag
		return overhead + TagLen, nil
	}
	if dl.outer != nil {
		return dl.outer.GetNextMessageOverhead()
	}
	return 0, ErrInvalidState
}

// PushPSK is not applicable for dual-layer handshakes.
// Rust panics on this call; Go returns error.
func (dl *DualLayerHandshake) PushPSK(_ []byte) error {
	return fmt.Errorf("%w: PSK not applicable for dual-layer handshakes", ErrInvalidState)
}

// GetHandshakeHash returns the inner handshake's hash.
func (dl *DualLayerHandshake) GetHandshakeHash() []byte {
	if dl.inner == nil {
		return nil
	}
	return dl.inner.GetHandshakeHash()
}

// Destroy zeros all state in both layers.
func (dl *DualLayerHandshake) Destroy() {
	if dl.outer != nil {
		dl.outer.Destroy()
		dl.outer = nil
	}
	if dl.inner != nil {
		dl.inner.Destroy()
		dl.inner = nil
	}
	if dl.outerTransport != nil {
		dl.outerTransport.Destroy()
		dl.outerTransport = nil
	}
	zeroSlice(dl.outerRecvBuf)
	dl.finalized = true // prevent use after destroy
}

// Compile-time check
var _ Handshaker = (*DualLayerHandshake)(nil)

// HybridDualLayerHandshake is like DualLayerHandshake but cryptographically binds
// the two layers together by mixing the outer handshake hash into the inner.
// Port of Rust Clatter's hybrid_dual_layer.rs.
//
// After the outer handshake completes:
//
//	MixHash("clatter.hybrid_dual_layer.outer")
//	MixKeyAndHash(h_outer)
//
// This ensures the inner transport keys contain entropy from both handshakes.
// The domain separator must be exact bytes for cross-implementation compatibility.
type HybridDualLayerHandshake struct {
	dl DualLayerHandshake // embedded for shared logic
}

// NewHybridDualLayerHandshake creates a hybrid dual-layer handshake.
// Same as DualLayerHandshake but with domain separator binding.
func NewHybridDualLayerHandshake(outer, inner Handshaker, bufSize int) (*HybridDualLayerHandshake, error) {
	base, err := newDualLayerGeneric(outer, inner, bufSize)
	if err != nil {
		return nil, err
	}
	return &HybridDualLayerHandshake{dl: *base}, nil
}

// mixHashIntoInner performs MixHash and MixKeyAndHash on the inner handshaker's
// symmetric state, regardless of the concrete inner type.
func (hdl *HybridDualLayerHandshake) mixHashIntoInner(domain, h []byte) error {
	switch inner := hdl.dl.inner.(type) {
	case *NqHandshake:
		inner.symmetricState.MixHash(domain)
		return inner.symmetricState.MixKeyAndHash(h)
	case *PqHandshake:
		inner.symmetricState.MixHash(domain)
		return inner.symmetricState.MixKeyAndHash(h)
	case *HybridHandshake:
		inner.symmetricState.MixHash(domain)
		return inner.symmetricState.MixKeyAndHash(h)
	default:
		return fmt.Errorf("%w: unsupported inner handshake type for hybrid dual-layer", ErrInvalidState)
	}
}

// updateOuterState is the hybrid version that mixes the domain separator.
func (hdl *HybridDualLayerHandshake) updateOuterState() error {
	if hdl.dl.outer != nil && hdl.dl.outer.IsFinished() {
		ts, err := hdl.dl.outer.Finalize()
		hdl.dl.outer = nil // consumed regardless of error
		if err != nil {
			return err
		}
		hdl.dl.outerTransport = ts
		hdl.dl.outerFinished = true

		// Mix domain separator and outer hash into inner handshake
		// Copy domain to prevent mutation of shared state
		domain := make([]byte, len(hybridDualLayerDomain))
		copy(domain, hybridDualLayerDomain)
		h := hdl.dl.outerTransport.GetHandshakeHash()
		if err := hdl.mixHashIntoInner(domain, h); err != nil {
			zeroSlice(h)
			// Inner is now in inconsistent state (MixHash succeeded, MixKeyAndHash failed).
			// Destroy inner to prevent use with corrupted handshake hash.
			if hdl.dl.inner != nil {
				hdl.dl.inner.Destroy()
				hdl.dl.inner = nil
			}
			hdl.dl.finalized = true
			return err
		}
		zeroSlice(h)
	}
	return nil
}

// WriteMessage writes the next handshake message.
// MaxMessageLen checked at this layer.
func (hdl *HybridDualLayerHandshake) WriteMessage(payload, out []byte) (int, error) {
	if hdl.dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if hdl.dl.outerFinished {
		// Check total output won't exceed MaxMessageLen
		overhead, err := hdl.GetNextMessageOverhead()
		if err != nil {
			return 0, err
		}
		totalNeeded := len(payload) + overhead
		if totalNeeded > MaxMessageLen {
			return 0, ErrMessageTooLarge
		}
		if len(out) < totalNeeded {
			return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, totalNeeded, len(out))
		}

		n, err := hdl.dl.inner.WriteMessage(payload, out)
		if err != nil {
			return 0, err
		}
		return hdl.dl.outerTransport.SendInPlace(out, n)
	}

	n, err := hdl.dl.outer.WriteMessage(payload, out)
	if err != nil {
		return 0, err
	}
	if err := hdl.updateOuterState(); err != nil {
		return 0, err
	}
	return n, nil
}

// ReadMessage reads and processes an incoming handshake message.
func (hdl *HybridDualLayerHandshake) ReadMessage(message, out []byte) (int, error) {
	if hdl.dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if hdl.dl.outerFinished {
		n, err := hdl.dl.outerTransport.Receive(message, hdl.dl.outerRecvBuf)
		if err != nil {
			return 0, err
		}
		payloadN, readErr := hdl.dl.inner.ReadMessage(hdl.dl.outerRecvBuf[:n], out)
		// Zero decrypted inner message from buffer immediately
		zeroSlice(hdl.dl.outerRecvBuf[:n])
		if readErr != nil {
			return 0, readErr
		}
		return payloadN, nil
	}

	n, err := hdl.dl.outer.ReadMessage(message, out)
	if err != nil {
		return 0, err
	}
	if err := hdl.updateOuterState(); err != nil {
		return 0, err
	}
	return n, nil
}

// IsFinished returns true when the inner handshake is complete.
func (hdl *HybridDualLayerHandshake) IsFinished() bool {
	return hdl.dl.IsFinished()
}

// IsWriteTurn returns true when it's our turn to send a message.
func (hdl *HybridDualLayerHandshake) IsWriteTurn() bool {
	return hdl.dl.IsWriteTurn()
}

// Finalize extracts the INNER transport state and destroys the outer.
func (hdl *HybridDualLayerHandshake) Finalize() (*TransportState, error) {
	return hdl.dl.Finalize()
}

// GetNextMessageOverhead returns the byte overhead for the next message.
func (hdl *HybridDualLayerHandshake) GetNextMessageOverhead() (int, error) {
	return hdl.dl.GetNextMessageOverhead()
}

// PushPSK is not applicable for hybrid dual-layer handshakes.
func (hdl *HybridDualLayerHandshake) PushPSK(_ []byte) error {
	return fmt.Errorf("%w: PSK not applicable for dual-layer handshakes", ErrInvalidState)
}

// GetHandshakeHash returns the inner handshake's hash.
func (hdl *HybridDualLayerHandshake) GetHandshakeHash() []byte {
	return hdl.dl.GetHandshakeHash()
}

// Destroy zeros all state in both layers.
func (hdl *HybridDualLayerHandshake) Destroy() {
	hdl.dl.Destroy()
}

// OuterCompleted returns true when the outer handshake has finished.
func (hdl *HybridDualLayerHandshake) OuterCompleted() bool {
	return hdl.dl.OuterCompleted()
}

// Compile-time check
var _ Handshaker = (*HybridDualLayerHandshake)(nil)
