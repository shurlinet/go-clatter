package clatter

import (
	"errors"
	"fmt"
)

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
//
// Only WithObserver and WithMaxMessageLen are accepted by the constructor; all
// other options are rejected with ErrInvalidOption (configure keys, prologue,
// rng, and SEEC per layer on the inner and outer handshakes).
type DualLayerHandshake struct {
	outer          Handshaker
	inner          Handshaker
	outerTransport *TransportState
	outerFinished  bool
	finalized      bool   // guards against double-finalize
	outerRecvBuf   []byte // sized to max inner message
	initiator      bool
	observer       Observer // DualLayer-level observer
	msgIndex       int      // continuous across outer+inner phases
	maxMsgLen      int      // DualLayer-level message limit (0 = MaxMessageLen)
}

// NewDualLayerHandshake creates a dual-layer handshake.
// outer completes first, then inner benefits from outer's transport encryption.
// bufSize is the intermediate decrypt buffer size. Must be large enough for
// all inner handshake messages (calculated at runtime).
//
// Options: only WithObserver and WithMaxMessageLen are applicable. Every other
// option (WithStaticKey, WithEphemeralKey, WithRemoteStatic, WithPrologue,
// WithRNG, WithSEEC, WithStaticKEMKey, WithRemoteStaticKEMKey,
// WithEphemeralKEMKey) is REJECTED with ErrInvalidOption: the layers are
// pre-constructed Handshakers, so key, prologue, rng, and SEEC options must be
// configured per layer on the inner and outer constructors. Rejecting rather
// than silently dropping them stops a caller from believing an option took
// effect when it did not (for SEEC, believing both layers are hedged when
// neither is). WithMaxMessageLen sets the DualLayer-level limit; the inner
// handshake's own maxMsgLen is not modified.
//
// Returns error if:
//   - outer and inner have different roles (both must be initiator or both responder)
//   - outer is a one-way pattern (Rust asserts this)
//   - maxMsgLen is negative or exceeds MaxMessageLen
//   - any inapplicable option was passed (see Options above) - returns ErrInvalidOption
func NewDualLayerHandshake(outer, inner Handshaker, bufSize int, opts ...Option) (*DualLayerHandshake, error) {
	return newDualLayerGeneric(outer, inner, bufSize, opts...)
}

// newDualLayerGeneric creates a dual-layer handshake validating role parity and one-way.
func newDualLayerGeneric(outer, inner Handshaker, bufSize int, opts ...Option) (*DualLayerHandshake, error) {
	// A negative bufSize would panic in make(); reject it as an error.
	// (An undersized positive buffer fails safely at runtime with a
	// bounds-checked Receive error.)
	if bufSize < 0 {
		return nil, fmt.Errorf("%w: bufSize must be non-negative, got %d", ErrInvalidPattern, bufSize)
	}

	outerInit := outer.IsInitiator()

	if outerInit != inner.IsInitiator() {
		return nil, fmt.Errorf("%w: outer and inner must have same role", ErrInvalidPattern)
	}

	// Rust: assert!(!outer.get_pattern().is_one_way())
	if outer.IsOneWay() {
		return nil, fmt.Errorf("%w: outer handshake must not be a one-way pattern", ErrInvalidPattern)
	}

	ho := applyOptions(opts)

	// Dual-layer wraps two pre-constructed Handshakers and consumes no key,
	// prologue, rng, or SEEC option. Zero any secret-bearing option clones on
	// every return path: the deferred call runs after the reject below (which
	// reads the still-non-nil option fields), and on success no key-bearing
	// option was accepted, so it is a no-op.
	defer ho.destroyKeyClones()

	// Reject every inapplicable option loudly. A silently dropped key/prologue/
	// rng/SEEC option would leave the caller believing it took effect (for SEEC,
	// believing both layers are hedged when neither is). Only WithObserver and
	// WithMaxMessageLen apply at this layer; everything else is configured per
	// layer on the inner and outer constructors.
	if err := dualLayerInapplicable(&ho); err != nil {
		return nil, err
	}

	maxMsgLen, err := resolveMaxMsgLen(ho.maxMsgLen)
	if err != nil {
		return nil, err
	}

	// Validate: inner's maxMsgLen + outer transport tag must fit within DualLayer limit.
	// During inner phase, every inner message is wrapped by outer transport encryption
	// which adds TagLen (16) bytes. Only validate when a custom (non-default) limit is set,
	// because the default case (both 65535) is architecturally correct - the DualLayer
	// WriteMessage check enforces the composite limit at runtime.
	if maxMsgLen < MaxMessageLen {
		innerMax := inner.MaxMessageLen()
		if innerMax+TagLen > maxMsgLen {
			return nil, fmt.Errorf("%w: maxMsgLen %d too small for inner messages: "+
				"inner maxMsgLen %d + outer tag %d = %d bytes required",
				ErrInvalidPattern, maxMsgLen, innerMax, TagLen, innerMax+TagLen)
		}
	}

	return &DualLayerHandshake{
		outer:        outer,
		inner:        inner,
		outerRecvBuf: make([]byte, bufSize),
		initiator:    outerInit,
		observer:     ho.observer,
		maxMsgLen:    maxMsgLen,
	}, nil
}

// dualLayerInapplicable returns an [ErrInvalidOption] error naming the first
// option that does not apply to a dual-layer wrap-constructor, or nil if only
// the applicable options (WithObserver, WithMaxMessageLen) were passed. The
// wrap-constructors take pre-built inner and outer Handshakers, so key,
// prologue, rng, and SEEC options must be configured per layer on those
// constructors instead; rejecting them here prevents a silent drop. WithRNG(nil)
// is indistinguishable from absent and has no effect, so it is neither detected
// nor rejected.
func dualLayerInapplicable(ho *handshakeOptions) error {
	// Identify the first inapplicable option (fixed order) by name, then build a
	// single uniform message. One template keeps every rejection consistent and
	// avoids per-case message drift.
	var opt string
	switch {
	case ho.seecSet:
		opt = "WithSEEC"
	case ho.prologue != nil:
		opt = "WithPrologue"
	case ho.rng != nil:
		opt = "WithRNG"
	case ho.staticKey != nil:
		opt = "WithStaticKey"
	case ho.ephemeralKey != nil:
		opt = "WithEphemeralKey"
	case ho.ephemeralKEMKey != nil:
		opt = "WithEphemeralKEMKey"
	case ho.staticKEM != nil:
		opt = "WithStaticKEMKey"
	case ho.remoteStatic != nil:
		opt = "WithRemoteStatic"
	case ho.remoteStaticKEM != nil:
		opt = "WithRemoteStaticKEMKey"
	default:
		return nil
	}
	return fmt.Errorf("%w: %s is not applicable to dual-layer handshakes; "+
		"configure it per layer on the inner and outer handshake constructors",
		ErrInvalidOption, opt)
}

// IsInitiator reports whether this dual-layer handshake plays the initiator
// role. Both layers share the role (enforced at construction).
func (dl *DualLayerHandshake) IsInitiator() bool {
	return dl.initiator
}

// IsOneWay always returns false: a dual-layer handshake is interactive by
// construction (its outer handshake is rejected if it uses a one-way pattern).
func (dl *DualLayerHandshake) IsOneWay() bool {
	return false
}

// MaxMessageLen returns the dual-layer-level message length limit.
func (dl *DualLayerHandshake) MaxMessageLen() int {
	return dl.maxMsgLen
}

// dlNotifyMessage delivers a HandshakeEvent to the DualLayer observer with panic recovery.
func (dl *DualLayerHandshake) dlNotifyMessage(event HandshakeEvent) {
	if dl.observer == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			func() {
				defer func() { recover() }()
				dl.observer.OnError(HandshakeErrorEvent{
					MessageIndex:  event.MessageIndex,
					Direction:     event.Direction,
					Phase:         event.Phase,
					HandshakeType: event.HandshakeType,
					IsInitiator:   event.IsInitiator,
					Err:           fmt.Errorf("clatter: observer OnMessage panic: %v", r),
				})
			}()
		}
	}()
	dl.observer.OnMessage(event)
}

// dlNotifyError delivers a HandshakeErrorEvent to the DualLayer observer with panic recovery.
func (dl *DualLayerHandshake) dlNotifyError(event HandshakeErrorEvent) {
	if dl.observer == nil {
		return
	}
	defer func() { recover() }()
	dl.observer.OnError(event)
}

// OuterCompleted returns true when the outer handshake has finished.
func (dl *DualLayerHandshake) OuterCompleted() bool {
	return dl.outerFinished
}

// updateOuterState checks if the outer handshake finished and transitions.
// Called after BOTH write and read operations; dir records which operation
// drove the transition (Sent from WriteMessage, Received from ReadMessage) so a
// finalize error is reported with the accurate Direction.
// Plain DualLayer: no domain binding (outer finalized, transport stored).
func (dl *DualLayerHandshake) updateOuterState(dir Direction) error {
	if dl.outer != nil && dl.outer.IsFinished() {
		ts, err := dl.outer.Finalize()
		// Nil outer regardless of error - Finalize zeroed its state (Rust move semantics).
		// Keeping a reference to a poisoned handshaker causes confusion.
		dl.outer = nil
		if err != nil {
			return dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: dir, Phase: OuterPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
		}
		dl.outerTransport = ts
		dl.outerFinished = true
	}
	return nil
}

// failAndZero zeroes ALL dual-layer secret material - the outer and inner
// handshakes, the outer transport's live session keys, and the receive buffer -
// and marks the handshake finalized. It is the shared cleanup behind both
// Destroy and every fatal-error path (via fail), so a fatal error leaves the
// dual-layer in the same zeroed terminal state as an explicit Destroy (honoring
// the library's zero-secrets-on-error invariant, the same contract single-layer
// setError enforces) and any subsequent Write/Read/Finalize fails closed with
// ErrAlreadyFinished rather than reusing or dereferencing a partially
// torn-down handshake. Idempotent: every field is nil-checked.
func (dl *DualLayerHandshake) failAndZero() {
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
	dl.finalized = true
}

// isRetryableSubError reports whether err from a delegated sub-handshake
// WriteMessage/ReadMessage is a non-corrupting API-misuse error (output buffer
// too small, message too large, or concurrent use). Per the documented observer
// contract (see [Observer.OnError]) these leave the sub-handshake reusable and
// MUST NOT fire OnError; the dual-layer therefore returns them verbatim without
// tearing down either layer - mirroring both the single-layer contract and the
// dual-layer's own pre-flight checks (GetNextMessageOverhead / buffer size).
// Genuinely fatal errors (crypto/protocol failures, or transport-op / bind /
// finalize failures) still route through fail(), so the zero-secrets-on-error
// invariant is preserved.
func isRetryableSubError(err error) bool {
	return errors.Is(err, ErrBufferTooSmall) ||
		errors.Is(err, ErrMessageTooLarge) ||
		errors.Is(err, ErrConcurrentUse)
}

// fail notifies the observer of a fatal error, zeroes all secret material, and
// finalizes, returning event.Err. Every fatal-error path routes through it so
// the zero-secrets-on-error invariant cannot be missed at any single site. The
// observer is notified BEFORE zeroing (msgIndex and state stay readable in the
// callback), matching the single-layer setError ordering.
func (dl *DualLayerHandshake) fail(event HandshakeErrorEvent) error {
	dl.dlNotifyError(event)
	dl.failAndZero()
	return event.Err
}

// WriteMessage writes the next handshake message.
// During outer phase: delegates to outer handshaker.
// During inner phase: inner writes to out, then outer transport encrypts in-place.
// Buffer must account for inner message + outer transport tag.
// Message length checked at this layer against dl.maxMsgLen.
func (dl *DualLayerHandshake) WriteMessage(payload, out []byte) (int, error) {
	if dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if dl.outerFinished {
		// Check total output won't exceed DualLayer limit
		overhead, err := dl.GetNextMessageOverhead()
		if err != nil {
			return 0, err
		}
		totalNeeded := len(payload) + overhead
		if totalNeeded > dl.maxMsgLen {
			return 0, ErrMessageTooLarge
		}
		// Check output buffer can hold inner message + outer transport tag
		if len(out) < totalNeeded {
			return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, totalNeeded, len(out))
		}

		// Inner phase: inner writes, outer encrypts in-place
		n, err := dl.inner.WriteMessage(payload, out)
		if err != nil {
			if isRetryableSubError(err) {
				return 0, err
			}
			return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
		}
		n, err = dl.outerTransport.SendInPlace(out, n)
		if err != nil {
			return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
		}
		dl.dlNotifyMessage(HandshakeEvent{
			MessageIndex:  dl.msgIndex,
			Direction:     Sent,
			Phase:         InnerPhase,
			HandshakeType: TypeDualLayer,
			IsInitiator:   dl.initiator,
			PayloadLen:    len(payload),
		})
		dl.msgIndex++
		return n, nil
	}

	// Outer phase: delegate to outer
	n, err := dl.outer.WriteMessage(payload, out)
	if err != nil {
		if isRetryableSubError(err) {
			return 0, err
		}
		return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Sent, Phase: OuterPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
	}
	// Fire DualLayer observer on outer phase
	dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  dl.msgIndex,
		Direction:     Sent,
		Phase:         OuterPhase,
		HandshakeType: TypeDualLayer,
		IsInitiator:   dl.initiator,
		PayloadLen:    len(payload),
	})
	dl.msgIndex++
	// updateOuterState after write
	if err := dl.updateOuterState(Sent); err != nil {
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
			return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Received, Phase: InnerPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
		}
		payloadN, readErr := dl.inner.ReadMessage(dl.outerRecvBuf[:n], out)
		zeroSlice(dl.outerRecvBuf[:n])
		if readErr != nil {
			if isRetryableSubError(readErr) {
				return 0, readErr
			}
			return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Received, Phase: InnerPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: readErr})
		}
		dl.dlNotifyMessage(HandshakeEvent{
			MessageIndex:  dl.msgIndex,
			Direction:     Received,
			Phase:         InnerPhase,
			HandshakeType: TypeDualLayer,
			IsInitiator:   dl.initiator,
			PayloadLen:    payloadN,
		})
		dl.msgIndex++
		return payloadN, nil
	}

	// Outer phase: delegate to outer
	n, err := dl.outer.ReadMessage(message, out)
	if err != nil {
		if isRetryableSubError(err) {
			return 0, err
		}
		return 0, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Received, Phase: OuterPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
	}
	dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  dl.msgIndex,
		Direction:     Received,
		Phase:         OuterPhase,
		HandshakeType: TypeDualLayer,
		IsInitiator:   dl.initiator,
		PayloadLen:    n,
	})
	dl.msgIndex++
	// updateOuterState after read
	if err := dl.updateOuterState(Received); err != nil {
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
		return nil, dl.fail(HandshakeErrorEvent{MessageIndex: dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeDualLayer, IsInitiator: dl.initiator, Err: err})
	}

	// Set returned TransportState's maxMsgLen to DualLayer's limit
	ts.maxMsgLen = dl.maxMsgLen

	// Fire DualLayer IsComplete event
	dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  dl.msgIndex,
		Direction:     Sent,
		Phase:         InnerPhase,
		HandshakeType: TypeDualLayer,
		IsInitiator:   dl.initiator,
		HandshakeHash: ts.GetHandshakeHash(), // copy from inner transport
		IsComplete:    true,
	})

	// Destroy outer transport (secrets zeroed)
	if dl.outerTransport != nil {
		dl.outerTransport.Destroy()
		dl.outerTransport = nil
	}

	// Zero receive buffer
	zeroSlice(dl.outerRecvBuf)

	dl.finalized = true
	dl.observer = nil
	// maxMsgLen is left set (non-secret limit) so MaxMessageLen() stays
	// race-free against a concurrent caller; post-finalize ops gate on
	// finalized first.
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
	dl.failAndZero() // zero outer, inner, outer transport, recv buffer; finalize
	dl.observer = nil
	// maxMsgLen is left set (non-secret limit) so MaxMessageLen() stays
	// race-free against a concurrent Destroy.
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
//
// Because the outer handshake hash already incorporates the outer prologue, an
// outer-layer prologue binds the inner transitively through this mixing - there
// is no separate wrap-level prologue option (and one would be unsound: the inner
// is already constructed and MixHash is non-associative). As with DualLayer, only
// WithObserver and WithMaxMessageLen are accepted; all other options are rejected
// with ErrInvalidOption.
type HybridDualLayerHandshake struct {
	dl DualLayerHandshake // embedded for shared logic
}

// NewHybridDualLayerHandshake creates a hybrid dual-layer handshake.
// Same as DualLayerHandshake but with domain separator binding.
// Options: only WithObserver and WithMaxMessageLen are applicable; every other
// option is rejected with ErrInvalidOption. Configure key, prologue, rng, and
// SEEC options per layer on the inner and outer handshake constructors. An outer
// prologue still reaches the inner transitively: it is folded into the outer
// handshake hash, which is mixed into the inner at the layer transition.
//
// The inner handshake must be a built-in NQ, PQ, or Hybrid handshake (the only
// types that can be cryptographically bound to the outer layer); a nested
// dual-layer inner, or any external Handshaker, is rejected with
// ErrInvalidPattern at construction.
func NewHybridDualLayerHandshake(outer, inner Handshaker, bufSize int, opts ...Option) (*HybridDualLayerHandshake, error) {
	base, err := newDualLayerGeneric(outer, inner, bufSize, opts...)
	if err != nil {
		return nil, err
	}
	// The hybrid layer binds the inner by mixing the outer hash into its
	// symmetric state at the transition. Only the built-in NQ/PQ/Hybrid
	// handshakes can be bound; refuse anything else (a nested dual-layer, or
	// any external Handshaker) here, at construction, rather than mid-handshake.
	// Do NOT destroy base/inner/outer on this path: inner and outer are
	// caller-owned, and base holds no secret of its own.
	if _, ok := inner.(outerBindable); !ok {
		return nil, fmt.Errorf("%w: inner handshake cannot be cryptographically bound; a hybrid dual-layer inner must be a built-in NQ, PQ, or Hybrid handshake", ErrInvalidPattern)
	}
	return &HybridDualLayerHandshake{dl: *base}, nil
}

// updateOuterState is the hybrid version that mixes the domain separator.
// dir records which operation drove the transition (Sent from WriteMessage,
// Received from ReadMessage) so a finalize or bind error is reported with the
// accurate Direction.
func (hdl *HybridDualLayerHandshake) updateOuterState(dir Direction) error {
	if hdl.dl.outer != nil && hdl.dl.outer.IsFinished() {
		ts, err := hdl.dl.outer.Finalize()
		hdl.dl.outer = nil // consumed regardless of error
		if err != nil {
			return hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: dir, Phase: OuterPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
		}
		hdl.dl.outerTransport = ts
		hdl.dl.outerFinished = true

		// Mix domain separator and outer hash into inner handshake.
		// Copy domain to prevent mutation of shared state.
		domain := make([]byte, len(hybridDualLayerDomain))
		copy(domain, hybridDualLayerDomain)
		h := hdl.dl.outerTransport.GetHandshakeHash()
		// Bind the layers via the inner's outerBindable capability. The
		// construction-time gate in NewHybridDualLayerHandshake guarantees the
		// inner implements outerBindable, so the !ok branch is defense-in-depth:
		// it preserves the pre-interface behavior (an unbindable inner errors
		// with ErrInvalidState rather than silently skipping the binding).
		binder, ok := hdl.dl.inner.(outerBindable)
		if !ok {
			return hdl.failInnerBind(h, dir, fmt.Errorf("%w: inner handshake does not support outer binding", ErrInvalidState))
		}
		if err := binder.bindOuterTransport(domain, h); err != nil {
			return hdl.failInnerBind(h, dir, err)
		}
		zeroSlice(h)
	}
	return nil
}

// failInnerBind handles a failed (or impossible) layer binding: it zeroes the
// outer hash and routes through fail, which notifies the observer and zeroes
// ALL secret material - the live outer transport (already finalized into
// outerTransport before the bind was attempted), the inner (which may be left
// in an inconsistent state if MixHash succeeded but MixKeyAndHash failed), and
// the receive buffer - then finalizes. Shared by the two binding-failure paths
// in updateOuterState so they cannot drift apart. dir is threaded through so the
// bind failure is reported with the accurate Direction (Sent from WriteMessage,
// Received from ReadMessage).
func (hdl *HybridDualLayerHandshake) failInnerBind(h []byte, dir Direction, err error) error {
	zeroSlice(h)
	return hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: dir, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
}

// WriteMessage writes the next handshake message.
// Message length checked at this layer against dl.maxMsgLen.
func (hdl *HybridDualLayerHandshake) WriteMessage(payload, out []byte) (int, error) {
	if hdl.dl.finalized {
		return 0, ErrAlreadyFinished
	}
	if hdl.dl.outerFinished {
		// Check total output won't exceed DualLayer limit
		overhead, err := hdl.GetNextMessageOverhead()
		if err != nil {
			return 0, err
		}
		totalNeeded := len(payload) + overhead
		if totalNeeded > hdl.dl.maxMsgLen {
			return 0, ErrMessageTooLarge
		}
		if len(out) < totalNeeded {
			return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, totalNeeded, len(out))
		}

		n, err := hdl.dl.inner.WriteMessage(payload, out)
		if err != nil {
			if isRetryableSubError(err) {
				return 0, err
			}
			return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
		}
		n, err = hdl.dl.outerTransport.SendInPlace(out, n)
		if err != nil {
			return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
		}
		hdl.dl.dlNotifyMessage(HandshakeEvent{
			MessageIndex:  hdl.dl.msgIndex,
			Direction:     Sent,
			Phase:         InnerPhase,
			HandshakeType: TypeHybridDualLayer,
			IsInitiator:   hdl.dl.initiator,
			PayloadLen:    len(payload),
		})
		hdl.dl.msgIndex++
		return n, nil
	}

	n, err := hdl.dl.outer.WriteMessage(payload, out)
	if err != nil {
		if isRetryableSubError(err) {
			return 0, err
		}
		return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Sent, Phase: OuterPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
	}
	hdl.dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  hdl.dl.msgIndex,
		Direction:     Sent,
		Phase:         OuterPhase,
		HandshakeType: TypeHybridDualLayer,
		IsInitiator:   hdl.dl.initiator,
		PayloadLen:    len(payload),
	})
	hdl.dl.msgIndex++
	if err := hdl.updateOuterState(Sent); err != nil {
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
			return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Received, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
		}
		payloadN, readErr := hdl.dl.inner.ReadMessage(hdl.dl.outerRecvBuf[:n], out)
		zeroSlice(hdl.dl.outerRecvBuf[:n])
		if readErr != nil {
			if isRetryableSubError(readErr) {
				return 0, readErr
			}
			return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Received, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: readErr})
		}
		hdl.dl.dlNotifyMessage(HandshakeEvent{
			MessageIndex:  hdl.dl.msgIndex,
			Direction:     Received,
			Phase:         InnerPhase,
			HandshakeType: TypeHybridDualLayer,
			IsInitiator:   hdl.dl.initiator,
			PayloadLen:    payloadN,
		})
		hdl.dl.msgIndex++
		return payloadN, nil
	}

	n, err := hdl.dl.outer.ReadMessage(message, out)
	if err != nil {
		if isRetryableSubError(err) {
			return 0, err
		}
		return 0, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Received, Phase: OuterPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
	}
	hdl.dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  hdl.dl.msgIndex,
		Direction:     Received,
		Phase:         OuterPhase,
		HandshakeType: TypeHybridDualLayer,
		IsInitiator:   hdl.dl.initiator,
		PayloadLen:    n,
	})
	hdl.dl.msgIndex++
	if err := hdl.updateOuterState(Received); err != nil {
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

// IsInitiator reports whether this handshake plays the initiator role.
func (hdl *HybridDualLayerHandshake) IsInitiator() bool {
	return hdl.dl.IsInitiator()
}

// IsOneWay always returns false (a dual-layer handshake is interactive).
func (hdl *HybridDualLayerHandshake) IsOneWay() bool {
	return hdl.dl.IsOneWay()
}

// MaxMessageLen returns the dual-layer-level message length limit.
func (hdl *HybridDualLayerHandshake) MaxMessageLen() int {
	return hdl.dl.MaxMessageLen()
}

// Finalize extracts the INNER transport state and destroys the outer.
func (hdl *HybridDualLayerHandshake) Finalize() (*TransportState, error) {
	if hdl.dl.finalized {
		return nil, ErrAlreadyFinished
	}
	if hdl.dl.inner == nil || !hdl.dl.inner.IsFinished() {
		return nil, ErrNotFinished
	}

	ts, err := hdl.dl.inner.Finalize()
	if err != nil {
		return nil, hdl.dl.fail(HandshakeErrorEvent{MessageIndex: hdl.dl.msgIndex, Direction: Sent, Phase: InnerPhase, HandshakeType: TypeHybridDualLayer, IsInitiator: hdl.dl.initiator, Err: err})
	}

	// Set returned TransportState's maxMsgLen to DualLayer's limit
	ts.maxMsgLen = hdl.dl.maxMsgLen

	// Fire HybridDualLayer IsComplete event
	hdl.dl.dlNotifyMessage(HandshakeEvent{
		MessageIndex:  hdl.dl.msgIndex,
		Direction:     Sent,
		Phase:         InnerPhase,
		HandshakeType: TypeHybridDualLayer,
		IsInitiator:   hdl.dl.initiator,
		HandshakeHash: ts.GetHandshakeHash(), // copy from inner transport
		IsComplete:    true,
	})

	if hdl.dl.outerTransport != nil {
		hdl.dl.outerTransport.Destroy()
		hdl.dl.outerTransport = nil
	}
	zeroSlice(hdl.dl.outerRecvBuf)
	hdl.dl.finalized = true
	hdl.dl.observer = nil
	// maxMsgLen left set (non-secret) so MaxMessageLen() stays race-free.
	return ts, nil
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
