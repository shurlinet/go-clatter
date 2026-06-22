package clatter

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"sync/atomic"
)

// HandshakeStatus represents the current state of a Noise handshake.
// Message ordering is driven by status combined with pattern indices.
type HandshakeStatus uint8

const (
	StatusSend    HandshakeStatus = iota // Our turn to write
	StatusReceive                        // Their turn to write (we read)
	StatusReady                          // Handshake complete, ready for Finalize
	StatusError                          // Unrecoverable error; all state zeroed
)

// Handshaker is the interface implemented by all handshake types (NQ, PQ, Hybrid).
// WriteMessage/ReadMessage advance the pattern state machine one message at a time.
// Implementations enforce single-goroutine use via an atomic guard, and zero
// all cryptographic state immediately on any error.
type Handshaker interface {
	// WriteMessage writes the next handshake message.
	// payload is optional application data to encrypt with this message.
	// Returns the number of bytes written to out.
	// The output buffer must be large enough for the message overhead plus payload.
	WriteMessage(payload, out []byte) (int, error)

	// ReadMessage reads and processes an incoming handshake message.
	// Returns decrypted payload bytes.
	// Validates that message length covers at least the expected overhead.
	ReadMessage(message, out []byte) (int, error)

	// IsFinished returns true when the handshake is complete (status == Ready).
	IsFinished() bool

	// IsWriteTurn returns true when it's our turn to send a message.
	IsWriteTurn() bool

	// Finalize extracts transport keys and zeros handshake state.
	// Can only be called once; subsequent calls return ErrAlreadyFinished.
	Finalize() (*TransportState, error)

	// GetNextMessageOverhead returns the byte overhead for the next message.
	// Returns error if the pattern index is out of bounds.
	GetNextMessageOverhead() (int, error)

	// PushPSK queues a pre-shared key for the handshake.
	PushPSK(psk []byte) error

	// GetHandshakeHash returns the current handshake hash (h).
	GetHandshakeHash() []byte

	// IsInitiator reports whether this handshake plays the initiator role.
	// The role is fixed at construction; this is safe to call at any time
	// without the concurrency guard.
	IsInitiator() bool

	// IsOneWay reports whether the handshake pattern is one-way (N/K/X).
	// Fixed at construction.
	IsOneWay() bool

	// MaxMessageLen returns the per-handshake maximum message length.
	// Fixed at construction.
	MaxMessageLen() int

	// Destroy zeros ALL fields in the handshake state, including the
	// symmetric state, all keypairs, PSK queue, and KEM state.
	Destroy()
}

// outerBindable is implemented by handshakes whose symmetric state can absorb
// an outer transport's domain separator and handshake hash, binding a dual
// layer. HybridDualLayerHandshake requires its inner handshake to implement it;
// the wrapper dual-layer types deliberately do not, so a nested dual layer is
// refused at construction (fail-closed) instead of mid-handshake.
//
// It is unexported on purpose. Mixing raw bytes into a live transcript is
// internal dual-layer plumbing, not a consumer operation - Rust Clatter keeps
// the equivalent mix_hash/mix_key_and_hash on a crate-private trait for the
// same reason. Only the built-in NQ/PQ/Hybrid handshakes satisfy it; an
// external Handshaker cannot, so it can never be a HybridDualLayer inner (which
// is correct: a sound inner needs the unexported Noise state machine anyway).
type outerBindable interface {
	// bindOuterTransport mixes the domain separator and the outer handshake
	// hash into the inner symmetric state: MixHash(domain) then
	// MixKeyAndHash(outerHash). The caller owns the slices and the zeroing of
	// outerHash. Sound ONLY at the dual-layer transition; mixing into a
	// standalone or in-flight handshake corrupts its handshake hash.
	bindOuterTransport(domain, outerHash []byte) error
}

// HandshakeInternals holds shared state for all handshake implementations.
// Destroy() zeros ALL fields. getNextMessage() uses 4-way dispatch on
// (initiator, status) to select the correct pattern message list.
//
// This struct is embedded by NqHandshake, PqHandshake, HybridHandshake.
type HandshakeInternals struct {
	symmetricState *SymmetricState

	// DH keypairs (used by NQ and Hybrid)
	s  *KeyPair // local static
	e  *KeyPair // local ephemeral
	rs *KeyPair // remote static (public only)
	re *KeyPair // remote ephemeral (public only)

	// Pattern state
	pattern        *HandshakePattern
	initiator      bool
	status         HandshakeStatus
	initIdx        int // initiator message index
	respIdx        int // responder message index
	finalized      bool
	ownRandApplied bool // tracks whether local entropy has been contributed
	pskApplied     bool // tracks whether a PSK token has been processed

	// PSK queue
	psks PSKQueue

	// RNG source (injectable for deterministic testing; defaults to crypto/rand.Reader)
	rng RNG

	// SEEC instance for hedged handshake coins (nil = SEEC off, the
	// default). The handshake BORROWS the instance: Destroy/setError nil
	// this reference but never call the instance's own Destroy - the
	// consumer owns its lifecycle (it is typically shared across many
	// handshakes, which is the PQNoise paper's model).
	seec SEEC

	// Atomic guard against concurrent use. Only one goroutine may
	// call WriteMessage/ReadMessage/Finalize at a time.
	inUse atomic.Uint32

	// Cipher and Hash for creating new primitives
	cipher Cipher
	hash   HashFunc

	// KEM fields (used by PQ and Hybrid) - set by handshake constructors
	ekem KEM // ephemeral KEM
	skem KEM // static KEM

	// Observer fields
	observer      Observer
	msgIndex      int
	protocolName  string
	handshakeType HandshakeType

	// Per-handshake message length limit (default MaxMessageLen = 65535).
	// Immutable after construction. Must be in [1, MaxMessageLen].
	maxMsgLen int
}

// acquireUse attempts to acquire exclusive access for a handshake operation.
// Returns ErrConcurrentUse if another goroutine is already active.
func (h *HandshakeInternals) acquireUse() error {
	if !h.inUse.CompareAndSwap(0, 1) {
		return ErrConcurrentUse
	}
	return nil
}

// releaseUse releases exclusive access.
func (h *HandshakeInternals) releaseUse() {
	h.inUse.Store(0)
}

// checkState validates the handshake is in a usable state.
// Returns sticky error if in error state, or ErrAlreadyFinished if finalized.
func (h *HandshakeInternals) checkState() error {
	if h.status == StatusError {
		return ErrErrorState
	}
	if h.finalized {
		return ErrAlreadyFinished
	}
	return nil
}

// setError records an error and zeros all cryptographic state immediately.
// After this call, status is Error and all secrets are zeroed. No recovery.
// Notifies observer BEFORE zeroing so msgIndex is still readable.
func (h *HandshakeInternals) setError(err error) {
	// Infer direction from current status for error event
	dir := Sent
	if h.status == StatusReceive {
		dir = Received
	}

	// Notify observer before zeroing state
	h.notifyError(HandshakeErrorEvent{
		MessageIndex:  h.msgIndex,
		Direction:     dir,
		Phase:         SinglePhase,
		HandshakeType: h.handshakeType,
		IsInitiator:   h.initiator,
		Err:           err,
	})

	h.status = StatusError
	if h.symmetricState != nil {
		h.symmetricState.SetError(err)
		h.symmetricState = nil
	}
	h.destroyKeys()
	// Drop the borrowed SEEC reference (never destroy it - consumer owns it).
	h.seec = nil
}

// destroyKeys zeros all keypair material and nils pointers.
func (h *HandshakeInternals) destroyKeys() {
	if h.s != nil {
		h.s.Destroy()
		h.s = nil
	}
	if h.e != nil {
		h.e.Destroy()
		h.e = nil
	}
	if h.rs != nil {
		h.rs.Destroy()
		h.rs = nil
	}
	if h.re != nil {
		h.re.Destroy()
		h.re = nil
	}
	h.psks.Destroy()
}

// Destroy zeros ALL fields in the handshake internals, including the
// symmetric state, keypairs, PSK queue, KEM references, and pattern indices.
// All pointers are nil'd after zeroing to prevent stale access.
func (h *HandshakeInternals) Destroy() {
	if h.symmetricState != nil {
		h.symmetricState.Destroy()
		h.symmetricState = nil
	}
	h.destroyKeys()
	h.status = StatusError
	h.initIdx = 0
	h.respIdx = 0
	h.ownRandApplied = false
	h.pskApplied = false
	h.rng = nil
	h.seec = nil // borrowed reference only; the consumer owns the instance
	h.ekem = nil
	h.skem = nil
	h.observer = nil
	// maxMsgLen is intentionally NOT zeroed: it is a non-secret limit, and
	// keeping it set leaves MaxMessageLen() race-free against a concurrent
	// Destroy (the field is then only ever written at construction). Every
	// post-Destroy operation gates on status/finalized before reading it.
}

// notifyMessage delivers a HandshakeEvent to the observer with panic recovery.
// Zero cost when observer is nil (nil check only, no allocation).
// Uses double-recover pattern: if OnMessage panics, tries OnError with panic
// info. If OnError also panics, silently discards.
func (h *HandshakeInternals) notifyMessage(event HandshakeEvent) {
	if h.observer == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// OnMessage panicked. Try to deliver error event.
			func() {
				defer func() { recover() }() // discard OnError panic
				h.observer.OnError(HandshakeErrorEvent{
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
	h.observer.OnMessage(event)
}

// notifyError delivers a HandshakeErrorEvent to the observer with panic recovery.
// Zero cost when observer is nil.
func (h *HandshakeInternals) notifyError(event HandshakeErrorEvent) {
	if h.observer == nil {
		return
	}
	defer func() { recover() }() // discard OnError panic
	h.observer.OnError(event)
}

// IsFinished returns true when the handshake is complete.
// Returns false while another goroutine holds the handshake (a racing read
// of in-flight state would be meaningless); poll again after the operation
// completes.
func (h *HandshakeInternals) IsFinished() bool {
	if err := h.acquireUse(); err != nil {
		return false
	}
	defer h.releaseUse()
	return h.status == StatusReady
}

// IsWriteTurn returns true when it's our turn to send a message.
// Returns false while another goroutine holds the handshake; poll again
// after the operation completes.
func (h *HandshakeInternals) IsWriteTurn() bool {
	if err := h.acquireUse(); err != nil {
		return false
	}
	defer h.releaseUse()
	return h.status == StatusSend
}

// GetHandshakeHash returns a copy of the current handshake hash.
// Returns nil while another goroutine holds the handshake: the hash of an
// in-flight operation must never be used for channel binding.
func (h *HandshakeInternals) GetHandshakeHash() []byte {
	if err := h.acquireUse(); err != nil {
		return nil
	}
	defer h.releaseUse()
	return h.handshakeHash()
}

// handshakeHash returns a copy of the current handshake hash without
// acquiring the concurrency guard. For internal use on paths that already
// hold the guard (observer events, Finalize).
func (h *HandshakeInternals) handshakeHash() []byte {
	if h.symmetricState == nil {
		return nil
	}
	return h.symmetricState.GetHandshakeHash()
}

// PushPSK queues a pre-shared key.
func (h *HandshakeInternals) PushPSK(psk []byte) error {
	return h.psks.Push(psk)
}

// IsInitiator reports whether this handshake plays the initiator role.
// initiator is set once at construction and never mutated (not even by
// Destroy), so no concurrency guard is needed - unlike IsFinished/IsWriteTurn,
// which read in-flight state.
func (h *HandshakeInternals) IsInitiator() bool {
	return h.initiator
}

// IsOneWay reports whether the handshake pattern is one-way (N/K/X).
// pattern is set once at construction by every constructor (which reject a
// nil pattern up front via pattern.Type()) and never nil'd, so this never
// dereferences nil through the public API.
func (h *HandshakeInternals) IsOneWay() bool {
	return h.pattern.IsOneWay()
}

// MaxMessageLen returns the per-handshake maximum message length.
// maxMsgLen is set once at construction and is NOT zeroed by Destroy (it is
// not a secret), so this getter is unconditionally free of data races.
func (h *HandshakeInternals) MaxMessageLen() int {
	return h.maxMsgLen
}

// bindOuterTransport mixes the outer domain separator and handshake hash into
// the symmetric state, binding this handshake as the inner layer of a hybrid
// dual-layer handshake: MixHash(domain) then MixKeyAndHash(outerHash), the
// exact sequence the layer transition needs. Single-goroutine by contract (the
// transition holds no concurrent operation), so it does not acquire the
// concurrency guard. Unexported - see [outerBindable]. Returns ErrInvalidState
// if the state has already been destroyed (nil symmetric state), mirroring the
// other accessors rather than dereferencing nil.
func (h *HandshakeInternals) bindOuterTransport(domain, outerHash []byte) error {
	if h.symmetricState == nil {
		return ErrInvalidState
	}
	h.symmetricState.MixHash(domain)
	return h.symmetricState.MixKeyAndHash(outerHash)
}

// getNextMessage returns the token list for the next message to process.
// The returned slice references the pattern's internal array - DO NOT MODIFY.
// PRECONDITION: caller must call checkState() and acquireUse() before this.
//
// Uses 4-way dispatch on (initiator, status) to select the correct message list.
// The pattern index is incremented BEFORE token processing so that on error
// the handshake cannot retry the same message (errors are non-recoverable).
func (h *HandshakeInternals) getNextMessage() ([]Token, error) {
	switch {
	case h.initiator && h.status == StatusSend:
		// Initiator writing: use initiator pattern at initIdx
		if h.initIdx >= h.pattern.numInitiator {
			return nil, fmt.Errorf("%w: initiator write index overflow", ErrInvalidState)
		}
		msg := &h.pattern.initiatorMsgs[h.initIdx]
		h.initIdx++ // increment BEFORE processing
		return msg.tokens[:msg.count], nil

	case h.initiator && h.status == StatusReceive:
		// Initiator reading: use responder pattern at respIdx
		if h.respIdx >= h.pattern.numResponder {
			return nil, fmt.Errorf("%w: responder read index overflow", ErrInvalidState)
		}
		msg := &h.pattern.responderMsgs[h.respIdx]
		h.respIdx++
		return msg.tokens[:msg.count], nil

	case !h.initiator && h.status == StatusSend:
		// Responder writing: use responder pattern at respIdx
		if h.respIdx >= h.pattern.numResponder {
			return nil, fmt.Errorf("%w: responder write index overflow", ErrInvalidState)
		}
		msg := &h.pattern.responderMsgs[h.respIdx]
		h.respIdx++
		return msg.tokens[:msg.count], nil

	case !h.initiator && h.status == StatusReceive:
		// Responder reading: use initiator pattern at initIdx
		if h.initIdx >= h.pattern.numInitiator {
			return nil, fmt.Errorf("%w: initiator read index overflow", ErrInvalidState)
		}
		msg := &h.pattern.initiatorMsgs[h.initIdx]
		h.initIdx++
		return msg.tokens[:msg.count], nil

	default:
		return nil, ErrInvalidState
	}
}

// updateStatus checks if the handshake is complete after processing a message.
// Ready requires BOTH initiator and responder indices matching pattern lengths.
func (h *HandshakeInternals) updateStatus() {
	if h.initIdx >= h.pattern.numInitiator && h.respIdx >= h.pattern.numResponder {
		h.status = StatusReady
		return
	}

	// Toggle between Send and Receive
	if h.status == StatusSend {
		h.status = StatusReceive
	} else if h.status == StatusReceive {
		h.status = StatusSend
	}
}

// determineInitialStatus sets the initial send/receive status.
// Initiator always sends first. Responder receives first.
func (h *HandshakeInternals) determineInitialStatus() {
	if h.initiator {
		h.status = StatusSend
	} else {
		h.status = StatusReceive
	}
}

// messageReader is a stateful parser for incoming handshake messages.
// It advances through the input buffer, extracting fixed-size fields.
// Used identically across NQ, PQ, and Hybrid handshake read paths.
type messageReader struct {
	data   []byte
	offset int
}

// newMessageReader creates a reader over the given message bytes.
func newMessageReader(data []byte) *messageReader {
	return &messageReader{data: data, offset: 0}
}

// read returns the next n bytes from the message, advancing the offset.
// Returns error if insufficient bytes remain.
func (r *messageReader) read(n int) ([]byte, error) {
	if r.offset+n > len(r.data) {
		return nil, fmt.Errorf("%w: need %d bytes at offset %d, have %d",
			ErrInvalidMessage, n, r.offset, len(r.data))
	}
	result := r.data[r.offset : r.offset+n]
	r.offset += n
	return result, nil
}

// remaining returns the number of unread bytes.
func (r *messageReader) remaining() int {
	return len(r.data) - r.offset
}

// rest returns all remaining unread bytes.
func (r *messageReader) rest() []byte {
	return r.data[r.offset:]
}

// CipherSuite bundles all cryptographic primitive choices for a handshake.
// Created once, passed to handshake constructors. Avoids Go generics by
// using runtime interface dispatch.
//
// Set Experimental to true when using pre-FIPS KEMs (e.g. HQC).
// The constructor rejects experimental suites unless [AllowExperimental] is
// also set to true, providing a two-layer defense against accidental use.
type CipherSuite struct {
	DH           DH       // X25519
	Cipher       Cipher   // ChaCha20Poly1305 or AES-256-GCM
	Hash         HashFunc // SHA256, SHA512, BLAKE2s, BLAKE2b
	EKEM         KEM      // Ephemeral KEM (ML-KEM-768, ML-KEM-1024, or HQC with build tag)
	SKEM         KEM      // Static KEM (same types as EKEM), usually same instance
	Experimental bool     // true for pre-FIPS algorithms (HQC). Requires AllowExperimental.
}

// Option is a functional option for handshake constructors.
type Option func(*handshakeOptions)

type handshakeOptions struct {
	staticKey       *KeyPair
	ephemeralKey    *KeyPair // Pre-set DH ephemeral keypair (NQ/Hybrid; standard Noise API, matches Rust e: Option<KeyPair>)
	ephemeralKEMKey *KeyPair // Pre-set KEM ephemeral keypair (PQ: hs.e, Hybrid: hs.kemE)
	remoteStatic    []byte
	staticKEM       *KeyPair // Hybrid: local static KEM keypair
	remoteStaticKEM []byte   // Hybrid: remote static KEM public key
	prologue        []byte
	rng             RNG
	observer        Observer
	maxMsgLen       int // 0 = default (MaxMessageLen = 65535)
	seec            SEEC
	seecSet         bool // distinguishes WithSEEC(nil) (rejected) from option absent
}

// WithStaticKey sets the local static keypair for the handshake.
//
// On PQ (KEM-only) handshakes the static IS a KEM keypair and is set via this
// option; PQ rejects the Hybrid-only [WithStaticKEMKey].
//
// A pattern in which the local party transmits no static of its own (it sends no
// Token::S and has no own pre-message static, e.g. the anonymous role of NN/NX or
// a one-way N initiator) rejects this option with [ErrInvalidOption]: the preset
// static would never be used, so it fails loudly rather than being silently
// dropped.
//
// The supplied keypair's Public is validated at construction to correspond to its
// secret (the public is re-derived from the secret and constant-time compared); a
// mismatch returns [ErrDH] on NQ/Hybrid (DH static) or [ErrKEMInvalidKey] on PQ
// (KEM static), instead of failing mid-handshake when the keys diverge. For
// X25519 this checks correspondence, not secret canonicity.
func WithStaticKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		if o.staticKey != nil {
			o.staticKey.Destroy()
		}
		clone := kp.Clone()
		o.staticKey = &clone
	}
}

// WithEphemeralKey sets a pre-existing DH ephemeral keypair for the handshake.
// This is a standard Noise API feature (matches Rust Clatter's e: Option<KeyPair>
// constructor parameter, nq.rs line 72). When set, WriteMessage uses this key
// instead of generating a fresh one for Token::E.
//
// NQ and Hybrid handshakes store it as the DH ephemeral (hs.e). PQ handshakes
// reject it with [ErrInvalidOption] (KEM-only, no DH ephemeral - use
// [WithEphemeralKEMKey] for the KEM ephemeral). A pattern in which the local
// party emits no Token::E (an NQ one-way responder) also rejects it, since the
// pre-set ephemeral would never be used.
//
// Primary use: cross-implementation test vectors (Cacophony, Snow) which require
// deterministic ephemeral keys for byte-for-byte ciphertext verification.
//
// The supplied keypair's Public is validated at construction to correspond to its
// secret (re-derived and constant-time compared); a mismatch returns [ErrDH]. For
// X25519 this checks correspondence, not secret canonicity.
func WithEphemeralKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		if o.ephemeralKey != nil {
			o.ephemeralKey.Destroy()
		}
		clone := kp.Clone()
		o.ephemeralKey = &clone
	}
}

// WithRemoteStatic sets the remote party's known static public key.
//
// On PQ handshakes this is the remote KEM static, an encapsulation key the
// handshake encapsulates to; it is structurally validated at construction
// (FIPS 203 Section 7.2) and a malformed key returns [ErrKEMInvalidKey] rather
// than failing mid-handshake at the first encapsulation. On NQ and Hybrid
// handshakes this is the remote DH static, validated by length only: X25519 has
// no invalid 32-byte encodings, and low-order points are rejected at DH time.
//
// This option has effect only when the peer pre-shares its static (the pattern
// gives the peer a pre-message static, e.g. NK/IK/KK). When the remote static is
// instead transmitted in-band (e.g. an XX/IX/XN initiator), it is learned from
// the wire and overwrites any preset before use, so a pattern in which the peer
// pre-shares no static rejects this option with [ErrInvalidOption] rather than
// silently discarding it.
func WithRemoteStatic(pub []byte) Option {
	return func(o *handshakeOptions) {
		o.remoteStatic = make([]byte, len(pub))
		copy(o.remoteStatic, pub)
	}
}

// WithPrologue sets the prologue data for channel binding.
func WithPrologue(data []byte) Option {
	return func(o *handshakeOptions) {
		o.prologue = make([]byte, len(data))
		copy(o.prologue, data)
	}
}

// WithRNG sets the random number generator (default: crypto/rand.Reader).
// Injectable for deterministic testing with DummyRng.
//
// Scope caveat: rng feeds key GENERATION (DH ephemerals, KEM keypair
// seeds). Production ML-KEM ENCAPSULATION ignores it and uses Go's
// internal CSPRNG; only the *Testing KEM variants draw encapsulation
// entropy from rng. Fully deterministic handshakes therefore require
// the Testing KEM constructors in the CipherSuite as well.
func WithRNG(rng RNG) Option {
	return func(o *handshakeOptions) {
		o.rng = rng
	}
}

// WithSEEC enables Static-Ephemeral Entropy Combination for the handshake:
// every ephemeral keypair seed (DH and KEM) and every KEM encapsulation
// coin is drawn through s instead of directly from the handshake rng, so
// the coins stay unpredictable if EITHER the rng or the SEEC secret is
// uncompromised (PQNoise paper, eprint 2022/539). SEEC is wire-invisible:
// a SEEC-enabled party interoperates with any peer, SEEC-enabled or not.
//
// The handshake BORROWS s and never destroys it; one long-lived instance
// shared across many handshakes is the paper's model (the built-in
// [SEECPRF] is safe for that sharing). Destroying s mid-handshake makes
// affected handshakes fail closed on their next draw.
//
// Constructor behavior:
//   - WithSEEC(nil) and typed-nil values (e.g. WithSEEC((*SEECPRF)(nil)))
//     are constructor errors - misconfiguration fails loud, never
//     silently off.
//   - PQ and Hybrid constructors require EKEM and SKEM to implement
//     [CoinsEncapsulator]; otherwise the constructor errors. SEEC never
//     silently downgrades to keygen-only hedging.
//   - DualLayer and HybridDualLayer constructors reject WithSEEC with
//     [ErrInvalidOption] (it is not applicable to a wrapper of pre-built
//     layers); configure SEEC per layer on the inner and outer handshakes.
//
// Interactions:
//   - WithRNG: the rng still supplies the per-call fresh entropy r; with
//     SEEC on, production KEM encapsulation coins derive from that rng
//     stream mixed with the SEEC secret (the v0.5.0 "production
//     encapsulation ignores rng" behavior no longer applies).
//   - WithEphemeralKey / WithEphemeralKEMKey: a pre-set ephemeral skips
//     key generation, so SEEC never fires for that token's keygen draw.
//     NQ honors WithEphemeralKey (DH-e); PQ honors WithEphemeralKEMKey
//     (KEM-e); Hybrid honors both (DH-e and KEM-e independently).
//   - Receiving one-way messages draws nothing: SEEC only covers locally
//     generated coins.
func WithSEEC(s SEEC) Option {
	return func(o *handshakeOptions) {
		o.seec = s
		o.seecSet = true
	}
}

// WithStaticKEMKey sets the local static KEM keypair (Hybrid handshakes only).
// Required for patterns with pre-message S (KK, IK).
//
// NQ and PQ handshakes reject this option with [ErrInvalidOption]: NQ is
// DH-only, and PQ sets its (KEM) static via [WithStaticKey]. Rejecting rather
// than silently dropping it prevents a caller from believing a static was set
// when it was not.
//
// On Hybrid, a pattern in which the role transmits no static of its own (it sends
// no Token::S and has no own pre-message static; Token::S carries the DH and KEM
// static together) also rejects this option with [ErrInvalidOption] for the same
// reason - the preset would never be used.
//
// The supplied keypair's Public is validated at construction to correspond to its
// secret (re-derived and constant-time compared); a mismatch returns
// [ErrKEMInvalidKey], instead of failing mid-handshake when the keys diverge.
func WithStaticKEMKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		if o.staticKEM != nil {
			o.staticKEM.Destroy()
		}
		clone := kp.Clone()
		o.staticKEM = &clone
	}
}

// WithRemoteStaticKEMKey sets the remote static KEM public key (Hybrid handshakes only).
// Required for patterns with pre-message S (NK, KK, XK, IK).
//
// NQ and PQ handshakes reject this option with [ErrInvalidOption]: NQ is
// DH-only, and PQ sets its remote (KEM) static via [WithRemoteStatic].
//
// On Hybrid, this option has effect only when the peer pre-shares its static (a
// pre-message static, e.g. NK/IK). When the remote KEM static is transmitted
// in-band (e.g. a hybridXX initiator) it is learned from the wire and overwrites
// any preset before use, so a pattern in which the peer pre-shares no static
// rejects this option with [ErrInvalidOption] rather than silently discarding it.
//
// The key is structurally validated at construction (FIPS 203 Section 7.2); a
// malformed key returns [ErrKEMInvalidKey] rather than failing mid-handshake at
// the first encapsulation.
func WithRemoteStaticKEMKey(pub []byte) Option {
	return func(o *handshakeOptions) {
		o.remoteStaticKEM = make([]byte, len(pub))
		copy(o.remoteStaticKEM, pub)
	}
}

// WithEphemeralKEMKey sets a pre-existing ephemeral KEM keypair.
// PQ handshakes store it as the ephemeral (hs.e); Hybrid handshakes
// store it as the KEM ephemeral (hs.kemE); NQ handshakes (DH-only)
// reject it with [ErrInvalidOption] - a KEM ephemeral cannot be honored
// by a classical handshake, so the misuse fails at construction rather
// than silently downgrading to classical-only.
//
// It is honored only for a party that emits Token::E (the initiator in every
// built-in PQ pattern; both roles in every built-in Hybrid pattern). A party
// that sends no Token::E - a PQ responder, which only encapsulates to the
// initiator's ephemeral - rejects it with [ErrInvalidOption], since the pre-set
// ephemeral would otherwise be silently ignored.
//
// The keypair is cloned; the caller retains ownership of the original.
// The secret must be in seed form (ML-KEM: 64 bytes, HQC: 32 bytes).
//
// Usage: deterministic test vectors only. In production, ephemeral
// keys should be generated fresh by the handshake (the default).
// Reusing the same keypair across handshakes defeats ephemeral security.
//
// The supplied keypair's Public is validated at construction to correspond to its
// secret (re-derived and constant-time compared); a mismatch returns
// [ErrKEMInvalidKey].
func WithEphemeralKEMKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		if o.ephemeralKEMKey != nil {
			o.ephemeralKEMKey.Destroy()
		}
		clone := kp.Clone()
		o.ephemeralKEMKey = &clone
	}
}

// WithMaxMessageLen sets a per-handshake maximum message length.
// The limit applies to both handshake and transport messages.
//
// Valid range: 1 to MaxMessageLen (65535). Zero means default (65535).
// Values above MaxMessageLen or below zero return an error from the
// handshake constructor.
//
// The constructor validates that maxMsgLen is large enough for every
// message in the pattern. If any message's overhead exceeds the limit,
// the constructor returns a descriptive error identifying which message
// and how many bytes it requires.
//
// For DualLayer handshakes, the outer transport tag (16 bytes) is
// automatically accounted for. The inner handshake's own maxMsgLen
// is not modified; validation ensures the inner's maximum message
// plus the tag fits within the DualLayer limit.
//
// This limit is immutable after construction.
func WithMaxMessageLen(n int) Option {
	return func(o *handshakeOptions) {
		o.maxMsgLen = n
	}
}

// resolveMaxMsgLen validates and resolves the maxMsgLen option value.
// Returns MaxMessageLen (65535) for zero. Returns error for negative or > MaxMessageLen.
func resolveMaxMsgLen(n int) (int, error) {
	if n == 0 {
		return MaxMessageLen, nil
	}
	if n < 0 {
		return 0, fmt.Errorf("%w: maxMsgLen must be non-negative, got %d", ErrInvalidPattern, n)
	}
	if n > MaxMessageLen {
		return 0, fmt.Errorf("%w: maxMsgLen %d exceeds Noise spec maximum %d",
			ErrInvalidPattern, n, MaxMessageLen)
	}
	return n, nil
}

// tokenOverheadFunc computes the wire overhead for a single token.
// hasKey is the current symmetric state key status (mutated by the caller).
type tokenOverheadFunc func(token Token, hasKey *bool) int

// validatePatternMaxMsgLen walks ALL messages in the pattern, simulates HasKey
// evolution, computes the maximum overhead for each message, and returns an error
// if any message's overhead (without payload) exceeds maxMsgLen.
//
// This catches misconfiguration at construction time rather than at the first
// WriteMessage/ReadMessage call, producing a descriptive error message identifying
// which message is too large and how many bytes it requires.
func validatePatternMaxMsgLen(pattern *HandshakePattern, maxMsgLen int, tokenOverhead tokenOverheadFunc) error {
	// Pre-message E with PSK establishes HasKey before the first message body.
	hasKey := pattern.HasPSK() &&
		(patternContainsToken(pattern.preInitiator[:pattern.numPreInit], TokenE) ||
			patternContainsToken(pattern.preResponder[:pattern.numPreResp], TokenE))

	// Walk the interleaved message sequence (shared with the ephemeral-precedence
	// validator) and bound each message's overhead, carrying HasKey across messages.
	return pattern.walkInterleaved(func(writer hsRole, msgNum int, tokens []Token) error {
		overhead := 0
		simKey := hasKey
		for _, token := range tokens {
			overhead += tokenOverhead(token, &simKey)
		}
		// Payload tag when key is established
		if simKey {
			overhead += TagLen
		}

		if overhead > maxMsgLen {
			return fmt.Errorf("%w: maxMsgLen %d too small for %s message %d (requires %d bytes overhead)",
				ErrInvalidPattern, maxMsgLen, writer, msgNum, overhead)
		}

		// Propagate HasKey state for subsequent messages
		hasKey = simKey
		return nil
	})
}

// applyOptions processes functional options into a handshakeOptions struct.
// errEphemeralNoOp builds the rejection for a pre-set ephemeral option that the
// handshake role would never consume: the local party emits no Token::E in this
// pattern, so the pre-set ephemeral never reaches a keygen, the wire, or a DH /
// KEM operation. Rejecting loudly prevents a caller from believing an ephemeral
// was pinned when it was silently ignored. Shared by the NQ / PQ / Hybrid
// constructors so the message stays identical across families.
func errEphemeralNoOp(option, patternName string) error {
	return fmt.Errorf("%w: %s has no effect in pattern %s for this role; it sends no Token::E, so the pre-set ephemeral would never be used", ErrInvalidOption, option, patternName)
}

// errStaticNoOp builds the rejection for a static-key option the handshake role
// would never consume: the role transmits no static of that kind and (for a
// remote static) the peer pre-shares none, so the pre-set key is silently
// ignored. Rejecting loudly prevents a caller from believing a static was set -
// e.g. an identity pinned - when it was dropped. Shared by the NQ / PQ / Hybrid
// constructors so the message stays identical across families.
func errStaticNoOp(option, patternName string) error {
	return fmt.Errorf("%w: %s has no effect in pattern %s for this role; this role uses no static of that kind here (it transmits none, or the remote static is learned in-band and a preset would be overwritten), so the key would be silently ignored", ErrInvalidOption, option, patternName)
}

func applyOptions(opts []Option) handshakeOptions {
	var ho handshakeOptions
	for _, opt := range opts {
		opt(&ho)
	}
	return ho
}

// destroyKeyClones zeroes the secret-bearing keypair clones held by the
// options struct. Constructors call it (via defer) when construction fails
// before the clones are consumed, and directly for option keys the
// handshake family does not use - an ignored WithStaticKey/WithEphemeralKey/
// WithStaticKEMKey/WithEphemeralKEMKey clone must never outlive construction
// unzeroed.
func (ho *handshakeOptions) destroyKeyClones() {
	if ho.staticKey != nil {
		ho.staticKey.Destroy()
		ho.staticKey = nil
	}
	if ho.ephemeralKey != nil {
		ho.ephemeralKey.Destroy()
		ho.ephemeralKey = nil
	}
	if ho.ephemeralKEMKey != nil {
		ho.ephemeralKEMKey.Destroy()
		ho.ephemeralKEMKey = nil
	}
	if ho.staticKEM != nil {
		ho.staticKEM.Destroy()
		ho.staticKEM = nil
	}
}

// validateSuitePrimitives checks the declared geometry of the
// consumer-chosen Hash and Cipher at construction, so a violating
// implementation surfaces as a constructor error instead of a
// slice-out-of-range panic (HashLen beyond the MaxHashLen state arrays)
// or silent wire corruption (a tag or key size the protocol's hardcoded
// framing cannot carry) mid-handshake.
func validateSuitePrimitives(h HashFunc, c Cipher) error {
	if hl, bl := h.HashLen(), h.BlockLen(); hl <= 0 || hl > MaxHashLen || bl <= 0 || hl > bl {
		return fmt.Errorf("%w: HashFunc geometry unusable: hash length %d, block length %d (need 0 < hash length <= block length and hash length <= %d)",
			ErrInvalidSuite, hl, bl, MaxHashLen)
	}
	if tl := c.TagLen(); tl != TagLen {
		return fmt.Errorf("%w: Cipher tag length %d unsupported (the Noise framing requires %d)",
			ErrInvalidSuite, tl, TagLen)
	}
	if kl := c.KeyLen(); kl != KeyLen {
		return fmt.Errorf("%w: Cipher key length %d unsupported (the Noise key schedule requires %d)",
			ErrInvalidSuite, kl, KeyLen)
	}
	return nil
}

// validateKeyLen checks a pre-set public key length from an option against
// the suite's declared length. A wrong-length key would otherwise produce
// a silently malformed wire message (overhead math uses the declared
// length, the copy truncates) that only fails at the remote peer.
func validateKeyLen(what string, got, want int) error {
	if got != want {
		return fmt.Errorf("%w: %s is %d bytes, suite requires %d", ErrInvalidKeyLength, what, got, want)
	}
	return nil
}

// keypairDeriver is the common derivation surface of DH and KEM: both regenerate
// a keypair deterministically from a seed supplied as the RNG. It lets
// validateKeyPairConsistency re-derive a pre-set local keypair's public from its
// secret with no new method on either the DH or the KEM interface.
type keypairDeriver interface {
	GenerateKeypair(RNG) (KeyPair, error)
}

// validateKeyPairConsistency re-derives the public key from kp's secret seed and
// constant-time compares it to kp.Public, proving a pre-set LOCAL keypair's
// Public corresponds to its secret. Without this, a caller-supplied keypair
// whose halves disagree is accepted at construction and fails only mid-handshake
// (the peer's reply decapsulates to a divergent shared secret and the AEAD tag
// check fails) - a confusing late error for a purely local misconfiguration.
//
// Lengths MUST already be validated by the caller: a wrong-length secret makes
// the derive fail with a wrapped entropy error rather than a clean length error,
// so the per-slot length checks run first. A derive error is returned VERBATIM
// (never relabeled as a mismatch, never swallowed as success) so an
// ErrExperimentalNotAllowed or a primitive failure is not mistaken for a bad
// key. The freshly derived keypair carries a secret copy and is zeroed here.
//
// For X25519 this proves correspondence, NOT secret canonicity: the stored
// secret is the raw seed and clamping happens only inside the scalar
// multiplication, so a clamp-equivalent secret that derives to the same public
// is a valid, working keypair and is accepted. On a mismatch (derive succeeds but
// the public differs) it returns mismatchErr (ErrKEMInvalidKey for a KEM slot,
// ErrDH for a DH slot) wrapped with a message naming the slot (what), so the
// caller sees which pre-set keypair is inconsistent rather than a bare sentinel.
func validateKeyPairConsistency(gen keypairDeriver, kp *KeyPair, mismatchErr error, what string) error {
	derived, err := gen.GenerateKeypair(bytes.NewReader(kp.SecretSlice()))
	if err != nil {
		return err
	}
	defer derived.Destroy()
	if subtle.ConstantTimeCompare(derived.Public, kp.Public) != 1 {
		return fmt.Errorf("%w: pre-set %s keypair public does not correspond to its secret", mismatchErr, what)
	}
	return nil
}
