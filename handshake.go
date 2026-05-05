package clatter

import (
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

	// Destroy zeros ALL fields in the handshake state, including the
	// symmetric state, all keypairs, PSK queue, and KEM state.
	Destroy()
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
	pattern     *HandshakePattern
	initiator   bool
	status      HandshakeStatus
	initIdx     int // initiator message index
	respIdx     int // responder message index
	finalized      bool
	ownRandApplied bool // tracks whether local entropy has been contributed
	pskApplied     bool // tracks whether a PSK token has been processed

	// PSK queue
	psks PSKQueue

	// RNG source (injectable for deterministic testing; defaults to crypto/rand.Reader)
	rng RNG

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
	h.ekem = nil
	h.skem = nil
	h.observer = nil
	h.maxMsgLen = 0
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
func (h *HandshakeInternals) IsFinished() bool {
	return h.status == StatusReady
}

// IsWriteTurn returns true when it's our turn to send a message.
func (h *HandshakeInternals) IsWriteTurn() bool {
	return h.status == StatusSend
}

// GetHandshakeHash returns a copy of the current handshake hash.
func (h *HandshakeInternals) GetHandshakeHash() []byte {
	if h.symmetricState == nil {
		return nil
	}
	return h.symmetricState.GetHandshakeHash()
}

// PushPSK queues a pre-shared key.
func (h *HandshakeInternals) PushPSK(psk []byte) error {
	return h.psks.Push(psk)
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
type CipherSuite struct {
	DH     DH       // X25519
	Cipher Cipher   // ChaCha20Poly1305 or AES-256-GCM
	Hash   HashFunc // SHA256, SHA512, BLAKE2s, BLAKE2b
	EKEM   KEM      // ML-KEM-768 or 1024 (ephemeral KEM)
	SKEM   KEM      // ML-KEM-768 or 1024 (static KEM), usually same as EKEM
}

// Option is a functional option for handshake constructors.
type Option func(*handshakeOptions)

type handshakeOptions struct {
	staticKey       *KeyPair
	ephemeralKey    *KeyPair // Pre-set ephemeral keypair (standard Noise API, matches Rust e: Option<KeyPair>)
	remoteStatic    []byte
	staticKEM       *KeyPair // Hybrid: local static KEM keypair
	remoteStaticKEM []byte   // Hybrid: remote static KEM public key
	prologue        []byte
	rng             RNG
	observer        Observer
	maxMsgLen       int // 0 = default (MaxMessageLen = 65535)
}

// WithStaticKey sets the local static keypair for the handshake.
func WithStaticKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		clone := kp.Clone()
		o.staticKey = &clone
	}
}

// WithEphemeralKey sets a pre-existing ephemeral keypair for the handshake.
// This is a standard Noise API feature (matches Rust Clatter's e: Option<KeyPair>
// constructor parameter, nq.rs line 72). When set, WriteMessage uses this key
// instead of generating a fresh one for Token::E.
//
// Primary use: cross-implementation test vectors (Cacophony, Snow) which require
// deterministic ephemeral keys for byte-for-byte ciphertext verification.
func WithEphemeralKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		clone := kp.Clone()
		o.ephemeralKey = &clone
	}
}

// WithRemoteStatic sets the remote party's known static public key.
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
func WithRNG(rng RNG) Option {
	return func(o *handshakeOptions) {
		o.rng = rng
	}
}

// WithStaticKEMKey sets the local static KEM keypair (Hybrid handshakes only).
// Required for patterns with pre-message S (KK, IK).
func WithStaticKEMKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		clone := kp.Clone()
		o.staticKEM = &clone
	}
}

// WithRemoteStaticKEMKey sets the remote static KEM public key (Hybrid handshakes only).
// Required for patterns with pre-message S (NK, KK, XK, IK).
func WithRemoteStaticKEMKey(pub []byte) Option {
	return func(o *handshakeOptions) {
		o.remoteStaticKEM = make([]byte, len(pub))
		copy(o.remoteStaticKEM, pub)
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
	// Walk the interleaved message sequence: initiator[0], responder[0], initiator[1], ...
	initIdx := 0
	respIdx := 0
	msgNum := 0
	initiatorTurn := true

	// Pre-message E with PSK establishes HasKey before the first message body.
	// Compute initial HasKey state from pre-messages.
	hasKey := false
	if pattern.HasPSK() {
		preInit := pattern.PreInitiator()
		for _, t := range preInit {
			if t == TokenE {
				hasKey = true
				break
			}
		}
		if !hasKey {
			preResp := pattern.PreResponder()
			for _, t := range preResp {
				if t == TokenE {
					hasKey = true
					break
				}
			}
		}
	}

	for initIdx < pattern.numInitiator || respIdx < pattern.numResponder {
		var tokens []Token
		var role string

		if initiatorTurn && initIdx < pattern.numInitiator {
			msg := &pattern.initiatorMsgs[initIdx]
			tokens = msg.tokens[:msg.count]
			role = "initiator"
			initIdx++
		} else if !initiatorTurn && respIdx < pattern.numResponder {
			msg := &pattern.responderMsgs[respIdx]
			tokens = msg.tokens[:msg.count]
			role = "responder"
			respIdx++
		} else {
			// Toggle for patterns with unequal message counts
			initiatorTurn = !initiatorTurn
			continue
		}

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
				ErrInvalidPattern, maxMsgLen, role, msgNum, overhead)
		}

		// Propagate HasKey state for subsequent messages
		hasKey = simKey
		msgNum++
		initiatorTurn = !initiatorTurn
	}

	return nil
}

// applyOptions processes functional options into a handshakeOptions struct.
func applyOptions(opts []Option) handshakeOptions {
	var ho handshakeOptions
	for _, opt := range opts {
		opt(&ho)
	}
	return ho
}
