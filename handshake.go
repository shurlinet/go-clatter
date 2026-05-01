package clatter

import (
	"fmt"
	"sync/atomic"
)

// HandshakeStatus represents the current state of the handshake.
// F9: Message ordering is driven by status + pattern indices.
type HandshakeStatus uint8

const (
	StatusSend    HandshakeStatus = iota // Our turn to write
	StatusReceive                        // Their turn to write (we read)
	StatusReady                          // Handshake complete, ready for Finalize
	StatusError                          // Unrecoverable error (F62)
)

// Handshaker is the interface implemented by all handshake types (NQ, PQ, Hybrid).
// F9: WriteMessage/ReadMessage advance the state machine.
// F36: Implementations MUST check inUse atomic for goroutine safety.
// F162/F164: All implementations must zero state on error via setError.
type Handshaker interface {
	// WriteMessage writes the next handshake message.
	// payload is optional application data to encrypt with this message.
	// Returns the number of bytes written to out.
	// F171: Validates buffer size before processing.
	WriteMessage(payload, out []byte) (int, error)

	// ReadMessage reads and processes an incoming handshake message.
	// Returns decrypted payload bytes.
	// F172: Validates message length >= overhead before processing.
	ReadMessage(message, out []byte) (int, error)

	// IsFinished returns true when the handshake is complete (status == Ready).
	IsFinished() bool

	// IsWriteTurn returns true when it's our turn to send a message.
	IsWriteTurn() bool

	// Finalize extracts transport keys. Zeros handshake state.
	// F117: Sets finalized=true, prevents double-finalize.
	Finalize() (*TransportState, error)

	// GetNextMessageOverhead returns the byte overhead for the next message.
	// F80: Can error (pattern index out of bounds).
	GetNextMessageOverhead() (int, error)

	// PushPSK queues a pre-shared key for the handshake.
	PushPSK(psk []byte) error

	// GetHandshakeHash returns the current handshake hash (h).
	GetHandshakeHash() []byte

	// Destroy zeros ALL fields in the handshake state.
	// F128: Must zero symmetricState, s, e, rs, re, psks, rng, pattern.
	Destroy()
}

// TransportState holds post-handshake encryption keys.
// Placeholder for Batch 5 implementation.
type TransportState struct {
	initiatorToResponder *CipherState
	responderToInitiator *CipherState
	initiator            bool
	destroyed            bool
}

// HandshakeInternals holds shared state for all handshake implementations.
// F128: Destroy() zeros ALL fields.
// F129: getNextMessage() uses 4-way dispatch on (initiator, status).
// F160: messageReader is used for parsing incoming messages.
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
	ownRandApplied bool // F57: tracks local entropy contribution
	pskApplied     bool // F86: tracks whether PSK token processed in this handshake

	// PSK queue
	psks PSKQueue

	// RNG (F70: injectable for testing)
	rng RNG

	// F36: Atomic guard against concurrent use
	inUse atomic.Uint32

	// Cipher and Hash for creating new primitives
	cipher Cipher
	hash   HashFunc

	// KEM fields (used by PQ and Hybrid) - set by handshake constructors
	ekem KEM // ephemeral KEM
	skem KEM // static KEM
}

// acquireUse attempts to acquire exclusive access for a handshake operation.
// F36: Returns error if another goroutine is already using this handshake.
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
// F62: Returns sticky error if in error state.
// F117: Returns error if already finalized.
func (h *HandshakeInternals) checkState() error {
	if h.status == StatusError {
		return ErrErrorState
	}
	if h.finalized {
		return ErrAlreadyFinished
	}
	return nil
}

// setError records an error and zeros all cryptographic state.
// F63/F164: On ANY error, state is wiped immediately. No recovery.
// After this call, status is Error and all secrets are zeroed.
func (h *HandshakeInternals) setError(err error) {
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

// Destroy zeros ALL fields in the handshake internals.
// F128: Must zero symmetricState, s, e, rs, re, psks, rng, ekem, skem, pattern indices.
// All pointers nil'd after zeroing to prevent stale access.
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
// F129: 4-way dispatch on (initiator, status).
// F66: Pattern index is incremented BEFORE token processing.
// F150: After fetch, index already advanced. Errors are non-recoverable.
func (h *HandshakeInternals) getNextMessage() ([]Token, error) {
	switch {
	case h.initiator && h.status == StatusSend:
		// Initiator writing: use initiator pattern at initIdx
		if h.initIdx >= h.pattern.numInitiator {
			return nil, fmt.Errorf("%w: initiator write index overflow", ErrInvalidState)
		}
		msg := &h.pattern.initiatorMsgs[h.initIdx]
		h.initIdx++ // F66: increment BEFORE processing
		return msg.tokens[:msg.count], nil

	case h.initiator && h.status == StatusReceive:
		// Initiator reading: use responder pattern at respIdx (F88)
		if h.respIdx >= h.pattern.numResponder {
			return nil, fmt.Errorf("%w: responder read index overflow", ErrInvalidState)
		}
		msg := &h.pattern.responderMsgs[h.respIdx]
		h.respIdx++ // F66
		return msg.tokens[:msg.count], nil

	case !h.initiator && h.status == StatusSend:
		// Responder writing: use responder pattern at respIdx
		if h.respIdx >= h.pattern.numResponder {
			return nil, fmt.Errorf("%w: responder write index overflow", ErrInvalidState)
		}
		msg := &h.pattern.responderMsgs[h.respIdx]
		h.respIdx++ // F66
		return msg.tokens[:msg.count], nil

	case !h.initiator && h.status == StatusReceive:
		// Responder reading: use initiator pattern at initIdx (F88)
		if h.initIdx >= h.pattern.numInitiator {
			return nil, fmt.Errorf("%w: initiator read index overflow", ErrInvalidState)
		}
		msg := &h.pattern.initiatorMsgs[h.initIdx]
		h.initIdx++ // F66
		return msg.tokens[:msg.count], nil

	default:
		return nil, ErrInvalidState
	}
}

// updateStatus checks if the handshake is complete after processing a message.
// F87: Ready requires BOTH indices matching pattern lengths.
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

// messageReader is a stateful message parser for incoming handshake messages.
// F160: Identical concept across all 3 modules (NQ, PQ, Hybrid).
// Replaces Rust's `get` closure that advances through the input buffer.
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

// CipherSuite bundles all crypto choices for a handshake.
// Created once, passed to constructors. No Go generics needed (F3/F81).
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
	remoteStatic    []byte
	staticKEM       *KeyPair // Hybrid: local static KEM keypair
	remoteStaticKEM []byte   // Hybrid: remote static KEM public key
	prologue        []byte
	rng             RNG
}

// WithStaticKey sets the local static keypair for the handshake.
func WithStaticKey(kp KeyPair) Option {
	return func(o *handshakeOptions) {
		clone := kp.Clone()
		o.staticKey = &clone
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
// F70: Injectable for deterministic testing.
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

// applyOptions processes functional options into a handshakeOptions struct.
func applyOptions(opts []Option) handshakeOptions {
	var ho handshakeOptions
	for _, opt := range opts {
		opt(&ho)
	}
	return ho
}
