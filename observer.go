package clatter

// Direction indicates whether a handshake message was sent or received.
type Direction uint8

const (
	Sent     Direction = iota // We wrote the message
	Received                  // We read the message
)

// String returns the direction name.
func (d Direction) String() string {
	switch d {
	case Sent:
		return "Sent"
	case Received:
		return "Received"
	default:
		return "Unknown"
	}
}

// HandshakeType identifies the concrete handshake implementation.
type HandshakeType uint8

const (
	TypeNQ              HandshakeType = iota // Classical DH-only
	TypePQ                                   // KEM-only (post-quantum)
	TypeHybrid                               // DH + KEM combined
	TypeDualLayer                            // Two-layer (unbound)
	TypeHybridDualLayer                      // Two-layer (cryptographically bound)
)

// String returns the handshake type name.
func (t HandshakeType) String() string {
	switch t {
	case TypeNQ:
		return "NQ"
	case TypePQ:
		return "PQ"
	case TypeHybrid:
		return "Hybrid"
	case TypeDualLayer:
		return "DualLayer"
	case TypeHybridDualLayer:
		return "HybridDualLayer"
	default:
		return "Unknown"
	}
}

// Phase indicates which layer of a dual-layer handshake fired the event.
type Phase uint8

const (
	SinglePhase Phase = iota // Non-dual-layer handshake (NQ, PQ, Hybrid)
	OuterPhase               // Outer handshake of a dual-layer
	InnerPhase               // Inner handshake of a dual-layer
)

// String returns the phase name.
func (p Phase) String() string {
	switch p {
	case SinglePhase:
		return "Single"
	case OuterPhase:
		return "Outer"
	case InnerPhase:
		return "Inner"
	default:
		return "Unknown"
	}
}

// HandshakeEvent reports the state after a handshake message is processed.
// All byte slice fields are fresh copies owned by the observer. Mutating them
// does not affect the handshake state.
//
// Remote key fields are non-nil only when the corresponding key was LEARNED
// in this message (nil->non-nil transition). WriteMessage events always have
// nil remote key fields (we sent, we didn't learn).
type HandshakeEvent struct {
	// MessageIndex is a zero-based counter incremented on each successful
	// Write or Read. Continuous across phases for dual-layer handshakes.
	MessageIndex int

	// Direction indicates whether we sent or received this message.
	Direction Direction

	// Phase indicates which layer of a dual-layer handshake fired.
	Phase Phase

	// HandshakeType identifies the concrete handshake implementation.
	HandshakeType HandshakeType

	// IsInitiator is true if this handshake side is the initiator.
	IsInitiator bool

	// ProtocolName is the full Noise protocol name (e.g.
	// "Noise_XX_25519_ChaChaPoly_SHA256"). Empty for DualLayer-level events
	// (individual layer observers have correct names).
	ProtocolName string

	// HandshakeHash is a copy of h after processing this message.
	HandshakeHash []byte

	// PayloadLen is the byte length of the decrypted payload (Read) or
	// plaintext payload provided (Write). Zero for empty payloads.
	PayloadLen int

	// IsComplete is true on the final event (Finalize). After this event,
	// the handshake state is destroyed.
	IsComplete bool

	// Remote DH keys learned in this message (nil if not learned here).
	RemoteEphemeralDH []byte
	RemoteStaticDH    []byte

	// Remote KEM keys learned in this message (nil if not learned here).
	RemoteEphemeralKEM []byte
	RemoteStaticKEM    []byte
}

// HandshakeErrorEvent reports a fatal handshake error.
// After this event, the handshake is in error state and all secrets are zeroed.
type HandshakeErrorEvent struct {
	// MessageIndex is the index of the message that failed.
	MessageIndex int

	// Direction indicates which operation failed.
	Direction Direction

	// Phase indicates which layer failed (for dual-layer).
	Phase Phase

	// HandshakeType identifies the concrete handshake implementation.
	HandshakeType HandshakeType

	// IsInitiator is true if this handshake side is the initiator.
	IsInitiator bool

	// Err is the error that caused the handshake to fail.
	Err error
}

// Observer receives notifications about handshake progress.
// Implementations MUST return quickly from both methods. Long-running
// operations (logging to disk, network calls) should use a channel send.
//
// Concurrency: go-clatter guarantees single-goroutine access per handshake.
// However, a shared Observer instance used across multiple handshakes will
// receive concurrent calls from different goroutines and MUST be safe for
// concurrent use.
//
// Panics: If OnMessage panics, go-clatter recovers and attempts to deliver
// a HandshakeErrorEvent with the panic info via OnError. If OnError also
// panics, the panic is silently discarded. The handshake continues normally
// in both cases.
//
// Error semantics: OnError fires ONLY on fatal protocol errors (decryption
// failure, DH failure, KEM failure, invalid message). After OnError, the
// handshake is dead - all secrets are zeroed, and all subsequent operations
// return ErrErrorState. API-misuse errors (ErrBufferTooSmall before
// processing, ErrConcurrentUse, ErrAlreadyFinished, ErrNotFinished) do NOT
// fire OnError because the handshake state is not corrupted.
//
// Re-entrancy: Calling back into the handshake (WriteMessage, ReadMessage,
// Finalize) from within an observer callback will return ErrConcurrentUse
// because the atomic guard is still held.
//
// Extensibility: Future versions may add optional observer interfaces
// (checked via type assertion at runtime) rather than adding methods to
// this interface. This preserves backward compatibility for all existing
// implementations.
type Observer interface {
	// OnMessage is called after each successful handshake message and on
	// Finalize (with IsComplete=true). Called on the handshake goroutine.
	OnMessage(HandshakeEvent)

	// OnError is called when a fatal error transitions the handshake to
	// error state. Called on the handshake goroutine.
	OnError(HandshakeErrorEvent)
}

// WithObserver sets an observer for the handshake. The observer is immutable
// after construction (no SetObserver method exists). A nil observer is valid
// and results in zero overhead (nil check only, no allocations).
func WithObserver(obs Observer) Option {
	return func(o *handshakeOptions) {
		o.observer = obs
	}
}
