package clatter

import "fmt"

// TransportState holds post-handshake encryption keys for secure communication.
// Port of Rust Clatter's transportstate.rs.
//
// Message length violations return errors (never panic). One-way patterns
// enforce directional restrictions: only the initiator may send, only the
// responder may receive. SetReceivingNonce is provided for nonce synchronization;
// SetSendingNonce is intentionally absent (callers should not manipulate outbound
// nonces). Rekey rotates the cipher key without resetting the nonce counter.
type TransportState struct {
	initiatorToResponder *CipherState
	responderToInitiator *CipherState
	pattern              *HandshakePattern
	h                    []byte // handshake hash (for dual-layer binding)
	maxMsgLen            int    // per-session message length limit
	initiator            bool
	destroyed            bool
}

// newTransportState creates a TransportState from a completed handshake's components.
func newTransportState(cs1, cs2 *CipherState, pattern *HandshakePattern, h []byte, initiator bool, maxMsgLen int) *TransportState {
	return &TransportState{
		initiatorToResponder: cs1,
		responderToInitiator: cs2,
		pattern:              pattern,
		h:                    h,
		maxMsgLen:            maxMsgLen,
		initiator:            initiator,
	}
}

// MaxMessageLen returns the per-session message length limit.
// Returns 0 if the TransportState is nil or destroyed.
func (ts *TransportState) MaxMessageLen() int {
	if ts == nil || ts.destroyed {
		return 0
	}
	return ts.maxMsgLen
}

// Send encrypts payload for sending to the remote party.
// Returns error when payload + tag exceeds the session message length limit,
// or when a responder attempts to send on a one-way pattern.
// If the payload is too large, the caller must fragment at the application
// layer. TransportState does not perform fragmentation.
func (ts *TransportState) Send(payload, out []byte) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	outLen := len(payload) + TagLen
	if outLen > ts.maxMsgLen {
		return 0, ErrMessageTooLarge
	}
	if len(out) < outLen {
		return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, outLen, len(out))
	}

	// One-way pattern enforcement: responder cannot send.
	if ts.pattern != nil && ts.pattern.IsOneWay() && !ts.initiator {
		return 0, ErrOneWayViolation
	}

	cs := ts.sendCipher()
	if cs == nil {
		return 0, ErrMissingKey
	}

	ct, err := cs.EncryptWithAd(nil, payload)
	if err != nil {
		return 0, err
	}
	n := copy(out, ct)
	return n, nil
}

// SendInPlace encrypts msgLen bytes in msg in-place.
// Returns total ciphertext length (msgLen + TagLen).
// The buffer must have room for msgLen + TagLen bytes.
// Used by DualLayer to wrap inner handshake messages with outer transport.
func (ts *TransportState) SendInPlace(msg []byte, msgLen int) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	outLen := msgLen + TagLen
	if outLen > ts.maxMsgLen {
		return 0, ErrMessageTooLarge
	}
	if len(msg) < outLen {
		return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, outLen, len(msg))
	}

	if ts.pattern != nil && ts.pattern.IsOneWay() && !ts.initiator {
		return 0, ErrOneWayViolation
	}

	cs := ts.sendCipher()
	if cs == nil {
		return 0, ErrMissingKey
	}

	return cs.EncryptWithAdInPlace(nil, msg, msgLen)
}

// Receive decrypts a message from the remote party.
// Returns error when message exceeds the session message length limit,
// or when an initiator attempts to receive on a one-way pattern.
func (ts *TransportState) Receive(message, out []byte) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	if len(message) < TagLen {
		return 0, fmt.Errorf("%w: message too short", ErrInvalidMessage)
	}
	if len(message) > ts.maxMsgLen {
		return 0, ErrMessageTooLarge
	}

	if ts.pattern != nil && ts.pattern.IsOneWay() && ts.initiator {
		return 0, ErrOneWayViolation
	}

	cs := ts.receiveCipher()
	if cs == nil {
		return 0, ErrMissingKey
	}

	pt, err := cs.DecryptWithAd(nil, message)
	if err != nil {
		return 0, err
	}
	if len(out) < len(pt) {
		return 0, fmt.Errorf("%w: output buffer too small: need %d, have %d",
			ErrBufferTooSmall, len(pt), len(out))
	}
	n := copy(out, pt)
	return n, nil
}

// ReceiveInPlace decrypts msgLen bytes in msg in-place.
// Returns plaintext length (msgLen - TagLen).
func (ts *TransportState) ReceiveInPlace(msg []byte, msgLen int) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	if msgLen < TagLen {
		return 0, fmt.Errorf("%w: message too short", ErrInvalidMessage)
	}
	if msgLen > ts.maxMsgLen {
		return 0, ErrMessageTooLarge
	}
	if msgLen > len(msg) {
		return 0, fmt.Errorf("%w: msgLen %d exceeds buffer %d", ErrBufferTooSmall, msgLen, len(msg))
	}

	if ts.pattern != nil && ts.pattern.IsOneWay() && ts.initiator {
		return 0, ErrOneWayViolation
	}

	cs := ts.receiveCipher()
	if cs == nil {
		return 0, ErrMissingKey
	}

	return cs.DecryptWithAdInPlace(nil, msg, msgLen)
}

// SendingNonce returns the forthcoming outbound nonce value.
func (ts *TransportState) SendingNonce() uint64 {
	cs := ts.sendCipher()
	if cs == nil {
		return 0
	}
	return cs.Nonce()
}

// ReceivingNonce returns the forthcoming inbound nonce value.
func (ts *TransportState) ReceivingNonce() uint64 {
	cs := ts.receiveCipher()
	if cs == nil {
		return 0
	}
	return cs.Nonce()
}

// SetReceivingNonce sets the forthcoming inbound nonce value.
// Only the receiving nonce may be set; the sending nonce is intentionally
// read-only to prevent callers from desynchronizing the outbound stream.
func (ts *TransportState) SetReceivingNonce(nonce uint64) {
	cs := ts.receiveCipher()
	if cs != nil {
		cs.setNonce(nonce)
	}
}

// RekeySender rekeys the outbound cipher.
// The nonce counter is NOT reset - rekeying only rotates the key material.
func (ts *TransportState) RekeySender() error {
	if ts.destroyed {
		return ErrDestroyed
	}
	cs := ts.sendCipher()
	if cs == nil {
		return ErrMissingKey
	}
	return cs.Rekey()
}

// RekeyReceiver rekeys the inbound cipher.
// The nonce counter is NOT reset - rekeying only rotates the key material.
func (ts *TransportState) RekeyReceiver() error {
	if ts.destroyed {
		return ErrDestroyed
	}
	cs := ts.receiveCipher()
	if cs == nil {
		return ErrMissingKey
	}
	return cs.Rekey()
}

// GetHandshakeHash returns a copy of the session handshake hash.
// Used by HybridDualLayerHandshake to bind layers.
func (ts *TransportState) GetHandshakeHash() []byte {
	if ts.h == nil {
		return nil
	}
	out := make([]byte, len(ts.h))
	copy(out, ts.h)
	return out
}

// Take returns both CipherStates and marks this TransportState as destroyed.
// The caller takes ownership of the returned keys and is responsible for
// destroying them when done.
func (ts *TransportState) Take() (initiatorToResponder, responderToInitiator *CipherState) {
	i2r := ts.initiatorToResponder
	r2i := ts.responderToInitiator
	ts.initiatorToResponder = nil
	ts.responderToInitiator = nil
	ts.destroyed = true
	zeroSlice(ts.h)
	ts.h = nil
	ts.maxMsgLen = 0
	return i2r, r2i
}

// Destroy zeros both CipherStates and the handshake hash.
func (ts *TransportState) Destroy() {
	if ts.initiatorToResponder != nil {
		ts.initiatorToResponder.Destroy()
		ts.initiatorToResponder = nil
	}
	if ts.responderToInitiator != nil {
		ts.responderToInitiator.Destroy()
		ts.responderToInitiator = nil
	}
	zeroSlice(ts.h)
	ts.h = nil
	ts.maxMsgLen = 0
	ts.destroyed = true
}

// IsDestroyed returns true if the TransportState has been destroyed.
func (ts *TransportState) IsDestroyed() bool {
	return ts.destroyed
}

// sendCipher returns the CipherState used for sending.
func (ts *TransportState) sendCipher() *CipherState {
	if ts.initiator {
		return ts.initiatorToResponder
	}
	return ts.responderToInitiator
}

// receiveCipher returns the CipherState used for receiving.
func (ts *TransportState) receiveCipher() *CipherState {
	if ts.initiator {
		return ts.responderToInitiator
	}
	return ts.initiatorToResponder
}
