package clatter

import "fmt"

// Send encrypts payload for sending to the remote party.
// F131: Returns error (not panic) when message exceeds MaxMessageLen.
// F132: One-way enforcement deferred to Batch 5 (full TransportState port).
func (ts *TransportState) Send(payload, out []byte) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	var cs *CipherState
	if ts.initiator {
		cs = ts.initiatorToResponder
	} else {
		cs = ts.responderToInitiator
	}

	if cs == nil {
		return 0, ErrMissingKey
	}

	needed := len(payload) + TagLen
	if needed > MaxMessageLen {
		return 0, ErrMessageTooLarge
	}
	if len(out) < needed {
		return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, needed, len(out))
	}

	ct, err := cs.EncryptWithAd(nil, payload)
	if err != nil {
		return 0, err
	}
	n := copy(out, ct)
	return n, nil
}

// Receive decrypts a message from the remote party.
// F131: Returns error (not panic) when message exceeds MaxMessageLen.
func (ts *TransportState) Receive(message, out []byte) (int, error) {
	if ts.destroyed {
		return 0, ErrDestroyed
	}

	var cs *CipherState
	if ts.initiator {
		cs = ts.responderToInitiator
	} else {
		cs = ts.initiatorToResponder
	}

	if cs == nil {
		return 0, ErrMissingKey
	}

	if len(message) > MaxMessageLen {
		return 0, ErrMessageTooLarge
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

// Destroy zeros both CipherStates.
// F134: TransportState needs explicit Destroy.
func (ts *TransportState) Destroy() {
	if ts.initiatorToResponder != nil {
		ts.initiatorToResponder.Destroy()
		ts.initiatorToResponder = nil
	}
	if ts.responderToInitiator != nil {
		ts.responderToInitiator.Destroy()
		ts.responderToInitiator = nil
	}
	ts.destroyed = true
}
