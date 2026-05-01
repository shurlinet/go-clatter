package clatter

import (
	"crypto/rand"
	"fmt"
)

// Compile-time interface compliance check.
var _ Handshaker = (*NqHandshake)(nil)

// NqHandshake implements the classical (non-quantum) Noise handshake.
// Port of Rust Clatter's nq.rs. Uses DH-only tokens (E, S, EE, ES, SE, SS, PSK).
//
// Finding coverage:
// F11/F79:  buildName produces exact protocol string matching Clatter
// F12:      Ephemeral keys generated INSIDE WriteMessage, never from constructor
// F36:      acquireUse/releaseUse atomic guard against concurrent access
// F57:      ownRandApplied tracked for PSK validity
// F62:      Sticky error state, no recovery
// F138:     PSK validity check on write-side only (Token::S write)
// F151:     Payload encrypt/decrypt always LAST after all tokens
// F152:     Pre-message Token::E has different mix logic than message-body Token::E
// F162:     Destroy() zeros ALL fields
// F164:     setError() called on ANY failure
// F171:     WriteMessage validates buffer size before processing
// F172:     ReadMessage validates message length >= overhead before processing
type NqHandshake struct {
	HandshakeInternals
	dh DH // DH algorithm (X25519)
}

// NewNqHandshake creates a classical DH-only Noise handshake.
// Pattern must be PatternTypeDH. Returns error for PQ or Hybrid patterns.
func NewNqHandshake(
	pattern *HandshakePattern,
	initiator bool,
	suite CipherSuite,
	opts ...Option,
) (*NqHandshake, error) {
	if pattern.Type() != PatternTypeDH {
		return nil, fmt.Errorf("%w: NQ handshake requires DH-only pattern, got %d",
			ErrInvalidPattern, pattern.Type())
	}
	if suite.DH == nil || suite.Cipher == nil || suite.Hash == nil {
		return nil, fmt.Errorf("%w: CipherSuite requires DH, Cipher, and Hash", ErrMissingKey)
	}

	ho := applyOptions(opts)

	rng := ho.rng
	if rng == nil {
		rng = rand.Reader
	}

	hs := &NqHandshake{dh: suite.DH}
	hs.pattern = pattern
	hs.initiator = initiator
	hs.rng = rng
	hs.cipher = suite.Cipher
	hs.hash = suite.Hash

	// Build protocol name and initialize symmetric state
	name := nqBuildName(pattern, suite)
	hs.symmetricState = InitializeSymmetric(suite.Hash, suite.Cipher, name)

	// Mix prologue (Noise spec: always mixed, even if empty)
	hs.symmetricState.MixHash(ho.prologue)

	// Set local static key
	if ho.staticKey != nil {
		hs.s = ho.staticKey
	}

	// Set pre-existing ephemeral key (standard Noise API, matches Rust e: Option<KeyPair>)
	if ho.ephemeralKey != nil {
		hs.e = ho.ephemeralKey
	}

	// Set remote static public key
	if ho.remoteStatic != nil {
		hs.rs = &KeyPair{Public: ho.remoteStatic}
	}

	// Process pre-messages (F152: pre-message E has different mix logic)
	if err := hs.processPreMessages(); err != nil {
		hs.Destroy()
		return nil, err
	}

	// Set initial status
	hs.determineInitialStatus()

	return hs, nil
}

// processPreMessages mixes pre-message tokens into the handshake hash.
// F152: Pre-message Token::E mixes public key + conditional mixKey if hasPSK.
// F46: Pre-message order is DH first, KEM second (NQ has no KEM, so DH only).
func (hs *NqHandshake) processPreMessages() error {
	// Initiator pre-messages
	preInit := hs.pattern.PreInitiator()
	for _, token := range preInit {
		switch token {
		case TokenE:
			if hs.initiator {
				// Our ephemeral - should already be set (unusual for pre-message)
				if hs.e == nil {
					return fmt.Errorf("%w: pre-message e requires ephemeral key", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.e.Public)
			} else {
				// Remote ephemeral
				if hs.re == nil {
					return fmt.Errorf("%w: pre-message re requires remote ephemeral", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.re.Public)
			}
			// F152: conditional mixKey if hasPSK
			if hs.pattern.HasPSK() {
				var pubkey []byte
				if hs.initiator {
					pubkey = hs.e.Public
				} else {
					pubkey = hs.re.Public
				}
				if err := hs.symmetricState.MixKey(pubkey); err != nil {
					return err
				}
			}
		case TokenS:
			if hs.initiator {
				if hs.s == nil {
					return fmt.Errorf("%w: pre-message s requires static key", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.s.Public)
			} else {
				if hs.rs == nil {
					return fmt.Errorf("%w: pre-message rs requires remote static", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.rs.Public)
			}
		default:
			return fmt.Errorf("%w: invalid pre-message token", ErrInvalidPattern)
		}
	}

	// Responder pre-messages
	preResp := hs.pattern.PreResponder()
	for _, token := range preResp {
		switch token {
		case TokenE:
			if !hs.initiator {
				if hs.e == nil {
					return fmt.Errorf("%w: pre-message e requires ephemeral key", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.e.Public)
			} else {
				if hs.re == nil {
					return fmt.Errorf("%w: pre-message re requires remote ephemeral", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.re.Public)
			}
			if hs.pattern.HasPSK() {
				var pubkey []byte
				if !hs.initiator {
					pubkey = hs.e.Public
				} else {
					pubkey = hs.re.Public
				}
				if err := hs.symmetricState.MixKey(pubkey); err != nil {
					return err
				}
			}
		case TokenS:
			if !hs.initiator {
				if hs.s == nil {
					return fmt.Errorf("%w: pre-message s requires static key", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.s.Public)
			} else {
				if hs.rs == nil {
					return fmt.Errorf("%w: pre-message rs requires remote static", ErrMissingKey)
				}
				hs.symmetricState.MixHash(hs.rs.Public)
			}
		default:
			return fmt.Errorf("%w: invalid pre-message token", ErrInvalidPattern)
		}
	}

	return nil
}

// WriteMessage writes the next handshake message.
// F12: Ephemeral keys generated here, never from constructor.
// F36: Acquires exclusive access via atomic guard.
// F151: Payload encrypted LAST after all tokens.
// F164: setError called on ANY failure.
// F171: Buffer size validated before processing.
func (hs *NqHandshake) WriteMessage(payload, out []byte) (int, error) {
	if err := hs.acquireUse(); err != nil {
		return 0, err
	}
	defer hs.releaseUse()

	if err := hs.checkState(); err != nil {
		return 0, err
	}
	if hs.status != StatusSend {
		return 0, ErrInvalidState
	}

	// F171: Check buffer size before processing
	overhead, err := hs.getNextMessageOverheadNQ()
	if err != nil {
		hs.setError(err)
		return 0, err
	}
	needed := overhead + len(payload)
	if needed > MaxMessageLen {
		err = ErrMessageTooLarge
		hs.setError(err)
		return 0, err
	}
	if len(out) < needed {
		return 0, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooSmall, needed, len(out))
	}

	// F66: getNextMessage increments index BEFORE token processing
	tokens, err := hs.getNextMessage()
	if err != nil {
		hs.setError(err)
		return 0, err
	}

	offset := 0

	for _, token := range tokens {
		n, tokenErr := hs.processWriteToken(token, out[offset:])
		if tokenErr != nil {
			hs.setError(tokenErr)
			return 0, tokenErr
		}
		offset += n
	}

	// F86: Post-payload PSK validity check (Rust: after all tokens, before encrypt)
	if len(payload) > 0 && hs.pskApplied && !hs.ownRandApplied {
		err = fmt.Errorf("%w: PSK requires own randomness before payload", ErrPSKInvalid)
		hs.setError(err)
		return 0, err
	}

	// F151: Payload encrypted LAST after all tokens.
	// Always call EncryptAndHash even for empty payload - it MixHashes the result
	// which is required for handshake hash to match Rust (verified empirically).
	ct, encErr := hs.symmetricState.EncryptAndHash(payload)
	if encErr != nil {
		hs.setError(encErr)
		return 0, encErr
	}
	copy(out[offset:], ct)
	offset += len(ct)

	hs.updateStatus()

	return offset, nil
}

// ReadMessage reads and processes an incoming handshake message.
// F36: Acquires exclusive access.
// F151: Payload decrypted LAST.
// F164: setError called on ANY failure.
// F172: Message length validated >= overhead.
func (hs *NqHandshake) ReadMessage(message, out []byte) (int, error) {
	if err := hs.acquireUse(); err != nil {
		return 0, err
	}
	defer hs.releaseUse()

	if err := hs.checkState(); err != nil {
		return 0, err
	}
	if hs.status != StatusReceive {
		return 0, ErrInvalidState
	}

	// F172: Validate message length
	overhead, err := hs.getNextMessageOverheadNQ()
	if err != nil {
		hs.setError(err)
		return 0, err
	}
	if len(message) < overhead {
		err = fmt.Errorf("%w: message too short: %d < %d", ErrInvalidMessage, len(message), overhead)
		hs.setError(err)
		return 0, err
	}
	if len(message) > MaxMessageLen {
		err = ErrMessageTooLarge
		hs.setError(err)
		return 0, err
	}

	// F66: getNextMessage increments index BEFORE token processing
	tokens, err := hs.getNextMessage()
	if err != nil {
		hs.setError(err)
		return 0, err
	}

	// F160: messageReader for stateful parsing
	reader := newMessageReader(message)

	for _, token := range tokens {
		if tokenErr := hs.processReadToken(token, reader); tokenErr != nil {
			hs.setError(tokenErr)
			return 0, tokenErr
		}
	}

	// F151: Payload decrypted LAST.
	// Always call DecryptAndHash even for empty remaining - it MixHashes the ciphertext.
	remaining := reader.rest()
	pt, decErr := hs.symmetricState.DecryptAndHash(remaining)
	if decErr != nil {
		hs.setError(decErr)
		return 0, decErr
	}

	// Validate out buffer can hold decrypted payload
	if len(out) < len(pt) {
		err = fmt.Errorf("%w: payload output buffer too small: need %d, have %d",
			ErrBufferTooSmall, len(pt), len(out))
		hs.setError(err)
		return 0, err
	}

	copy(out, pt)
	payloadLen := len(pt)

	hs.updateStatus()

	return payloadLen, nil
}

// Finalize extracts transport keys and zeros handshake state.
// F117: Sets finalized=true, prevents double-finalize.
// F124: Requires HasKey (at least one MixKey occurred).
func (hs *NqHandshake) Finalize() (*TransportState, error) {
	if err := hs.acquireUse(); err != nil {
		return nil, err
	}
	defer hs.releaseUse()

	if hs.finalized {
		return nil, ErrAlreadyFinished
	}
	if hs.status != StatusReady {
		return nil, ErrNotFinished
	}

	cs1, cs2, err := hs.symmetricState.Split()
	if err != nil {
		hs.setError(err)
		return nil, err
	}

	h := hs.symmetricState.GetHandshakeHash()
	ts := newTransportState(cs1, cs2, hs.pattern, h, hs.initiator)

	hs.finalized = true
	// F162: Zero ALL handshake state after finalize
	hs.Destroy()

	return ts, nil
}

// GetNextMessageOverhead returns the byte overhead for the next message.
func (hs *NqHandshake) GetNextMessageOverhead() (int, error) {
	if err := hs.checkState(); err != nil {
		return 0, err
	}
	return hs.getNextMessageOverheadNQ()
}

// Destroy zeros ALL fields in the NQ handshake.
// F128/F162: Zeros HandshakeInternals + NQ-specific dh field.
func (hs *NqHandshake) Destroy() {
	hs.HandshakeInternals.Destroy()
	hs.dh = nil
}

// getNextMessageOverheadNQ calculates overhead for the next NQ message.
// F68: Simulates has_key() changes during token processing for accurate overhead.
func (hs *NqHandshake) getNextMessageOverheadNQ() (int, error) {
	// Peek at next message tokens without advancing index
	var tokens []Token
	switch {
	case hs.initiator && hs.status == StatusSend:
		if hs.initIdx >= hs.pattern.numInitiator {
			return 0, fmt.Errorf("%w: no more messages", ErrInvalidState)
		}
		msg := &hs.pattern.initiatorMsgs[hs.initIdx]
		tokens = msg.tokens[:msg.count]
	case hs.initiator && hs.status == StatusReceive:
		if hs.respIdx >= hs.pattern.numResponder {
			return 0, fmt.Errorf("%w: no more messages", ErrInvalidState)
		}
		msg := &hs.pattern.responderMsgs[hs.respIdx]
		tokens = msg.tokens[:msg.count]
	case !hs.initiator && hs.status == StatusSend:
		if hs.respIdx >= hs.pattern.numResponder {
			return 0, fmt.Errorf("%w: no more messages", ErrInvalidState)
		}
		msg := &hs.pattern.responderMsgs[hs.respIdx]
		tokens = msg.tokens[:msg.count]
	case !hs.initiator && hs.status == StatusReceive:
		if hs.initIdx >= hs.pattern.numInitiator {
			return 0, fmt.Errorf("%w: no more messages", ErrInvalidState)
		}
		msg := &hs.pattern.initiatorMsgs[hs.initIdx]
		tokens = msg.tokens[:msg.count]
	default:
		return 0, ErrInvalidState
	}

	overhead := 0
	// F68: Simulate has_key() to predict overhead accurately
	hasKey := hs.symmetricState.HasKey()
	dhPubLen := hs.dh.PubKeyLen()

	hasPSK := hs.pattern.HasPSK()

	for _, token := range tokens {
		switch token {
		case TokenE:
			overhead += dhPubLen
			// E with PSK does MixKey(pubkey), establishing a key
			if hasPSK {
				hasKey = true
			}
		case TokenS:
			overhead += dhPubLen
			if hasKey {
				overhead += TagLen
			}
		case TokenEE, TokenES, TokenSE, TokenSS:
			// DH tokens establish keys but add no wire bytes
			hasKey = true
		case TokenPsk:
			hasKey = true
		}
	}

	// Payload tag (when key established)
	if hasKey {
		overhead += TagLen
	}

	return overhead, nil
}

// processWriteToken processes a single token during WriteMessage.
// Returns the number of bytes written to out.
func (hs *NqHandshake) processWriteToken(token Token, out []byte) (int, error) {
	switch token {
	case TokenE:
		return hs.writeTokenE(out)
	case TokenS:
		return hs.writeTokenS(out)
	case TokenEE:
		return 0, hs.doDH(hs.e, hs.re)
	case TokenES:
		if hs.initiator {
			return 0, hs.doDH(hs.e, hs.rs)
		}
		return 0, hs.doDH(hs.s, hs.re)
	case TokenSE:
		if hs.initiator {
			return 0, hs.doDH(hs.s, hs.re)
		}
		return 0, hs.doDH(hs.e, hs.rs)
	case TokenSS:
		return 0, hs.doDH(hs.s, hs.rs)
	case TokenPsk:
		return 0, hs.processTokenPsk()
	default:
		return 0, fmt.Errorf("%w: unsupported NQ token %d", ErrInvalidPattern, token)
	}
}

// processReadToken processes a single token during ReadMessage.
func (hs *NqHandshake) processReadToken(token Token, reader *messageReader) error {
	switch token {
	case TokenE:
		return hs.readTokenE(reader)
	case TokenS:
		return hs.readTokenS(reader)
	case TokenEE:
		return hs.doDH(hs.e, hs.re)
	case TokenES:
		if hs.initiator {
			return hs.doDH(hs.e, hs.rs)
		}
		return hs.doDH(hs.s, hs.re)
	case TokenSE:
		if hs.initiator {
			return hs.doDH(hs.s, hs.re)
		}
		return hs.doDH(hs.e, hs.rs)
	case TokenSS:
		return hs.doDH(hs.s, hs.rs)
	case TokenPsk:
		return hs.processTokenPsk()
	default:
		return fmt.Errorf("%w: unsupported NQ token %d", ErrInvalidPattern, token)
	}
}

// writeTokenE generates or uses pre-set ephemeral key, writes pubkey, mixes.
// F12: Ephemeral generated HERE, inside WriteMessage (unless pre-set via WithEphemeralKey).
// F57: Sets ownRandApplied.
func (hs *NqHandshake) writeTokenE(out []byte) (int, error) {
	if hs.e == nil {
		// No pre-set ephemeral: generate fresh (normal production path)
		kp, err := hs.dh.GenerateKeypair(hs.rng)
		if err != nil {
			return 0, fmt.Errorf("%w: ephemeral keygen: %v", ErrDH, err)
		}
		hs.e = &kp
	}
	// else: pre-set via WithEphemeralKey (test vector path, matches Rust e: Option<KeyPair>)

	// Mix into handshake hash (Rust order: MixHash -> MixKey -> copy -> set flag)
	hs.symmetricState.MixHash(hs.e.Public)

	// F152: Message-body Token::E does conditional mixKey if hasPSK
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.e.Public); err != nil {
			return 0, err
		}
	}

	// Write ephemeral pubkey to output
	n := copy(out, hs.e.Public)

	// F57: Set AFTER crypto ops + write (matches Rust order)
	hs.ownRandApplied = true

	return n, nil
}

// readTokenE reads remote ephemeral from message.
func (hs *NqHandshake) readTokenE(reader *messageReader) error {
	pubLen := hs.dh.PubKeyLen()
	pubBytes, err := reader.read(pubLen)
	if err != nil {
		return err
	}

	hs.re = &KeyPair{Public: make([]byte, pubLen)}
	copy(hs.re.Public, pubBytes)

	hs.symmetricState.MixHash(hs.re.Public)

	// F152: conditional mixKey if hasPSK
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.re.Public); err != nil {
			return err
		}
	}

	return nil
}

// writeTokenS encrypts and writes local static public key.
// F138: PSK validity check on write-side only.
func (hs *NqHandshake) writeTokenS(out []byte) (int, error) {
	if hs.s == nil {
		return 0, fmt.Errorf("%w: static key required for Token::S", ErrMissingKey)
	}

	// F86/F138: PSK validity check - if PSK was applied, must have own randomness
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Token::S", ErrPSKInvalid)
	}

	ct, err := hs.symmetricState.EncryptAndHash(hs.s.Public)
	if err != nil {
		return 0, err
	}

	n := copy(out, ct)
	return n, nil
}

// readTokenS reads and decrypts remote static public key.
func (hs *NqHandshake) readTokenS(reader *messageReader) error {
	readLen := hs.dh.PubKeyLen()
	if hs.symmetricState.HasKey() {
		readLen += TagLen
	}

	data, err := reader.read(readLen)
	if err != nil {
		return err
	}

	pubBytes, err := hs.symmetricState.DecryptAndHash(data)
	if err != nil {
		return err
	}

	hs.rs = &KeyPair{Public: make([]byte, len(pubBytes))}
	copy(hs.rs.Public, pubBytes)

	return nil
}

// doDH performs DH between local keypair and remote public key, then MixKey.
// F78: DH can fail - propagate error.
// F84: Low-order points caught by X25519 impl (returns zeros or error).
func (hs *NqHandshake) doDH(local, remote *KeyPair) error {
	if local == nil || remote == nil {
		return fmt.Errorf("%w: DH requires both keypairs", ErrMissingKey)
	}

	ss, err := hs.dh.DH(*local, remote.Public)
	if err != nil {
		return err
	}
	defer zeroSlice(ss)

	return hs.symmetricState.MixKey(ss)
}

// processTokenPsk mixes a pre-shared key.
// F86: Sets pskApplied for validity checks. Does NOT set ownRandApplied.
// PSK is a pre-shared secret, not locally-generated randomness.
// Only Token::E satisfies the own-randomness requirement in NQ (F90).
func (hs *NqHandshake) processTokenPsk() error {
	psk, err := hs.psks.Pop()
	if err != nil {
		return fmt.Errorf("%w: no PSK available", ErrPSKInvalid)
	}
	defer func() {
		for i := range psk {
			psk[i] = 0
		}
	}()

	hs.pskApplied = true // F86: runtime PSK tracking (NOT ownRandApplied)
	return hs.symmetricState.MixKeyAndHash(psk[:])
}

// nqBuildName constructs the Noise protocol name for NQ handshakes.
// F11/F79: Format: "Noise_{pattern}_{DH}_{Cipher}_{Hash}"
// F154: NQ has exactly one format (simplest of the 5 variants).
func nqBuildName(pattern *HandshakePattern, suite CipherSuite) string {
	return fmt.Sprintf("Noise_%s_%s_%s_%s",
		pattern.Name(),
		suite.DH.Name(),
		suite.Cipher.Name(),
		suite.Hash.Name(),
	)
}
