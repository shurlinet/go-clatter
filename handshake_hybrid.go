package clatter

import (
	"crypto/rand"
	"fmt"
)

// Compile-time interface compliance check.
var _ Handshaker = (*HybridHandshake)(nil)

// HybridHandshake implements the Hybrid (DH+KEM) Noise handshake.
// Port of Rust Clatter's hybrid.rs. Combines classical DH and post-quantum
// KEM operations in a single symmetric state, achieving true hybrid security.
//
// Token::E generates BOTH DH AND KEM ephemeral keypairs.
// Token::S sends BOTH DH AND KEM static public keys, encrypted with sequential
// nonces from the same CipherState.
// DH tokens (EE/ES/SE/SS) perform classical DH and MixKey.
// Ekem is identical to PQ: MixHash + MixKey (ciphertext in plaintext).
// Skem is identical to PQ: EncryptAndHash + MixKeyAndHash (ciphertext encrypted).
//
// DH keypairs are stored in HandshakeInternals (s/e/rs/re).
// KEM keypairs are stored in the Hybrid-specific fields (kemS/kemE/kemRS/kemRE).
type HybridHandshake struct {
	HandshakeInternals
	dh DH // DH algorithm (X25519)

	// KEM keypairs stored separately from DH keypairs in HandshakeInternals.
	kemS  *KeyPair // local static KEM keypair (SKEM type)
	kemE  *KeyPair // local ephemeral KEM keypair (EKEM type)
	kemRS *KeyPair // remote static KEM public key (SKEM type)
	kemRE *KeyPair // remote ephemeral KEM public key (EKEM type)
}

// NewHybridHandshake creates a Hybrid (DH+KEM) Noise handshake.
// Pattern must be PatternTypeHybrid. Returns error for DH-only or KEM-only patterns.
//
// CipherSuite must have DH, EKEM, SKEM, Cipher, and Hash set.
func NewHybridHandshake(
	pattern *HandshakePattern,
	initiator bool,
	suite CipherSuite,
	opts ...Option,
) (*HybridHandshake, error) {
	if pattern.Type() != PatternTypeHybrid {
		return nil, fmt.Errorf("%w: Hybrid handshake requires Hybrid pattern, got %d",
			ErrInvalidPattern, pattern.Type())
	}
	if suite.DH == nil || suite.EKEM == nil || suite.SKEM == nil || suite.Cipher == nil || suite.Hash == nil {
		return nil, fmt.Errorf("%w: CipherSuite requires DH, EKEM, SKEM, Cipher, and Hash", ErrMissingKey)
	}

	ho := applyOptions(opts)

	rng := ho.rng
	if rng == nil {
		rng = rand.Reader
	}

	hs := &HybridHandshake{dh: suite.DH}
	hs.pattern = pattern
	hs.initiator = initiator
	hs.rng = rng
	hs.cipher = suite.Cipher
	hs.hash = suite.Hash
	hs.ekem = suite.EKEM
	hs.skem = suite.SKEM

	// Build protocol name and initialize symmetric state
	name := hybridBuildName(pattern, suite)
	hs.symmetricState = InitializeSymmetric(suite.Hash, suite.Cipher, name)
	hs.protocolName = name
	hs.handshakeType = TypeHybrid
	hs.observer = ho.observer

	// Mix prologue (Noise spec: always mixed, even if empty)
	hs.symmetricState.MixHash(ho.prologue)

	// Set local DH static key
	if ho.staticKey != nil {
		hs.s = ho.staticKey
	}

	// Set remote DH static public key
	if ho.remoteStatic != nil {
		hs.rs = &KeyPair{Public: ho.remoteStatic}
	}

	// Set KEM static keys from options (needed before pre-message processing)
	if ho.staticKEM != nil {
		hs.kemS = ho.staticKEM
	}
	if ho.remoteStaticKEM != nil {
		hs.kemRS = &KeyPair{Public: ho.remoteStaticKEM}
	}

	// Process pre-messages.
	// Pre-message S mixes BOTH DH and KEM pubkeys.
	// Pre-message E mixes 2 or 4 times depending on PSK.
	if err := hs.processPreMessages(); err != nil {
		hs.Destroy()
		return nil, err
	}

	// Set initial status
	hs.determineInitialStatus()

	return hs, nil
}

// processPreMessages mixes pre-message tokens into the handshake hash.
// Pre-message Token::S does TWO MixHash calls (DH pubkey, then KEM pubkey).
// Pre-message Token::E does MixHash(DH) + MixHash(KEM), plus conditional
// MixKey(DH) + MixKey(KEM) when the pattern uses PSKs.
func (hs *HybridHandshake) processPreMessages() error {
	// Initiator pre-messages
	for _, token := range hs.pattern.PreInitiator() {
		if err := hs.processPreMessageToken(token, hs.initiator); err != nil {
			return err
		}
	}

	// Responder pre-messages
	for _, token := range hs.pattern.PreResponder() {
		if err := hs.processPreMessageToken(token, !hs.initiator); err != nil {
			return err
		}
	}

	return nil
}

// processPreMessageToken processes a single pre-message token.
// isLocal is true if this token refers to our keys.
func (hs *HybridHandshake) processPreMessageToken(token Token, isLocal bool) error {
	switch token {
	case TokenS:
		// TWO MixHash calls: DH pubkey then KEM pubkey
		if isLocal {
			if hs.s == nil {
				return fmt.Errorf("%w: pre-message s requires DH static key", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.s.Public)
			if hs.kemS == nil {
				return fmt.Errorf("%w: pre-message s requires KEM static key", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.kemS.Public)
		} else {
			if hs.rs == nil {
				return fmt.Errorf("%w: pre-message rs requires remote DH static", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.rs.Public)
			if hs.kemRS == nil {
				return fmt.Errorf("%w: pre-message rs requires remote KEM static", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.kemRS.Public)
		}

	case TokenE:
		// MixHash(DH) + MixHash(KEM), then if PSK: MixKey(DH) + MixKey(KEM)
		if isLocal {
			if hs.e == nil {
				return fmt.Errorf("%w: pre-message e requires DH ephemeral key", ErrMissingKey)
			}
			if hs.kemE == nil {
				return fmt.Errorf("%w: pre-message e requires KEM ephemeral key", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.e.Public)
			hs.symmetricState.MixHash(hs.kemE.Public)
			if hs.pattern.HasPSK() {
				if err := hs.symmetricState.MixKey(hs.e.Public); err != nil {
					return err
				}
				if err := hs.symmetricState.MixKey(hs.kemE.Public); err != nil {
					return err
				}
			}
		} else {
			if hs.re == nil {
				return fmt.Errorf("%w: pre-message re requires remote DH ephemeral", ErrMissingKey)
			}
			if hs.kemRE == nil {
				return fmt.Errorf("%w: pre-message re requires remote KEM ephemeral", ErrMissingKey)
			}
			hs.symmetricState.MixHash(hs.re.Public)
			hs.symmetricState.MixHash(hs.kemRE.Public)
			if hs.pattern.HasPSK() {
				if err := hs.symmetricState.MixKey(hs.re.Public); err != nil {
					return err
				}
				if err := hs.symmetricState.MixKey(hs.kemRE.Public); err != nil {
					return err
				}
			}
		}

	default:
		return fmt.Errorf("%w: invalid pre-message token", ErrInvalidPattern)
	}
	return nil
}

// WriteMessage writes the next handshake message.
// Token::E generates BOTH DH AND KEM ephemeral keypairs.
// Token::S encrypts BOTH pubkeys with HasKey checked once for consistency.
// Acquires exclusive access. Validates buffer size before processing.
// Payload is encrypted LAST after all tokens. State is zeroed on any failure.
func (hs *HybridHandshake) WriteMessage(payload, out []byte) (int, error) {
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

	// Check buffer size before processing
	overhead, err := hs.getNextMessageOverheadHybrid()
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

	// getNextMessage increments index BEFORE token processing
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

	// Post-payload PSK validity check
	if len(payload) > 0 && hs.pskApplied && !hs.ownRandApplied {
		err = fmt.Errorf("%w: PSK requires own randomness before payload", ErrPSKInvalid)
		hs.setError(err)
		return 0, err
	}

	// Payload encrypted LAST after all tokens.
	ct, encErr := hs.symmetricState.EncryptAndHash(payload)
	if encErr != nil {
		hs.setError(encErr)
		return 0, encErr
	}
	copy(out[offset:], ct)
	offset += len(ct)

	hs.updateStatus()

	hs.notifyMessage(HandshakeEvent{
		MessageIndex:  hs.msgIndex,
		Direction:     Sent,
		Phase:         SinglePhase,
		HandshakeType: TypeHybrid,
		IsInitiator:   hs.initiator,
		ProtocolName:  hs.protocolName,
		HandshakeHash: hs.GetHandshakeHash(),
		PayloadLen:    len(payload),
	})
	hs.msgIndex++

	return offset, nil
}

// ReadMessage reads and processes an incoming handshake message.
// Acquires exclusive access. Validates message length >= overhead.
// Payload is decrypted LAST. State is zeroed on any failure.
func (hs *HybridHandshake) ReadMessage(message, out []byte) (int, error) {
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

	// Validate message length
	overhead, err := hs.getNextMessageOverheadHybrid()
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

	// getNextMessage increments index BEFORE token processing
	tokens, err := hs.getNextMessage()
	if err != nil {
		hs.setError(err)
		return 0, err
	}

	// Snapshot remote keys before token processing
	preRE := hs.re
	preRS := hs.rs
	preKemRE := hs.kemRE
	preKemRS := hs.kemRS

	// Stateful message parser
	reader := newMessageReader(message)

	for _, token := range tokens {
		if tokenErr := hs.processReadToken(token, reader); tokenErr != nil {
			hs.setError(tokenErr)
			return 0, tokenErr
		}
	}

	// Payload decrypted LAST.
	remaining := reader.rest()
	pt, decErr := hs.symmetricState.DecryptAndHash(remaining)
	if decErr != nil {
		hs.setError(decErr)
		return 0, decErr
	}

	if len(out) < len(pt) {
		err = fmt.Errorf("%w: payload output buffer too small: need %d, have %d",
			ErrBufferTooSmall, len(pt), len(out))
		hs.setError(err)
		return 0, err
	}

	copy(out, pt)
	payloadLen := len(pt)

	hs.updateStatus()

	// Detect learned keys (nil->non-nil transition)
	var learnedRE, learnedRS, learnedKemRE, learnedKemRS []byte
	if preRE == nil && hs.re != nil {
		learnedRE = copyBytes(hs.re.Public)
	}
	if preRS == nil && hs.rs != nil {
		learnedRS = copyBytes(hs.rs.Public)
	}
	if preKemRE == nil && hs.kemRE != nil {
		learnedKemRE = copyBytes(hs.kemRE.Public)
	}
	if preKemRS == nil && hs.kemRS != nil {
		learnedKemRS = copyBytes(hs.kemRS.Public)
	}
	hs.notifyMessage(HandshakeEvent{
		MessageIndex:       hs.msgIndex,
		Direction:          Received,
		Phase:              SinglePhase,
		HandshakeType:      TypeHybrid,
		IsInitiator:        hs.initiator,
		ProtocolName:       hs.protocolName,
		HandshakeHash:      hs.GetHandshakeHash(),
		PayloadLen:         payloadLen,
		RemoteEphemeralDH:  learnedRE,
		RemoteStaticDH:     learnedRS,
		RemoteEphemeralKEM: learnedKemRE,
		RemoteStaticKEM:    learnedKemRS,
	})
	hs.msgIndex++

	return payloadLen, nil
}

// Finalize extracts transport keys and zeros handshake state.
// Can only be called once; subsequent calls return ErrAlreadyFinished.
func (hs *HybridHandshake) Finalize() (*TransportState, error) {
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

	// Notify observer IsComplete BEFORE Destroy
	hs.notifyMessage(HandshakeEvent{
		MessageIndex:  hs.msgIndex,
		Direction:     Sent,
		Phase:         SinglePhase,
		HandshakeType: TypeHybrid,
		IsInitiator:   hs.initiator,
		ProtocolName:  hs.protocolName,
		HandshakeHash: copyBytes(h),
		IsComplete:    true,
	})

	hs.finalized = true
	// Zero ALL handshake state after finalize
	hs.Destroy()

	return ts, nil
}

// GetNextMessageOverhead returns the byte overhead for the next message.
func (hs *HybridHandshake) GetNextMessageOverhead() (int, error) {
	if err := hs.checkState(); err != nil {
		return 0, err
	}
	return hs.getNextMessageOverheadHybrid()
}

// Destroy zeros ALL fields in the Hybrid handshake, including the
// HandshakeInternals, the DH reference, and all KEM keypairs.
func (hs *HybridHandshake) Destroy() {
	hs.HandshakeInternals.Destroy()
	hs.dh = nil
	if hs.kemS != nil {
		hs.kemS.Destroy()
		hs.kemS = nil
	}
	if hs.kemE != nil {
		hs.kemE.Destroy()
		hs.kemE = nil
	}
	if hs.kemRS != nil {
		hs.kemRS.Destroy()
		hs.kemRS = nil
	}
	if hs.kemRE != nil {
		hs.kemRE.Destroy()
		hs.kemRE = nil
	}
}

// getNextMessageOverheadHybrid calculates overhead for the next Hybrid message.
// Includes DH+KEM sizes for E and S tokens. Simulates HasKey state changes
// during token processing for accurate overhead prediction.
// Token::S adds TagLen*2 when HasKey (one tag per pubkey: DH and KEM).
func (hs *HybridHandshake) getNextMessageOverheadHybrid() (int, error) {
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
	hasKey := hs.symmetricState.HasKey()
	hasPSK := hs.pattern.HasPSK()

	for _, token := range tokens {
		switch token {
		case TokenE:
			// DH pubkey + KEM pubkey
			overhead += hs.dh.PubKeyLen()
			overhead += hs.ekem.PubKeyLen()
			if hasPSK {
				hasKey = true
			}
		case TokenS:
			// DH pubkey + KEM pubkey, each with tag when HasKey
			overhead += hs.dh.PubKeyLen()
			overhead += hs.skem.PubKeyLen()
			if hasKey {
				overhead += TagLen * 2 // one tag per pubkey
			}
		case TokenEE, TokenES, TokenSE, TokenSS:
			// DH tokens establish keys but add no wire bytes
			hasKey = true
		case TokenEkem:
			// Ekem ciphertext is plaintext (MixHash only)
			overhead += hs.ekem.CiphertextLen()
			hasKey = true
		case TokenSkem:
			// Skem ciphertext is encrypted (EncryptAndHash adds tag)
			overhead += hs.skem.CiphertextLen()
			if hasKey {
				overhead += TagLen
			}
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
func (hs *HybridHandshake) processWriteToken(token Token, out []byte) (int, error) {
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
	case TokenEkem:
		return hs.writeTokenEkem(out)
	case TokenSkem:
		return hs.writeTokenSkem(out)
	case TokenPsk:
		return 0, hs.processTokenPsk()
	default:
		return 0, fmt.Errorf("%w: unsupported Hybrid token %d", ErrInvalidPattern, token)
	}
}

// processReadToken processes a single token during ReadMessage.
func (hs *HybridHandshake) processReadToken(token Token, reader *messageReader) error {
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
	case TokenEkem:
		return hs.readTokenEkem(reader)
	case TokenSkem:
		return hs.readTokenSkem(reader)
	case TokenPsk:
		return hs.processTokenPsk()
	default:
		return fmt.Errorf("%w: unsupported Hybrid token %d", ErrInvalidPattern, token)
	}
}

// writeTokenE generates BOTH DH AND KEM ephemeral keypairs, writes both public
// keys to the output buffer, and mixes them into the handshake state.
// DH pubkey is written first, then KEM pubkey (matching Rust hybrid.rs order).
// Sets ownRandApplied after all crypto operations complete.
func (hs *HybridHandshake) writeTokenE(out []byte) (int, error) {
	// Generate DH ephemeral if not present
	if hs.e == nil {
		kp, err := hs.dh.GenerateKeypair(hs.rng)
		if err != nil {
			return 0, fmt.Errorf("%w: DH ephemeral keygen: %v", ErrDH, err)
		}
		hs.e = &kp
	}

	// Generate KEM ephemeral if not present
	if hs.kemE == nil {
		kp, err := hs.ekem.GenerateKeypair(hs.rng)
		if err != nil {
			return 0, fmt.Errorf("%w: KEM ephemeral keygen: %v", ErrKEM, err)
		}
		hs.kemE = &kp
	}

	cur := 0

	// Send DH public key: MixHash + conditional MixKey
	hs.symmetricState.MixHash(hs.e.Public)
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.e.Public); err != nil {
			return 0, err
		}
	}
	n := copy(out[cur:], hs.e.Public)
	cur += n

	// Send KEM public key: MixHash + conditional MixKey
	hs.symmetricState.MixHash(hs.kemE.Public)
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.kemE.Public); err != nil {
			return 0, err
		}
	}
	n = copy(out[cur:], hs.kemE.Public)
	cur += n

	// Set AFTER all crypto ops + writes (matches Rust order)
	hs.ownRandApplied = true

	return cur, nil
}

// readTokenE reads BOTH DH AND KEM remote ephemeral public keys.
// Reads DH pubkey then KEM pubkey (matching Rust hybrid.rs order).
func (hs *HybridHandshake) readTokenE(reader *messageReader) error {
	// Read DH ephemeral public key
	dhPubLen := hs.dh.PubKeyLen()
	dhPubBytes, err := reader.read(dhPubLen)
	if err != nil {
		return err
	}

	hs.re = &KeyPair{Public: make([]byte, dhPubLen)}
	copy(hs.re.Public, dhPubBytes)

	hs.symmetricState.MixHash(hs.re.Public)
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.re.Public); err != nil {
			return err
		}
	}

	// Read KEM ephemeral public key
	kemPubLen := hs.ekem.PubKeyLen()
	kemPubBytes, err := reader.read(kemPubLen)
	if err != nil {
		return err
	}

	hs.kemRE = &KeyPair{Public: make([]byte, kemPubLen)}
	copy(hs.kemRE.Public, kemPubBytes)

	hs.symmetricState.MixHash(hs.kemRE.Public)
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.kemRE.Public); err != nil {
			return err
		}
	}

	return nil
}

// writeTokenS encrypts and writes BOTH DH AND KEM static public keys.
// Both EncryptAndHash calls use the same CipherState with sequential nonces:
// DH pubkey gets nonce n, KEM pubkey gets nonce n+1. HasKey state cannot change
// between the two calls (only MixKey/MixKeyAndHash modify it, neither called here).
// Validates PSK own-randomness requirement on write-side.
func (hs *HybridHandshake) writeTokenS(out []byte) (int, error) {
	if hs.s == nil || hs.kemS == nil {
		return 0, fmt.Errorf("%w: static keys required for Token::S", ErrMissingKey)
	}

	// PSK validity check
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Token::S", ErrPSKInvalid)
	}

	cur := 0

	// Encrypt and send DH static public key
	dhCt, err := hs.symmetricState.EncryptAndHash(hs.s.Public)
	if err != nil {
		return 0, err
	}
	n := copy(out[cur:], dhCt)
	cur += n

	// Encrypt and send KEM static public key
	kemCt, err := hs.symmetricState.EncryptAndHash(hs.kemS.Public)
	if err != nil {
		return 0, err
	}
	n = copy(out[cur:], kemCt)
	cur += n

	return cur, nil
}

// readTokenS reads and decrypts BOTH DH AND KEM remote static public keys.
// HasKey is checked once and reused for both DecryptAndHash calls.
func (hs *HybridHandshake) readTokenS(reader *messageReader) error {
	hasKey := hs.symmetricState.HasKey()

	// Read DH static public key
	dhReadLen := hs.dh.PubKeyLen()
	if hasKey {
		dhReadLen += TagLen
	}
	dhData, err := reader.read(dhReadLen)
	if err != nil {
		return err
	}
	dhPubBytes, err := hs.symmetricState.DecryptAndHash(dhData)
	if err != nil {
		return err
	}
	hs.rs = &KeyPair{Public: make([]byte, len(dhPubBytes))}
	copy(hs.rs.Public, dhPubBytes)

	// Read KEM static public key
	kemReadLen := hs.skem.PubKeyLen()
	if hasKey {
		kemReadLen += TagLen
	}
	kemData, err := reader.read(kemReadLen)
	if err != nil {
		return err
	}
	kemPubBytes, err := hs.symmetricState.DecryptAndHash(kemData)
	if err != nil {
		return err
	}
	hs.kemRS = &KeyPair{Public: make([]byte, len(kemPubBytes))}
	copy(hs.kemRS.Public, kemPubBytes)

	return nil
}

// doDH performs DH between a local keypair and a remote public key, then MixKey.
// DH can fail (e.g., low-order points caught by X25519).
func (hs *HybridHandshake) doDH(local, remote *KeyPair) error {
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

// writeTokenEkem encapsulates to the remote ephemeral KEM key.
// Ekem uses MixKey (2-output HKDF), NOT MixKeyAndHash.
// Ekem ciphertext is sent in plaintext (MixHash only, not EncryptAndHash).
// Sets ownRandApplied. Identical to PQ Ekem write.
func (hs *HybridHandshake) writeTokenEkem(out []byte) (int, error) {
	if hs.kemRE == nil {
		return 0, fmt.Errorf("%w: Ekem requires remote ephemeral KEM key", ErrMissingKey)
	}

	ct, ss, err := hs.ekem.Encapsulate(hs.kemRE.Public, hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: Ekem encapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// Ekem ciphertext is plaintext: MixHash only
	hs.symmetricState.MixHash(ct)

	// Ekem uses MixKey (2-output HKDF)
	if err := hs.symmetricState.MixKey(ss); err != nil {
		return 0, err
	}

	n := copy(out, ct)

	// Set AFTER crypto ops complete
	hs.ownRandApplied = true

	return n, nil
}

// readTokenEkem decapsulates from local ephemeral KEM key.
// Ekem uses MixKey. Ekem ciphertext is plaintext (MixHash).
func (hs *HybridHandshake) readTokenEkem(reader *messageReader) error {
	ctLen := hs.ekem.CiphertextLen()
	ct, err := reader.read(ctLen)
	if err != nil {
		return err
	}

	// MixHash the plaintext ciphertext FIRST (matches Rust order)
	hs.symmetricState.MixHash(ct)

	if hs.kemE == nil {
		return fmt.Errorf("%w: Ekem read requires local ephemeral KEM key", ErrMissingKey)
	}

	ss, err := hs.ekem.Decapsulate(ct, hs.kemE.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Ekem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// MixKey with shared secret
	return hs.symmetricState.MixKey(ss)
}

// writeTokenSkem encapsulates to the remote static KEM key.
// Skem uses MixKeyAndHash (3-output HKDF), NOT MixKey.
// Skem ciphertext IS encrypted (EncryptAndHash, not MixHash).
// Sets ownRandApplied. Validates PSK own-randomness requirement.
func (hs *HybridHandshake) writeTokenSkem(out []byte) (int, error) {
	if hs.kemRS == nil {
		return 0, fmt.Errorf("%w: Skem requires remote static KEM key", ErrMissingKey)
	}

	// PSK validity check
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Skem", ErrPSKInvalid)
	}

	ct, ss, err := hs.skem.Encapsulate(hs.kemRS.Public, hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: Skem encapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// Skem ciphertext is encrypted via EncryptAndHash
	encCt, err := hs.symmetricState.EncryptAndHash(ct)
	// Zero plaintext KEM ciphertext after encryption - it's the raw
	// KEM output that would enable decapsulation if leaked from memory.
	zeroSlice(ct)
	if err != nil {
		return 0, err
	}

	// Skem uses MixKeyAndHash (3-output HKDF)
	if err := hs.symmetricState.MixKeyAndHash(ss); err != nil {
		return 0, err
	}

	n := copy(out, encCt)

	// Set AFTER all crypto ops complete
	hs.ownRandApplied = true

	return n, nil
}

// readTokenSkem decapsulates from local static KEM key.
// Skem uses MixKeyAndHash. Skem ciphertext IS encrypted (DecryptAndHash).
// CRITICAL: decapsulate with the DECRYPTED ciphertext, not the wire ciphertext.
func (hs *HybridHandshake) readTokenSkem(reader *messageReader) error {
	readLen := hs.skem.CiphertextLen()
	if hs.symmetricState.HasKey() {
		readLen += TagLen
	}

	// Read wire ciphertext (possibly encrypted)
	ctEnc, err := reader.read(readLen)
	if err != nil {
		return err
	}

	// DecryptAndHash to get the plaintext KEM ciphertext.
	// Decapsulate with the decrypted ciphertext, NOT the wire ciphertext.
	ctPlain, err := hs.symmetricState.DecryptAndHash(ctEnc)
	if err != nil {
		return err
	}

	if hs.kemS == nil {
		return fmt.Errorf("%w: Skem read requires local static KEM key", ErrMissingKey)
	}

	// Decapsulate with DECRYPTED ciphertext
	ss, err := hs.skem.Decapsulate(ctPlain, hs.kemS.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Skem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// MixKeyAndHash with shared secret
	return hs.symmetricState.MixKeyAndHash(ss)
}

// processTokenPsk mixes a pre-shared key via MixKeyAndHash.
// Sets pskApplied for validity checks. Does NOT set ownRandApplied because
// a PSK is a pre-shared secret, not locally-generated randomness.
// Only E, Ekem, and Skem satisfy the own-randomness requirement.
func (hs *HybridHandshake) processTokenPsk() error {
	psk, err := hs.psks.Pop()
	if err != nil {
		return fmt.Errorf("%w: no PSK available", ErrPSKInvalid)
	}
	defer func() {
		for i := range psk {
			psk[i] = 0
		}
	}()

	hs.pskApplied = true
	return hs.symmetricState.MixKeyAndHash(psk[:])
}

// hybridBuildName constructs the Noise protocol name for Hybrid handshakes.
// Has two formats depending on whether EKEM and SKEM are the same:
//
// Same KEM:      "Noise_{pattern}_{DH}+{EKEM}_{Cipher}_{Hash}"
// Different KEM: "Noise_{pattern}_{DH}+{EKEM}+{SKEM}_{Cipher}_{Hash}"
func hybridBuildName(pattern *HandshakePattern, suite CipherSuite) string {
	ekemName := suite.EKEM.Name()
	skemName := suite.SKEM.Name()

	if ekemName == skemName {
		return fmt.Sprintf("Noise_%s_%s+%s_%s_%s",
			pattern.Name(),
			suite.DH.Name(),
			ekemName,
			suite.Cipher.Name(),
			suite.Hash.Name(),
		)
	}
	return fmt.Sprintf("Noise_%s_%s+%s+%s_%s_%s",
		pattern.Name(),
		suite.DH.Name(),
		ekemName,
		skemName,
		suite.Cipher.Name(),
		suite.Hash.Name(),
	)
}
