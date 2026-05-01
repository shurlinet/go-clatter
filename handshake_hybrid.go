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
// Token::E generates BOTH DH AND KEM ephemeral keypairs (F141).
// Token::S sends BOTH DH AND KEM static public keys (F142/F155).
// DH tokens (EE/ES/SE/SS) perform classical DH and MixKey.
// Ekem/Skem are identical to PQ module (F42/F43/F143/F158/F159).
//
// Finding coverage:
// F41:  Token::S encrypts DH and KEM pubkeys with same cipherstate, sequential nonces.
// F42:  Ekem uses MixKey (2-output HKDF). Skem uses MixKeyAndHash (3-output HKDF).
// F43:  Ekem ciphertext is plaintext (MixHash). Skem ciphertext is encrypted (EncryptAndHash).
// F57:  ownRandApplied tracked for PSK validity.
// F59:  Overhead includes DH+KEM sizes for E and S tokens.
// F62:  Sticky error state, no recovery.
// F65:  Pre-message E mixes 4 times when PSK (MixHash DH, MixHash KEM, MixKey DH, MixKey KEM).
// F68:  has_key() changes during token processing - overhead simulation tracks this.
// F69:  Skem read: decapsulate with DECRYPTED CT, not wire CT.
// F81:  DH types in HandshakeInternals, KEM types as separate fields.
// F86:  PSK validity check at Token::S, Token::Skem, and post-payload.
// F90:  E, Ekem, and Skem all set ownRandApplied.
// F141: Token::E generates BOTH DH AND KEM ephemeral keypairs.
// F142: Token::S computes has_key ONCE, reuses for BOTH encrypt_and_hash calls.
// F143: Ekem is plaintext (MixHash+MixKey), Skem is encrypted (EncryptAndHash+MixKeyAndHash).
// F151: Payload encrypt/decrypt always LAST after all tokens.
// F154: hybridBuildName is one of 5 format variants (this is the Hybrid variant).
// F155: Pre-message Token::S = TWO MixHash calls (DH pubkey then KEM pubkey).
// F156: Token::S overhead = tag_len*2 when has_key (one tag per pubkey).
// F161: Pre-message Token::E = 2 ops (no PSK) or 4 ops (has PSK).
// F162: Destroy() zeros ALL fields including KEM keypairs.
// F164: setError() called on ANY failure.
// F171: WriteMessage validates buffer size before processing.
// F172: ReadMessage validates message length >= overhead before processing.
type HybridHandshake struct {
	HandshakeInternals
	dh DH // DH algorithm (X25519)

	// F81: KEM keypairs stored separately from DH keypairs in HandshakeInternals.
	// HandshakeInternals.s/e/rs/re hold DH keys.
	// These fields hold KEM keys.
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
	// F154: Hybrid dual-format build_name
	name := hybridBuildName(pattern, suite)
	hs.symmetricState = InitializeSymmetric(suite.Hash, suite.Cipher, name)

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

	// Process pre-messages
	// F155: Pre-message S mixes BOTH DH and KEM pubkeys.
	// F65/F161: Pre-message E mixes 2 or 4 times depending on PSK.
	if err := hs.processPreMessages(); err != nil {
		hs.Destroy()
		return nil, err
	}

	// Set initial status
	hs.determineInitialStatus()

	return hs, nil
}

// processPreMessages mixes pre-message tokens into the handshake hash.
// F155: Pre-message Token::S = TWO MixHash calls (DH pubkey, then KEM pubkey).
// F65/F161: Pre-message Token::E = MixHash(DH) + MixHash(KEM) + conditional MixKey(DH) + MixKey(KEM) when PSK.
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
		// F155: TWO MixHash calls - DH pubkey then KEM pubkey
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
		// F65/F161: MixHash(DH) + MixHash(KEM), then if PSK: MixKey(DH) + MixKey(KEM)
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
// F141: Token::E generates BOTH DH AND KEM ephemeral keypairs.
// F142: Token::S encrypts BOTH pubkeys with has_key checked ONCE.
// F151: Payload encrypted LAST after all tokens.
// F164: setError called on ANY failure.
// F171: Buffer size validated before processing.
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

	// F171: Check buffer size before processing
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

	// F86: Post-payload PSK validity check
	if len(payload) > 0 && hs.pskApplied && !hs.ownRandApplied {
		err = fmt.Errorf("%w: PSK requires own randomness before payload", ErrPSKInvalid)
		hs.setError(err)
		return 0, err
	}

	// F151: Payload encrypted LAST after all tokens.
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
// F151: Payload decrypted LAST.
// F164: setError called on ANY failure.
// F172: Message length validated >= overhead before processing.
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

	// F172: Validate message length
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

	return payloadLen, nil
}

// Finalize extracts transport keys and zeros handshake state.
// F117: Sets finalized=true, prevents double-finalize.
// F124: Requires HasKey (at least one MixKey occurred).
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

	ts := &TransportState{
		initiatorToResponder: cs1,
		responderToInitiator: cs2,
		initiator:            hs.initiator,
	}

	hs.finalized = true
	// F162: Zero ALL handshake state after finalize
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

// Destroy zeros ALL fields in the Hybrid handshake.
// F128/F162: Zeros HandshakeInternals + Hybrid-specific DH and KEM fields.
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
// F59: DH+KEM sizes for E and S tokens.
// F68: Simulates has_key() changes during token processing for accurate overhead.
// F156: Token::S adds tag_len*2 when has_key (one per pubkey).
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
			// F141/F59: DH pubkey + KEM pubkey
			overhead += hs.dh.PubKeyLen()
			overhead += hs.ekem.PubKeyLen()
			if hasPSK {
				hasKey = true
			}
		case TokenS:
			// F156: DH pubkey + KEM pubkey, each with tag when has_key
			overhead += hs.dh.PubKeyLen()
			overhead += hs.skem.PubKeyLen()
			if hasKey {
				overhead += TagLen * 2 // F156: one tag per pubkey
			}
		case TokenEE, TokenES, TokenSE, TokenSS:
			// DH tokens establish keys but add no wire bytes
			hasKey = true
		case TokenEkem:
			// F43: Ekem ciphertext is plaintext
			overhead += hs.ekem.CiphertextLen()
			hasKey = true
		case TokenSkem:
			// F43: Skem ciphertext is encrypted
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

// writeTokenE generates BOTH DH AND KEM ephemeral keypairs, writes both pubkeys, mixes.
// F141: Generates DH ephemeral + KEM ephemeral.
// F12: Ephemerals generated HERE, inside WriteMessage.
// F57/F90: Sets ownRandApplied.
// Rust hybrid.rs lines 460-493: DH pubkey first, then KEM pubkey.
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

	// F57/F90: Set AFTER all crypto ops + writes (matches Rust order)
	hs.ownRandApplied = true

	return cur, nil
}

// readTokenE reads BOTH DH AND KEM remote ephemeral public keys.
// F141: Reads DH pubkey then KEM pubkey.
// Rust hybrid.rs lines 635-651.
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
// F41: Sequential nonces from same cipherstate for DH then KEM.
// F142: has_key checked ONCE, reused for BOTH encrypt_and_hash calls.
// F86/F138: PSK validity check on write-side only.
// Rust hybrid.rs lines 494-526.
func (hs *HybridHandshake) writeTokenS(out []byte) (int, error) {
	if hs.s == nil || hs.kemS == nil {
		return 0, fmt.Errorf("%w: static keys required for Token::S", ErrMissingKey)
	}

	// F86/F138: PSK validity check
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Token::S", ErrPSKInvalid)
	}

	cur := 0

	// F41/F142: Both EncryptAndHash calls use the same CipherState with sequential
	// nonces. DH pubkey gets nonce n, KEM pubkey gets n+1. The has_key state is
	// checked internally by EncryptAndHash (copies plaintext when no key, encrypts
	// when key exists). This is correct because has_key cannot change between the
	// two calls - only MixKey/MixKeyAndHash modify has_key, and neither is called here.

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
// F142: has_key checked ONCE, reused for both decrypt_and_hash calls.
// Rust hybrid.rs lines 652-677.
func (hs *HybridHandshake) readTokenS(reader *messageReader) error {
	// F142: Check has_key ONCE for both reads
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

// doDH performs DH between local keypair and remote public key, then MixKey.
// F78: DH can fail - propagate error.
// F84: Low-order points caught by X25519 impl.
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

// writeTokenEkem encapsulates to remote ephemeral KEM key.
// F42: Ekem uses MixKey (2-output HKDF), NOT MixKeyAndHash.
// F43/F143: Ekem ciphertext is plaintext - MixHash, not EncryptAndHash.
// F90: Sets ownRandApplied.
// F158: Identical to PQ Ekem write.
// Rust hybrid.rs lines 542-558.
func (hs *HybridHandshake) writeTokenEkem(out []byte) (int, error) {
	if hs.kemRE == nil {
		return 0, fmt.Errorf("%w: Ekem requires remote ephemeral KEM key", ErrMissingKey)
	}

	ct, ss, err := hs.ekem.Encapsulate(hs.kemRE.Public, hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: Ekem encapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F43: Ekem ciphertext is plaintext - MixHash only
	hs.symmetricState.MixHash(ct)

	// F42: Ekem uses MixKey (2-output HKDF)
	if err := hs.symmetricState.MixKey(ss); err != nil {
		return 0, err
	}

	n := copy(out, ct)

	// F90: Set AFTER crypto ops complete
	hs.ownRandApplied = true

	return n, nil
}

// readTokenEkem decapsulates from local ephemeral KEM key.
// F42: Ekem uses MixKey.
// F43: Ekem ciphertext is plaintext - MixHash.
// Rust hybrid.rs lines 694-698.
func (hs *HybridHandshake) readTokenEkem(reader *messageReader) error {
	ctLen := hs.ekem.CiphertextLen()
	ct, err := reader.read(ctLen)
	if err != nil {
		return err
	}

	// F43: MixHash the plaintext ciphertext FIRST
	hs.symmetricState.MixHash(ct)

	if hs.kemE == nil {
		return fmt.Errorf("%w: Ekem read requires local ephemeral KEM key", ErrMissingKey)
	}

	ss, err := hs.ekem.Decapsulate(ct, hs.kemE.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Ekem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F42: MixKey with shared secret
	return hs.symmetricState.MixKey(ss)
}

// writeTokenSkem encapsulates to remote static KEM key.
// F42: Skem uses MixKeyAndHash (3-output HKDF), NOT MixKey.
// F43/F143: Skem ciphertext IS encrypted - EncryptAndHash, not MixHash.
// F86/F159: PSK validity check.
// F90: Sets ownRandApplied.
// Rust hybrid.rs lines 559-587.
func (hs *HybridHandshake) writeTokenSkem(out []byte) (int, error) {
	if hs.kemRS == nil {
		return 0, fmt.Errorf("%w: Skem requires remote static KEM key", ErrMissingKey)
	}

	// F86/F159: PSK validity check
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Skem", ErrPSKInvalid)
	}

	ct, ss, err := hs.skem.Encapsulate(hs.kemRS.Public, hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: Skem encapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F43: Skem ciphertext is encrypted via EncryptAndHash
	encCt, err := hs.symmetricState.EncryptAndHash(ct)
	// F85: Zero plaintext KEM ciphertext after encryption - it's the raw
	// KEM output that would enable decapsulation if leaked from memory.
	zeroSlice(ct)
	if err != nil {
		return 0, err
	}

	// F42: Skem uses MixKeyAndHash (3-output HKDF)
	if err := hs.symmetricState.MixKeyAndHash(ss); err != nil {
		return 0, err
	}

	n := copy(out, encCt)

	// F90: Set AFTER all crypto ops complete
	hs.ownRandApplied = true

	return n, nil
}

// readTokenSkem decapsulates from local static KEM key.
// F42: Skem uses MixKeyAndHash.
// F43: Skem ciphertext IS encrypted - DecryptAndHash.
// F69: CRITICAL - decapsulate with DECRYPTED CT, not wire CT.
// Rust hybrid.rs lines 700-718.
func (hs *HybridHandshake) readTokenSkem(reader *messageReader) error {
	readLen := hs.skem.CiphertextLen()
	if hs.symmetricState.HasKey() {
		readLen += TagLen
	}

	// F69: ctEnc = wire ciphertext (possibly encrypted)
	ctEnc, err := reader.read(readLen)
	if err != nil {
		return err
	}

	// F43/F69: DecryptAndHash to get the plaintext KEM ciphertext
	ctPlain, err := hs.symmetricState.DecryptAndHash(ctEnc)
	if err != nil {
		return err
	}

	if hs.kemS == nil {
		return fmt.Errorf("%w: Skem read requires local static KEM key", ErrMissingKey)
	}

	// F69: Decapsulate with DECRYPTED CT (ctPlain), not wire CT (ctEnc)
	ss, err := hs.skem.Decapsulate(ctPlain, hs.kemS.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Skem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F42: MixKeyAndHash with shared secret
	return hs.symmetricState.MixKeyAndHash(ss)
}

// processTokenPsk mixes a pre-shared key.
// F86: Sets pskApplied. Does NOT set ownRandApplied.
// PSK is a pre-shared secret, not locally-generated randomness.
// Only E, Ekem, and Skem satisfy the own-randomness requirement (F90).
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

	hs.pskApplied = true // F86: runtime PSK tracking (NOT ownRandApplied)
	return hs.symmetricState.MixKeyAndHash(psk[:])
}

// hybridBuildName constructs the Noise protocol name for Hybrid handshakes.
// F154: One of 5 format variants (this is the Hybrid variant).
//
// Rust hybrid.rs lines 826-856:
// When EKEM == SKEM (same name): "Noise_{pattern}_{DH}+{EKEM}_{Cipher}_{Hash}"
// When EKEM != SKEM (diff name): "Noise_{pattern}_{DH}+{EKEM}+{SKEM}_{Cipher}_{Hash}"
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
