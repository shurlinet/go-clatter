package clatter

import (
	"crypto/rand"
	"fmt"
)

// Compile-time interface compliance check.
var _ Handshaker = (*PqHandshake)(nil)

// PqHandshake implements the PQ (KEM-only) Noise handshake.
// Port of Rust Clatter's pq.rs. Uses KEM-only tokens (E, S, Ekem, Skem, PSK).
// No DH operations. All key exchange via KEM encapsulate/decapsulate.
//
// Finding coverage:
// F42:  Ekem uses MixKey (2-output HKDF). Skem uses MixKeyAndHash (3-output HKDF).
// F43:  Ekem ciphertext is plaintext (MixHash). Skem ciphertext is encrypted (EncryptAndHash).
// F57:  ownRandApplied tracked for PSK validity.
// F62:  Sticky error state, no recovery.
// F69:  Skem read: decapsulate with DECRYPTED CT, not wire CT.
// F90:  E, Ekem, and Skem all set ownRandApplied.
// F137: pqBuildName has dual format (EKEM==SKEM vs EKEM!=SKEM).
// F138: PSK validity check on write-side only (Token::S write).
// F151: Payload encrypt/decrypt always LAST after all tokens.
// F154: buildName is one of 5 variants (this is the PQ variant).
// F157: PQ Token::E uses EKEM types, Token::S uses SKEM types.
// F158: PQ Ekem write identical to Hybrid Ekem write.
// F159: PQ Skem write calls psk_validity_check.
// F162: Destroy() zeros ALL fields.
// F164: setError() called on ANY failure.
// F171: WriteMessage validates buffer size before processing.
// F172: ReadMessage validates message length >= overhead before processing.
type PqHandshake struct {
	HandshakeInternals
}

// NewPqHandshake creates a PQ (KEM-only) Noise handshake.
// Pattern must be PatternTypeKEM. Returns error for DH or Hybrid patterns.
//
// CipherSuite must have EKEM, SKEM, Cipher, and Hash set. DH is not used.
// If EKEM and SKEM are the same KEM, pass the same instance for both.
func NewPqHandshake(
	pattern *HandshakePattern,
	initiator bool,
	suite CipherSuite,
	opts ...Option,
) (*PqHandshake, error) {
	if pattern.Type() != PatternTypeKEM {
		return nil, fmt.Errorf("%w: PQ handshake requires KEM-only pattern, got %d",
			ErrInvalidPattern, pattern.Type())
	}
	if suite.EKEM == nil || suite.SKEM == nil || suite.Cipher == nil || suite.Hash == nil {
		return nil, fmt.Errorf("%w: CipherSuite requires EKEM, SKEM, Cipher, and Hash", ErrMissingKey)
	}

	ho := applyOptions(opts)

	rng := ho.rng
	if rng == nil {
		rng = rand.Reader
	}

	hs := &PqHandshake{}
	hs.pattern = pattern
	hs.initiator = initiator
	hs.rng = rng
	hs.cipher = suite.Cipher
	hs.hash = suite.Hash
	hs.ekem = suite.EKEM
	hs.skem = suite.SKEM

	// Build protocol name and initialize symmetric state
	// F137/F154: PQ dual-format build_name
	name := pqBuildName(pattern, suite)
	hs.symmetricState = InitializeSymmetric(suite.Hash, suite.Cipher, name)

	// Mix prologue (Noise spec: always mixed, even if empty)
	hs.symmetricState.MixHash(ho.prologue)

	// F157: PQ static keys are KEM keys (SKEM type), not DH keys.
	// Set local static key (KEM keypair stored in s field)
	if ho.staticKey != nil {
		hs.s = ho.staticKey
	}

	// Set remote static public key (KEM public key stored in rs field)
	if ho.remoteStatic != nil {
		hs.rs = &KeyPair{Public: ho.remoteStatic}
	}

	// Process pre-messages
	if err := hs.processPreMessages(); err != nil {
		hs.Destroy()
		return nil, err
	}

	// Set initial status
	hs.determineInitialStatus()

	return hs, nil
}

// processPreMessages mixes pre-message tokens into the handshake hash.
// F46: Pre-message order is DH first, KEM second. PQ has no DH, only KEM pubkeys.
// F157: PQ uses SKEM public keys for pre-message S tokens.
func (hs *PqHandshake) processPreMessages() error {
	// Initiator pre-messages
	preInit := hs.pattern.PreInitiator()
	for _, token := range preInit {
		switch token {
		case TokenE:
			if hs.initiator {
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
			// Conditional MixKey if hasPSK (same as NQ)
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
			// F157: PQ static keys are KEM (SKEM) public keys
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
// F151: Payload encrypted LAST after all tokens.
// F164: setError called on ANY failure.
// F171: Buffer size validated before processing.
func (hs *PqHandshake) WriteMessage(payload, out []byte) (int, error) {
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
	overhead, err := hs.getNextMessageOverheadPQ()
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
// F172: Message length validated >= overhead.
func (hs *PqHandshake) ReadMessage(message, out []byte) (int, error) {
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
	overhead, err := hs.getNextMessageOverheadPQ()
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
func (hs *PqHandshake) Finalize() (*TransportState, error) {
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
func (hs *PqHandshake) GetNextMessageOverhead() (int, error) {
	if err := hs.checkState(); err != nil {
		return 0, err
	}
	return hs.getNextMessageOverheadPQ()
}

// Destroy zeros ALL fields in the PQ handshake.
// F128/F162: HandshakeInternals.Destroy() zeros all fields including ekem/skem.
func (hs *PqHandshake) Destroy() {
	hs.HandshakeInternals.Destroy()
}

// getNextMessageOverheadPQ calculates overhead for the next PQ message.
// F68: Simulates has_key() changes during token processing for accurate overhead.
// F157: Uses EKEM sizes for Token::E, SKEM sizes for Token::S.
func (hs *PqHandshake) getNextMessageOverheadPQ() (int, error) {
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
			// F157: PQ Token::E uses EKEM public key size
			overhead += hs.ekem.PubKeyLen()
			// E with PSK does MixKey(pubkey), establishing a key
			if hasPSK {
				hasKey = true
			}
		case TokenS:
			// F157: PQ Token::S uses SKEM public key size
			overhead += hs.skem.PubKeyLen()
			if hasKey {
				overhead += TagLen
			}
		case TokenEkem:
			// Ekem: ciphertext + MixKey (establishes key)
			// F43: Ekem ciphertext is plaintext (MixHash only, no encrypt)
			overhead += hs.ekem.CiphertextLen()
			hasKey = true
		case TokenSkem:
			// F43: Skem ciphertext is encrypted (EncryptAndHash)
			overhead += hs.skem.CiphertextLen()
			if hasKey {
				overhead += TagLen // EncryptAndHash adds tag
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
// Returns the number of bytes written to out.
func (hs *PqHandshake) processWriteToken(token Token, out []byte) (int, error) {
	switch token {
	case TokenE:
		return hs.writeTokenE(out)
	case TokenS:
		return hs.writeTokenS(out)
	case TokenEkem:
		return hs.writeTokenEkem(out)
	case TokenSkem:
		return hs.writeTokenSkem(out)
	case TokenPsk:
		return 0, hs.processTokenPsk()
	default:
		return 0, fmt.Errorf("%w: unsupported PQ token %d", ErrInvalidPattern, token)
	}
}

// processReadToken processes a single token during ReadMessage.
func (hs *PqHandshake) processReadToken(token Token, reader *messageReader) error {
	switch token {
	case TokenE:
		return hs.readTokenE(reader)
	case TokenS:
		return hs.readTokenS(reader)
	case TokenEkem:
		return hs.readTokenEkem(reader)
	case TokenSkem:
		return hs.readTokenSkem(reader)
	case TokenPsk:
		return hs.processTokenPsk()
	default:
		return fmt.Errorf("%w: unsupported PQ token %d", ErrInvalidPattern, token)
	}
}

// writeTokenE generates ephemeral KEM keypair, writes pubkey, mixes.
// F12: Ephemeral generated HERE, inside WriteMessage.
// F57/F90: Sets ownRandApplied.
// F157: PQ Token::E uses EKEM types.
func (hs *PqHandshake) writeTokenE(out []byte) (int, error) {
	if hs.e != nil {
		return 0, fmt.Errorf("%w: ephemeral already set", ErrInvalidState)
	}

	// F157: Generate EKEM ephemeral keypair
	kp, err := hs.ekem.GenerateKeypair(hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: ephemeral keygen: %v", ErrKEM, err)
	}

	hs.e = &kp

	// Mix into handshake hash (Rust order: MixHash -> MixKey -> copy -> set flag)
	hs.symmetricState.MixHash(hs.e.Public)

	// Conditional MixKey if hasPSK
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.e.Public); err != nil {
			return 0, err
		}
	}

	// Write ephemeral pubkey to output
	n := copy(out, hs.e.Public)

	// F57/F90: Set AFTER crypto ops + write (matches Rust order)
	hs.ownRandApplied = true

	return n, nil
}

// readTokenE reads remote ephemeral KEM public key from message.
// F157: PQ Token::E uses EKEM types.
func (hs *PqHandshake) readTokenE(reader *messageReader) error {
	pubLen := hs.ekem.PubKeyLen()
	pubBytes, err := reader.read(pubLen)
	if err != nil {
		return err
	}

	hs.re = &KeyPair{Public: make([]byte, pubLen)}
	copy(hs.re.Public, pubBytes)

	hs.symmetricState.MixHash(hs.re.Public)

	// Conditional MixKey if hasPSK
	if hs.pattern.HasPSK() {
		if err := hs.symmetricState.MixKey(hs.re.Public); err != nil {
			return err
		}
	}

	return nil
}

// writeTokenS encrypts and writes local static KEM public key.
// F138/F159: PSK validity check on write-side only.
// F157: PQ Token::S uses SKEM public key.
func (hs *PqHandshake) writeTokenS(out []byte) (int, error) {
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

// readTokenS reads and decrypts remote static KEM public key.
// F157: PQ Token::S uses SKEM public key size.
func (hs *PqHandshake) readTokenS(reader *messageReader) error {
	readLen := hs.skem.PubKeyLen()
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

// writeTokenEkem encapsulates to remote ephemeral KEM key.
// F42: Ekem uses MixKey (2-output HKDF), NOT MixKeyAndHash.
// F43: Ekem ciphertext is plaintext - MixHash, not EncryptAndHash.
// F90: Sets ownRandApplied.
// F158: Identical to Hybrid Ekem write.
func (hs *PqHandshake) writeTokenEkem(out []byte) (int, error) {
	if hs.re == nil {
		return 0, fmt.Errorf("%w: Ekem requires remote ephemeral key", ErrMissingKey)
	}

	// Encapsulate to remote ephemeral public key
	ct, ss, err := hs.ekem.Encapsulate(hs.re.Public, hs.rng)
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

	// Write ciphertext to output
	n := copy(out, ct)

	// F90: Set AFTER crypto ops complete (matches Rust order)
	hs.ownRandApplied = true

	return n, nil
}

// readTokenEkem decapsulates from local ephemeral KEM key.
// F42: Ekem uses MixKey.
// F43: Ekem ciphertext is plaintext - MixHash.
func (hs *PqHandshake) readTokenEkem(reader *messageReader) error {
	ctLen := hs.ekem.CiphertextLen()
	ct, err := reader.read(ctLen)
	if err != nil {
		return err
	}

	// F43: MixHash the plaintext ciphertext FIRST (matches Rust order)
	hs.symmetricState.MixHash(ct)

	if hs.e == nil {
		return fmt.Errorf("%w: Ekem read requires local ephemeral key", ErrMissingKey)
	}

	// Decapsulate using local ephemeral secret key
	ss, err := hs.ekem.Decapsulate(ct, hs.e.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Ekem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F42: MixKey with shared secret
	return hs.symmetricState.MixKey(ss)
}

// writeTokenSkem encapsulates to remote static KEM key.
// F42: Skem uses MixKeyAndHash (3-output HKDF), NOT MixKey.
// F43: Skem ciphertext IS encrypted - EncryptAndHash, not MixHash.
// F90: Sets ownRandApplied.
// F159: Skem write calls PSK validity check.
func (hs *PqHandshake) writeTokenSkem(out []byte) (int, error) {
	if hs.rs == nil {
		return 0, fmt.Errorf("%w: Skem requires remote static key", ErrMissingKey)
	}

	// F86/F159: PSK validity check - if PSK was applied, must have own randomness
	if hs.pskApplied && !hs.ownRandApplied {
		return 0, fmt.Errorf("%w: PSK requires own randomness before Skem", ErrPSKInvalid)
	}

	// Encapsulate to remote static public key
	ct, ss, err := hs.skem.Encapsulate(hs.rs.Public, hs.rng)
	if err != nil {
		return 0, fmt.Errorf("%w: Skem encapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F43: Skem ciphertext is encrypted via EncryptAndHash
	encCt, err := hs.symmetricState.EncryptAndHash(ct)
	if err != nil {
		return 0, err
	}

	// F42: Skem uses MixKeyAndHash (3-output HKDF)
	if err := hs.symmetricState.MixKeyAndHash(ss); err != nil {
		return 0, err
	}

	// Write encrypted ciphertext to output
	n := copy(out, encCt)

	// F90: Set AFTER all crypto ops complete (matches Rust order)
	hs.ownRandApplied = true

	return n, nil
}

// readTokenSkem decapsulates from local static KEM key.
// F42: Skem uses MixKeyAndHash.
// F43: Skem ciphertext IS encrypted - DecryptAndHash.
// F69: CRITICAL - decapsulate with DECRYPTED CT, not wire CT.
func (hs *PqHandshake) readTokenSkem(reader *messageReader) error {
	// Read encrypted ciphertext from wire
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
	// F69: ctPlain = decrypted KEM ciphertext. Decapsulate with ctPlain, NOT ctEnc.
	ctPlain, err := hs.symmetricState.DecryptAndHash(ctEnc)
	if err != nil {
		return err
	}

	if hs.s == nil {
		return fmt.Errorf("%w: Skem read requires local static key", ErrMissingKey)
	}

	// F69: Decapsulate with DECRYPTED CT (ctPlain), not wire CT (ctEnc)
	ss, err := hs.skem.Decapsulate(ctPlain, hs.s.SecretSlice())
	if err != nil {
		return fmt.Errorf("%w: Skem decapsulate: %v", ErrKEM, err)
	}
	defer zeroSlice(ss)

	// F42: MixKeyAndHash with shared secret
	return hs.symmetricState.MixKeyAndHash(ss)
}

// processTokenPsk mixes a pre-shared key.
// F86: Sets pskApplied for validity checks. Does NOT set ownRandApplied.
// PSK is a pre-shared secret, not locally-generated randomness.
// Only E, Ekem, and Skem satisfy the own-randomness requirement (F90).
func (hs *PqHandshake) processTokenPsk() error {
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

// pqBuildName constructs the Noise protocol name for PQ handshakes.
// F137: Dual format - different when EKEM and SKEM are the same vs different.
// F154: One of 5 format variants (NQ has 1, PQ has 2, Hybrid has 2).
//
// When EKEM == SKEM (same name): "Noise_pqXX_MLKEM768_ChaChaPoly_SHA256"
// When EKEM != SKEM (diff name): "Noise_pqXX_MLKEM768+MLKEM1024_ChaChaPoly_SHA256"
func pqBuildName(pattern *HandshakePattern, suite CipherSuite) string {
	ekemName := suite.EKEM.Name()
	skemName := suite.SKEM.Name()

	if ekemName == skemName {
		return fmt.Sprintf("Noise_%s_%s_%s_%s",
			pattern.Name(),
			ekemName,
			suite.Cipher.Name(),
			suite.Hash.Name(),
		)
	}
	return fmt.Sprintf("Noise_%s_%s+%s_%s_%s",
		pattern.Name(),
		ekemName,
		skemName,
		suite.Cipher.Name(),
		suite.Hash.Name(),
	)
}
