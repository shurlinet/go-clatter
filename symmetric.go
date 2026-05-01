package clatter

import "fmt"

// SymmetricState is the core Noise protocol state machine.
// Matches Rust Clatter's symmetricstate.rs.
//
// F119: InitializeSymmetric hashes or pads the protocol name based on HASHLEN.
//       Same name produces different h with SHA-256 (HASHLEN=32) vs SHA-512 (HASHLEN=64).
// F120: h and ck are fixed-size arrays. Array assignment copies in Go (no aliasing).
// F122: Protocol name exactly equal to HASHLEN is PADDED (<=), not hashed.
// F165: cs (CipherState) is nil before first MixKey. encryptAndHash/decryptAndHash
//       copy plaintext verbatim when cs is nil (F31).
// F28:  decryptAndHash hashes CIPHERTEXT, not plaintext (Noise spec 5.2).
// F29:  MixKey destroys old CipherState before replacing.
// F30:  Truncate HKDF output to KeyLen (first 32 bytes) for 64-byte hashes.
// F38:  encryptAndHash output size depends on HasKey state.
// F63:  setError zeros all state immediately via Destroy().
// F166: Only SymmetricState + CipherState have explicit Destroy(). All other types
//       rely on containment (handshake structs call Destroy on their SymmetricState).
// F167: AD for encrypt/decrypt within handshake = current h.
// F169: Split uses empty IKM, zeros temp keys.
type SymmetricState struct {
	h       [MaxHashLen]byte // handshake hash
	ck      [MaxHashLen]byte // chaining key
	cs      *CipherState     // nil before first MixKey (F165)
	hashLen int              // active hash output length
	hash    HashFunc         // hash function
	cipher  Cipher           // cipher for creating new CipherStates
	err     error            // sticky error (F62)
}

// InitializeSymmetric creates a new SymmetricState from a protocol name.
//
// F119: If len(protocolName) <= HASHLEN: h = protocolName padded with zeros.
//       If len(protocolName) > HASHLEN: h = Hash(protocolName).
// F120: ck = copy of h (array assignment, no aliasing).
// F122: Exactly HASHLEN bytes = padded, not hashed (uses <=).
func InitializeSymmetric(h HashFunc, c Cipher, protocolName string) *SymmetricState {
	ss := &SymmetricState{
		hashLen: h.HashLen(),
		hash:    h,
		cipher:  c,
	}

	nameBytes := []byte(protocolName)

	if len(nameBytes) <= ss.hashLen {
		// F119/F122: Pad with zeros (array is already zeroed)
		copy(ss.h[:], nameBytes)
	} else {
		// F119: Hash the protocol name
		hashed := h.Hash(nameBytes)
		copy(ss.h[:], hashed)
		zeroSlice(hashed)
	}

	// F120: ck = h. Array assignment copies bytes, no aliasing.
	ss.ck = ss.h

	return ss
}

// checkErr returns the sticky error if the SymmetricState is in error state (F62).
// Every mutating method must call this first.
func (ss *SymmetricState) checkErr() error {
	if ss.err != nil {
		return ss.err
	}
	return nil
}

// MixHash updates h = Hash(h || data).
// Intermediate buffer zeroed after hashing (contains handshake state).
func (ss *SymmetricState) MixHash(data []byte) {
	combined := make([]byte, ss.hashLen+len(data))
	copy(combined, ss.h[:ss.hashLen])
	copy(combined[ss.hashLen:], data)
	hashed := ss.hash.Hash(combined)
	zeroSlice(combined)
	copy(ss.h[:], hashed[:ss.hashLen])
}

// MixKey derives a new CipherState from h and input key material.
//
// F29: Destroys old CipherState before replacing.
// F30: Truncates tempK to KeyLen for 64-byte hashes (SHA-512).
// F118: Copies ck to local before HKDF to prevent aliasing.
// F165: After MixKey, cs is non-nil (HasKey becomes true).
func (ss *SymmetricState) MixKey(ikm []byte) error {
	if err := ss.checkErr(); err != nil {
		return err
	}
	// F118: Copy ck to prevent aliasing during HKDF
	ckCopy := make([]byte, ss.hashLen)
	copy(ckCopy, ss.ck[:ss.hashLen])

	newCk, tempK, err := HKDF2(ss.hash, ckCopy, ikm)
	zeroSlice(ckCopy)
	if err != nil {
		return fmt.Errorf("MixKey: %w", err)
	}

	// Update ck
	copy(ss.ck[:], newCk[:ss.hashLen])
	zeroSlice(newCk)

	// F30: Truncate to KeyLen for 64-byte hashes
	if len(tempK) > KeyLen {
		zeroSlice(tempK[KeyLen:])
		tempK = tempK[:KeyLen]
	}

	// F29: Destroy old CipherState before replacement
	if ss.cs != nil {
		ss.cs.Destroy()
	}

	ss.cs, err = NewCipherState(ss.cipher, tempK)
	zeroSlice(tempK)
	if err != nil {
		return fmt.Errorf("MixKey: %w", err)
	}

	return nil
}

// MixKeyAndHash derives ck, h-update, and a new CipherState from 3-output HKDF.
//
// F29: Destroys old CipherState before replacing.
// F30: Truncates tempK to KeyLen for 64-byte hashes.
// F118: Copies ck to local before HKDF.
func (ss *SymmetricState) MixKeyAndHash(ikm []byte) error {
	if err := ss.checkErr(); err != nil {
		return err
	}
	ckCopy := make([]byte, ss.hashLen)
	copy(ckCopy, ss.ck[:ss.hashLen])

	newCk, tempH, tempK, err := HKDF3(ss.hash, ckCopy, ikm)
	zeroSlice(ckCopy)
	if err != nil {
		return fmt.Errorf("MixKeyAndHash: %w", err)
	}

	// Update ck
	copy(ss.ck[:], newCk[:ss.hashLen])
	zeroSlice(newCk)

	// MixHash with tempH
	ss.MixHash(tempH)
	zeroSlice(tempH)

	// F30: Truncate to KeyLen
	if len(tempK) > KeyLen {
		zeroSlice(tempK[KeyLen:])
		tempK = tempK[:KeyLen]
	}

	// F29: Destroy old CipherState
	if ss.cs != nil {
		ss.cs.Destroy()
	}

	ss.cs, err = NewCipherState(ss.cipher, tempK)
	zeroSlice(tempK)
	if err != nil {
		return fmt.Errorf("MixKeyAndHash: %w", err)
	}

	return nil
}

// HasKey returns true if a CipherState has been established (after first MixKey).
// F165: Before first MixKey, cs is nil, HasKey returns false.
func (ss *SymmetricState) HasKey() bool {
	return ss.cs.HasKey()
}

// EncryptAndHash encrypts plaintext (or copies verbatim if no key yet).
// Returns ciphertext. Updates h with the output (ciphertext, not plaintext).
//
// F28: MixHash is called with CIPHERTEXT, not plaintext.
// F31: Before first MixKey, copies plaintext verbatim (no encryption).
// F38: Output size depends on HasKey: with key = plaintext+tag, without = plaintext.
// F167: AD = current h[:hashLen].
func (ss *SymmetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	if err := ss.checkErr(); err != nil {
		return nil, err
	}
	var ciphertext []byte

	if ss.cs.HasKey() {
		// F167: AD is the current handshake hash
		ad := make([]byte, ss.hashLen)
		copy(ad, ss.h[:ss.hashLen])

		var err error
		ciphertext, err = ss.cs.EncryptWithAd(ad, plaintext)
		zeroSlice(ad)
		if err != nil {
			return nil, err
		}
	} else {
		// F31: No key yet, copy plaintext verbatim
		ciphertext = make([]byte, len(plaintext))
		copy(ciphertext, plaintext)
	}

	// F28: Hash the CIPHERTEXT, not the plaintext
	ss.MixHash(ciphertext)

	return ciphertext, nil
}

// DecryptAndHash decrypts ciphertext (or copies verbatim if no key yet).
// Returns plaintext. Updates h with the ciphertext (before decryption).
//
// F28: MixHash is called with CIPHERTEXT (the input), not the decrypted plaintext.
// F31: Before first MixKey, copies ciphertext verbatim.
func (ss *SymmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	if err := ss.checkErr(); err != nil {
		return nil, err
	}
	var plaintext []byte

	if ss.cs.HasKey() {
		ad := make([]byte, ss.hashLen)
		copy(ad, ss.h[:ss.hashLen])

		var err error
		plaintext, err = ss.cs.DecryptWithAd(ad, ciphertext)
		zeroSlice(ad)
		if err != nil {
			return nil, err
		}
	} else {
		// F31: No key yet, copy verbatim
		plaintext = make([]byte, len(ciphertext))
		copy(plaintext, ciphertext)
	}

	// F28: Hash the CIPHERTEXT, not the plaintext
	ss.MixHash(ciphertext)

	return plaintext, nil
}

// Split returns two CipherStates for transport encryption.
//
// F108: HKDF with empty IKM.
// F109: Both CipherStates start at nonce=0.
// F110: Temp keys zeroed after creating CipherStates.
// F118: Copy ck before HKDF.
// F124: Requires HasKey (at least one MixKey must have occurred).
// F169: Confirms F108 + F110.
func (ss *SymmetricState) Split() (cs1, cs2 *CipherState, err error) {
	if err := ss.checkErr(); err != nil {
		return nil, nil, err
	}
	if !ss.cs.HasKey() {
		return nil, nil, fmt.Errorf("%w: Split requires established key", ErrMissingKey)
	}

	// F118: Copy ck before HKDF
	ckCopy := make([]byte, ss.hashLen)
	copy(ckCopy, ss.ck[:ss.hashLen])

	// F108: Empty IKM
	tempK1, tempK2, hkdfErr := HKDF2(ss.hash, ckCopy, nil)
	zeroSlice(ckCopy)
	if hkdfErr != nil {
		return nil, nil, fmt.Errorf("Split: %w", hkdfErr)
	}

	// F30: Truncate to KeyLen
	if len(tempK1) > KeyLen {
		zeroSlice(tempK1[KeyLen:])
		tempK1 = tempK1[:KeyLen]
	}
	if len(tempK2) > KeyLen {
		zeroSlice(tempK2[KeyLen:])
		tempK2 = tempK2[:KeyLen]
	}

	// F109: Both at nonce=0
	cs1, err = NewCipherState(ss.cipher, tempK1)
	// F110: Zero temp keys
	zeroSlice(tempK1)
	if err != nil {
		zeroSlice(tempK2)
		return nil, nil, err
	}

	cs2, err = NewCipherState(ss.cipher, tempK2)
	zeroSlice(tempK2)
	if err != nil {
		cs1.Destroy()
		return nil, nil, err
	}

	return cs1, cs2, nil
}

// GetHandshakeHash returns a copy of the current handshake hash h.
func (ss *SymmetricState) GetHandshakeHash() []byte {
	out := make([]byte, ss.hashLen)
	copy(out, ss.h[:ss.hashLen])
	return out
}

// ChainingKey returns a copy of the current chaining key ck.
// The caller MUST zero the returned slice when done - ck is secret keying material.
func (ss *SymmetricState) ChainingKey() []byte {
	out := make([]byte, ss.hashLen)
	copy(out, ss.ck[:ss.hashLen])
	return out
}

// SetError records a sticky error and zeros all state.
// F63: On ANY error, all crypto state is wiped immediately.
// F62: Error state is sticky - no recovery.
func (ss *SymmetricState) SetError(err error) {
	ss.err = err
	ss.Destroy()
}

// Err returns the sticky error, if any.
func (ss *SymmetricState) Err() error {
	return ss.err
}

// Destroy zeros all secret state in the SymmetricState.
// F63: Called by SetError.
func (ss *SymmetricState) Destroy() {
	for i := range ss.h {
		ss.h[i] = 0
	}
	for i := range ss.ck {
		ss.ck[i] = 0
	}
	if ss.cs != nil {
		ss.cs.Destroy()
		ss.cs = nil
	}
}
