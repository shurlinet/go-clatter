package clatter

import "fmt"

// SymmetricState is the core Noise protocol state machine.
// Matches Rust Clatter's symmetricstate.rs.
//
// InitializeSymmetric hashes or pads the protocol name based on HASHLEN:
// the same name produces different h values with SHA-256 vs SHA-512.
// h and ck are fixed-size arrays; Go array assignment copies bytes (no aliasing).
//
// Before the first MixKey call, cs is nil and encrypt/decrypt operations
// copy plaintext verbatim (no encryption). After MixKey, cs holds the active
// CipherState. MixKey always destroys the old CipherState before replacing it.
// HKDF output is truncated to KeyLen (32 bytes) for 64-byte hash functions.
//
// Error state is sticky: once SetError is called, all crypto state is zeroed
// and no further operations succeed.
type SymmetricState struct {
	h       [MaxHashLen]byte // handshake hash
	ck      [MaxHashLen]byte // chaining key
	cs      *CipherState     // nil before first MixKey
	hashLen int              // active hash output length
	hash    HashFunc         // hash function
	cipher  Cipher           // cipher for creating new CipherStates
	err     error            // sticky error
}

// InitializeSymmetric creates a new SymmetricState from a protocol name.
//
// If len(protocolName) <= HASHLEN: h is set to protocolName zero-padded.
// If len(protocolName) > HASHLEN: h is set to Hash(protocolName).
// ck is then set to a copy of h (array assignment, no aliasing).
func InitializeSymmetric(h HashFunc, c Cipher, protocolName string) *SymmetricState {
	ss := &SymmetricState{
		hashLen: h.HashLen(),
		hash:    h,
		cipher:  c,
	}

	nameBytes := []byte(protocolName)

	if len(nameBytes) <= ss.hashLen {
		// Pad with zeros (array is already zeroed)
		copy(ss.h[:], nameBytes)
	} else {
		// Hash the protocol name
		hashed := h.Hash(nameBytes)
		copy(ss.h[:], hashed)
		zeroSlice(hashed)
	}

	// ck = h. Array assignment copies bytes, no aliasing.
	ss.ck = ss.h

	return ss
}

// checkErr returns the sticky error if the SymmetricState is in error state.
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

// MixKey derives a new CipherState from the chaining key and input key material.
//
// The old CipherState is destroyed before replacement. HKDF output is truncated
// to KeyLen for 64-byte hashes (SHA-512). The chaining key is copied to a local
// buffer before HKDF to prevent aliasing. After MixKey, HasKey returns true.
func (ss *SymmetricState) MixKey(ikm []byte) error {
	if err := ss.checkErr(); err != nil {
		return err
	}
	// Copy ck to prevent aliasing during HKDF
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

	// Truncate to KeyLen for 64-byte hashes
	if len(tempK) > KeyLen {
		zeroSlice(tempK[KeyLen:])
		tempK = tempK[:KeyLen]
	}

	// Destroy old CipherState before replacement
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

// MixKeyAndHash derives ck, an h-update, and a new CipherState from 3-output HKDF.
//
// The old CipherState is destroyed before replacement. HKDF output is truncated
// to KeyLen for 64-byte hashes. The chaining key is copied before HKDF to
// prevent aliasing.
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

	// Truncate to KeyLen
	if len(tempK) > KeyLen {
		zeroSlice(tempK[KeyLen:])
		tempK = tempK[:KeyLen]
	}

	// Destroy old CipherState
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
func (ss *SymmetricState) HasKey() bool {
	return ss.cs.HasKey()
}

// EncryptAndHash encrypts plaintext (or copies verbatim if no key yet).
// Returns ciphertext. Updates h with the output (ciphertext, not plaintext).
//
// Before the first MixKey, plaintext is copied verbatim (no encryption, no tag).
// After MixKey, plaintext is AEAD-encrypted with the current h as AD.
// In both cases, MixHash is called with the CIPHERTEXT output per Noise spec 5.2.
func (ss *SymmetricState) EncryptAndHash(plaintext []byte) ([]byte, error) {
	if err := ss.checkErr(); err != nil {
		return nil, err
	}
	var ciphertext []byte

	if ss.cs.HasKey() {
		// AD is the current handshake hash
		ad := make([]byte, ss.hashLen)
		copy(ad, ss.h[:ss.hashLen])

		var err error
		ciphertext, err = ss.cs.EncryptWithAd(ad, plaintext)
		zeroSlice(ad)
		if err != nil {
			return nil, err
		}
	} else {
		// No key yet, copy plaintext verbatim
		ciphertext = make([]byte, len(plaintext))
		copy(ciphertext, plaintext)
	}

	// Hash the CIPHERTEXT, not the plaintext (Noise spec 5.2)
	ss.MixHash(ciphertext)

	return ciphertext, nil
}

// DecryptAndHash decrypts ciphertext (or copies verbatim if no key yet).
// Returns plaintext. Updates h with the ciphertext (before decryption).
//
// MixHash is called with the CIPHERTEXT input, not the decrypted plaintext.
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
		// No key yet, copy verbatim
		plaintext = make([]byte, len(ciphertext))
		copy(plaintext, ciphertext)
	}

	// Hash the CIPHERTEXT, not the plaintext
	ss.MixHash(ciphertext)

	return plaintext, nil
}

// Split returns two CipherStates for transport encryption.
//
// Uses HKDF with empty IKM to derive two independent keys from the chaining key.
// Both CipherStates start at nonce 0. Temp keys are zeroed after use.
// Requires that at least one MixKey has occurred (HasKey must be true).
func (ss *SymmetricState) Split() (cs1, cs2 *CipherState, err error) {
	if err := ss.checkErr(); err != nil {
		return nil, nil, err
	}
	if !ss.cs.HasKey() {
		return nil, nil, fmt.Errorf("%w: Split requires established key", ErrMissingKey)
	}

	// Copy ck before HKDF to prevent aliasing
	ckCopy := make([]byte, ss.hashLen)
	copy(ckCopy, ss.ck[:ss.hashLen])

	// Empty IKM
	tempK1, tempK2, hkdfErr := HKDF2(ss.hash, ckCopy, nil)
	zeroSlice(ckCopy)
	if hkdfErr != nil {
		return nil, nil, fmt.Errorf("Split: %w", hkdfErr)
	}

	// Truncate to KeyLen for 64-byte hashes
	if len(tempK1) > KeyLen {
		zeroSlice(tempK1[KeyLen:])
		tempK1 = tempK1[:KeyLen]
	}
	if len(tempK2) > KeyLen {
		zeroSlice(tempK2[KeyLen:])
		tempK2 = tempK2[:KeyLen]
	}

	cs1, err = NewCipherState(ss.cipher, tempK1)
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

// SetError records a sticky error and zeros all cryptographic state immediately.
// Once in error state, no recovery is possible.
func (ss *SymmetricState) SetError(err error) {
	ss.err = err
	ss.Destroy()
}

// Err returns the sticky error, if any.
func (ss *SymmetricState) Err() error {
	return ss.err
}

// Destroy zeros all secret state in the SymmetricState,
// including h, ck, and the CipherState.
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
