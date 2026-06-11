package clatter

import (
	"fmt"
	"math"
)

// CipherState holds a symmetric cipher key and a monotonically incrementing nonce.
//
// After construction, each call to EncryptWithAd or DecryptWithAd uses the current
// nonce value and advances it by one. The nonce is never reset; when it reaches
// MaxUint64, that final operation succeeds and all subsequent calls return
// ErrNonceOverflow. This matches the Noise protocol specification.
//
// CipherState is not safe for concurrent use. Callers must synchronize access
// externally or use the handshake-level atomic guards.
//
// Call Destroy to zero all key material when done.
type CipherState struct {
	key        [KeyLen]byte
	nonce      uint64
	hasKey     bool
	overflowed bool
	destroyed  bool
	cipher     Cipher    // the raw AEAD implementation
	keyed      KeyedAEAD // cached keyed instance when cipher implements KeyedCipher
}

// NewCipherState creates a CipherState with the given key and nonce starting at 0.
// The key must be exactly KeyLen (32) bytes; returns ErrInvalidKeyLength otherwise.
//
// The caller is responsible for zeroing the source key slice after this call.
// NewCipherState copies the key but does not zero the source, because Split
// passes the same slice to two consecutive NewCipherState calls.
//
// If c implements KeyedCipher, the keyed AEAD is built once here (and on
// Rekey) instead of running the key schedule on every message.
func NewCipherState(c Cipher, key []byte) (*CipherState, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKeyLength, len(key), KeyLen)
	}
	cs := &CipherState{
		nonce:  0,
		hasKey: true,
		cipher: c,
	}
	copy(cs.key[:], key)
	if err := cs.rebuildKeyed(); err != nil {
		cs.Destroy()
		return nil, err
	}
	return cs, nil
}

// rebuildKeyed refreshes the cached keyed AEAD from the current key.
// No-op (cache stays nil, stateless path used) when the cipher does not
// implement KeyedCipher. Must be called after every key change.
func (cs *CipherState) rebuildKeyed() error {
	cs.keyed = nil
	kc, ok := cs.cipher.(KeyedCipher)
	if !ok {
		return nil
	}
	keyed, err := kc.NewKeyed(cs.key)
	if err != nil {
		return fmt.Errorf("%w: keyed AEAD: %v", ErrCipher, err)
	}
	cs.keyed = keyed
	return nil
}

// encrypt dispatches to the cached keyed AEAD when available, otherwise
// to the stateless per-call path.
func (cs *CipherState) encrypt(nonce uint64, ad, plaintext, out []byte) ([]byte, error) {
	if cs.keyed != nil {
		return cs.keyed.Encrypt(nonce, ad, plaintext, out)
	}
	return cs.cipher.Encrypt(cs.key, nonce, ad, plaintext, out)
}

// decrypt dispatches to the cached keyed AEAD when available, otherwise
// to the stateless per-call path.
func (cs *CipherState) decrypt(nonce uint64, ad, ciphertext, out []byte) ([]byte, error) {
	if cs.keyed != nil {
		return cs.keyed.Decrypt(nonce, ad, ciphertext, out)
	}
	return cs.cipher.Decrypt(cs.key, nonce, ad, ciphertext, out)
}

// HasKey returns true if a key has been set.
// Returns false for nil CipherState, which represents the "empty" state before
// the first MixKey call in SymmetricState.
func (cs *CipherState) HasKey() bool {
	if cs == nil {
		return false
	}
	return cs.hasKey
}

// EncryptWithAd encrypts plaintext with the given associated data using the
// current nonce, then advances the nonce. Returns the ciphertext (plaintext + tag).
//
// Returns ErrNonceOverflow if the nonce was exhausted by a previous call.
// Returns ErrDestroyed if Destroy has been called.
func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if cs == nil {
		return nil, ErrCipher
	}
	if cs.destroyed {
		return nil, ErrDestroyed
	}
	if !cs.hasKey {
		return nil, ErrCipher
	}
	if cs.overflowed {
		return nil, ErrNonceOverflow
	}

	out := make([]byte, len(plaintext)+TagLen)
	result, err := cs.encrypt(cs.nonce, ad, plaintext, out)
	if err != nil {
		zeroSlice(out)
		return nil, err
	}

	// Nonce overflow is a post-check: the operation at MaxUint64 succeeds,
	// then all future operations are blocked.
	if cs.nonce == math.MaxUint64 {
		cs.overflowed = true
	} else {
		cs.nonce++
	}

	return result, nil
}

// DecryptWithAd decrypts ciphertext with the given associated data using the
// current nonce, then advances the nonce. Returns the plaintext.
//
// Returns ErrDecrypt if authentication fails.
// Returns ErrNonceOverflow if the nonce was exhausted by a previous call.
func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if cs == nil {
		return nil, ErrCipher
	}
	if cs.destroyed {
		return nil, ErrDestroyed
	}
	if !cs.hasKey {
		return nil, ErrCipher
	}
	if cs.overflowed {
		return nil, ErrNonceOverflow
	}

	if len(ciphertext) < TagLen {
		return nil, ErrDecrypt
	}

	out := make([]byte, len(ciphertext))
	result, err := cs.decrypt(cs.nonce, ad, ciphertext, out)
	if err != nil {
		zeroSlice(out)
		return nil, err
	}

	if cs.nonce == math.MaxUint64 {
		cs.overflowed = true
	} else {
		cs.nonce++
	}

	return result, nil
}

// Rekey replaces the current key by encrypting a block of zeros with the
// MaxUint64 nonce. This calls the raw AEAD directly (not through EncryptWithAd)
// to avoid triggering the nonce overflow guard.
//
// Per the Noise specification, Rekey does NOT reset the nonce counter.
func (cs *CipherState) Rekey() error {
	if cs == nil {
		return ErrCipher
	}
	if cs.destroyed {
		return ErrDestroyed
	}
	if !cs.hasKey {
		return ErrCipher
	}

	var zeros [KeyLen]byte
	out := make([]byte, KeyLen+TagLen)
	result, err := cs.encrypt(math.MaxUint64, nil, zeros[:], out)
	if err != nil {
		zeroSlice(out)
		return fmt.Errorf("%w: rekey failed: %v", ErrCipher, err)
	}

	// Take the first KeyLen bytes as the new key, discard the tag.
	copy(cs.key[:], result[:KeyLen])
	zeroSlice(out)

	// The cached keyed AEAD is bound to the OLD key; rebuild it or every
	// subsequent operation would silently keep using the old key.
	if err := cs.rebuildKeyed(); err != nil {
		cs.Destroy()
		return err
	}
	return nil
}

// EncryptWithAdInPlace encrypts msgLen bytes from inOut in-place, appending the
// authentication tag. The buffer must have room for msgLen + TagLen bytes.
// Returns the total ciphertext length.
func (cs *CipherState) EncryptWithAdInPlace(ad []byte, inOut []byte, msgLen int) (int, error) {
	if cs == nil {
		return 0, ErrCipher
	}
	if cs.destroyed {
		return 0, ErrDestroyed
	}
	if !cs.hasKey {
		return 0, ErrCipher
	}
	if cs.overflowed {
		return 0, ErrNonceOverflow
	}

	outLen := msgLen + TagLen
	if len(inOut) < outLen {
		return 0, fmt.Errorf("%w: in-place buffer too small: need %d, have %d",
			ErrBufferTooSmall, outLen, len(inOut))
	}

	// Copy plaintext to a temporary buffer to avoid aliasing issues during encrypt.
	plaintext := make([]byte, msgLen)
	copy(plaintext, inOut[:msgLen])
	_, err := cs.encrypt(cs.nonce, ad, plaintext, inOut[:outLen])
	zeroSlice(plaintext)
	if err != nil {
		return 0, err
	}

	if cs.nonce == math.MaxUint64 {
		cs.overflowed = true
	} else {
		cs.nonce++
	}

	return outLen, nil
}

// DecryptWithAdInPlace decrypts msgLen bytes from inOut in-place.
// Returns the plaintext length (msgLen - TagLen).
func (cs *CipherState) DecryptWithAdInPlace(ad []byte, inOut []byte, msgLen int) (int, error) {
	if cs == nil {
		return 0, ErrCipher
	}
	if cs.destroyed {
		return 0, ErrDestroyed
	}
	if !cs.hasKey {
		return 0, ErrCipher
	}
	if cs.overflowed {
		return 0, ErrNonceOverflow
	}

	if msgLen < TagLen {
		return 0, ErrDecrypt
	}
	if msgLen > len(inOut) {
		return 0, fmt.Errorf("%w: msgLen %d exceeds buffer %d", ErrBufferTooSmall, msgLen, len(inOut))
	}

	ptLen := msgLen - TagLen
	ciphertext := make([]byte, msgLen)
	copy(ciphertext, inOut[:msgLen])
	_, err := cs.decrypt(cs.nonce, ad, ciphertext, inOut[:ptLen])
	zeroSlice(ciphertext)
	if err != nil {
		return 0, err
	}

	if cs.nonce == math.MaxUint64 {
		cs.overflowed = true
	} else {
		cs.nonce++
	}

	return ptLen, nil
}

// setNonce sets the nonce value. Internal use only (unexported).
// Used by TransportState.SetReceivingNonce for receive-side nonce synchronization.
func (cs *CipherState) setNonce(n uint64) {
	cs.nonce = n
	cs.overflowed = false
}

// Nonce returns the current nonce value.
func (cs *CipherState) Nonce() uint64 {
	return cs.nonce
}

// Destroy zeros the key, resets all state, and marks this CipherState as destroyed.
// All subsequent operations return ErrDestroyed.
func (cs *CipherState) Destroy() {
	if cs == nil {
		return
	}
	for i := range cs.key {
		cs.key[i] = 0
	}
	cs.nonce = 0
	cs.hasKey = false
	cs.overflowed = false
	cs.cipher = nil
	// The keyed AEAD holds expanded key material that cannot be zeroed
	// explicitly; dropping the reference leaves it to the GC (documented
	// on KeyedAEAD).
	cs.keyed = nil
	cs.destroyed = true
}

// IsDestroyed returns true if Destroy has been called.
// Returns true for nil CipherState.
func (cs *CipherState) IsDestroyed() bool {
	if cs == nil {
		return true
	}
	return cs.destroyed
}
