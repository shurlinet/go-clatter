package clatter

import (
	"fmt"
	"math"
)

// CipherState holds a symmetric cipher key and monotonic nonce.
// Matches Rust Clatter's cipherstate.rs.
//
// F27: SetNonce is NOT exported - nonce rollback = catastrophic key reuse.
// F34: No Take() exposed - internal copy zeros source.
// F54: Rekey calls raw AEAD with MaxUint64 nonce, bypassing overflow check.
// F109: split() creates CipherStates with nonce=0.
// F165: CipherState is nil/absent before first mixKey in SymmetricState.
// F168: Constructor returns error on wrong key length (Clatter panics).
// F170: Nonce overflow is post-check: MaxUint64 encrypts, THEN overflowed=true.
//       Next call returns ErrNonceOverflow. One encrypt at MaxUint64, then blocked.
type CipherState struct {
	key        [KeyLen]byte
	nonce      uint64
	hasKey     bool
	overflowed bool
	destroyed  bool
	cipher     Cipher // the raw AEAD implementation
}

// NewCipherState creates a CipherState with the given key and nonce=0.
// F109: Both CipherStates from split() start at nonce 0.
// F168: Returns error on wrong key length.
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
	// Caller is responsible for zeroing key after this call.
	// NewCipherState does NOT zero the source: Split() passes the same
	// slice to two NewCipherState calls, and defensive zeroing here would
	// give the second CipherState a zero key.
	return cs, nil
}

// HasKey returns true if a key has been set (false before first mixKey).
// F165: SymmetricState checks this to decide encrypt vs plaintext copy.
func (cs *CipherState) HasKey() bool {
	if cs == nil {
		return false
	}
	return cs.hasKey
}

// EncryptWithAd encrypts plaintext with associated data.
// Nonce increments after each call.
// F170: Post-check overflow - MaxUint64 encrypts successfully, then blocks.
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
	result, err := cs.cipher.Encrypt(cs.key, cs.nonce, ad, plaintext, out)
	if err != nil {
		zeroSlice(out)
		return nil, err
	}

	// F170: Post-check. nonce was used successfully, now try to advance.
	if cs.nonce == math.MaxUint64 {
		cs.overflowed = true
	} else {
		cs.nonce++
	}

	return result, nil
}

// DecryptWithAd decrypts ciphertext with associated data.
// F170: Same post-check overflow logic as encrypt.
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
	result, err := cs.cipher.Decrypt(cs.key, cs.nonce, ad, ciphertext, out)
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

// Rekey replaces the key using AEAD encrypt with MaxUint64 nonce.
// F54: Calls raw AEAD Seal directly, NOT through EncryptWithAd
// (would hit overflow guard). Noise spec: rekey does NOT reset nonce (F135).
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

	// AEAD encrypt with nonce=MaxUint64, empty AD, zeros plaintext.
	// F110: All intermediates zeroed after use.
	var zeros [KeyLen]byte
	out := make([]byte, KeyLen+TagLen)
	result, err := cs.cipher.Encrypt(cs.key, math.MaxUint64, nil, zeros[:], out)
	if err != nil {
		zeroSlice(out)
		return fmt.Errorf("%w: rekey failed: %v", ErrCipher, err)
	}

	// Truncate to KeyLen (discard tag), then zero the full result buffer
	copy(cs.key[:], result[:KeyLen])
	zeroSlice(out)
	return nil
}

// EncryptWithAdInPlace encrypts msgLen bytes in inOut in-place.
// Returns total ciphertext length (msgLen + TagLen).
// F104: In-place Seal verified for Go's AES-GCM and ChaCha20Poly1305.
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

	// Copy plaintext to temp buffer to avoid aliasing issues during encrypt.
	plaintext := make([]byte, msgLen)
	copy(plaintext, inOut[:msgLen])
	_, err := cs.cipher.Encrypt(cs.key, cs.nonce, ad, plaintext, inOut[:outLen])
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

// DecryptWithAdInPlace decrypts msgLen bytes in inOut in-place.
// Returns plaintext length (msgLen - TagLen).
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
	_, err := cs.cipher.Decrypt(cs.key, cs.nonce, ad, ciphertext, inOut[:ptLen])
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

// setNonce sets the nonce value. Internal only, NOT exported (F27).
// Used for SetReceivingNonce in TransportState (F133).
func (cs *CipherState) setNonce(n uint64) {
	cs.nonce = n
	cs.overflowed = false
}

// Nonce returns the current nonce value. Read-only access for testing/transport.
func (cs *CipherState) Nonce() uint64 {
	return cs.nonce
}

// Destroy zeros ALL fields and marks the CipherState as destroyed.
// F29: Called by SymmetricState.mixKey before replacing the old CipherState.
// Zeros key, nonce (usage count is metadata), and nils cipher reference.
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
	cs.destroyed = true
}

// IsDestroyed returns true if the CipherState has been zeroed.
func (cs *CipherState) IsDestroyed() bool {
	if cs == nil {
		return true
	}
	return cs.destroyed
}
