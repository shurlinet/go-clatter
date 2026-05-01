package clatter

import "crypto/subtle"

// SecretKey32 is a 32-byte secret key stored as a fixed array.
// Fixed arrays don't move in Go's GC, unlike slices.
// Call Destroy() to zero the key when done.
type SecretKey32 struct {
	key       [KeyLen]byte
	destroyed bool
}

// NewSecretKey32 creates a SecretKey32 from a 32-byte slice.
func NewSecretKey32(b []byte) (SecretKey32, error) {
	if len(b) != KeyLen {
		return SecretKey32{}, ErrInvalidKeyLength
	}
	var k SecretKey32
	copy(k.key[:], b)
	return k, nil
}

// Bytes returns a copy of the key bytes. Panics if destroyed.
func (s *SecretKey32) Bytes() [KeyLen]byte {
	if s.destroyed {
		panic("use of destroyed SecretKey32")
	}
	return s.key
}

// Slice returns a slice view of the key. Panics if destroyed.
func (s *SecretKey32) Slice() []byte {
	if s.destroyed {
		panic("use of destroyed SecretKey32")
	}
	return s.key[:]
}

// Destroy zeros all key bytes and marks the key as destroyed.
func (s *SecretKey32) Destroy() {
	for i := range s.key {
		s.key[i] = 0
	}
	s.destroyed = true
}

// IsDestroyed returns true if Destroy() has been called.
func (s *SecretKey32) IsDestroyed() bool {
	return s.destroyed
}

// Equal performs constant-time comparison of two SecretKey32 values.
func (s *SecretKey32) Equal(other *SecretKey32) bool {
	if s.destroyed || other.destroyed {
		return false
	}
	return subtle.ConstantTimeCompare(s.key[:], other.key[:]) == 1
}

// SecretKey64 is a 64-byte secret key (used for ML-KEM seeds).
type SecretKey64 struct {
	key       [MaxHashLen]byte
	destroyed bool
}

// NewSecretKey64 creates a SecretKey64 from a 64-byte slice.
func NewSecretKey64(b []byte) (SecretKey64, error) {
	if len(b) != MaxHashLen {
		return SecretKey64{}, ErrInvalidKeyLength
	}
	var k SecretKey64
	copy(k.key[:], b)
	return k, nil
}

// Bytes returns a copy of the key bytes. Panics if destroyed.
func (s *SecretKey64) Bytes() [MaxHashLen]byte {
	if s.destroyed {
		panic("use of destroyed SecretKey64")
	}
	return s.key
}

// Slice returns a slice view of the key. Panics if destroyed.
func (s *SecretKey64) Slice() []byte {
	if s.destroyed {
		panic("use of destroyed SecretKey64")
	}
	return s.key[:]
}

// Destroy zeros all key bytes and marks the key as destroyed.
func (s *SecretKey64) Destroy() {
	for i := range s.key {
		s.key[i] = 0
	}
	s.destroyed = true
}

// IsDestroyed returns true if Destroy() has been called.
func (s *SecretKey64) IsDestroyed() bool {
	return s.destroyed
}

// Equal performs constant-time comparison of two SecretKey64 values.
func (s *SecretKey64) Equal(other *SecretKey64) bool {
	if s.destroyed || other.destroyed {
		return false
	}
	return subtle.ConstantTimeCompare(s.key[:], other.key[:]) == 1
}

// KeyPair holds a public key (exported) and a secret key (unexported).
// The secret is never directly accessible; use SecretSlice() for controlled access.
type KeyPair struct {
	Public []byte
	secret []byte
}

// NewKeyPair creates a KeyPair from public and secret byte slices.
// Both are copied.
func NewKeyPair(pub, secret []byte) KeyPair {
	kp := KeyPair{
		Public: make([]byte, len(pub)),
		secret: make([]byte, len(secret)),
	}
	copy(kp.Public, pub)
	copy(kp.secret, secret)
	return kp
}

// SecretSlice returns a reference to the secret key bytes.
func (kp *KeyPair) SecretSlice() []byte {
	return kp.secret
}

// Destroy zeros the secret key material.
func (kp *KeyPair) Destroy() {
	for i := range kp.secret {
		kp.secret[i] = 0
	}
}

// Clone returns a deep copy of the KeyPair.
func (kp *KeyPair) Clone() KeyPair {
	return NewKeyPair(kp.Public, kp.secret)
}

// PSKQueue holds up to MaxPSKs pre-shared keys in FIFO order.
// Freed slots are zeroed immediately.
type PSKQueue struct {
	keys  [MaxPSKs][PSKLen]byte
	count int
}

// Push adds a PSK to the queue. Returns error if full or wrong length.
func (q *PSKQueue) Push(psk []byte) error {
	if len(psk) != PSKLen {
		return ErrPSKInvalid
	}
	if q.count >= MaxPSKs {
		return ErrPSKQueueFull
	}
	copy(q.keys[q.count][:], psk)
	q.count++
	return nil
}

// Pop removes and returns the first PSK. Returns error if empty.
func (q *PSKQueue) Pop() ([PSKLen]byte, error) {
	if q.count == 0 {
		return [PSKLen]byte{}, ErrPSKInvalid
	}
	var out [PSKLen]byte
	copy(out[:], q.keys[0][:])

	// Shift remaining keys forward, then zero the vacated last slot.
	for i := 0; i < q.count-1; i++ {
		q.keys[i] = q.keys[i+1]
	}
	for i := range q.keys[q.count-1] {
		q.keys[q.count-1][i] = 0
	}
	q.count--
	return out, nil
}

// Len returns the number of PSKs in the queue.
func (q *PSKQueue) Len() int {
	return q.count
}

// Destroy zeros all PSK material.
func (q *PSKQueue) Destroy() {
	for i := range q.keys {
		for j := range q.keys[i] {
			q.keys[i][j] = 0
		}
	}
	q.count = 0
}
