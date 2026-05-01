package clatter

import "errors"

// Sentinel errors for all failure modes. Every Clatter panic becomes a Go error.
// Grouped by subsystem matching Rust Clatter's error hierarchy.
var (
	// Handshake errors
	ErrErrorState      = errors.New("clatter: handshake in error state")
	ErrInvalidState    = errors.New("clatter: invalid handshake state")
	ErrBufferTooSmall  = errors.New("clatter: buffer too small")
	ErrInvalidMessage  = errors.New("clatter: invalid message")
	ErrNotFinished     = errors.New("clatter: handshake not finished")
	ErrAlreadyFinished = errors.New("clatter: handshake already finalized")
	ErrMessageTooLarge = errors.New("clatter: message exceeds maximum length")
	ErrInvalidPattern  = errors.New("clatter: invalid handshake pattern")
	ErrMissingKey      = errors.New("clatter: required key not provided")
	ErrPSKInvalid      = errors.New("clatter: PSK invalid for pattern")
	ErrPSKQueueFull    = errors.New("clatter: PSK queue full")
	ErrOneWayViolation = errors.New("clatter: one-way pattern send/receive violation")
	ErrConcurrentUse   = errors.New("clatter: concurrent handshake use detected")

	// DH errors
	ErrDH         = errors.New("clatter: DH operation failed")
	ErrDHLowOrder = errors.New("clatter: DH low-order point")

	// Cipher errors
	ErrCipher        = errors.New("clatter: cipher operation failed")
	ErrDecrypt       = errors.New("clatter: decryption failed")
	ErrNonceOverflow = errors.New("clatter: nonce overflow")

	// KEM errors
	ErrKEM             = errors.New("clatter: KEM operation failed")
	ErrKEMDecapsulate  = errors.New("clatter: KEM decapsulation failed")
	ErrKEMInvalidKey   = errors.New("clatter: KEM invalid key")

	// Secret lifecycle errors
	ErrDestroyed = errors.New("clatter: use of destroyed secret")

	// Key errors
	ErrInvalidKeyLength = errors.New("clatter: invalid key length")
)
