package slhdsa

import "errors"

var (
	// ErrDestroyed is returned when operating on a destroyed private key.
	ErrDestroyed = errors.New("slhdsa: key has been destroyed")

	// ErrInvalidParamSet is returned for unrecognized parameter set values.
	ErrInvalidParamSet = errors.New("slhdsa: invalid parameter set")

	// ErrInvalidSecretKeySize is returned when secret key bytes have wrong length.
	ErrInvalidSecretKeySize = errors.New("slhdsa: invalid secret key size")

	// ErrInvalidPublicKeySize is returned when public key bytes have wrong length.
	ErrInvalidPublicKeySize = errors.New("slhdsa: invalid public key size")

	// ErrInvalidPublicKey is returned when ParsePublicKey receives malformed data.
	ErrInvalidPublicKey = errors.New("slhdsa: invalid public key")

	// ErrContextTooLong is returned when the context string exceeds 255 bytes.
	ErrContextTooLong = errors.New("slhdsa: context must be at most 255 bytes")

	// ErrPreHashNotSupported is returned when pre-hash mode is used with a
	// parameter set that has no FIPS 205 OID defined (e.g., BLAKE3 variants).
	ErrPreHashNotSupported = errors.New("slhdsa: pre-hash mode not supported for this parameter set")

	// ErrInvalidHashFunc is returned for unrecognized pre-hash function values.
	ErrInvalidHashFunc = errors.New("slhdsa: invalid hash function for pre-hash")
)
