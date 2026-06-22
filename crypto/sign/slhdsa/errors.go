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

	// ErrInvalidPublicKey is returned when ParsePublicKey receives malformed
	// data. It is the umbrella sentinel: every ParsePublicKey failure matches
	// errors.Is(err, ErrInvalidPublicKey). Structural causes additionally wrap a
	// specific sentinel (ErrUnsupportedVersion, ErrInvalidParamSet, or
	// ErrInvalidPublicKeySize) so a caller can distinguish them if desired.
	ErrInvalidPublicKey = errors.New("slhdsa: invalid public key")

	// ErrUnsupportedVersion is returned (wrapped under ErrInvalidPublicKey) when
	// ParsePublicKey encounters a self-describing public key whose version byte
	// is not the supported version (1). It signals a wire-format version
	// mismatch, distinct from a bad parameter set or wrong length.
	ErrUnsupportedVersion = errors.New("slhdsa: unsupported public key version")

	// ErrContextTooLong is returned when the context string exceeds 255 bytes.
	ErrContextTooLong = errors.New("slhdsa: context must be at most 255 bytes")

	// ErrPreHashNotSupported is returned when pre-hash mode is used with a
	// parameter set that has no FIPS 205 OID defined (e.g., BLAKE3 variants).
	ErrPreHashNotSupported = errors.New("slhdsa: pre-hash mode not supported for this parameter set")

	// ErrInvalidHashFunc is returned for unrecognized pre-hash function values.
	ErrInvalidHashFunc = errors.New("slhdsa: invalid hash function for pre-hash")

	// ErrInvalidDigestLength is returned by the crypto.Signer Sign pre-hash
	// path when the supplied digest is not exactly the output length of the
	// selected hash function. In pre-hash mode the digest is the pre-computed
	// PH(M) (FIPS 205 Algorithm 25), which has a fixed per-hash length.
	ErrInvalidDigestLength = errors.New("slhdsa: digest length does not match the selected hash function")
)
