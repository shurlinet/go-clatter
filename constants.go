package clatter

// Protocol constants matching Rust Clatter (constants.rs).
const (
	// MaxMessageLen is the maximum Noise message length (spec-mandated).
	MaxMessageLen = 65535

	// PSKLen is the required length of a pre-shared key in bytes.
	PSKLen = 32

	// MaxPSKs is the maximum number of PSKs that can be queued.
	MaxPSKs = 4

	// MaxHashLen is the maximum hash output length in bytes.
	// SHA-512 and BLAKE2b output 64 bytes. Used for h/ck array sizing.
	MaxHashLen = 64

	// KeyLen is the standard symmetric key length in bytes.
	KeyLen = 32

	// TagLen is the AEAD authentication tag length in bytes.
	TagLen = 16
)
