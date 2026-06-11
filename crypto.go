package clatter

import "io"

// RNG abstracts a random number generator.
// Default: crypto/rand.Reader. Testing: deterministic.
type RNG interface {
	io.Reader
}

// DH abstracts a Diffie-Hellman key exchange algorithm.
type DH interface {
	// Name returns the algorithm name for protocol string construction.
	Name() string
	// GenerateKeypair generates a new keypair using the given RNG.
	GenerateKeypair(rng RNG) (KeyPair, error)
	// DH performs DH between our secret and their public key.
	// Returns the shared secret. Rejects low-order public keys with
	// ErrDHLowOrder: the Noise spec (section 4.1) permits either
	// returning output that is purely a function of the public key or
	// signaling an error; go-clatter signals an error.
	DH(kp KeyPair, pubkey []byte) ([]byte, error)
	// PubKeyLen returns the public key length in bytes.
	PubKeyLen() int
}

// Cipher abstracts an AEAD cipher (ChaCha20Poly1305 or AES-256-GCM).
type Cipher interface {
	// Name returns the cipher name for protocol string construction.
	Name() string
	// Encrypt encrypts plaintext with the given key, nonce, and AD.
	// Appends the authentication tag. out must have room for plaintext + TagLen().
	// In-place: out may alias plaintext (verified empirically).
	Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error)
	// Decrypt decrypts ciphertext with the given key, nonce, and AD.
	// out must have room for ciphertext - TagLen().
	// In-place: out may alias ciphertext.
	Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error)
	// TagLen returns the AEAD tag length (always 16 for both ciphers).
	TagLen() int
	// KeyLen returns the key length (always 32).
	KeyLen() int
}

// HashFunc abstracts a hash function (SHA-256, SHA-512, BLAKE2s, BLAKE2b).
type HashFunc interface {
	// Name returns the hash name for protocol string construction.
	Name() string
	// HashLen returns the hash output length in bytes.
	HashLen() int
	// BlockLen returns the hash block length in bytes.
	BlockLen() int
	// Hash computes the hash of data.
	Hash(data []byte) []byte
	// NewHMAC returns a new HMAC writer keyed with key.
	NewHMAC(key []byte) HMACWriter
}

// HMACWriter computes HMAC incrementally via Write calls, then Sum.
type HMACWriter interface {
	Write(p []byte) (n int, err error)
	Sum() []byte
}

// KeyedCipher is an optional interface a Cipher may implement so that
// CipherState can build the keyed AEAD once per key instead of running
// the key schedule on every message (AES key expansion and ChaCha state
// setup are per-key work, not per-message work).
//
// Implementations must produce byte-identical output to their stateless
// Encrypt/Decrypt methods for the same key, nonce, AD, and input. Ciphers
// that do not implement this interface keep the stateless per-call path.
type KeyedCipher interface {
	Cipher
	// NewKeyed returns an AEAD instance bound to key.
	NewKeyed(key [32]byte) (KeyedAEAD, error)
}

// KeyedAEAD is an AEAD bound to a fixed key, produced by
// KeyedCipher.NewKeyed. Nonce encoding is the implementation's
// responsibility and must match its stateless counterpart.
//
// Note: the underlying AEAD holds expanded key material internally that
// cannot be explicitly zeroed; dropping the reference (CipherState.Destroy)
// leaves it to the garbage collector. This is inherent to wrapping
// stdlib/x-crypto AEADs (same caveat as expanded signing keys).
type KeyedAEAD interface {
	// Encrypt encrypts plaintext with the bound key. Appends the tag.
	// In-place: out may alias plaintext.
	Encrypt(nonce uint64, ad, plaintext, out []byte) ([]byte, error)
	// Decrypt decrypts ciphertext with the bound key.
	// In-place: out may alias ciphertext.
	Decrypt(nonce uint64, ad, ciphertext, out []byte) ([]byte, error)
}

// KEM abstracts a Key Encapsulation Mechanism (ML-KEM-768 or ML-KEM-1024).
type KEM interface {
	// Name returns the KEM name for protocol string construction.
	Name() string
	// GenerateKeypair generates a new KEM keypair.
	// rng is used for deterministic testing (reads seed bytes).
	GenerateKeypair(rng RNG) (KeyPair, error)
	// Encapsulate generates a shared secret and ciphertext from a public key.
	//
	// rng is honored only by deterministic testing implementations (the
	// *Testing KEM constructors). Production implementations (ML-KEM,
	// HQC) IGNORE rng for encapsulation and draw entropy from the
	// underlying library's internal CSPRNG. Do not assume WithRNG
	// controls production encapsulation randomness.
	Encapsulate(pk []byte, rng RNG) (ct, ss []byte, err error)
	// Decapsulate recovers the shared secret from a ciphertext and secret key.
	Decapsulate(ct, sk []byte) ([]byte, error)
	// PubKeyLen returns the public key length in bytes.
	PubKeyLen() int
	// SecretKeyLen returns the secret key length (64 for Go seed form).
	SecretKeyLen() int
	// CiphertextLen returns the ciphertext length in bytes.
	CiphertextLen() int
	// SharedSecretLen returns the shared secret length (always 32).
	SharedSecretLen() int
}
