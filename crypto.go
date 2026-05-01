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
	// Returns the shared secret. Returns zeros on low-order input (F84).
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
	// In-place: out may alias plaintext (F104 verified).
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

// KEM abstracts a Key Encapsulation Mechanism (ML-KEM-768 or ML-KEM-1024).
type KEM interface {
	// Name returns the KEM name for protocol string construction.
	Name() string
	// GenerateKeypair generates a new KEM keypair.
	// rng is used for deterministic testing (reads seed bytes).
	GenerateKeypair(rng RNG) (KeyPair, error)
	// Encapsulate generates a shared secret and ciphertext from a public key.
	// rng is used for deterministic testing.
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
