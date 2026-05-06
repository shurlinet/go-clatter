// Package slhdsa implements SLH-DSA (FIPS 205) digital signatures.
//
// SLH-DSA is a hash-based signature scheme selected by NIST as a backup
// to lattice-based ML-DSA. It provides post-quantum security based solely
// on hash function security, with no algebraic structure to attack.
//
// This package wraps an embedded Trail of Bits go-slh-dsa engine and adds:
// lifecycle management (Destroy, secret zeroing), thread safety (RWMutex),
// pre-hash mode (Hash-SLH-DSA, FIPS 205 Algorithms 25-26), crypto.Signer
// interface, and self-describing public key serialization.
//
// # Parameter Sets
//
// 18 parameter sets are available: 12 FIPS 205 (SHA2 + SHAKE) and
// 6 non-FIPS BLAKE3 variants (added in a later batch). Each parameter set
// offers different tradeoffs between signature size, signing speed, and
// security level:
//
//   - Level 1 (128-bit): SHA2/SHAKE/BLAKE3-128f (fast) and 128s (small sigs)
//   - Level 3 (192-bit): SHA2/SHAKE/BLAKE3-192f and 192s
//   - Level 5 (256-bit): SHA2/SHAKE/BLAKE3-256f and 256s
//
// # Thread Safety
//
// PrivateKey methods are safe for concurrent use. Sign acquires a shared
// read lock; Destroy acquires an exclusive write lock and blocks until
// all in-flight operations complete.
//
// # Key Lifecycle
//
// After Destroy, all secret material is zeroed. The cached PublicKey
// survives Destroy and can still verify signatures. Intermediate secrets
// created during signing (~3MB for 128f) are subject to Go's GC and
// cannot be zeroed by this package.
//
// # Message Size
//
// Pure mode (Sign/SignWithContext) allocates O(message_size) for the
// internal M' construction. For messages larger than available memory,
// use SignPreHash which hashes the message first, producing a fixed-size
// M' regardless of original message size.
//
// # Nonce Reuse Safety
//
// SLH-DSA is safe against RNG nonce reuse. Repeated randomness produces
// repeated signatures without key leakage (unlike ECDSA). Hedged signing
// (the default) uses fresh randomness per signature.
package slhdsa

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	crypto_rand "crypto/rand"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// PrivateKey is an SLH-DSA private key.
//
// All methods are safe for concurrent use. The zero value is not valid;
// use GenerateKey or NewPrivateKeyFromBytes to create a PrivateKey.
type PrivateKey struct {
	mu          sync.RWMutex
	paramSet    ParamSet
	params      internal.ParamSet // cached at construction
	internalKey internal.SLHSecretKey
	pub         *PublicKey
	destroyed   bool
}

// PublicKey is an SLH-DSA public key.
//
// PublicKey has no secret material and no destroyed state.
// A PublicKey obtained via PrivateKey.PublicKey() remains valid
// after the private key is destroyed.
type PublicKey struct {
	paramSet   ParamSet
	params     internal.ParamSet // cached at construction
	internalPK internal.SLHPublicKey
}

// GenerateKey generates a new SLH-DSA key pair using the specified
// parameter set and cryptographic random number generator.
//
// The parameter set must be runtime-ready (BLAKE3 param sets are not
// available until the BLAKE3 hash functions are implemented).
func GenerateKey(ps ParamSet) (*PrivateKey, error) {
	if !runtimeReady(ps) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParamSet, ps)
	}
	params := ps.internalParams()
	n := int(params.N)

	skseed := make([]byte, n)
	skprf := make([]byte, n)
	pkseed := make([]byte, n)
	if _, err := io.ReadFull(crypto_rand.Reader, skseed); err != nil {
		return nil, fmt.Errorf("slhdsa: generate skseed: %w", err)
	}
	if _, err := io.ReadFull(crypto_rand.Reader, skprf); err != nil {
		return nil, fmt.Errorf("slhdsa: generate skprf: %w", err)
	}
	if _, err := io.ReadFull(crypto_rand.Reader, pkseed); err != nil {
		return nil, fmt.Errorf("slhdsa: generate pkseed: %w", err)
	}

	sk, _ := internal.SLHKeygenInternal(params, skseed, skprf, pkseed)
	// Use sk.PublicKey() which clones pkseed/pkroot, ensuring the cached
	// PublicKey survives Destroy (sk.Zero() zeros the shared backing array).
	clonedPK := sk.PublicKey()
	pub := &PublicKey{paramSet: ps, params: params, internalPK: clonedPK}
	return &PrivateKey{
		paramSet:    ps,
		params:      params,
		internalKey: sk,
		pub:         pub,
	}, nil
}

// NewPrivateKeyFromBytes loads a private key from its serialized form.
//
// The bytes must be exactly SecretKeySize(ps) bytes (4*N), in the order
// skseed || skprf || pkseed || pkroot as defined by FIPS 205 Section 8.1.
// The caller is responsible for zeroing their copy of skBytes after use.
func NewPrivateKeyFromBytes(ps ParamSet, skBytes []byte) (*PrivateKey, error) {
	if !runtimeReady(ps) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParamSet, ps)
	}
	params := ps.internalParams()
	if len(skBytes) != int(params.N)*4 {
		return nil, ErrInvalidSecretKeySize
	}
	sk, err := internal.LoadSecretKey(params, skBytes)
	if err != nil {
		return nil, ErrInvalidSecretKeySize
	}
	pk := sk.PublicKey()
	pub := &PublicKey{paramSet: ps, params: params, internalPK: pk}
	return &PrivateKey{
		paramSet:    ps,
		params:      params,
		internalKey: sk,
		pub:         pub,
	}, nil
}

// NewPublicKey creates a public key from raw bytes and an explicit parameter set.
//
// The bytes must be exactly PublicKeySize(ps) bytes (2*N), in the order
// pkseed || pkroot.
func NewPublicKey(ps ParamSet, pubBytes []byte) (*PublicKey, error) {
	if !runtimeReady(ps) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidParamSet, ps)
	}
	params := ps.internalParams()
	if len(pubBytes) != int(params.N)*2 {
		return nil, ErrInvalidPublicKeySize
	}
	pk, err := internal.LoadPublicKey(params, pubBytes)
	if err != nil {
		return nil, ErrInvalidPublicKeySize
	}
	return &PublicKey{paramSet: ps, params: params, internalPK: pk}, nil
}

// ParsePublicKey parses a self-describing public key produced by
// PublicKey.MarshalBinary.
//
// Format: [version=1 | paramset_byte | raw_public_key]
//
// The ParamSet is NOT authenticated. Use application-layer integrity
// checks if the wire format is untrusted.
func ParsePublicKey(data []byte) (*PublicKey, error) {
	if len(data) < 2 {
		return nil, ErrInvalidPublicKey
	}
	if data[0] != 1 {
		return nil, ErrInvalidPublicKey
	}
	ps := ParamSet(data[1])
	if !runtimeReady(ps) {
		return nil, ErrInvalidPublicKey
	}
	params := ps.internalParams()
	expected := int(params.N) * 2
	if len(data) != 2+expected {
		return nil, ErrInvalidPublicKey
	}
	pk, err := internal.LoadPublicKey(params, data[2:])
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	return &PublicKey{paramSet: ps, params: params, internalPK: pk}, nil
}

// --- PrivateKey methods ---

// SignMessage signs msg using hedged randomness (recommended for production).
// Equivalent to SignWithContext(msg, "").
func (k *PrivateKey) SignMessage(msg []byte) ([]byte, error) {
	return k.signPure(msg, "")
}

// SignWithContext signs msg with a context string for domain separation.
// The context must be at most 255 bytes.
func (k *PrivateKey) SignWithContext(msg []byte, ctx string) ([]byte, error) {
	return k.signPure(msg, ctx)
}

// SignDeterministic signs msg deterministically (same message + key = same
// signature). Use only for test vector reproduction; production code should
// use Sign (hedged).
func (k *PrivateKey) SignDeterministic(msg []byte) ([]byte, error) {
	return k.signDeterministic(msg, "")
}

// SignDeterministicWithContext signs msg deterministically with a context string.
func (k *PrivateKey) SignDeterministicWithContext(msg []byte, ctx string) ([]byte, error) {
	return k.signDeterministic(msg, ctx)
}

func (k *PrivateKey) signPure(msg []byte, ctx string) ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.destroyed {
		return nil, ErrDestroyed
	}
	if len(ctx) > 255 {
		return nil, ErrContextTooLong
	}

	mprime := makeMPrime(normalizeMsg(msg), ctx)
	n := int(k.params.N)
	addrnd := make([]byte, n)
	if _, err := io.ReadFull(crypto_rand.Reader, addrnd); err != nil {
		return nil, fmt.Errorf("slhdsa: generate addrnd: %w", err)
	}
	sig := internal.SLHSignInternal(k.params, mprime, k.internalKey, addrnd)
	return sig.Bytes(), nil
}

func (k *PrivateKey) signDeterministic(msg []byte, ctx string) ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.destroyed {
		return nil, ErrDestroyed
	}
	if len(ctx) > 255 {
		return nil, ErrContextTooLong
	}

	mprime := makeMPrime(normalizeMsg(msg), ctx)
	sig := internal.SLHSignInternalDeterministic(k.params, mprime, k.internalKey)
	return sig.Bytes(), nil
}

// Bytes returns the serialized private key (4*N bytes: skseed || skprf || pkseed || pkroot).
// Returns nil after Destroy.
func (k *PrivateKey) Bytes() ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.destroyed {
		return nil, ErrDestroyed
	}
	return k.internalKey.Bytes(), nil
}

// PublicKey returns the public key. The returned PublicKey is cached at
// construction time and survives Destroy.
func (k *PrivateKey) PublicKey() *PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// ParamSet returns the parameter set used by this key.
// Returns 0 (SHA2_128f) for nil receiver.
func (k *PrivateKey) ParamSet() ParamSet {
	if k == nil {
		return 0
	}
	return k.paramSet
}

// Equal reports whether k and x have the same secret key material.
// Returns false if either key is nil or destroyed.
func (k *PrivateKey) Equal(x *PrivateKey) bool {
	if k == nil || x == nil {
		return false
	}
	if k.paramSet != x.paramSet {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	x.mu.RLock()
	defer x.mu.RUnlock()
	if k.destroyed || x.destroyed {
		return false
	}
	return subtle.ConstantTimeCompare(k.internalKey.Bytes(), x.internalKey.Bytes()) == 1
}

// Destroy zeros all secret material in the private key.
// After Destroy, Sign and Bytes return ErrDestroyed.
// The cached PublicKey remains valid.
// Blocks until all in-flight Sign calls complete.
// Safe to call multiple times (idempotent).
func (k *PrivateKey) Destroy() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.destroyed {
		return
	}
	k.destroyed = true
	k.internalKey.Zero()
}

// Public returns the public key as a crypto.PublicKey (implements crypto.Signer).
func (k *PrivateKey) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	return k.pub
}

// SignerOpts provides options for crypto.Signer.Sign.
// Hash selects pure mode (0) or pre-hash mode (non-zero HashFunc).
// Context provides domain separation (max 255 bytes).
type SignerOpts struct {
	Hash    HashFunc
	Context string
}

// HashFunc returns the hash function identifier for crypto.SignerOpts.
func (o *SignerOpts) HashFunc() crypto.Hash {
	if o == nil {
		return 0
	}
	return crypto.Hash(o.Hash)
}

// Sign implements crypto.Signer.
//
// For SLH-DSA, the digest parameter is always the FULL message regardless
// of HashFunc. Pre-hashing is computed internally by the wrapper.
//
// If rand is nil, crypto/rand.Reader is used. If opts is nil or
// opts.HashFunc() == 0, pure mode is used. If opts.HashFunc() != 0,
// pre-hash mode is used.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k == nil {
		return nil, ErrDestroyed
	}

	var ctx string
	var hashFunc HashFunc

	if opts != nil {
		if so, ok := opts.(*SignerOpts); ok {
			ctx = so.Context
			hashFunc = so.Hash
		} else if opts.HashFunc() != 0 {
			hf, ok := cryptoHashToHashFunc(opts.HashFunc())
			if !ok {
				return nil, ErrInvalidHashFunc
			}
			hashFunc = hf
		}
	}

	if hashFunc != 0 {
		return k.SignPreHashWithContext(digest, hashFunc, ctx)
	}
	return k.SignWithContext(digest, ctx)
}

// cryptoHashToHashFunc maps Go's crypto.Hash to our HashFunc.
// Returns false for unsupported hash functions.
func cryptoHashToHashFunc(h crypto.Hash) (HashFunc, bool) {
	switch h {
	case crypto.SHA224:
		return HashSHA2_224, true
	case crypto.SHA256:
		return HashSHA2_256, true
	case crypto.SHA384:
		return HashSHA2_384, true
	case crypto.SHA512:
		return HashSHA2_512, true
	case crypto.SHA512_224:
		return HashSHA2_512224, true
	case crypto.SHA512_256:
		return HashSHA2_512256, true
	case crypto.SHA3_224:
		return HashSHA3_224, true
	case crypto.SHA3_256:
		return HashSHA3_256, true
	case crypto.SHA3_384:
		return HashSHA3_384, true
	case crypto.SHA3_512:
		return HashSHA3_512, true
	default:
		return 0, false
	}
}

// --- PublicKey methods ---

// Verify verifies a signature on msg. Equivalent to VerifyWithContext(msg, sig, "").
func (k *PublicKey) Verify(msg, sig []byte) bool {
	return k.verifyPure(msg, sig, "")
}

// VerifyWithContext verifies a signature on msg with a context string.
func (k *PublicKey) VerifyWithContext(msg, sig []byte, ctx string) bool {
	return k.verifyPure(msg, sig, ctx)
}

func (k *PublicKey) verifyPure(msg, sig []byte, ctx string) bool {
	if k == nil {
		return false
	}
	if !k.initialized() {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	if len(sig) != sigSize(k.params) {
		return false
	}
	loaded, err := internal.LoadSignature(k.params, sig)
	if err != nil {
		return false
	}
	mprime := makeMPrime(normalizeMsg(msg), ctx)
	return internal.SLHVerifyInternal(k.params, mprime, loaded, k.internalPK)
}

// Bytes returns the raw public key bytes (2*N bytes: pkseed || pkroot).
// Returns nil for nil or uninitialized public keys.
func (k *PublicKey) Bytes() []byte {
	if k == nil || !k.initialized() {
		return nil
	}
	return k.internalPK.Bytes()
}

// MarshalBinary returns the self-describing public key encoding.
// Format: [version=1 | paramset_byte | raw_public_key]
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	if k == nil || !k.initialized() {
		return nil, ErrInvalidPublicKey
	}
	raw := k.internalPK.Bytes()
	out := make([]byte, 2+len(raw))
	out[0] = 1
	out[1] = byte(k.paramSet)
	copy(out[2:], raw)
	return out, nil
}

// ParamSet returns the parameter set used by this key.
func (k *PublicKey) ParamSet() ParamSet {
	if k == nil {
		return 0
	}
	return k.paramSet
}

// Equal reports whether k and x are the same public key.
// Returns false if either key is nil or uninitialized.
func (k *PublicKey) Equal(x *PublicKey) bool {
	if k == nil || x == nil {
		return false
	}
	if !k.initialized() || !x.initialized() {
		return false
	}
	if k.paramSet != x.paramSet {
		return false
	}
	return subtle.ConstantTimeCompare(k.Bytes(), x.Bytes()) == 1
}

// initialized reports whether this PublicKey was properly constructed.
// A zero-value PublicKey (never initialized) has empty Bytes().
func (k *PublicKey) initialized() bool {
	return k.params.N > 0
}

// sigSize computes signature size directly from cached params, avoiding
// the internalParams() switch re-evaluation in the verify hot path.
func sigSize(p internal.ParamSet) int {
	n := int(p.N)
	k := int(p.K)
	a := int(p.A)
	h := int(p.H)
	d := int(p.D)
	wl := int(p.GetWOTSLen())
	return n + k*(1+a)*n + (h+d*wl)*n
}

// --- Internal helpers ---

// makeMPrime constructs M' for pure SLH-DSA (FIPS 205 Algorithm 22).
// M' = [0x00 | ctxLen | ctx | M]
func makeMPrime(msg []byte, ctx string) []byte {
	mp := make([]byte, 0, 2+len(ctx)+len(msg))
	mp = append(mp, 0x00)
	mp = append(mp, byte(len(ctx)))
	mp = append(mp, []byte(ctx)...)
	mp = append(mp, msg...)
	return mp
}

// normalizeMsg converts nil to empty slice for consistent MakeMPrime output.
func normalizeMsg(msg []byte) []byte {
	if msg == nil {
		return []byte{}
	}
	return msg
}
