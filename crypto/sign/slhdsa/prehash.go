package slhdsa

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	crypto_rand "crypto/rand"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// HashFunc identifies a hash function for pre-hash mode (Hash-SLH-DSA).
//
// These values are specific to SLH-DSA pre-hash and do NOT correspond
// to Go's crypto.Hash constants (SHAKE has no crypto.Hash equivalent).
type HashFunc uint8

// Pre-hash function identifiers.
// All hash functions listed in FIPS 205 Table 2 plus additional NIST-approved
// hash functions that appear in ACVP test vectors.
const (
	HashSHA2_224    HashFunc = 1
	HashSHA2_256    HashFunc = 2
	HashSHA2_384    HashFunc = 3
	HashSHA2_512    HashFunc = 4
	HashSHA2_512224 HashFunc = 5 // SHA-512/224
	HashSHA2_512256 HashFunc = 6 // SHA-512/256
	HashSHA3_224    HashFunc = 7
	HashSHA3_256    HashFunc = 8
	HashSHA3_384    HashFunc = 9
	HashSHA3_512    HashFunc = 10
	HashSHAKE128    HashFunc = 11
	HashSHAKE256    HashFunc = 12
)

// Pre-hash OIDs from FIPS 205 Table 2 (DER-encoded ASN.1).
// OID arc: 2.16.840.1.101.3.4.2.{x}
// Format: [tag=0x06 | length=0x09 | oid_bytes...]
// All are 11 bytes: the common prefix differs only in the last byte.
var (
	oidSHA2_224    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}
	oidSHA2_256    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
	oidSHA2_384    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}
	oidSHA2_512    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}
	oidSHA2_512224 = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}
	oidSHA2_512256 = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}
	oidSHA3_224    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}
	oidSHA3_256    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}
	oidSHA3_384    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}
	oidSHA3_512    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a}
	oidSHAKE128    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b}
	oidSHAKE256    = [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c}
)

// preHashOID returns a fresh copy of the DER-encoded OID for the given hash function.
// Returns a copy to prevent callers from mutating the global OID arrays.
func preHashOID(hf HashFunc) []byte {
	var src *[11]byte
	switch hf {
	case HashSHA2_224:
		src = &oidSHA2_224
	case HashSHA2_256:
		src = &oidSHA2_256
	case HashSHA2_384:
		src = &oidSHA2_384
	case HashSHA2_512:
		src = &oidSHA2_512
	case HashSHA2_512224:
		src = &oidSHA2_512224
	case HashSHA2_512256:
		src = &oidSHA2_512256
	case HashSHA3_224:
		src = &oidSHA3_224
	case HashSHA3_256:
		src = &oidSHA3_256
	case HashSHA3_384:
		src = &oidSHA3_384
	case HashSHA3_512:
		src = &oidSHA3_512
	case HashSHAKE128:
		src = &oidSHAKE128
	case HashSHAKE256:
		src = &oidSHAKE256
	default:
		return nil
	}
	out := make([]byte, 11)
	copy(out, src[:])
	return out
}

// computePreHash computes PH(M) using the specified hash function.
// For SHAKE XOFs, fixed output lengths are used per FIPS 205 Section 9.2:
// SHAKE-128 -> 32 bytes, SHAKE-256 -> 64 bytes.
func computePreHash(hf HashFunc, msg []byte) []byte {
	switch hf {
	case HashSHA2_224:
		h := sha256.New224()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA2_256:
		h := sha256.New()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA2_384:
		h := sha512.New384()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA2_512:
		h := sha512.New()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA2_512224:
		h := sha512.New512_224()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA2_512256:
		h := sha512.New512_256()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA3_224:
		h := sha3.New224()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA3_256:
		h := sha3.New256()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA3_384:
		h := sha3.New384()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHA3_512:
		h := sha3.New512()
		h.Write(msg)
		return h.Sum(nil)
	case HashSHAKE128:
		h := sha3.NewShake128()
		h.Write(msg)
		buf := make([]byte, 32)
		io.ReadFull(h, buf) //nolint:errcheck // SHAKE never short-reads
		return buf
	case HashSHAKE256:
		h := sha3.NewShake256()
		h.Write(msg)
		buf := make([]byte, 64)
		io.ReadFull(h, buf) //nolint:errcheck
		return buf
	default:
		return nil
	}
}

func validPreHashFunc(hf HashFunc) bool {
	return hf >= HashSHA2_224 && hf <= HashSHAKE256
}

// makeMPrimePreHash constructs M' for Hash-SLH-DSA (FIPS 205 Algorithm 25).
// M' = [0x01 | ctxLen | ctx | OID | PH(M)]
func makeMPrimePreHash(msg []byte, hf HashFunc, ctx string) []byte {
	oid := preHashOID(hf)
	phm := computePreHash(hf, msg)
	mp := make([]byte, 0, 2+len(ctx)+len(oid)+len(phm))
	mp = append(mp, 0x01)
	mp = append(mp, byte(len(ctx)))
	mp = append(mp, []byte(ctx)...)
	mp = append(mp, oid...)
	mp = append(mp, phm...)
	return mp
}

// SignPreHash signs msg using pre-hash mode with the specified hash function
// and empty context. Use SignPreHashWithContext for domain separation.
//
// Implements FIPS 205 Algorithm 25 (Hash-SLH-DSA-Sign).
// BLAKE3 parameter sets do not support pre-hash (no FIPS 205 OID).
func (k *PrivateKey) SignPreHash(msg []byte, hashFunc HashFunc) ([]byte, error) {
	return k.SignPreHashWithContext(msg, hashFunc, "")
}

// SignPreHashWithContext signs msg using pre-hash mode with context.
func (k *PrivateKey) SignPreHashWithContext(msg []byte, hashFunc HashFunc, ctx string) ([]byte, error) {
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
	if k.paramSet.IsBLAKE3() {
		return nil, ErrPreHashNotSupported
	}
	if !validPreHashFunc(hashFunc) {
		return nil, ErrInvalidHashFunc
	}

	mprime := makeMPrimePreHash(normalizeMsg(msg), hashFunc, ctx)
	n := int(k.params.N)
	addrnd := make([]byte, n)
	if _, err := io.ReadFull(crypto_rand.Reader, addrnd); err != nil {
		return nil, fmt.Errorf("slhdsa: generate addrnd: %w", err)
	}
	sig := internal.SLHSignInternal(k.params, mprime, k.internalKey, addrnd)
	return sig.Bytes(), nil
}

// VerifyPreHash verifies a pre-hash signature with empty context.
// Use VerifyPreHashWithContext for domain separation.
//
// Implements FIPS 205 Algorithm 26 (Hash-SLH-DSA-Verify).
func (k *PublicKey) VerifyPreHash(msg, sig []byte, hashFunc HashFunc) bool {
	return k.VerifyPreHashWithContext(msg, sig, hashFunc, "")
}

// VerifyPreHashWithContext verifies a pre-hash signature with context.
func (k *PublicKey) VerifyPreHashWithContext(msg, sig []byte, hashFunc HashFunc, ctx string) bool {
	if k == nil || !k.initialized() {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	if k.paramSet.IsBLAKE3() {
		return false
	}
	if !validPreHashFunc(hashFunc) {
		return false
	}
	if len(sig) != sigSize(k.params) {
		return false
	}
	loaded, err := internal.LoadSignature(k.params, sig)
	if err != nil {
		return false
	}
	mprime := makeMPrimePreHash(normalizeMsg(msg), hashFunc, ctx)
	return internal.SLHVerifyInternal(k.params, mprime, loaded, k.internalPK)
}

