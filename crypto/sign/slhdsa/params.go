package slhdsa

import (
	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/hashfuncs"
	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// ParamSet identifies an SLH-DSA parameter set.
//
// Byte assignments are permanent wire-format identifiers used in
// MarshalBinary/ParsePublicKey. NEVER reassign existing values.
// New hash families get new ranges (e.g., SM3 = 18-23, NGCC = 24+).
type ParamSet uint8

// FIPS 205 parameter sets (SHA2 + SHAKE, 12 total).
// Interleaved by security level: each level groups SHA2 and SHAKE variants.
const (
	SHA2_128f  ParamSet = 0
	SHA2_128s  ParamSet = 1
	SHAKE_128f ParamSet = 2
	SHAKE_128s ParamSet = 3
	SHA2_192f  ParamSet = 4
	SHA2_192s  ParamSet = 5
	SHAKE_192f ParamSet = 6
	SHAKE_192s ParamSet = 7
	SHA2_256f  ParamSet = 8
	SHA2_256s  ParamSet = 9
	SHAKE_256f ParamSet = 10
	SHAKE_256s ParamSet = 11

	// BLAKE3 parameter sets (non-FIPS, PQC Suite B).
	// Reserved byte range 12-17.
	BLAKE3_128f ParamSet = 12
	BLAKE3_128s ParamSet = 13
	BLAKE3_192f ParamSet = 14
	BLAKE3_192s ParamSet = 15
	BLAKE3_256f ParamSet = 16
	BLAKE3_256s ParamSet = 17

	// maxParamSet is the highest valid ParamSet value.
	// All ParamSet methods guard against values > maxParamSet to prevent panics.
	maxParamSet ParamSet = 17
)

// validParamSet returns true if ps is a recognized parameter set byte value.
// This validates the wire-format identifier, not runtime readiness.
func validParamSet(ps ParamSet) bool {
	return ps <= maxParamSet
}

// runtimeReady returns true if ps has a fully wired hash function implementation.
// All 18 param sets (SHA2 + SHAKE + BLAKE3) are runtime-ready.
// Returns false only for invalid ParamSet values (> maxParamSet).
func runtimeReady(ps ParamSet) bool {
	return validParamSet(ps) && ps.internalParams().Funcs != nil
}

// String returns the FIPS 205 / PQC Suite B name for the parameter set.
// Returns "unknown" for invalid values.
func (ps ParamSet) String() string {
	switch ps {
	case SHA2_128f:
		return "SLH-DSA-SHA2-128f"
	case SHA2_128s:
		return "SLH-DSA-SHA2-128s"
	case SHAKE_128f:
		return "SLH-DSA-SHAKE-128f"
	case SHAKE_128s:
		return "SLH-DSA-SHAKE-128s"
	case SHA2_192f:
		return "SLH-DSA-SHA2-192f"
	case SHA2_192s:
		return "SLH-DSA-SHA2-192s"
	case SHAKE_192f:
		return "SLH-DSA-SHAKE-192f"
	case SHAKE_192s:
		return "SLH-DSA-SHAKE-192s"
	case SHA2_256f:
		return "SLH-DSA-SHA2-256f"
	case SHA2_256s:
		return "SLH-DSA-SHA2-256s"
	case SHAKE_256f:
		return "SLH-DSA-SHAKE-256f"
	case SHAKE_256s:
		return "SLH-DSA-SHAKE-256s"
	case BLAKE3_128f:
		return "SLH-DSA-BLAKE3-128f"
	case BLAKE3_128s:
		return "SLH-DSA-BLAKE3-128s"
	case BLAKE3_192f:
		return "SLH-DSA-BLAKE3-192f"
	case BLAKE3_192s:
		return "SLH-DSA-BLAKE3-192s"
	case BLAKE3_256f:
		return "SLH-DSA-BLAKE3-256f"
	case BLAKE3_256s:
		return "SLH-DSA-BLAKE3-256s"
	default:
		return "unknown"
	}
}

// internalParams returns the internal.ParamSet struct for this parameter set.
// Returns a zero-value ParamSet (N=0) for invalid values.
//
// All numeric values are copied directly from Trail of Bits go-slh-dsa params.go
// (commit 15ed0951). These are FIPS 205 constants that never change.
func (ps ParamSet) internalParams() internal.ParamSet {
	switch ps {
	// --- SHA2 ---
	case SHA2_128f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat1{}, N: 16, H: 66, D: 22, Hp: 3, A: 6, K: 33, Lgw: 4, M: 34}
	case SHA2_128s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat1{}, N: 16, H: 63, D: 7, Hp: 9, A: 12, K: 14, Lgw: 4, M: 30}
	case SHA2_192f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat3{}, N: 24, H: 66, D: 22, Hp: 3, A: 8, K: 33, Lgw: 4, M: 42}
	case SHA2_192s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat3{}, N: 24, H: 63, D: 7, Hp: 9, A: 14, K: 17, Lgw: 4, M: 39}
	case SHA2_256f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat5{}, N: 32, H: 68, D: 17, Hp: 4, A: 9, K: 35, Lgw: 4, M: 49}
	case SHA2_256s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetSha2Cat5{}, N: 32, H: 64, D: 8, Hp: 8, A: 14, K: 22, Lgw: 4, M: 47}
	// --- SHAKE ---
	case SHAKE_128f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 16, H: 66, D: 22, Hp: 3, A: 6, K: 33, Lgw: 4, M: 34}
	case SHAKE_128s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 16, H: 63, D: 7, Hp: 9, A: 12, K: 14, Lgw: 4, M: 30}
	case SHAKE_192f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 24, H: 66, D: 22, Hp: 3, A: 8, K: 33, Lgw: 4, M: 42}
	case SHAKE_192s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 24, H: 63, D: 7, Hp: 9, A: 14, K: 17, Lgw: 4, M: 39}
	case SHAKE_256f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 32, H: 68, D: 17, Hp: 4, A: 9, K: 35, Lgw: 4, M: 49}
	case SHAKE_256s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetShake{}, N: 32, H: 64, D: 8, Hp: 8, A: 14, K: 22, Lgw: 4, M: 47}
	// --- BLAKE3 (non-FIPS, PQC Suite B) ---
	// BLAKE3 param sets use identical numeric params to SHA2/SHAKE equivalents.
	// Only the Funcs field changes. BLAKE3 is uniform across all categories
	// (single ParamSetBLAKE3 struct, unlike SHA2's three category-specific structs).
	case BLAKE3_128f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 16, H: 66, D: 22, Hp: 3, A: 6, K: 33, Lgw: 4, M: 34}
	case BLAKE3_128s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 16, H: 63, D: 7, Hp: 9, A: 12, K: 14, Lgw: 4, M: 30}
	case BLAKE3_192f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 24, H: 66, D: 22, Hp: 3, A: 8, K: 33, Lgw: 4, M: 42}
	case BLAKE3_192s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 24, H: 63, D: 7, Hp: 9, A: 14, K: 17, Lgw: 4, M: 39}
	case BLAKE3_256f:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 32, H: 68, D: 17, Hp: 4, A: 9, K: 35, Lgw: 4, M: 49}
	case BLAKE3_256s:
		return internal.ParamSet{Funcs: hashfuncs.ParamSetBLAKE3{}, N: 32, H: 64, D: 8, Hp: 8, A: 14, K: 22, Lgw: 4, M: 47}
	default:
		return internal.ParamSet{}
	}
}

// N returns the security parameter (hash output length in bytes) for this param set.
// Returns 0 for invalid param set values.
func (ps ParamSet) N() uint8 {
	if !validParamSet(ps) {
		return 0
	}
	return ps.internalParams().N
}

// SecretKeySize returns the secret key size in bytes (4*N).
// Returns 0 for invalid param set values.
func (ps ParamSet) SecretKeySize() int {
	return int(ps.N()) * 4
}

// PublicKeySize returns the public key size in bytes (2*N).
// Returns 0 for invalid param set values.
func (ps ParamSet) PublicKeySize() int {
	return int(ps.N()) * 2
}

// SignatureSize returns the signature size in bytes.
// Formula: N + K*(1+A)*N + (H + D*WOTSLen)*N
// Returns 0 for invalid param set values.
func (ps ParamSet) SignatureSize() int {
	if !validParamSet(ps) {
		return 0
	}
	p := ps.internalParams()
	n := int(p.N)
	k := int(p.K)
	a := int(p.A)
	h := int(p.H)
	d := int(p.D)
	wl := int(p.GetWOTSLen())
	return n + k*(1+a)*n + (h+d*wl)*n
}

// IsBLAKE3 returns true if this param set uses the BLAKE3 hash family.
func (ps ParamSet) IsBLAKE3() bool {
	return ps >= BLAKE3_128f && ps <= BLAKE3_256s
}
