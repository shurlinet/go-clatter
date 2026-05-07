// Package hashfuncs implements hash function parameter sets for SLH-DSA (FIPS 205).
//
// SHA2 hash functions are split into three category-specific structs because
// FIPS 205 Section 10.2 specifies different hash algorithms for different
// security categories:
//
//   - Category 1 (N=16): SHA-256 for all 6 functions
//   - Category 3 (N=24): SHA-256 for PRF/F, SHA-512 for PrfMsg/Hmsg/Tl/H
//   - Category 5 (N=32): SHA-256 for PRF/F, SHA-512 for PrfMsg/Hmsg/Tl/H
//
// The PRF/F split (SHA-256 for Cat3/Cat5 instead of SHA-512) is specified by
// FIPS 205 and is CRITICAL for correctness. Using SHA-512 for Cat3 PRF/F
// produces wrong output that fails all ACVP vectors.
package hashfuncs

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// Compile-time interface satisfaction checks.
var _ internal.ParamSetFuncs = ParamSetSha2Cat1{}
var _ internal.ParamSetFuncs = ParamSetSha2Cat3{}
var _ internal.ParamSetFuncs = ParamSetSha2Cat5{}

// genericSha256 is a shared helper for SHA-256-based PRF, H, and F operations.
// Used by all three categories for PRF and F, and by Cat1 for H.
func genericSha256(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	i_64_n := uint8(64) - n
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}

// genericSha512 is a shared helper for SHA-512-based Tl and H operations.
// Used by Cat3 and Cat5 for Tl and H.
func genericSha512(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	h := sha512.New()
	in := uint8(128) - n
	h.Write(pkseed)
	h.Write(internal.ToByte(0, in))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}

// ParamSetSha2Cat1 implements ParamSetFuncs using SHA-256 for Category 1 (N=16).
// All 6 methods use SHA-256 exclusively.
type ParamSetSha2Cat1 struct{}

// PrfMsg implements FIPS 205 PRF_msg: HMAC-SHA-256(skprf, opt_rand || M).
func (x ParamSetSha2Cat1) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha256.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

// Hmsg implements FIPS 205 H_msg using MGF1-SHA-256.
func (x ParamSetSha2Cat1) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha256.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha256.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

// PRF implements FIPS 205 PRF using SHA-256 with CompressedAddress.
func (x ParamSetSha2Cat1) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(uint8(16), cadrs, pkseed, skseed, outlen)
}

// Tl implements FIPS 205 T_l using SHA-256 with CompressedAddress.
func (x ParamSetSha2Cat1) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(48)
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

// H implements FIPS 205 H using SHA-256 with CompressedAddress.
func (x ParamSetSha2Cat1) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(16, cadrs, pkseed, M2, outlen)
}

// F implements FIPS 205 F using SHA-256 with CompressedAddress.
func (x ParamSetSha2Cat1) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(16, cadrs, pkseed, M1, outlen)
}

// ParamSetSha2Cat3 implements ParamSetFuncs for Category 3 (N=24).
// CRITICAL: PRF and F use SHA-256, while PrfMsg/Hmsg/Tl/H use SHA-512.
// This asymmetry is specified by FIPS 205 Section 10.2.
type ParamSetSha2Cat3 struct{}

// PrfMsg implements FIPS 205 PRF_msg: HMAC-SHA-512(skprf, opt_rand || M).
func (x ParamSetSha2Cat3) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha512.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

// Hmsg implements FIPS 205 H_msg using MGF1-SHA-512.
func (x ParamSetSha2Cat3) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha512.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha512.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

// PRF uses SHA-256 (NOT SHA-512) per FIPS 205 Section 10.2.
func (x ParamSetSha2Cat3) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(40) // 64 - 24
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

// Tl implements FIPS 205 T_l using SHA-512 with CompressedAddress.
func (x ParamSetSha2Cat3) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(104) // 128 - 24
	h := sha512.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

// H implements FIPS 205 H using SHA-512 with CompressedAddress.
func (x ParamSetSha2Cat3) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha512(24, cadrs, pkseed, M2, outlen)
}

// F uses SHA-256 (NOT SHA-512) per FIPS 205 Section 10.2.
func (x ParamSetSha2Cat3) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(24, cadrs, pkseed, M1, outlen)
}

// ParamSetSha2Cat5 implements ParamSetFuncs for Category 5 (N=32).
// CRITICAL: PRF and F use SHA-256, while PrfMsg/Hmsg/Tl/H use SHA-512.
// Same asymmetry as Category 3, specified by FIPS 205 Section 10.2.
type ParamSetSha2Cat5 struct{}

// PrfMsg implements FIPS 205 PRF_msg: HMAC-SHA-512(skprf, opt_rand || M).
func (x ParamSetSha2Cat5) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha512.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

// Hmsg implements FIPS 205 H_msg using MGF1-SHA-512.
func (x ParamSetSha2Cat5) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha512.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha512.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

// PRF uses SHA-256 (NOT SHA-512) per FIPS 205 Section 10.2.
func (x ParamSetSha2Cat5) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(32) // 64 - 32
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

// Tl implements FIPS 205 T_l using SHA-512 with CompressedAddress.
func (x ParamSetSha2Cat5) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(96) // 128 - 32
	h := sha512.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

// H implements FIPS 205 H using SHA-512 with CompressedAddress.
func (x ParamSetSha2Cat5) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha512(32, cadrs, pkseed, M2, outlen)
}

// F uses SHA-256 (NOT SHA-512) per FIPS 205 Section 10.2.
func (x ParamSetSha2Cat5) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(32, cadrs, pkseed, M1, outlen)
}
