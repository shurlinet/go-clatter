package hashfuncs

import (
	"io"

	"lukechampine.com/blake3"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// Compile-time interface satisfaction check.
var _ internal.ParamSetFuncs = ParamSetBLAKE3{}

// ParamSetBLAKE3 implements ParamSetFuncs using unkeyed BLAKE3 in XOF mode.
// BLAKE3 is uniform across all security categories (unlike SHA2 which splits
// into Cat1/Cat3/Cat5). All 6 methods use unkeyed BLAKE3 with full 32-byte
// addresses (same as SHAKE, not SHA2's CompressedAddress).
//
// No explicit domain separation tags are needed: structural separation is
// provided by the address type field (at a fixed position in the 32-byte
// address) and differing argument counts/layouts between functions.
//
// PQC Suite B (Aumasson, Wilcox-O'Hearn, Pruden) defines the BLAKE3
// instantiation of SLH-DSA. This implementation follows their Rust reference
// at github.com/PQC-Suite-B/signatures commit b392fe82.
type ParamSetBLAKE3 struct{}

// All methods use blake3.New(32, nil): the size parameter (32) only affects
// Sum() output length which we never call. We use XOF() for variable-length
// output. The nil key means unkeyed BLAKE3 (not keyed MAC mode).

// PrfMsg implements FIPS 205 PRF_msg: BLAKE3(skprf || opt_rand || M).
func (ParamSetBLAKE3) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(skprf)
	h.Write(opt_rand)
	h.Write(M)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}

// Hmsg implements FIPS 205 H_msg: BLAKE3(R || pkseed || pkroot || msg).
func (ParamSetBLAKE3) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(R)
	h.Write(pkseed)
	h.Write(pkroot)
	h.Write(msg)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}

// PRF implements FIPS 205 PRF: BLAKE3(pkseed || adrs || skseed).
func (ParamSetBLAKE3) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(skseed)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}

// Tl implements FIPS 205 T_l: BLAKE3(pkseed || adrs || Ml[0] || ... || Ml[L-1]).
func (ParamSetBLAKE3) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	for _, m := range Ml {
		h.Write(m)
	}
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}

// H implements FIPS 205 H: BLAKE3(pkseed || adrs || M2).
func (ParamSetBLAKE3) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M2)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}

// F implements FIPS 205 F: BLAKE3(pkseed || adrs || M1).
func (ParamSetBLAKE3) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	h := blake3.New(32, nil)
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M1)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h.XOF(), out); err != nil {
		panic("slhdsa: BLAKE3 XOF short read: " + err.Error())
	}
	return out
}
