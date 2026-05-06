package hashfuncs

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

// Compile-time interface satisfaction check.
var _ internal.ParamSetFuncs = ParamSetShake{}

// ParamSetShake implements ParamSetFuncs using SHAKE256 XOF.
// SHAKE is uniform across all security categories (unlike SHA2 which splits
// into Cat1/Cat3/Cat5). All 6 methods use SHAKE256 with full 32-byte addresses.
//
// Originally from github.com/trailofbits/go-slh-dsa params.go.
// Modified: io.ReadFull replaces raw h.Read for defense-in-depth (F507/F578).
type ParamSetShake struct{}

func (x ParamSetShake) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(skprf)
	h.Write(opt_rand)
	h.Write(M)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}

func (x ParamSetShake) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(R)
	h.Write(pkseed)
	h.Write(pkroot)
	h.Write(msg)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}

func (x ParamSetShake) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(skseed)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}

func (x ParamSetShake) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}

func (x ParamSetShake) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M2)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}

func (x ParamSetShake) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M1)
	out := make([]byte, outlen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("slhdsa: SHAKE256 XOF short read: " + err.Error())
	}
	return out
}
