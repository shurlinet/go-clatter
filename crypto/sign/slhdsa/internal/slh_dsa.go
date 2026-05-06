// Originally from github.com/trailofbits/go-slh-dsa
// Commit: 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
// License: BSD-3-Clause
// Copyright (c) 2025 Trail of Bits. All rights reserved.
//
// Modifications by go-clatter authors:
// - Package path changed to crypto/sign/slhdsa/internal
// - Added Zero() method on SLHSecretKey for key lifecycle management

package internal

import (
	"errors"
	"slices"
)

type SLHSecretKey struct {
	skseed []byte
	skprf  []byte
	pkseed []byte
	pkroot []byte
}

type SLHPublicKey struct {
	pkseed []byte
	pkroot []byte
}

type SLHSignature struct {
	R    []byte
	FORS []byte
	HT   []byte
}

func (k SLHSecretKey) Bytes() []byte {
	out := []byte{}
	out = append(out, slices.Clone(k.skseed)...)
	out = append(out, slices.Clone(k.skprf)...)
	out = append(out, slices.Clone(k.pkseed)...)
	out = append(out, slices.Clone(k.pkroot)...)
	return out
}

// Zero zeros all secret material in the key and nils the backing arrays.
// After Zero(), Bytes() returns an empty slice.
// Safe to call on nil receiver or already-zeroed key (idempotent).
func (k *SLHSecretKey) Zero() {
	if k == nil {
		return
	}
	for i := range k.skseed {
		k.skseed[i] = 0
	}
	for i := range k.skprf {
		k.skprf[i] = 0
	}
	for i := range k.pkseed {
		k.pkseed[i] = 0
	}
	for i := range k.pkroot {
		k.pkroot[i] = 0
	}
	k.skseed = nil
	k.skprf = nil
	k.pkseed = nil
	k.pkroot = nil
}

func (k SLHSecretKey) PublicKey() SLHPublicKey {
	return SLHPublicKey{
		pkseed: slices.Clone(k.pkseed),
		pkroot: slices.Clone(k.pkroot),
	}
}
func (k SLHPublicKey) Bytes() []byte {
	out := []byte{}
	out = append(out, slices.Clone(k.pkseed)...)
	out = append(out, slices.Clone(k.pkroot)...)
	return out
}

func (s SLHSignature) Bytes() []byte {
	out := []byte{}
	out = append(out, slices.Clone(s.R)...)
	out = append(out, slices.Clone(s.FORS)...)
	out = append(out, slices.Clone(s.HT)...)
	return out
}

func LoadSecretKey(params ParamSet, b []byte) (SLHSecretKey, error) {
	n := int(params.N)
	if len(b) != (n * 4) {
		return SLHSecretKey{}, errors.New("invalid secret key length")
	}
	buf := slices.Clone(b)
	skseed, buf := buf[0:n], buf[n:]
	skprf, buf := buf[0:n], buf[n:]
	pkseed, buf := buf[0:n], buf[n:]
	pkroot := buf[0:n]
	return SLHSecretKey{
		skseed: skseed,
		skprf:  skprf,
		pkseed: pkseed,
		pkroot: pkroot,
	}, nil
}

func LoadPublicKey(params ParamSet, b []byte) (SLHPublicKey, error) {
	n := int(params.N)
	if len(b) != (n * 2) {
		return SLHPublicKey{}, errors.New("invalid public key length")
	}
	buf := slices.Clone(b)
	pkseed, pkroot := buf[0:n], buf[n:]
	return SLHPublicKey{
		pkseed: pkseed,
		pkroot: pkroot,
	}, nil
}

func LoadSignature(params ParamSet, b []byte) (SLHSignature, error) {
	n := int(params.N)
	k := int(params.K)
	a := int(params.A)
	d := int(params.D)
	h := int(params.H)
	l := int(params.GetWOTSLen())
	forsLen := k * (1 + a) * n
	htLen := (h + d*l) * n
	total := n + forsLen + htLen
	if len(b) != total {
		return SLHSignature{}, errors.New("invalid signature length")
	}
	// Break into constituent parts
	buf := slices.Clone(b)
	R, buf := buf[0:n], buf[n:]
	fors, HT := buf[0:forsLen], buf[forsLen:]
	return SLHSignature{R: R, FORS: fors, HT: HT}, nil
}

// Algorithm 18
func SLHKeygenInternal(params ParamSet, skseed, skprf, pkseed []byte) (SLHSecretKey, SLHPublicKey) {
	d := uint32(params.D)
	hp := uint32(params.Hp)
	adrs := NewAddress()
	adrs.SetLayerAddress(d - 1)
	pkroot := XmssNode(params, skseed, 0, hp, pkseed, adrs)
	return SLHSecretKey{
			skseed: skseed,
			skprf:  skprf,
			pkseed: pkseed,
			pkroot: pkroot,
		}, SLHPublicKey{
			pkseed: pkseed,
			pkroot: pkroot,
		}
}

func SLHSignInternalDeterministic(params ParamSet, M []byte, sk SLHSecretKey) SLHSignature {
	addrnd := slices.Clone(sk.pkseed)
	return SLHSignInternal(params, M, sk, addrnd)
}

func SLHSignInternal(params ParamSet, M []byte, sk SLHSecretKey, addrnd []byte) SLHSignature {
	outlen := int(params.N)
	m8 := int(params.M)

	k := uint32(params.K)
	a := uint32(params.A)
	// d := uint32(params.D)
	h := uint32(params.H)
	hp := uint32(params.Hp)
	adrs := NewAddress()
	opt_rand := append([]byte{}, addrnd...)
	R := params.Funcs.PrfMsg(sk.skprf, opt_rand, M, outlen)
	digest := params.Funcs.Hmsg(R, sk.pkseed, sk.pkroot, M, m8)

	// Intermediate values derived from the parameter sets
	// ceil(k * a / 8)
	ka8 := ((k * a) + 7) >> 3
	// ceil((h - (h/d))/8)
	hhd := ((h - hp) + 7) >> 3
	// ceil(h / 8d)
	h_8d := ((hp) + 7) >> 3

	tmpIdxTree := make([]byte, 12)
	tmpIdxLeaf := make([]byte, 4)
	md := digest[0:ka8]
	start := ka8
	innerStart := 12 - hhd
	stop := ka8 + hhd
	copy(tmpIdxTree[innerStart:], digest[start:stop])
	// tmpIdxTree := digest[start:stop]
	start += hhd
	stop = start + h_8d
	innerStart = 4 - h_8d
	copy(tmpIdxLeaf[innerStart:], digest[start:stop])
	idxTree := IndexFrom(tmpIdxTree, hhd).ModuloPow2(params.H - params.Hp)
	idxLeaf := ToInt(tmpIdxLeaf) & ((1 << hp) - 1)
	adrs.SetTreeAddress(idxTree)
	adrs.SetTypeAndClear(FORS_TREE)
	adrs.SetKeyPairAddress(idxLeaf)
	sigFors := ForsSign(params, md, sk.skseed, sk.pkseed, adrs)
	// sig = append(sig, sigFors...)

	pkFors := ForsPKFromSig(params, sigFors, md, sk.pkseed, adrs)
	sigHt := HTSign(params, pkFors, sk.skseed, sk.pkseed, idxTree.Clone(), idxLeaf)
	// sig = append(sig, sigHt.Bytes()...)
	return SLHSignature{
		R:    R,
		FORS: sigFors,
		HT:   sigHt.Bytes(),
	}
}

func SLHVerifyInternal(params ParamSet, M []byte, sig SLHSignature, pk SLHPublicKey) bool {
	m8 := int(params.M)
	k := uint32(params.K)
	a := uint32(params.A)
	// d := uint32(params.D)
	h := uint32(params.H)
	hp := uint32(params.Hp)
	// Length check moved to serialization
	adrs := NewAddress()
	digest := params.Funcs.Hmsg(sig.R[:], pk.pkseed, pk.pkroot, slices.Clone(M), m8)

	// Intermediate values derived from the parameter sets
	// ceil(k * a / 8)
	ka8 := ((k * a) + 7) >> 3
	// ceil((h - (h/d))/8)
	hhd := ((h - hp) + 7) >> 3
	// ceil(h / 8d)
	h_8d := ((hp) + 7) >> 3

	tmpIdxTree := make([]byte, 12)
	tmpIdxLeaf := make([]byte, 4)
	md := digest[0:ka8]
	start := ka8
	innerStart := 12 - hhd
	stop := ka8 + hhd
	copy(tmpIdxTree[innerStart:], digest[start:stop])
	// tmpIdxTree := digest[start:stop]
	start += hhd
	stop = start + h_8d
	innerStart = 4 - h_8d
	copy(tmpIdxLeaf[innerStart:], digest[start:stop])
	idxTree := IndexFrom(tmpIdxTree, hhd).ModuloPow2(params.H - params.Hp)
	idxLeaf := ToInt(tmpIdxLeaf) & ((1 << hp) - 1)
	adrs.SetTreeAddress(idxTree)
	adrs.SetTypeAndClear(FORS_TREE)
	adrs.SetKeyPairAddress(idxLeaf)
	pkFors := ForsPKFromSig(params, sig.FORS, md, pk.pkseed, adrs.Clone())
	htsig, err := BytesToHTSignature(params, sig.HT)
	if err != nil {
		return false
	}
	// fmt.Printf("sig.HT = %x\n", sig.HT)
	// fmt.Printf("htsig = %x\n", htsig.Bytes())
	return HTVerify(params, htsig, pkFors, pk.pkseed, idxTree, idxLeaf, pk.pkroot)
}
