// Originally from github.com/trailofbits/go-slh-dsa
// Commit: 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
// License: BSD-3-Clause
// Copyright (c) 2025 Trail of Bits. All rights reserved.
//
// Modifications by go-clatter authors:
// - Package path changed to crypto/sign/slhdsa/internal

package internal

import (
	"errors"
)

type XmssSignature struct {
	WotsSig [][]byte
	Auth    [][]byte
}

func (x XmssSignature) Bytes() []byte {
	sig := []byte{}
	for i := range x.WotsSig {
		sig = append(sig, x.WotsSig[i]...)
	}
	for i := range x.Auth {
		sig = append(sig, x.Auth[i]...)
	}
	return sig
}

func (x XmssSignature) Clone() XmssSignature {
	wotsSig := make([][]byte, len(x.WotsSig))
	for i := range x.WotsSig {
		wotsSig[i] = make([]byte, len(x.WotsSig[i]))
		copy(wotsSig[i][:], x.WotsSig[i][:])
	}
	auth := make([][]byte, len(x.Auth))
	for i := range x.Auth {
		auth[i] = make([]byte, len(x.Auth[i]))
		copy(auth[i][:], x.Auth[i][:])
	}
	return XmssSignature{
		WotsSig: wotsSig,
		Auth:    auth,
	}
}

func BytesToXmssSignature(params ParamSet, buf []byte) (XmssSignature, error) {
	n := uint32(params.N)
	wotsSigLen := params.GetWOTSLen()
	authPieceCount := uint32(params.Hp)
	calculated := int((wotsSigLen * n) + (authPieceCount * n))
	if len(buf) != calculated {
		return XmssSignature{}, errors.New("incorrect length for serialized XMSS signature")
	}

	// Start with the SIG_wots+
	start := uint32(0)
	wotsSig := make([][]byte, wotsSigLen)
	for i := range wotsSigLen {
		end := start + n
		chunk := buf[start:end]
		wotsSig[i] = make([]byte, n)
		copy(wotsSig[i][:], chunk)
		start += n
	}
	auth := make([][]byte, authPieceCount)
	for i := range authPieceCount {
		end := start + n
		chunk := buf[start:end]
		auth[i] = make([]byte, n)
		copy(auth[i][:], chunk[:])
		start += n
	}
	return XmssSignature{
		WotsSig: wotsSig,
		Auth:    auth,
	}, nil
}

func (x XmssSignature) GetWotsSig() [][]byte {
	tmp := make([][]byte, len(x.WotsSig))
	for i := range x.WotsSig {
		tmp[i] = make([]byte, len(x.WotsSig[i]))
		copy(tmp[i][:], x.WotsSig[i][:])
	}
	return tmp
}

func (x XmssSignature) GetAuthPath() [][]byte {
	tmp := make([][]byte, len(x.Auth))
	for i := range x.Auth {
		tmp[i] = make([]byte, len(x.Auth[i]))
		copy(tmp[i][:], x.Auth[i][:])
	}
	return tmp
}

// Algorithm 9
func XmssNode(params ParamSet, skseed []byte, i, z uint32, pkseed []byte, adrs Address) []byte {
	if z == 0 {
		adrs.SetTypeAndClear(WOTS_HASH)
		adrs.SetKeyPairAddress(i)
		return WotsPkGen(params, skseed, pkseed, adrs)
	}
	outlen := int(params.N)
	lnode := XmssNode(params, skseed, 2*i, z-1, pkseed, adrs)
	rnode := XmssNode(params, skseed, (2*i)+1, z-1, pkseed, adrs)
	adrs.SetTypeAndClear(TREE)
	adrs.SetTreeHeight(z)
	adrs.SetTreeIndex(i)
	return params.Funcs.H(pkseed, adrs, append(lnode, rnode...), outlen)
}

// Algorithm 10
func XmssSign(params ParamSet, M, skseed []byte, idx uint32, pkseed []byte, adrs Address) XmssSignature {
	Hp := uint32(params.Hp)
	Auth := make([][]byte, Hp)
	for j := range Hp {
		k := (idx >> j) ^ 1
		Auth[j] = XmssNode(params, skseed, k, j, pkseed, adrs)
	}
	adrs.SetTypeAndClear(WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := WotsSign(params, M, skseed, pkseed, adrs)
	return XmssSignature{
		WotsSig: sig,
		Auth:    Auth,
	}
}

// Algorithm 11
func XmssPkFromSig(params ParamSet, idx uint32, signature XmssSignature, M, pkseed []byte, adrs Address) []byte {
	Hp := uint32(params.Hp)

	adrs.SetTypeAndClear(WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := signature.GetWotsSig()
	auth := signature.GetAuthPath()
	node := WotsPkFromSig(params, sig, M, pkseed, adrs)
	outlen := int(params.N)

	adrs.SetTypeAndClear(TREE)
	adrs.SetTreeIndex(idx)
	for k := range Hp {
		adrs.SetTreeHeight(k + 1)
		e := idx >> k
		adrs.SetTreeIndex(adrs.GetTreeIndex() >> 1)
		/*
			if e&1 == 0 {
				node = params.Funcs.H(pkseed, adrs, append(node, auth[k]...), outlen)
			} else {
				node = params.Funcs.H(pkseed, adrs, append(auth[k], node...), outlen)
			}
		*/
		// Constant-time variant of the above branch:
		mask := byte(-(e & 1))
		authk := auth[k]
		tmp := make([]byte, outlen*2)
		for i := range outlen {
			d := authk[i] ^ node[i]
			tmp[i] = node[i] ^ (d & mask)
			tmp[i+outlen] = authk[i] ^ (d & mask)
		}
		node = params.Funcs.H(pkseed, adrs, tmp, outlen)
	}
	return node
}
