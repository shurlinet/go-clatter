// Originally from github.com/trailofbits/go-slh-dsa
// Commit: 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
// License: BSD-3-Clause
// Copyright (c) 2025 Trail of Bits. All rights reserved.
//
// Modifications by go-clatter authors:
// - Package path changed to crypto/sign/slhdsa/internal

package internal

import (
	"slices"
)

// Algorithm 14
func ForsSKGen(params ParamSet, skseed, pkseed []byte, adrs Address, idx uint32) []byte {
	skADRS := adrs.Clone()
	skADRS.SetTypeAndClear(FORS_PRF)
	skADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	skADRS.SetTreeIndex(idx)
	outlen := int(params.N)
	return params.Funcs.PRF(pkseed, skseed, skADRS, outlen)
}

// Algorithm 15
func ForsNode(params ParamSet, skseed []byte, i uint32, z uint32, pkseed []byte, adrs Address) []byte {
	outlen := int(params.N)
	if z == 0 {
		sk := ForsSKGen(params, skseed, pkseed, adrs, i)
		adrs.SetTreeHeight(uint32(0))
		adrs.SetTreeIndex(i)
		return params.Funcs.F(pkseed, adrs, sk, outlen)
	}
	lnode := ForsNode(params, skseed, (2 * i), z-1, pkseed, adrs)
	rnode := ForsNode(params, skseed, (2*i)+1, z-1, pkseed, adrs)
	adrs.SetTreeHeight(z)
	adrs.SetTreeIndex(i)
	return params.Funcs.H(pkseed, adrs, append(lnode, rnode...), outlen)
}

// Algorithm 16
func ForsSign(params ParamSet, md, skseed, pkseed []byte, adrs Address) []byte {
	sigFors := []byte{}
	a := uint32(params.A)
	k := uint32(params.K)
	indices := ToBase2b(md, a, k)
	for i := range k {
		tmp := ForsSKGen(params, skseed, pkseed, adrs, (i<<a)+indices[i])
		sigFors = append(sigFors, tmp...)
		for j := range a {
			s := (indices[i] >> j) ^ 1
			auth := ForsNode(params, skseed, (i<<(a-j))+s, j, pkseed, adrs.Clone())
			sigFors = append(sigFors, auth...)
		}
	}
	return sigFors[:]
}

// Algorithm 17
func ForsPKFromSig(params ParamSet, sig, md, pkseed []byte, adrs Address) []byte {
	a := uint32(params.A)
	k := uint32(params.K)
	n := uint32(params.N)
	outlen := int(params.N)
	indices := ToBase2b(md, a, k)
	root := make([][]byte, k)
	for i := range k {
		start := i * (a + 1) * n
		end := (i*(a+1) + 1) * n
		sk := sig[start:end]

		adrs.SetTreeHeight(0)
		adrs.SetTreeIndex(i<<a + indices[i])
		node := params.Funcs.F(pkseed, adrs, sk, outlen)

		start = (i*(a+1) + 1) * n
		end = (i + 1) * (a + 1) * n
		auth := sig[start:end]
		for j := range a {
			// extract auth[j] from auth above
			authstart := j * n
			authend := authstart + n
			authj := auth[authstart:authend]

			adrs.SetTreeHeight(j + 1)
			adrs.SetTreeIndex(adrs.GetTreeIndex() >> 1)
			bit := (indices[i] >> j) & 1
			// if even, node || authj; otherwise, authj || node
			// We implement this in constant-time
			mask := byte(-bit)
			tmp := make([]byte, outlen*2)
			for x := range outlen {
				d := authj[x] ^ node[x]
				tmp[x] = node[x] ^ (d & mask)
				tmp[x+outlen] = authj[x] ^ (d & mask)
			}
			node = params.Funcs.H(pkseed, adrs.Clone(), tmp, outlen)
		}
		root[i] = slices.Clone(node)
	}
	forspkADRS := adrs.Clone()
	forspkADRS.SetTypeAndClear(FORS_ROOTS)
	forspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return params.Funcs.Tl(pkseed, forspkADRS, root, outlen)
}
