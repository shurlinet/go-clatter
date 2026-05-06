// Originally from github.com/trailofbits/go-slh-dsa
// Commit: 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
// License: BSD-3-Clause
// Copyright (c) 2025 Trail of Bits. All rights reserved.
//
// Modifications by go-clatter authors:
// - Package path changed to crypto/sign/slhdsa/internal

package internal

type Index [3]uint32

func IndexFrom(x []byte, b uint32) Index {
	hi, mid, low := uint32(0), uint32(0), uint32(0)
	if b >= 8 {
		hi = ToInt(x[0:4])
	}
	if b >= 4 {
		mid = ToInt(x[4:8])
	}
	low = ToInt(x[8:12])
	return Index{hi, mid, low}
}
func (i Index) Clone() Index {
	return Index{i[0], i[1], i[2]}
}
func (i Index) Residue(h uint8) uint32 {
	m := uint32(1<<h) - 1
	return i[2] & m
}
func (i Index) RemoveBits(h uint8) Index {
	m := uint32(1<<h) - 1
	hi := i[0] >> h
	mid := (i[1] >> h) | ((i[0] & m) << (32 - h))
	lo := (i[2] >> h) | ((i[1] & m) << (32 - h))
	return Index{hi, mid, lo}
}
func (i Index) ModuloPow2(b uint8) Index {
	hi := i[0]
	if b < 64 {
		hi = 0
	} else {
		hi &= (1<<(b-64) - 1)
	}
	mid := i[1]
	if b < 32 {
		mid = 0
	} else if b < 64 {
		mid &= (1<<(b-32) - 1)
	}
	lo := i[2]
	if b < 32 {
		lo &= (1<<b - 1)
	}
	return Index{hi, mid, lo}
}

type Address struct {
	data [32]byte
}

func NewAddress() Address {
	var buf [32]byte
	for i := range buf {
		buf[i] = 0
	}
	return Address{
		data: buf,
	}
}
func (a Address) Bytes() []byte {
	buf := make([]byte, 32)
	copy(buf[:], a.data[:])
	return buf[:]
}
func (a Address) Clone() Address {
	var buf [32]byte
	copy(buf[:], a.data[:])
	return Address{
		data: buf,
	}
}
func (a *Address) SetLayerAddress(i uint32) {
	s := append(ToByte(i, uint8(4)), a.data[4:32]...)
	copy(a.data[:], s[:])
}
func (a *Address) SetTreeAddress(index Index) {
	h := ToByte(index[0], 4)
	m := ToByte(index[1], 4)
	l := ToByte(index[2], 4)
	s := append(a.data[0:4], h...)
	s = append(s, m...)
	s = append(s, l...)
	s = append(s, a.data[16:32]...)
	copy(a.data[:], s[:])
}
func (a *Address) SetTypeAndClear(Y uint32) {
	y := ToByte(Y, 4)
	s := append(a.data[0:16], y...)
	z := make([]byte, 12)
	for i := range z {
		z[i] = 0
	}
	s = append(s, z...)
	copy(a.data[:], s[:])
}
func (a *Address) SetKeyPairAddress(i uint32) {
	s0 := a.data[0:20]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	s = append(s, a.data[24:32]...)
	copy(a.data[:], s[:])
}
func (a *Address) SetChainAddress(i uint32) {
	s0 := a.data[0:24]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	s = append(s, a.data[28:32]...)
	copy(a.data[:], s[:])
}
func (a *Address) SetHashAddress(i uint32) {
	s0 := a.data[0:28]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	copy(a.data[:], s[:])
}
func (a *Address) SetTreeHeight(i uint32) {
	a.SetChainAddress(i)
}
func (a *Address) SetTreeIndex(i uint32) {
	a.SetHashAddress(i)
}
func (a Address) GetKeyPairAddress() uint32 {
	return ToInt(a.data[20:24])
}
func (a Address) GetTreeIndex() uint32 {
	return ToInt(a.data[28:32])
}

type CompressedAddress struct {
	data [22]byte
}
type CompressedIndex [2]uint32

func NewCompressedAddress() CompressedAddress {
	var buf [22]byte
	for i := range buf {
		buf[i] = 0
	}
	return CompressedAddress{
		data: buf,
	}
}
func (a CompressedAddress) Bytes() []byte {
	buf := make([]byte, 22)
	copy(buf[:], a.data[:])
	return buf[:]
}
func (a CompressedAddress) Clone() CompressedAddress {
	var buf [22]byte
	copy(buf[:], a.data[:])
	return CompressedAddress{
		data: buf,
	}
}
func (a *CompressedAddress) SetLayerAddress(i uint32) {
	s := append(ToByte(i, uint8(1)), a.data[1:22]...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetTreeAddress(index CompressedIndex) {
	h := ToByte(index[0], 4)
	l := ToByte(index[1], 4)
	s := append(a.data[0:1], h...)
	s = append(s, l...)
	s = append(s, a.data[9:22]...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetTypeAndClear(Y uint32) {
	y := ToByte(Y, 1)
	s := append(a.data[0:9], y...)
	z := make([]byte, 12)
	for i := range z {
		z[i] = 0
	}
	s = append(s, z...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetKeyPairAddress(i uint32) {
	s0 := a.data[0:10]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	s = append(s, a.data[14:22]...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetChainAddress(i uint32) {
	s0 := a.data[0:14]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	s = append(s, a.data[18:22]...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetHashAddress(i uint32) {
	s0 := a.data[0:18]
	s1 := ToByte(i, uint8(4))
	s := append(s0, s1...)
	copy(a.data[:], s[:])
}
func (a *CompressedAddress) SetTreeHeight(i uint32) {
	a.SetChainAddress(i)
}
func (a *CompressedAddress) SetTreeIndex(i uint32) {
	a.SetHashAddress(i)
}
func (a CompressedAddress) GetKeyPairAddress() uint32 {
	return ToInt(a.data[10:14])
}
func (a CompressedAddress) GetTreeIndex() uint32 {
	return ToInt(a.data[18:22])
}

func (a Address) Compress() CompressedAddress {
	s := []byte{}
	s = append(s, a.data[3])
	s = append(s, a.data[8:16]...)
	s = append(s, a.data[19:32]...)
	c := NewCompressedAddress()
	copy(c.data[:], s[:])
	return c
}

type ParamSetFuncs interface {
	PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte
	Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte
	PRF(pkseed, skseed []byte, adrs Address, outlen int) []byte
	Tl(pkseed []byte, adrs Address, Ml [][]byte, outlen int) []byte
	H(pkseed []byte, adrs Address, M2 []byte, outlen int) []byte
	F(pkseed []byte, adrs Address, M1 []byte, outlen int) []byte
}

type ParamSet struct {
	Funcs ParamSetFuncs
	N     uint8
	H     uint8
	D     uint8
	Hp    uint8
	A     uint8
	K     uint8
	Lgw   uint8
	M     uint8
}

// the formulas in section 5 give a shorthand for when lg_w = 4, which is the case for all param sets
func (p ParamSet) GetWOTSLen1() uint32 {
	return uint32(p.N) * 2
}
func (p ParamSet) GetWOTSLen2() uint32 {
	return uint32(3)
}
func (p ParamSet) GetWOTSLen() uint32 {
	return p.GetWOTSLen1() + p.GetWOTSLen2()
}
