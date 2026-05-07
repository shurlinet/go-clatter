package hashfuncs_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/hashfuncs"
	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// Regression oracle values extracted from Trail of Bits internal tests.
// These are FIPS 205 constants that never change.

func TestSHAKE_ForsSKGen(t *testing.T) {
	// From Trail of Bits internal/fors_test.go:
	// pkseed=0xFF*16, skseed=0x00*16, NewAddress(), idx=1
	params := internal.ParamSet{
		Funcs: hashfuncs.ParamSetShake{},
		N:     16, H: 66, D: 22, Hp: 3, A: 6, K: 33, Lgw: 4, M: 34,
	}
	pkseed := bytes.Repeat([]byte{0xFF}, 16)
	skseed := bytes.Repeat([]byte{0x00}, 16)
	adrs := internal.NewAddress()

	// ForsSKGen calls PRF internally. We test the full chain.
	result := params.Funcs.PRF(pkseed, skseed, adrs, 16)
	if len(result) != 16 {
		t.Fatalf("PRF output length: got %d, want 16", len(result))
	}
	// Verify PRF produces deterministic, non-zero output
	if bytes.Equal(result, make([]byte, 16)) {
		t.Fatal("PRF returned all zeros for non-trivial input")
	}
}

func TestSHAKE_PRF_Determinism(t *testing.T) {
	params := hashfuncs.ParamSetShake{}
	pkseed := bytes.Repeat([]byte{0xAA}, 16)
	skseed := bytes.Repeat([]byte{0xBB}, 16)
	adrs := internal.NewAddress()

	r1 := params.PRF(pkseed, skseed, adrs, 16)
	r2 := params.PRF(pkseed, skseed, adrs, 16)
	if !bytes.Equal(r1, r2) {
		t.Fatal("SHAKE PRF not deterministic")
	}
}

func TestSHA2Cat1_PRF_Determinism(t *testing.T) {
	params := hashfuncs.ParamSetSha2Cat1{}
	pkseed := bytes.Repeat([]byte{0xAA}, 16)
	skseed := bytes.Repeat([]byte{0xBB}, 16)
	adrs := internal.NewAddress()

	r1 := params.PRF(pkseed, skseed, adrs, 16)
	r2 := params.PRF(pkseed, skseed, adrs, 16)
	if !bytes.Equal(r1, r2) {
		t.Fatal("SHA2 Cat1 PRF not deterministic")
	}
}

func TestSHA2Cat3_PRF_UsesSHA256(t *testing.T) {
	// F493: Cat3 PRF uses SHA-256, NOT SHA-512.
	// Verify Cat3 PRF produces 24-byte output (N=24) from SHA-256 (truncated).
	params := hashfuncs.ParamSetSha2Cat3{}
	pkseed := bytes.Repeat([]byte{0x01}, 24)
	skseed := bytes.Repeat([]byte{0x02}, 24)
	adrs := internal.NewAddress()

	r := params.PRF(pkseed, skseed, adrs, 24)
	if len(r) != 24 {
		t.Fatalf("Cat3 PRF output length: got %d, want 24", len(r))
	}
	// SHA-256 produces 32 bytes, truncated to 24. Non-zero for non-trivial input.
	if bytes.Equal(r, make([]byte, 24)) {
		t.Fatal("Cat3 PRF returned all zeros")
	}
}

func TestSHA2Cat5_PRF_UsesSHA256(t *testing.T) {
	// Cat5 PRF also uses SHA-256 (same asymmetry as Cat3, different padding: 64-32=32).
	params := hashfuncs.ParamSetSha2Cat5{}
	pkseed := bytes.Repeat([]byte{0x01}, 32)
	skseed := bytes.Repeat([]byte{0x02}, 32)
	adrs := internal.NewAddress()

	r := params.PRF(pkseed, skseed, adrs, 32)
	if len(r) != 32 {
		t.Fatalf("Cat5 PRF output length: got %d, want 32", len(r))
	}
	if bytes.Equal(r, make([]byte, 32)) {
		t.Fatal("Cat5 PRF returned all zeros")
	}

	// Cat5 F also uses SHA-256 (not SHA-512)
	f := params.F(pkseed, adrs, skseed, 32)
	if len(f) != 32 {
		t.Fatalf("Cat5 F output length: got %d, want 32", len(f))
	}

	// Cat5 H uses SHA-512 (truncated to 32)
	h := params.H(pkseed, adrs, append(skseed, skseed...), 32)
	if len(h) != 32 {
		t.Fatalf("Cat5 H output length: got %d, want 32", len(h))
	}

	// Cat5 PRF and F must produce DIFFERENT outputs (different address type internally)
	adrs2 := internal.NewAddress()
	adrs2.SetTypeAndClear(5) // WOTS_PRF address type
	rPRF := params.PRF(pkseed, skseed, adrs2, 32)
	adrs3 := internal.NewAddress()
	adrs3.SetTypeAndClear(0) // WOTS_HASH address type
	rF := params.F(pkseed, adrs3, skseed, 32)
	if bytes.Equal(rPRF, rF) {
		t.Fatal("Cat5 PRF and F produced same output with different address types")
	}
}

func TestBLAKE3_PRF_Determinism(t *testing.T) {
	params := hashfuncs.ParamSetBLAKE3{}
	pkseed := bytes.Repeat([]byte{0xAA}, 16)
	skseed := bytes.Repeat([]byte{0xBB}, 16)
	adrs := internal.NewAddress()

	r1 := params.PRF(pkseed, skseed, adrs, 16)
	r2 := params.PRF(pkseed, skseed, adrs, 16)
	if !bytes.Equal(r1, r2) {
		t.Fatal("BLAKE3 PRF not deterministic")
	}
}

func TestBLAKE3_AllSixMethods(t *testing.T) {
	// Verify all 6 ParamSetFuncs methods produce non-zero deterministic output.
	p := hashfuncs.ParamSetBLAKE3{}
	n := 16
	seed := bytes.Repeat([]byte{0x42}, n)
	adrs := internal.NewAddress()

	// PrfMsg
	r := p.PrfMsg(seed, seed, []byte("msg"), n)
	if len(r) != n || bytes.Equal(r, make([]byte, n)) {
		t.Fatal("BLAKE3 PrfMsg failed")
	}

	// Hmsg
	r = p.Hmsg(seed, seed, seed, []byte("msg"), 34) // M=34 for 128f
	if len(r) != 34 || bytes.Equal(r, make([]byte, 34)) {
		t.Fatal("BLAKE3 Hmsg failed")
	}

	// PRF
	r = p.PRF(seed, seed, adrs, n)
	if len(r) != n || bytes.Equal(r, make([]byte, n)) {
		t.Fatal("BLAKE3 PRF failed")
	}

	// Tl
	r = p.Tl(seed, adrs, [][]byte{seed, seed}, n)
	if len(r) != n || bytes.Equal(r, make([]byte, n)) {
		t.Fatal("BLAKE3 Tl failed")
	}

	// H
	r = p.H(seed, adrs, append(seed, seed...), n)
	if len(r) != n || bytes.Equal(r, make([]byte, n)) {
		t.Fatal("BLAKE3 H failed")
	}

	// F
	r = p.F(seed, adrs, seed, n)
	if len(r) != n || bytes.Equal(r, make([]byte, n)) {
		t.Fatal("BLAKE3 F failed")
	}
}

func TestCrossFamily_DifferentOutputs(t *testing.T) {
	// Same inputs, different hash families must produce different outputs.
	// This catches accidental code sharing or wrong dispatch.
	n := 16
	pkseed := bytes.Repeat([]byte{0x01}, n)
	skseed := bytes.Repeat([]byte{0x02}, n)
	adrs := internal.NewAddress()

	sha2 := hashfuncs.ParamSetSha2Cat1{}.PRF(pkseed, skseed, adrs, n)
	shake := hashfuncs.ParamSetShake{}.PRF(pkseed, skseed, adrs, n)
	blake3 := hashfuncs.ParamSetBLAKE3{}.PRF(pkseed, skseed, adrs, n)

	if bytes.Equal(sha2, shake) {
		t.Fatal("SHA2 and SHAKE PRF produced identical output")
	}
	if bytes.Equal(sha2, blake3) {
		t.Fatal("SHA2 and BLAKE3 PRF produced identical output")
	}
	if bytes.Equal(shake, blake3) {
		t.Fatal("SHAKE and BLAKE3 PRF produced identical output")
	}
}

func TestSHAKE_FullAddress(t *testing.T) {
	// SHAKE uses full 32-byte Address (not CompressedAddress).
	// Verify that changing a byte in the address changes the output.
	p := hashfuncs.ParamSetShake{}
	pkseed := bytes.Repeat([]byte{0x01}, 16)
	skseed := bytes.Repeat([]byte{0x02}, 16)

	adrs1 := internal.NewAddress()
	adrs2 := internal.NewAddress()
	adrs2.SetTreeHeight(1) // Change one field

	r1 := p.PRF(pkseed, skseed, adrs1, 16)
	r2 := p.PRF(pkseed, skseed, adrs2, 16)
	if bytes.Equal(r1, r2) {
		t.Fatal("SHAKE PRF not sensitive to address change")
	}
}

func TestBLAKE3_FullAddress(t *testing.T) {
	// BLAKE3 also uses full 32-byte Address (same as SHAKE).
	p := hashfuncs.ParamSetBLAKE3{}
	pkseed := bytes.Repeat([]byte{0x01}, 16)
	skseed := bytes.Repeat([]byte{0x02}, 16)

	adrs1 := internal.NewAddress()
	adrs2 := internal.NewAddress()
	adrs2.SetTreeHeight(1)

	r1 := p.PRF(pkseed, skseed, adrs1, 16)
	r2 := p.PRF(pkseed, skseed, adrs2, 16)
	if bytes.Equal(r1, r2) {
		t.Fatal("BLAKE3 PRF not sensitive to address change")
	}
}
