// SLH-DSA with BLAKE3 hash function: non-FIPS, high-performance variant.
//
// BLAKE3 parameter sets mirror FIPS 205 but use BLAKE3 instead of SHA2/SHAKE.
// Same security levels, potentially faster on x86 hardware with SIMD.
// Note: BLAKE3 variants do NOT support pre-hash mode (no FIPS 205 OID).
//
// Run: go run ./examples/slhdsa_blake3/
package main

import (
	"fmt"
	"os"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

func main() {
	// Generate a BLAKE3-128f key pair.
	priv, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateKey: %v\n", err)
		os.Exit(1)
	}
	defer priv.Destroy()

	pub := priv.PublicKey()
	fmt.Printf("Param set: %s\n", priv.ParamSet())
	fmt.Printf("Signature size: %d bytes (same as SHA2-128f)\n", slhdsa.BLAKE3_128f.SignatureSize())

	// Sign and verify.
	msg := []byte("BLAKE3-based post-quantum signatures")
	sig, err := priv.SignMessage(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Verified: %v\n", pub.Verify(msg, sig))

	// Pre-hash is NOT supported for BLAKE3 (no FIPS 205 OID).
	_, err = priv.SignPreHash(msg, slhdsa.HashSHA2_256)
	fmt.Printf("Pre-hash on BLAKE3 key: %v\n", err)

	// PublicKey survives Destroy.
	priv.Destroy()
	fmt.Printf("Verify after Destroy: %v\n", pub.Verify(msg, sig))
}
