// ML-DSA-65 (FIPS 204) post-quantum signing: generate, sign, verify, destroy.
//
// Demonstrates key generation, hedged signing, context-separated signatures,
// seed export/import for key persistence, and secure key destruction.
//
// Run: go run ./examples/mldsa65/
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/shurlinet/go-clatter/crypto/sign/mldsa65"
)

func main() {
	// Generate a fresh ML-DSA-65 key pair.
	sk, err := mldsa65.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateKey: %v\n", err)
		os.Exit(1)
	}
	defer sk.Destroy()

	fmt.Printf("Public key size: %d bytes\n", len(sk.PublicKey().Bytes()))

	// Sign a message (hedged mode - recommended for production).
	msg := []byte("Hello, post-quantum world!")
	sig, err := sk.Sign(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signature size: %d bytes\n", len(sig))
	fmt.Printf("Signature (first 32 bytes): %s...\n", hex.EncodeToString(sig[:32]))

	// Verify the signature.
	ok := sk.PublicKey().Verify(msg, sig)
	fmt.Printf("Verify: %v\n", ok)

	// Context separation: signatures for different purposes cannot cross-verify.
	sigAuth, _ := sk.SignWithContext(msg, "auth/v1")
	sigPayment, _ := sk.SignWithContext(msg, "payment/v1")

	fmt.Printf("auth sig verifies with auth ctx: %v\n",
		sk.PublicKey().VerifyWithContext(msg, sigAuth, "auth/v1"))
	fmt.Printf("auth sig verifies with payment ctx: %v\n",
		sk.PublicKey().VerifyWithContext(msg, sigAuth, "payment/v1"))
	_ = sigPayment

	// Seed round-trip: export seed, reconstruct key later.
	seed, _ := sk.Seed()
	fmt.Printf("Seed (hex): %s\n", hex.EncodeToString(seed))

	sk2, _ := mldsa65.NewPrivateKeyFromSeed(seed)
	defer sk2.Destroy()
	fmt.Printf("Reconstructed key equal: %v\n", sk.Equal(sk2))

	// Cross-verify: signature from original verifies with reconstructed key.
	fmt.Printf("Cross-verify: %v\n", sk2.PublicKey().Verify(msg, sig))
}
