// SLH-DSA (FIPS 205) post-quantum signing with SHA2-128f: generate, sign, verify, destroy.
//
// SLH-DSA is a hash-based signature scheme, NIST's backup to lattice-based ML-DSA.
// It provides post-quantum security based solely on hash function security.
//
// Run: go run ./examples/slhdsa/
package main

import (
	"fmt"
	"os"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

func main() {
	// Generate a new SLH-DSA-SHA2-128f key pair (fastest FIPS 205 param set).
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateKey: %v\n", err)
		os.Exit(1)
	}
	defer priv.Destroy()

	pub := priv.PublicKey()
	fmt.Printf("Param set: %s\n", priv.ParamSet())
	fmt.Printf("Public key: %d bytes\n", len(pub.Bytes()))
	fmt.Printf("Secret key: %d bytes\n", slhdsa.SHA2_128f.SecretKeySize())

	// Sign a message (hedged randomness - recommended for production).
	msg := []byte("Post-quantum signatures with SLH-DSA")
	sig, err := priv.SignMessage(msg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signature: %d bytes\n", len(sig))

	// Verify.
	ok := pub.Verify(msg, sig)
	fmt.Printf("Verify: %v\n", ok)

	// Context separation: domain-separate signatures for different purposes.
	sigAuth, _ := priv.SignWithContext(msg, "auth/v1")
	fmt.Printf("Verify with correct context: %v\n",
		pub.VerifyWithContext(msg, sigAuth, "auth/v1"))
	fmt.Printf("Verify with wrong context: %v\n",
		pub.VerifyWithContext(msg, sigAuth, "wrong/ctx"))

	// Key serialization round-trip.
	skBytes, _ := priv.Bytes()
	priv2, _ := slhdsa.NewPrivateKeyFromBytes(slhdsa.SHA2_128f, skBytes)
	defer priv2.Destroy()
	fmt.Printf("Keys equal: %v\n", priv.Equal(priv2))

	// PublicKey survives Destroy.
	priv.Destroy()
	fmt.Printf("Verify after Destroy: %v\n", pub.Verify(msg, sig))
}
