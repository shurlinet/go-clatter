package slhdsa_test

import (
	"fmt"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

func Example() {
	// Generate a new SLH-DSA-SHA2-128f key pair (fastest parameter set).
	sk, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		panic(err)
	}
	defer sk.Destroy()

	// Sign a message (hedged randomness, recommended for production).
	msg := []byte("hello, post-quantum world")
	sig, err := sk.SignMessage(msg)
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: %d bytes\n", len(sig))

	// Verify with the public key.
	ok := sk.PublicKey().Verify(msg, sig)
	fmt.Println("verified:", ok)
	// Output:
	// signature: 17088 bytes
	// verified: true
}

func Example_withContext() {
	sk, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		panic(err)
	}
	defer sk.Destroy()

	msg := []byte("transfer authorization")
	sig, err := sk.SignWithContext(msg, "finance/v1")
	if err != nil {
		panic(err)
	}

	// Must verify with the same context.
	ok := sk.PublicKey().VerifyWithContext(msg, sig, "finance/v1")
	fmt.Println("correct context:", ok)

	// Wrong context rejects.
	ok = sk.PublicKey().VerifyWithContext(msg, sig, "other/v1")
	fmt.Println("wrong context:", ok)
	// Output:
	// correct context: true
	// wrong context: false
}

func Example_keyRoundTrip() {
	// Generate and export the secret key bytes for storage.
	sk, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		panic(err)
	}
	skBytes, _ := sk.Bytes()

	// Reconstruct from bytes - produces identical key.
	sk2, err := slhdsa.NewPrivateKeyFromBytes(slhdsa.SHA2_128f, skBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("keys equal:", sk.Equal(sk2))

	// Sign with original, verify with reconstructed.
	msg := []byte("persistence test")
	sig, _ := sk.SignMessage(msg)
	fmt.Println("cross-verify:", sk2.PublicKey().Verify(msg, sig))

	sk.Destroy()
	sk2.Destroy()
	// Output:
	// keys equal: true
	// cross-verify: true
}
