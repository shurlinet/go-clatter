//go:build hqc

// Post-quantum (PQ) Noise handshake using HQC-128, ChaCha20-Poly1305, and SHA-256.
// HQC is NIST's backup KEM (code-based, different math from ML-KEM).
// Pattern pqNN: anonymous handshake with KEM-only key exchange. No static keys needed.
//
// HQC requires two deliberate opt-ins: the "hqc" build tag (compile-time) and
// AllowExperimental (runtime). Both gates will be relaxed as HQC progresses
// through FIPS standardization.
//
// Run: go run -tags hqc ./examples/hqc/
package main

import (
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func main() {
	// Enable experimental algorithms (required for pre-FIPS KEMs).
	clatter.AllowExperimental.Store(true)

	suite := clatter.CipherSuite{
		EKEM:         kem.NewHqc128(),
		SKEM:         kem.NewHqc128(),
		Cipher:       cipher.NewChaChaPoly(),
		Hash:         hash.NewSha256(),
		Experimental: true,
	}

	alice, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	bob, _ := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)

	// Handshake message buffers. HQC-128 pqNN's second message is ~4.4 KB
	// (4433-byte KEM ciphertext + 16-byte payload tag), exceeding the
	// 4096-byte buffers used by ML-KEM examples.
	buf := make([]byte, 65535)
	out := make([]byte, 65535)

	// First handshake message from initiator to responder
	// e -->
	n, _ := alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// Second handshake message from responder to initiator
	// <-- ekem
	n, _ = bob.WriteMessage(nil, buf)
	_, _ = alice.ReadMessage(buf[:n], out)

	// Handshake should be done
	if !alice.IsFinished() || !bob.IsFinished() {
		panic("handshake not finished")
	}

	// Finish handshakes and move to transport mode
	aliceT, _ := alice.Finalize()
	bobT, _ := bob.Finalize()
	defer aliceT.Destroy()
	defer bobT.Destroy()

	// Send a message from Alice to Bob
	msg := []byte("Hello from initiator (HQC-128)")
	n, _ = aliceT.Send(msg, buf)
	n, _ = bobT.Receive(buf[:n], out)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
