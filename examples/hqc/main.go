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
	"os"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// check aborts on the first error. A failed handshake step (including a
// failed decrypt in ReadMessage, the MITM/tamper path) means the session
// is dead and must be abandoned - never proceed past it.
func check(step string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
		os.Exit(1)
	}
}

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

	alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	check("alice NewPqHandshake", err)
	bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
	check("bob NewPqHandshake", err)

	// Handshake message buffers. HQC-128 pqNN's second message is ~4.4 KB
	// (4433-byte KEM ciphertext + 16-byte payload tag), exceeding the
	// 4096-byte buffers used by ML-KEM examples.
	buf := make([]byte, 65535)
	out := make([]byte, 65535)

	// First handshake message from initiator to responder
	// e -->
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// Second handshake message from responder to initiator
	// <-- ekem
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	// Handshake should be done
	if !alice.IsFinished() || !bob.IsFinished() {
		fmt.Fprintln(os.Stderr, "handshake not finished")
		os.Exit(1)
	}

	// Finish handshakes and move to transport mode
	aliceT, err := alice.Finalize()
	check("alice Finalize", err)
	bobT, err := bob.Finalize()
	check("bob Finalize", err)
	defer aliceT.Destroy()
	defer bobT.Destroy()

	// Send a message from Alice to Bob
	msg := []byte("Hello from initiator (HQC-128)")
	n, err = aliceT.Send(msg, buf)
	check("alice Send", err)
	n, err = bobT.Receive(buf[:n], out)
	check("bob Receive", err)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
