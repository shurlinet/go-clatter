// Hybrid Noise handshake combining X25519 DH and ML-KEM-768 in a single symmetric state.
// Pattern hybridNN: anonymous handshake with both classical and post-quantum protection.
// Both DH and KEM key exchanges are mixed into the same session keys.
//
// Run: go run ./examples/hybrid/
package main

import (
	"fmt"
	"os"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
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
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	prologue := []byte("shared prologue bytes")

	alice, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite,
		clatter.WithPrologue(prologue),
	)
	check("alice NewHybridHandshake", err)
	bob, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite,
		clatter.WithPrologue(prologue),
	)
	check("bob NewHybridHandshake", err)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// First handshake message from initiator to responder
	// e -->
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// Second handshake message from responder to initiator
	// <-- e, ee, ekem
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
	msg := []byte("Hello from initiator")
	n, err = aliceT.Send(msg, buf)
	check("alice Send", err)
	n, err = bobT.Receive(buf[:n], out)
	check("bob Receive", err)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
