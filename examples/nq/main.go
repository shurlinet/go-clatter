// Classical (NQ) Noise handshake using X25519, ChaCha20-Poly1305, and SHA-512.
// Pattern XX: both parties transmit their static keys during the handshake.
//
// Run: go run ./examples/nq/
package main

import (
	"fmt"
	"os"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
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
	x := dh.NewX25519()
	suite := clatter.CipherSuite{
		DH:     x,
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	// Generate static keys
	aliceS, err := x.GenerateKeypair(clatter.NewDummyRng(1))
	check("alice GenerateKeypair", err)
	bobS, err := x.GenerateKeypair(clatter.NewDummyRng(2))
	check("bob GenerateKeypair", err)

	alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(aliceS),
	)
	check("alice NewNqHandshake", err)
	bob, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(bobS),
	)
	check("bob NewNqHandshake", err)

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
	// <-- e, ee, s, es
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	// Third handshake message from initiator to responder
	// --> s, se
	n, err = alice.WriteMessage(nil, buf)
	check("alice WriteMessage 3", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 3", err)

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
