// Pre-shared key (PSK) Noise handshake. Both parties must hold the same 32-byte
// PSK before the handshake begins. Pattern XXpsk3 applies the PSK in the third
// message, after both static keys have been exchanged.
//
// Run: go run ./examples/psk/
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

	// Pre-shared key (must be exactly 32 bytes)
	psk := []byte("Trapped inside this Octavarium!!")

	// Generate static keys
	aliceS, err := x.GenerateKeypair(clatter.NewDummyRng(1))
	check("alice GenerateKeypair", err)
	bobS, err := x.GenerateKeypair(clatter.NewDummyRng(2))
	check("bob GenerateKeypair", err)

	alice, err := clatter.NewNqHandshake(clatter.PatternXXpsk3, true, suite,
		clatter.WithStaticKey(aliceS),
	)
	check("alice NewNqHandshake", err)
	bob, err := clatter.NewNqHandshake(clatter.PatternXXpsk3, false, suite,
		clatter.WithStaticKey(bobS),
	)
	check("bob NewNqHandshake", err)

	// Both parties push the PSK before the handshake begins
	check("alice PushPSK", alice.PushPSK(psk))
	check("bob PushPSK", bob.PushPSK(psk))

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
	// --> s, se, psk
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
