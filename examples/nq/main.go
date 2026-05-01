// Classical (NQ) Noise handshake using X25519, ChaCha20-Poly1305, and SHA-512.
// Pattern XX: both parties transmit their static keys during the handshake.
//
// Run: go run ./examples/nq/
package main

import (
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
)

func main() {
	x := dh.NewX25519()
	suite := clatter.CipherSuite{
		DH:     x,
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	// Generate static keys
	aliceS, _ := x.GenerateKeypair(clatter.NewDummyRng(1))
	bobS, _ := x.GenerateKeypair(clatter.NewDummyRng(2))

	alice, _ := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(aliceS),
	)
	bob, _ := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(bobS),
	)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// First handshake message from initiator to responder
	// e -->
	n, _ := alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// Second handshake message from responder to initiator
	// <-- e, ee, s, es
	n, _ = bob.WriteMessage(nil, buf)
	_, _ = alice.ReadMessage(buf[:n], out)

	// Third handshake message from initiator to responder
	// --> s, se
	n, _ = alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

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
	msg := []byte("Hello from initiator")
	n, _ = aliceT.Send(msg, buf)
	n, _ = bobT.Receive(buf[:n], out)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
