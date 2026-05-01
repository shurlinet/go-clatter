// Pre-shared key (PSK) Noise handshake. Both parties must hold the same 32-byte
// PSK before the handshake begins. Pattern XXpsk3 applies the PSK in the third
// message, after both static keys have been exchanged.
//
// Run: go run ./examples/psk/
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

	// Pre-shared key (must be exactly 32 bytes)
	psk := []byte("Trapped inside this Octavarium!!")

	// Generate static keys
	aliceS, _ := x.GenerateKeypair(clatter.NewDummyRng(1))
	bobS, _ := x.GenerateKeypair(clatter.NewDummyRng(2))

	alice, _ := clatter.NewNqHandshake(clatter.PatternXXpsk3, true, suite,
		clatter.WithStaticKey(aliceS),
	)
	bob, _ := clatter.NewNqHandshake(clatter.PatternXXpsk3, false, suite,
		clatter.WithStaticKey(bobS),
	)

	// Both parties push the PSK before the handshake begins
	_ = alice.PushPSK(psk)
	_ = bob.PushPSK(psk)

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
	// --> s, se, psk
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
