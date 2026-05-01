// Hybrid Noise handshake combining X25519 DH and ML-KEM-768 in a single symmetric state.
// Pattern hybridNN: anonymous handshake with both classical and post-quantum protection.
// Both DH and KEM key exchanges are mixed into the same session keys.
//
// Run: go run ./examples/hybrid/
package main

import (
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func main() {
	suite := clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	prologue := []byte("shared prologue bytes")

	alice, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, suite,
		clatter.WithPrologue(prologue),
	)
	bob, _ := clatter.NewHybridHandshake(clatter.PatternHybridNN, false, suite,
		clatter.WithPrologue(prologue),
	)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// First handshake message from initiator to responder
	// e -->
	n, _ := alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// Second handshake message from responder to initiator
	// <-- e, ee, ekem
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
	msg := []byte("Hello from initiator")
	n, _ = aliceT.Send(msg, buf)
	n, _ = bobT.Receive(buf[:n], out)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
