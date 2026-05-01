// Post-quantum (PQ) Noise handshake using ML-KEM-768, ChaCha20-Poly1305, and SHA-512.
// Pattern pqNN: anonymous handshake with KEM-only key exchange. No static keys needed.
//
// Run: go run ./examples/pq/
package main

import (
	"fmt"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func main() {
	suite := clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	alice, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite)
	bob, _ := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

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
	msg := []byte("Hello from initiator")
	n, _ = aliceT.Send(msg, buf)
	n, _ = bobT.Receive(buf[:n], out)

	fmt.Printf("Bob received from Alice: %s\n", out[:n])
}
