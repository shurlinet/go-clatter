// Dual-layer Noise handshake: outer NQ (classical) handshake completes first,
// then inner PQ (post-quantum) handshake runs encrypted by the outer transport.
// Final transport keys derive from the inner handshake only.
//
// For cryptographic binding between layers, use HybridDualLayerHandshake instead.
//
// Run: go run ./examples/dual_layer/
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
	x := dh.NewX25519()
	nqSuite := clatter.CipherSuite{
		DH:     x,
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}
	pqSuite := clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	// Outer layer: NQ NN
	aliceNQ, _ := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	bobNQ, _ := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)

	// Inner layer: PQ NN
	alicePQ, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)
	bobPQ, _ := clatter.NewPqHandshake(clatter.PatternPqNN, false, pqSuite)

	// Compose into dual-layer handshake
	alice, _ := clatter.NewDualLayerHandshake(aliceNQ, alicePQ, 4096)
	bob, _ := clatter.NewDualLayerHandshake(bobNQ, bobPQ, 4096)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// OUTER LAYER - NQ NN HANDSHAKE
	// e -->
	n, _ := alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// <-- e, ee
	n, _ = bob.WriteMessage(nil, buf)
	_, _ = alice.ReadMessage(buf[:n], out)

	fmt.Printf("Outer layer complete: %v\n", alice.OuterCompleted())

	// INNER LAYER - PQ NN HANDSHAKE (encrypted by outer transport)
	// e -->
	n, _ = alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

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
