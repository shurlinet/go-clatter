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
	aliceNQ, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
	check("alice NewNqHandshake", err)
	bobNQ, err := clatter.NewNqHandshake(clatter.PatternNN, false, nqSuite)
	check("bob NewNqHandshake", err)

	// Inner layer: PQ NN
	alicePQ, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)
	check("alice NewPqHandshake", err)
	bobPQ, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, pqSuite)
	check("bob NewPqHandshake", err)

	// Compose into dual-layer handshake
	alice, err := clatter.NewDualLayerHandshake(aliceNQ, alicePQ, 4096)
	check("alice NewDualLayerHandshake", err)
	bob, err := clatter.NewDualLayerHandshake(bobNQ, bobPQ, 4096)
	check("bob NewDualLayerHandshake", err)

	// Handshake message buffers
	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// OUTER LAYER - NQ NN HANDSHAKE
	// e -->
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// <-- e, ee
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	fmt.Printf("Outer layer complete: %v\n", alice.OuterCompleted())

	// INNER LAYER - PQ NN HANDSHAKE (encrypted by outer transport)
	// e -->
	n, err = alice.WriteMessage(nil, buf)
	check("alice WriteMessage 3", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 3", err)

	// <-- ekem
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 4", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 4", err)

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
