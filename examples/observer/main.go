// Observer callback example: attach an observer to a Noise handshake
// to receive real-time notifications about handshake progress.
//
// Run: go run ./examples/observer/
package main

import (
	"fmt"
	"os"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
)

// loggingObserver prints each handshake event to stdout.
type loggingObserver struct{}

func (l *loggingObserver) OnMessage(e clatter.HandshakeEvent) {
	fmt.Printf("[msg %d] %s type=%s protocol=%s payload=%d bytes",
		e.MessageIndex, e.Direction, e.HandshakeType, e.ProtocolName, e.PayloadLen)
	if e.RemoteEphemeralDH != nil {
		fmt.Printf(" +remote_ephemeral_dh")
	}
	if e.RemoteStaticDH != nil {
		fmt.Printf(" +remote_static_dh")
	}
	if e.IsComplete {
		fmt.Printf(" COMPLETE hash=%x", e.HandshakeHash[:8])
	}
	fmt.Println()
}

func (l *loggingObserver) OnError(e clatter.HandshakeErrorEvent) {
	fmt.Printf("[msg %d] %s ERROR: %v\n", e.MessageIndex, e.Direction, e.Err)
}

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
		Hash:   hash.NewSha256(),
	}

	aliceS, err := x.GenerateKeypair(clatter.NewDummyRng(1))
	check("alice GenerateKeypair", err)
	bobS, err := x.GenerateKeypair(clatter.NewDummyRng(2))
	check("bob GenerateKeypair", err)

	obs := &loggingObserver{}

	alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(aliceS),
		clatter.WithObserver(obs),
	)
	check("alice NewNqHandshake", err)
	bob, err := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(bobS),
	)
	check("bob NewNqHandshake", err)

	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// XX handshake: 3 messages
	// --> e
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// <-- e, ee, s, es
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	// --> s, se (with payload)
	n, err = alice.WriteMessage([]byte("hello bob"), buf)
	check("alice WriteMessage 3", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 3", err)

	// Finalize
	aliceTS, err := alice.Finalize()
	check("alice Finalize", err)
	bobTS, err := bob.Finalize()
	check("bob Finalize", err)

	// Transport messages
	n, err = aliceTS.Send([]byte("encrypted message"), buf)
	check("alice Send", err)
	ptLen, err := bobTS.Receive(buf[:n], out)
	check("bob Receive", err)
	fmt.Printf("\nDecrypted: %s\n", out[:ptLen])

	aliceTS.Destroy()
	bobTS.Destroy()
}
