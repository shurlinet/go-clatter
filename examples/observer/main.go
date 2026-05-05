// Observer callback example: attach an observer to a Noise handshake
// to receive real-time notifications about handshake progress.
//
// Run: go run ./examples/observer/
package main

import (
	"fmt"

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

func main() {
	x := dh.NewX25519()
	suite := clatter.CipherSuite{
		DH:     x,
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}

	aliceS, _ := x.GenerateKeypair(clatter.NewDummyRng(1))
	bobS, _ := x.GenerateKeypair(clatter.NewDummyRng(2))

	obs := &loggingObserver{}

	alice, _ := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
		clatter.WithStaticKey(aliceS),
		clatter.WithObserver(obs),
	)
	bob, _ := clatter.NewNqHandshake(clatter.PatternXX, false, suite,
		clatter.WithStaticKey(bobS),
	)

	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// XX handshake: 3 messages
	// --> e
	n, _ := alice.WriteMessage(nil, buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// <-- e, ee, s, es
	n, _ = bob.WriteMessage(nil, buf)
	_, _ = alice.ReadMessage(buf[:n], out)

	// --> s, se (with payload)
	n, _ = alice.WriteMessage([]byte("hello bob"), buf)
	_, _ = bob.ReadMessage(buf[:n], out)

	// Finalize
	aliceTS, _ := alice.Finalize()
	bobTS, _ := bob.Finalize()

	// Transport messages
	n, _ = aliceTS.Send([]byte("encrypted message"), buf)
	ptLen, _ := bobTS.Receive(buf[:n], out)
	fmt.Printf("\nDecrypted: %s\n", out[:ptLen])

	aliceTS.Destroy()
	bobTS.Destroy()
}
