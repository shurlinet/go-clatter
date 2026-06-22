// SEEC (Static-Ephemeral Entropy Combination) hedges a handshake's randomness
// with a long-lived 32-byte secret: the encapsulation and keygen coins stay
// unpredictable as long as EITHER the secret OR the fresh RNG draw is
// uncompromised. This is the built-in software instantiation, clatter.SEECPRF.
//
// SEEC is self-protective and opt-in: enable it for your OWN party (here the
// initiator). It is transparent to the wire - a SEEC-on handshake interoperates
// with a SEEC-off peer. Losing or omitting the secret loses only the hedge, not
// the ability to handshake.
//
// The 32-byte secret is the consumer's to provision and protect: generate it
// once from a trusted source, store it with the same care as a static identity
// key, and keep it DEDICATED to SEEC (do not reuse another key). A SEECPRF is
// safe for concurrent use and is meant to be shared across many handshakes
// (the paper's long-lived-secret model). For a hardware-backed secret (e.g. a
// YubiKey), see examples/seec_yubikey/.
//
// Run: go run ./examples/seec/
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

func check(step string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
		os.Exit(1)
	}
}

func main() {
	// Provision the long-lived SEEC secret. In production this is generated
	// once at install time and loaded from protected storage - NOT generated
	// fresh per process (that defeats the long-lived-secret model). Here we
	// generate one for the demo.
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	check("generate SEEC secret", err)

	prf, err := clatter.NewSEECPRF(hash.NewSha256(), secret)
	check("NewSEECPRF", err)
	for i := range secret { // NewSEECPRF copied it; zero our copy
		secret[i] = 0
	}
	defer prf.Destroy() // zeroes the PRF key when the instance is retired

	suite := clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	// The initiator hedges its coins with SEEC; the responder runs plain.
	alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(prf))
	check("alice NewPqHandshake", err)
	bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
	check("bob NewPqHandshake", err)

	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// e -->
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// <-- ekem
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	if !alice.IsFinished() || !bob.IsFinished() {
		fmt.Fprintln(os.Stderr, "handshake not finished")
		os.Exit(1)
	}
	fmt.Println("pqNN handshake complete with a software SEEC hedge on the initiator.")
}
