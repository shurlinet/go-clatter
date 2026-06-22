package clatter

import "fmt"

// SetLocalStaticPublicForTest overwrites a constructed handshake's local static
// public key with pub, simulating a NON-COMPLIANT / malicious peer that transmits
// a structurally malformed static on the wire. A compliant caller can no longer
// hold such a keypair (the construction-time public/secret consistency check
// rejects it), so the wire-learned-remote-static validation path (readTokenS) is
// exercised by corrupting the local static AFTER construction and letting the
// handshake transmit it. PQ stores its KEM static in the embedded
// HandshakeInternals.s; Hybrid stores its KEM static in kemS (its DH static is
// left intact). Test-only: this file compiles only under `go test`.
func SetLocalStaticPublicForTest(h Handshaker, pub []byte) {
	switch hs := h.(type) {
	case *PqHandshake:
		hs.s.Public = pub
	case *HybridHandshake:
		hs.kemS.Public = pub
	default:
		// A test-only corruption seam must never silently no-op: a future
		// caller wiring it to an unsupported type would otherwise get a
		// vacuously-passing test instead of the corruption it asked for.
		panic(fmt.Sprintf("SetLocalStaticPublicForTest: unsupported handshake type %T", h))
	}
}
