package clatter_test

import clatter "github.com/shurlinet/go-clatter"

// Helpers that pass static-key options only to the (pattern, role) pairs that
// consume them, mirroring the applicability the constructors now enforce. Tests
// that previously over-provisioned keys ("unused keys are silently ignored")
// route their static options through these so a no-op option is never passed -
// the resulting handshakes are byte-identical (the dropped options had no
// effect). needsStaticKey / hasPreToken live in handshake_nq_test.go.

// remoteStaticApplicable reports whether WithRemoteStatic / WithRemoteStaticKEMKey
// has any effect for the given role: only when the peer PRE-SHARES its static
// (its pre-message contains Token::S). An in-band-transmitted remote static is
// learned via readTokenS and overwrites any preset before use, so passing it is a
// no-op the constructors reject.
func remoteStaticApplicable(p *clatter.HandshakePattern, initiator bool) bool {
	if initiator {
		return hasPreToken(p.PreResponder(), clatter.TokenS)
	}
	return hasPreToken(p.PreInitiator(), clatter.TokenS)
}

// singleStaticOpts returns the static options applicable to (p, role) for any
// single-static-pair handshake - NQ (DH static) or PQ (KEM static), both set via
// WithStaticKey / WithRemoteStatic. Hybrid uses hybridStaticOpts.
func singleStaticOpts(p *clatter.HandshakePattern, initiator bool, localKP clatter.KeyPair, remotePub []byte) []clatter.Option {
	var o []clatter.Option
	if needsStaticKey(p, initiator) {
		o = append(o, clatter.WithStaticKey(localKP))
	}
	if remoteStaticApplicable(p, initiator) {
		o = append(o, clatter.WithRemoteStatic(remotePub))
	}
	return o
}

// hybridStaticOpts returns the static options applicable to (p, role) for a Hybrid
// handshake (Token::S carries both the DH and KEM static, so one applicability
// bit governs both).
func hybridStaticOpts(p *clatter.HandshakePattern, initiator bool, dhKP clatter.KeyPair, dhRemotePub []byte, kemKP clatter.KeyPair, kemRemotePub []byte) []clatter.Option {
	var o []clatter.Option
	if needsStaticKey(p, initiator) {
		o = append(o, clatter.WithStaticKey(dhKP), clatter.WithStaticKEMKey(kemKP))
	}
	if remoteStaticApplicable(p, initiator) {
		o = append(o, clatter.WithRemoteStatic(dhRemotePub), clatter.WithRemoteStaticKEMKey(kemRemotePub))
	}
	return o
}
