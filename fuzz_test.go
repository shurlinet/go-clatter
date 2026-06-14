package clatter_test

import (
	"bytes"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// fuzzPSK matches Rust's PSK: "Trapped inside this Octavarium!!"
var fuzzPSK = []byte("Trapped inside this Octavarium!!")

// setupNqPair creates an NQ handshake pair for fuzzing.
func setupNqPair(pattern *clatter.HandshakePattern, suite clatter.CipherSuite) (*clatter.NqHandshake, *clatter.NqHandshake) {
	aliceS, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(1))
	bobS, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(2))

	alice, _ := clatter.NewNqHandshake(pattern, true, suite,
		clatter.WithStaticKey(aliceS),
		clatter.WithRemoteStatic(bobS.Public),
	)
	bob, _ := clatter.NewNqHandshake(pattern, false, suite,
		clatter.WithStaticKey(bobS),
		clatter.WithRemoteStatic(aliceS.Public),
	)
	_ = alice.PushPSK(fuzzPSK)
	_ = bob.PushPSK(fuzzPSK)
	return alice, bob
}

// setupPqPair creates a PQ handshake pair for fuzzing.
func setupPqPair(pattern *clatter.HandshakePattern, suite clatter.CipherSuite) (*clatter.PqHandshake, *clatter.PqHandshake) {
	aliceS, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(10))
	bobS, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(20))

	alice, _ := clatter.NewPqHandshake(pattern, true, suite,
		clatter.WithStaticKey(aliceS),
		clatter.WithRemoteStatic(bobS.Public),
	)
	bob, _ := clatter.NewPqHandshake(pattern, false, suite,
		clatter.WithStaticKey(bobS),
		clatter.WithRemoteStatic(aliceS.Public),
	)
	_ = alice.PushPSK(fuzzPSK)
	_ = bob.PushPSK(fuzzPSK)
	return alice, bob
}

// setupHybridPair creates a Hybrid handshake pair for fuzzing.
func setupHybridPair(pattern *clatter.HandshakePattern, suite clatter.CipherSuite) (*clatter.HybridHandshake, *clatter.HybridHandshake) {
	aliceDH, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(30))
	bobDH, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(40))
	aliceKEM, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(50))
	bobKEM, _ := suite.SKEM.GenerateKeypair(clatter.NewDummyRng(60))

	alice, _ := clatter.NewHybridHandshake(pattern, true, suite,
		clatter.WithStaticKey(aliceDH),
		clatter.WithRemoteStatic(bobDH.Public),
		clatter.WithStaticKEMKey(aliceKEM),
		clatter.WithRemoteStaticKEMKey(bobKEM.Public),
	)
	bob, _ := clatter.NewHybridHandshake(pattern, false, suite,
		clatter.WithStaticKey(bobDH),
		clatter.WithRemoteStatic(aliceDH.Public),
		clatter.WithStaticKEMKey(bobKEM),
		clatter.WithRemoteStaticKEMKey(aliceKEM.Public),
	)
	_ = alice.PushPSK(fuzzPSK)
	_ = bob.PushPSK(fuzzPSK)
	return alice, bob
}

// completeHandshake runs a handshake to completion, returning transport states.
// Errors during handshake completion indicate a bug in test setup, not in the
// fuzzer input, so they are fatal.
func completeHandshake(t *testing.T, alice, bob clatter.Handshaker) (*clatter.TransportState, *clatter.TransportState) {
	t.Helper()
	buf := make([]byte, clatter.MaxMessageLen)
	outBuf := make([]byte, clatter.MaxMessageLen)

	for {
		n, err := alice.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("completeHandshake: alice write: %v", err)
		}
		_, err = bob.ReadMessage(buf[:n], outBuf)
		if err != nil {
			t.Fatalf("completeHandshake: bob read: %v", err)
		}
		if alice.IsFinished() && bob.IsFinished() {
			break
		}
		n, err = bob.WriteMessage(nil, buf)
		if err != nil {
			t.Fatalf("completeHandshake: bob write: %v", err)
		}
		_, err = alice.ReadMessage(buf[:n], outBuf)
		if err != nil {
			t.Fatalf("completeHandshake: alice read: %v", err)
		}
		if alice.IsFinished() && bob.IsFinished() {
			break
		}
	}

	aliceT, err := alice.Finalize()
	if err != nil {
		t.Fatalf("completeHandshake: alice finalize: %v", err)
	}
	bobT, err := bob.Finalize()
	if err != nil {
		t.Fatalf("completeHandshake: bob finalize: %v", err)
	}
	return aliceT, bobT
}

// nqSuite returns the default NQ CipherSuite for fuzz tests.
func nqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// pqSuite returns the default PQ CipherSuite for fuzz tests.
func pqSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// hybridSuite returns the default Hybrid CipherSuite for fuzz tests.
func hybridSuite() clatter.CipherSuite {
	return clatter.CipherSuite{
		DH:     dh.NewX25519(),
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha256(),
	}
}

// --- NQ Fuzz Targets (3) ---

// FuzzNqHandshakeRead feeds random bytes to ReadMessage.
// Matches Rust: nq_handshake_read.rs
func FuzzNqHandshakeRead(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := nqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range nqPatterns() {
			alice, bob := setupNqPair(p, suite)

			if !p.IsOneWay() {
				_, _ = alice.WriteMessage(nil, buf)
				safeReadMessage(alice, data, buf)
			}
			safeReadMessage(bob, data, buf)

			alice.Destroy()
			bob.Destroy()
		}
	})
}

// FuzzNqHandshakePayload feeds random bytes as WriteMessage payload.
// Matches Rust: nq_handshake_payload.rs
func FuzzNqHandshakePayload(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := nqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range nqPatterns() {
			alice, bob := setupNqPair(p, suite)
			safeWriteMessage(alice, data, buf)
			alice.Destroy()
			bob.Destroy()
		}
	})
}

// FuzzNqTransport feeds random bytes to transport Receive.
// Matches Rust: nq_transport.rs
func FuzzNqTransport(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := nqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range nqPatterns() {
			alice, bob := setupNqPair(p, suite)
			aliceT, bobT := completeHandshake(t, alice, bob)

			if !p.IsOneWay() {
				_, _ = aliceT.Receive(data, buf)
				_, _ = bobT.Receive(data, buf)
				_, _ = aliceT.Send(data, buf)
				_, _ = bobT.Send(data, buf)
			} else {
				_, _ = aliceT.Send(data, buf)
				_, _ = bobT.Receive(data, buf)
			}

			aliceT.Destroy()
			bobT.Destroy()
		}
	})
}

// --- PQ Fuzz Targets (3) ---

// FuzzPqHandshakeRead feeds random bytes to PQ ReadMessage.
// Matches Rust: pq_handshake_read.rs
// Also drives a SEEC-on pqXX pair per input (C-10vi): the SEEC wiring
// must never panic on hostile incoming bytes either.
func FuzzPqHandshakeRead(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 256))
	f.Add(bytes.Repeat([]byte{0xA5}, 1184)) // SEEC-on seed: EKEM pubkey width

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := pqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range pqPatterns() {
			alice, bob := setupPqPair(p, suite)

			_, _ = alice.WriteMessage(nil, buf)
			safeReadMessage(alice, data, buf)
			safeReadMessage(bob, data, buf)

			alice.Destroy()
			bob.Destroy()
		}

		// SEEC-on pair (one pattern keeps the per-input cost low).
		seecSecret := bytes.Repeat([]byte{0x42}, 32)
		s, err := clatter.NewSEECPRF(hash.NewSha256(), seecSecret)
		if err != nil {
			t.Fatalf("NewSEECPRF: %v", err)
		}
		alice, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithSEEC(s))
		bob, _ := clatter.NewPqHandshake(clatter.PatternPqXX, false, suite, clatter.WithSEEC(s))
		_, _ = alice.WriteMessage(nil, buf)
		safeReadMessage(alice, data, buf)
		safeReadMessage(bob, data, buf)
		alice.Destroy()
		bob.Destroy()
	})
}

// FuzzPqHandshakePayload feeds random bytes as PQ WriteMessage payload.
// Matches Rust: pq_handshake_payload.rs
func FuzzPqHandshakePayload(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := pqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range pqPatterns() {
			alice, bob := setupPqPair(p, suite)
			safeWriteMessage(alice, data, buf)
			alice.Destroy()
			bob.Destroy()
		}
	})
}

// FuzzPqTransport feeds random bytes to PQ transport Receive.
// Matches Rust: pq_transport.rs
func FuzzPqTransport(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := pqSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range pqPatterns() {
			alice, bob := setupPqPair(p, suite)
			aliceT, bobT := completeHandshake(t, alice, bob)

			_, _ = aliceT.Receive(data, buf)
			_, _ = bobT.Receive(data, buf)
			_, _ = aliceT.Send(data, buf)
			_, _ = bobT.Send(data, buf)

			aliceT.Destroy()
			bobT.Destroy()
		}
	})
}

// --- Hybrid Fuzz Targets (3) ---

// FuzzHybridHandshakeRead feeds random bytes to Hybrid ReadMessage.
// Matches Rust: hybrid_handshake_read.rs
func FuzzHybridHandshakeRead(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 256))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := hybridSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range hybridPatterns() {
			alice, bob := setupHybridPair(p, suite)

			_, _ = alice.WriteMessage(nil, buf)
			safeReadMessage(alice, data, buf)
			safeReadMessage(bob, data, buf)

			alice.Destroy()
			bob.Destroy()
		}
	})
}

// FuzzHybridHandshakePayload feeds random bytes as Hybrid WriteMessage payload.
// Matches Rust: hybrid_handshake_payload.rs
func FuzzHybridHandshakePayload(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := hybridSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range hybridPatterns() {
			alice, bob := setupHybridPair(p, suite)
			safeWriteMessage(alice, data, buf)
			alice.Destroy()
			bob.Destroy()
		}
	})
}

// FuzzHybridTransport feeds random bytes to Hybrid transport Receive.
// Matches Rust: hybrid_transport.rs
func FuzzHybridTransport(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		suite := hybridSuite()
		buf := make([]byte, clatter.MaxMessageLen)

		for _, p := range hybridPatterns() {
			alice, bob := setupHybridPair(p, suite)
			aliceT, bobT := completeHandshake(t, alice, bob)

			_, _ = aliceT.Receive(data, buf)
			_, _ = bobT.Receive(data, buf)
			_, _ = aliceT.Send(data, buf)
			_, _ = bobT.Send(data, buf)

			aliceT.Destroy()
			bobT.Destroy()
		}
	})
}

// FuzzSEECPRF drives the exported SEEC surface with arbitrary secrets,
// purposes, output lengths, and rng streams. Contract under fuzz: never
// panic; invalid inputs error with nil output; valid inputs yield exactly
// n bytes, deterministic in (secret, r, purpose, n); a destroyed instance
// always errors.
func FuzzSEECPRF(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x42}, 32), byte(1), 32, bytes.Repeat([]byte{0x07}, 32))
	f.Add(bytes.Repeat([]byte{0x01}, 32), byte(2), 255, bytes.Repeat([]byte{0xFF}, 64))
	f.Add([]byte{1}, byte(0), 0, []byte{})
	f.Add(make([]byte, 32), byte(9), 64, make([]byte, 16))

	f.Fuzz(func(t *testing.T, secret []byte, purpose byte, n int, rngBytes []byte) {
		s, err := clatter.NewSEECPRF(hash.NewSha256(), secret)
		if err != nil {
			return // invalid secret correctly rejected
		}

		out, err := s.GenRand(bytes.NewReader(rngBytes), clatter.SEECPurpose(purpose), n)
		if err != nil {
			if out != nil {
				t.Fatal("GenRand returned output alongside an error")
			}
		} else {
			if len(out) != n {
				t.Fatalf("GenRand returned %d bytes, want %d", len(out), n)
			}
			out2, err2 := s.GenRand(bytes.NewReader(rngBytes), clatter.SEECPurpose(purpose), n)
			if err2 != nil || !bytes.Equal(out, out2) {
				t.Fatal("GenRand not deterministic in (secret, r, purpose, n)")
			}
		}

		s.Destroy()
		if _, err := s.GenRand(bytes.NewReader(rngBytes), clatter.SEECPurpose(purpose), n); err == nil {
			t.Fatal("GenRand after Destroy must error")
		}
	})
}

// safeReadMessage calls ReadMessage. Errors are expected (fuzz input is garbage).
// Panics are NOT expected and must NOT be recovered - go-clatter should never
// panic on any input. If it panics, the fuzz engine catches it as a real failure.
func safeReadMessage(hs clatter.Handshaker, data, buf []byte) {
	_, _ = hs.ReadMessage(data, buf)
}

// safeWriteMessage calls WriteMessage. Same contract as safeReadMessage.
func safeWriteMessage(hs clatter.Handshaker, data, buf []byte) {
	_, _ = hs.WriteMessage(data, buf)
}
