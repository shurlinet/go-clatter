package clatter_test

import (
	crand "crypto/rand"
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// These tests pin the construction-time LOCAL keypair public<->secret
// consistency check: a pre-set keypair whose public does not correspond to its
// secret is rejected at construction (ErrDH for DH, ErrKEMInvalidKey for KEM)
// instead of failing mid-handshake with a divergent shared secret and an AEAD
// tag mismatch.

// flipPublicByte returns a copy of kp with one PUBLIC-key byte flipped and the
// SAME (valid) secret: a right-length keypair whose public no longer corresponds
// to its secret. The PUBLIC (not the secret) is corrupted on purpose - for
// X25519, clamping makes secrets that differ only in clamped-away bits derive to
// the same public, so a secret flip can be a no-op (see the clamp-equivalence
// test below). Flipping the public is the only reliable mismatch for every alg.
func flipPublicByte(kp clatter.KeyPair) clatter.KeyPair {
	badPub := make([]byte, len(kp.Public))
	copy(badPub, kp.Public)
	badPub[0] ^= 0xFF
	return clatter.NewKeyPair(badPub, kp.SecretSlice())
}

// TestKeyPairConsistency_LocalMismatchRejectedAtConstruction covers all 8 local
// keypair sites across NQ/PQ/Hybrid (DH static/ephemeral, KEM static/ephemeral):
// a valid keypair constructs, the same keypair with a flipped public is rejected
// with the slot-correct sentinel.
func TestKeyPairConsistency_LocalMismatchRejectedAtConstruction(t *testing.T) {
	x := dh.NewX25519()
	nq := nqSuite()
	pq := pqSuiteProd()
	hy := hybridSuiteProd()

	mkDH := func() clatter.KeyPair { kp, _ := x.GenerateKeypair(crand.Reader); return kp }
	mkKEM := func() clatter.KeyPair { kp, _ := pq.SKEM.GenerateKeypair(crand.Reader); return kp } // ML-KEM-768, fits both EKEM and SKEM slots here

	cases := []struct {
		name string
		mk   func() clatter.KeyPair
		run  func(kp clatter.KeyPair) error
		want error
	}{
		{"NQ/DHStatic", mkDH, func(kp clatter.KeyPair) error {
			_, err := clatter.NewNqHandshake(clatter.PatternXX, true, nq, clatter.WithStaticKey(kp))
			return err
		}, clatter.ErrDH},
		{"NQ/DHEphemeral", mkDH, func(kp clatter.KeyPair) error {
			_, err := clatter.NewNqHandshake(clatter.PatternNN, true, nq, clatter.WithEphemeralKey(kp))
			return err
		}, clatter.ErrDH},
		{"PQ/KEMStatic", mkKEM, func(kp clatter.KeyPair) error {
			_, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pq, clatter.WithStaticKey(kp))
			return err
		}, clatter.ErrKEMInvalidKey},
		{"PQ/KEMEphemeral", mkKEM, func(kp clatter.KeyPair) error {
			_, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pq, clatter.WithEphemeralKEMKey(kp))
			return err
		}, clatter.ErrKEMInvalidKey},
		{"Hybrid/DHStatic", mkDH, func(kp clatter.KeyPair) error {
			_, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hy, clatter.WithStaticKey(kp))
			return err
		}, clatter.ErrDH},
		{"Hybrid/DHEphemeral", mkDH, func(kp clatter.KeyPair) error {
			_, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, hy, clatter.WithEphemeralKey(kp))
			return err
		}, clatter.ErrDH},
		{"Hybrid/KEMStatic", mkKEM, func(kp clatter.KeyPair) error {
			_, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hy, clatter.WithStaticKEMKey(kp))
			return err
		}, clatter.ErrKEMInvalidKey},
		{"Hybrid/KEMEphemeral", mkKEM, func(kp clatter.KeyPair) error {
			_, err := clatter.NewHybridHandshake(clatter.PatternHybridNN, true, hy, clatter.WithEphemeralKEMKey(kp))
			return err
		}, clatter.ErrKEMInvalidKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			good := tc.mk()
			if err := tc.run(good); err != nil {
				t.Fatalf("valid keypair must construct, got %v", err)
			}
			if err := tc.run(flipPublicByte(good)); !errors.Is(err, tc.want) {
				t.Fatalf("flipped-public keypair: want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestKeyPairConsistency_WrongLengthIsLengthErr_NotMismatch pins the ordering
// invariant: the per-slot length check runs BEFORE the consistency check, so a
// wrong-length secret is a clean ErrInvalidKeyLength (not a wrapped derive error
// or a mismatch), while a right-length wrong-public keypair is the mismatch.
func TestKeyPairConsistency_WrongLengthIsLengthErr_NotMismatch(t *testing.T) {
	pq := pqSuiteProd()
	good, _ := pq.SKEM.GenerateKeypair(crand.Reader)

	shortSecret := clatter.NewKeyPair(good.Public, make([]byte, 16))
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pq, clatter.WithStaticKey(shortSecret)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("wrong-length secret: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pq, clatter.WithStaticKey(flipPublicByte(good))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("right-length mismatch: want ErrKEMInvalidKey, got %v", err)
	}
}

// TestKeyPairConsistency_MixedSuite_SlotCorrectKEM proves the consistency check
// uses the slot-correct KEM: with EKEM=ML-KEM-768 and SKEM=ML-KEM-1024 (distinct
// public lengths), a valid static (SKEM) and a valid ephemeral (EKEM) BOTH
// construct - which is only possible if the static is derived via SKEM and the
// ephemeral via EKEM (deriving with the wrong KEM yields a wrong-length public
// and a false reject). Corrupting each still rejects (defense-in-depth).
func TestKeyPairConsistency_MixedSuite_SlotCorrectKEM(t *testing.T) {
	suite := mixedPqSuite() // EKEM ML-KEM-768, SKEM ML-KEM-1024
	staticKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	ephKP, _ := suite.EKEM.GenerateKeypair(crand.Reader)

	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithStaticKey(staticKP)); err != nil {
		t.Fatalf("valid SKEM static must construct (slot-correct KEM): %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithEphemeralKEMKey(ephKP)); err != nil {
		t.Fatalf("valid EKEM ephemeral must construct (slot-correct KEM): %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithStaticKey(flipPublicByte(staticKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("corrupt SKEM static: want ErrKEMInvalidKey, got %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithEphemeralKEMKey(flipPublicByte(ephKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("corrupt EKEM ephemeral: want ErrKEMInvalidKey, got %v", err)
	}
}

// TestKeyPairConsistency_AllSlotsInOneConstruction_Isolated presets all four
// Hybrid local keypairs in a single construction: all-valid constructs, and
// corrupting exactly one slot rejects with that slot's sentinel while the other
// three remain valid (slot isolation, no cross-contamination).
func TestKeyPairConsistency_AllSlotsInOneConstruction_Isolated(t *testing.T) {
	hy := hybridSuiteProd()
	x := hy.DH
	dhS, _ := x.GenerateKeypair(crand.Reader)
	dhE, _ := x.GenerateKeypair(crand.Reader)
	kemS, _ := hy.SKEM.GenerateKeypair(crand.Reader)
	kemE, _ := hy.EKEM.GenerateKeypair(crand.Reader)

	build := func(s, e, ks, ke clatter.KeyPair) error {
		_, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hy,
			clatter.WithStaticKey(s), clatter.WithEphemeralKey(e),
			clatter.WithStaticKEMKey(ks), clatter.WithEphemeralKEMKey(ke))
		return err
	}

	if err := build(dhS, dhE, kemS, kemE); err != nil {
		t.Fatalf("all four valid presets must construct: %v", err)
	}
	if err := build(flipPublicByte(dhS), dhE, kemS, kemE); !errors.Is(err, clatter.ErrDH) {
		t.Fatalf("corrupt only DH static: want ErrDH, got %v", err)
	}
	if err := build(dhS, dhE, kemS, flipPublicByte(kemE)); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("corrupt only KEM ephemeral: want ErrKEMInvalidKey, got %v", err)
	}
}

// TestKeyPairConsistency_SameInstanceEKEMSKEM_SlotPointer guards against a
// wrong-keypair-pointer bug that a same-KEM suite would otherwise hide: with one
// shared ML-KEM-768 instance for EKEM and SKEM, a valid static and a corrupted
// ephemeral must reject specifically because the EPHEMERAL slot is checked (if
// the ephemeral site mistakenly validated the static keypair, the valid static
// would pass and the corruption would slip through).
func TestKeyPairConsistency_SameInstanceEKEMSKEM_SlotPointer(t *testing.T) {
	k := kem.NewMlKem768()
	suite := clatter.CipherSuite{EKEM: k, SKEM: k, Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	staticKP, _ := suite.SKEM.GenerateKeypair(crand.Reader)
	ephKP, _ := suite.EKEM.GenerateKeypair(crand.Reader)

	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
		clatter.WithStaticKey(staticKP), clatter.WithEphemeralKEMKey(ephKP)); err != nil {
		t.Fatalf("valid static + ephemeral (same KEM instance) must construct: %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
		clatter.WithStaticKey(staticKP), clatter.WithEphemeralKEMKey(flipPublicByte(ephKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("valid static + corrupt ephemeral: want ErrKEMInvalidKey from the ephemeral slot, got %v", err)
	}
}

// TestKeyPairConsistency_PSKPattern_DoesNotInterfere confirms the check runs
// normally inside a PSK pattern (the PSK is orthogonal to the local keypair): a
// valid local static constructs, a mismatched one is still rejected.
func TestKeyPairConsistency_PSKPattern_DoesNotInterfere(t *testing.T) {
	pq := pqSuiteProd()
	staticKP, _ := pq.SKEM.GenerateKeypair(crand.Reader)

	if _, err := clatter.NewPqHandshake(clatter.PatternPqXXpsk3, true, pq, clatter.WithStaticKey(staticKP)); err != nil {
		t.Fatalf("valid static in a PSK pattern must construct: %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXXpsk3, true, pq, clatter.WithStaticKey(flipPublicByte(staticKP))); !errors.Is(err, clatter.ErrKEMInvalidKey) {
		t.Fatalf("mismatched static in a PSK pattern: want ErrKEMInvalidKey, got %v", err)
	}
}

// TestKeyPairConsistency_X25519_ClampEquivalentSecretAccepted documents that the
// check validates CORRESPONDENCE, not secret canonicity: an X25519 secret that
// differs from the canonical one only in clamped-away bits derives to the same
// public, so the pairing is a valid working keypair and is ACCEPTED. (This is why
// the mismatch tests above flip the PUBLIC byte, never the secret.)
func TestKeyPairConsistency_X25519_ClampEquivalentSecretAccepted(t *testing.T) {
	x := dh.NewX25519()
	kp, _ := x.GenerateKeypair(crand.Reader)

	variant := make([]byte, len(kp.SecretSlice()))
	copy(variant, kp.SecretSlice())
	variant[0] ^= 0x07 // low 3 bits of byte 0 are cleared by X25519 clamping -> same public

	clampEquivalent := clatter.NewKeyPair(kp.Public, variant)
	if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqSuite(), clatter.WithStaticKey(clampEquivalent)); err != nil {
		t.Fatalf("a clamp-equivalent X25519 secret must be accepted (correspondence, not canonicity), got %v", err)
	}
}
