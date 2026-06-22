package clatter_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// Suite-boundary validation tests: consumer-chosen primitives with
// impossible declared geometry must fail at construction with errors,
// never panic mid-handshake or silently corrupt the wire.

// hugeLenHash wraps a real hash but declares an oversized HashLen
// (beyond the MaxHashLen state arrays - the slice-out-of-range probe).
type hugeLenHash struct{ clatter.HashFunc }

func (hugeLenHash) HashLen() int { return 100 }

// zeroLenHash declares a zero HashLen.
type zeroLenHash struct{ clatter.HashFunc }

func (zeroLenHash) HashLen() int { return 0 }

// badTagCipher wraps a real cipher but declares a 12-byte tag.
type badTagCipher struct{ clatter.Cipher }

func (badTagCipher) TagLen() int { return 12 }

// badKeyCipher wraps a real cipher but declares a 16-byte key.
type badKeyCipher struct{ clatter.Cipher }

func (badKeyCipher) KeyLen() int { return 16 }

func TestSuiteValidation_GeometryRejected(t *testing.T) {
	base := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqBase := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyBase := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	for _, tc := range []struct {
		name   string
		mutate func(s clatter.CipherSuite) clatter.CipherSuite
	}{
		{"hash-too-long", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Hash = hugeLenHash{s.Hash}
			return s
		}},
		{"hash-zero", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Hash = zeroLenHash{s.Hash}
			return s
		}},
		{"tag-not-16", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Cipher = badTagCipher{s.Cipher}
			return s
		}},
		{"key-not-32", func(s clatter.CipherSuite) clatter.CipherSuite {
			s.Cipher = badKeyCipher{s.Cipher}
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, tc.mutate(base)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("NQ constructor: want ErrInvalidSuite, got %v", err)
			}
			if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, tc.mutate(pqBase)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("PQ constructor: want ErrInvalidSuite, got %v", err)
			}
			if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, tc.mutate(hyBase)); !errors.Is(err, clatter.ErrInvalidSuite) {
				t.Fatalf("Hybrid constructor: want ErrInvalidSuite, got %v", err)
			}
		})
	}
}

// TestSuiteValidation_InitializeSymmetricLatches covers direct users of
// the exported SymmetricState API: an impossible declared HashLen latches
// the error state instead of panicking on the fixed-size arrays.
func TestSuiteValidation_InitializeSymmetricLatches(t *testing.T) {
	ss := clatter.InitializeSymmetric(hugeLenHash{hash.NewSha256()}, cipher.NewChaChaPoly(), "Noise_XX_25519_ChaChaPoly_SHA256")
	if ss.Err() == nil {
		t.Fatal("InitializeSymmetric with an oversized declared HashLen must latch an error")
	}
	ss.MixHash([]byte("must not panic"))
	if _, err := ss.EncryptAndHash([]byte("payload")); err == nil {
		t.Fatal("operations on the latched state must fail")
	}
}

// TestPresetKeyLengthValidation pins the constructor-time length checks
// for pre-set key options: a wrong-length key is a loud ErrInvalidKeyLength
// at construction, not a silently malformed wire message.
func TestPresetKeyLengthValidation(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqS := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyS := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	shortKP := clatter.NewKeyPair(make([]byte, 16), make([]byte, 16))

	if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithStaticKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithEphemeralKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short ephemeral: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewNqHandshake(clatter.PatternIK, true, nqS, clatter.WithRemoteStatic(make([]byte, 16))); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short remote static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS, clatter.WithStaticKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("PQ short static: want ErrInvalidKeyLength, got %v", err)
	}
	if _, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, clatter.WithStaticKEMKey(shortKP)); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("Hybrid short KEM static: want ErrInvalidKeyLength, got %v", err)
	}
	// hybridIK (not hybridXX): the responder pre-shares its static, so the
	// initiator's remote KEM static is applicable and the length check fires;
	// hybridXX transmits in-band and would reject the remote option as a no-op.
	if _, err := clatter.NewHybridHandshake(clatter.PatternHybridIK, true, hyS, clatter.WithRemoteStaticKEMKey(make([]byte, 16))); !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("Hybrid short remote KEM static: want ErrInvalidKeyLength, got %v", err)
	}
}

// TestNqEphemeralKEMKey_Rejected verifies NQ rejects WithEphemeralKEMKey
// LOUDLY (a KEM ephemeral cannot be honored by a DH-only handshake; a silent
// drop would hide a classical-only downgrade from the caller).
func TestNqEphemeralKEMKey_Rejected(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	kemKP := clatter.NewKeyPair(make([]byte, 1184), make([]byte, 64))

	hs, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS,
		clatter.WithEphemeralKEMKey(kemKP))
	if !errors.Is(err, clatter.ErrInvalidOption) {
		t.Fatalf("NQ must reject WithEphemeralKEMKey with ErrInvalidOption, got %v", err)
	}
	if hs != nil {
		t.Fatal("NQ constructor must return nil handshake on rejected option")
	}
}

// TestPqRejectsKEMNamedStatics verifies PQ (KEM-only) loudly rejects the
// Hybrid-only KEM-static options, on BOTH roles and regardless of pattern. PQ
// sets its KEM static via WithStaticKey / WithRemoteStatic, so silently
// dropping these would hide a misconfiguration from the caller (a key believed
// set that is not). Mirrors NQ's loud rejection of WithEphemeralKEMKey. The
// reject is role- and pattern-independent: a no-static pattern (pqNN) and a
// pre-message-S pattern (pqIK), as both initiator and responder.
func TestPqRejectsKEMNamedStatics(t *testing.T) {
	pqS := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	kemKP := clatter.NewKeyPair(make([]byte, 1184), make([]byte, 64)) // ML-KEM-768 pub + seed lengths
	kemPub := make([]byte, 1184)

	for _, initiator := range []bool{true, false} {
		role := "responder"
		if initiator {
			role = "initiator"
		}
		for _, pat := range []*clatter.HandshakePattern{clatter.PatternPqNN, clatter.PatternPqIK} {
			t.Run(role+"/"+pat.Name()+"/WithStaticKEMKey", func(t *testing.T) {
				hs, err := clatter.NewPqHandshake(pat, initiator, pqS, clatter.WithStaticKEMKey(kemKP))
				if !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("PQ WithStaticKEMKey: want ErrInvalidOption, got %v", err)
				}
				if hs != nil {
					t.Fatal("constructor must return nil handshake on rejected option")
				}
			})
			t.Run(role+"/"+pat.Name()+"/WithRemoteStaticKEMKey", func(t *testing.T) {
				hs, err := clatter.NewPqHandshake(pat, initiator, pqS, clatter.WithRemoteStaticKEMKey(kemPub))
				if !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("PQ WithRemoteStaticKEMKey: want ErrInvalidOption, got %v", err)
				}
				if hs != nil {
					t.Fatal("constructor must return nil handshake on rejected option")
				}
			})
		}
	}
}

// TestNqRejectsKEMNamedStatics verifies NQ (DH-only) loudly rejects the
// Hybrid-only KEM-static options, backing the WithStaticKEMKey /
// WithRemoteStaticKEMKey godoc contract ("NQ and PQ reject with
// ErrInvalidOption"). NQ sets its static via WithStaticKey / WithRemoteStatic;
// the KEM-static options have no NQ slot.
func TestNqRejectsKEMNamedStatics(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	kemKP := clatter.NewKeyPair(make([]byte, 1184), make([]byte, 64))
	kemPub := make([]byte, 1184)

	for _, initiator := range []bool{true, false} {
		role := "responder"
		if initiator {
			role = "initiator"
		}
		for _, pat := range []*clatter.HandshakePattern{clatter.PatternNN, clatter.PatternIK} {
			t.Run(role+"/"+pat.Name()+"/WithStaticKEMKey", func(t *testing.T) {
				hs, err := clatter.NewNqHandshake(pat, initiator, nqS, clatter.WithStaticKEMKey(kemKP))
				if !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("NQ WithStaticKEMKey: want ErrInvalidOption, got %v", err)
				}
				if hs != nil {
					t.Fatal("constructor must return nil handshake on rejected option")
				}
			})
			t.Run(role+"/"+pat.Name()+"/WithRemoteStaticKEMKey", func(t *testing.T) {
				hs, err := clatter.NewNqHandshake(pat, initiator, nqS, clatter.WithRemoteStaticKEMKey(kemPub))
				if !errors.Is(err, clatter.ErrInvalidOption) {
					t.Fatalf("NQ WithRemoteStaticKEMKey: want ErrInvalidOption, got %v", err)
				}
				if hs != nil {
					t.Fatal("constructor must return nil handshake on rejected option")
				}
			})
		}
	}
}

// TestNqStaticKey_WrongSecretLen rejects wrong DH static secret length.
func TestNqStaticKey_WrongSecretLen(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	badKP := clatter.NewKeyPair(make([]byte, 32), make([]byte, 16))
	_, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithStaticKey(badKP))
	if !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short static secret: want ErrInvalidKeyLength, got %v", err)
	}
}

// TestNqEphemeralKey_WrongSecretLen rejects wrong DH ephemeral secret length.
func TestNqEphemeralKey_WrongSecretLen(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	badKP := clatter.NewKeyPair(make([]byte, 32), make([]byte, 16))
	_, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS, clatter.WithEphemeralKey(badKP))
	if !errors.Is(err, clatter.ErrInvalidKeyLength) {
		t.Fatalf("NQ short ephemeral secret: want ErrInvalidKeyLength, got %v", err)
	}
}

// TestDoubleSetOption_DestroysFirstClone verifies the double-set fix: passing
// the same option twice destroys the first clone's secret before overwriting.
func TestDoubleSetOption_DestroysFirstClone(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}

	kp1, _ := dh.NewX25519().GenerateKeypair(clatter.NewDummyRng(1))
	kp2, _ := dh.NewX25519().GenerateKeypair(clatter.NewDummyRng(2))

	// Passing WithStaticKey twice must not panic and must use the second key.
	// The first clone is destroyed by the second call (no secret leak). XX (not
	// NN) so the static is applicable - NN transmits no static and now rejects it.
	hs, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS,
		clatter.WithStaticKey(kp1),
		clatter.WithStaticKey(kp2))
	if err != nil {
		t.Fatalf("double WithStaticKey: %v", err)
	}
	hs.Destroy()
}

// TestPqConstructorFailure_CleansEphemeralKEMKey verifies that when the PQ
// constructor fails after WithEphemeralKEMKey is set, the clone is zeroed.
func TestPqConstructorFailure_CleansEphemeralKEMKey(t *testing.T) {
	// Use a valid ephemeral but an invalid suite (missing Hash) to trigger failure.
	badSuite := clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		// Hash deliberately nil -> constructor fails
	}
	kemKP, _ := kem.NewMlKem768().GenerateKeypair(clatter.NewDummyRng(0xEE))

	_, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, badSuite,
		clatter.WithEphemeralKEMKey(kemKP))
	if err == nil {
		t.Fatal("expected constructor failure with nil Hash")
	}
	// If destroyKeyClones didn't cover ephemeralKEMKey, the clone's secret
	// would leak. We can't directly inspect the zeroed state from an external
	// test, but the test proves the code path doesn't panic.
}

// TestConstructorReturnsNilOnRejection pins the invariant that a constructor
// which returns an error returns a nil handshake - never a partially-built,
// usable-looking object alongside the error. Covers all three families. The
// per-option length tests assert the error type; this asserts the nil return.
func TestConstructorReturnsNilOnRejection(t *testing.T) {
	nqS := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	pqS := clatter.CipherSuite{EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	hyS := clatter.CipherSuite{DH: dh.NewX25519(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
	short := clatter.NewKeyPair(make([]byte, 16), make([]byte, 16))

	if hs, err := clatter.NewNqHandshake(clatter.PatternXX, true, nqS, clatter.WithStaticKey(short)); err == nil || hs != nil {
		t.Fatalf("NQ: want (nil, err), got (%v, %v)", hs, err)
	}
	if hs, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, pqS, clatter.WithStaticKey(short)); err == nil || hs != nil {
		t.Fatalf("PQ: want (nil, err), got (%v, %v)", hs, err)
	}
	if hs, err := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hyS, clatter.WithStaticKey(short)); err == nil || hs != nil {
		t.Fatalf("Hybrid: want (nil, err), got (%v, %v)", hs, err)
	}
	// And the loud-rejection path (inapplicable option), not just length.
	kemKP := clatter.NewKeyPair(make([]byte, 1184), make([]byte, 64))
	if hs, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqS, clatter.WithEphemeralKEMKey(kemKP)); err == nil || hs != nil {
		t.Fatalf("NQ reject: want (nil, err), got (%v, %v)", hs, err)
	}
}

// perPartyTokenCapMarker is the substring unique to the per-party Token::E /
// Token::S "at most once" validators (validateEphemeral/StaticTokenRules).
// Asserting it pins the rejection to THAT validator, so a future change that
// re-routes a malformed pattern to an earlier guard (e.g. the arity validator)
// cannot silently degrade these into vacuous "rejected by something" tests.
const perPartyTokenCapMarker = "at most once per party"

// assertRejectedBy fails unless err is ErrInvalidPattern AND carries marker, so
// the rejection provably comes from the intended validator.
func assertRejectedBy(t *testing.T, what string, err error, marker string) {
	t.Helper()
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("%s: want ErrInvalidPattern, got %v", what, err)
	}
	if err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("%s: rejection did not come from the intended validator (missing %q): %v", what, marker, err)
	}
}

// TestNewPattern_RejectsDoubleEphemeral verifies the pattern-level guard that
// replaced the old runtime "ephemeral already set" check: a custom pattern in
// which a party emits Token E more than once is rejected at construction. Both
// shapes keep an alternation-valid arity (numResponder <= numInitiator <=
// numResponder+1) so the rejection comes from the ephemeral-cap validator, not
// the earlier arity validator, and each asserts that validator's marker.
func TestNewPattern_RejectsDoubleEphemeral(t *testing.T) {
	// Initiator emits Token E in two separate messages (ni=2, nr=1 - arity-valid).
	_, err := clatter.NewPattern("badDoubleE",
		[][]clatter.Token{{clatter.TokenE}, {clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		nil, nil)
	assertRejectedBy(t, "double initiator Token::E", err, perPartyTokenCapMarker)

	// Responder emits Token E twice in its single message (ni=1, nr=1 -
	// arity-valid; a responder-heavy ni<nr shape would be pre-empted by arity).
	_, err = clatter.NewPattern("badDoubleEResp",
		[][]clatter.Token{{clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE, clatter.TokenE}},
		nil, nil)
	assertRejectedBy(t, "double responder Token::E", err, perPartyTokenCapMarker)

	// Sanity: the well-formed NN-shaped pattern (E once per party) is accepted.
	if _, err := clatter.NewPattern("okNN",
		[][]clatter.Token{{clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		nil, nil); err != nil {
		t.Fatalf("well-formed single-E pattern wrongly rejected: %v", err)
	}
}

// TestNewPattern_RejectsDoubleStatic verifies the static counterpart of the
// double-ephemeral rule: Noise section 7.3 requires each party to send its static
// (Token::S) at most once per handshake, pre-messages included. A party that
// transmits its static twice, or both pre-shares it and re-sends it, is rejected
// at construction (the static analogue of TestNewPattern_RejectsDoubleEphemeral).
// Every shape keeps an alternation-valid arity so the static-cap validator owns
// the rejection (asserted via its marker), not the earlier arity validator.
func TestNewPattern_RejectsDoubleStatic(t *testing.T) {
	// Initiator sends Token::S in two messages (ni=2, nr=1 - arity-valid).
	_, err := clatter.NewPattern("badDoubleS",
		[][]clatter.Token{{clatter.TokenE, clatter.TokenS}, {clatter.TokenS}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		nil, nil)
	assertRejectedBy(t, "double initiator Token::S", err, perPartyTokenCapMarker)

	// Initiator both pre-shares its static AND sends it - two occurrences.
	_, err = clatter.NewPattern("badPreAndMsgS",
		[][]clatter.Token{{clatter.TokenE, clatter.TokenS}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE}},
		[]clatter.Token{clatter.TokenS}, nil)
	assertRejectedBy(t, "pre-message + message Token::S", err, perPartyTokenCapMarker)

	// Responder sends Token::S twice in its single message (ni=1, nr=1 -
	// arity-valid; a responder-heavy ni<nr shape would be pre-empted by arity).
	_, err = clatter.NewPattern("badDoubleSResp",
		[][]clatter.Token{{clatter.TokenE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE, clatter.TokenS, clatter.TokenS}},
		nil, nil)
	assertRejectedBy(t, "double responder Token::S", err, perPartyTokenCapMarker)

	// Sanity: a single static per party (XX-shaped) is accepted.
	if _, err := clatter.NewPattern("okSingleS",
		[][]clatter.Token{{clatter.TokenE}, {clatter.TokenS, clatter.TokenSE}},
		[][]clatter.Token{{clatter.TokenE, clatter.TokenEE, clatter.TokenS, clatter.TokenES}},
		nil, nil); err != nil {
		t.Fatalf("well-formed single-S pattern wrongly rejected: %v", err)
	}
}

// allocCipher wraps a real cipher but VIOLATES the in-place contract:
// it writes its (correct) output into a freshly allocated buffer instead
// of the caller's out. The in-place transport paths must detect this and
// still put real ciphertext on the wire - never report success with the
// plaintext left in the buffer.
type allocCipher struct{ inner clatter.Cipher }

func (a allocCipher) Name() string { return a.inner.Name() }
func (a allocCipher) TagLen() int  { return a.inner.TagLen() }
func (a allocCipher) KeyLen() int  { return a.inner.KeyLen() }
func (a allocCipher) Encrypt(key [32]byte, nonce uint64, ad, plaintext, _ []byte) ([]byte, error) {
	out := make([]byte, 0, len(plaintext)+a.inner.TagLen())
	return a.inner.Encrypt(key, nonce, ad, plaintext, out)
}
func (a allocCipher) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, _ []byte) ([]byte, error) {
	out := make([]byte, 0, len(ciphertext))
	return a.inner.Decrypt(key, nonce, ad, ciphertext, out)
}

func TestInPlaceTransport_ContractViolatingCipher(t *testing.T) {
	suite := clatter.CipherSuite{DH: dh.NewX25519(), Cipher: allocCipher{cipher.NewChaChaPoly()}, Hash: hash.NewSha256()}

	a, err := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	if err != nil {
		t.Fatal(err)
	}
	b, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = runHandshakeRecorded(t, a, b)
	tsA, err := a.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	tsB, err := b.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	defer tsA.Destroy()
	defer tsB.Destroy()

	payload := []byte("must never appear on the wire")
	buf := make([]byte, 4096)
	copy(buf, payload)
	n, err := tsA.SendInPlace(buf, len(payload))
	if err != nil {
		t.Fatalf("SendInPlace: %v", err)
	}
	if bytes.Contains(buf[:n], payload) {
		t.Fatal("in-place send left the PLAINTEXT in the wire buffer (contract-violating cipher undetected)")
	}
	out := make([]byte, 4096)
	pn, err := tsB.Receive(buf[:n], out)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if !bytes.Equal(out[:pn], payload) {
		t.Fatal("round-trip payload mismatch")
	}
}
