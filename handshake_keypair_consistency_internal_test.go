package clatter

import (
	"errors"
	"strings"
	"testing"
)

// erroringDeriver is a keypairDeriver whose GenerateKeypair always fails, used to
// prove validateKeyPairConsistency propagates a derive error verbatim.
type erroringDeriver struct{ err error }

func (e erroringDeriver) GenerateKeypair(RNG) (KeyPair, error) { return KeyPair{}, e.err }

// fixedDeriver is a keypairDeriver that always derives the same public, used to
// drive the match/mismatch branches deterministically without a real primitive.
type fixedDeriver struct{ pub []byte }

func (f fixedDeriver) GenerateKeypair(RNG) (KeyPair, error) {
	return NewKeyPair(f.pub, make([]byte, 32)), nil
}

// TestValidateKeyPairConsistency_DeriveErrorPropagatedVerbatim: a derive error is
// returned as-is, never relabeled as the mismatch sentinel (which would mislabel
// the failure and, if swallowed, risk a false-accept).
func TestValidateKeyPairConsistency_DeriveErrorPropagatedVerbatim(t *testing.T) {
	sentinel := errors.New("derive failed")
	kp := NewKeyPair([]byte{1, 2, 3}, []byte{4, 5, 6})

	got := validateKeyPairConsistency(erroringDeriver{err: sentinel}, &kp, ErrKEMInvalidKey, "static KEM")
	if !errors.Is(got, sentinel) {
		t.Fatalf("want the derive error verbatim, got %v", got)
	}
	if errors.Is(got, ErrKEMInvalidKey) {
		t.Fatal("a derive error must NOT be relabeled as a key mismatch")
	}
}

// TestValidateKeyPairConsistency_ExperimentalGateErrorPropagated: the HQC
// experimental-gate error (the realistic derive error) is propagated verbatim,
// not turned into ErrDH/ErrKEMInvalidKey.
func TestValidateKeyPairConsistency_ExperimentalGateErrorPropagated(t *testing.T) {
	kp := NewKeyPair([]byte{1}, []byte{2})

	got := validateKeyPairConsistency(erroringDeriver{err: ErrExperimentalNotAllowed}, &kp, ErrDH, "static")
	if !errors.Is(got, ErrExperimentalNotAllowed) {
		t.Fatalf("want ErrExperimentalNotAllowed verbatim, got %v", got)
	}
	if errors.Is(got, ErrDH) {
		t.Fatal("the gate error must not be relabeled as a DH mismatch")
	}
}

// TestValidateKeyPairConsistency_MatchAccepts_MismatchRejects: a re-derived public
// equal to kp.Public accepts; a differing one returns the mismatch sentinel.
func TestValidateKeyPairConsistency_MatchAccepts_MismatchRejects(t *testing.T) {
	pub := []byte{9, 9, 9, 9}
	matching := NewKeyPair(pub, []byte{1, 2, 3})
	if err := validateKeyPairConsistency(fixedDeriver{pub: pub}, &matching, ErrKEMInvalidKey, "static KEM"); err != nil {
		t.Fatalf("matching public must accept, got %v", err)
	}

	differing := NewKeyPair([]byte{8, 8, 8, 8}, []byte{1, 2, 3})
	err := validateKeyPairConsistency(fixedDeriver{pub: pub}, &differing, ErrKEMInvalidKey, "static KEM")
	if !errors.Is(err, ErrKEMInvalidKey) {
		t.Fatalf("differing public must return the mismatch sentinel, got %v", err)
	}
	// The mismatch error must carry descriptive context (slot + cause), not be a
	// bare sentinel, matching the package's other validation errors.
	if msg := err.Error(); !strings.Contains(msg, "static KEM") || !strings.Contains(msg, "does not correspond") {
		t.Fatalf("mismatch error must name the slot and cause, got %q", msg)
	}
}
