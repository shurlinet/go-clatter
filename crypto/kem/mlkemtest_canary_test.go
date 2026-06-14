package kem

import (
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"testing"
)

// TestMlkemTestCanary exists to break CI LOUDLY if crypto/mlkem/mlkemtest
// ever changes shape, gets gated, or is removed from the standard library
// (PQF-2b).
//
// WHY: mlkemtest is the standard library's only FIPS 203 Encaps_internal
// (derandomized encapsulation) entry point, and its own documentation
// scopes it to known-answer tests - the Go team makes NO compatibility
// promise for it. go-clatter's SEEC-hedged encapsulation for ML-KEM is
// built on it (EncapsulateWithCoins). If a future Go release moves or
// removes it, this test - and the adapter build - must fail with a clear
// trail back to this comment, instead of the breakage first surfacing in
// a consumer's build. HQC is unaffected (go-hqc exposes deterministic
// encapsulation as a first-class production API).
func TestMlkemTestCanary(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("mlkem keygen: %v", err)
	}
	coins := bytes.Repeat([]byte{0x07}, 32)
	ss, ct, err := mlkemtest.Encapsulate768(dk.EncapsulationKey(), coins)
	if err != nil {
		t.Fatalf("mlkemtest.Encapsulate768 failed: the stdlib derandomized interface changed; SEEC-encaps for ML-KEM depends on it: %v", err)
	}
	ss2, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ss, ss2) {
		t.Fatal("mlkemtest round-trip broke: derandomized and standard paths disagree")
	}
}
