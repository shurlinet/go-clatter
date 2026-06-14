package clatter_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// TestSEEC_FIPS140OnlyFailsClosed empirically verifies the C-8/E-4 claim:
// under GODEBUG=fips140=only, crypto/mlkem/mlkemtest refuses derandomized
// encapsulation, so SEEC-hedged encapsulation fails CLOSED - at the
// adapter (EncapsulateWithCoins errors wrapping ErrKEM while production
// Encapsulate succeeds on the approved internal DRBG), and mid-handshake
// (a SEEC-on pqNN dies at the responder's first encaps draw with ErrKEM,
// before any AEAD operation, and stays in the sticky error state).
//
// Empirical fact discovered writing this test: NO go-clatter handshake
// completes under fips140=only regardless of SEEC - Noise's deterministic
// counter nonces are rejected by GCM in that mode ("use of GCM with
// arbitrary IVs is not allowed in FIPS 140-only mode") and ChaChaPoly is
// not an approved cipher. The planned SEEC-off full-handshake baseline is
// therefore structurally impossible; the adapter-level contrast above is
// what isolates the mlkemtest gate.
//
// GODEBUG=fips140=only must be set at process start, so the test re-execs
// itself as a subprocess with the environment applied.
func TestSEEC_FIPS140OnlyFailsClosed(t *testing.T) {
	if os.Getenv("GO_CLATTER_SEEC_FIPS_CHILD") == "1" {
		runSeecFipsChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestSEEC_FIPS140OnlyFailsClosed$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "GO_CLATTER_SEEC_FIPS_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=only subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "SEEC_FIPS_CHILD_OK") {
		t.Fatalf("fips140=only subprocess did not report success:\n%s", out)
	}
}

// runSeecFipsChild executes inside the fips140=only subprocess.
func runSeecFipsChild(t *testing.T) {
	k := kem.NewMlKem768()

	// Adapter-level contrast: production encapsulation (approved internal
	// DRBG) succeeds; coins-driven encapsulation (mlkemtest) is gated.
	kp, err := k.GenerateKeypair(clatter.NewDummyRng(0xdeadbeef))
	if err != nil {
		t.Fatalf("keygen under fips140=only: %v", err)
	}
	if _, _, err := k.Encapsulate(kp.Public, nil); err != nil {
		t.Fatalf("production encapsulation must succeed under fips140=only, got: %v", err)
	}
	_, _, err = k.EncapsulateWithCoins(kp.Public, make([]byte, 32))
	if err == nil {
		t.Fatal("EncapsulateWithCoins succeeded under fips140=only: mlkemtest gate not in effect")
	}
	if !errors.Is(err, clatter.ErrKEM) {
		t.Fatalf("EncapsulateWithCoins fips140=only failure must wrap ErrKEM, got: %v", err)
	}

	// Handshake-level: a SEEC-on pqNN dies at the responder's first
	// encaps draw (BEFORE any AEAD operation - Noise's own GCM nonce use
	// is rejected in this mode, see the test comment), wrapped in ErrKEM,
	// and the responder latches the sticky error state.
	suite := clatter.CipherSuite{
		EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768(),
		Cipher: cipher.NewAesGcm(), Hash: hash.NewSha256(),
	}
	s, err := clatter.NewSEECPRF(hash.NewSha256(), seecTestSecret())
	if err != nil {
		t.Fatalf("NewSEECPRF: %v", err)
	}
	a, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatalf("initiator constructor: %v", err)
	}
	b, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite, clatter.WithSEEC(s))
	if err != nil {
		t.Fatalf("responder constructor: %v", err)
	}
	buf := make([]byte, clatter.MaxMessageLen)
	out := make([]byte, clatter.MaxMessageLen)
	n, err := a.WriteMessage(nil, buf) // initiator keygen: external-seed key import, approved
	if err != nil {
		t.Fatalf("initiator msg1 under fips140=only: %v", err)
	}
	if _, err := b.ReadMessage(buf[:n], out); err != nil {
		t.Fatalf("responder read msg1 under fips140=only: %v", err)
	}
	_, err = b.WriteMessage(nil, buf)
	if err == nil {
		t.Fatal("SEEC-on responder encaps completed under fips140=only: mlkemtest gate not in effect")
	}
	if !errors.Is(err, clatter.ErrKEM) {
		t.Fatalf("SEEC-on mid-handshake failure must wrap ErrKEM, got: %v", err)
	}
	if _, err := b.WriteMessage(nil, buf); !errors.Is(err, clatter.ErrErrorState) {
		t.Fatalf("responder must latch the sticky error state, got: %v", err)
	}

	fmt.Println("SEEC_FIPS_CHILD_OK")
}
