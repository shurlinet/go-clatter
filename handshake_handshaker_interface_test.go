package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// The Handshaker interface exposes IsInitiator/IsOneWay/MaxMessageLen
// and an internal bind capability that NewHybridDualLayerHandshake requires of
// its inner. These tests exercise that surface through an EXTERNAL Handshaker
// implementation (the first in the suite) plus the concrete types.

// mockHandshaker is a minimal external clatter.Handshaker. Only the role /
// one-way / limit accessors carry real values; the protocol methods are inert
// stubs because dual-layer CONSTRUCTION only calls the accessors (it never
// drives the mock). Being external, it cannot implement the package-internal
// bind capability, so it is never accepted as a hybrid dual-layer inner.
type mockHandshaker struct {
	initiator bool
	oneWay    bool
	maxMsgLen int
}

func (m *mockHandshaker) WriteMessage(payload, out []byte) (int, error) { return 0, nil }
func (m *mockHandshaker) ReadMessage(message, out []byte) (int, error)  { return 0, nil }
func (m *mockHandshaker) IsFinished() bool                              { return false }
func (m *mockHandshaker) IsWriteTurn() bool                             { return m.initiator }
func (m *mockHandshaker) Finalize() (*clatter.TransportState, error)    { return nil, nil }
func (m *mockHandshaker) GetNextMessageOverhead() (int, error)          { return 0, nil }
func (m *mockHandshaker) PushPSK(psk []byte) error                      { return nil }
func (m *mockHandshaker) GetHandshakeHash() []byte                      { return nil }
func (m *mockHandshaker) IsInitiator() bool                             { return m.initiator }
func (m *mockHandshaker) IsOneWay() bool                                { return m.oneWay }
func (m *mockHandshaker) MaxMessageLen() int                            { return m.maxMsgLen }
func (m *mockHandshaker) Destroy()                                      {}

// Compile-time: the external mock satisfies the enlarged Handshaker. It cannot
// satisfy the package-internal bind capability, so it can never be a hybrid
// dual-layer inner - which is exactly what TestHandshakerInterface_HybridDualRejects... asserts.
var _ clatter.Handshaker = (*mockHandshaker)(nil)

func nqSuiteHandshakerInterface() clatter.CipherSuite {
	return clatter.CipherSuite{DH: dh.NewX25519(), Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256()}
}

func pqSuiteHandshakerInterface() clatter.CipherSuite {
	return clatter.CipherSuite{Cipher: cipher.NewChaChaPoly(), Hash: hash.NewSha256(), EKEM: kem.NewMlKem768(), SKEM: kem.NewMlKem768()}
}

// TestHandshakerInterface_RoleParityViaInterface: a role mismatch is detected by reading
// IsInitiator() through the interface on an external Handshaker.
func TestHandshakerInterface_RoleParityViaInterface(t *testing.T) {
	_, err := clatter.NewDualLayerHandshake(
		&mockHandshaker{initiator: true},
		&mockHandshaker{initiator: false},
		4096)
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("role mismatch: got %v, want ErrInvalidPattern", err)
	}
}

// TestHandshakerInterface_OneWayOuterRejectedViaInterface: an external one-way outer is now
// rejected. Previously getPattern() returned nil for non-built-in types, so the
// one-way check was silently skipped (previously a silently-skipped check).
func TestHandshakerInterface_OneWayOuterRejectedViaInterface(t *testing.T) {
	_, err := clatter.NewDualLayerHandshake(
		&mockHandshaker{initiator: true, oneWay: true},
		&mockHandshaker{initiator: true},
		4096)
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("one-way external outer: got %v, want ErrInvalidPattern", err)
	}
}

// TestHandshakerInterface_InnerMaxViaInterface: the inner-fits-the-limit check reads
// inner.MaxMessageLen(). A custom dl limit smaller than inner+TagLen is rejected.
func TestHandshakerInterface_InnerMaxViaInterface(t *testing.T) {
	_, err := clatter.NewDualLayerHandshake(
		&mockHandshaker{initiator: true},
		&mockHandshaker{initiator: true, maxMsgLen: 1000},
		4096,
		clatter.WithMaxMessageLen(500))
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("inner max 1000 > dl limit 500: got %v, want ErrInvalidPattern", err)
	}
}

// TestHandshakerInterface_HybridDualRejectsNonBindableInner: an external inner (which cannot
// be cryptographically bound) is rejected at construction; the SAME inner is
// fine for a plain dual-layer (which does not bind).
func TestHandshakerInterface_HybridDualRejectsNonBindableInner(t *testing.T) {
	_, err := clatter.NewHybridDualLayerHandshake(
		&mockHandshaker{initiator: false},
		&mockHandshaker{initiator: false}, // external -> not bindable
		4096)
	if !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("non-bindable inner: got %v, want ErrInvalidPattern", err)
	}

	if _, err := clatter.NewDualLayerHandshake(
		&mockHandshaker{initiator: false},
		&mockHandshaker{initiator: false},
		4096); err != nil {
		t.Fatalf("plain dual-layer with non-bindable inner should succeed: %v", err)
	}
}

// TestHandshakerInterface_HybridDualAcceptsBuiltinInner: a built-in PQ inner (which CAN be
// bound) constructs cleanly - the positive counterpart to the rejection tests.
// (The binding is then actually invoked and verified byte-for-byte by the
// hybrid-dual vector and smoke tests, and by TestHandshakeInternals_bindOuterTransport.)
func TestHandshakerInterface_HybridDualAcceptsBuiltinInner(t *testing.T) {
	outer, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuiteHandshakerInterface())
	if err != nil {
		t.Fatalf("outer NN: %v", err)
	}
	inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuiteHandshakerInterface())
	if err != nil {
		t.Fatalf("inner pqNN: %v", err)
	}
	if _, err := clatter.NewHybridDualLayerHandshake(outer, inner, 8192); err != nil {
		t.Fatalf("built-in inner should construct: %v", err)
	}
}

// TestHandshakerInterface_HybridDualRejectsNestedDualLayerInner: a nested dual-layer cannot be
// bound (the dual-layer types are not bindable inners), so it is refused
// at construction instead of mid-handshake (fail-closed).
func TestHandshakerInterface_HybridDualRejectsNestedDualLayerInner(t *testing.T) {
	nq, pq := nqSuiteHandshakerInterface(), pqSuiteHandshakerInterface()
	oI, err := clatter.NewNqHandshake(clatter.PatternNN, true, nq)
	if err != nil {
		t.Fatalf("outer NN: %v", err)
	}
	iI, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pq)
	if err != nil {
		t.Fatalf("inner pqNN: %v", err)
	}
	nested, err := clatter.NewDualLayerHandshake(oI, iI, 8192)
	if err != nil {
		t.Fatalf("build nested dual-layer: %v", err)
	}

	outer2, err := clatter.NewNqHandshake(clatter.PatternNN, true, nq)
	if err != nil {
		t.Fatalf("outer2 NN: %v", err)
	}
	if _, err := clatter.NewHybridDualLayerHandshake(outer2, nested, 16384); !errors.Is(err, clatter.ErrInvalidPattern) {
		t.Fatalf("nested dual-layer inner: got %v, want ErrInvalidPattern", err)
	}
}

// TestHandshakerInterface_ConcreteGetters: the new getters report the constructed role,
// one-wayness, and limit for each built-in handshake type.
func TestHandshakerInterface_ConcreteGetters(t *testing.T) {
	suite := nqSuiteHandshakerInterface()
	rkp, _ := suite.DH.GenerateKeypair(clatter.NewDummyRng(0xABCD))

	// One-way N initiator.
	n, err := clatter.NewNqHandshake(clatter.PatternN, true, suite, clatter.WithRemoteStatic(rkp.Public))
	if err != nil {
		t.Fatalf("PatternN: %v", err)
	}
	if !n.IsInitiator() {
		t.Error("N initiator: IsInitiator should be true")
	}
	if !n.IsOneWay() {
		t.Error("PatternN: IsOneWay should be true")
	}
	if n.MaxMessageLen() != clatter.MaxMessageLen {
		t.Errorf("N default MaxMessageLen: got %d, want %d", n.MaxMessageLen(), clatter.MaxMessageLen)
	}

	// Interactive NN responder with a custom limit.
	nn, err := clatter.NewNqHandshake(clatter.PatternNN, false, suite, clatter.WithMaxMessageLen(4096))
	if err != nil {
		t.Fatalf("PatternNN: %v", err)
	}
	if nn.IsInitiator() {
		t.Error("NN responder: IsInitiator should be false")
	}
	if nn.IsOneWay() {
		t.Error("PatternNN: IsOneWay should be false")
	}
	if nn.MaxMessageLen() != 4096 {
		t.Errorf("NN custom MaxMessageLen: got %d, want 4096", nn.MaxMessageLen())
	}

	// Dual-layer reports not-one-way and the dual-layer-level limit.
	oI, _ := clatter.NewNqHandshake(clatter.PatternNN, true, suite)
	iI, _ := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuiteHandshakerInterface())
	dl, err := clatter.NewDualLayerHandshake(oI, iI, 8192)
	if err != nil {
		t.Fatalf("dual-layer: %v", err)
	}
	if !dl.IsInitiator() {
		t.Error("dual-layer: IsInitiator should be true")
	}
	if dl.IsOneWay() {
		t.Error("dual-layer: IsOneWay should be false")
	}
	if dl.MaxMessageLen() != clatter.MaxMessageLen {
		t.Errorf("dual-layer MaxMessageLen: got %d, want %d", dl.MaxMessageLen(), clatter.MaxMessageLen)
	}
}

// TestHandshakerInterface_MaxMessageLenSurvivesDestroy pins the decision that maxMsgLen is a
// non-secret limit and is NOT zeroed by Destroy, keeping MaxMessageLen()
// race-free against a concurrent Destroy.
func TestHandshakerInterface_MaxMessageLenSurvivesDestroy(t *testing.T) {
	hs, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuiteHandshakerInterface(), clatter.WithMaxMessageLen(4096))
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	hs.Destroy()
	if got := hs.MaxMessageLen(); got != 4096 {
		t.Errorf("MaxMessageLen after Destroy: got %d, want 4096 (not zeroed)", got)
	}
}
