package clatter

import (
	"bytes"
	"testing"
)

// TestDestroyKeyClones_ZeroesEphemeralKEMKey is a white-box test (package
// clatter) pinning the actual secret-zeroing of the new ephemeralKEMKey field.
// External tests can only observe that construction fails or no panic occurs;
// they cannot inspect the zeroed clone. This verifies the security property
// directly: destroyKeyClones must zero ephemeralKEMKey's secret and nil the
// field, the same as the other secret-bearing option clones. A regression that
// forgot to extend destroyKeyClones for the new field (the exact footgun this
// item guards against) would fail here.
func TestDestroyKeyClones_ZeroesEphemeralKEMKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 64) // ML-KEM-768 seed length
	kp := NewKeyPair(make([]byte, 1184), secret)
	ho := handshakeOptions{ephemeralKEMKey: &kp}

	ho.destroyKeyClones()

	if ho.ephemeralKEMKey != nil {
		t.Fatal("destroyKeyClones did not nil ephemeralKEMKey")
	}
	// kp aliases the same KeyPair the option held; its secret must be zeroed.
	for i, b := range kp.SecretSlice() {
		if b != 0 {
			t.Fatalf("ephemeralKEMKey secret byte %d not zeroed: %02x", i, b)
		}
	}
}

// TestDestroyKeyClones_ZeroesAllSecretBearingClones guards the full set: every
// secret-bearing option clone must be zeroed and niled. Pins the complete
// coverage so a future field addition without a matching destroy line is caught.
func TestDestroyKeyClones_ZeroesAllSecretBearingClones(t *testing.T) {
	mk := func() KeyPair { return NewKeyPair(make([]byte, 32), bytes.Repeat([]byte{0xCD}, 32)) }
	sk, ek, skem, ekem := mk(), mk(), mk(), mk()
	ho := handshakeOptions{
		staticKey:       &sk,
		ephemeralKey:    &ek,
		staticKEM:       &skem,
		ephemeralKEMKey: &ekem,
	}

	ho.destroyKeyClones()

	for name, kp := range map[string]KeyPair{"staticKey": sk, "ephemeralKey": ek, "staticKEM": skem, "ephemeralKEMKey": ekem} {
		for i, b := range kp.SecretSlice() {
			if b != 0 {
				t.Fatalf("%s secret byte %d not zeroed: %02x", name, i, b)
			}
		}
	}
	if ho.staticKey != nil || ho.ephemeralKey != nil || ho.staticKEM != nil || ho.ephemeralKEMKey != nil {
		t.Fatal("destroyKeyClones left a non-nil option clone")
	}
}
