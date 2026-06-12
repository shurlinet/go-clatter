//go:build hqc

package kem

import (
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// NO t.Parallel() in any HQC test. AllowExperimental is a global
// atomic.Bool; parallel tests would race on it.

func TestHqc128_KeygenRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKeygenRNGSemantics(t, NewHqc128(), 32)
}

func TestHqc192_KeygenRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKeygenRNGSemantics(t, NewHqc192(), 32)
}

func TestHqc256_KeygenRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testKeygenRNGSemantics(t, NewHqc256(), 32)
}

func TestHqc128_EncapsRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testEncapsRNGSemantics(t, NewHqc128Testing(), 32)
}

func TestHqc192_EncapsRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testEncapsRNGSemantics(t, NewHqc192Testing(), 40)
}

func TestHqc256_EncapsRNGSemantics(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testEncapsRNGSemantics(t, NewHqc256Testing(), 48)
}
