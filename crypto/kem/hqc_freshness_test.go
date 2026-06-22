//go:build hqc

package kem

import (
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// HQC production-entropy freshness tests. Same rationale as the
// ML-KEM freshness tests in kem_freshness_test.go.
//
// NO t.Parallel() in any HQC test (AllowExperimental is a global atomic).

func TestHqc128_ProductionEncapsFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionEncapsFreshness(t, NewHqc128())
}

func TestHqc192_ProductionEncapsFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionEncapsFreshness(t, NewHqc192())
}

func TestHqc256_ProductionEncapsFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionEncapsFreshness(t, NewHqc256())
}

func TestHqc128_ProductionKeygenFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionKeygenFreshness(t, NewHqc128())
}

func TestHqc192_ProductionKeygenFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionKeygenFreshness(t, NewHqc192())
}

func TestHqc256_ProductionKeygenFreshness(t *testing.T) {
	clatter.AllowExperimental.Store(true)
	defer clatter.AllowExperimental.Store(false)
	testProductionKeygenFreshness(t, NewHqc256())
}
