// export_test.go exposes internal functions for use by the external test
// package (package slhdsa_test). This file is compiled ONLY during testing.
// None of these exports are part of the public API.

package slhdsa

import "github.com/shurlinet/go-clatter/crypto/sign/slhdsa/internal"

// MakeMPrimeForTest exposes makeMPrime for ACVP vector tests.
var MakeMPrimeForTest = makeMPrime

// MakeMPrimePreHashForTest exposes makeMPrimePreHash for ACVP pre-hash vector tests.
var MakeMPrimePreHashForTest = makeMPrimePreHash

// InternalParamsForTest returns the internal.ParamSet for a given ParamSet.
func InternalParamsForTest(ps ParamSet) internal.ParamSet {
	return ps.internalParams()
}

// Re-export internal types and functions needed by ACVP tests.
type (
	InternalSLHSecretKey = internal.SLHSecretKey
	InternalSLHSignature = internal.SLHSignature
	InternalParamSet     = internal.ParamSet
)

var (
	InternalSLHKeygenInternal            = internal.SLHKeygenInternal
	InternalSLHSignInternal              = internal.SLHSignInternal
	InternalSLHSignInternalDeterministic = internal.SLHSignInternalDeterministic
	InternalSLHVerifyInternal            = internal.SLHVerifyInternal
	InternalLoadSecretKey                = internal.LoadSecretKey
	InternalLoadPublicKey                = internal.LoadPublicKey
	InternalLoadSignature                = internal.LoadSignature
)

// HashFuncFromACVP maps ACVP JSON hashAlg string to HashFunc.
// Test-only utility - not part of the public API.
func HashFuncFromACVP(s string) HashFunc {
	switch s {
	case "SHA2-224":
		return HashSHA2_224
	case "SHA2-256":
		return HashSHA2_256
	case "SHA2-384":
		return HashSHA2_384
	case "SHA2-512":
		return HashSHA2_512
	case "SHA2-512/224":
		return HashSHA2_512224
	case "SHA2-512/256":
		return HashSHA2_512256
	case "SHA3-224":
		return HashSHA3_224
	case "SHA3-256":
		return HashSHA3_256
	case "SHA3-384":
		return HashSHA3_384
	case "SHA3-512":
		return HashSHA3_512
	case "SHAKE-128":
		return HashSHAKE128
	case "SHAKE-256":
		return HashSHAKE256
	default:
		return 0
	}
}
