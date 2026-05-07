package slhdsa_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

// --- ACVP JSON struct definitions ---

type acvpKeyGenFile struct {
	Algorithm  string             `json:"algorithm"`
	Mode       string             `json:"mode"`
	TestGroups []acvpKeyGenGroup  `json:"testGroups"`
}
type acvpKeyGenGroup struct {
	TgID         int              `json:"tgId"`
	ParameterSet string           `json:"parameterSet"`
	Tests        []acvpKeyGenTest `json:"tests"`
}
type acvpKeyGenTest struct {
	TcID     int    `json:"tcId"`
	Deferred bool   `json:"deferred"`
	SkSeed   string `json:"skSeed"`
	SkPrf    string `json:"skPrf"`
	PkSeed   string `json:"pkSeed"`
	Sk       string `json:"sk"`
	Pk       string `json:"pk"`
}

type acvpSigGenFile struct {
	TestGroups []acvpSigGenGroup `json:"testGroups"`
}
type acvpSigGenGroup struct {
	TgID          int              `json:"tgId"`
	ParameterSet  string           `json:"parameterSet"`
	Deterministic bool             `json:"deterministic"`
	PreHash       string           `json:"preHash"`
	HashAlg       string           `json:"hashAlg"`
	Tests         []acvpSigGenTest `json:"tests"`
}
type acvpSigGenTest struct {
	TcID                 int    `json:"tcId"`
	Deferred             bool   `json:"deferred"`
	Sk                   string `json:"sk"`
	Pk                   string `json:"pk"`
	AdditionalRandomness string `json:"additionalRandomness"`
	MessageLength        int    `json:"messageLength"`
	Message              string `json:"message"`
	Context              string `json:"context"`
	HashAlg              string `json:"hashAlg"`
	Signature            string `json:"signature"`
}

type acvpSigVerFile struct {
	TestGroups []acvpSigVerGroup `json:"testGroups"`
}
type acvpSigVerGroup struct {
	TgID         int              `json:"tgId"`
	ParameterSet string           `json:"parameterSet"`
	PreHash      string           `json:"preHash"`
	Tests        []acvpSigVerTest `json:"tests"`
}
type acvpSigVerTest struct {
	TcID                 int    `json:"tcId"`
	Deferred             bool   `json:"deferred"`
	TestPassed           bool   `json:"testPassed"`
	Sk                   string `json:"sk"`
	Pk                   string `json:"pk"`
	AdditionalRandomness string `json:"additionalRandomness"`
	Message              string `json:"message"`
	Context              string `json:"context"`
	HashAlg              string `json:"hashAlg"`
	Signature            string `json:"signature"`
	Reason               string `json:"reason"`
}

// --- Parameter set string mapping ---

func paramSetFromString(name string) (slhdsa.ParamSet, bool) {
	switch name {
	case "SLH-DSA-SHA2-128f":
		return slhdsa.SHA2_128f, true
	case "SLH-DSA-SHA2-128s":
		return slhdsa.SHA2_128s, true
	case "SLH-DSA-SHA2-192f":
		return slhdsa.SHA2_192f, true
	case "SLH-DSA-SHA2-192s":
		return slhdsa.SHA2_192s, true
	case "SLH-DSA-SHA2-256f":
		return slhdsa.SHA2_256f, true
	case "SLH-DSA-SHA2-256s":
		return slhdsa.SHA2_256s, true
	case "SLH-DSA-SHAKE-128f":
		return slhdsa.SHAKE_128f, true
	case "SLH-DSA-SHAKE-128s":
		return slhdsa.SHAKE_128s, true
	case "SLH-DSA-SHAKE-192f":
		return slhdsa.SHAKE_192f, true
	case "SLH-DSA-SHAKE-192s":
		return slhdsa.SHAKE_192s, true
	case "SLH-DSA-SHAKE-256f":
		return slhdsa.SHAKE_256f, true
	case "SLH-DSA-SHAKE-256s":
		return slhdsa.SHAKE_256s, true
	case "SLH-DSA-BLAKE3-128f":
		return slhdsa.BLAKE3_128f, true
	case "SLH-DSA-BLAKE3-128s":
		return slhdsa.BLAKE3_128s, true
	case "SLH-DSA-BLAKE3-192f":
		return slhdsa.BLAKE3_192f, true
	case "SLH-DSA-BLAKE3-192s":
		return slhdsa.BLAKE3_192s, true
	case "SLH-DSA-BLAKE3-256f":
		return slhdsa.BLAKE3_256f, true
	case "SLH-DSA-BLAKE3-256s":
		return slhdsa.BLAKE3_256s, true
	default:
		return 0, false
	}
}

// --- Hex helpers ---

// mustACVPHex decodes uppercase ACVP hex, fatal on error.
func mustACVPHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode failed: %v (first 40 chars: %q)", err, truncStr(s, 40))
	}
	return b
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- KeyGen test ---

func TestACVPKeyGen(t *testing.T) {
	data, err := os.ReadFile("testdata/acvp/keygen.json")
	if err != nil {
		t.Fatal(err)
	}
	var file acvpKeyGenFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			t.Logf("skipping unknown param set: %s", group.ParameterSet)
			continue
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-SHA2-128f" {
			continue
		}

		for _, tc := range group.Tests {
			t.Run(fmt.Sprintf("%s/tc%d", group.ParameterSet, tc.TcID), func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				skseed := mustACVPHex(t, tc.SkSeed)
				skprf := mustACVPHex(t, tc.SkPrf)
				pkseed := mustACVPHex(t, tc.PkSeed)
				expectedSK := mustACVPHex(t, tc.Sk)
				expectedPK := mustACVPHex(t, tc.Pk)

				params := slhdsa.InternalParamsForTest(ps)
				sk, pk := slhdsa.InternalSLHKeygenInternal(params, skseed, skprf, pkseed)

				if !bytes.Equal(sk.Bytes(), expectedSK) {
					t.Errorf("SK mismatch (got %d bytes, want %d)", len(sk.Bytes()), len(expectedSK))
				}
				if !bytes.Equal(pk.Bytes(), expectedPK) {
					t.Errorf("PK mismatch (got %d bytes, want %d)", len(pk.Bytes()), len(expectedPK))
				}
			})
		}
	}
}

// --- SigGen test ---

func TestACVPSigGen(t *testing.T) {
	data, err := os.ReadFile("testdata/acvp/sigGen.json")
	if err != nil {
		t.Fatal(err)
	}
	var file acvpSigGenFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			continue
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-SHA2-128f" {
			continue
		}

		params := slhdsa.InternalParamsForTest(ps)

		for _, tc := range group.Tests {
			name := fmt.Sprintf("%s/%s/det=%v/tc%d", group.ParameterSet, group.PreHash, group.Deterministic, tc.TcID)
			t.Run(name, func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				skBytes := mustACVPHex(t, tc.Sk)
				msg := mustACVPHex(t, tc.Message)
				expectedSig := mustACVPHex(t, tc.Signature)
				addrnd := mustACVPHex(t, tc.AdditionalRandomness)

				internalSK, err := slhdsa.InternalLoadSecretKey(params, skBytes)
				if err != nil {
					t.Fatalf("LoadSecretKey: %v", err)
				}

				// Construct M' based on preHash mode
				var mprime []byte
				switch group.PreHash {
				case "none":
					// Legacy mode: raw message passed directly to engine
					mprime = msg
				case "pure":
					// Algorithm 22: M' = [0x00 | ctxLen | ctx | M]
					ctx := mustACVPHex(t, tc.Context)
					mprime = slhdsa.MakeMPrimeForTest(msg, string(ctx))
				case "preHash":
					// Algorithm 25: M' = [0x01 | ctxLen | ctx | OID | PH(M)]
					hashAlg := tc.HashAlg
					if hashAlg == "" {
						hashAlg = group.HashAlg
					}
					hf := slhdsa.HashFuncFromACVP(hashAlg)
					if hf == 0 {
						t.Skipf("unsupported hashAlg: %s", hashAlg)
					}
					ctx := mustACVPHex(t, tc.Context)
					mprime = slhdsa.MakeMPrimePreHashForTest(msg, hf, string(ctx))
				default:
					t.Fatalf("unknown preHash: %s", group.PreHash)
				}

				// Sign
				var sig slhdsa.InternalSLHSignature
				if group.Deterministic || len(addrnd) == 0 {
					sig = slhdsa.InternalSLHSignInternalDeterministic(params, mprime, internalSK)
				} else {
					sig = slhdsa.InternalSLHSignInternal(params, mprime, internalSK, addrnd)
				}

				if !bytes.Equal(sig.Bytes(), expectedSig) {
					t.Errorf("signature mismatch (got %d bytes, want %d bytes)", len(sig.Bytes()), len(expectedSig))
				}

				// Also verify our generated signature via the public API
				if group.PreHash != "none" {
					pkBytes := mustACVPHex(t, tc.Pk)
					pub, err := slhdsa.NewPublicKey(ps, pkBytes)
					if err != nil {
						t.Fatalf("NewPublicKey: %v", err)
					}
					switch group.PreHash {
					case "pure":
						ctx := mustACVPHex(t, tc.Context)
						if !pub.VerifyWithContext(msg, sig.Bytes(), string(ctx)) {
							t.Error("public API verify failed on generated signature")
						}
					case "preHash":
						hashAlg := tc.HashAlg
						if hashAlg == "" {
							hashAlg = group.HashAlg
						}
						hf := slhdsa.HashFuncFromACVP(hashAlg)
						ctx := mustACVPHex(t, tc.Context)
						if !pub.VerifyPreHashWithContext(msg, sig.Bytes(), hf, string(ctx)) {
							t.Error("public API pre-hash verify failed on generated signature")
						}
					}
				}
			})
		}
	}
}

// --- SigVer test ---

func TestACVPSigVer(t *testing.T) {
	data, err := os.ReadFile("testdata/acvp/sigVer.json")
	if err != nil {
		t.Fatal(err)
	}
	var file acvpSigVerFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			continue
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-SHA2-128f" {
			continue
		}

		for _, tc := range group.Tests {
			name := fmt.Sprintf("%s/%s/tc%d", group.ParameterSet, group.PreHash, tc.TcID)
			t.Run(name, func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				pkBytes := mustACVPHex(t, tc.Pk)
				msgBytes := mustACVPHex(t, tc.Message)
				sigBytes := mustACVPHex(t, tc.Signature)

				pub, err := slhdsa.NewPublicKey(ps, pkBytes)
				if err != nil {
					if !tc.TestPassed {
						return // expected failure at PK load
					}
					t.Fatalf("expected pass but PK load failed: %v", err)
				}

				var verified bool
				switch group.PreHash {
				case "none":
					// Legacy mode: verify by constructing M' = raw message internally
					// We use the internal engine directly since our wrapper always uses MakeMPrime
					params := slhdsa.InternalParamsForTest(ps)
					loaded, loadErr := slhdsa.InternalLoadSignature(params, sigBytes)
					if loadErr != nil {
						verified = false
					} else {
						internalPK, _ := slhdsa.InternalLoadPublicKey(params, pkBytes)
						verified = slhdsa.InternalSLHVerifyInternal(params, msgBytes, loaded, internalPK)
					}
				case "pure":
					ctx := mustACVPHex(t, tc.Context)
					verified = pub.VerifyWithContext(msgBytes, sigBytes, string(ctx))
				case "preHash":
					hashAlg := tc.HashAlg
					hf := slhdsa.HashFuncFromACVP(hashAlg)
					if hf == 0 {
						t.Skipf("unsupported hashAlg: %s", hashAlg)
					}
					ctx := mustACVPHex(t, tc.Context)
					verified = pub.VerifyPreHashWithContext(msgBytes, sigBytes, hf, string(ctx))
				default:
					t.Fatalf("unknown preHash: %s", group.PreHash)
				}

				if verified != tc.TestPassed {
					t.Errorf("verify: got %v, want %v (reason: %s)", verified, tc.TestPassed, tc.Reason)
				}

				// Re-sign pattern for positive vectors (F547/F554)
				if tc.TestPassed && tc.Sk != "" && tc.AdditionalRandomness != "" && group.PreHash != "" {
					params := slhdsa.InternalParamsForTest(ps)
					skBytes := mustACVPHex(t, tc.Sk)
					addrnd := mustACVPHex(t, tc.AdditionalRandomness)
					internalSK, skErr := slhdsa.InternalLoadSecretKey(params, skBytes)
					if skErr != nil {
						t.Logf("re-sign: sk load failed (expected for some negative vectors)")
						return
					}

					var mprime []byte
					switch group.PreHash {
					case "none":
						mprime = msgBytes
					case "pure":
						ctx := mustACVPHex(t, tc.Context)
						mprime = slhdsa.MakeMPrimeForTest(msgBytes, string(ctx))
					case "preHash":
						hashAlg := tc.HashAlg
						hf := slhdsa.HashFuncFromACVP(hashAlg)
						if hf == 0 {
							return
						}
						ctx := mustACVPHex(t, tc.Context)
						mprime = slhdsa.MakeMPrimePreHashForTest(msgBytes, hf, string(ctx))
					}

					genSig := slhdsa.InternalSLHSignInternal(params, mprime, internalSK, addrnd)
					if !bytes.Equal(genSig.Bytes(), sigBytes) {
						t.Error("re-sign: engine produces different signature for same (sk, msg, addrnd)")
					}
				}
			})
		}
	}
}
