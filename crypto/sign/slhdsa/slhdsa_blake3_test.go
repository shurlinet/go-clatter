package slhdsa_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

// --- PQC Suite B BLAKE3 vector JSON structs ---
// Same ACVP schema but no context/hashAlg/preHash fields.

type blake3KeyGenFile struct {
	TestGroups []blake3KeyGenGroup `json:"testGroups"`
}
type blake3KeyGenGroup struct {
	TgID         int                `json:"tgId"`
	ParameterSet string             `json:"parameterSet"`
	Tests        []blake3KeyGenTest `json:"tests"`
}
type blake3KeyGenTest struct {
	TcID     int    `json:"tcId"`
	Deferred bool   `json:"deferred"`
	SkSeed   string `json:"skSeed"`
	SkPrf    string `json:"skPrf"`
	PkSeed   string `json:"pkSeed"`
	Sk       string `json:"sk"`
	Pk       string `json:"pk"`
}

type blake3SigGenFile struct {
	TestGroups []blake3SigGenGroup `json:"testGroups"`
}
type blake3SigGenGroup struct {
	TgID          int                `json:"tgId"`
	ParameterSet  string             `json:"parameterSet"`
	Deterministic bool               `json:"deterministic"`
	Tests         []blake3SigGenTest `json:"tests"`
}
type blake3SigGenTest struct {
	TcID                 int    `json:"tcId"`
	Deferred             bool   `json:"deferred"`
	Sk                   string `json:"sk"`
	AdditionalRandomness string `json:"additionalRandomness"`
	MessageLength        int    `json:"messageLength"`
	Message              string `json:"message"`
	Signature            string `json:"signature"`
}

type blake3SigVerFile struct {
	TestGroups []blake3SigVerGroup `json:"testGroups"`
}
type blake3SigVerGroup struct {
	TgID         int                `json:"tgId"`
	ParameterSet string             `json:"parameterSet"`
	Tests        []blake3SigVerTest `json:"tests"`
}
type blake3SigVerTest struct {
	TcID                 int    `json:"tcId"`
	Deferred             bool   `json:"deferred"`
	TestPassed           bool   `json:"testPassed"`
	Sk                   string `json:"sk"`
	Pk                   string `json:"pk"`
	AdditionalRandomness string `json:"additionalRandomness"`
	Message              string `json:"message"`
	Signature            string `json:"signature"`
	Reason               string `json:"reason"`
}

// --- KeyGen ---

func TestBLAKE3KeyGen(t *testing.T) {
	data, err := os.ReadFile("testdata/blake3/blake3_keygen.json")
	if err != nil {
		t.Fatal(err)
	}
	var file blake3KeyGenFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			t.Fatalf("unknown param set: %s", group.ParameterSet)
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-BLAKE3-128f" {
			continue
		}

		for _, tc := range group.Tests {
			t.Run(fmt.Sprintf("%s/tc%d", group.ParameterSet, tc.TcID), func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				skseed := mustHex(t, tc.SkSeed)
				skprf := mustHex(t, tc.SkPrf)
				pkseed := mustHex(t, tc.PkSeed)
				expectedSK := mustHex(t, tc.Sk)
				expectedPK := mustHex(t, tc.Pk)

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

// --- SigGen ---

func TestBLAKE3SigGen(t *testing.T) {
	data, err := os.ReadFile("testdata/blake3/blake3_sig.json")
	if err != nil {
		t.Fatal(err)
	}
	var file blake3SigGenFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			continue
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-BLAKE3-128f" {
			continue
		}

		params := slhdsa.InternalParamsForTest(ps)

		for _, tc := range group.Tests {
			name := fmt.Sprintf("%s/det=%v/tc%d", group.ParameterSet, group.Deterministic, tc.TcID)
			t.Run(name, func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				skBytes := mustHex(t, tc.Sk)
				msg := mustHex(t, tc.Message)
				expectedSig := mustHex(t, tc.Signature)
				addrnd := mustHex(t, tc.AdditionalRandomness)

				internalSK, err := slhdsa.InternalLoadSecretKey(params, skBytes)
				if err != nil {
					t.Fatalf("LoadSecretKey: %v", err)
				}

				// BLAKE3 vectors use the INTERNAL API directly (raw message,
				// no MakeMPrime wrapper). Same as NIST ACVP "none" preHash mode.
				mprime := msg

				var sig slhdsa.InternalSLHSignature
				if group.Deterministic || len(addrnd) == 0 {
					sig = slhdsa.InternalSLHSignInternalDeterministic(params, mprime, internalSK)
				} else {
					sig = slhdsa.InternalSLHSignInternal(params, mprime, internalSK, addrnd)
				}

				if !bytes.Equal(sig.Bytes(), expectedSig) {
					t.Errorf("signature mismatch (got %d bytes, want %d bytes)", len(sig.Bytes()), len(expectedSig))
				}
			})
		}
	}
}

// --- SigVer ---

func TestBLAKE3SigVer(t *testing.T) {
	data, err := os.ReadFile("testdata/blake3/blake3_ver.json")
	if err != nil {
		t.Fatal(err)
	}
	var file blake3SigVerFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	for _, group := range file.TestGroups {
		ps, ok := paramSetFromString(group.ParameterSet)
		if !ok {
			continue
		}
		if testing.Short() && group.ParameterSet != "SLH-DSA-BLAKE3-128f" {
			continue
		}

		for _, tc := range group.Tests {
			name := fmt.Sprintf("%s/tc%d", group.ParameterSet, tc.TcID)
			t.Run(name, func(t *testing.T) {
				if tc.Deferred {
					t.Skip("deferred vector")
				}

				pkBytes := mustHex(t, tc.Pk)
				msgBytes := mustHex(t, tc.Message)
				sigBytes := mustHex(t, tc.Signature)

				// BLAKE3 vectors use the INTERNAL API directly (raw message,
				// no MakeMPrime wrapper). Use internal verify path.
				params := slhdsa.InternalParamsForTest(ps)
				var verified bool
				loaded, loadErr := slhdsa.InternalLoadSignature(params, sigBytes)
				if loadErr != nil {
					verified = false
				} else {
					internalPK, pkErr := slhdsa.InternalLoadPublicKey(params, pkBytes)
					if pkErr != nil {
						verified = false
					} else {
						verified = slhdsa.InternalSLHVerifyInternal(params, msgBytes, loaded, internalPK)
					}
				}

				if verified != tc.TestPassed {
					t.Errorf("verify: got %v, want %v (reason: %s)", verified, tc.TestPassed, tc.Reason)
				}

				// Re-sign pattern for positive vectors
				if tc.TestPassed && tc.Sk != "" && tc.AdditionalRandomness != "" {
					skBytes := mustHex(t, tc.Sk)
					addrnd := mustHex(t, tc.AdditionalRandomness)
					internalSK, skErr := slhdsa.InternalLoadSecretKey(params, skBytes)
					if skErr != nil {
						t.Logf("re-sign: sk load failed")
						return
					}

					genSig := slhdsa.InternalSLHSignInternal(params, msgBytes, internalSK, addrnd)
					if !bytes.Equal(genSig.Bytes(), sigBytes) {
						t.Error("re-sign: engine produces different signature for same (sk, msg, addrnd)")
					}
				}
			})
		}
	}
}
