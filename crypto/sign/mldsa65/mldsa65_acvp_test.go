package mldsa65

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// NIST ACVP vector tests. See testdata/acvp/README.txt for provenance.
//
// Coverage through this package's public API:
//   - keyGen: seed -> public key, byte-for-byte against NIST (25 cases).
//   - sigVer: NIST positive AND negative cases (modified message,
//     commitment, z, hint) against Verify/VerifyWithContext (15 cases).
//   - sign anchor: deterministic and hedged signatures under NIST
//     keyGen-derived keys must verify against the NIST public key.
//
// ACVP sigGen byte-equality is not testable here: those vectors carry
// only the expanded secret key, and this package deliberately imports
// keys from the 32-byte seed only.

type acvpVectorFile struct {
	VsID       int             `json:"vsId"`
	Algorithm  string          `json:"algorithm"`
	Mode       string          `json:"mode"`
	Revision   string          `json:"revision"`
	TestGroups []acvpTestGroup `json:"testGroups"`
}

type acvpTestGroup struct {
	TgID         int            `json:"tgId"`
	TestType     string         `json:"testType"`
	ParameterSet string         `json:"parameterSet"`
	PreHash      string         `json:"preHash"`
	Tests        []acvpTestCase `json:"tests"`
}

type acvpTestCase struct {
	TcID       int    `json:"tcId"`
	Seed       string `json:"seed"`
	PK         string `json:"pk"`
	Message    string `json:"message"`
	Context    string `json:"context"`
	Signature  string `json:"signature"`
	TestPassed bool   `json:"testPassed"`
	Reason     string `json:"reason"`
}

func loadACVP(t *testing.T, path string) *acvpVectorFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vf acvpVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return &vf
}

func acvpHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in %s: %v", field, err)
	}
	return b
}

// TestACVP_KeyGen verifies seed -> public key byte-for-byte against the
// NIST ML-DSA-65 keyGen vectors, plus the seed export round-trip.
func TestACVP_KeyGen(t *testing.T) {
	vf := loadACVP(t, "testdata/acvp/keygen.json")

	total := 0
	for _, g := range vf.TestGroups {
		if g.ParameterSet != "ML-DSA-65" {
			t.Fatalf("group %d: unexpected parameter set %s", g.TgID, g.ParameterSet)
		}
		for _, tc := range g.Tests {
			seed := acvpHex(t, "seed", tc.Seed)
			wantPK := acvpHex(t, "pk", tc.PK)

			sk, err := NewPrivateKeyFromSeed(seed)
			if err != nil {
				t.Fatalf("tc %d: NewPrivateKeyFromSeed: %v", tc.TcID, err)
			}

			if got := sk.PublicKey().Bytes(); !bytes.Equal(got, wantPK) {
				t.Fatalf("tc %d: public key mismatch\n  got:  %x...\n  want: %x...",
					tc.TcID, got[:16], wantPK[:16])
			}

			gotSeed, err := sk.Seed()
			if err != nil {
				t.Fatalf("tc %d: Seed: %v", tc.TcID, err)
			}
			if !bytes.Equal(gotSeed, seed) {
				t.Fatalf("tc %d: seed round-trip mismatch", tc.TcID)
			}
			sk.Destroy()
			total++
		}
	}
	if total != 25 {
		t.Fatalf("ran %d keyGen cases, want exactly 25 (vector file changed?)", total)
	}
}

// TestACVP_SigVer runs the NIST ML-DSA-65 signature verification vectors,
// including the negative cases (modified message, commitment, z, hint).
// Every case must produce exactly the NIST-expected verdict.
func TestACVP_SigVer(t *testing.T) {
	vf := loadACVP(t, "testdata/acvp/sigVer.json")

	total, negatives := 0, 0
	for _, g := range vf.TestGroups {
		if g.ParameterSet != "ML-DSA-65" {
			t.Fatalf("group %d: unexpected parameter set %s", g.TgID, g.ParameterSet)
		}
		for _, tc := range g.Tests {
			pk, err := NewPublicKey(acvpHex(t, "pk", tc.PK))
			if err != nil {
				t.Fatalf("tc %d: NewPublicKey: %v", tc.TcID, err)
			}
			msg := acvpHex(t, "message", tc.Message)
			sig := acvpHex(t, "signature", tc.Signature)
			ctx := acvpHex(t, "context", tc.Context)

			var got bool
			if len(ctx) == 0 {
				got = pk.Verify(msg, sig)
			} else {
				got = pk.VerifyWithContext(msg, sig, string(ctx))
			}
			if got != tc.TestPassed {
				t.Fatalf("tc %d (%s): Verify = %v, NIST expects %v",
					tc.TcID, tc.Reason, got, tc.TestPassed)
			}
			if !tc.TestPassed {
				negatives++
			}
			total++
		}
	}
	if total != 15 {
		t.Fatalf("ran %d sigVer cases, want exactly 15 (vector file changed?)", total)
	}
	if negatives != 12 {
		t.Fatalf("ran %d negative cases, want exactly 12", negatives)
	}
}

// TestACVP_SignUnderNISTKeys anchors the signing path to NIST material:
// keys derived from NIST keyGen seeds must produce signatures (both
// deterministic and hedged) that verify under the NIST-provided public
// key bytes.
func TestACVP_SignUnderNISTKeys(t *testing.T) {
	vf := loadACVP(t, "testdata/acvp/keygen.json")

	msg := []byte("ACVP keyGen-derived signing anchor")
	checked := 0
	for _, g := range vf.TestGroups {
		for _, tc := range g.Tests {
			sk, err := NewPrivateKeyFromSeed(acvpHex(t, "seed", tc.Seed))
			if err != nil {
				t.Fatalf("tc %d: NewPrivateKeyFromSeed: %v", tc.TcID, err)
			}
			nistPK, err := NewPublicKey(acvpHex(t, "pk", tc.PK))
			if err != nil {
				t.Fatalf("tc %d: NewPublicKey: %v", tc.TcID, err)
			}

			detSig, err := sk.SignDeterministic(msg)
			if err != nil {
				t.Fatalf("tc %d: SignDeterministic: %v", tc.TcID, err)
			}
			if !nistPK.Verify(msg, detSig) {
				t.Fatalf("tc %d: deterministic signature rejected by NIST public key", tc.TcID)
			}

			hedgedSig, err := sk.Sign(msg)
			if err != nil {
				t.Fatalf("tc %d: Sign: %v", tc.TcID, err)
			}
			if !nistPK.Verify(msg, hedgedSig) {
				t.Fatalf("tc %d: hedged signature rejected by NIST public key", tc.TcID)
			}

			sk.Destroy()
			checked++
		}
	}
	if checked != 25 {
		t.Fatalf("anchored %d keys, want exactly 25", checked)
	}
}
