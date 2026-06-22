package slhdsa_test

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

// errSentinel + errReader exercise the fail-closed rand path: a reader
// that always errors must make Sign return an error reachable via errors.Is.
var errSentinel = errors.New("slhdsa_test: rng failure")

type errReader struct{ err error }

func (r *errReader) Read(p []byte) (int, error) { return 0, r.err }

// mustHex decodes a hex string, failing the test on error.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

// --- Basic roundtrip tests ---

func TestSignVerifyRoundtrip_SHA2_128f(t *testing.T) {
	testSignVerifyRoundtrip(t, slhdsa.SHA2_128f)
}

func TestSignVerifyRoundtrip_SHAKE_128f(t *testing.T) {
	testSignVerifyRoundtrip(t, slhdsa.SHAKE_128f)
}

func TestSignVerifyRoundtrip_BLAKE3_128f(t *testing.T) {
	testSignVerifyRoundtrip(t, slhdsa.BLAKE3_128f)
}

func testSignVerifyRoundtrip(t *testing.T, ps slhdsa.ParamSet) {
	priv, err := slhdsa.GenerateKey(ps)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	defer priv.Destroy()

	pub := priv.PublicKey()
	msg := []byte("test message for SLH-DSA")

	sig, err := priv.SignMessage(msg)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if len(sig) != ps.SignatureSize() {
		t.Fatalf("sig size: got %d, want %d", len(sig), ps.SignatureSize())
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("valid signature failed verification")
	}
	// Wrong message must fail
	if pub.Verify([]byte("wrong message"), sig) {
		t.Fatal("wrong message passed verification")
	}
}

// --- Context tests ---

func TestSignVerifyWithContext(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("context test")
	sig, err := priv.SignWithContext(msg, "app/v1")
	if err != nil {
		t.Fatal(err)
	}
	if !pub.VerifyWithContext(msg, sig, "app/v1") {
		t.Fatal("correct context failed")
	}
	if pub.VerifyWithContext(msg, sig, "app/v2") {
		t.Fatal("wrong context passed")
	}
	if pub.Verify(msg, sig) {
		t.Fatal("no-context verified context-signed message")
	}
}

func TestContextTooLong(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	longCtx := string(make([]byte, 256))
	_, err = priv.SignWithContext([]byte("msg"), longCtx)
	if err != slhdsa.ErrContextTooLong {
		t.Fatalf("expected ErrContextTooLong, got %v", err)
	}
}

func TestContext255Bytes(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	ctx255 := string(make([]byte, 255))
	msg := []byte("255-byte context")
	sig, err := priv.SignWithContext(msg, ctx255)
	if err != nil {
		t.Fatalf("255-byte context should work: %v", err)
	}
	if !pub.VerifyWithContext(msg, sig, ctx255) {
		t.Fatal("255-byte context verify failed")
	}
}

// --- Deterministic signing ---

func TestDeterministicSigning(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("deterministic test")
	sig1, err := priv.SignDeterministic(msg)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := priv.SignDeterministic(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("deterministic signing produced different signatures")
	}
	if !pub.Verify(msg, sig1) {
		t.Fatal("deterministic signature failed verification")
	}
}

// --- Destroy semantics ---

func TestDestroyPreventsSign(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()

	// Sign before destroy
	msg := []byte("before destroy")
	sig, err := priv.SignMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("pre-destroy sig failed")
	}

	priv.Destroy()

	_, err = priv.SignMessage(msg)
	if err != slhdsa.ErrDestroyed {
		t.Fatalf("expected ErrDestroyed, got %v", err)
	}
	_, err = priv.Bytes()
	if err != slhdsa.ErrDestroyed {
		t.Fatalf("Bytes after Destroy: expected ErrDestroyed, got %v", err)
	}

	// PublicKey survives Destroy
	if !pub.Verify(msg, sig) {
		t.Fatal("PublicKey should survive Destroy")
	}
}

func TestDoubleDestroy(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	priv.Destroy()
	priv.Destroy() // must not panic
}

func TestNilReceiverSign(t *testing.T) {
	var priv *slhdsa.PrivateKey
	_, err := priv.SignMessage([]byte("test"))
	if err != slhdsa.ErrDestroyed {
		t.Fatalf("nil Sign: expected ErrDestroyed, got %v", err)
	}
}

func TestNilReceiverVerify(t *testing.T) {
	var pub *slhdsa.PublicKey
	if pub.Verify([]byte("test"), []byte("sig")) {
		t.Fatal("nil Verify should return false")
	}
}

// --- Key serialization ---

func TestKeyRoundtrip(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	skBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(skBytes) != slhdsa.SHA2_128f.SecretKeySize() {
		t.Fatalf("sk size: got %d, want %d", len(skBytes), slhdsa.SHA2_128f.SecretKeySize())
	}

	priv2, err := slhdsa.NewPrivateKeyFromBytes(slhdsa.SHA2_128f, skBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer priv2.Destroy()

	if !priv.Equal(priv2) {
		t.Fatal("loaded key not equal to original")
	}
	if priv.ParamSet() != slhdsa.SHA2_128f {
		t.Fatalf("ParamSet: got %v, want SHA2_128f", priv.ParamSet())
	}

	// Sign with loaded key, verify with original pub
	msg := []byte("roundtrip test")
	sig, err := priv2.SignDeterministic(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey().Verify(msg, sig) {
		t.Fatal("sig from loaded key failed verification with original pub")
	}
}

func TestEqualDifferentParamSet(t *testing.T) {
	priv1, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv1.Destroy()
	priv2, err := slhdsa.GenerateKey(slhdsa.SHAKE_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv2.Destroy()

	if priv1.Equal(priv2) {
		t.Fatal("different param set keys should not be equal")
	}
	if priv1.PublicKey().Equal(priv2.PublicKey()) {
		t.Fatal("different param set public keys should not be equal")
	}
}

func TestEqualDestroyedKey(t *testing.T) {
	priv1, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv2.Destroy()

	priv1.Destroy()
	if priv1.Equal(priv2) {
		t.Fatal("destroyed key should not be equal to live key")
	}
}

func TestZeroValuePublicKeyNotEqual(t *testing.T) {
	var pub1, pub2 slhdsa.PublicKey
	if pub1.Equal(&pub2) {
		t.Fatal("zero-value public keys should not be equal")
	}
}

func TestPublicKeyMarshalParse(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	data, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2+slhdsa.SHA2_128f.PublicKeySize() {
		t.Fatalf("marshal size: got %d", len(data))
	}

	pub2, err := slhdsa.ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(pub2) {
		t.Fatal("parsed key not equal to original")
	}
	if pub2.ParamSet() != slhdsa.SHA2_128f {
		t.Fatalf("parsed ParamSet: got %v", pub2.ParamSet())
	}
}

func TestParsePublicKeyInvalid(t *testing.T) {
	// paramset 0 == SHA2_128f (a runtime-ready set), so {1, 0, 0} reaches the
	// length check with a valid header and a too-short body -> size error;
	// paramset 255 is unknown -> paramset error before any length check.
	cases := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{"empty", nil, slhdsa.ErrInvalidPublicKey},
		{"one byte", []byte{1}, slhdsa.ErrInvalidPublicKey},
		{"wrong version", []byte{2, 0, 0, 0}, slhdsa.ErrUnsupportedVersion},
		{"wrong paramset", []byte{1, 255}, slhdsa.ErrInvalidParamSet},
		{"wrong length", []byte{1, 0, 0}, slhdsa.ErrInvalidPublicKeySize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := slhdsa.ParsePublicKey(tc.data)
			if err == nil {
				t.Fatal("expected error")
			}
			// The umbrella sentinel matches for every malformed input.
			if !errors.Is(err, slhdsa.ErrInvalidPublicKey) {
				t.Fatalf("want errors.Is ErrInvalidPublicKey, got %v", err)
			}
			// The specific cause is distinguishable.
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want errors.Is %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// --- Concurrent safety ---

func TestConcurrentSign(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("concurrent test")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := priv.SignMessage(msg)
			if err != nil {
				t.Errorf("concurrent sign: %v", err)
				return
			}
			if !pub.Verify(msg, sig) {
				t.Error("concurrent sig failed verification")
			}
		}()
	}
	wg.Wait()
}

// --- crypto.Signer ---

func TestCryptoSigner(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	var signer crypto.Signer = priv
	msg := []byte("crypto.Signer test")

	// Pure mode: nil opts
	sig, err := signer.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("crypto.Signer.Sign: %v", err)
	}
	pub := priv.PublicKey()
	if !pub.Verify(msg, sig) {
		t.Fatal("crypto.Signer signature failed verification")
	}

	// Pure mode with context via SignerOpts
	sig2, err := signer.Sign(nil, msg, &slhdsa.SignerOpts{Context: "test/ctx"})
	if err != nil {
		t.Fatalf("crypto.Signer.Sign with context: %v", err)
	}
	if !pub.VerifyWithContext(msg, sig2, "test/ctx") {
		t.Fatal("crypto.Signer context sig failed")
	}
}

// --- crypto.Signer with foreign opts ---

func TestCryptoSignerForeignOpts(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("foreign opts test")

	// Conforming crypto.Signer contract: the caller pre-hashes and passes the
	// digest. Foreign opts crypto.SHA256 maps to HashSHA2_256; the digest is used
	// directly as PH(M) with NO re-hash. VerifyPreHash takes the full message and
	// computes PH itself, so it is the independent standard verifier.
	d := sha256.Sum256(msg)
	sig, err := priv.Sign(nil, d[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("foreign opts SHA256: %v", err)
	}
	if !pub.VerifyPreHash(msg, sig, slhdsa.HashSHA2_256) {
		t.Fatal("conforming digest signature failed verification")
	}

	// MUTATION GUARD: the OLD abuse (full message passed as the "digest") must now
	// be rejected. msg is 17 bytes != 32 (SHA-256), so the mandatory digest-length
	// validation rejects it. This line PASSED under the old double-hash contract;
	// under the conforming crypto.Signer contract it MUST fail.
	_, err = priv.Sign(nil, msg, crypto.SHA256)
	if !errors.Is(err, slhdsa.ErrInvalidDigestLength) {
		t.Fatalf("full-message-as-digest must be rejected: got %v, want ErrInvalidDigestLength", err)
	}

	// EXACT-LENGTH residual: a 32-byte FULL message PASSES the
	// length guard but is treated as PH(M), so it must NOT verify - the verifier
	// computes PH(msg) != msg. This is the case the length guard cannot catch; it
	// is the only guard against a regression that re-introduced an internal
	// re-hash on the digest path (which would double-hash a 32-byte input and
	// still pass every length check).
	msg32 := bytes.Repeat([]byte{0xAB}, 32)
	sig32, err := priv.Sign(nil, msg32, crypto.SHA256)
	if err != nil {
		t.Fatalf("32-byte input must pass the length guard: %v", err)
	}
	if pub.VerifyPreHash(msg32, sig32, slhdsa.HashSHA2_256) {
		t.Fatal("a full message signed as a digest must NOT verify (proves the digest path does not re-hash)")
	}

	// Foreign opts with unsupported hash must return error
	_, err = priv.Sign(nil, d[:], crypto.MD5)
	if err == nil {
		t.Fatal("foreign opts MD5 should fail")
	}
}

// --- Pre-hash ---

func TestPreHashSignVerify(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("pre-hash test message")
	sig, err := priv.SignPreHash(msg, slhdsa.HashSHA2_256)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.VerifyPreHash(msg, sig, slhdsa.HashSHA2_256) {
		t.Fatal("pre-hash verify failed")
	}
	// Wrong hash func
	if pub.VerifyPreHash(msg, sig, slhdsa.HashSHA3_256) {
		t.Fatal("wrong hash func should fail")
	}
	// Pure verify should fail on pre-hash sig
	if pub.Verify(msg, sig) {
		t.Fatal("pure verify on pre-hash sig should fail")
	}
}

func TestPreHashBLAKE3Rejected(t *testing.T) {
	// BLAKE3 param sets work for pure signing but do NOT support pre-hash
	// (no FIPS 205 OID defined for BLAKE3).
	priv, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err != nil {
		t.Fatalf("BLAKE3 GenerateKey should succeed: %v", err)
	}
	defer priv.Destroy()

	// Pure signing works
	msg := []byte("blake3 test")
	sig, err := priv.SignMessage(msg)
	if err != nil {
		t.Fatalf("BLAKE3 SignMessage should succeed: %v", err)
	}
	if !priv.PublicKey().Verify(msg, sig) {
		t.Fatal("BLAKE3 signature failed verification")
	}

	// Pre-hash is rejected
	_, err = priv.SignPreHash(msg, slhdsa.HashSHA2_256)
	if err != slhdsa.ErrPreHashNotSupported {
		t.Fatalf("expected ErrPreHashNotSupported, got %v", err)
	}
}

func TestPreHashInvalidHashFunc(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	_, err = priv.SignPreHash([]byte("msg"), slhdsa.HashFunc(99))
	if err != slhdsa.ErrInvalidHashFunc {
		t.Fatalf("expected ErrInvalidHashFunc, got %v", err)
	}
}

// --- Empty/nil message ---

func TestSignNilMessage(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	sig, err := priv.SignMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(nil, sig) {
		t.Fatal("nil message verify failed")
	}
	if !pub.Verify([]byte{}, sig) {
		t.Fatal("empty message verify failed (should match nil)")
	}
}

func TestSignNilMessage_BLAKE3(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	sig, err := priv.SignMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(nil, sig) {
		t.Fatal("BLAKE3 nil message verify failed")
	}
	if !pub.Verify([]byte{}, sig) {
		t.Fatal("BLAKE3 empty message verify failed (should match nil)")
	}
}

// --- Deterministic with context ---

func TestDeterministicWithContext(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("deterministic context test")
	sig1, err := priv.SignDeterministicWithContext(msg, "ctx/v1")
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := priv.SignDeterministicWithContext(msg, "ctx/v1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("deterministic+context produced different signatures")
	}
	if !pub.VerifyWithContext(msg, sig1, "ctx/v1") {
		t.Fatal("deterministic+context verify failed")
	}
	if pub.VerifyWithContext(msg, sig1, "ctx/v2") {
		t.Fatal("wrong context should fail")
	}
}

// --- crypto.Signer with pre-hash ---

func TestCryptoSignerPreHash(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("crypto.Signer pre-hash test")
	d := sha256.Sum256(msg)
	opts := &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256, Context: "prehash/ctx"}
	sig, err := priv.Sign(nil, d[:], opts)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.VerifyPreHashWithContext(msg, sig, slhdsa.HashSHA2_256, "prehash/ctx") {
		t.Fatal("crypto.Signer pre-hash verify failed")
	}
}

// --- Corrupted signature rejection ---

func TestCorruptedSignatureRejected(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("corruption test")
	sig, err := priv.SignMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("valid sig failed")
	}

	// Flip first byte
	corrupted := make([]byte, len(sig))
	copy(corrupted, sig)
	corrupted[0] ^= 0x01
	if pub.Verify(msg, corrupted) {
		t.Fatal("corrupted signature should be rejected")
	}

	// Wrong length
	if pub.Verify(msg, sig[:len(sig)-1]) {
		t.Fatal("truncated signature should be rejected")
	}
	extended := make([]byte, len(sig)+1)
	copy(extended, sig)
	if pub.Verify(msg, extended) {
		t.Fatal("extended signature should be rejected")
	}
}

// --- Cross-param-set rejection (F397) ---

func TestCrossParamSetRejection(t *testing.T) {
	// Sign with SHA2-128f, try to verify with SHAKE-128f (same N, different hash)
	privSHA2, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer privSHA2.Destroy()

	privSHAKE, err := slhdsa.GenerateKey(slhdsa.SHAKE_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer privSHAKE.Destroy()

	msg := []byte("cross-param-set test")
	sig, err := privSHA2.SignMessage(msg)
	if err != nil {
		t.Fatal(err)
	}

	// Must fail: different key (different hash family)
	if privSHAKE.PublicKey().Verify(msg, sig) {
		t.Fatal("cross-param-set verification should fail")
	}
}

// --- Invalid param set ---

func TestNewPrivateKeyFromBytesWrongSize(t *testing.T) {
	_, err := slhdsa.NewPrivateKeyFromBytes(slhdsa.SHA2_128f, []byte{1, 2, 3})
	if err != slhdsa.ErrInvalidSecretKeySize {
		t.Fatalf("expected ErrInvalidSecretKeySize, got %v", err)
	}
}

// --- Regression vectors ---
// First test case from each ACVP keygen group.
// These are FIPS 205 constants that never change.

func TestRegressionVectors(t *testing.T) {
	vectors := []struct {
		name   string
		ps     slhdsa.ParamSet
		skSeed string
		skPrf  string
		pkSeed string
		pkRoot string
	}{
		{name: "SHA2-128s", ps: slhdsa.SHA2_128s,
			skSeed: "AC379F047FAAB2004F3AE32350AC9A3D",
			skPrf:  "829FFF0AA59E956A87F3971C4D58E710",
			pkSeed: "0566D240CC519834322EAFBCC73C79F5",
			pkRoot: "A4B84F02E8BF0CBD54017B2D3C494B57"},
		{name: "SHA2-128f", ps: slhdsa.SHA2_128f,
			skSeed: "AED6F6F5C5408BBFFA1136BC9049A701",
			skPrf:  "4D4CE0711E176A0C8A023508A692C207",
			pkSeed: "74D98D5000AF53B98F36389A1292BED3",
			pkRoot: "F4A650C56C426FCFDB88E3355459440C"},
		{name: "SHAKE-128s", ps: slhdsa.SHAKE_128s,
			skSeed: "2A2CCF3CD8F9F86E131BE654CFF6C0B4",
			skPrf:  "FDFCEB1AA2F0BA2C3C1388194F6116C7",
			pkSeed: "890CC7F4A46FE6C34D3F26A62FF962E1",
			pkRoot: "E8C88D2BDCBA6F66E50403E77FA92EFE"},
		{name: "SHAKE-128f", ps: slhdsa.SHAKE_128f,
			skSeed: "CD4A308C03D970508572C0815D7488B7",
			skPrf:  "F3FD6D2DCC7E5120FA544846AEDDED81",
			pkSeed: "BC435C3E66E4C2E4FBC09779DA5F74D4",
			pkRoot: "4EA0E0DF05C2457BCC81F59928433390"},
		{name: "SHA2-192s", ps: slhdsa.SHA2_192s,
			skSeed: "3BFAED208B7DC795BF3647F86E4B48BF9ADB8D6784C50155",
			skPrf:  "A20311739497C3FCB860EE47E09EDE036F7AE8A939155BC0",
			pkSeed: "A67856A81A6ADBCED7F1A2780CC48A06681BA5E8C7938506",
			pkRoot: "BD031BC8124F95F0BAE2BECB2A3FBBAEC453C04A6E918FFB"},
		{name: "SHA2-192f", ps: slhdsa.SHA2_192f,
			skSeed: "45D7131C727DF1CC51DB85B44E37868215DF8AEC5D1B552F",
			skPrf:  "92BC5FC8A2969FE0A522492082E994DE1DDC90FA984F847B",
			pkSeed: "8330589C20701AA9F11B473B67E1D67E1C6A2EB6C86265ED",
			pkRoot: "13A3EA895C4EEEADDE8A796BBA5233F0D86EE5CBF2A6F99C"},
		{name: "SHAKE-192s", ps: slhdsa.SHAKE_192s,
			skSeed: "915173EE0D17F30877E1D463E3DEC914E71F436867AD7615",
			skPrf:  "ED782E7033C4963A7FF0B67181DE0F0EA7EFABB326D40A86",
			pkSeed: "520660F654D537DA6934F96E5EE01B24A2F36102F68DCD10",
			pkRoot: "AA206FC79803E63850DA5E86969569FC8FB021B6C40616E2"},
		{name: "SHAKE-192f", ps: slhdsa.SHAKE_192f,
			skSeed: "855000FDFFFBA76962809C69432452F3DC79428F662C59B1",
			skPrf:  "43B1FC381C300B5ECEC7571B5DE2FCA16737E4C14911F683",
			pkSeed: "124623BA6CA1BC1B0E1A303099E2A608B0AC41715BC788A1",
			pkRoot: "9873C783378F935794ABC0313243EFC3F4A10A619CB1B1FE"},
		{name: "SHA2-256s", ps: slhdsa.SHA2_256s,
			skSeed: "2FBEAB9A6A80FD817E7EFCDF834EFBD4F0A36195D7598408A6A151E93DE6A557",
			skPrf:  "5D0B37D1ECBC68265B0AFEECBBA783DD27EAFDBDF3143E4AF3E5057FD5C2DADA",
			pkSeed: "1322F94917AE67D0DB420203178D591283C08BE8A1385A16CE70CD9FBAFD2AC6",
			pkRoot: "40041EAB68A4A653F89CAB7585F6B410603326DBBAAF733E7E72CB6097A4A452"},
		{name: "SHA2-256f", ps: slhdsa.SHA2_256f,
			skSeed: "B8ABC485122BE003CF36D677BEE7F47EA1017C39D96D0C56A87A7ADAD24F731A",
			skPrf:  "9222684FFACF803D44CB98222C44B3C519698B798D8F7A759FE2FA6EF173CF64",
			pkSeed: "0D50E82BEDB42E03CC967E7FD24C12777855A946FD49471184330F096A75B561",
			pkRoot: "7FB65FBD08D05F24F20CB3875E28FAC4A52A2513C7EF447B8E9328632A684CF7"},
		{name: "SHAKE-256s", ps: slhdsa.SHAKE_256s,
			skSeed: "7D88445A7B0022F12E9E2D74755431505FF6DB1C38A8CE44864D34CFF1A12CE0",
			skPrf:  "FF2CD133AD00728EB29DD0CE881C41C640F2E28861555B59D4E0BAA0447BB542",
			pkSeed: "87A133B92EB6C81771AE002819B4C0300FA63CD7181C805096BFB16067F52A45",
			pkRoot: "CC785237C24D9235B6BC3194B79E5A9F953388EA745D7CFB87826A94E5B271D5"},
		{name: "SHAKE-256f", ps: slhdsa.SHAKE_256f,
			skSeed: "3DE4B54A5F5FB98D6638FB3D8899355CC3582E8A397D0990CAD032D78EE9E199",
			skPrf:  "DA7F71D21D0182A99DE34E2796FE5DDE046D9C9E961DCE24C2562728BE7D9632",
			pkSeed: "B3EF3825A515E0B2E4164DB7EC805B4CF1C7A2DE6E63D7DF359B99B1F3063F25",
			pkRoot: "AEC38FF53C46AAD930166957CA0DB5C5466D0CBE9A11970987A230EBBB5450A4"},
		// BLAKE3 (PQC Suite B vectors)
		{name: "BLAKE3-128f", ps: slhdsa.BLAKE3_128f,
			skSeed: "163FDE32A1FD975478E45A17D4FEFE52",
			skPrf:  "ABF34218E3B4BB9A986B7BAB6B6A05B6",
			pkSeed: "5F8CA12CCDED72F25353C832CF51A72B",
			pkRoot: "CE2FBFC032752EE846169DC528108270"},
		{name: "BLAKE3-128s", ps: slhdsa.BLAKE3_128s,
			skSeed: "A910B1F27A2CE155BB50E6A0631495AE",
			skPrf:  "8AF004E2979B707466229F05EBFC9569",
			pkSeed: "DF19136B3AD7D2587D3AD6F04473FB27",
			pkRoot: "569DE582201522D312B21E0DC8D291BD"},
		{name: "BLAKE3-192f", ps: slhdsa.BLAKE3_192f,
			skSeed: "0746C6203827ACBE57CC716AFBB2AC8FBB747BFFF3055CAA",
			skPrf:  "AABEA3E8C61323E46629002863482DD13E916DBB373D2B2C",
			pkSeed: "0EB283F3C51237A9FB7F96CDA19E1A76B5D286208CA8CB45",
			pkRoot: "0B041DF3B91B598FF49FE48DFC957FA57205F31EFE0932CB"},
		{name: "BLAKE3-192s", ps: slhdsa.BLAKE3_192s,
			skSeed: "30231D5C2574218DBCD8E4F12A509DA9A7E74E0AE38C461E",
			skPrf:  "261CB7075E525525C0FFD82FEE430FBBA57D7925E3C5E16B",
			pkSeed: "4DBB201406B97B18FF98464EE19C427EAB9136BA3A31DFD6",
			pkRoot: "7423EC67BDA34E36C762D22FE95D9147935EAD3FDB8165CA"},
		{name: "BLAKE3-256f", ps: slhdsa.BLAKE3_256f,
			skSeed: "8D36BA0F84B323995050F3386745904F7C2560AEF77677908233BF4722895D11",
			skPrf:  "278462B8D83C0C30102407F372119326E0305E33BE8365DEBBF668E5EB3428F9",
			pkSeed: "50B4335814AF78691251EA43377AB7C06CA73CCC293F42149869D2DEB562AE24",
			pkRoot: "FBC4D9070B6A12DAF9848695EC796D836ACDAD9DB0AAFF3B860D0F80CC4DB53A"},
		{name: "BLAKE3-256s", ps: slhdsa.BLAKE3_256s,
			skSeed: "DFEFC733F82A4A891A4094F84B2AD7A091784BB0225B0C331D8AF6D9C73A937A",
			skPrf:  "A5F226DDABE8BCD9C74D4445BB211808F57620AB56BCE0760F817674A1AC29F1",
			pkSeed: "40514B6E6D4CBF174DD3E0E3B2F01811588F5E3F1D141E5E5410C1C9814BDC3E",
			pkRoot: "54823335D579B2AC80699C11D70548B6B9820A621B351C6C780DAC91A6997372"},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			params := slhdsa.InternalParamsForTest(v.ps)
			skseed := mustHex(t, v.skSeed)
			skprf := mustHex(t, v.skPrf)
			pkseed := mustHex(t, v.pkSeed)
			expectedRoot := mustHex(t, v.pkRoot)

			_, pk := slhdsa.InternalSLHKeygenInternal(params, skseed, skprf, pkseed)
			pkBytes := pk.Bytes()
			n := int(v.ps.N())
			gotRoot := pkBytes[n:]

			if !bytes.Equal(gotRoot, expectedRoot) {
				t.Errorf("pkRoot mismatch\ngot:  %X\nwant: %X", gotRoot, expectedRoot)
			}
		})
	}
}

// --- Benchmarks ---

func BenchmarkSign_SHA2_128f(b *testing.B) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Destroy()
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.SignMessage(msg)
	}
}

func BenchmarkVerify_SHA2_128f(b *testing.B) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()
	msg := []byte("benchmark message")
	sig, _ := priv.SignMessage(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.Verify(msg, sig)
	}
}

func BenchmarkSign_BLAKE3_128f(b *testing.B) {
	priv, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Destroy()
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.SignMessage(msg)
	}
}

func BenchmarkVerify_BLAKE3_128f(b *testing.B) {
	priv, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err != nil {
		b.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()
	msg := []byte("benchmark message")
	sig, _ := priv.SignMessage(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.Verify(msg, sig)
	}
}

// --- crypto.Signer hardening: honor rand + digest-as-prehash + validation + HashFunc truth ---

// TestCryptoSignerHonorsRand verifies a non-nil rand is honored
// (deterministic reproducibility), nil falls back to crypto/rand, and an
// erroring reader fails closed with the error reachable via errors.Is.
func TestCryptoSignerHonorsRand(t *testing.T) {
	// Table-driven across N in {16,24,32} and both hash families so the
	// N-dependent addrnd path (signMPrime: addrnd = make([]byte, params.N)) is
	// exercised on every size, not just N=16.
	for _, ps := range []slhdsa.ParamSet{slhdsa.SHA2_128f, slhdsa.SHA2_192f, slhdsa.SHAKE_256f} {
		ps := ps
		t.Run(ps.String(), func(t *testing.T) {
			priv, err := slhdsa.GenerateKey(ps)
			if err != nil {
				t.Fatal(err)
			}
			defer priv.Destroy()
			pub := priv.PublicKey()
			msg := []byte("rand honoring test")
			n := int(ps.N())

			// Deterministic reader of EXACTLY n bytes (nil error on the fill) ->
			// reproducible signature.
			seed := bytes.Repeat([]byte{0x5A}, n)
			s1, err := priv.Sign(bytes.NewReader(seed), msg, nil)
			if err != nil {
				t.Fatalf("Sign(det 1): %v", err)
			}
			s2, err := priv.Sign(bytes.NewReader(seed), msg, nil)
			if err != nil {
				t.Fatalf("Sign(det 2): %v", err)
			}
			if !bytes.Equal(s1, s2) {
				t.Fatal("same deterministic rand must produce the same signature")
			}
			if !pub.Verify(msg, s1) {
				t.Fatal("deterministic-rand signature failed verification")
			}

			// The FULL n-byte addrnd is consumed: flipping the LAST seed byte
			// must change the signature. Catches a bug that sized addrnd to a
			// hardcoded length instead of params.N.
			seed2 := bytes.Repeat([]byte{0x5A}, n)
			seed2[n-1] ^= 0xFF
			s3, err := priv.Sign(bytes.NewReader(seed2), msg, nil)
			if err != nil {
				t.Fatalf("Sign(det flipped): %v", err)
			}
			if bytes.Equal(s1, s3) {
				t.Fatal("changing the last addrnd byte must change the signature (addrnd must be exactly params.N bytes)")
			}

			// nil rand -> crypto/rand: verifies.
			s4, err := priv.Sign(nil, msg, nil)
			if err != nil {
				t.Fatalf("Sign(nil rand): %v", err)
			}
			if !pub.Verify(msg, s4) {
				t.Fatal("nil-rand (crypto/rand) signature failed verification")
			}

			// Always-erroring reader -> fail-closed; error reachable via errors.Is.
			if _, err := priv.Sign(&errReader{err: errSentinel}, msg, nil); !errors.Is(err, errSentinel) {
				t.Fatalf("erroring reader must fail closed via errors.Is: got %v", err)
			}

			// Short reader (n-1 bytes then EOF) -> fail-closed via io.EOF. This is
			// the exact case io.ReadFull would mishandle and the reason this
			// package routes addrnd through entropy.Fill (slhdsa.go GenerateKey).
			if _, err := priv.Sign(bytes.NewReader(make([]byte, n-1)), msg, nil); !errors.Is(err, io.EOF) {
				t.Fatalf("short reader must fail closed via io.EOF: got %v", err)
			}
		})
	}
}

// TestCryptoSignerDigestValidation verifies the digest-as-PH branch
// rejects a wrong-length digest with ErrInvalidDigestLength and accepts the
// exact length.
func TestCryptoSignerDigestValidation(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	for _, badLen := range []int{0, 16, 31, 33, 64} {
		_, err := priv.Sign(nil, make([]byte, badLen), &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256})
		if !errors.Is(err, slhdsa.ErrInvalidDigestLength) {
			t.Errorf("digest len %d: got %v, want ErrInvalidDigestLength", badLen, err)
		}
	}
	if _, err := priv.Sign(nil, make([]byte, 32), &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256}); err != nil {
		t.Fatalf("correct-length (32) digest must be accepted: %v", err)
	}
}

// TestCryptoSignerErrorPrecedence pins the guard order in the digest-as-PH path
// ErrDestroyed > ErrContextTooLong > ErrPreHashNotSupported(BLAKE3) >
// ErrInvalidHashFunc > ErrInvalidDigestLength.
func TestCryptoSignerErrorPrecedence(t *testing.T) {
	longCtx := string(make([]byte, 256))

	dead, _ := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	dead.Destroy()
	if _, err := dead.Sign(nil, make([]byte, 5), &slhdsa.SignerOpts{Hash: slhdsa.HashFunc(99), Context: longCtx}); err != slhdsa.ErrDestroyed {
		t.Fatalf("destroyed: want ErrDestroyed, got %v", err)
	}

	live, _ := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	defer live.Destroy()
	if _, err := live.Sign(nil, make([]byte, 5), &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256, Context: longCtx}); err != slhdsa.ErrContextTooLong {
		t.Fatalf("long ctx: want ErrContextTooLong, got %v", err)
	}

	b3, _ := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	defer b3.Destroy()
	if _, err := b3.Sign(nil, make([]byte, 5), &slhdsa.SignerOpts{Hash: slhdsa.HashFunc(99)}); err != slhdsa.ErrPreHashNotSupported {
		t.Fatalf("BLAKE3 pre-hash: want ErrPreHashNotSupported, got %v", err)
	}

	if _, err := live.Sign(nil, make([]byte, 5), &slhdsa.SignerOpts{Hash: slhdsa.HashFunc(99)}); err != slhdsa.ErrInvalidHashFunc {
		t.Fatalf("invalid hashfunc: want ErrInvalidHashFunc, got %v", err)
	}
}

// TestCryptoSignerSHAKEPreHash proves SHAKE pre-hash WORKS via *SignerOpts:
// there is no crypto.Hash for SHAKE, but Sign reads SignerOpts.Hash
// directly, so a SHAKE digest-as-PH signs and verifies.
func TestCryptoSignerSHAKEPreHash(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("shake pre-hash via SignerOpts")
	h := sha3.NewShake128()
	h.Write(msg)
	d := make([]byte, 32) // SHAKE-128 fixed pre-hash length (FIPS 205 9.2)
	if _, err := io.ReadFull(h, d); err != nil {
		t.Fatal(err)
	}
	sig, err := priv.Sign(nil, d, &slhdsa.SignerOpts{Hash: slhdsa.HashSHAKE128})
	if err != nil {
		t.Fatalf("SHAKE128 digest-as-PH sign: %v", err)
	}
	if !pub.VerifyPreHash(msg, sig, slhdsa.HashSHAKE128) {
		t.Fatal("SHAKE128 pre-hash signature failed verification")
	}
}

// TestSignerOptsHashFunc verifies HashFunc() returns the truthful
// crypto.Hash for SHA2/SHA3 and 0 for SHAKE (no stdlib constant).
func TestSignerOptsHashFunc(t *testing.T) {
	cases := []struct {
		hf   slhdsa.HashFunc
		want crypto.Hash
	}{
		{slhdsa.HashSHA2_224, crypto.SHA224},
		{slhdsa.HashSHA2_256, crypto.SHA256},
		{slhdsa.HashSHA2_384, crypto.SHA384},
		{slhdsa.HashSHA2_512, crypto.SHA512},
		{slhdsa.HashSHA2_512224, crypto.SHA512_224},
		{slhdsa.HashSHA2_512256, crypto.SHA512_256},
		{slhdsa.HashSHA3_224, crypto.SHA3_224},
		{slhdsa.HashSHA3_256, crypto.SHA3_256},
		{slhdsa.HashSHA3_384, crypto.SHA3_384},
		{slhdsa.HashSHA3_512, crypto.SHA3_512},
		{slhdsa.HashSHAKE128, 0},
		{slhdsa.HashSHAKE256, 0},
	}
	for _, c := range cases {
		if got := (&slhdsa.SignerOpts{Hash: c.hf}).HashFunc(); got != c.want {
			t.Errorf("HashFunc(hf=%d): got %d, want %d", c.hf, got, c.want)
		}
	}
	var nilOpts *slhdsa.SignerOpts
	if nilOpts.HashFunc() != 0 {
		t.Error("nil SignerOpts.HashFunc() must be 0")
	}
}

// TestDigestAsPHAssemblyOracle breaks the shared-assembler circularity:
// the digest-path M' assembly equals the canonical full-message assembly when
// digest == hash(msg), and the canonical M' prefix is pinned byte-for-byte.
func TestDigestAsPHAssemblyOracle(t *testing.T) {
	msg := []byte("assembly oracle")
	ctx := "v1"
	d := sha256.Sum256(msg)

	got := slhdsa.AssembleMPrimePreHashForTest(d[:], slhdsa.HashSHA2_256, ctx)
	want := slhdsa.MakeMPrimePreHashForTest(msg, slhdsa.HashSHA2_256, ctx)
	if !bytes.Equal(got, want) {
		t.Fatalf("digest-path M' != canonical M'\n got:  %x\n want: %x", got, want)
	}

	// Frozen pin: 0x01 | ctxLen=0x02 | "v1" | OID(SHA-256, 11 bytes), then 32-byte PH.
	wantPrefix := mustHex(t, "010276310609608648016503040201")
	if !bytes.HasPrefix(want, wantPrefix) {
		t.Fatalf("canonical M' prefix mismatch:\n got:        %x\n want prefix: %x", want, wantPrefix)
	}
	if len(want) != len(wantPrefix)+32 {
		t.Fatalf("M' length: got %d, want %d", len(want), len(wantPrefix)+32)
	}
}

// TestCryptoSignerConcurrentSharedReader covers the documented concurrent path:
// crypto/rand.Reader (the realistic shared reader) is concurrency-safe, so
// sharing it across concurrent Sign calls must be race-clean. Run under -race.
func TestCryptoSignerConcurrentSharedReader(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()
	msg := []byte("concurrent shared reader")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := priv.Sign(cryptorand.Reader, msg, nil)
			if err != nil {
				t.Errorf("concurrent Sign(crypto/rand): %v", err)
				return
			}
			if !pub.Verify(msg, sig) {
				t.Error("concurrent shared-reader signature failed verification")
			}
		}()
	}
	wg.Wait()
}

// TestNamedVsDigestPreHashEquivalence proves the named pre-hash entry point and
// the crypto.Signer digest-as-PH entry point are the same function of
// (msg, hf, ctx): both verify under the same VerifyPreHashWithContext (same M'),
// and both bind the context. (Byte-identity is established transitively by
// TestDigestAsPHAssemblyOracle, since the named path has no rand injection.)
func TestNamedVsDigestPreHashEquivalence(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	pub := priv.PublicKey()

	msg := []byte("named vs digest equivalence")
	ctx := "v1"
	d := sha256.Sum256(msg)

	sigNamed, err := priv.SignPreHashWithContext(msg, slhdsa.HashSHA2_256, ctx)
	if err != nil {
		t.Fatalf("named SignPreHashWithContext: %v", err)
	}
	sigDigest, err := priv.Sign(nil, d[:], &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256, Context: ctx})
	if err != nil {
		t.Fatalf("digest path Sign: %v", err)
	}

	if !pub.VerifyPreHashWithContext(msg, sigNamed, slhdsa.HashSHA2_256, ctx) {
		t.Fatal("named-path signature failed verification")
	}
	if !pub.VerifyPreHashWithContext(msg, sigDigest, slhdsa.HashSHA2_256, ctx) {
		t.Fatal("digest-path signature failed verification (named and digest paths must agree on M')")
	}
	// Both paths must BIND the context: a wrong ctx fails for the digest path.
	if pub.VerifyPreHashWithContext(msg, sigDigest, slhdsa.HashSHA2_256, "wrong") {
		t.Fatal("digest path must bind the context")
	}
}

// TestCryptoSignerBranchParity proves the two Sign input branches - a foreign
// crypto.Hash opts (generic consumer) and a *SignerOpts (native) - produce
// byte-identical signatures for the same logical hash across ALL 10 mapped
// SHA2/SHA3 functions, given the same deterministic addrnd.
func TestCryptoSignerBranchParity(t *testing.T) {
	priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	n := int(priv.ParamSet().N())

	cases := []struct {
		ch crypto.Hash
		hf slhdsa.HashFunc
		dl int
	}{
		{crypto.SHA224, slhdsa.HashSHA2_224, 28},
		{crypto.SHA256, slhdsa.HashSHA2_256, 32},
		{crypto.SHA384, slhdsa.HashSHA2_384, 48},
		{crypto.SHA512, slhdsa.HashSHA2_512, 64},
		{crypto.SHA512_224, slhdsa.HashSHA2_512224, 28},
		{crypto.SHA512_256, slhdsa.HashSHA2_512256, 32},
		{crypto.SHA3_224, slhdsa.HashSHA3_224, 28},
		{crypto.SHA3_256, slhdsa.HashSHA3_256, 32},
		{crypto.SHA3_384, slhdsa.HashSHA3_384, 48},
		{crypto.SHA3_512, slhdsa.HashSHA3_512, 64},
	}
	for _, c := range cases {
		digest := bytes.Repeat([]byte{0x77}, c.dl)
		sigGeneric, err := priv.Sign(bytes.NewReader(bytes.Repeat([]byte{0x01}, n)), digest, c.ch)
		if err != nil {
			t.Fatalf("%v generic branch: %v", c.ch, err)
		}
		sigNative, err := priv.Sign(bytes.NewReader(bytes.Repeat([]byte{0x01}, n)), digest, &slhdsa.SignerOpts{Hash: c.hf})
		if err != nil {
			t.Fatalf("%v native branch: %v", c.ch, err)
		}
		if !bytes.Equal(sigGeneric, sigNative) {
			t.Errorf("%v: generic crypto.Hash branch != *SignerOpts branch", c.ch)
		}
	}
}
