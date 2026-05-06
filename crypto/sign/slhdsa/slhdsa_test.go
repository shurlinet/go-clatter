package slhdsa_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/shurlinet/go-clatter/crypto/sign/slhdsa"
)

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
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte", []byte{1}},
		{"wrong version", []byte{2, 0, 0, 0}},
		{"wrong paramset", []byte{1, 255}},
		{"wrong length", []byte{1, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := slhdsa.ParsePublicKey(tc.data)
			if err == nil {
				t.Fatal("expected error")
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

	// Foreign opts with crypto.SHA256 must correctly map to HashSHA2_256
	sig, err := priv.Sign(nil, msg, crypto.SHA256)
	if err != nil {
		t.Fatalf("foreign opts SHA256: %v", err)
	}
	if !pub.VerifyPreHash(msg, sig, slhdsa.HashSHA2_256) {
		t.Fatal("foreign opts SHA256 verify failed")
	}

	// Foreign opts with unsupported hash must return error
	_, err = priv.Sign(nil, msg, crypto.MD5)
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
	// BLAKE3 param sets are not runtime-ready yet, so GenerateKey fails.
	// Test that runtimeReady rejects them.
	_, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
	if err == nil {
		t.Fatal("BLAKE3 should not be runtime-ready")
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
	opts := &slhdsa.SignerOpts{Hash: slhdsa.HashSHA2_256, Context: "prehash/ctx"}
	sig, err := priv.Sign(nil, msg, opts)
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
