package vectors_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
)

// vectorFile matches the JSON structure of cacophony.txt and snow.txt.
type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	ProtocolName    string    `json:"protocol_name"`
	InitPrologue    hexBytes  `json:"init_prologue"`
	InitEphemeral   hexBytes  `json:"init_ephemeral"`
	InitStatic      *hexBytes `json:"init_static"`
	InitRemoteStatic *hexBytes `json:"init_remote_static"`
	InitPSKs        []hexBytes `json:"init_psks"`
	RespPrologue    hexBytes  `json:"resp_prologue"`
	RespEphemeral   *hexBytes `json:"resp_ephemeral"`
	RespStatic      *hexBytes `json:"resp_static"`
	RespRemoteStatic *hexBytes `json:"resp_remote_static"`
	RespPSKs        []hexBytes `json:"resp_psks"`
	HandshakeHash   *hexBytes `json:"handshake_hash"`
	Messages        []message `json:"messages"`
}

type message struct {
	Payload    hexBytes `json:"payload"`
	Ciphertext hexBytes `json:"ciphertext"`
}

// hexBytes is a byte slice that deserializes from hex strings.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = []byte{}
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// patternMap maps pattern name substrings to go-clatter pattern pointers.
var patternMap = map[string]*clatter.HandshakePattern{
	"N":       clatter.PatternN,
	"K":       clatter.PatternK,
	"X":       clatter.PatternX,
	"NN":      clatter.PatternNN,
	"NK":      clatter.PatternNK,
	"NX":      clatter.PatternNX,
	"KN":      clatter.PatternKN,
	"KK":      clatter.PatternKK,
	"KX":      clatter.PatternKX,
	"XN":      clatter.PatternXN,
	"XK":      clatter.PatternXK,
	"XX":      clatter.PatternXX,
	"IN":      clatter.PatternIN,
	"IK":      clatter.PatternIK,
	"IX":      clatter.PatternIX,
	"NNpsk0":  clatter.PatternNNpsk0,
	"NNpsk2":  clatter.PatternNNpsk2,
	"NKpsk0":  clatter.PatternNKpsk0,
	"NKpsk2":  clatter.PatternNKpsk2,
	"NXpsk2":  clatter.PatternNXpsk2,
	"KNpsk0":  clatter.PatternKNpsk0,
	"KNpsk2":  clatter.PatternKNpsk2,
	"KKpsk0":  clatter.PatternKKpsk0,
	"KKpsk2":  clatter.PatternKKpsk2,
	"KXpsk2":  clatter.PatternKXpsk2,
	"XNpsk3":  clatter.PatternXNpsk3,
	"XKpsk3":  clatter.PatternXKpsk3,
	"XXpsk3":  clatter.PatternXXpsk3,
	"INpsk1":  clatter.PatternINpsk1,
	"INpsk2":  clatter.PatternINpsk2,
	"IKpsk1":  clatter.PatternIKpsk1,
	"IKpsk2":  clatter.PatternIKpsk2,
	"IXpsk2":  clatter.PatternIXpsk2,
	"Npsk0":   clatter.PatternNpsk0,
	"Kpsk0":   clatter.PatternKpsk0,
	"Xpsk1":   clatter.PatternXpsk1,
}

// parseProtocolName splits "Noise_{pattern}_{dh}_{cipher}_{hash}" into components.
func parseProtocolName(name string) (patternName, dhName, cipherName, hashName string, ok bool) {
	parts := strings.SplitN(name, "_", 5)
	if len(parts) != 5 || parts[0] != "Noise" {
		return "", "", "", "", false
	}
	return parts[1], parts[2], parts[3], parts[4], true
}

// lookupPattern returns the go-clatter pattern for a name, or nil if unsupported.
func lookupPattern(name string) *clatter.HandshakePattern {
	return patternMap[name]
}

// lookupCipher returns the go-clatter cipher for a name, or nil if unsupported.
func lookupCipher(name string) clatter.Cipher {
	switch name {
	case "ChaChaPoly":
		return cipher.NewChaChaPoly()
	case "AESGCM":
		return cipher.NewAesGcm()
	default:
		return nil
	}
}

// lookupHash returns the go-clatter hash for a name, or nil if unsupported.
func lookupHash(name string) clatter.HashFunc {
	switch name {
	case "SHA256":
		return hash.NewSha256()
	case "SHA512":
		return hash.NewSha512()
	case "BLAKE2s":
		return hash.NewBlake2s()
	case "BLAKE2b":
		return hash.NewBlake2b()
	default:
		return nil
	}
}

// makeKeyPairFromSecret constructs a KeyPair from a DH secret key by computing the public key.
func makeKeyPairFromSecret(dhAlg clatter.DH, secret []byte) (clatter.KeyPair, error) {
	// X25519: use ecdh to derive public from private
	rng := &sliceReader{data: secret}
	return dhAlg.GenerateKeypair(rng)
}

// sliceReader is a one-shot RNG that returns pre-set bytes.
type sliceReader struct {
	data []byte
	off  int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	n := copy(p, r.data[r.off:])
	r.off += n
	if n < len(p) {
		return n, fmt.Errorf("sliceReader exhausted")
	}
	return n, nil
}

// verifyVector runs a single test vector and returns true if verified, false if skipped.
func verifyVector(t *testing.T, v *vector) bool {
	t.Helper()

	patName, dhName, cipherName, hashName, ok := parseProtocolName(v.ProtocolName)
	if !ok {
		return false
	}

	// Skip Curve448 (no Go implementation, same as Rust)
	if dhName == "448" {
		return false
	}
	// Only support 25519
	if dhName != "25519" {
		return false
	}

	pattern := lookupPattern(patName)
	if pattern == nil {
		return false // deferred/fallback/unsupported pattern
	}

	c := lookupCipher(cipherName)
	if c == nil {
		return false
	}
	h := lookupHash(hashName)
	if h == nil {
		return false
	}

	x := dh.NewX25519()
	suite := clatter.CipherSuite{
		DH:     x,
		Cipher: c,
		Hash:   h,
	}

	// Build alice (initiator) options
	aliceOpts := []clatter.Option{
		clatter.WithPrologue(v.InitPrologue),
	}

	// Ephemeral key - always present for initiator
	aliceEph, err := makeKeyPairFromSecret(x, v.InitEphemeral)
	if err != nil {
		t.Fatalf("%s: alice ephemeral: %v", v.ProtocolName, err)
	}
	aliceOpts = append(aliceOpts, clatter.WithEphemeralKey(aliceEph))

	if v.InitStatic != nil {
		aliceS, err := makeKeyPairFromSecret(x, *v.InitStatic)
		if err != nil {
			t.Fatalf("%s: alice static: %v", v.ProtocolName, err)
		}
		aliceOpts = append(aliceOpts, clatter.WithStaticKey(aliceS))
	}
	if v.InitRemoteStatic != nil {
		aliceOpts = append(aliceOpts, clatter.WithRemoteStatic(*v.InitRemoteStatic))
	}

	// Build bob (responder) options
	bobOpts := []clatter.Option{
		clatter.WithPrologue(v.RespPrologue),
	}

	if v.RespEphemeral != nil {
		bobEph, err := makeKeyPairFromSecret(x, *v.RespEphemeral)
		if err != nil {
			t.Fatalf("%s: bob ephemeral: %v", v.ProtocolName, err)
		}
		bobOpts = append(bobOpts, clatter.WithEphemeralKey(bobEph))
	}
	if v.RespStatic != nil {
		bobS, err := makeKeyPairFromSecret(x, *v.RespStatic)
		if err != nil {
			t.Fatalf("%s: bob static: %v", v.ProtocolName, err)
		}
		bobOpts = append(bobOpts, clatter.WithStaticKey(bobS))
	}
	if v.RespRemoteStatic != nil {
		bobOpts = append(bobOpts, clatter.WithRemoteStatic(*v.RespRemoteStatic))
	}

	alice, err := clatter.NewNqHandshake(pattern, true, suite, aliceOpts...)
	if err != nil {
		t.Fatalf("%s: alice init: %v", v.ProtocolName, err)
	}

	bob, err := clatter.NewNqHandshake(pattern, false, suite, bobOpts...)
	if err != nil {
		t.Fatalf("%s: bob init: %v", v.ProtocolName, err)
	}

	// Push PSKs
	for _, psk := range v.InitPSKs {
		if err := alice.PushPSK(psk); err != nil {
			t.Fatalf("%s: alice PSK: %v", v.ProtocolName, err)
		}
	}
	for _, psk := range v.RespPSKs {
		if err := bob.PushPSK(psk); err != nil {
			t.Fatalf("%s: bob PSK: %v", v.ProtocolName, err)
		}
	}

	sendBuf := make([]byte, 65535)
	recvBuf := make([]byte, 65535)

	initiatorsTurn := true
	handshakeDone := false
	var aliceTransport, bobTransport *clatter.TransportState

	for i, m := range v.Messages {
		if !handshakeDone {
			var sender, receiver clatter.Handshaker
			if initiatorsTurn {
				sender, receiver = alice, bob
			} else {
				sender, receiver = bob, alice
			}

			if !sender.IsWriteTurn() {
				t.Fatalf("%s msg %d: sender not in write turn", v.ProtocolName, i)
			}

			// Verify overhead
			overhead, err := sender.GetNextMessageOverhead()
			if err != nil {
				t.Fatalf("%s msg %d: overhead: %v", v.ProtocolName, i, err)
			}
			expectedLen := len(m.Payload) + overhead
			if expectedLen != len(m.Ciphertext) {
				t.Fatalf("%s msg %d: overhead mismatch: payload(%d)+overhead(%d)=%d != ciphertext(%d)",
					v.ProtocolName, i, len(m.Payload), overhead, expectedLen, len(m.Ciphertext))
			}

			// Write and verify ciphertext
			n, err := sender.WriteMessage(m.Payload, sendBuf)
			if err != nil {
				t.Fatalf("%s msg %d: write: %v", v.ProtocolName, i, err)
			}
			if n != len(m.Ciphertext) {
				t.Fatalf("%s msg %d: write len %d != expected %d", v.ProtocolName, i, n, len(m.Ciphertext))
			}
			if !bytes.Equal(sendBuf[:n], m.Ciphertext) {
				t.Fatalf("%s msg %d: ciphertext mismatch\n  got:  %x\n  want: %x",
					v.ProtocolName, i, sendBuf[:n], []byte(m.Ciphertext))
			}

			// Receive and verify payload
			n, err = receiver.ReadMessage(sendBuf[:n], recvBuf)
			if err != nil {
				t.Fatalf("%s msg %d: read: %v", v.ProtocolName, i, err)
			}
			if !bytes.Equal(recvBuf[:n], m.Payload) {
				t.Fatalf("%s msg %d: payload mismatch", v.ProtocolName, i)
			}

			if sender.IsFinished() {
				if !receiver.IsFinished() {
					t.Fatalf("%s msg %d: sender finished but receiver not", v.ProtocolName, i)
				}

				aliceTransport, err = alice.Finalize()
				if err != nil {
					t.Fatalf("%s: alice finalize: %v", v.ProtocolName, err)
				}
				bobTransport, err = bob.Finalize()
				if err != nil {
					t.Fatalf("%s: bob finalize: %v", v.ProtocolName, err)
				}

				// Verify handshake hash
				hi := aliceTransport.GetHandshakeHash()
				hr := bobTransport.GetHandshakeHash()
				if !bytes.Equal(hi, hr) {
					t.Fatalf("%s: handshake hash mismatch between peers", v.ProtocolName)
				}
				if v.HandshakeHash != nil {
					if !bytes.Equal(hi, *v.HandshakeHash) {
						t.Fatalf("%s: handshake hash mismatch with vector\n  got:  %x\n  want: %x",
							v.ProtocolName, hi, []byte(*v.HandshakeHash))
					}
				}

				handshakeDone = true
			}
		} else {
			// Transport messages
			if initiatorsTurn {
				n, err := aliceTransport.Send(m.Payload, sendBuf)
				if err != nil {
					t.Fatalf("%s msg %d: transport send: %v", v.ProtocolName, i, err)
				}
				if !bytes.Equal(sendBuf[:n], m.Ciphertext) {
					t.Fatalf("%s msg %d: transport ciphertext mismatch", v.ProtocolName, i)
				}
				n, err = bobTransport.Receive(sendBuf[:n], recvBuf)
				if err != nil {
					t.Fatalf("%s msg %d: transport receive: %v", v.ProtocolName, i, err)
				}
				if !bytes.Equal(recvBuf[:n], m.Payload) {
					t.Fatalf("%s msg %d: transport payload mismatch", v.ProtocolName, i)
				}
			} else {
				n, err := bobTransport.Send(m.Payload, sendBuf)
				if err != nil {
					t.Fatalf("%s msg %d: transport send: %v", v.ProtocolName, i, err)
				}
				if !bytes.Equal(sendBuf[:n], m.Ciphertext) {
					t.Fatalf("%s msg %d: transport ciphertext mismatch", v.ProtocolName, i)
				}
				n, err = aliceTransport.Receive(sendBuf[:n], recvBuf)
				if err != nil {
					t.Fatalf("%s msg %d: transport receive: %v", v.ProtocolName, i, err)
				}
				if !bytes.Equal(recvBuf[:n], m.Payload) {
					t.Fatalf("%s msg %d: transport payload mismatch", v.ProtocolName, i)
				}
			}
		}

		if !pattern.IsOneWay() {
			initiatorsTurn = !initiatorsTurn
		}
	}

	// Cleanup
	if aliceTransport != nil {
		aliceTransport.Destroy()
	}
	if bobTransport != nil {
		bobTransport.Destroy()
	}

	return true
}

func TestCacophonyVectors(t *testing.T) {
	data, err := os.ReadFile("cacophony.txt")
	if err != nil {
		t.Fatalf("read cacophony.txt: %v", err)
	}

	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse cacophony.txt: %v", err)
	}

	completed, skipped := 0, 0
	for _, v := range vf.Vectors {
		v := v
		if verifyVector(t, &v) {
			completed++
		} else {
			skipped++
		}
	}

	t.Logf("Cacophony vectors: %d completed, %d skipped (total %d)",
		completed, skipped, len(vf.Vectors))

	if completed == 0 {
		t.Fatal("no cacophony vectors completed")
	}
}

func TestSnowVectors(t *testing.T) {
	data, err := os.ReadFile("snow.txt")
	if err != nil {
		t.Fatalf("read snow.txt: %v", err)
	}

	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse snow.txt: %v", err)
	}

	completed, skipped := 0, 0
	for _, v := range vf.Vectors {
		v := v
		if verifyVector(t, &v) {
			completed++
		} else {
			skipped++
		}
	}

	t.Logf("Snow vectors: %d completed, %d skipped (total %d)",
		completed, skipped, len(vf.Vectors))

	if completed == 0 {
		t.Fatal("no snow vectors completed")
	}
}
