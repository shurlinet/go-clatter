package clatter_test

import (
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/dh"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// PSKs matching Rust smoke.rs: [0;32], [1;32], [2;32], [3;32]
var smokePSKs [4][32]byte

func init() {
	for i := 0; i < 32; i++ {
		smokePSKs[0][i] = 0
		smokePSKs[1][i] = 1
		smokePSKs[2][i] = 2
		smokePSKs[3][i] = 3
	}
}

// nqPatterns returns all 36 NQ patterns (matching Rust lib.rs).
func nqPatterns() []*clatter.HandshakePattern {
	return []*clatter.HandshakePattern{
		clatter.PatternN, clatter.PatternK, clatter.PatternX,
		clatter.PatternNN, clatter.PatternNK, clatter.PatternNX,
		clatter.PatternKN, clatter.PatternKK, clatter.PatternKX,
		clatter.PatternXN, clatter.PatternXK, clatter.PatternXX,
		clatter.PatternIN, clatter.PatternIK, clatter.PatternIX,
		clatter.PatternNpsk0, clatter.PatternKpsk0, clatter.PatternXpsk1,
		clatter.PatternNNpsk0, clatter.PatternNNpsk2,
		clatter.PatternNKpsk0, clatter.PatternNKpsk2,
		clatter.PatternNXpsk2,
		clatter.PatternKNpsk0, clatter.PatternKNpsk2,
		clatter.PatternKKpsk0, clatter.PatternKKpsk2,
		clatter.PatternKXpsk2,
		clatter.PatternXNpsk3, clatter.PatternXKpsk3, clatter.PatternXXpsk3,
		clatter.PatternINpsk1, clatter.PatternINpsk2,
		clatter.PatternIKpsk1, clatter.PatternIKpsk2,
		clatter.PatternIXpsk2,
	}
}

// pqPatterns returns all 26 PQ patterns (matching Rust lib.rs).
func pqPatterns() []*clatter.HandshakePattern {
	return []*clatter.HandshakePattern{
		clatter.PatternPqNN, clatter.PatternPqNK, clatter.PatternPqNX,
		clatter.PatternPqKN, clatter.PatternPqKK, clatter.PatternPqKX,
		clatter.PatternPqXN, clatter.PatternPqXK, clatter.PatternPqXX,
		clatter.PatternPqIN, clatter.PatternPqIK, clatter.PatternPqIX,
		clatter.PatternPqNNpsk2,
		clatter.PatternPqNKpsk2,
		clatter.PatternPqNXpsk2,
		clatter.PatternPqKNpsk2,
		clatter.PatternPqKKpsk2,
		clatter.PatternPqKXpsk2,
		clatter.PatternPqXNpsk3, clatter.PatternPqXKpsk3, clatter.PatternPqXXpsk3,
		clatter.PatternPqINpsk1, clatter.PatternPqINpsk2,
		clatter.PatternPqIKpsk1, clatter.PatternPqIKpsk2,
		clatter.PatternPqIXpsk2,
	}
}

// hybridPatterns returns all 28 Hybrid patterns (matching Rust lib.rs).
func hybridPatterns() []*clatter.HandshakePattern {
	return []*clatter.HandshakePattern{
		clatter.PatternHybridNN, clatter.PatternHybridNK, clatter.PatternHybridNX,
		clatter.PatternHybridKN, clatter.PatternHybridKK, clatter.PatternHybridKX,
		clatter.PatternHybridXN, clatter.PatternHybridXK, clatter.PatternHybridXX,
		clatter.PatternHybridIN, clatter.PatternHybridIK, clatter.PatternHybridIX,
		clatter.PatternHybridNNpsk0, clatter.PatternHybridNNpsk2,
		clatter.PatternHybridNKpsk2,
		clatter.PatternHybridNXpsk2,
		clatter.PatternHybridKNpsk0, clatter.PatternHybridKNpsk2,
		clatter.PatternHybridKKpsk2,
		clatter.PatternHybridKXpsk2,
		clatter.PatternHybridXNpsk3, clatter.PatternHybridXKpsk3, clatter.PatternHybridXXpsk3,
		clatter.PatternHybridINpsk1, clatter.PatternHybridINpsk2,
		clatter.PatternHybridIKpsk1, clatter.PatternHybridIKpsk2,
		clatter.PatternHybridIXpsk2,
	}
}

// cipherHashCombos returns all 8 cipher+hash combinations.
type cipherHashCombo struct {
	cipher clatter.Cipher
	hash   clatter.HashFunc
	name   string
}

func allCipherHashCombos() []cipherHashCombo {
	ciphers := []struct {
		c    clatter.Cipher
		name string
	}{
		{cipher.NewChaChaPoly(), "ChaChaPoly"},
		{cipher.NewAesGcm(), "AESGCM"},
	}
	hashes := []struct {
		h    clatter.HashFunc
		name string
	}{
		{hash.NewSha256(), "SHA256"},
		{hash.NewSha512(), "SHA512"},
		{hash.NewBlake2s(), "BLAKE2s"},
		{hash.NewBlake2b(), "BLAKE2b"},
	}

	combos := make([]cipherHashCombo, 0, 8)
	for _, c := range ciphers {
		for _, h := range hashes {
			combos = append(combos, cipherHashCombo{
				cipher: c.c,
				hash:   h.h,
				name:   c.name + "_" + h.name,
			})
		}
	}
	return combos
}

// verifyHandshake runs a full handshake + 3 transport messages.
// Matches Rust smoke.rs verify_handshake exactly:
//  1. Handshake with empty payloads
//  2. Normal send: "Scream without a sound"
//  3. In-place send: "Flying off the handle"
//  4. Normal send (third msg): "Eugene gene the dance machine"
func verifyHandshake(t *testing.T, alice, bob clatter.Handshaker, label string) {
	t.Helper()

	aliceBuf := make([]byte, 65535)
	bobBuf := make([]byte, 65535)

	// Run handshake
	for {
		if alice.IsWriteTurn() && !bob.IsWriteTurn() {
			n, err := alice.WriteMessage(nil, aliceBuf)
			if err != nil {
				t.Fatalf("%s: alice write: %v", label, err)
			}
			_, err = bob.ReadMessage(aliceBuf[:n], bobBuf)
			if err != nil {
				t.Fatalf("%s: bob read: %v", label, err)
			}
		} else if !alice.IsWriteTurn() && bob.IsWriteTurn() {
			n, err := bob.WriteMessage(nil, bobBuf)
			if err != nil {
				t.Fatalf("%s: bob write: %v", label, err)
			}
			_, err = alice.ReadMessage(bobBuf[:n], aliceBuf)
			if err != nil {
				t.Fatalf("%s: alice read: %v", label, err)
			}
		} else {
			t.Fatalf("%s: state issue", label)
		}

		if alice.IsFinished() && bob.IsFinished() {
			break
		}
	}

	aliceT, err := alice.Finalize()
	if err != nil {
		t.Fatalf("%s: alice finalize: %v", label, err)
	}
	defer aliceT.Destroy()

	bobT, err := bob.Finalize()
	if err != nil {
		t.Fatalf("%s: bob finalize: %v", label, err)
	}
	defer bobT.Destroy()

	// Message 1: normal send
	msg1 := []byte("Scream without a sound")
	n, err := aliceT.Send(msg1, aliceBuf)
	if err != nil {
		t.Fatalf("%s: transport send 1: %v", label, err)
	}
	n, err = bobT.Receive(aliceBuf[:n], bobBuf)
	if err != nil {
		t.Fatalf("%s: transport receive 1: %v", label, err)
	}
	if string(bobBuf[:n]) != string(msg1) {
		t.Fatalf("%s: msg1 mismatch", label)
	}

	// Message 2: in-place send
	msg2 := []byte("Flying off the handle")
	inPlaceBuf := make([]byte, 65535)
	copy(inPlaceBuf, msg2)
	n, err = aliceT.SendInPlace(inPlaceBuf, len(msg2))
	if err != nil {
		t.Fatalf("%s: transport send_in_place: %v", label, err)
	}
	n, err = bobT.ReceiveInPlace(inPlaceBuf, n)
	if err != nil {
		t.Fatalf("%s: transport receive_in_place: %v", label, err)
	}
	if string(inPlaceBuf[:n]) != string(msg2) {
		t.Fatalf("%s: msg2 mismatch", label)
	}

	// Message 3: normal send (third message, matching Rust's send_vec/receive_vec)
	msg3 := []byte("Eugene gene the dance machine")
	n, err = aliceT.Send(msg3, aliceBuf)
	if err != nil {
		t.Fatalf("%s: transport send 3: %v", label, err)
	}
	n, err = bobT.Receive(aliceBuf[:n], bobBuf)
	if err != nil {
		t.Fatalf("%s: transport receive 3: %v", label, err)
	}
	if string(bobBuf[:n]) != string(msg3) {
		t.Fatalf("%s: msg3 mismatch", label)
	}
}

// pushPSKs pushes 4 PSKs to a handshaker.
func pushPSKs(t *testing.T, hs clatter.Handshaker, label string) {
	t.Helper()
	for i := range smokePSKs {
		if err := hs.PushPSK(smokePSKs[i][:]); err != nil {
			t.Fatalf("%s: push PSK %d: %v", label, i, err)
		}
	}
}

func TestSmokeNqHandshakes(t *testing.T) {
	patterns := nqPatterns()
	combos := allCipherHashCombos()
	x := dh.NewX25519()

	count := 0
	for _, p := range patterns {
		for _, ch := range combos {
			suite := clatter.CipherSuite{DH: x, Cipher: ch.cipher, Hash: ch.hash}
			label := p.Name() + "_" + ch.name

			aliceS, _ := x.GenerateKeypair(clatter.NewDummyRng(1))
			bobS, _ := x.GenerateKeypair(clatter.NewDummyRng(2))

			alice, err := clatter.NewNqHandshake(p, true, suite,
				clatter.WithStaticKey(aliceS),
				clatter.WithRemoteStatic(bobS.Public),
				clatter.WithPrologue([]byte("Spinning round and round")),
			)
			if err != nil {
				t.Fatalf("%s: alice: %v", label, err)
			}

			bob, err := clatter.NewNqHandshake(p, false, suite,
				clatter.WithStaticKey(bobS),
				clatter.WithRemoteStatic(aliceS.Public),
				clatter.WithPrologue([]byte("Spinning round and round")),
			)
			if err != nil {
				t.Fatalf("%s: bob: %v", label, err)
			}

			pushPSKs(t, alice, label)
			pushPSKs(t, bob, label)

			verifyHandshake(t, alice, bob, label)
			count++
		}
	}

	t.Logf("NQ smoke: %d handshakes completed (%d patterns x %d combos)",
		count, len(patterns), len(combos))
}

func TestSmokePqHandshakes(t *testing.T) {
	patterns := pqPatterns()
	combos := allCipherHashCombos()
	kemSizes := []struct {
		ekem clatter.KEM
		skem clatter.KEM
		name string
	}{
		{kem.NewMlKem768(), kem.NewMlKem768(), "MLKEM768"},
		{kem.NewMlKem1024(), kem.NewMlKem1024(), "MLKEM1024"},
	}

	count := 0
	for _, p := range patterns {
		for _, ch := range combos {
			for _, k := range kemSizes {
				suite := clatter.CipherSuite{
					EKEM: k.ekem, SKEM: k.skem,
					Cipher: ch.cipher, Hash: ch.hash,
				}
				label := p.Name() + "_" + k.name + "_" + ch.name

				aliceS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(10))
				bobS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(20))

				alice, err := clatter.NewPqHandshake(p, true, suite,
					clatter.WithStaticKey(aliceS),
					clatter.WithRemoteStatic(bobS.Public),
					clatter.WithPrologue([]byte("Stumbling all around")),
				)
				if err != nil {
					t.Fatalf("%s: alice: %v", label, err)
				}

				bob, err := clatter.NewPqHandshake(p, false, suite,
					clatter.WithStaticKey(bobS),
					clatter.WithRemoteStatic(aliceS.Public),
					clatter.WithPrologue([]byte("Stumbling all around")),
				)
				if err != nil {
					t.Fatalf("%s: bob: %v", label, err)
				}

				pushPSKs(t, alice, label)
				pushPSKs(t, bob, label)

				verifyHandshake(t, alice, bob, label)
				count++
			}
		}
	}

	t.Logf("PQ smoke: %d handshakes completed (%d patterns x %d combos x %d KEMs)",
		count, len(patterns), len(combos), len(kemSizes))
}

func TestSmokeHybridHandshakes(t *testing.T) {
	patterns := hybridPatterns()
	combos := allCipherHashCombos()
	x := dh.NewX25519()
	kemSizes := []struct {
		ekem clatter.KEM
		skem clatter.KEM
		name string
	}{
		{kem.NewMlKem768(), kem.NewMlKem768(), "MLKEM768"},
		{kem.NewMlKem1024(), kem.NewMlKem1024(), "MLKEM1024"},
	}

	count := 0
	for _, p := range patterns {
		for _, ch := range combos {
			for _, k := range kemSizes {
				suite := clatter.CipherSuite{
					DH: x, EKEM: k.ekem, SKEM: k.skem,
					Cipher: ch.cipher, Hash: ch.hash,
				}
				label := p.Name() + "_" + k.name + "_" + ch.name

				aliceDH, _ := x.GenerateKeypair(clatter.NewDummyRng(30))
				bobDH, _ := x.GenerateKeypair(clatter.NewDummyRng(40))
				aliceKEM, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(50))
				bobKEM, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(60))

				alice, err := clatter.NewHybridHandshake(p, true, suite,
					clatter.WithStaticKey(aliceDH),
					clatter.WithRemoteStatic(bobDH.Public),
					clatter.WithStaticKEMKey(aliceKEM),
					clatter.WithRemoteStaticKEMKey(bobKEM.Public),
					clatter.WithPrologue([]byte("Stumbling all around")),
				)
				if err != nil {
					t.Fatalf("%s: alice: %v", label, err)
				}

				bob, err := clatter.NewHybridHandshake(p, false, suite,
					clatter.WithStaticKey(bobDH),
					clatter.WithRemoteStatic(aliceDH.Public),
					clatter.WithStaticKEMKey(bobKEM),
					clatter.WithRemoteStaticKEMKey(aliceKEM.Public),
					clatter.WithPrologue([]byte("Stumbling all around")),
				)
				if err != nil {
					t.Fatalf("%s: bob: %v", label, err)
				}

				pushPSKs(t, alice, label)
				pushPSKs(t, bob, label)

				verifyHandshake(t, alice, bob, label)
				count++
			}
		}
	}

	t.Logf("Hybrid smoke: %d handshakes completed (%d patterns x %d combos x %d KEMs)",
		count, len(patterns), len(combos), len(kemSizes))
}

func TestSmokeDualLayerHandshakes(t *testing.T) {
	nqPats := nqPatterns()
	pqPats := pqPatterns()
	combos := allCipherHashCombos()
	x := dh.NewX25519()
	kemSizes := []struct {
		ekem clatter.KEM
		skem clatter.KEM
		name string
	}{
		{kem.NewMlKem768(), kem.NewMlKem768(), "MLKEM768"},
		{kem.NewMlKem1024(), kem.NewMlKem1024(), "MLKEM1024"},
	}

	count := 0
	for _, nqPat := range nqPats {
		if nqPat.IsOneWay() {
			continue // DualLayer outer must not be one-way
		}
		for _, pqPat := range pqPats {
			for _, ch := range combos {
				for _, k := range kemSizes {
					nqSuite := clatter.CipherSuite{DH: x, Cipher: ch.cipher, Hash: ch.hash}
					pqSuite := clatter.CipherSuite{
						EKEM: k.ekem, SKEM: k.skem,
						Cipher: ch.cipher, Hash: ch.hash,
					}
					label := nqPat.Name() + "+" + pqPat.Name() + "_" + k.name + "_" + ch.name

					// Helper to create NQ+PQ pair with given RNG seeds
					makeNqPq := func(nqSeed, pqSeed uint64) (*clatter.NqHandshake, *clatter.NqHandshake, *clatter.PqHandshake, *clatter.PqHandshake) {
						aliceNqS, _ := x.GenerateKeypair(clatter.NewDummyRng(nqSeed))
						bobNqS, _ := x.GenerateKeypair(clatter.NewDummyRng(nqSeed + 1))
						alicePqS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(pqSeed))
						bobPqS, _ := k.skem.GenerateKeypair(clatter.NewDummyRng(pqSeed + 1))

						aNQ, err := clatter.NewNqHandshake(nqPat, true, nqSuite,
							clatter.WithStaticKey(aliceNqS),
							clatter.WithRemoteStatic(bobNqS.Public),
							clatter.WithPrologue([]byte("Spinning round and round")),
						)
						if err != nil {
							t.Fatalf("%s: alice NQ: %v", label, err)
						}
						bNQ, err := clatter.NewNqHandshake(nqPat, false, nqSuite,
							clatter.WithStaticKey(bobNqS),
							clatter.WithRemoteStatic(aliceNqS.Public),
							clatter.WithPrologue([]byte("Spinning round and round")),
						)
						if err != nil {
							t.Fatalf("%s: bob NQ: %v", label, err)
						}
						pushPSKs(t, aNQ, label)
						pushPSKs(t, bNQ, label)

						aPQ, err := clatter.NewPqHandshake(pqPat, true, pqSuite,
							clatter.WithStaticKey(alicePqS),
							clatter.WithRemoteStatic(bobPqS.Public),
							clatter.WithPrologue([]byte("Stumbling all around")),
						)
						if err != nil {
							t.Fatalf("%s: alice PQ: %v", label, err)
						}
						bPQ, err := clatter.NewPqHandshake(pqPat, false, pqSuite,
							clatter.WithStaticKey(bobPqS),
							clatter.WithRemoteStatic(alicePqS.Public),
							clatter.WithPrologue([]byte("Stumbling all around")),
						)
						if err != nil {
							t.Fatalf("%s: bob PQ: %v", label, err)
						}
						pushPSKs(t, aPQ, label)
						pushPSKs(t, bPQ, label)
						return aNQ, bNQ, aPQ, bPQ
					}

					// DualLayer (independent layers)
					aNQ, bNQ, aPQ, bPQ := makeNqPq(100, 300)
					aliceDL, err := clatter.NewDualLayerHandshake(aNQ, aPQ, 65535)
					if err != nil {
						t.Fatalf("%s: alice DL: %v", label, err)
					}
					bobDL, err := clatter.NewDualLayerHandshake(bNQ, bPQ, 65535)
					if err != nil {
						t.Fatalf("%s: bob DL: %v", label, err)
					}
					verifyHandshake(t, aliceDL, bobDL, "DL_"+label)
					count++

					// HybridDualLayer (cryptographically bound layers)
					aNQ2, bNQ2, aPQ2, bPQ2 := makeNqPq(500, 700)
					aliceHDL, err := clatter.NewHybridDualLayerHandshake(aNQ2, aPQ2, 65535)
					if err != nil {
						t.Fatalf("%s: alice HDL: %v", label, err)
					}
					bobHDL, err := clatter.NewHybridDualLayerHandshake(bNQ2, bPQ2, 65535)
					if err != nil {
						t.Fatalf("%s: bob HDL: %v", label, err)
					}
					verifyHandshake(t, aliceHDL, bobHDL, "HDL_"+label)
					count++
				}
			}
		}
	}

	t.Logf("DualLayer smoke: %d handshakes completed", count)
}
