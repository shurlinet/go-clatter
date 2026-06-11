package clatter_test

import (
	"bytes"
	"math"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
)

// keyedEquivalenceCiphers returns the production ciphers that implement
// the KeyedCipher fast path.
func keyedEquivalenceCiphers() map[string]clatter.KeyedCipher {
	return map[string]clatter.KeyedCipher{
		"ChaChaPoly": cipher.NewChaChaPoly(),
		"AESGCM":     cipher.NewAesGcm(),
	}
}

// TestKeyedCipher_StatelessEquivalence verifies the keyed AEAD fast path
// produces byte-identical output to the stateless per-call path for both
// production ciphers, across nonces including 0 and MaxUint64, with and
// without AD, including in-place operation.
func TestKeyedCipher_StatelessEquivalence(t *testing.T) {
	for name, c := range keyedEquivalenceCiphers() {
		t.Run(name, func(t *testing.T) {
			var key [32]byte
			for i := range key {
				key[i] = byte(i*7 + 3)
			}
			keyed, err := c.NewKeyed(key)
			if err != nil {
				t.Fatalf("NewKeyed: %v", err)
			}

			plaintext := []byte("keyed path equivalence payload")
			ad := []byte("associated data")

			for _, nonce := range []uint64{0, 1, 2, 1 << 32, math.MaxUint64} {
				for _, useAD := range []bool{false, true} {
					var a []byte
					if useAD {
						a = ad
					}

					statelessOut := make([]byte, len(plaintext)+c.TagLen())
					want, err := c.Encrypt(key, nonce, a, plaintext, statelessOut)
					if err != nil {
						t.Fatalf("stateless Encrypt: %v", err)
					}

					keyedOut := make([]byte, len(plaintext)+c.TagLen())
					got, err := keyed.Encrypt(nonce, a, plaintext, keyedOut)
					if err != nil {
						t.Fatalf("keyed Encrypt: %v", err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("nonce %d ad=%v: keyed ciphertext diverges from stateless", nonce, useAD)
					}

					// Decrypt equivalence both directions.
					ptBuf := make([]byte, len(want))
					pt, err := keyed.Decrypt(nonce, a, want, ptBuf)
					if err != nil {
						t.Fatalf("keyed Decrypt of stateless ct: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Fatal("keyed Decrypt plaintext mismatch")
					}

					// Tamper rejection on the keyed path.
					bad := append([]byte{}, want...)
					bad[0] ^= 1
					if _, err := keyed.Decrypt(nonce, a, bad, ptBuf); err == nil {
						t.Fatal("keyed Decrypt accepted tampered ciphertext")
					}
				}
			}
		})
	}
}

// TestKeyedCipher_RekeyRebuildsCache verifies CipherState.Rekey rebinds
// the cached keyed AEAD to the new key: a peer CipherState rekeyed
// identically must still interoperate, and the post-rekey ciphertext must
// differ from the pre-rekey ciphertext for the same nonce and plaintext.
func TestKeyedCipher_RekeyRebuildsCache(t *testing.T) {
	for name, c := range keyedEquivalenceCiphers() {
		t.Run(name, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x42}, 32)
			enc, err := clatter.NewCipherState(c, key)
			if err != nil {
				t.Fatalf("enc: %v", err)
			}
			dec, err := clatter.NewCipherState(c, key)
			if err != nil {
				t.Fatalf("dec: %v", err)
			}

			msg := []byte("before rekey")
			ctBefore, err := enc.EncryptWithAd(nil, msg)
			if err != nil {
				t.Fatalf("encrypt before rekey: %v", err)
			}
			if _, err := dec.DecryptWithAd(nil, ctBefore); err != nil {
				t.Fatalf("decrypt before rekey: %v", err)
			}

			if err := enc.Rekey(); err != nil {
				t.Fatalf("enc rekey: %v", err)
			}
			if err := dec.Rekey(); err != nil {
				t.Fatalf("dec rekey: %v", err)
			}

			ctAfter, err := enc.EncryptWithAd(nil, msg)
			if err != nil {
				t.Fatalf("encrypt after rekey: %v", err)
			}
			pt, err := dec.DecryptWithAd(nil, ctAfter)
			if err != nil {
				t.Fatalf("decrypt after rekey: %v (stale keyed cache?)", err)
			}
			if !bytes.Equal(pt, msg) {
				t.Fatal("post-rekey round-trip plaintext mismatch")
			}

			// Same plaintext, different key: ciphertexts must differ.
			// (Nonces differ too, but a stale cache reusing the old key
			// would already have failed the round-trip above.)
			if bytes.Equal(ctBefore, ctAfter) {
				t.Fatal("rekey did not change the effective key")
			}

			enc.Destroy()
			dec.Destroy()
		})
	}
}

// statelessOnly hides the KeyedCipher fast path of a production cipher,
// forcing CipherState onto the per-message key schedule. Used to keep a
// permanent benchmark of what the keyed cache saves.
type statelessOnly struct {
	c clatter.KeyedCipher
}

func (s statelessOnly) Name() string { return s.c.Name() }
func (s statelessOnly) TagLen() int  { return s.c.TagLen() }
func (s statelessOnly) KeyLen() int  { return s.c.KeyLen() }
func (s statelessOnly) Encrypt(key [32]byte, nonce uint64, ad, plaintext, out []byte) ([]byte, error) {
	return s.c.Encrypt(key, nonce, ad, plaintext, out)
}
func (s statelessOnly) Decrypt(key [32]byte, nonce uint64, ad, ciphertext, out []byte) ([]byte, error) {
	return s.c.Decrypt(key, nonce, ad, ciphertext, out)
}

// BenchmarkCipherState_Send measures the per-message cost through
// CipherState for both production ciphers, on the keyed fast path and on
// the stateless path (per-message key schedule) for comparison.
func BenchmarkCipherState_Send(b *testing.B) {
	payload := make([]byte, 1024)
	for name, kc := range keyedEquivalenceCiphers() {
		for variant, c := range map[string]clatter.Cipher{
			"keyed":     kc,
			"stateless": statelessOnly{c: kc},
		} {
			b.Run(name+"/"+variant, func(b *testing.B) {
				key := bytes.Repeat([]byte{0x42}, 32)
				cs, err := clatter.NewCipherState(c, key)
				if err != nil {
					b.Fatal(err)
				}
				defer cs.Destroy()
				buf := make([]byte, len(payload)+16)
				copy(buf, payload)
				b.SetBytes(int64(len(payload)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := cs.EncryptWithAdInPlace(nil, buf, len(payload)); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
