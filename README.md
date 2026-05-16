# go-clatter 🔊

[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-clatter.svg)](https://pkg.go.dev/github.com/shurlinet/go-clatter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Post-quantum [Noise](https://noiseprotocol.org/noise.html) handshakes for Go. Implements the [PQNoise](https://doi.org/10.1145/3548606.3560577) ([alt](https://sci-net.xyz/10.1145/3548606.3560577)) extensions (ACM CCS 2022) that replace classical DH key exchanges with quantum-resistant KEMs while preserving Noise's formal security guarantees.

Ported from [Rust Clatter v2.2.0](https://github.com/jmlepisto/clatter) by [Joni Lepisto](https://github.com/jmlepisto) and verified against it byte-for-byte. Built on Go stdlib crypto (`crypto/mlkem`, `crypto/ecdh`) with `golang.org/x/crypto` for ChaCha20-Poly1305 and BLAKE2. No other external dependencies. All secret key material lives in fixed-size arrays with explicit `Destroy()` zeroing.

⚠️ **Warning** ⚠️

* This library has not received any formal audit
* While we use Go's standard library cryptographic primitives, it is up to **you** to evaluate whether they meet your security and integrity requirements
* Post-quantum cryptography is not as established as classical cryptography. Users are encouraged to use hybrid handshakes (`HybridHandshake`, `HybridDualLayerHandshake`) that combine classical and post-quantum primitives for defense in depth
* This Go port was written with AI assistance ([Claude](https://claude.ai)) and reviewed by a human. All code is verified against the Rust reference implementation byte-for-byte, and tested with 26,000+ handshakes, 408 cross-implementation vectors, 1,452 NIST/PQC-Suite-B vectors, and 11 fuzz targets. The AI generated code; the human made every design decision, reviewed every line, and owns every bug.

📖 **Documentation** 📖

* [`pkg.go.dev`](https://pkg.go.dev/github.com/shurlinet/go-clatter) - API reference and type docs
* [`examples/`](examples/) - Runnable examples for every handshake type, observer callbacks, ML-DSA-65, and SLH-DSA signing

## Noise Protocol

This library tracks Noise protocol framework **revision 34**. The following features are not supported:

* Curve 448 DH support - No suitable Go implementation exists
* Deferred pattern support - Can be implemented by the user
* Fallback pattern support - Can be implemented by the user

### PSK Validity Rule

go-clatter adopts the same modified PSK validity interpretation as Rust Clatter for post-quantum patterns.
When PQ patterns are used, sending either an `e` or `ekem` token provides the required self-chosen randomness
equivalent to the `e` token in classical Noise patterns. `skem` also satisfies this requirement if it comes
before any `psk` tokens in the message pattern.

## Handshake Types

* **NQ** (`NqHandshake`) - Classical DH-only handshakes using X25519
* **PQ** (`PqHandshake`) - KEM-only handshakes using ML-KEM-768 or ML-KEM-1024
* **Hybrid** (`HybridHandshake`) - True hybrid handshakes combining DH and KEM operations in a single symmetric state
* **DualLayer** (`DualLayerHandshake`) - Outer-encrypts-inner piped handshake with independent layers
* **HybridDualLayer** (`HybridDualLayerHandshake`) - Outer-encrypts-inner piped handshake with cryptographic binding between layers

90 handshake patterns. 4 hash functions. 2 AEAD ciphers. 2 KEM sizes.

## Post-Quantum Signing

* **ML-DSA-65** (`crypto/sign/mldsa65`) - FIPS 204 lattice-based digital signatures (NIST Level 3, ~192-bit security). Seed = 32 B, PubKey = 1952 B, Sig = 3309 B.
* **SLH-DSA** (`crypto/sign/slhdsa`) - FIPS 205 hash-based digital signatures. NIST's backup to ML-DSA. 18 parameter sets: 12 FIPS (SHA2 + SHAKE) and 6 non-FIPS BLAKE3 variants. Security levels 1/3/5 with fast-sign and small-sig tradeoffs. Verified against 1,260 NIST ACVP vectors and 192 PQC Suite B BLAKE3 vectors.

Standalone signing modules. Not integrated into the Noise handshake - these are general-purpose signing primitives for application-layer use.

## Crypto Primitives

| Primitive | Implementation | Protocol Name |
|-----------|---------------|---------------|
| X25519 DH | `crypto/ecdh` | `25519` |
| ML-KEM-768 | `crypto/mlkem` (FIPS 203) | `MLKEM768` |
| ML-KEM-1024 | `crypto/mlkem` (FIPS 203) | `MLKEM1024` |
| ChaCha20-Poly1305 | `golang.org/x/crypto` | `ChaChaPoly` |
| AES-256-GCM | `crypto/aes` | `AESGCM` |
| SHA-256 | `crypto/sha256` | `SHA256` |
| SHA-512 | `crypto/sha512` | `SHA512` |
| BLAKE2s | `golang.org/x/crypto/blake2s` | `BLAKE2s` |
| BLAKE2b | `golang.org/x/crypto/blake2b` | `BLAKE2b` |
| ML-DSA-65 | `filippo.io/mldsa` (FIPS 204) | - |
| SLH-DSA (SHA2) | Embedded [Trail of Bits go-slh-dsa](https://github.com/trailofbits/go-slh-dsa) (FIPS 205) | - |
| SLH-DSA (SHAKE) | Embedded Trail of Bits + `golang.org/x/crypto/sha3` | - |
| SLH-DSA (BLAKE3) | Embedded Trail of Bits + `lukechampine.com/blake3` | - |

## Protocol Naming

go-clatter uses the same naming scheme as Rust Clatter for cross-implementation compatibility:

```text
Noise_NN_25519_ChaChaPoly_SHA256              (NQ)
Noise_pqNN_MLKEM768_ChaChaPoly_SHA256         (PQ, same KEM)
Noise_pqNN_MLKEM768+MLKEM1024_ChaChaPoly_SHA256  (PQ, different KEMs)
Noise_hybridNN_25519+MLKEM768_ChaChaPoly_SHA256   (Hybrid)
```

## Usage

```go
import (
    clatter "github.com/shurlinet/go-clatter"
    "github.com/shurlinet/go-clatter/crypto/cipher"
    "github.com/shurlinet/go-clatter/crypto/dh"
    "github.com/shurlinet/go-clatter/crypto/hash"
    "github.com/shurlinet/go-clatter/crypto/kem"
)

// NQ handshake (classical)
suite := clatter.CipherSuite{
    DH:     dh.NewX25519(),
    Cipher: cipher.NewChaChaPoly(),
    Hash:   hash.NewSha256(),
}

alice, _ := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
    clatter.WithPrologue([]byte("my-app/v1")),
)

// Hybrid handshake (quantum-resistant)
hybridSuite := clatter.CipherSuite{
    DH:     dh.NewX25519(),
    EKEM:   kem.NewMlKem768(),
    SKEM:   kem.NewMlKem768(),
    Cipher: cipher.NewChaChaPoly(),
    Hash:   hash.NewSha256(),
}

alice, _ := clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hybridSuite,
    clatter.WithStaticKey(aliceDHKeys),
    clatter.WithStaticKEMKey(aliceKEMKeys),
    clatter.WithPrologue([]byte("my-app/v1")),
)
```

### ML-DSA-65 Signing

```go
import "github.com/shurlinet/go-clatter/crypto/sign/mldsa65"

// Generate a key pair.
sk, _ := mldsa65.GenerateKey()
defer sk.Destroy() // zeros seed on cleanup

// Sign (hedged randomness - recommended for production).
sig, _ := sk.Sign([]byte("message to sign"))

// Verify.
ok := sk.PublicKey().Verify([]byte("message to sign"), sig)

// Context separation prevents cross-purpose replay.
sig, _ = sk.SignWithContext([]byte("data"), "my-app/transfers/v1")
ok = sk.PublicKey().VerifyWithContext([]byte("data"), sig, "my-app/transfers/v1")

// Seed export/import for key persistence.
seed, _ := sk.Seed()       // 32 bytes - store securely
sk2, _ := mldsa65.NewPrivateKeyFromSeed(seed) // reconstruct later
defer sk2.Destroy()
```

### SLH-DSA Signing

```go
import "github.com/shurlinet/go-clatter/crypto/sign/slhdsa"

// Generate a key pair (SHA2-128f: fastest FIPS 205 param set).
priv, _ := slhdsa.GenerateKey(slhdsa.SHA2_128f)
defer priv.Destroy()

// Sign (hedged randomness - recommended for production).
sig, _ := priv.SignMessage([]byte("message"))

// Verify.
ok := priv.PublicKey().Verify([]byte("message"), sig)

// BLAKE3 variant (non-FIPS, faster on x86 with SIMD).
// Same API, just a different ParamSet constant.
privB, _ := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
defer privB.Destroy()
sigB, _ := privB.SignMessage([]byte("blake3 message"))
_ = privB.PublicKey().Verify([]byte("blake3 message"), sigB)

// Pre-hash mode for large files (SHA2/SHAKE param sets only).
largeFile := []byte("contents of a large file")
sig, _ = priv.SignPreHash(largeFile, slhdsa.HashSHA2_256)
ok = priv.PublicKey().VerifyPreHash(largeFile, sig, slhdsa.HashSHA2_256)
```

18 parameter sets available. See the [SLH-DSA godoc](https://pkg.go.dev/github.com/shurlinet/go-clatter/crypto/sign/slhdsa) for the full API and parameter set guide.

## Observability

Attach an `Observer` to any handshake to receive real-time notifications about message processing, key exchange events, and errors:

```go
type myObserver struct{}

func (o *myObserver) OnMessage(e clatter.HandshakeEvent) {
    fmt.Printf("[msg %d] %s type=%s payload=%d bytes\n",
        e.MessageIndex, e.Direction, e.HandshakeType, e.PayloadLen)
}
func (o *myObserver) OnError(e clatter.HandshakeErrorEvent) {
    fmt.Printf("[msg %d] ERROR: %v\n", e.MessageIndex, e.Err)
}

alice, _ := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
    clatter.WithObserver(&myObserver{}),
)
```

Observer events report learned remote keys (DH and KEM), handshake hash, protocol name, phase (for dual-layer), and completion status. A nil observer has zero overhead. Panics in observer callbacks are recovered. See [`examples/observer/`](examples/observer/) and the [Observer godoc](https://pkg.go.dev/github.com/shurlinet/go-clatter#Observer).

## Differences to Rust Clatter

* **CipherSuite struct** instead of generic type parameters - Go's type system favours runtime dispatch
* **All Rust panics are Go errors** - go-clatter never panics on user input
* **No ML-KEM-512** - Go stdlib `crypto/mlkem` ships 768 and 1024 only (NIST security margin decision)
* **No cross-vendor KEM tests** - Go has one KEM implementation per key size (stdlib)
* **Post-quantum signing modules** - go-clatter extends beyond handshakes with standalone FIPS 204 (ML-DSA-65) and FIPS 205 (SLH-DSA) signature primitives. Rust Clatter does not include signing modules. This gives Go consumers a complete PQ toolkit: quantum-resistant key exchange (ML-KEM), lattice-based signatures (ML-DSA), and hash-based signatures (SLH-DSA) under one roof.

## Verification

go-clatter is verified by:

* Unit tests across all packages
* [Smoke tests](smoke_test.go) - 26,112 handshakes across all pattern/cipher/hash/KEM combinations (NQ + PQ + Hybrid + DualLayer + HybridDualLayer)
* [Property tests](maxmsglen_property_test.go) - All 90 patterns verified with independent overhead calculator, per-message runtime cross-check, actual-bytes-written oracle, constructor boundary validation, and transport enforcement
* [Fuzz tests](fuzz_test.go) - 9 Noise fuzz targets matching Rust Clatter's fuzz suite + 2 SLH-DSA fuzz targets (sign-verify round-trip + loader crash resistance)
* [MaxMsgLen fuzz](maxmsglen_fuzz_test.go) - Boundary sharpness verification across 3 patterns (NQ, PQ, Hybrid) covering all message count shapes
* [Cacophony](https://github.com/haskell-cryptography/cacophony) and [Snow](https://github.com/mcginty/snow) test vectors - 408 cross-implementation vectors verified byte-for-byte ([vectors/](vectors/))
* 10 Rust interop vectors generated from Rust Clatter with deterministic RNG
* [NIST ACVP vectors](crypto/sign/slhdsa/testdata/acvp/) - 1,260 SLH-DSA test vectors (keygen + sigGen + sigVer) across all 12 FIPS 205 parameter sets including pre-hash mode
* [PQC Suite B BLAKE3 vectors](crypto/sign/slhdsa/testdata/blake3/) - 192 cross-implementation vectors for all 6 BLAKE3 parameter sets

```
make test
```

Or equivalently: `go test -race -count=1 -timeout 30m ./...`

The SLH-DSA package includes 1,452 ACVP/BLAKE3 vectors across all 18 parameter sets. The `-s` (small signature) variants build deep hypertrees and take 15+ minutes with `-race`. The default Go timeout of 10 minutes is not enough. The Makefile ensures the correct flags are always used.

## Future Work

* **SM3 hash function support** - [SM3](https://grokipedia.com/page/sm3_hash_function) is China's national cryptographic hash (ISO/IEC 10118-3:2018, 256-bit, equivalent security to SHA-256). SLH-DSA's hash-agnostic architecture enables SM3-instantiated parameter sets alongside SHA2/SHAKE/BLAKE3. Go library: [`emmansun/gmsm`](https://github.com/emmansun/gmsm). Waiting for official SLH-DSA-SM3 spec.
* **HQC KEM** - NIST-selected backup KEM (code-based, different math from ML-KEM). Awaiting NIST FIPS finalization (expected late 2026 / early 2027).
* **China NGCC algorithms** - China's [Next-Generation Commercial Cryptographic Algorithms Program](https://www.niccs.org.cn/en/) (NGCC, launched February 2025) is running its own PQC standardization independently of NIST, with submissions closing June 2026 and algorithm selections expected 2027-2028. go-clatter's modular architecture (CipherSuite, ParamSetFuncs interface) is designed to accommodate new KEM and signature algorithms as they are standardized, regardless of origin.

## Dependencies

* Go 1.26+ (required for `crypto/mlkem`)
* `golang.org/x/crypto` (ChaCha20-Poly1305, BLAKE2, SHA3/SHAKE)
* [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) (ML-DSA-65 signing) - Pre-release of Go's upcoming `crypto/mldsa` stdlib package, maintained by [Filippo Valsorda](https://filippo.io). Migration to stdlib is a single import path change when `crypto/mldsa` ships (proposal [#77626](https://github.com/golang/go/issues/77626) accepted).
* [`lukechampine.com/blake3`](https://pkg.go.dev/lukechampine.com/blake3) (SLH-DSA BLAKE3 param sets) - Pure Go + SIMD assembly for amd64/arm64.

## Acknowledgments

Special thanks to [Joni Lepisto](https://github.com/jmlepisto) for creating [Rust Clatter](https://github.com/jmlepisto/clatter). His clean, well-tested implementation made this Go port possible and his test infrastructure (interop vectors, smoke tests, fuzz targets) set the standard we verify against.

Thanks also to the projects whose test vector datasets we use to verify correctness:

* [Cacophony](https://github.com/haskell-cryptography/cacophony) (Haskell Noise implementation) - 944 test vectors
* [Snow](https://github.com/mcginty/snow) (Rust Noise implementation) - 408 test vectors

And to the authors of the PQNoise paper for the foundational research this library implements.

Thanks to [Filippo Valsorda](https://filippo.io) for [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) - the ML-DSA implementation that powers our signing module. Filippo maintains Go's cryptography standard library and designed this package as the direct precursor to `crypto/mldsa`. His work gives the Go ecosystem production-ready post-quantum signatures years before the stdlib ships them.

Thanks to [Trail of Bits](https://trailofbits.com) for [go-slh-dsa](https://github.com/trailofbits/go-slh-dsa) - the SLH-DSA engine embedded in our signing module. Their implementation is pure Go, side-channel resistant, and covers all 12 FIPS 205 parameter sets.

Thanks to [JP Aumasson](https://aumasson.jp), [Zooko Wilcox-O'Hearn](https://grokipedia.com/page/Zooko_Wilcox-O'Hearn), and Alex Pruden for [PQC Suite B](https://github.com/PQC-Suite-B/) - the BLAKE3 variant research and test vectors that validate our BLAKE3 parameter sets.

Thanks to [Luke Champine](https://github.com/lukechampine) for [lukechampine.com/blake3](https://github.com/lukechampine/blake3) - the BLAKE3 implementation with SIMD acceleration for amd64 and arm64.

## License

MIT - matching the upstream Rust Clatter license.
