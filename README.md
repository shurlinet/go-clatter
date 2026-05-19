# go-clatter 🔊

[![Go Tests](https://github.com/shurlinet/go-clatter/actions/workflows/ci.yml/badge.svg)](https://github.com/shurlinet/go-clatter/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-clatter.svg)](https://pkg.go.dev/github.com/shurlinet/go-clatter)
[![Go Report Card](https://goreportcard.com/badge/github.com/shurlinet/go-clatter)](https://goreportcard.com/report/github.com/shurlinet/go-clatter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Post-quantum [Noise](https://noiseprotocol.org/noise.html) handshakes for Go. Implements the [PQNoise](https://doi.org/10.1145/3548606.3560577) ([alt](https://sci-net.xyz/10.1145/3548606.3560577)) extensions (ACM CCS 2022) that replace classical DH key exchanges with quantum-resistant KEMs while preserving Noise's formal security guarantees.

Ported from [Rust Clatter v2.2.0](https://github.com/jmlepisto/clatter) by [Joni Lepisto](https://github.com/jmlepisto) and verified against it byte-for-byte. Built on Go stdlib crypto (`crypto/mlkem`, `crypto/ecdh`) with `golang.org/x/crypto` for ChaCha20-Poly1305 and BLAKE2. No other external dependencies for Noise handshakes.

> **Warning**
>
> * This library has not received any formal audit
> * While we use Go's standard library cryptographic primitives, it is up to **you** to evaluate whether they meet your security and integrity requirements
> * Post-quantum cryptography is not as established as classical cryptography. Users are encouraged to use hybrid handshakes (`HybridHandshake`, `HybridDualLayerHandshake`) that combine classical and post-quantum primitives for defense in depth

## Install

```
go get github.com/shurlinet/go-clatter
```

Requires Go 1.26+ (for `crypto/mlkem`).

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

90 handshake patterns. 4 hash functions. 2 AEAD ciphers. 2 ML-KEM sizes. 3 HQC sizes (experimental).

## Post-Quantum Signing

* **ML-DSA-65** (`crypto/sign/mldsa65`) - FIPS 204 lattice-based digital signatures (NIST Level 3, ~192-bit security). Seed = 32 B, PubKey = 1952 B, Sig = 3309 B.
* **SLH-DSA** (`crypto/sign/slhdsa`) - FIPS 205 hash-based digital signatures. NIST's backup to ML-DSA. 18 parameter sets: 12 FIPS (SHA2 + SHAKE) and 6 non-FIPS BLAKE3 variants. Security levels 1/3/5 with fast-sign and small-sig tradeoffs. Verified against 1,260 NIST ACVP vectors and 192 PQC Suite B BLAKE3 vectors.

Standalone signing modules. Not integrated into the Noise handshake - these are general-purpose signing primitives for application-layer use.

## Security

* **Stdlib crypto** - All Noise handshake primitives use Go's standard library (`crypto/mlkem`, `crypto/ecdh`, `crypto/aes`) or `golang.org/x/crypto` (ChaCha20-Poly1305, BLAKE2). No hand-rolled cryptography.
* **Secret zeroing** - All secret key material lives in fixed-size arrays with explicit `Destroy()` methods. Callers must call `Destroy()` when keys are no longer needed.
* **Errors, not panics** - All error conditions return Go `error` values. Invalid inputs, state violations, and crypto failures are handled through Go's standard error pattern.
* **HKDF key derivation** - Manual HKDF implementation matching Noise spec (not a wrapper), with HMAC key length validation and full error propagation through HKDF2/HKDF3.
* **Concurrency safety** - Handshake objects detect concurrent use via atomic guards and return errors. Transport ciphers use independent nonce counters per direction.
* **Minimal dependencies** - Noise handshakes depend only on Go stdlib + `golang.org/x/crypto`. Signing modules add `filippo.io/mldsa` (ML-DSA) and embedded Trail of Bits engine (SLH-DSA).

## Spec Compliance

| Feature | Status | Notes |
|---------|--------|-------|
| Noise rev 34 one-way patterns | Supported | N, K, X |
| Noise rev 34 interactive patterns | Supported | NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX |
| PQNoise KEM patterns (ACM CCS 2022) | Supported | pqNN, pqNK, pqNX, pqKN, pqKK, pqKX, pqXN, pqXK, pqXX, pqIN, pqIK, pqIX |
| Hybrid DH+KEM patterns | Supported | All interactive patterns with combined DH and KEM |
| Dual-layer piped handshakes | Supported | DualLayer and HybridDualLayer with cryptographic binding |
| PSK modifiers (psk0-psk4) | Supported | Modified validity rule for PQ patterns (see PSK section) |
| Curve 448 DH | Not supported | No suitable Go implementation |
| Deferred/fallback patterns | Not supported | Can be implemented by the user |

## Crypto Primitives

| Primitive | Implementation | Protocol Name |
|-----------|---------------|---------------|
| X25519 DH | `crypto/ecdh` | `25519` |
| ML-KEM-768 | `crypto/mlkem` (FIPS 203) | `MLKEM768` |
| ML-KEM-1024 | `crypto/mlkem` (FIPS 203) | `MLKEM1024` |
| HQC-128 | [`go-hqc`](https://pkg.go.dev/github.com/shurlinet/go-hqc) (experimental, build tag `hqc`) | `HQC128` |
| HQC-192 | `go-hqc` (experimental) | `HQC192` |
| HQC-256 | `go-hqc` (experimental) | `HQC256` |
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

### HQC (Experimental)

HQC is NIST's backup KEM (code-based, different math from ML-KEM). It requires two deliberate opt-ins:

1. **Build tag**: compile with `-tags hqc`
2. **Runtime flag**: `clatter.AllowExperimental.Store(true)`

```go
//go:build hqc

import (
    clatter "github.com/shurlinet/go-clatter"
    "github.com/shurlinet/go-clatter/crypto/cipher"
    "github.com/shurlinet/go-clatter/crypto/hash"
    "github.com/shurlinet/go-clatter/crypto/kem"
)

clatter.AllowExperimental.Store(true)

suite := clatter.CipherSuite{
    EKEM:         kem.NewHqc128(),
    SKEM:         kem.NewHqc128(),
    Cipher:       cipher.NewChaChaPoly(),
    Hash:         hash.NewSha256(),
    Experimental: true,
}

alice, _ := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
)
```

Without the build tag, HQC code is not compiled (zero binary bloat). Without `AllowExperimental`, every KEM operation returns `ErrExperimentalNotAllowed`. Both gates will be relaxed as HQC progresses through FIPS standardization.

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

## Examples

| Example | Description |
|---------|-------------|
| [`examples/nq/`](examples/nq/) | Classical NQ (X25519) handshake |
| [`examples/pq/`](examples/pq/) | Post-quantum PQ (ML-KEM) handshake |
| [`examples/hqc/`](examples/hqc/) | Post-quantum PQ (HQC-128) handshake (experimental, `-tags hqc`) |
| [`examples/hybrid/`](examples/hybrid/) | Hybrid DH+KEM handshake |
| [`examples/dual_layer/`](examples/dual_layer/) | Dual-layer piped handshake |
| [`examples/psk/`](examples/psk/) | Pre-shared key handshake |
| [`examples/observer/`](examples/observer/) | Observer callbacks for handshake events |
| [`examples/mldsa65/`](examples/mldsa65/) | ML-DSA-65 post-quantum signing |
| [`examples/slhdsa/`](examples/slhdsa/) | SLH-DSA signing (SHA2/SHAKE) |
| [`examples/slhdsa_blake3/`](examples/slhdsa_blake3/) | SLH-DSA signing (BLAKE3) |

## Consumer Responsibilities

* **Call `Destroy()` on private keys** when they are no longer needed. `Destroy()` zeroes secret material. The Go garbage collector does not guarantee timely zeroing of freed memory.
* **Use hybrid handshakes for defense in depth.** PQC is newer than classical crypto. `HybridHandshake` and `HybridDualLayerHandshake` combine both so that security holds even if one primitive is broken.
* **Set a prologue** for protocol binding. The prologue is mixed into the handshake hash and prevents cross-protocol replay. Use a unique string per application (e.g., `"my-app/v1"`).
* **Do not reuse handshake objects.** Each handshake instance is single-use. Create a new one per connection.
* **Transport ciphers are directional.** After handshake completion, `TransportState` provides separate send/receive ciphers. Do not swap them.

## Differences to Rust Clatter

| Feature | go-clatter | Rust Clatter |
|---------|-----------|--------------|
| Type dispatch | `CipherSuite` struct (runtime) | Generic type parameters (compile-time) |
| Error handling | Go `error` values (idiomatic Go) | Panics for invariant violations (idiomatic Rust) |
| ML-KEM-512 | Not available (Go stdlib ships 768+1024 only) | Available |
| Cross-vendor KEM tests | N/A (Go has one stdlib impl) | Tests against multiple KEM implementations |
| Signing modules | ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205) | Not in scope |
| Observer callbacks | Supported | Not in scope |
| Max message size | Configurable per-handshake | Fixed |

## Verification

go-clatter is verified by:

* Unit tests across all packages
* [Smoke tests](smoke_test.go) - 26,112 handshakes across all pattern/cipher/hash/KEM combinations (NQ + PQ + Hybrid + DualLayer + HybridDualLayer)
* [Property tests](maxmsglen_property_test.go) - All 90 patterns verified with independent overhead calculator, per-message runtime cross-check, actual-bytes-written oracle, constructor boundary validation, and transport enforcement
* [HQC smoke tests](smoke_hqc_test.go) - PQ (all 3 param sets), Hybrid, DualLayer, mixed KEM, experimental gate, and mid-handshake toggle tests (build tag `hqc`)
* [HQC property tests](maxmsglen_hqc_property_test.go) - All 90 patterns verified with HQC-128 overhead calculator (build tag `hqc`)
* [Fuzz tests](fuzz_test.go) - 9 Noise fuzz targets matching Rust Clatter + 1 [HQC fuzz](smoke_hqc_test.go) (build tag `hqc`) + 2 SLH-DSA fuzz targets (sign-verify round-trip + loader crash resistance)
* [MaxMsgLen fuzz](maxmsglen_fuzz_test.go) - Boundary sharpness verification across 3 patterns (NQ, PQ, Hybrid) covering all message count shapes
* [Cacophony](https://github.com/haskell-cryptography/cacophony) and [Snow](https://github.com/mcginty/snow) test vectors - 408 cross-implementation vectors verified byte-for-byte ([vectors/](vectors/))
* 10 Rust interop vectors generated from Rust Clatter with deterministic RNG
* [NIST ACVP vectors](crypto/sign/slhdsa/testdata/acvp/) - 1,260 SLH-DSA test vectors (keygen + sigGen + sigVer) across all 12 FIPS 205 parameter sets including pre-hash mode
* [PQC Suite B BLAKE3 vectors](crypto/sign/slhdsa/testdata/blake3/) - 192 cross-implementation vectors for all 6 BLAKE3 parameter sets

```
make test
```

Or equivalently: `go test -race -count=1 -timeout 30m ./...`

The SLH-DSA package includes 1,452 ACVP/BLAKE3 vectors across all 18 parameter sets. The `-s` (small signature) variants build deep hypertrees and take 15+ minutes with `-race` on Apple Silicon, longer on CI runners. The default Go timeout of 10 minutes is not enough. The Makefile ensures the correct flags are always used. CI uses a 90-minute timeout for the slhdsa package to account for slower shared runners.

## Future Work

* **SM3 hash function support** - [SM3](https://grokipedia.com/page/sm3_hash_function) is China's national cryptographic hash (ISO/IEC 10118-3:2018, 256-bit, equivalent security to SHA-256). SLH-DSA's hash-agnostic architecture enables SM3-instantiated parameter sets alongside SHA2/SHAKE/BLAKE3. Go library: [`emmansun/gmsm`](https://github.com/emmansun/gmsm). Waiting for official SLH-DSA-SM3 spec.
* **HQC KEM FIPS finalization** - HQC-128/192/256 are available as experimental KEMs (build tag `hqc`) backed by [`go-hqc`](https://github.com/shurlinet/go-hqc). The `Experimental` gate will be removed once NIST publishes FIPS 207 (expected late 2026 / early 2027).
* **MAYO signing** - [MAYO](https://pqmayo.org/) is a multivariate signature scheme in [NIST's additional signatures Round 3](https://csrc.nist.gov/projects/pqc-dig-sig/round-3-additional-signatures) (40 submissions → 14 → 9 survivors). Compact signatures (~320 bytes at Level 1) compared to ML-DSA-65's 3309 bytes. Selections expected 2027-2028.
* **HAWK signing** - [HAWK](https://hawk-sign.info/) is an NTRU lattice-based signature scheme, also in NIST Round 3. Different lattice construction from ML-DSA (NTRU vs module-LWE), providing mathematical diversity. Compact signatures (~700 bytes). By [Thomas Pornin](https://github.com/pornin) (author of FALCON/FN-DSA).
* **China NGCC algorithms** - China's [Next-Generation Commercial Cryptographic Algorithms Program](https://www.niccs.org.cn/en/) (NGCC, launched February 2025) is running its own PQC standardization independently of NIST, with submissions closing June 2026 and algorithm selections expected 2027-2028. go-clatter's modular architecture (CipherSuite, ParamSetFuncs interface) is designed to accommodate new KEM and signature algorithms as they are standardized, regardless of origin.

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| Go 1.26+ | Required for `crypto/mlkem` |
| `golang.org/x/crypto` | ChaCha20-Poly1305, BLAKE2, SHA3/SHAKE |
| [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) | ML-DSA-65 signing. Pre-release of Go's upcoming `crypto/mldsa` stdlib package, maintained by [Filippo Valsorda](https://filippo.io). Migration to stdlib is a single import path change when `crypto/mldsa` ships (proposal [#77626](https://github.com/golang/go/issues/77626) accepted). |
| [`lukechampine.com/blake3`](https://pkg.go.dev/lukechampine.com/blake3) | SLH-DSA BLAKE3 param sets. Pure Go + SIMD assembly for amd64/arm64. |
| [`github.com/shurlinet/go-hqc`](https://pkg.go.dev/github.com/shurlinet/go-hqc) | HQC KEM (experimental, build tag `hqc`). NIST backup KEM. |

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

## AI Transparency

This Go port was written with AI assistance ([Claude](https://claude.ai)) and reviewed by a human. All code is verified against the Rust reference implementation byte-for-byte, and tested with 26,000+ handshakes, 408 cross-implementation vectors, 1,452 NIST/PQC-Suite-B vectors, and 13 fuzz targets. The AI generated code; the human made every design decision, reviewed every line, and owns every bug.

## License

MIT - matching the upstream Rust Clatter license. See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for embedded dependencies.
