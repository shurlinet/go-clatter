# go-clatter 🔊

[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-clatter.svg)](https://pkg.go.dev/github.com/shurlinet/go-clatter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Post-quantum [Noise](https://noiseprotocol.org/noise.html) handshakes for Go. Implements the [PQNoise](https://doi.org/10.1145/3548606.3560577) ([alt](https://sci-net.xyz/10.1145/3548606.3560577)) extensions (ACM CCS 2022) that replace classical DH key exchanges with quantum-resistant KEMs while preserving Noise's formal security guarantees.

Ported from [Rust Clatter v2.2.0](https://github.com/jmlepisto/clatter) by [Joni Lepisto](https://github.com/jmlepisto) and verified against it byte-for-byte. Built on Go stdlib crypto (`crypto/mlkem`, `crypto/ecdh`) with `golang.org/x/crypto` for ChaCha20-Poly1305 and BLAKE2. No other external dependencies. All secret key material lives in fixed-size arrays with explicit `Destroy()` zeroing.

⚠️ **Warning** ⚠️

* This library has not received any formal audit
* While we use Go's standard library cryptographic primitives, it is up to **you** to evaluate whether they meet your security and integrity requirements
* Post-quantum cryptography is not as established as classical cryptography. Users are encouraged to use hybrid handshakes (`HybridHandshake`, `HybridDualLayerHandshake`) that combine classical and post-quantum primitives for defense in depth
* This Go port was written with AI assistance ([Claude](https://claude.ai)) and reviewed by a human. All code is verified against the Rust reference implementation byte-for-byte, and tested with 13,000+ handshakes, 408 cross-implementation vectors, and 9 fuzz targets. The AI generated code; the human made every design decision, reviewed every line, and owns every bug.

📖 **Documentation** 📖

* [`pkg.go.dev`](https://pkg.go.dev/github.com/shurlinet/go-clatter) - API reference and type docs
* [`examples/`](examples/) - Runnable examples for every handshake type, observer callbacks, and ML-DSA-65 signing

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

91 handshake patterns. 4 hash functions. 2 AEAD ciphers. 2 KEM sizes.

## Post-Quantum Signing

* **ML-DSA-65** (`crypto/sign/mldsa65`) - FIPS 204 digital signatures (NIST Level 3, ~192-bit security)

Standalone signing module. Not integrated into the Noise handshake - this is a general-purpose signing primitive for application-layer use (agent identity cards, capability tokens, signed manifests, relay admin commands, or any use case requiring post-quantum signatures).

Key sizes: Seed = 32 bytes, Public Key = 1952 bytes, Signature = 3309 bytes.

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
* **ML-DSA-65 signing module** - go-clatter extends beyond handshakes with a standalone FIPS 204 post-quantum signature primitive (`crypto/sign/mldsa65`). Rust Clatter does not include a signing module. This gives Go consumers a complete PQ toolkit in one repository: quantum-resistant key exchange (ML-KEM) AND quantum-resistant signatures (ML-DSA) under one roof.

## Verification

go-clatter is verified by:

* Unit tests across all packages
* [Smoke tests](smoke_test.go) - 13,632 handshakes across all pattern/cipher/hash/KEM combinations
* [Fuzz tests](fuzz_test.go) - 9 fuzz targets matching Rust Clatter's fuzz suite
* [Cacophony](https://github.com/haskell-cryptography/cacophony) and [Snow](https://github.com/mcginty/snow) test vectors - 408 cross-implementation vectors verified byte-for-byte ([vectors/](vectors/))
* 10 Rust interop vectors generated from Rust Clatter with deterministic RNG

```
go test -race -count=1 ./...
```

## Dependencies

* Go 1.26+ (required for `crypto/mlkem`)
* `golang.org/x/crypto` (ChaCha20-Poly1305, BLAKE2)
* [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) (ML-DSA-65 signing) - This is the pre-release of Go's upcoming `crypto/mldsa` stdlib package, maintained by [Filippo Valsorda](https://filippo.io) who leads Go's cryptography standard library. The API is designed to be identical to the stdlib version. When `crypto/mldsa` lands in a future Go release (proposal [#77626](https://github.com/golang/go/issues/77626) accepted), the migration is a single import path change with zero code modifications for consumers of this package.

## Acknowledgments

Special thanks to [Joni Lepisto](https://github.com/jmlepisto) for creating [Rust Clatter](https://github.com/jmlepisto/clatter). His clean, well-tested implementation made this Go port possible and his test infrastructure (interop vectors, smoke tests, fuzz targets) set the standard we verify against.

Thanks also to the projects whose test vector datasets we use to verify correctness:

* [Cacophony](https://github.com/haskell-cryptography/cacophony) (Haskell Noise implementation) - 944 test vectors
* [Snow](https://github.com/mcginty/snow) (Rust Noise implementation) - 408 test vectors

And to the authors of the PQNoise paper for the foundational research this library implements.

Thanks to [Filippo Valsorda](https://filippo.io) for [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) - the ML-DSA implementation that powers our signing module. Filippo maintains Go's cryptography standard library and designed this package as the direct precursor to `crypto/mldsa`. His work gives the Go ecosystem production-ready post-quantum signatures years before the stdlib ships them.

## License

MIT - matching the upstream Rust Clatter license.
