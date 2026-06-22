# go-clatter 🔊

[![Go Tests](https://github.com/shurlinet/go-clatter/actions/workflows/ci.yml/badge.svg)](https://github.com/shurlinet/go-clatter/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-clatter.svg)](https://pkg.go.dev/github.com/shurlinet/go-clatter)
[![Go Report Card](https://goreportcard.com/badge/github.com/shurlinet/go-clatter)](https://goreportcard.com/report/github.com/shurlinet/go-clatter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Post-quantum [Noise](https://noiseprotocol.org/noise.html) handshakes for Go. Implements the [PQNoise](https://eprint.iacr.org/2022/539) ([ACM CCS 2022](https://doi.org/10.1145/3548606.3560577), [alt](https://sci-net.xyz/10.1145/3548606.3560577)) extensions that replace classical DH key exchanges with quantum-resistant KEMs while preserving Noise's formal security guarantees.

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
* **Secret zeroing** - Every type holding secrets implements an explicit `Destroy()` method. Fixed-size secrets (cipher keys, chaining keys, PSKs) live in fixed-size arrays; variable-size KEM secrets live in heap slices that `Destroy()` zeroes in place. Callers must call `Destroy()` when keys are no longer needed.
* **Errors, not panics** - All error conditions return Go `error` values. Invalid inputs, state violations, and crypto failures are handled through Go's standard error pattern.
* **HKDF key derivation** - Manual HKDF implementation matching Noise spec (not a wrapper), with HMAC key length validation and full error propagation through HKDF2/HKDF3.
* **Concurrency safety** - Handshake objects detect concurrent use via atomic guards and return errors. Transport ciphers use independent nonce counters per direction.
* **Minimal dependencies** - Noise handshakes depend only on Go stdlib + `golang.org/x/crypto`. Signing modules add `filippo.io/mldsa` (ML-DSA) and embedded Trail of Bits engine (SLH-DSA).
* **Construction-time pattern validation** - `NewPattern` rejects malformed custom patterns up front against the Noise [section 7.3](https://noiseprotocol.org/noise.html#pattern-validity) well-formedness rules: token limits, at-most-once key and DH-calculation counts, key-availability precedence, and forward secrecy. The forward-secrecy check extends the classical Noise rule, which is defined for Diffie-Hellman, to post-quantum KEM patterns - a static-KEM seal must be complemented by an *achievable* ephemeral-KEM - derived from first principles, since the classical well-formedness rules predate the post-quantum setting. Scope is deliberately narrow and worth reading with the right lens: it is a construction-time check that changes no wire bytes, all 90 built-in patterns satisfy it, and no real handshake is affected. It exists to fail loud on a *hand-authored custom pattern* that would otherwise be built with a forward-secrecy footgun - high cryptographic rigor, low practical blast radius.
* **Loud rejection of inapplicable options** - each handshake family accepts only the options that apply to it. A KEM-typed option on a classical handshake, a dual-layer wrapper given static/ephemeral/prologue options, and similar mismatches are rejected at construction with `ErrInvalidOption` rather than silently ignored. Silent option-dropping is a security degradation (e.g. a dropped prologue stops binding the transcript); go-clatter fails closed instead.
* **Pre-set key validation** - pre-set keypairs (`WithStaticKey`, `WithEphemeralKey`, `WithStaticKEMKey`, `WithEphemeralKEMKey`, and remote variants) are length-checked at construction (`ErrInvalidKeyLength`), local keypairs are verified self-consistent (public re-derived from secret, constant-time compared), and remote KEM encapsulation keys are validated per [FIPS 203 §7.2](https://csrc.nist.gov/pubs/fips/203/final) before use. Setting the same slot twice under two names is a construction error.

## SEEC (Static-Ephemeral Entropy Combination)

SEEC hedges a handshake's randomness against a weak, predictable, or compromised RNG. It is the production-ready implementation of the construction from the [PQNoise paper](https://eprint.iacr.org/2022/539) (Definition 14, Appendix C). go-clatter is the first production PQNoise library to ship it.

**The guarantee.** Each coin SEEC produces stays unpredictable as long as *either* a long-lived 32-byte secret *or* the fresh per-call RNG draw is uncompromised (a NAXOS-style combination). An attacker who reads or predicts your RNG stream learns nothing about the coins without also holding the secret; an attacker who steals the secret learns nothing while your RNG is sound.

**Proven model, stated precisely.** The paper's theorems cover *revealed or predictable but still uniform* coins - an adversary who can see or predict the RNG output. Resistance to a *biased* (non-uniform) RNG is heuristic defense-in-depth here, not a proven property.

**Self-protective - the organizing principle.** SEEC protects the party that enables it, and only that party. Your secret hedges *your* coins: your ability to authenticate the peer if your RNG leaks, the confidentiality of your encapsulations, and your keygen seeds. It does **not** protect your authenticity *to* the peer - that rests on the peer's coins and the peer's SEEC. Enabling SEEC is therefore a unilateral, local decision ("turn it on for your own protection"), needing zero coordination. Protection in both directions requires both sides to enable it.

**What it rescues** (PQNoise paper, Table 2). Without SEEC, if the ephemeral randomness on *both* sides is corrupted while statics stay safe (the Maximal Exposure / MEX scenario), confidentiality is lost entirely and every authenticated PQ pattern loses its initiator/responder authenticity. With SEEC those rows recover to their normal stages. SEEC also brings confidentiality *earlier* for the X-family patterns (stage 2 with SEEC versus stage 4 without). And it benefits a static-keyless party: a party with no static KEM key can still hold a static SEEC key (an identity-independent secret), so `WithSEEC` is never coupled to having a static key.

**`pqNN` + bilateral SEEC, scoped.** With both parties holding SEEC secrets, the static-key-free `pqNN` pattern achieves MEX-resistant confidentiality - **against a passive adversary only.** `pqNN` has no authentication at any stage, so an active man-in-the-middle substitutes its own ephemeral and ciphertext and reads everything, both SEEC secrets notwithstanding. SEEC does not add MITM or active-attacker resistance to an unauthenticated pattern.

**Secrecy, not freshness.**

> SEEC hedges coin SECRECY, never coin FRESHNESS - under a repeating RNG, encapsulation coins repeat and ciphertexts become linkable even with the secret intact.

Under a single failure (the secret intact but the RNG repeating or rolled back), identical encapsulations appear on the wire - a linkability distinguisher plus shared-secret reuse - which is strictly worse than non-SEEC behavior on that one axis. SEEC defends the *predictability* of coins, not their *uniqueness*.

### Using SEEC

```go
// secret: 32 bytes, dedicated to SEEC, provisioned once and stored like a static key.
prf, err := clatter.NewSEECPRF(hash.NewSha256(), secret)
if err != nil {
    panic(err)
}
defer prf.Destroy()

// Enable it for your own party (here, the initiator). Transparent to the wire.
alice, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite, clatter.WithSEEC(prf))
```

See [`examples/seec/`](examples/seec/) (software) and [`examples/seec_yubikey/`](examples/seec_yubikey/) (hardware-backed).

Interaction with other options:

* **Pre-set ephemerals** (`WithEphemeralKey`, `WithEphemeralKEMKey`): a pre-set key skips keygen, so SEEC does not fire for that token - the encapsulation coins are still hedged.
* **`WithRNG`**: with SEEC on, the encapsulation path consumes the handshake RNG (see the inversion note below).
* **Dual-layer** (`DualLayerHandshake`, `HybridDualLayerHandshake`): `WithSEEC` is rejected with `ErrInvalidOption`, like the other inapplicable options on the wrappers. Apply SEEC to each layer's own constructor.
* **PSK**: orthogonal - SEEC hedges the e/ekem/encaps coins regardless of PSK modifiers.

### Definition 14 mapping

| PQNoise paper (Definition 14) | go-clatter |
|---|---|
| `GenKey(1^λ) -> sk` (long-lived secret) | `NewSEECPRF(hash, secret)` - the consumer supplies the 32-byte `sk` |
| `GenRand(sk, r) -> (rand, sk)` | `SEEC.GenRand(rng, purpose, n)` - `r` is drawn from the handshake RNG at call time |
| long-term key `sk`, reused across sessions | the consumer's 32-byte secret, shared across handshakes |
| (no coin-purpose separation) | `SEECPurpose` (keygen vs. encapsulation) - a deliberate go-clatter strengthening |

The `SEECPRF` construction is RFC 5869 Extract-then-Expand with a per-call re-key over the library's HMAC. A `SEECPRF` is safe for concurrent use by many handshakes - one shared long-lived instance per process or identity is the paper's model. Coin draws wider than 255 bytes are composed from multiple `GenRand` calls (each with fresh `r`); custom KEM implementations that need wide draws inherit this contract.

### Secret lifecycle and FIPS caveats

* **RAM residence (honest).** A software SEEC secret lives in process memory. It hedges revealed or predictable RNG output; it does **not** defend host compromise - an attacker who can read process memory reads the secret too. `Destroy()` zeroing is best-effort (the Go runtime may have copied the underlying memory).
* **`GODEBUG=fips140=only` is incompatible with the library as a whole**, SEEC or not. Noise's deterministic counter nonces are rejected by FIPS-mode GCM ("use of GCM with arbitrary IVs is not allowed in FIPS 140-only mode") and ChaCha20-Poly1305 is not FIPS-approved, so no handshake completes in that mode. With SEEC on, external-coin ML-KEM encapsulation additionally fails mid-handshake under `fips140=only`.
* **`mlkemtest` is a known-answer-test API.** External-coin ML-KEM encapsulation uses `crypto/mlkem/mlkemtest`, which the standard library documents as for known-answer tests only, with no compatibility promise. go-clatter uses it deliberately - it is the only stdlib path to deterministic ML-KEM coins - and isolates it behind the per-KEM `CoinsEncapsulator` interface plus a CI canary, so a future stdlib change breaks loudly and is localized to the ML-KEM adapter. HQC's external-coin path is a first-class production API and is unaffected.
* **`WithRNG` inversion.** Normally production encapsulation ignores `WithRNG`. With SEEC on, the encapsulation path consumes the handshake RNG, so a misused `WithRNG` (a low-entropy or repeating reader) now feeds SEEC - and per the freshness limit above, a single failure (intact secret, repeating RNG) already yields linkable wire ciphertexts.

### Hardware seam (consumer-side, never a dependency)

The `SEEC` interface *is* the hardware seam. go-clatter ships no hardware code; a consumer implements `GenRand` backed by a non-extractable on-device PRF. [`examples/seec_yubikey/`](examples/seec_yubikey/) is a runnable worked example backed by a YubiKey HMAC-SHA1 challenge-response slot through the `ykman` CLI - no Go dependency, the library never imports it.

Recommended deployment: **boot-derive.** Use the token once at startup to derive a 32-byte software SEEC secret, then run software SEEC at full speed. The token gates startup, not every handshake.

* **Per-handshake hardware SEEC** means one device round-trip (and one touch, if the slot is touch-required) per coin draw - one to four per PQ handshake. A serial USB token caps the whole node at a few handshakes per second. That fits a low-frequency interactive endpoint; it is the wrong design for a headless or high-throughput node.
* **Graceful degradation is the first rule: never make hardware SEEC a critical path.** Losing the token must fall back to RNG-only (normal non-SEEC security), not brick handshakes. SEEC is opt-in hedging.
* **YubiKey HMAC-SHA1 specifics.** The 20-byte slot secret is a 160-bit cap on secret-side entropy (HKDF adds none). HMAC-SHA1's PRF security does not rest on SHA-1 collision resistance - this is deliberate, not naive. Pin one challenge mode at provisioning: variable-length and fixed-64 challenges produce different responses for the same input. A 160-bit secret gives roughly 80-bit security against a quantum key-search adversary, below the 128-bit post-quantum floor the rest of the system clears - for quantum-durable hardware SEEC prefer a ≥256-bit HMAC slot (HMAC-SHA-256 / PIV-HMAC on newer tokens). The architecture needs no change for this: `GenRand` is a consumer `io.Reader` and a wider hardware PRF drops in. Device-generated secrets are genuinely non-extractable but un-backupable; user-loaded secrets are backupable onto a second token but exist off-device at provisioning - pick one.
* **macOS note.** `ykman otp` is silently blocked with `kIOReturnNotPermitted` until the host application is granted Input Monitoring permission (the OTP slot enumerates as a keyboard HID).

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

alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
    clatter.WithPrologue([]byte("my-app/v1")),
)
if err != nil {
    panic(err)
}

// Hybrid handshake (quantum-resistant)
hybridSuite := clatter.CipherSuite{
    DH:     dh.NewX25519(),
    EKEM:   kem.NewMlKem768(),
    SKEM:   kem.NewMlKem768(),
    Cipher: cipher.NewChaChaPoly(),
    Hash:   hash.NewSha256(),
}

alice, err = clatter.NewHybridHandshake(clatter.PatternHybridXX, true, hybridSuite,
    clatter.WithStaticKey(aliceDHKeys),
    clatter.WithStaticKEMKey(aliceKEMKeys),
    clatter.WithPrologue([]byte("my-app/v1")),
)
if err != nil {
    panic(err)
}
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

alice, err := clatter.NewPqHandshake(clatter.PatternPqXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
)
if err != nil {
    panic(err)
}
```

Without the build tag, HQC code is not compiled (zero binary bloat). Without `AllowExperimental`, every KEM operation returns `ErrExperimentalNotAllowed`. Both gates will be relaxed as HQC progresses through FIPS standardization.

### ML-DSA-65 Signing

```go
import "github.com/shurlinet/go-clatter/crypto/sign/mldsa65"

// Generate a key pair.
sk, err := mldsa65.GenerateKey()
if err != nil {
    panic(err)
}
defer sk.Destroy() // zeros seed on cleanup

// Sign (hedged randomness - recommended for production).
sig, err := sk.Sign([]byte("message to sign"))
if err != nil {
    panic(err)
}

// Verify.
ok := sk.PublicKey().Verify([]byte("message to sign"), sig)

// Context separation prevents cross-purpose replay.
sig, err = sk.SignWithContext([]byte("data"), "my-app/transfers/v1")
if err != nil {
    panic(err)
}
ok = sk.PublicKey().VerifyWithContext([]byte("data"), sig, "my-app/transfers/v1")

// Seed export/import for key persistence.
seed, err := sk.Seed() // 32 bytes - store securely
if err != nil {
    panic(err)
}
sk2, err := mldsa65.NewPrivateKeyFromSeed(seed) // reconstruct later
if err != nil {
    panic(err)
}
defer sk2.Destroy()
```

### SLH-DSA Signing

```go
import "github.com/shurlinet/go-clatter/crypto/sign/slhdsa"

// Generate a key pair (SHA2-128f: fastest FIPS 205 param set).
priv, err := slhdsa.GenerateKey(slhdsa.SHA2_128f)
if err != nil {
    panic(err)
}
defer priv.Destroy()

// Sign (hedged randomness - recommended for production).
sig, err := priv.SignMessage([]byte("message"))
if err != nil {
    panic(err)
}

// Verify.
ok := priv.PublicKey().Verify([]byte("message"), sig)

// BLAKE3 variant (non-FIPS, faster on x86 with SIMD).
// Same API, just a different ParamSet constant.
privB, err := slhdsa.GenerateKey(slhdsa.BLAKE3_128f)
if err != nil {
    panic(err)
}
defer privB.Destroy()
sigB, err := privB.SignMessage([]byte("blake3 message"))
if err != nil {
    panic(err)
}
ok = privB.PublicKey().Verify([]byte("blake3 message"), sigB)

// Pre-hash mode for large files (SHA2/SHAKE param sets only).
largeFile := []byte("contents of a large file")
sig, err = priv.SignPreHash(largeFile, slhdsa.HashSHA2_256)
if err != nil {
    panic(err)
}
ok = priv.PublicKey().VerifyPreHash(largeFile, sig, slhdsa.HashSHA2_256)
```

18 parameter sets available. See the [SLH-DSA godoc](https://pkg.go.dev/github.com/shurlinet/go-clatter/crypto/sign/slhdsa) for the full API and parameter set guide.

`*PrivateKey` also implements the standard [`crypto.Signer`](https://pkg.go.dev/crypto#Signer) interface for use with generic signing consumers: `Sign(rand, digest, opts)` treats `digest` as the pre-computed pre-hash and uses it directly with no re-hashing, honors `rand` (falling back to `crypto/rand` when nil), and reports the matching hash via `HashFunc()`. `ParsePublicKey` distinguishes its malformed-input causes (wrong size, unknown parameter set) under the `ErrInvalidPublicKey` umbrella, reachable via `errors.Is`.

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

alice, err := clatter.NewNqHandshake(clatter.PatternXX, true, suite,
    clatter.WithStaticKey(aliceKeys),
    clatter.WithObserver(&myObserver{}),
)
if err != nil {
    panic(err)
}
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
| [`examples/seec/`](examples/seec/) | SEEC randomness hedging with a software secret |
| [`examples/seec_yubikey/`](examples/seec_yubikey/) | Hardware-backed SEEC via a YubiKey HMAC-SHA1 slot (`ykman`, no Go dependency) |
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
* **Provision the SEEC secret carefully** if you enable randomness hedging. Use 32 bytes from a trusted source, dedicate them to SEEC (do not reuse a static or identity key), and store them with the same protection as a static identity key. Call `Destroy()` on the `SEECPRF` when retiring it. A `SEECPRF` is safe to share across concurrent handshakes - that shared, long-lived instance is the model SEEC's security is proven under.

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
| pqKN / pqNK naming | Distinct patterns, per the PQNoise paper (Figure 2) | `noise_pqkn()` mislabels its pattern "pqNK", shipping two patterns under one name |
| Low-order X25519 input | Rejected with `ErrDHLowOrder` (Noise spec section 4.1 option 2) | Continues with all-zero shared secret (option 1; both are spec-compliant, divergence only on adversarial input) |
| SEEC randomness hedging | Supported (first production PQNoise library to ship it) | Not implemented (Rust Clatter README: "Clatter does not currently implement SEEC") |
| Inapplicable handshake options | Rejected at construction (`ErrInvalidOption`) | N/A (generic types make most mismatches a compile error) |
| `crypto.Signer` conformance (SLH-DSA) | `Sign` conforms to the standard `crypto.Signer` contract (pre-hash digest used directly, `rand` honored) | Not in scope |

## Deviations from nyquist (the SEEC reference)

The PQNoise paper's own Go artifact, [nyquist](https://github.com/Yawning/nyquist), ships a reference SEEC implementation. go-clatter's differs deliberately:

| Aspect | go-clatter | nyquist |
|--------|-----------|---------|
| PRF construction | RFC 5869 HKDF with a per-call re-key over the library's HMAC | TupleHash (SP 800-185 cSHAKE) |
| Secret residence | Consumer-supplied, long-lived, shared across handshakes (the paper's "long-term key" model) | A fresh per-handshake key sampled from the same RNG SEEC is hedging |
| Coin purpose separation | Domain-separated (`SEECPurpose`: keygen vs. encapsulation) | None |
| DH ephemeral keygen | Hedged | Not hedged (KEM coins only) |
| Wide-block PRP-SEEC variant | Not ported (avoids extra dependencies); the `SEEC` interface seam carries it for consumers who want it | Ported (EME wide-block) |
| Secret zeroing | `Destroy()` zeroes the PRF key | None |
| Encapsulation coins | Threaded through an optional per-KEM `CoinsEncapsulator` interface, leaving the KEM interface clean | Threaded through the KEM interface itself |

Choosing HKDF over TupleHash also sidesteps a real SP 800-185 conformance defect in nyquist's pinned `x/crypto` `cSHAKE`: at sponge-rate-aligned customization-string lengths its `bytepad` absorbs a spurious zero block, so a conformant TupleHash would derive different SEEC coins at those boundaries. go-clatter is immune by construction.

## Verification

go-clatter is verified by:

* Unit tests across all packages
* [Smoke tests](smoke_test.go) - 26,112 handshakes across all pattern/cipher/hash/KEM combinations (NQ + PQ + Hybrid + DualLayer + HybridDualLayer)
* [Property tests](maxmsglen_property_test.go) - All 90 patterns verified with independent overhead calculator, per-message runtime cross-check, actual-bytes-written oracle, constructor boundary validation, and transport enforcement
* [HQC smoke tests](smoke_hqc_test.go) - PQ (all 3 param sets), Hybrid, DualLayer, mixed KEM, experimental gate, and mid-handshake toggle tests (build tag `hqc`)
* [HQC property tests](maxmsglen_hqc_property_test.go) - All 90 patterns verified with HQC-128 overhead calculator (build tag `hqc`)
* [Fuzz tests](fuzz_test.go) - 9 Noise fuzz targets matching Rust Clatter + 1 SEEC PRF fuzz target (`FuzzSEECPRF`) + 1 [HQC fuzz](smoke_hqc_test.go) (build tag `hqc`) + 2 SLH-DSA fuzz targets (sign-verify round-trip + loader crash resistance)
* [MaxMsgLen fuzz](maxmsglen_fuzz_test.go) - Boundary sharpness verification across 3 patterns (NQ, PQ, Hybrid) covering all message count shapes
* [Cacophony](https://github.com/haskell-cryptography/cacophony) and [Snow](https://github.com/mcginty/snow) test vectors - 408 cross-implementation vectors verified byte-for-byte ([vectors/](vectors/))
* 10 Rust interop vectors generated from Rust Clatter with deterministic RNG, all verified byte-for-byte including the DualLayer and HybridDualLayer composites (wire bytes, per-message handshake hashes, and transport ciphertexts)
* [SEEC tests](handshake_seec_vector_test.go) - 3 SEEC-on handshake vector files (pqXX, pqNNpsk2, hybridXX) pinned and verified byte-for-byte, 8 hardcoded `SEECPRF` regression vectors generated through an independent HKDF path that references no library constant, and a blind-oracle check that SEEC-on coins differ from SEEC-off at an identical RNG seed
* [NIST ACVP vectors](crypto/sign/slhdsa/testdata/acvp/) - 1,260 SLH-DSA test vectors (keygen + sigGen + sigVer) across all 12 FIPS 205 parameter sets including pre-hash mode
* [NIST ACVP ML-DSA vectors](crypto/sign/mldsa65/testdata/acvp/) - ML-DSA-65 keyGen verified seed-to-public-key byte-for-byte plus sigVer including all NIST negative cases (modified message, commitment, z, hint)
* [PQC Suite B BLAKE3 vectors](crypto/sign/slhdsa/testdata/blake3/) - 192 cross-implementation vectors for all 6 BLAKE3 parameter sets

```
make test
```

Or equivalently: `go test -race -count=1 -timeout 30m ./...`

The SLH-DSA package includes 1,452 ACVP/BLAKE3 vectors across all 18 parameter sets. The `-s` (small signature) variants build deep hypertrees and take 15+ minutes with `-race` on Apple Silicon, longer on CI runners. The default Go timeout of 10 minutes is not enough. The Makefile ensures the correct flags are always used. CI uses a 90-minute timeout for the slhdsa package to account for slower shared runners.

## Post-Quantum Boundaries

These are boundaries of the **PQNoise paper and the Noise framework**, not of go-clatter specifically - Rust Clatter and nyquist inherit the same ones, since they implement the same protocols. Documented so they are not future surprises. Where a boundary has a go-clatter-specific *expression* (an API shape or extension seam), that is noted explicitly.

* **Identity is KEM-possession, not signatures** (PQNoise paper). PQNoise authenticates a party by its possession of a static KEM key; the paper defines no signature-based identity, and the Noise framework itself has none - so no faithful implementation (Rust Clatter, nyquist) has signature authentication in the handshake. *go-clatter expression:* `CipherSuite` is a struct with `DH`/`EKEM`/`SKEM`/`Cipher`/`Hash` slots and no `SIG` slot; that slot is the named extension point if a future post-quantum PKI converges on signature identity. The standalone `mldsa65`/`slhdsa` modules sign *outside* the tunnel, not in-handshake.
* **Hybrid is DH+KEM, not KEM+KEM** (PQNoise paper / Clatter family). The paper's Hybrid mode combines a classical DH leg with a PQ KEM leg; go-clatter ported Rust Clatter's hybrid byte-for-byte, so both are identical here. A single-round-trip PQ+PQ composition (two independent KEMs, e.g. ML-KEM ⊕ HQC for algorithm diversity) is not expressible in one Hybrid handshake in either - the classical leg is `DH`-typed. PQ+PQ diversity is available now via the dual-layer construct (present in both ports) at the cost of two stacked handshakes. *go-clatter expression:* the `DH`-typed leg in `CipherSuite` is the extension seam.
* **NQ has no quantum resistance** (classical X25519, true everywhere). Classical handshakes fall to a quantum adversary in any implementation; this is a property of X25519, not of go-clatter. There is no downgrade *attack* - suites are fixed at construction and Noise mixes the protocol name into the transcript, so a cross-suite handshake fails to decrypt rather than silently weakening (a Noise-framework property, shared by all). The only risk is misconfiguration: choosing NQ when you need PQ. Use PQ or Hybrid for forward-secure deployments.

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

Thanks to the authors of [Post-Quantum Noise](https://eprint.iacr.org/2022/539) (IACR ePrint 2022/539, the full version) for the foundational research this library implements. Special thanks to [Yawning Angel](https://github.com/Yawning) - a co-author of that paper and the author of [nyquist](https://github.com/Yawning/nyquist), the Go Noise implementation whose construction-time pattern-validation model guided go-clatter's Noise section 7.3 well-formedness hardening.

Thanks to [Filippo Valsorda](https://filippo.io) for [`filippo.io/mldsa`](https://pkg.go.dev/filippo.io/mldsa) - the ML-DSA implementation that powers our signing module. Filippo maintains Go's cryptography standard library and designed this package as the direct precursor to `crypto/mldsa`. His work gives the Go ecosystem production-ready post-quantum signatures years before the stdlib ships them.

Thanks to [Trail of Bits](https://trailofbits.com) for [go-slh-dsa](https://github.com/trailofbits/go-slh-dsa) - the SLH-DSA engine embedded in our signing module. Their implementation is pure Go, side-channel resistant, and covers all 12 FIPS 205 parameter sets.

Thanks to [JP Aumasson](https://aumasson.jp), [Zooko Wilcox-O'Hearn](https://grokipedia.com/page/Zooko_Wilcox-O'Hearn), and Alex Pruden for [PQC Suite B](https://github.com/PQC-Suite-B/) - the BLAKE3 variant research and test vectors that validate our BLAKE3 parameter sets.

Thanks to [Luke Champine](https://github.com/lukechampine) for [lukechampine.com/blake3](https://github.com/lukechampine/blake3) - the BLAKE3 implementation with SIMD acceleration for amd64 and arm64.

## AI Transparency

This Go port was written with AI assistance ([Claude](https://claude.ai)) and reviewed by a human. All code is verified against the Rust reference implementation byte-for-byte, and tested with 26,000+ handshakes, 408 cross-implementation vectors, 1,452 NIST/PQC-Suite-B vectors, and 14 fuzz targets. The AI generated code; the human made every design decision, reviewed every line, and owns every bug.

## License

MIT - matching the upstream Rust Clatter license. See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) for embedded dependencies.
