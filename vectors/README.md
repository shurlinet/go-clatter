# Noise Test Vectors

Cross-implementation verification vectors for go-clatter.

## Vector Sources

- **cacophony.txt** (34,851 lines) - From the Haskell [Cacophony](https://github.com/centromere/cacophony) project. 944 vectors covering all standard Noise patterns with X25519, Curve448, AES-GCM, ChaChaPoly, SHA-256, SHA-512, BLAKE2s, BLAKE2b.

- **snow.txt** (10,347 lines) - From the Rust [Snow](https://github.com/mcginty/snow) project. 408 vectors with a different set of key/prologue values.

- **Rust interop vectors** (10 .txt files) - Generated from Rust Clatter v2.2.0 with DummyRng(0xdeadbeef). Cover NQ, PQ, Hybrid, DualLayer, and HybridDualLayer handshakes. Byte-for-byte match between Go and Rust implementations.

## What Gets Verified

Each vector contains pre-set keys (ephemeral, static, remote static, PSKs), prologues, and expected ciphertext for every handshake message plus transport messages. The test harness:

1. Parses the protocol name to select pattern, cipher, and hash
2. Constructs both initiator and responder with exact keys from the vector
3. Runs each message: write on sender, verify ciphertext byte-for-byte, read on receiver, verify payload
4. After handshake: verifies handshake hash matches vector
5. Runs transport messages with the same byte-for-byte ciphertext verification

## Skipped Vectors

- **Curve448**: No Go stdlib implementation (same as Rust Clatter)
- **Deferred/fallback patterns**: Not implemented (same as Rust Clatter)

## Running

```
go test ./vectors/ -v
```
