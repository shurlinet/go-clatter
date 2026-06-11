# Upstream Dependencies

Embedded and vendored code tracked for security fixes and updates.

## Trail of Bits go-slh-dsa

- **Repo:** https://github.com/trailofbits/go-slh-dsa
- **Embedded commit:** 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
- **Embedded into:** crypto/sign/slhdsa/internal/
- **License:** BSD-3-Clause
- **Files:** types.go, slh_dsa.go, utility.go, fors.go, hypertree.go, wotsplus.go, xmss.go, mgf1.go
- **Modifications:** Package path changed, Zero() method added to SLHSecretKey, nil guard on Zero()
- **Last checked:** 2026-06-11

## PQC Suite B SLH-DSA-B Test Vectors

- **Repo:** https://github.com/PQC-Suite-B/signatures
- **Vector commit:** b392fe82d2d9770142477a576a758a233888bc0a (2025-11-07)
- **Copied into:** crypto/sign/slhdsa/testdata/blake3/
- **License:** Apache-2.0 OR MIT
- **Files:** blake3_keygen.json, blake3_sig.json, blake3_ver.json
- **Last checked:** 2026-06-11

## NIST ACVP-Server SLH-DSA Vectors

- **Repo:** https://github.com/usnistgov/ACVP-Server (via Trail of Bits KAT/)
- **Vector commit:** obtained from Trail of Bits go-slh-dsa KAT/ at commit 15ed0951bd833dd5699dcceddaf614826e3fcb14; the originating ACVP-Server commit was not recorded by upstream. Vectors are static NIST test data; integrity is anchored by the 1,260 tests passing.
- **Copied into:** crypto/sign/slhdsa/testdata/acvp/
- **License:** Public domain (U.S. Government work)
- **Files:** keygen.json, sigGen.json, sigVer.json
- **Last checked:** 2026-06-11

## NIST ACVP-Server ML-DSA Vectors

- **Repo:** https://github.com/usnistgov/ACVP-Server
- **Vector commit:** 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0 (2026-04-16)
- **Copied into:** crypto/sign/mldsa65/testdata/acvp/
- **License:** Public domain (U.S. Government work)
- **Files:** keygen.json (ML-DSA-65 subset), sigVer.json (ML-DSA-65 pure/external subset); filter documented in the testdata README
- **Last checked:** 2026-06-11
