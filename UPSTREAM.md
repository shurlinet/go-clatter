# Upstream Dependencies

Embedded and vendored code tracked for security fixes and updates.

## Trail of Bits go-slh-dsa

- **Repo:** https://github.com/trailofbits/go-slh-dsa
- **Embedded commit:** 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
- **Embedded into:** crypto/sign/slhdsa/internal/
- **License:** BSD-3-Clause
- **Files:** types.go, slh_dsa.go, utility.go, fors.go, hypertree.go, wotsplus.go, xmss.go, mgf1.go
- **Modifications:** Package path changed, Zero() method added to SLHSecretKey, nil guard on Zero()
- **Last checked:** 2026-05-07

## PQC Suite B SLH-DSA-B Test Vectors

- **Repo:** https://github.com/PQC-Suite-B/signatures
- **Vector commit:** b392fe82d2d9770142477a576a758a233888bc0a (2025-11-07)
- **Copied into:** crypto/sign/slhdsa/testdata/blake3/
- **License:** Apache-2.0 OR MIT
- **Files:** blake3_keygen.json, blake3_sig.json, blake3_ver.json
- **Last checked:** 2026-05-07

## NIST ACVP-Server SLH-DSA Vectors

- **Repo:** https://github.com/usnistgov/ACVP-Server (via Trail of Bits KAT/)
- **Copied into:** crypto/sign/slhdsa/testdata/acvp/
- **License:** Public domain (U.S. Government work)
- **Files:** keygen.json, sigGen.json, sigVer.json
- **Last checked:** 2026-05-07
