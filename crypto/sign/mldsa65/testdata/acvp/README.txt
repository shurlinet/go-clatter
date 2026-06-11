NIST ACVP ML-DSA Test Vectors (ML-DSA-65 subset)

Source: https://github.com/usnistgov/ACVP-Server
        commit 15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0 (2026-04-16)
        gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
        gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json
License: Public domain (U.S. Government work)

Files (filtered from the originals, test case fields unmodified):
  keygen.json - ML-DSA-65 key generation vectors (25 tests).
                Filter: parameterSet == ML-DSA-65.
  sigVer.json - ML-DSA-65 signature verification vectors (15 tests:
                3 valid, 12 negative across modified message, modified
                commitment, modified z, and modified hint).
                Filter: parameterSet == ML-DSA-65, preHash == pure,
                signatureInterface == external, externalMu == false
                (this package wraps the pure, non-pre-hash interface).

The ACVP sigGen vectors are NOT included: they provide only the expanded
secret key, and this package's API deliberately exposes seed-only key
import (NewPrivateKeyFromSeed). Signature generation is anchored by
mldsa65_acvp_test.go signing under NIST keyGen-derived keys and verifying
against the NIST-provided public keys, plus the package's deterministic
regression vectors.

See THIRD_PARTY_LICENSES in the repository root for full license details.
