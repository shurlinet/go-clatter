# check-upstream

Supply chain integrity tools for go-clatter's embedded dependencies.

## Tools

### `go run ./tools/check-upstream/`

Queries each upstream repository recorded in `UPSTREAM.md` for its current HEAD commit. Reports whether any upstream has moved ahead of our embedded/copied version.

Also updates the "Last checked" dates in `UPSTREAM.md` automatically.

**When to run:**
- Before every go-clatter release
- At the start of every SLH-DSA development session
- After any security advisory affecting dependencies

**Exit codes:**
- `0` - all upstreams up to date
- `1` - updates available or errors occurred

### `./tools/check-upstream/verify-embed.sh`

Clones the Trail of Bits go-slh-dsa repository at the exact commit recorded in `UPSTREAM.md`, strips our documented modifications (header comments + Zero() method), and diffs against our embedded files byte-for-byte.

Proves no undocumented changes were introduced to the embedded engine code.

**When to run:**
- Before every release (supply chain verification)
- If you suspect tampering or want to audit the embed

**Exit codes:**
- `0` - embedded code matches upstream (only documented modifications)
- `1` - unexpected differences found

## What Gets Checked

| Upstream | What | Location |
|----------|------|----------|
| Trail of Bits go-slh-dsa | SLH-DSA engine (8 .go files) | `crypto/sign/slhdsa/internal/` |
| PQC Suite B signatures | BLAKE3 test vectors (3 JSON files) | `crypto/sign/slhdsa/testdata/blake3/` |
| NIST ACVP-Server | FIPS 205 test vectors (3 JSON files) | `crypto/sign/slhdsa/testdata/acvp/` |

## If Updates Are Found

1. **Security fixes**: port immediately, same session
2. **Performance improvements**: evaluate and port if relevant
3. **API changes**: assess wrapper impact, port if beneficial
4. Update the embedded commit hash in `UPSTREAM.md` after porting
