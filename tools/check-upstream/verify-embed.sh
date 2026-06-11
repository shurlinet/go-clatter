#!/bin/bash
# verify-embed.sh - Verifies embedded Trail of Bits source matches upstream commit.
#
# Clones the upstream repo at the recorded commit, strips our documented
# modifications (header comments + Zero() method), and diffs against upstream.
# Any unexpected differences indicate either an undocumented modification or
# a supply chain issue.
#
# Usage: ./tools/check-upstream/verify-embed.sh
#
# Exit codes:
#   0 - embedded code matches upstream (only documented modifications)
#   1 - unexpected differences found

set -euo pipefail

UPSTREAM_REPO="https://github.com/trailofbits/go-slh-dsa"
UPSTREAM_COMMIT="15ed0951bd833dd5699dcceddaf614826e3fcb14"
EMBEDDED_DIR="crypto/sign/slhdsa/internal"
UPSTREAM_SUBDIR="slh_dsa/internal"

# Find repo root from the script's own location, NOT the caller's cwd:
# invoked from outside the repo, cwd-based resolution silently diffs
# against the wrong tree (or none at all).
REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "=== Verify Embedded Code ==="
echo "Upstream: $UPSTREAM_REPO @ $UPSTREAM_COMMIT"
echo "Embedded: $EMBEDDED_DIR"
echo ""

# Clone upstream at exact commit
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Cloning upstream at recorded commit..."
git clone --quiet "$UPSTREAM_REPO" "$TMPDIR/upstream" 2>/dev/null
cd "$TMPDIR/upstream"
git checkout --quiet "$UPSTREAM_COMMIT"
cd "$REPO_ROOT"

echo "Comparing files..."
echo ""

FAILURES=0
FILES=(types.go slh_dsa.go utility.go fors.go hypertree.go wotsplus.go xmss.go mgf1.go)

for f in "${FILES[@]}"; do
    UPSTREAM_FILE="$TMPDIR/upstream/$UPSTREAM_SUBDIR/$f"
    EMBEDDED_FILE="$EMBEDDED_DIR/$f"

    if [ ! -f "$UPSTREAM_FILE" ]; then
        echo "  ERROR: $f not found in upstream at $UPSTREAM_COMMIT"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    if [ ! -f "$EMBEDDED_FILE" ]; then
        echo "  ERROR: $f not found in embedded directory"
        FAILURES=$((FAILURES + 1))
        continue
    fi

    # Strip our go-clatter header from embedded file (lines starting with // before package)
    # and the Zero() method we added to slh_dsa.go
    STRIPPED="$TMPDIR/stripped_$f"
    if [ "$f" = "slh_dsa.go" ]; then
        # Remove header comments + Zero() method block. The Zero() block
        # sits mid-file with a separating blank line on each side, so the
        # removal must also consume ONE adjacent blank line or the
        # stripped file keeps a doubled blank where upstream has one.
        sed '/^\/\/ Originally from/,/^$/d' "$EMBEDDED_FILE" | \
        awk '
            /^\/\/ Zero zeros all secret material/ { inblock = 1 }
            inblock && /^}$/ { inblock = 0; skipblank = 1; next }
            inblock { next }
            skipblank && /^$/ { skipblank = 0; next }
            { skipblank = 0; print }
        ' > "$STRIPPED"
    else
        # Remove header comments only (everything before "package internal")
        sed '/^\/\/ Originally from/,/^$/d' "$EMBEDDED_FILE" > "$STRIPPED"
    fi

    # Normalize trailing blank lines on both sides before diffing: the
    # Zero() method is appended after a separating blank line, and the
    # block strip above leaves that blank behind, which is whitespace,
    # not a code difference. ($(<file) drops trailing newlines.)
    NORM_UPSTREAM="$TMPDIR/norm_upstream_$f"
    printf '%s\n' "$(<"$UPSTREAM_FILE")" > "$NORM_UPSTREAM"
    printf '%s\n' "$(<"$STRIPPED")" > "$STRIPPED.norm"

    DIFF=$(diff "$NORM_UPSTREAM" "$STRIPPED.norm" || true)

    if [ -z "$DIFF" ]; then
        echo "  OK: $f (matches upstream)"
    else
        DIFF_LINES=$(echo "$DIFF" | grep -c "^[<>]" || true)
        echo "  DIFF: $f ($DIFF_LINES lines differ)"
        if [ "$DIFF_LINES" -le 10 ]; then
            echo "$DIFF"
        else
            echo "  (showing first 10 differing lines)"
            echo "$DIFF" | grep "^[<>]" | head -10
        fi
        echo ""
        FAILURES=$((FAILURES + 1))
    fi
done

echo ""
if [ $FAILURES -eq 0 ]; then
    echo "RESULT: All embedded files match upstream (documented modifications only)."
    exit 0
else
    echo "RESULT: $FAILURES file(s) have unexpected differences."
    echo "Review diffs above. If modifications are intentional, document them in UPSTREAM.md."
    exit 1
fi
