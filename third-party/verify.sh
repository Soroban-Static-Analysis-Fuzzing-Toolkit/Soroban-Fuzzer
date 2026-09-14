#!/usr/bin/env bash
#
# Proves the vendored contract under third-party/soroban-token-example/src/ still
# matches the pinned upstream revision, apart from one documented, additive hunk
# appended to `lib.rs` (see PROVENANCE.md).
#
# Fetching from the pinned commit rather than from `main` is deliberate: this check
# must be deterministic. If upstream moves, the comparison still passes as long as
# our copy matches the revision PROVENANCE.md names.
#
# How the comparison works: upstream's file must match our file byte for byte up to
# upstream's line count, and whatever follows in our file must be exactly the
# tail this script expects for that file (empty for every file but `lib.rs`). Any
# edit to contract code, or any additional line, fails.
#
# Usage: third-party/verify.sh
set -euo pipefail

cd "$(dirname "$0")"

REV="1f5aeb53d3db5d0e61e53f59d5e6c5ab58eaf8ce"
UPSTREAM="https://raw.githubusercontent.com/stellar/soroban-examples/$REV"
BASE="$UPSTREAM/token"
DEST="soroban-token-example/src"
FILES=(admin allowance balance contract lib metadata storage_types test)

# The exact text permitted after the end of the upstream file, per file.
expected_tail() {
  case "$1" in
    lib)
      cat <<'EOF'

// --- vendoring addition, see PROVENANCE.md ---
// Upstream re-exports only the generated client. The contract type itself must be
// reachable to register the contract in the test environment, so it is re-exported
// here. Additive only: no contract logic or visibility is changed.
pub use crate::contract::Token;
EOF
      ;;
    *) : ;;
  esac
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
for f in "${FILES[@]}"; do
  url="$BASE/src/$f.rs"
  if ! curl -sSfL -o "$work/$f.rs" "$url" 2>/dev/null; then
    echo "FAIL  could not download $url (is there network access?)" >&2
    fail=1
    continue
  fi

  upstream_lines=$(wc -l < "$work/$f.rs")
  head -n "$upstream_lines" "$DEST/$f.rs" > "$work/ours_$f.rs"
  tail -n "+$((upstream_lines + 1))" "$DEST/$f.rs" > "$work/tail_$f.rs"
  expected_tail "$f" > "$work/expected_$f.rs"

  if ! cmp -s "$work/ours_$f.rs" "$work/$f.rs"; then
    echo "FAIL  $DEST/$f.rs differs from upstream $REV in the first $upstream_lines lines" >&2
    diff -u "$work/$f.rs" "$work/ours_$f.rs" | head -40 >&2 || true
    fail=1
  elif ! cmp -s "$work/tail_$f.rs" "$work/expected_$f.rs"; then
    echo "FAIL  $DEST/$f.rs has an undocumented addition past upstream's end" >&2
    diff -u "$work/expected_$f.rs" "$work/tail_$f.rs" | head -40 >&2 || true
    fail=1
  else
    echo "ok    $DEST/$f.rs"
  fi
done

# The vendored directory ships upstream's license alongside the source, because an
# Apache-2.0 redistribution has to include it. The license sits at the repository
# root upstream, not inside `token/`.
if ! curl -sSfL -o "$work/LICENSE" "$UPSTREAM/LICENSE" 2>/dev/null; then
  echo "FAIL  could not download $UPSTREAM/LICENSE" >&2
  fail=1
elif cmp -s "soroban-token-example/LICENSE" "$work/LICENSE"; then
  echo "ok    soroban-token-example/LICENSE"
else
  echo "FAIL  soroban-token-example/LICENSE differs from upstream $REV" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo >&2
  echo "The vendored contract no longer matches its pinned revision beyond the one" >&2
  echo "documented addition. Either revert the change, or re-vendor from upstream and" >&2
  echo "update PROVENANCE.md, this script, and its expected tail." >&2
  exit 1
fi

echo
echo "All ${#FILES[@]} source files and the license match \
stellar/soroban-examples@$REV (plus the one documented addition)."
