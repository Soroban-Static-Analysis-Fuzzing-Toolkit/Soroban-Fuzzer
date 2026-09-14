# Provenance

This directory contains a verbatim copy of the Soroban token contract from
Stellar's example repository, vendored so that `soroban-fuzzer` can be exercised
against code it did not design.

| | |
| --- | --- |
| Source repository | <https://github.com/stellar/soroban-examples> |
| Path within the repository | `token/` |
| Revision | [`1f5aeb53d3db5d0e61e53f59d5e6c5ab58eaf8ce`](https://github.com/stellar/soroban-examples/commit/1f5aeb53d3db5d0e61e53f59d5e6c5ab58eaf8ce) (last commit touching `token/`, 2026-09-09) |
| License | Apache-2.0 (see the upstream repository's `LICENSE`) |
| Copyright | Stellar Development Foundation and contributors |

## Why it is vendored

The harness's own fixtures were written to be fuzzable — they expose the exact
view functions the invariants need, and their storage layout is chosen to be
easy to read back. That proves the harness works on contracts it was designed
around.

This contract is a useful counterweight: it is the reference implementation of
the Soroban token interface, its API is fixed by the standard rather than by the
fuzzer, and it exercises shapes the hand-written fixtures do not. Specifically it
uses

* the standard `TokenInterface` trait, including `MuxedAddress` destinations,
* temporary storage with per-entry TTL for allowances, and global TTL extension,
* `soroban_token_sdk` events and metadata rather than hand-rolled storage keys.

Nothing about the contract was changed to make it easier to fuzz.

## What is different from upstream

Seven of the eight files under `src/` are **byte-identical** to upstream. The
seventh and eighth: `src/test.rs` is byte-identical and simply compiles out (see
below), and `src/lib.rs` carries one additive hunk.

### `src/lib.rs` — one additive hunk

Upstream ends with:

```rust
pub use crate::contract::TokenClient;
```

appended with:

```rust
// --- vendoring addition, see PROVENANCE.md ---
// Upstream re-exports only the generated client. The contract type itself must be
// reachable to register the contract in the test environment, so it is re-exported
// here. Additive only: no contract logic or visibility is changed.
pub use crate::contract::Token;
```

This is required and not cosmetic. `mod contract;` is private, so without it the
`Token` type is unreachable from outside the crate and there is no way to call
`Env::register(Token, ..)` — the token interface re-exports only the generated
`TokenClient`, which can only address an *already deployed* contract. The change
adds a re-export; it removes nothing and alters no contract logic.

`third-party/verify.sh` deletes exactly these five lines from our copy before
comparing it against upstream, so any *other* edit to `lib.rs` — or to any other
file — still fails the check.

### `Cargo.toml` — three changes

1. **`crate-type` gains `rlib`.** Upstream declares `crate-type = ["cdylib"]`,
   which is right for the deployed Wasm but cannot be linked into a native test
   binary. Without `rlib` the fuzzer cannot call the contract natively.
2. **The `[profile.release]` and `[profile.release-with-logs]` tables are
   removed.** Cargo ignores profile tables in non-root packages and warns about
   them, so keeping them would only add noise.
3. **`publish = false` and `license` are added**, so this vendored copy is never
   published to crates.io under the toolkit's name.

### Why `src/test.rs` is kept

`src/lib.rs` declares `mod test;` unconditionally, so dropping `test.rs` would have
meant editing `lib.rs` for no functional reason. Keeping it means the module
declaration is genuine. As a dependency it compiles to nothing — `test.rs` opens
with `#![cfg(test)]` — so it costs no build time and the fuzzer does not run
upstream's tests.

### `LICENSE` — added, verbatim

An Apache-2.0 redistribution has to carry the license text, so upstream's `LICENSE`
at this revision is included here word for word; `verify.sh` checks it too. It is the
unmodified Apache-2.0 text, so the copy at the repository root is the same file — the
root is where this repository's own license lives, since the toolkit declared
Apache-2.0 in its manifests and README but shipped no license file until now.
Upstream has no `NOTICE` file at this revision, so none is required; the repository's
root `NOTICE` records the attribution anyway.

## Regenerating

`third-party/verify.sh` fetches every file from the pinned revision and fails if
any of them differs from the copy in this directory. Run it after touching
anything in here.

To re-vendor from scratch:

```bash
rev=1f5aeb53d3db5d0e61e53f59d5e6c5ab58eaf8ce
root=https://raw.githubusercontent.com/stellar/soroban-examples/$rev
for f in admin allowance balance contract lib metadata storage_types test; do
  curl -sS "$root/token/src/$f.rs" -o "third-party/soroban-token-example/src/$f.rs"
done
# The license is at the repository root upstream, not inside `token/`.
curl -sS "$root/LICENSE" -o third-party/soroban-token-example/LICENSE
```

Then re-apply the three `Cargo.toml` changes and the one `lib.rs` addition above, and
update the revision here and in `verify.sh` — pinning the revision in the URLs is what
makes the check reproducible rather than a comparison against a moving `main`.
