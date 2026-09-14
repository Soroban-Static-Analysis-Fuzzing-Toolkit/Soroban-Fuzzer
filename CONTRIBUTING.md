# Contributing

This toolkit exists to be a free first line of defence for Soroban contracts, and the
thing that makes it useful is a steady stream of small, independently reviewable
additions: one detector, one invariant helper, one bug-class test at a time. This
document is how to add one.

## Setup

Rust **1.91 or newer** (`rust-version` in the manifests is authoritative — the CI job
named `msrv` builds on exactly that version with `--locked`).

```bash
git clone https://github.com/<owner>/Soroban-Fuzzer
cd Soroban-Fuzzer
export PATH="$HOME/.cargo/bin:$PATH"

cargo fmt --all                                          # format
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace                                   # integration tests + doctests
cargo test --workspace --release                         # the detectors must hold optimised too
cargo bench -p soroban-fuzzer                            # prints numbers, asserts nothing
cargo run --example token_fuzz                           # finds a planted bug in one call
```

`cargo test --release` is not optional. Soroban contracts deploy with
`overflow-checks = true`, so an arithmetic finding that exists in debug and disappears
in release is a finding that would not exist in production either. The workspace sets
`overflow-checks = true` in the release profile for exactly this reason.

The vendored third-party contract has its own integrity check:

```bash
./third-party/verify.sh
```

It re-downloads every source file from the pinned upstream revision and fails on any
difference beyond the one documented, additive `pub use`. If you change anything under
`third-party/soroban-token-example/`, it is not vendored code any more and the script
will say so.

## What one pull request should be

Scope is the reviewable unit here. A pull request that adds one detector and the two
fixtures that prove it fires and does not over-fire can be reviewed on its own merits
in minutes. A pull request that also refactors the engine cannot, and will sit.

Prefer adding over restructuring:

- **Add** a detector, an invariant, a bug-class test, a capability flag.
- **Resist** broad refactors, module reshuffles, or "while I was in there" cleanups.
  If one is genuinely needed, propose it as its own pull request and say why.
- Keep the public API's existing shape. A change to `Target`, `Runtime`, `Invariant` or
  `FuzzConfig` affects every downstream target, so it needs a reason in the
  description, not just a diff.

Every pull request should answer three questions in its description:

1. **Which issue does this close?**
2. **What proves the change?** Name the test that fails without it, and run it failing
   first. A change with no such test is a claim, not a fix.
3. **Does behaviour change for existing targets?** "Yes, and here is why" is a fine
   answer; leaving the question unanswered is not.

## Adding a detector

The intended model is one detector per pull request. A detector is a vulnerability
class expressed as a check, plus the evidence that it is neither blind nor noisy.

1. **Write the fixtures first.** Two source files under the detector's fixture
   directory: one containing the vulnerable pattern, one that is correctly written and
   superficially similar. The second matters more — a detector that fires on everything
   is worse than no detector, because it teaches people to ignore findings.
2. **Implement the check** against the parsed source, reporting file, span, line,
   column, severity, message and remediation.
3. **Add the rule metadata** for its id, severity, rationale and references.
4. **Wire up both directions as tests**: the vulnerable fixture produces exactly the
   expected finding, and the correct fixture produces none.

**The standard, stated plainly: a detector with no fixture proving it fires, and no
fixture proving it does not over-fire, is not mergeable.** This is not a style
preference. A detector is a false-positive generator until it is shown otherwise, and
the only acceptance test that matters is the two fixtures.

A detector proposal issue has a template (see [Templates](#templates)). It asks for the
Soroban-specific reason general Rust tooling does not catch the class, a vulnerable
snippet, a correct snippet, and the severity rationale — the same information the
pull request will need, so writing it down first is not overhead.

## Adding a bug-class test for the fuzzer

`tests/detects_bugs.rs` holds one deliberately vulnerable contract per bug class, and a
test asserting the harness finds it. Those tests follow a rule that is easy to miss:

**Assert the minimal reproducer's length, not merely that a failure occurred.**

```rust
assert_eq!(
    report.minimal_sequence.len(),
    1,
    "a missing require_auth should shrink to the single privileged call: {:?}",
    report.minimal_sequence
);
```

The reason is not tidiness. When this was written, a harness bug meant the shrinker
deleted *entire sequences* and reported an empty reproducer, and every test that only
asserted "it failed" stayed green through it. Counting the actions is what caught it. A
finding whose reproducer does not describe the bug that was found is worse than no
finding, because it sends you to the wrong place.

So, to add a bug class:

1. Add the vulnerable contract to `tests/common/mod.rs`, with a doc comment naming the
   class and why it is Soroban-specific.
2. Add the target and the test in `tests/detects_bugs.rs`.
3. Assert the failure **and** the exact reproducer length, plus the finding's `kind` and
   that `detail` names the thing that went wrong.
4. If the class needs a guard the harness lacks, add the guard in `src/`, and add a test
   that the guard catches the mistake rather than merely not breaking on it.

## Adding an invariant

`src/invariant.rs` holds `FnInvariant` (the general escape hatch), `SupplyConserved` and
`StorageGrowthBounded`. A new invariant should be one that many contracts want and few
would think to write — that is the bar. It needs a rustdoc example that compiles (this
crate's doctests are part of its test suite), and a test that it fires on a contract
that violates it.

Invariants must be **read-only**. The harness snapshots storage around every check and
fails the case if a check changed anything, because a checker that mutates the contract
makes the run's results depend on the checker. If your invariant needs to call an
entrypoint, call a view. If the contract has no view that answers the question, say so
in the docs and read the storage snapshot instead — that is what
`tests/third_party.rs` does for conservation of supply, because the standard token
interface has no `total_supply`.

## Verifying a change

Beyond the commands above, two habits catch most of what review would:

- **Run the new test with the fix removed** and watch it fail. A test that passes both
  ways is not testing anything.
- **Put numbers in the description** for anything performance-related, from
  `cargo bench -p soroban-fuzzer`, with the machine named. Ranges, not point values: an
  early run of the snapshot benchmark read twice as slow as three consecutive later
  ones, and quoting the single figure would have been misleading.

## Licences and provenance

The repository is Apache-2.0 (see `LICENSE`), and it redistributes third-party code
under `third-party/`. Two rules follow.

- **Vendored code is vendored byte-for-byte.** Take it from a pinned upstream revision,
  record the revision, licence and any (ideally additive) change in that directory's
  `PROVENANCE.md`, and make `./third-party/verify.sh` able to re-derive it. A "small
  fix" to vendored code destroys the property that makes it worth having: a fixture
  that the harness did not design.
- **Do not paste code of unclear origin into the repository.** If you are adapting a
  snippet, name its source and licence in the pull request. Apache-2.0 is the licence
  for this project's own code; a dependency under a different licence is fine (it will
  be checked) but adding files under one needs to be deliberate.

`NOTICE` records the attribution for the vendored contract. If you vendor anything
else, it needs an entry there too.

## Templates

Filing an issue or opening a pull request gives you a template that asks for the things
above: a detector proposal asks for the vulnerable and correct snippets, a bug report
asks for the seed and minimal reproducer, and the pull request checklist asks for the
test that fails without the change.

## Questions

Open a discussion or an issue. "Is this bug class worth a detector?" is a good issue to
file before writing one — half the value of a detector is that the class is real.
