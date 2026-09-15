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
cargo run -p soroban-analyzer -- soroban-fuzzer/examples # the analyser finds the same bug
cargo deny check                                         # licences, advisories and sources
python3 scripts/check-docs.py                            # the docs match the code
```

The estimator needs a compiled contract, which means the target the Soroban SDK supports:

```bash
rustup target add wasm32v1-none
cargo build --target wasm32v1-none --release
cargo run -p soroban-budget -- target/wasm32v1-none/release/<your contract>.wasm
```

Its own tests build `third-party/soroban-token-example` for that target on first run and
cache the artefact under `target/`. Without the target they skip and say so, unless
`SOROBAN_REQUIRE_WASM_FIXTURE=1` is set, which is what CI sets — a skip in CI is a green
build that measured nothing.

`scripts/check-docs.py` is the one check here that is about the documents rather than
the code. It re-counts the tests in the landing page's `Tests` row, compares "five rules
ship today" against `rules/*.json`, fails on a relative link that no longer resolves,
and fails when a module is missing from its crate's map. If it fails, the fix is to write
down what was measured — the point of the check is that a measured fact in prose is
also a fact somebody re-measures.

The analyser is run on this repository by CI, in both directions: the vendored
third-party contract must come back clean, and the planted bug in
`soroban-fuzzer/examples/` must be found. If a detector change makes the first of those
fail, the change over-fires on code this project did not write — which is the only
precision evidence that is not a fixture written by whoever wrote the detector.

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

## Changing the GitHub Action

The Action in [`action.yml`](action.yml) is a composite action: YAML plumbing around
`scripts/run-analysis.sh`. Keep the decisions in the script, because the script is the part
that can be tested — `soroban-analyzer/tests/action.rs` runs it with fixtures and asserts
every exit status, the summary it writes, and what lands in the step outputs.

The YAML around it is exercised by this repository's own CI, which runs the Action against
the example contract, so a broken input name fails the build. `scripts/check-docs.py` also
checks that every declared input is used, that every referenced input is declared, and that
every path the Action runs is committed: an input typo is a workflow value that arrives
empty, which is the same class of failure as a configuration key that silently does
nothing.

Do not add a rule to the Action that the analyser does not have. The Action's job is to
run the analyser where a reviewer can see the result, not to decide anything about
findings on its own.

## Adding a detector

The intended model is one detector per pull request, and the format is built so that a
detector pull request touches no shared file: the registry is generated from the
directory at build time. A detector is two files in `soroban-analyzer/`.

1. **`rules/<id>.json`** — the rule's metadata, including **both fixtures**: source that
   must trigger it and source that must not. Start here, because the fixtures are the
   specification and the crate's tests run them on every commit.
2. **`src/detectors/<name>.rs`** — a `pub struct Detector` implementing `Detector`,
   naming the rule id from `id()` and using `sink.report(span, message)`.

Then check it locally:

```bash
cargo test -p soroban-analyzer          # runs every rule's own fixtures
cargo test -p soroban-analyzer --test rules -- --nocapture
cargo run -p soroban-analyzer -- --explain <your-rule-id>
```

**The standard, stated plainly: a detector with no fixture proving it fires, and no
fixture proving it does not over-fire, is not mergeable.** This is not a style
preference. A detector is a false-positive generator until it is shown otherwise, and
the fixtures are what show it — `tests/rules.rs` parses and runs every rule's own
examples on every commit, so a detector that fires on its clean example, or does not
fire on its triggering one, fails the build. That test also asserts the rule is in the
README's table and that its `heuristic` flag agrees with its rationale, so the two
things a reviewer would otherwise have to remember are checked instead.

The second fixture matters more than the first. The first says the check works; the
second says it is worth running.

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

## Adding to the estimator

`soroban-budget` has two ways to be wrong, and a change needs a test for whichever one it
touches.

1. **The arithmetic.** Assemble a module in `tests/estimate.rs` with the counts known by
   construction — `common::nops`, `common::call`, `common::loop_forever` — and assert the
   number. A change to how a call tree is summed, or to what counts as an operation, is a
   change to every number the tool has ever printed, and this is where that is visible.
2. **The reading.** If the change touches how a module is parsed, the test belongs in
   `tests/compiled_contract.rs`, against the vendored token's compiled Wasm. A parser
   tested only against modules this project assembled is a parser that agrees with its
   author; the compiled artefact is the only half of the evidence that is not ours.

Do not add a rule that grades a loop, a `call_indirect` or a recursion: they make an upper
bound impossible, which is a fact about what the tool can conclude, not a defect in the
contract. They are reported, and the report says what they prevent.

## Adding an invariant

`src/invariant.rs` holds `FnInvariant` (the general escape hatch), `SupplyConserved`,
`StorageGrowthBounded` and `NonDecreasing`. A new invariant should be one that many
contracts want and few would think to write — that is the bar. The built-in three
follow it: two quantities that must not change, grow without bound or fall, each
stated in terms of storage the network can take away. It needs a rustdoc example that compiles (this
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
