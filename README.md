# Soroban Static Analysis & Fuzzing Toolkit

An open-source security toolkit for [Soroban](https://developers.stellar.org/docs/build/smart-contracts/overview)
smart contracts. Soroban has its own set of vulnerability classes that no general Rust
tool catches, and the ecosystem's only answer has been a paid audit. This toolkit is
the free first line of defence.

## Components

| Component | What it does | Status |
| --- | --- | --- |
| **[soroban-analyzer](soroban-analyzer/)** | Static analysis over the contract's Rust source. Five detectors, each with its own versioned rule metadata and fixtures: missing `require_auth`, storage-durability misuse, unbounded storage loops, a read-count estimate against the 200-entry ceiling, and unchecked arithmetic on amounts. Emits text, JSON or SARIF 2.1.0, and exits non-zero at a configurable severity gate. Adopting it on an existing contract is a recorded baseline plus a `.soroban-analyzer.json`, so only new findings gate, and it checks files in parallel without the output depending on how many cores did it. | **Implemented** |
| **[soroban-fuzzer](soroban-fuzzer/)** | Property-based invariant fuzzing. Generates sequences of contract calls against `soroban-sdk`'s test environment, checks your invariants after every call, and shrinks failures to a minimal reproducer. Detects missing `require_auth`, resource-budget blowouts, unbounded storage growth, unchecked arithmetic, and cumulative state that does not survive a ledger boundary. Supports cross-ledger scenarios, exact single-case replay, storage scoped to the contracts under test, and a strict authorization test that a panic cannot satisfy. | **Implemented** |

| **[soroban-budget](soroban-budget/)** | Static resource-budget estimation over the **compiled Wasm**. For every entrypoint: the instructions in its static call tree, the host functions it reaches, and whether that count is exact or only a lower bound — the latter whenever the code loops, calls indirectly or recurses, which the report names rather than glosses. Optional `--fail-over` and `--fail-unbounded` gates. | **Implemented** |

The three are for different things, and none replaces another. The analyser reads code it
cannot run — every branch, including the ones a fuzzer never reaches — and reasons about
patterns. The fuzzer runs the contract and finds what only an input can show. The estimator
reads the artefact that will actually be deployed, and says what it can and cannot conclude
from it: a structural measurement of the module, explicitly not a CPU prediction, because
the network meters at its own weights and no honest conversion exists without its table.

## Repository layout

```
.
├── Cargo.toml              # workspace
├── CONTRIBUTING.md         # the contribution model, and the bar a detector must clear
├── action.yml              # the composite GitHub Action: analyse, summarise, upload SARIF
├── scripts/                # run-analysis.sh — the Action's body, tested by tests/action.rs
├── .github/workflows/      # CI: format, lint, test, MSRV, docs, the Action, the analyser
│                           #   run, coverage, licences, benches, fuzz report, Wasm
│                           #   estimate
├── .github/ISSUE_TEMPLATE/ # detector proposals and bug reports
├── deny.toml               # dependency policy: licences, advisories, sources
├── third-party/            # vendored upstream contract used as a fuzzing and analysis
│                           #   fixture + verify.sh, which re-checks it against its revision
├── soroban-analyzer/       # the static analyser
│   ├── src/
│   │   ├── baseline.rs   # the findings a run does not gate on, so a tree can be adopted
│   │   ├── config.rs     # .soroban-analyzer.json: what a repository decides once
│   │   ├── source.rs     # a parsed file, and spans to line/column mapping
│   │   ├── syntax.rs     # shared queries: entrypoints, storage, durability, loop bounds
│   │   ├── detector.rs   # the Detector trait and the engine that runs detectors
│   │   ├── detectors/    # one file per rule; the registry is generated from this dir
│   │   ├── rules.rs      # rule metadata: loading, versioning, validation
│   │   ├── suppress.rs   # in-code `allow` markers, counted rather than dropped
│   │   ├── report.rs     # text, JSON and SARIF rendering, and the exit-status gate
│   │   └── walk.rs       # which files to analyse
│   ├── rules/            # one versioned JSON file per rule, each with both fixtures
│   └── tests/            # rule fixtures, detector behaviour, and the binary end to end
├── soroban-fuzzer/         # the property fuzzer
    ├── src/
    │   ├── arbitrary_bridge.rs  # use an existing `Arbitrary` impl as a Strategy
    │   ├── budget.rs       # resource metering against network limits
    │   ├── config.rs       # FuzzConfig, auth and resource policies
    │   ├── invariant.rs    # Invariant trait and built-in invariants
    │   ├── report.rs       # journal, failure reports, run outcomes
    │   ├── runner.rs       # generation, shrinking, per-case execution, replay
    │   ├── runtime.rs      # instrumented call context for actions
    │   ├── storage.rs      # ledger snapshots and diffs, scoped per contract
    │   ├── target.rs       # the Target trait
    │   └── prelude.rs      # one-line imports for target files
    ├── benches/            # throughput and snapshot-scaling measurements
    ├── examples/           # runnable end-to-end example
    └── tests/              # pass, detect, diagnostics, classification, runtime API,
                            #   third-party
└── soroban-budget/         # the resource-budget estimator over compiled Wasm
    ├── src/
    │   ├── module.rs       # reading the Wasm: imports, exports, per-function body facts
    │   ├── estimate.rs     # the cost model, and why an upper bound is impossible
    │   └── report.rs       # text and JSON, both stating what the numbers are
    └── tests/              # assembled modules, and the real contract's compiled Wasm
```

## Getting started

```bash
cargo test                                # both crates' test suites
cargo run --example token_fuzz            # see the fuzzer find a planted bug
cargo run -p soroban-analyzer -- src/     # see the analyser find one staticallycargo bench -p soroban-fuzzer                     # throughput and snapshot-cost numbers
cargo run -p soroban-budget -- contract.wasm      # what each entrypoint costs, statically
```

The estimator needs a compiled contract. The Soroban SDK builds for `wasm32v1-none`
(`rustup target add wasm32v1-none`), which is the target its own tests use:

```bash
cargo build --target wasm32v1-none --release
soroban-budget --fail-unbounded target/wasm32v1-none/release/my_contract.wasm
```

On a real contract, in CI, into the review UI:

```bash
soroban-analyze --format sarif --severity medium . > results.sarif
```

Requires Rust 1.91 or later, the floor set by `soroban-sdk` 27. CI checks that floor
rather than only declaring it.

## In a pull request, as a GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # what the SARIF upload needs

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: soroban-security/soroban-toolkit@v1
        with:
          path: .
          severity: high           # the analyser's own default
          baseline: .soroban-baseline.json   # optional: excuse what is already recorded
          fail-on-findings: 'false'          # annotate the diff first, gate later
```

[`action.yml`](action.yml) builds the analyser, runs it, writes the report, uploads it to
code scanning so each finding lands on the line it is about, and writes a summary of the
findings into the run — the count, the rule, the level and the location, so a reviewer can
read the checks tab without following a single annotation into the diff.

Three decisions worth knowing before you wire it up:

* **`fail-on-findings: 'false'` is the adoption path.** The run still analyses, annotates
  and summarises; it just does not fail. A team can turn the gate on when the findings it
  inherited are dealt with, and `baseline` is how they record what "inherited" means.
* **A baseline that was not checked out fails the run** rather than passing it silently.
  The alternative — treating every recorded finding as new — is a tool reporting a clean
tree it did not check.
* **A run of the analyser that could not run always fails the step**, whatever
  `fail-on-findings` says: a workflow that continues after the tool failed has published a
green tick over nothing.

Outputs: `findings` (how many at or above the gate) and `sarif-file` (the report, also
uploaded as an artefact). The Action is exercised on this repository by CI, on the
example with the planted bug, because a composite action's YAML runs nowhere else.

## Is it any good?

Neither half is only tested against fixtures written to be testable. Both are run against
an unmodified third-party contract — `stellar/soroban-examples`' standard token, vendored
byte-for-byte under [`third-party/`](third-party/) and re-verified against its pinned
revision by `third-party/verify.sh` — and against a two-contract composition built on it,
including a scenario that crosses a ledger boundary through the real token's
temporary-storage TTL.

The analyser is run on that contract by CI and must come back **clean**: it is the only
precision evidence for its rules that does not come from fixtures written by whoever wrote
the detector. The same job then analyses this repository's own example, which contains a
planted missing-authorization bug, and asserts the finding reaches a SARIF result at
`error` level with a resolving `ruleIndex` and a line number — because a finding that never
reaches the code-scanning view has not helped anyone.

The estimator is held to the same standard from the other end of the pipeline: it is run
over the Wasm that upstream's contract *actually compiles to*, built for `wasm32v1-none`
by CI, and the assertions are about structure rather than about numbers — every entrypoint
of the standard token is found with a body behind it, the `memory` export is not counted as
one, and at least one entrypoint is bounded exactly, because a reader that reported
everything as a lower bound would be reporting nothing. Its own arithmetic is tested the
other way round, against modules assembled with known counts.

Measured facts rather than impressions:

| Measurement | Value |
| --- | --- |
| Tests | 224 across the three crates (159 analyser, 44 fuzzer, 21 budget) plus 22 doctests; `scripts/check-docs.py` re-counts them and fails if this row drifts |
| Workspace coverage | 89.19% of regions, 88.66% of lines |
| Analyzer on the vendored real token | **no findings**, exit 0 |
| Analyzer on the planted-bug example | 5 findings, 1 critical, exit 1 |
| Estimator on the vendored real token's Wasm | 13 entrypoints, 3 exactly bounded, `transfer_from` the largest at 12,465 instructions and 148 host calls |
| Dependency policy | `cargo deny check`: advisories, bans, licences and sources all pass |
| Fuzzer throughput | 2,340–2,740 cases/s single-action; the table in [`soroban-fuzzer/README.md`](soroban-fuzzer/README.md) lists every measurement |

Design decisions are grounded in measurements against `soroban-sdk` 27 rather than
assumptions, and the awkward ones are written down instead of hidden. Two examples: a
failed `require_auth` and a plain `panic!` are *indistinguishable* in the test environment
(both are a `Rejected("Error(Context, InvalidAction)")`, while an arithmetic overflow is a
`Failed("Abort")` — which is why the analyzer's authorization rule is a positive assertion
and why the harness's strict authorization helper does not inspect errors at all); and the
test host applies temporary-entry expiry lazily on read rather than at ledger close. Where
a measurement changed the right answer, the code follows the measurement, and the tests
pin the measurement so that a future SDK restoring the distinction fails a build.

Each half documents where it breaks down: [`soroban-analyzer/README.md`](soroban-analyzer/README.md)
lists what a syntactic check cannot see and marks the three heuristic rules as such, and
[`soroban-fuzzer/README.md`](soroban-fuzzer/README.md) records throughput ranges, snapshot
scaling and the model-first blind spot. Both are worth reading before relying on a green
run — which is the honest position for a security tool, and the one this project takes.

## Contributing

The toolkit is built to accept small, independently mergeable contributions: one
detector per pull request for the analyser, one invariant helper, target or bug-class
test for the fuzzer.

[`CONTRIBUTING.md`](CONTRIBUTING.md) is the full guide — setup, the three questions every
pull request should answer, how to add a detector and how to add a bug-class test, the
licence and vendoring rules, and the one standard that matters: **a detector with no
fixture proving it fires, and one proving it does not over-fire, is not mergeable.**
Issues have templates, and the pull request checklist asks for the test that fails
without the change, because that is what keeps a detector honest.

In short: a new detector should come with a test that fails without it — see
`soroban-fuzzer/tests/detects_bugs.rs` for the pattern, where each test asserts the
minimal reproducer's length rather than merely that a failure occurred. For the analyser
the equivalent is the rule's own two fixtures, which CI runs whether or not the pull
request mentions them.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

The test fixture under [`third-party/`](third-party/) is Apache-2.0 code from
`stellar/soroban-examples`, redistributed unmodified; its license text and the exact
revision are recorded there, and [`NOTICE`](NOTICE) carries the attribution.
