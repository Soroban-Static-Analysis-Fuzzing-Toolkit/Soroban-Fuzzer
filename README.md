# Soroban Static Analysis & Fuzzing Toolkit

An open-source security toolkit for [Soroban](https://developers.stellar.org/docs/build/smart-contracts/overview)
smart contracts. Soroban has its own set of vulnerability classes that no general Rust
tool catches, and the ecosystem's only answer has been a paid audit. This toolkit is
the free first line of defence.

## Components

| Component | What it does | Status |
| --- | --- | --- |
| **[soroban-fuzzer](soroban-fuzzer/)** | Property-based invariant fuzzing. Generates sequences of contract calls against `soroban-sdk`'s test environment, checks your invariants after every call, and shrinks failures to a minimal reproducer. Detects missing `require_auth`, resource-budget blowouts, unbounded storage growth and unchecked arithmetic. Supports cross-ledger scenarios, exact single-case replay, storage scoped to the contracts under test, and a strict authorization test that a panic cannot satisfy. | **Implemented** |
| soroban-static-analyzer | Detector engine over Rust HIR/MIR and compiled Wasm, a resource-budget estimator, detector rules in a versioned community format, and a GitHub Action producing a SARIF report for PR review. | Planned |

## Repository layout

```
.
├── Cargo.toml              # workspace
├── CONTRIBUTING.md         # the contribution model, and the bar a detector must clear
├── .github/workflows/      # CI: format, lint, test, MSRV, benches, fuzz report
├── .github/ISSUE_TEMPLATE/ # detector proposals and bug reports
├── third-party/            # vendored upstream contract used as a fuzzing fixture +
│                           #   verify.sh, which re-checks it against its revision
└── soroban-fuzzer/         # the property fuzzer
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
    └── tests/              # pass, detect, diagnostics, classification, third-party
```

## Getting started

```bash
cargo test                        # run the harness's own test suite
cargo run --example token_fuzz    # see it find a planted bug
cargo bench -p soroban-fuzzer     # throughput and snapshot-cost numbers
```

Requires Rust 1.91 or later, the floor set by `soroban-sdk` 27. CI checks that floor
rather than only declaring it.

## Is it any good?

The fuzzer is not only tested against fixtures written to be fuzzable. It is run
against an unmodified third-party contract — `stellar/soroban-examples`' standard
token, vendored byte-for-byte under [`third-party/`](third-party/) and re-verified
against its pinned revision by `third-party/verify.sh` — and against a two-contract
composition built on it, including a scenario that crosses a ledger boundary through the
real token's temporary-storage TTL.

Its design decisions are grounded in measurements against `soroban-sdk` 27 rather than
assumptions, and the awkward ones are written down instead of hidden. Two examples: a
failed `require_auth` and a plain panic are *indistinguishable* in the test environment,
so no error inspection can tell them apart; and the test host applies temporary-entry
expiry lazily on read rather than at ledger close. Where a measurement changed the right answer,
the code follows the measurement — which is why the authorization test asserts the
demanded authorization tree instead of inspecting an error.

[`soroban-fuzzer/README.md`](soroban-fuzzer/README.md) documents what has actually been
measured — throughput ranges, snapshot scaling, the scoping win — and where the approach
breaks down. It is worth reading before relying on a green run.

Read [`soroban-fuzzer/README.md`](soroban-fuzzer/README.md) for the full guide: what it
detects and why, how to write a target and invariants, the authorization and resource
policies, and how to reproduce failures in CI.

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
minimal reproducer's length rather than merely that a failure occurred.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

The test fixture under [`third-party/`](third-party/) is Apache-2.0 code from
`stellar/soroban-examples`, redistributed unmodified; its license text and the exact
revision are recorded there, and [`NOTICE`](NOTICE) carries the attribution.
