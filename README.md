# Soroban Static Analysis & Fuzzing Toolkit

An open-source security toolkit for [Soroban](https://developers.stellar.org/docs/build/smart-contracts/overview)
smart contracts. Soroban has its own set of vulnerability classes that no general Rust
tool catches, and the ecosystem's only answer has been a paid audit. This toolkit is
the free first line of defence.

## Components

| Component | What it does | Status |
| --- | --- | --- |
| **[soroban-fuzzer](soroban-fuzzer/)** | Property-based invariant fuzzing. Generates sequences of contract calls against `soroban-sdk`'s test environment, checks your invariants after every call, and shrinks failures to a minimal reproducer. Detects missing `require_auth`, resource-budget blowouts, unbounded storage growth and unchecked arithmetic. | **Implemented** |
| soroban-static-analyzer | Detector engine over Rust HIR/MIR and compiled Wasm, a resource-budget estimator, detector rules in a versioned community format, and a GitHub Action producing a SARIF report for PR review. | Planned |

## Repository layout

```
.
├── Cargo.toml              # workspace
├── .github/workflows/      # CI: format, lint, test, MSRV, benches, fuzz report
├── third-party/            # vendored upstream contract used as a fuzzing fixture +
│                           #   verify.sh, which re-checks it against its revision
└── soroban-fuzzer/         # the property fuzzer
    ├── src/
    │   ├── budget.rs       # resource metering against network limits
    │   ├── config.rs       # FuzzConfig, auth and resource policies
    │   ├── invariant.rs    # Invariant trait and built-in invariants
    │   ├── report.rs       # journal, failure reports, run outcomes
    │   ├── runner.rs       # generation, shrinking, per-case execution
    │   ├── runtime.rs      # instrumented call context for actions
    │   ├── storage.rs      # ledger snapshots and diffs
    │   ├── target.rs       # the Target trait
    │   └── prelude.rs      # one-line imports for target files
    ├── benches/            # throughput and snapshot-scaling measurements
    ├── examples/           # runnable end-to-end example
    └── tests/              # pass, detect, classification, and third-party tests
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
composition built on it. The README for the fuzzer documents what has actually been
measured and where the approach breaks down; it is worth reading before relying on a
green run.

Read [`soroban-fuzzer/README.md`](soroban-fuzzer/README.md) for the full guide: what it
detects and why, how to write a target and invariants, the authorization and resource
policies, and how to reproduce failures in CI.

## Contributing

The toolkit is built to accept small, independently mergeable contributions. For the
static analyser that means one detector per pull request; for the fuzzer it means one
well-scoped invariant helper, target example or bug-class test at a time. New detectors
should come with a test that fails without them — see `soroban-fuzzer/tests/detects_bugs.rs`
for the pattern.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).

The test fixture under [`third-party/`](third-party/) is Apache-2.0 code from
`stellar/soroban-examples`, redistributed unmodified; its license text and the exact
revision are recorded there, and [`NOTICE`](NOTICE) carries the attribution.
