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
├── .github/workflows/      # CI: format, lint, test, and fuzz with a report artefact
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
    ├── examples/           # runnable end-to-end example
    └── tests/              # pass, detect, and classification tests
```

## Getting started

```bash
cargo test                        # run the harness's own test suite
cargo run --example token_fuzz    # see it find a planted bug
```

Requires Rust 1.91 or later, the floor set by `soroban-sdk` 27.

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

Apache-2.0.
