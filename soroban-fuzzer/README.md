# soroban-fuzzer

**Property-based invariant fuzzing for Soroban smart contracts.**

`soroban-fuzzer` generates sequences of contract calls, runs them against
[`soroban-sdk`](https://docs.rs/soroban-sdk)'s test environment, and checks your
invariants after every call. When something breaks, [proptest](https://docs.rs/proptest)
shrinks the sequence to the shortest call sequence that still reproduces it, and the
harness reports that sequence along with the resources each call consumed.

It is the fuzzing half of an open-source security toolkit for Soroban — a free first
line of defence for teams whose only other option is a paid audit.

```text
soroban-fuzzer: failing case
  kind:   unexpected-error
  detail: call succeeded but must have been refused: a privileged entrypoint may be
          missing require_auth, or an input check may be missing
  seed:   9719402080364109389  (reproduce with FuzzConfig::default().seed(9719402080364109389))
  cases:  64 requested, actions 1..=6, auth strict
  minimal sequence (1 action):
    1. set_fee_bps(bps=0) without authorization
  execution:
    #1 set_fee_bps(bps=0) without authorization -> violation: call succeeded but ...
        cpu=27138 mem=4313B reads=1 writes=1 entries=2
        call `set_fee_bps`: ok [cpu=27138, writes=0]
```

## Why a Soroban-specific fuzzer

Soroban has vulnerability classes that general Rust tooling does not catch. Three of
them are a natural fit for invariant fuzzing.

| Bug class | How this harness finds it |
| --- | --- |
| **Missing `require_auth`** | `AuthPolicy::Strict` is the default and installs no credentials, so a privileged entrypoint that mutates state for an unauthenticated address is caught. `call_without_auth(...).expect_rejected()` is a one-line negative test. |
| **Resource-budget blowouts** | Every invocation is metered and compared against the network's real ceilings — CPU instructions, memory, the **200-entry read limit**, write entries, bytes read and written. A call that cannot land on mainnet is reported by name, with the measured value and the excess. |
| **Unbounded storage growth** | `StorageGrowthBounded` fails a case when a contract's ledger entries pass a ceiling, catching loops that append to storage without converging. |

Add **unchecked arithmetic**, which surfaces as a trap that `expect_ok()` turns into a
finding, and you have the four classes most likely to cost a Soroban team money.

## Quick start

Add the harness as a dev-dependency:

```toml
[dev-dependencies]
soroban-fuzzer = "0.1"
soroban-sdk = { version = "27", features = ["testutils"] }
```

Describe your contract as a `Target` — a reference model, the actions to generate, how
to deploy the fixture, how to run one action, and the invariants:

```rust
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, Env, IntoVal};

#[derive(Clone, Debug)]
struct Model { balances: [i128; 3] }

#[derive(Clone, Debug)]
enum Act {
    Transfer { from: usize, to: usize, amount: i128 },
    AdvanceLedger { ledgers: u32 },
}

struct World { contract: Address, actors: [Address; 3] }

struct TokenTarget;

impl Target for TokenTarget {
    type State = Model;
    type Action = Act;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<Model> {
        constant(Model { balances: [1_000, 0, 0] })
    }

    fn setup(&self, env: &Env, initial: &Model) -> World {
        let actors: [Address; 3] = std::array::from_fn(|_| Address::generate(env));
        let supply: i128 = initial.balances.iter().sum();
        let contract = env.register(Token, (actors[0].clone(), supply));
        World { contract, actors }
    }

    fn actions(&self, state: &Model) -> BoxedStrategy<Act> {
        // Only transfer from an actor that holds a balance, so a rejection would be
        // a real finding rather than uninteresting input.
        let funded: Vec<usize> = (0..3).filter(|ix| state.balances[*ix] > 0).collect();
        let balances = state.balances;
        (proptest::sample::select(funded), 0usize..3)
            .prop_flat_map(move |(from, to)| {
                (1i128..=balances[from].max(1))
                    .prop_map(move |amount| Act::Transfer { from, to, amount })
            })
            .boxed()
    }

    fn next_state(&self, mut state: Model, action: &Act) -> Model {
        match action {
            Act::Transfer { from, to, amount } => {
                state.balances[*from] -= amount;
                state.balances[*to] += amount;
            }
            Act::AdvanceLedger { .. } => {}
        }
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, World>, action: &Act) -> StepOutcome {
        match action {
            Act::Transfer { from, to, amount } => {
                let from_addr = rt.world().actors[*from].clone();
                let to_addr = rt.world().actors[*to].clone();
                let contract = rt.world().contract.clone();

                // Authorize exactly this invocation for exactly this actor.
                let env = rt.env();
                env.mock_auths(&[MockAuth {
                    address: &from_addr,
                    invoke: &MockAuthInvoke {
                        contract: &contract,
                        fn_name: "transfer",
                        args: (from_addr.clone(), to_addr.clone(), *amount).into_val(env),
                        sub_invokes: &[],
                    },
                }]);

                let client = TokenClient::new(env, &contract);
                rt.call("transfer", || client.try_transfer(&from_addr, &to_addr, amount))
                    .expect_ok()
            }
            Act::AdvanceLedger { ledgers } => {
                rt.ledger().advance(*ledgers);
                StepOutcome::ok()
            }
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            // No coins are created or destroyed by a transfer.
            FnInvariant::new("balances-match-model", |ctx: &CheckCtx<'_, Self>| {
                let client = TokenClient::new(ctx.env, &ctx.world.contract);
                for (ix, expected) in ctx.model.balances.iter().enumerate() {
                    let actual = client.get_balance(&ctx.world.actors[ix]);
                    if actual != *expected {
                        return Err(format!("actor {ix}: contract {actual}, model {expected}"));
                    }
                }
                Ok(())
            })
            .boxed(),
            // Storage must not grow without bound.
            StorageGrowthBounded::total(64).boxed(),
        ]
    }
}
```

Then one line runs it:

```rust
#[test]
fn token_invariants_hold() {
    check(TokenTarget, FuzzConfig::from_env());
}
```

A complete, runnable version is in [`examples/token_fuzz.rs`](examples/token_fuzz.rs):

```bash
cargo run --example token_fuzz
```

It fuzzes a token once without a privileged entrypoint (clean) and once with it
(reports the planted missing-`require_auth` bug, shrunk to a single call).

## Concepts

**Target** — the contract under test plus its reference model. `State` is the model
(keep it plain and cheap to clone), `Action` is an enum of the operations to generate,
`World` holds the addresses deployment produced.

**Model, not reflection.** Sequences are generated and shrunk against the *model*, then
replayed against the contract. That keeps shrinking fast and every shrunken sequence
valid, and it lets invariants compare the contract against an independent
specification instead of re-deriving the contract's own logic.

**Execution.** `Target::execute` runs one action. Route contract calls through
`Runtime::call`, which snapshots storage before and after, captures the host's resource
metering, records everything in the run journal, applies the resource policy, and
classifies the result.

**Classification.** A generated client's `try_*` method returns
`Result<Result<V, ConversionError>, Result<E, InvokeError>>`. The harness flattens that
into `CallResult<V>`, and the conversion you choose expresses your intent:

| Conversion | Use for |
| --- | --- |
| `into_step()` | Calls whose failure is routine |
| `expect_ok()` | Calls that must succeed for the input to be meaningful |
| `expect_rejected()` | Negative tests: authorization that must not be granted |
| `expect_contract_error()` | Asserting a business error rather than a trap |

`expect_rejected()` accepts both a declared contract error and a host-level trap,
because a failed `require_auth` surfaces as either depending on whether the entrypoint
declares a typed error. `tests/classification.rs` pins those shapes down.

**Invariants** are checked after every action and on the initial state. `FnInvariant`
covers the general case; `SupplyConserved` and `StorageGrowthBounded` cover two
properties worth having out of the box.

## Authorization policy

The default is `AuthPolicy::Strict`: no credentials are mocked, and the policy is
re-applied before every action so one action's authorization never leaks into the next.
`mock_all_auths()` — the habit that makes unit tests hide missing-auth bugs — is opt-in
via `AuthPolicy::MockAll`.

Even under `MockAll`, `Runtime::call_without_auth` clears the credentials for a single
call, so the negative path stays testable.

## Resource budgets

`ResourcePolicy::Enforce` (the default) disables the SDK's own limit enforcement and
applies `FuzzConfig::limits` in the harness instead. A breach is then a structured
finding naming the limit, the measured value and the excess — instead of an opaque
panic from inside the host.

```rust
let mut limits = mainnet_limits();
limits.instructions = 100_000_000;      // stricter than the network
let config = FuzzConfig::default().limits(limits);
```

Measured resources approximate a real transaction rather than predicting it exactly:
transaction size, the return value, and XDR round-trips are not modelled, and natively
registered contracts hide VM instantiation cost. Treat a reported breach as a strong
signal and a reported non-breach as reassurance rather than proof.

## Reproducing and CI

Every run reports the seed it used, and an unpinned run picks one for you. Pin it to
replay a failure exactly:

```rust
run(TokenTarget, FuzzConfig::default().seed(9719402080364109389));
```

`FuzzConfig::from_env()` reads CI-friendly overrides, so a pipeline can widen a run
without a code change:

| Variable | Meaning |
| --- | --- |
| `SOROBAN_FUZZ_CASES` | Number of cases to run |
| `SOROBAN_FUZZ_SEED` | Fixed RNG seed |
| `SOROBAN_FUZZ_MAX_ACTIONS` | Maximum actions per sequence |
| `SOROBAN_FUZZ_REPORT` | Path for the JSON failure report |

A failure writes a machine-readable report that CI can consume:

```rust
let outcome = run(TokenTarget, FuzzConfig::from_env());
outcome.assert_ok();                      // panics with the rendered report
```

`FailureReport` serializes to JSON (`kind`, `detail`, `seed`, `minimal_sequence`,
per-call resource usage) for upload as a build artefact.

This repository's [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) is a working
example of both halves: a job that formats, lints and tests the workspace in debug and
release, and a job that fuzzes the example contract, **asserts the report is a
one-call reproducer with metered resource usage**, and uploads the report as an
artefact. The assertion is the point — it fails loudly if a detector silently stops
firing.

## What the harness handles for you

- Fresh, isolated environment per case, with the SDK's snapshot-at-drop writing
  disabled so a run does not litter `test_snapshots/`.
- Panic output from shrink iterations suppressed on the running thread, so the report
  is readable. The payload is still captured and included.
- Ledger control (`rt.ledger().advance(n)`) so TTL and time-based logic is reachable.
- Storage snapshots read from the host directly, keyed by owning contract, so entries
  from different contracts never collide and reads work outside a contract context.

## Status

This crate is the property-fuzzer component of a larger toolkit. The static analyser
(detector engine, resource-budget estimator, SARIF output for PR review) is a separate
component and is not in this repository yet. Detector-per-PR contributions are the
intended development model, so scoped issues and focused pull requests are welcome.

## License

Apache-2.0.
