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
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

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

                // Authorize exactly this invocation, for exactly this actor.
                rt.authorize(
                    &from_addr,
                    &contract,
                    "transfer",
                    (from_addr.clone(), to_addr.clone(), *amount),
                );

                let client = TokenClient::new(rt.env(), &contract);
                rt.call("transfer", || client.try_transfer(&from_addr, &to_addr, amount))
                    .expect_ok()
            }
            Act::AdvanceLedger { ledgers } => {
                rt.ledger().advance(*ledgers);
                StepOutcome::ok()
            }
        }
    }

    // Only this contract has state in the environment, so every snapshot can skip
    // everything else in the ledger.
    fn tracked_contracts(&self, world: &World) -> Vec<Address> {
        vec![world.contract.clone()]
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
| `expect_rejected()` | Negative tests: a call that must not go through |
| `expect_contract_error()` | Asserting a business error rather than a trap |

`expect_rejected()` accepts both a declared contract error and a host-level trap,
because a failed `require_auth` surfaces as either depending on whether the entrypoint
declares a typed error. `tests/classification.rs` pins those shapes down — along with a
measurement that is worth knowing before writing a negative test, below.

**Invariants** are checked after every action and on the initial state. `FnInvariant`
covers the general case; `SupplyConserved` and `StorageGrowthBounded` cover two
properties worth having out of the box. They must be read-only: the harness compares
storage snapshots around every check and fails the case if a check wrote, because a
checker that mutates the contract makes the run's results depend on the checker rather
than on the contract.

**Authorization.** `Runtime::authorize(&address, &contract, fn_name, args)` is the
built-in shorthand for "this address authorizes this entrypoint with exactly these
arguments". No helper needs to be written per target. `Runtime::install_auths` takes raw
`MockAuth` values for credential trees, which is what a call that authorizes onward
sub-invocations needs — see `tests/third_party.rs` for a worked example.

**Scoping.** `Target::tracked_contracts` names the contracts a run cares about, with an
empty list (the default) meaning "the whole ledger". See [Performance](#performance) for
why this is the biggest lever on throughput, and name *every* contract the run touches:
entries belonging to a contract that is not named are invisible to your invariants and to
the read-only guard.

**Ledger boundaries.** `rt.ledger().advance(n)` moves the clock within the current
transaction; `rt.ledger().close_ledger(n)` ends it and starts a new ledger, which is
where the network applies rent and TTL expiry. See [Multi-ledger
scenarios](#multi-ledger-scenarios).

## Negative authorization tests: why `expect_rejected` is not enough

The default `AuthPolicy::Strict` means a privileged entrypoint with no credentials is
refused, so `call_without_auth(...).expect_rejected()` looks like a complete test. It is
not, and the reason is a property of the environment rather than a gap in the harness.

**A failed `require_auth` and a contract that merely panics are indistinguishable at
the error level.** Measured against `soroban-sdk` 27 and pinned in
`tests/classification.rs`:

| Entrypoint | Failed `require_auth` | Plain `panic!` |
| --- | --- | --- |
| Declares no error type | `Err(Ok(Error(Context, InvalidAction)))` | *identical* |
| Declares a typed error | `Err(Err(InvokeError::Abort))` | *identical* |

The `Error` in the first row is not even typed as an authorization error: its
`is_type(ScErrorType::Auth)` is `false`. So no inspection of the returned error can tell
"refused because the caller was not authorized" from "panicked before it ever looked at
authorization" — and a negative test built on the error therefore passes for the wrong
reason whenever the entrypoint refuses on its input first.

`Runtime::call_requiring_auth` asserts the property **positively** instead. It switches
the host to recording authorization, runs the call, and reads the authorization tree the
contract actually demanded:

```rust
// Either form proves `transfer` is gated on `from`'s authorization. This one also
// proves the balance check did not get in the way, because the call had to succeed.
rt.call_requiring_auth("transfer", &from, || client.try_transfer(&from, &to, &amount))
```

It is the mechanism the SDK's own documentation recommends for exactly this question —
*"a test that uses `mock_all_auths` without verifying the resulting authorization tree
can pass even when a contract is missing a `require_auth` check"* — turned into one call
with a finding attached.

Its cost is honest and worth stating: recording authorization means the credential is
never refused, so **a correctly protected entrypoint runs to completion** and its state
changes are real. The action's model has to account for that, exactly as it would for any
positive call, and an entrypoint that fails on its input is reported as a violation
rather than a pass. `tests/classification.rs` has both directions, plus a test that the
lenient conversion accepts what the strict one rejects — so the difference between them
is a fact rather than a claim in this file.

## Multi-ledger scenarios

The default environment gives each case one ledger, which is enough for a great deal and
not enough for anything the network applies at a ledger boundary: rent, TTL expiry, and
reclamation of expired temporary entries.

`rt.ledger().close_ledger(n)` ends the transaction and starts the next ledger `n`
ledgers later. It is distinct from `advance(n)`, which moves the clock *within* the
current transaction, and it records the boundary in the run's journal so a report shows
where time moved rather than leaving a two-action reproducer looking like a single
instant.

What becomes reachable is exactly the class of bug a single-ledger run cannot find. An
allowance whose deadline is in the past reads as zero because the host has reclaimed the
expired entry rather than merely left it stale; a temporary entry past its TTL is gone; a
contract that reads a ledger number once keeps serving it until something forces a
re-read. `tests/third_party.rs` drives all three stages through the real vendored token
— approve with a short deadline, close the ledger past it, then spend — and asserts that
**every** generated sequence reached the spend and had it refused.

One fidelity note, stated rather than glossed: the test host applies expiry *lazily*, on
the next read, rather than sweeping at close. So in this environment the observable
difference from `advance` is that the boundary is explicit and journalled, not that state
is swept here.

## Preconditions: what keeps shrinking honest

A generated action is only meaningful if the contract could accept it, and
`Target::preconditions` is where you say so. It matters more than it looks: proptest's
shrinker consults preconditions too, and without them it will happily reduce a failing
case to an action the generator could never have produced.

This is not hypothetical. When the real-token fixture below was being written, a
finding shrank to a `burn(actor1, 1)` **from an actor holding nothing** — which panics,
and therefore still counts as "fails", so the shrinker kept it. The reported reproducer
then describes a different bug than the one that was found, and sends you chasing it.

```rust
fn preconditions(&self, state: &Model, action: &Act) -> bool {
    match action {
        Act::Transfer { from, amount, .. } => *amount <= state.balances[*from],
        Act::Burn { from, amount } => *amount <= state.balances[*from],
        // ... anything else the model knows must hold of the input.
        _ => true,
    }
}
```

Anything the model knows must hold of the input belongs here, including the conditions
the generator already enforces. Preconditions are also checked during generation, so
they filter as well as protect.

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

## Performance

`cargo bench -p soroban-fuzzer` prints these. They are wall-clock means from repeated
runs on the machine that built this crate, against the vendored real token contract,
and they are quoted as **ranges across those runs** — a single figure would be a lie.
A shared CI runner is slower and noisier still, which is why CI asserts only that every
measurement is still reported, never its value.| Operation | Cost |
| --- | --- |
| create a test environment | 1.3–2.3 µs |
| create an environment and deploy the real token | 129–161 µs |
| `StorageSnapshot::capture`, 1 entry | 1.7–3.1 µs |
| `StorageSnapshot::capture`, 16 entries | 18–47 µs |
| `StorageSnapshot::capture`, 256 entries | 363–737 µs |
| `capture_scoped`, 4 own + 64 foreign entries | 4.9–19 µs |
| `capture_scoped`, 4 own + 256 foreign entries | 10–29 µs |
| the same two captures unscoped | 83–269 µs / 407–599 µs |
| read the last invocation's resource metering | 3.4–8 ns |
| one case of one action, contract work only | 305–375 µs |
| one case of one action, through the harness | 365–427 µs |
| one case of eight actions, through the harness | 1.59–1.93 ms |

In round numbers that is **2,340–2,740 cases/s at one action per case** and
**520–630 cases/s at eight** — so 10,000 one-action cases is a few seconds of fuzzing.
The harness's own overhead is ~60–120 µs per case.

Three numbers are worth planning around rather than quoting:

* **Snapshot cost is linear in total ledger entries** and is paid twice per
  instrumented call. A contract holding 256 persistent entries spends ~0.4–0.7 ms per
  snapshot before it does any work of its own, which is comparable to the whole cost of
  a small case. This is what `Target::tracked_contracts` is for.
* **Scoping is the lever, and it scales with foreign state.** Capturing only the
  contracts under test instead of the whole ledger measured **roughly 10–20× faster**
  with 64–256 entries belonging to another contract, and the ratio grows with that
  number: a full capture pays for every entry in the environment on every call, a scoped
  one pays only for its own. It shows up end-to-end only to the extent the environment
  actually holds foreign state — a single-contract case in a fresh `Env` has almost
  none, which is why the `run:` rows above are flat across the full and scoped variants
  while the `capture_scoped` rows are not.
* **Deploy dominates cheap cases.** A fresh environment and a fresh deployment per case
  is what makes a counterexample trustworthy — nothing leaks between cases — and it is
  the main lever on throughput. It is not a knob; it is the property you are paying for.

## Reusing an `Arbitrary` definition

If an action type already derives `arbitrary::Arbitrary` — much Soroban code and internal
tooling does — you do not have to write a strategy for it:

```rust
fn actions(&self, _state: &Model) -> BoxedStrategy<Act> {
    from_arbitrary()
}
```

`from_arbitrary()` and `from_arbitrary_with()` turn any `Arbitrary` type into a proptest
`Strategy`; `tests/diagnostics.rs` drives a target through the bridge end to end.

## Validated against a real contract

`tests/third_party.rs` fuzzes a contract this harness did not design:
[`stellar/soroban-examples`](https://github.com/stellar/soroban-examples)' token,
vendored byte-for-byte under `third-party/soroban-token-example/` (see
`PROVENANCE.md`; `third-party/verify.sh` re-checks it against its pinned revision).

It is a useful counterweight to the crate's own fixtures, which were written to be
fuzzable. The real token's interface is fixed by the Soroban token standard, and it
exercises shapes the hand-written fixtures do not: `MuxedAddress` destinations,
temporary storage with per-entry TTL for allowances alongside persistent balances and
instance metadata, `soroban_token_sdk` events, and global TTL extension on every
entrypoint.

It also has **no `total_supply` view**, because the standard token interface does not
define one. The conservation-of-supply invariant therefore does not read it from the
contract: it sums the contract's own persistent balance entries out of the harness's
storage snapshot. That only works because entries are attributed to their owning
contract — which is exactly what the second half of that file depends on, where a
small vault composes with the token and the vault's own `i128` bookkeeping sits in the
same ledger as the token's balances.

The same file also covers the ledger boundary (an allowance written, a ledger closed
past its deadline, the spend refused) and pins the scoped-capture equivalence against a
two-contract ledger, including the fact that `mock_all_auths` leaves a temporary nonce
entry per authorizing address — an entry owned by that address rather than by any
contract, and correctly excluded from a scoped snapshot.

## Reproducing and CI

Every run reports the seed it used, and an unpinned run picks one for you. Pin it to
replay a failure exactly:

```rust
run(TokenTarget, FuzzConfig::default().seed(9719402080364109389));
```

Re-running a whole run to reproduce one case is a lot of noise when a target takes
minutes, so a case can be selected by index. The seed remains the only source of
randomness — every earlier case is still *generated* and discarded, so the selected case
is the same one the full run produced:

```rust
run(TokenTarget, FuzzConfig::default().seed(9719402080364109389).replay_case(37));
```

An index without a seed is refused rather than answered wrongly, because the index names
a position in a stream that does not otherwise exist. `tests/diagnostics.rs` asserts the
equivalence case by case.

`FuzzConfig::from_env()` reads CI-friendly overrides, so a pipeline can widen a run
without a code change:

| Variable | Meaning |
| --- | --- |
| `SOROBAN_FUZZ_CASES` | Number of cases to run |
| `SOROBAN_FUZZ_SEED` | Fixed RNG seed |
| `SOROBAN_FUZZ_MAX_ACTIONS` | Maximum actions per sequence |
| `SOROBAN_FUZZ_REPORT` | Path for the JSON failure report |
| `SOROBAN_FUZZ_REPLAY` | Run only this case of the seeded sequence |

A failure writes a machine-readable report that CI can consume:

```rust
let outcome = run(TokenTarget, FuzzConfig::from_env());
outcome.assert_ok();                      // panics with the rendered report
```

`FailureReport` serializes to JSON (`kind`, `detail`, `seed`, `minimal_sequence`,
per-call resource usage, the storage each call touched, and the action ratio of the
cases that led up to the failure) for upload as a build artefact.

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
- Ledger control (`rt.ledger().advance(n)`, and `rt.ledger().close_ledger(n)` to cross
  a ledger boundary) so TTL and time-based logic is reachable.
- Storage snapshots read from the host directly, keyed by owning contract, so entries
  from different contracts never collide and reads work outside a contract context —
  and scopable to the contracts under test, at a measured 10–20× less work.
- A guard that fails a case whose invariants wrote to storage, reporting which
  durability and which entries changed.
- A diagnostic on every passing run: the ratio of accepted to unexpectedly-rejected
  actions, with a warning when most generated calls were refused. "No findings in 200
  cases" is only evidence if the cases reached the contract, and the two look identical
  without it. Negative tests you *meant* to be refused are declared with
  `Target::expects_rejection` and kept out of the ratio, so the warning stays meaningful.

## Limitations

Worth knowing before you trust a green run.

**The fuzzer only explores what your model describes.** Sequences are generated from
`actions`, filtered by `preconditions`, and checked against `invariants`. A contract
behaviour the model does not mention is not fuzzed, and a model that disagrees with the
contract produces confusing findings rather than useful ones. This is inherent to
generating inputs from a model rather than from the contract's own interface; the
harness's contribution is that the disagreement surfaces as a failing invariant with a
minimal reproducer. Nothing validates the model for you, and a green run means "no
sequence I generated broke a property you stated", not "this contract is correct".

**`into_step()` is lenient about traps.** It treats a host-level trap as a rejection,
because a correctly-refusing entrypoint with a typed error surfaces as a trap, so a
stricter default would produce false positives. The consequence is that a genuine panic
on valid input passes silently under `into_step()`; use `expect_ok()` for calls whose
input is valid by construction, and `expect_contract_error()` when you want a panic to
be a finding.

**Invariant checks tolerate one snapshot change.** The read-only guard permits a
*temporary* entry to disappear during a check, because the host reclaims expired
temporary entries when reading them — a read-only check can therefore make one vanish.
Nothing else is tolerated: any change to instance or persistent data, and any addition
or value update in temporary storage, fails the case.

**One environment per case.** Cross-contract composition works and is tested, and
ledger boundaries are supported (`rt.ledger().close_ledger`) for the state the network
changes at them, but each case still runs in a single `Env` that is thrown away
afterwards. There is no support for a persistent multi-case ledger, for multiple
accounts' nonces, or for anything that needs two environments to interact.

**`expect_rejected` cannot tell an authorization refusal from a panic.** This is a
limitation of the environment, not of the harness — the shapes are byte-identical, as
the table above shows. Use `call_requiring_auth` when it matters; the lenient form is
fine when the only property you need is "the call did not go through".

**The read-only guard is scoped when the run is scoped.** A change an invariant makes to
a *contract you did not name in `tracked_contracts`* is invisible to the guard. The
default (name nothing) captures the whole ledger and is the safe direction; under-naming
narrows what the harness can notice.

## Status and API stability

0.1.x. The `Target` trait, the invariants and the runtime are expected to be stable;
`report.rs`'s output shape may still change as the consumer side (SARIF, PR review) is
designed. As semver requires while a crate is 0.x, a breaking change bumps the minor
version — treat every 0.x minor bump as potentially breaking.

This crate is the property-fuzzer component of a larger toolkit. The static analyser
(detector engine, resource-budget estimator, SARIF output for PR review) is a separate
component and is not in this repository yet. Detector-per-PR contributions are the
intended development model, so scoped issues and focused pull requests are welcome —
see [`CONTRIBUTING.md`](../CONTRIBUTING.md), which also states the bar a detector has to
clear (a fixture proving it fires, and one proving it does not over-fire).

## License

Apache-2.0.
