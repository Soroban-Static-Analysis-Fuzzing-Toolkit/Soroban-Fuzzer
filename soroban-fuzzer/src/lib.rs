//! Property-based invariant fuzzing for Soroban smart contracts.
//!
//! `soroban-fuzzer` runs generated sequences of contract calls against
//! [`soroban-sdk`](https://docs.rs/soroban-sdk)'s test environment and checks your
//! invariants after every call. When something breaks, `proptest` shrinks the
//! sequence to the shortest call sequence that still reproduces it, and the harness
//! reports the sequence together with the resources each call consumed.
//!
//! It is the invariant half of the Soroban Static Analysis & Fuzzing Toolkit: a
//! free first line of defence for contracts whose only other option is a paid audit.
//!
//! # What it checks that a unit test does not
//!
//! Soroban has vulnerability classes that general Rust tooling does not see.
//! Fuzzing is well suited to three of them in particular.
//!
//! **Missing authorization.** [`AuthPolicy::Strict`] is the default: no authorization
//! is mocked, so a contract that mutates state for an address that never called
//! `require_auth` is rejected during fuzzing. Mocking every authorization — the usual
//! habit in unit tests — hides exactly this bug class, which is why it is not the
//! default here.
//!
//! **Resource-budget blowouts.** Every invocation is metered, and the measured cost
//! is compared against the network's real ceilings: CPU instructions, memory, the
//! 200-entry read limit, write entries, and bytes read and written. A call that
//! cannot land on mainnet is reported as a finding naming the limit, the measured
//! value and the excess, rather than panicking opaquely inside the host.
//!
//! **Unbounded storage growth.** [`StorageGrowthBounded`] fails a case when a
//! contract's ledger entries grow past a ceiling, catching loops that append to
//! storage without converging.
//!
//! # Quick start
//!
//! Describe the contract as a [`Target`]: a reference model, the actions to
//! generate, how to deploy the fixture, how to run an action, and the invariants.
//! Then hand it to [`check`].
//!
//! ```no_run
//! use soroban_fuzzer::prelude::*;
//!
//! struct TokenTarget;
//!
//! # #[derive(Clone, Debug, Default)]
//! # struct Model;
//! # #[derive(Clone, Debug)]
//! # enum Action { Noop }
//! # struct World;
//! impl Target for TokenTarget {
//!     type State = Model;
//!     type Action = Action;
//!     type World = World;
//!
//!     fn init_state(&self) -> BoxedStrategy<Model> {
//!         constant(Model::default())
//!     }
//!
//!     fn setup(&self, _env: &Env, _initial: &Model) -> World {
//!         // Deploy the contract, generate actors, install prices...
//!         World
//!     }
//!
//!     fn actions(&self, _state: &Model) -> BoxedStrategy<Action> {
//!         Just(Action::Noop).boxed()
//!     }
//!
//!     fn next_state(&self, state: Model, _action: &Action) -> Model {
//!         state
//!     }
//!
//!     fn execute(&self, _rt: &mut Runtime<'_, World>, _action: &Action) -> StepOutcome {
//!         // `rt.call("transfer", || client.try_transfer(...)).into_step()`
//!         StepOutcome::ok()
//!     }
//!
//!     fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
//!         vec![StorageGrowthBounded::total(128).boxed()]
//!     }
//! }
//!
//! #[test]
//! fn token_invariants_hold() {
//!     check(TokenTarget, FuzzConfig::from_env().cases(64));
//! }
//! ```
//!
//! A complete, runnable version — a token with a conservation-of-supply invariant and
//! an authorization invariant — lives in `examples/token.rs`. The `tests/`
//! directory covers both a passing target and deliberately buggy targets that the
//! harness must catch and shrink.
//!
//! # How a case runs
//!
//! 1. The initial model state is generated from [`Target::init_state`].
//! 2. A fresh [`Env`] is created, and [`Target::setup`] deploys the fixture into it.
//! 3. [`Target::actions`] generates an action, filtered by [`Target::preconditions`].
//! 4. [`Target::next_state`] advances the model, then [`Target::execute`] runs the
//!    action against the contract. Contract calls go through [`Runtime::call`],
//!    which records resources, storage writes and the outcome.
//! 5. Every invariant is checked. The first failure fails the case.
//! 6. Steps 3–5 repeat until the generated sequence is exhausted.
//! 7. On failure, `proptest` shrinks the sequence to a minimum and the harness
//!    builds a [`FailureReport`].
//!
//! Sequences are generated and shrunk against the *model*, then replayed against the
//! contract, so a shrunken sequence is always valid for the model's state machine.
//!
//! # Budgets and limits
//!
//! By default ([`ResourcePolicy::Enforce`]) the harness disables the SDK's own
//! mainnet limit enforcement and applies [`FuzzConfig::limits`] itself. Breaches then
//! arrive as structured findings instead of a panic from inside the host. Set
//! [`ResourcePolicy::Sdk`] to keep the SDK's enforcement, or
//! [`ResourcePolicy::Record`] to measure without ever failing.
//!
//! Measured resources approximate a real transaction rather than predicting it
//! exactly — see [`ResourceUsage`] for what is and is not modelled.
//!
//! # Reproducing a failure
//!
//! Every run reports the seed it used. Pass it back with [`FuzzConfig::seed`] to
//! replay the same sequences deterministically:
//!
//! ```no_run
//! # use soroban_fuzzer::prelude::*;
//! # struct MyTarget;
//! # impl Target for MyTarget {
//! #   type State = (); type Action = (); type World = ();
//! #   fn init_state(&self) -> BoxedStrategy<()> { Just(()).boxed() }
//! #   fn setup(&self, _: &Env, _: &()) -> () {}
//! #   fn actions(&self, _: &()) -> BoxedStrategy<()> { Just(()).boxed() }
//! #   fn next_state(&self, _: (), _: &()) -> () {}
//! #   fn execute(&self, _: &mut Runtime<'_, ()>, _: &()) -> StepOutcome { StepOutcome::ok() }
//! # }
//! let outcome = run(MyTarget, FuzzConfig::default().seed(0x5EED).cases(256));
//! ```
//!
//! # Feature flags
//!
//! * `std` (default) — enables the failure-report writers that touch the filesystem.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

pub mod budget;
pub mod config;
pub mod invariant;
pub mod prelude;
pub mod report;
pub mod runner;
pub mod runtime;
pub mod storage;
pub mod target;

pub use budget::{
    mainnet_limits, InvocationResourceLimits, InvocationResources, LimitBreach, ResourceUsage,
};
pub use config::{AuthPolicy, FuzzConfig, ResourcePolicy};
pub use invariant::{
    CheckCtx, FnInvariant, Invariant, StorageGrowthBounded, SupplyConserved, SupplyReader,
};
pub use report::{CallRecord, FailureReport, FuzzOutcome, Journal, ReportConfig, StepRecord};
pub use runner::{check, run};
pub use runtime::{CallResult, LedgerCtl, Runtime, StepOutcome};
pub use storage::{
    ChangeSet, Entry, EntryCounts, EntryKey, EntryMap, StorageDelta, StorageSnapshot, StoreKind,
};
pub use target::{constant, Target};
