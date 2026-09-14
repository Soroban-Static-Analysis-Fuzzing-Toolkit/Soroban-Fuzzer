//! The [`Target`] trait: everything the harness needs to fuzz a contract.
//!
//! A target is a description of a contract under test plus a reference model of
//! what it is supposed to do. The harness generates sequences of actions from
//! [`Target::actions`], drives them through [`Target::execute`], and checks
//! [`Target::invariants`] after every one.
//!
//! The [`State`](Target::State) type is the *model*: your own bookkeeping of what
//! the contract should hold. Keeping the model deliberately simple — often just
//! balances in a `BTreeMap` — is what makes fuzzing effective, because invariants
//! can compare the contract against an independent specification instead of
//! re-deriving the contract's own logic.
//!
//! ```
//! use soroban_fuzzer::prelude::*;
//! use soroban_sdk::{Address, Env};
//!
//! // The model: total deposits seen so far.
//! #[derive(Clone, Debug, Default)]
//! struct Model {
//!     deposits: i128,
//! }
//!
//! // The operations to generate.
//! #[derive(Clone, Debug)]
//! enum Act {
//!     Deposit { amount: i128 },
//!     Snapshot,
//! }
//!
//! // Deployment artefacts.
//! struct World {
//!     caretaker: Address,
//! }
//!
//! struct DepositTarget;
//!
//! impl Target for DepositTarget {
//!     type State = Model;
//!     type Action = Act;
//!     type World = World;
//!
//!     fn init_state(&self) -> BoxedStrategy<Model> {
//!         Just(Model::default()).boxed()
//!     }
//!
//!     fn setup(&self, env: &Env, _initial: &Model) -> World {
//!         use soroban_sdk::testutils::Address as _;
//!         World { caretaker: Address::generate(env) }
//!     }
//!
//!     fn actions(&self, _state: &Model) -> BoxedStrategy<Act> {
//!         prop_oneof![
//!             4 => (1i128..=1_000).prop_map(|amount| Act::Deposit { amount }),
//!             1 => Just(Act::Snapshot),
//!         ]
//!         .boxed()
//!     }
//!
//!     fn next_state(&self, mut state: Model, action: &Act) -> Model {
//!         if let Act::Deposit { amount } = action {
//!             state.deposits += amount;
//!         }
//!         state
//!     }
//!
//!     fn execute(&self, _rt: &mut Runtime<'_, World>, _action: &Act) -> StepOutcome {
//!         // Call the contract here, for example:
//!         // rt.call("deposit", || client.try_deposit(&amount)).expect_ok()
//!         StepOutcome::ok()
//!     }
//!
//!     fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
//!         vec![FnInvariant::new("model-is-nonnegative", |ctx: &CheckCtx<'_, Self>| {
//!             if ctx.model.deposits < 0 {
//!                 Err(format!("model went negative: {}", ctx.model.deposits))
//!             } else {
//!                 Ok(())
//!             }
//!         })
//!         .boxed()]
//!     }
//! }
//! ```
//!
//! Because the harness is generic over the target, the same machinery works for a
//! token, an AMM, a lending market or an abstract account. Contract-specific
//! knowledge lives in the target; generation, shrinking, resource metering and
//! reporting live in the harness.

use core::fmt::Debug;

use proptest::prelude::{BoxedStrategy, Just, Strategy};
use soroban_sdk::Env;

use crate::invariant::Invariant;
use crate::runtime::{Runtime, StepOutcome};

/// The contract under test, its model, and how to fuzz it.
///
/// Implementations must be `Send + Sync + 'static` because proptest's strategy
/// combinators require it. In practice a target is a small plain struct; keeping a
/// `Rc` or a `RefCell` inside it will not compile, and is not needed since all
/// mutable contract state lives in the Soroban environment.
pub trait Target: 'static {
    /// The reference model, tracked across the action sequence.
    ///
    /// Keep this a plain data structure. It is cloned and shrunk by proptest, so it
    /// must be cheap to clone.
    type State: Clone + Debug + 'static;

    /// A single generated operation.
    ///
    /// An enum works well: one variant per contract entrypoint you want to fuzz,
    /// with fields holding the arguments.
    type Action: Clone + Debug + 'static;

    /// Deployment artefacts produced by [`Target::setup`].
    ///
    /// Typically the contract address plus any actor addresses. It must not borrow
    /// from the environment; store [`Address`](soroban_sdk::Address) values instead
    /// of references.
    type World: 'static;

    /// Strategy for the model state a case starts from.
    ///
    /// Use [`constant`] for the common case of a fixed initial state. Returning a
    /// generated state lets the fuzzer explore different starting conditions, for
    /// example a randomly pre-populated set of balances.
    fn init_state(&self) -> BoxedStrategy<Self::State>;

    /// Deploys the fixture into `env` and returns the world.
    ///
    /// Called once per case, on a fresh environment. `initial` is the model state
    /// that [`Target::init_state`] produced, so a generated starting state can be
    /// reflected in the deployment (mint the initial balances, and so on).
    fn setup(&self, env: &Env, initial: &Self::State) -> Self::World;

    /// Strategy for the actions valid from `state`.
    ///
    /// Returning a state-dependent set is how you keep generation productive: there
    /// is no point generating a `withdraw` before anything has been deposited. Use
    /// [`proptest::prop_oneof!`] to weight variants.
    fn actions(&self, state: &Self::State) -> BoxedStrategy<Self::Action>;

    /// Filters generated actions before they are used.
    ///
    /// Preconditions are checked during generation *and* while shrinking, so keep
    /// them cheap and deterministic. Rejections are filters, not failures: a
    /// precondition that is hard to satisfy slows the run down, so prefer shaping
    /// [`Target::actions`] over rejecting there.
    fn preconditions(&self, state: &Self::State, action: &Self::Action) -> bool {
        let _ = (state, action);
        true
    }

    /// Applies `action` to the model, returning the new model state.
    ///
    /// This is applied *before* [`Target::execute`] runs, mirroring
    /// `proptest-state-machine`, so invariants see the model state that corresponds
    /// to the world state after the action.
    fn next_state(&self, state: Self::State, action: &Self::Action) -> Self::State;

    /// Runs `action` against the deployed world.
    ///
    /// Route contract calls through [`Runtime::call`] so that resources, storage
    /// writes and outcomes are recorded. Returning
    /// [`StepOutcome::Rejected`](StepOutcome::Rejected) for expected contract errors
    /// keeps the run productive; returning
    /// [`StepOutcome::Violation`](StepOutcome::Violation) fails the case.
    ///
    /// Panicking is also a failure — the harness treats it as a finding, and
    /// proptest shrinks it to a minimal sequence.
    fn execute(&self, rt: &mut Runtime<'_, Self::World>, action: &Self::Action) -> StepOutcome;

    /// Renders an action for failure reports. Defaults to `Debug`.
    fn describe(&self, action: &Self::Action) -> String {
        format!("{action:?}")
    }

    /// The properties that must hold at every step.
    ///
    /// Called once per case, so invariants may capture per-case baselines.
    ///
    /// Note that this trait, like the rest of the harness, uses `std::vec::Vec`.
    /// `soroban_sdk::Vec` shadows it and does not implement `IntoIterator` the same
    /// way, so if a file imports both, alias the SDK's (`Vec as SdkVec`).
    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        Vec::new()
    }
}

/// Wraps a fixed value as a strategy.
///
/// Shorthand for `Just(value).boxed()`, used by [`Target::init_state`] when a case
/// always starts from the same model state.
pub fn constant<S: Clone + Debug + 'static>(value: S) -> BoxedStrategy<S> {
    Just(value).boxed()
}
