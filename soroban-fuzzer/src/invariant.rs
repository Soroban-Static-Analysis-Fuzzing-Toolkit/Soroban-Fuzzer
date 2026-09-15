//! Invariants: the properties a fuzz run tries to break.
//!
//! An invariant is a predicate over the world after every action — and over the
//! initial state. When it returns `Err`, the harness records the reason, fails the
//! case, and proptest shrinks the action sequence to the minimum that still breaks
//! it.
//!
//! Invariants receive a [`CheckCtx`], which carries the environment, the deployed
//! world, and the *model state* after the action. Having the model available lets
//! you assert the contract against a specification rather than only against the
//! contract's own storage:
//!
//! ```
//! use soroban_fuzzer::prelude::*;
//!
//! struct MyTarget;
//! # impl Target for MyTarget {
//! #   type State = ();
//! #   type Action = ();
//! #   type World = ();
//! #   fn init_state(&self) -> BoxedStrategy<()> { Just(()).boxed() }
//! #   fn setup(&self, _: &soroban_sdk::Env, _: &()) -> () {}
//! #   fn actions(&self, _: &()) -> BoxedStrategy<()> { Just(()).boxed() }
//! #   fn next_state(&self, _: (), _: &()) -> () {}
//! #   fn execute(&self, _: &mut Runtime<'_, ()>, _: &()) -> StepOutcome { StepOutcome::ok() }
//! # }
//! # fn demo() -> Vec<Box<dyn Invariant<MyTarget>>> {
//! vec![
//!     // The contract's balance total must match the model's, after every action.
//!     FnInvariant::new("balances-match-model", |ctx: &CheckCtx<'_, MyTarget>| {
//!         let _ = (ctx.model, ctx.env, ctx.world);
//!         Ok(())
//!     })
//!     .boxed(),
//!     // Storage must never grow past 64 entries.
//!     StorageGrowthBounded::total(64).boxed(),
//! ]
//! # }
//! ```
//!
//! Most projects only need [`FnInvariant`]; [`StorageGrowthBounded`],
//! [`SupplyConserved`] and [`NonDecreasing`] cover three properties worth having out of
//! the box.

use core::cell::Cell;
use core::fmt::Debug;

use soroban_sdk::Env;

use crate::storage::{StorageSnapshot, StoreKind};
use crate::target::Target;

/// Everything an invariant may inspect.
pub struct CheckCtx<'a, T: Target> {
    /// The Soroban test environment.
    pub env: &'a Env,
    /// The deployed world.
    pub world: &'a T::World,
    /// The model state *after* the action, or the initial state on the first check.
    pub model: &'a T::State,
    /// The action that just ran; `None` for the check on the initial state.
    pub action: Option<&'a T::Action>,
    /// Zero-based index of the action that just ran.
    pub step: usize,
}

impl<T: Target> CheckCtx<'_, T> {
    /// True for the check that runs before any action.
    pub fn is_initial(&self) -> bool {
        self.action.is_none()
    }
}

/// A property that must hold at every point in a fuzz case.
pub trait Invariant<T: Target> {
    /// Stable name, reported when the invariant fails.
    fn name(&self) -> &str;

    /// Checks the property. `Err` describes what was violated.
    fn check(&self, ctx: &CheckCtx<'_, T>) -> Result<(), String>;

    /// Whether to check before any action has run. Defaults to `true`.
    fn check_initial(&self) -> bool {
        true
    }
}

impl<T: Target> Debug for dyn Invariant<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// An invariant backed by a closure, for the common one-off case.
pub struct FnInvariant<F> {
    name: String,
    check: F,
    check_initial: bool,
}

impl<F> FnInvariant<F> {
    /// Creates an invariant that is also checked on the initial state.
    pub fn new(name: impl Into<String>, check: F) -> Self {
        Self {
            name: name.into(),
            check,
            check_initial: true,
        }
    }

    /// Skips the check on the initial state.
    ///
    /// Useful when a property only makes sense once setup actions have run.
    pub fn skip_initial(mut self) -> Self {
        self.check_initial = false;
        self
    }

    /// Erases the closure into an [`Invariant`] object.
    pub fn boxed<T: Target>(self) -> Box<dyn Invariant<T>>
    where
        F: for<'a> Fn(&CheckCtx<'a, T>) -> Result<(), String> + 'static,
    {
        Box::new(self)
    }
}

impl<T, F> Invariant<T> for FnInvariant<F>
where
    T: Target,
    F: for<'a> Fn(&CheckCtx<'a, T>) -> Result<(), String>,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, ctx: &CheckCtx<'_, T>) -> Result<(), String> {
        (self.check)(ctx)
    }

    fn check_initial(&self) -> bool {
        self.check_initial
    }
}

/// Fails when a contract's storage grows past a ceiling.
///
/// The cheapest way to catch unbounded storage growth: an action that adds an entry
/// per call (a loop that never converges, a list that is appended to but never
/// pruned) will exceed any ceiling within a short sequence.
pub struct StorageGrowthBounded {
    name: String,
    kind: Option<StoreKind>,
    max_entries: usize,
}

impl StorageGrowthBounded {
    /// Bounds total entries across instance, persistent and temporary storage.
    pub fn total(max_entries: usize) -> Self {
        Self {
            name: format!("storage-growth<= {max_entries} entries"),
            kind: None,
            max_entries,
        }
    }

    /// Bounds entries in a single durability.
    pub fn per_store(kind: StoreKind, max_entries: usize) -> Self {
        Self {
            name: format!("{kind}-storage-growth<= {max_entries} entries"),
            kind: Some(kind),
            max_entries,
        }
    }

    /// Erases into an [`Invariant`] object.
    pub fn boxed<T: Target>(self) -> Box<dyn Invariant<T>> {
        Box::new(self)
    }
}

impl<T: Target> Invariant<T> for StorageGrowthBounded {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, ctx: &CheckCtx<'_, T>) -> Result<(), String> {
        let counts = StorageSnapshot::capture(ctx.env).counts();
        let used = match self.kind {
            Some(kind) => counts.of(kind),
            None => counts.total(),
        };
        if used > self.max_entries {
            let scope = match self.kind {
                Some(kind) => format!("{kind} storage"),
                None => "storage".to_owned(),
            };
            Err(format!(
                "{scope} holds {used} entries, exceeding the ceiling of {}",
                self.max_entries
            ))
        } else {
            Ok(())
        }
    }
}

/// Reads a quantity out of the contract, given the environment and the world.
pub type SupplyReader<W> = Box<dyn Fn(&Env, &W) -> i128>;

/// Fails when a value read out of the contract changes from the value it had when
/// the case started.
///
/// This is the "total supply must be conserved" property in the shape it usually
/// takes: read a quantity out of the contract at the start of the case, and require
/// that no generated operation changes it. The baseline is captured automatically
/// on the initial check, so it is the state *after setup*, not before deployment.
///
/// ```
/// use soroban_fuzzer::prelude::*;
/// # struct MyTarget;
/// # impl Target for MyTarget {
/// #   type State = ();
/// #   type Action = ();
/// #   type World = ();
/// #   fn init_state(&self) -> BoxedStrategy<()> { Just(()).boxed() }
/// #   fn setup(&self, _: &soroban_sdk::Env, _: &()) -> () {}
/// #   fn actions(&self, _: &()) -> BoxedStrategy<()> { Just(()).boxed() }
/// #   fn next_state(&self, _: (), _: &()) -> () {}
/// #   fn execute(&self, _: &mut Runtime<'_, ()>, _: &()) -> StepOutcome { StepOutcome::ok() }
/// # }
/// # fn demo() -> Box<dyn Invariant<MyTarget>> {
/// SupplyConserved::new("total-supply", |_env: &soroban_sdk::Env, _world: &()| {
///     // Read the contract's total supply here; 1_000_000_000 in this example.
///     1_000_000_000i128
/// })
/// .boxed()
/// # }
/// ```
pub struct SupplyConserved<W> {
    name: String,
    read: SupplyReader<W>,
    baseline: Cell<Option<i128>>,
}

impl<W: 'static> SupplyConserved<W> {
    /// Creates the invariant from a reader that pulls the quantity out of the
    /// contract.
    ///
    /// The reader runs on the initial check and after every action.
    pub fn new(name: impl Into<String>, read: impl Fn(&Env, &W) -> i128 + 'static) -> Self {
        Self {
            name: name.into(),
            read: Box::new(read),
            baseline: Cell::new(None),
        }
    }

    /// Erases into an [`Invariant`] object.
    pub fn boxed<T: Target<World = W>>(self) -> Box<dyn Invariant<T>> {
        Box::new(self)
    }
}

impl<T: Target> Invariant<T> for SupplyConserved<T::World> {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, ctx: &CheckCtx<'_, T>) -> Result<(), String> {
        let observed = (self.read)(ctx.env, ctx.world);
        match self.baseline.get() {
            None => {
                // First check of the case: remember what we started from.
                self.baseline.set(Some(observed));
                Ok(())
            }
            Some(expected) if expected == observed => Ok(()),
            Some(expected) => Err(format!(
                "{} changed: expected {expected}, observed {observed}",
                self.name
            )),
        }
    }
}

/// Fails when a quantity read out of the contract is ever lower than it was the last
/// time it was read.
///
/// A cumulative quantity — total fees collected, deposits ever made, a nonce, an
/// issuance counter — only grows. A step that makes it go *backwards* is a strong
/// reason to look, because on Soroban the usual cause is not arithmetic but a lost
/// write: an entry that expired or was reclaimed reads as absent, and a contract that
/// serves `unwrap_or(0)` for it reports a total of zero rather than failing. A
/// contract that writes a growing counter to `temporary` storage, or to `persistent`
/// storage with a TTL it never extends, is a contract whose books quietly reset.
///
/// Contrast with [`SupplyConserved`], which requires a quantity to be *exactly* what it
/// was. This one permits growth, so it is the right shape for anything that accrues.
///
/// The comparison is against the previous check rather than the start of the case, so
/// the report names the step where the value dropped.
///
/// ```
/// use soroban_fuzzer::prelude::*;
/// # struct MyTarget;
/// # impl Target for MyTarget {
/// #   type State = ();
/// #   type Action = ();
/// #   type World = ();
/// #   fn init_state(&self) -> BoxedStrategy<()> { Just(()).boxed() }
/// #   fn setup(&self, _: &soroban_sdk::Env, _: &()) -> () {}
/// #   fn actions(&self, _: &()) -> BoxedStrategy<()> { Just(()).boxed() }
/// #   fn next_state(&self, _: (), _: &()) -> () {}
/// #   fn execute(&self, _: &mut Runtime<'_, ()>, _: &()) -> StepOutcome { StepOutcome::ok() }
/// # }
/// # fn demo() -> Box<dyn Invariant<MyTarget>> {
/// NonDecreasing::new("fees-collected", |_env: &soroban_sdk::Env, _world: &()| {
///     // Read the contract's cumulative total here; 0 in this example.
///     0i128
/// })
/// .boxed()
/// # }
/// ```
pub struct NonDecreasing<W> {
    name: String,
    read: SupplyReader<W>,
    previous: Cell<Option<i128>>,
}

impl<W: 'static> NonDecreasing<W> {
    /// Creates the invariant from a reader that pulls the quantity out of the
    /// contract.
    ///
    /// The reader runs on the initial check and after every action, which is what makes
    /// the first value it returns the baseline.
    pub fn new(name: impl Into<String>, read: impl Fn(&Env, &W) -> i128 + 'static) -> Self {
        Self {
            name: name.into(),
            read: Box::new(read),
            previous: Cell::new(None),
        }
    }

    /// Erases into an [`Invariant`] object.
    pub fn boxed<T: Target<World = W>>(self) -> Box<dyn Invariant<T>> {
        Box::new(self)
    }
}

impl<T: Target> Invariant<T> for NonDecreasing<T::World> {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, ctx: &CheckCtx<'_, T>) -> Result<(), String> {
        let observed = (self.read)(ctx.env, ctx.world);
        let previous = self.previous.get();

        // The value is remembered even when the check fails, so a later step that moves
        // it again reports the drop that just happened rather than the first one.
        self.previous.set(Some(observed));

        match previous {
            Some(previous) if observed < previous => Err(format!(
                "{} went backwards: was {previous}, now {observed} (a stored value that \
                 reads as a default usually means an entry expired or was reclaimed)",
                self.name
            )),
            _ => Ok(()),
        }
    }
}
