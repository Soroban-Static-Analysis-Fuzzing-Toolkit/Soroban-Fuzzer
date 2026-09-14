//! The execution context handed to a target's actions.
//!
//! [`Runtime`] is how an action talks to the contract under test. Every contract
//! call should go through [`Runtime::call`], which
//!
//! 1. snapshots storage before the call,
//! 2. runs the call,
//! 3. snapshots storage again and captures the host's resource metering,
//! 4. checks the measured resources against the network limits,
//! 5. records all of the above in the run journal for the failure report,
//! 6. classifies the result as success, an expected contract rejection, or a
//!    violation.
//!
//! Because the classification lives here, an action can be written as a single
//! expression per call:
//!
//! ```ignore
//! match action {
//!     Action::Transfer { from, to, amount } => rt
//!         .call("transfer", || client.try_transfer(from, to, amount))
//!         .into_step(),
//!     Action::Balance { who } => rt
//!         .call("balance", || client.try_balance(who))
//!         .expect_ok(),
//! }
//! ```

use std::cell::RefCell;
use std::fmt;
use std::fmt::Debug;
use std::rc::Rc;

use soroban_sdk::testutils::{Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, Env, IntoVal, InvokeError, Val};

use crate::budget::{InvocationResourceLimits, ResourceUsage};
use crate::config::{FuzzConfig, ResourcePolicy};
use crate::report::{CallRecord, Journal};
use crate::storage::StorageSnapshot;

/// Seconds of ledger time added per ledger when advancing the ledger.
pub const SECONDS_PER_LEDGER: u64 = 5;

/// Renders an address for a finding, using the same form the storage keys do.
fn display_address(address: &Address) -> String {
    soroban_sdk::xdr::ScAddress::from(address).to_string()
}

/// What an action did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// The action completed as intended.
    Ok,
    /// The contract rejected the action, and the rejection is expected: for
    /// example a withdrawal from an account with insufficient balance.
    Rejected(String),
    /// A contract violation: an unexpected error, a resource-limit breach, or a
    /// failed expectation. The harness fails and shrinks the case.
    Violation(String),
}

impl StepOutcome {
    /// The action completed as intended.
    pub fn ok() -> Self {
        StepOutcome::Ok
    }

    /// The contract rejected the action, as expected.
    pub fn rejected(reason: impl Into<String>) -> Self {
        StepOutcome::Rejected(reason.into())
    }

    /// The action revealed a violation.
    pub fn violation(reason: impl Into<String>) -> Self {
        StepOutcome::Violation(reason.into())
    }

    /// True for [`StepOutcome::Violation`].
    pub fn is_violation(&self) -> bool {
        matches!(self, StepOutcome::Violation(_))
    }

    /// Renders the outcome for the journal.
    pub fn describe(&self) -> String {
        match self {
            StepOutcome::Ok => "ok".to_owned(),
            StepOutcome::Rejected(reason) => format!("rejected: {reason}"),
            StepOutcome::Violation(reason) => format!("violation: {reason}"),
        }
    }
}

/// The result of a contract invocation, classified for fuzzing.
///
/// A generated client's `try_*` method returns
/// `Result<Result<V, ConversionError>, Result<E, InvokeError>>`. [`Runtime::call`]
/// flattens that into this type, so `Ok` genuinely holds the call's return value.
///
/// The four variants reflect what the Soroban test environment can actually tell
/// us, which is less than it might appear:
///
/// * a successful call returns `Ok(Ok(value))`;
/// * a contract that fails with its declared error type returns `Err(Ok(error))`;
/// * a host-level trap — a Rust `panic!`, an arithmetic overflow, a failed
///   `require_auth`, an out-of-budget trap — returns `Err(Err(InvokeError))` when
///   the entrypoint declares a typed error, and is otherwise **indistinguishable**
///   from a declared error, arriving as `Err(Ok(Error(..)))`.
///
/// Because of that last point, [`CallResult::expect_rejected`] accepts both
/// [`CallResult::Rejected`] and [`CallResult::Failed`]: "the call did not go
/// through" is the property that can be relied on, not the error's shape.
///
/// Which conversion an action should use:
///
/// | Conversion | Use for |
/// | --- | --- |
/// | [`CallResult::into_step`] | Calls whose failure is routine ("withdraw more than the balance") |
/// | [`CallResult::expect_ok`] | Calls that must succeed for the input to be meaningful |
/// | [`CallResult::expect_rejected`] | Negative tests: a call that must not go through |
/// | [`CallResult::expect_contract_error`] | Asserting a specific business error, not a trap |
///
/// `expect_rejected` is the *lenient* negative test, and it is worth knowing exactly
/// how lenient. A failed authorization and a contract that merely traps are not
/// distinguishable through this type at all — the Soroban test environment flattens
/// both onto the same host status (see `tests/classification.rs`, which pins the
/// shape). So `expect_rejected` cannot tell "refused because the caller was not
/// authorized" from "panicked before it ever checked authorization".
///
/// [`Runtime::call_requiring_auth`] is the strict form: it asserts positively that
/// the entrypoint *did* demand the authorization, which is what makes it specific
/// rather than merely negative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallResult<T> {
    /// The call returned a value.
    Ok(T),
    /// The contract signalled a failure through its declared error type, or a
    /// failure that the SDK mapped onto that type.
    Rejected(String),
    /// The call trapped: a panic, an overflow, a failed authorization, or another
    /// host-level failure.
    Failed(String),
    /// The invocation exceeded a configured network resource limit.
    LimitExceeded(String),
}

impl<T> CallResult<T> {
    /// Converts into a [`StepOutcome`], accepting any failure as a rejection.
    ///
    /// This is the lenient conversion, for calls whose failure is an expected part
    /// of the contract's behaviour. It does **not** assert anything beyond "the
    /// call did not panic the test".
    pub fn into_step(self) -> StepOutcome {
        match self {
            CallResult::Ok(_) => StepOutcome::Ok,
            CallResult::Rejected(reason) => StepOutcome::Rejected(reason),
            CallResult::Failed(reason) => StepOutcome::Rejected(format!("trapped: {reason}")),
            CallResult::LimitExceeded(reason) => StepOutcome::Violation(reason),
        }
    }

    /// Converts into a [`StepOutcome`], requiring the call to succeed.
    ///
    /// Use this when the generated input is valid by construction, so a failure
    /// means the contract is wrong rather than that the input was uninteresting.
    pub fn expect_ok(self) -> StepOutcome {
        match self {
            CallResult::Ok(_) => StepOutcome::Ok,
            CallResult::Rejected(reason) => {
                StepOutcome::Violation(format!("call was rejected but must succeed: {reason}"))
            }
            CallResult::Failed(reason) => {
                StepOutcome::Violation(format!("call trapped but must succeed: {reason}"))
            }
            CallResult::LimitExceeded(reason) => StepOutcome::Violation(reason),
        }
    }

    /// Converts into a [`StepOutcome`], requiring the call to be refused.
    ///
    /// This is the negative-test conversion, and it is how the fuzzer detects a
    /// missing `require_auth`: call a privileged entrypoint with
    /// [`Runtime::call_without_auth`] and require that it was refused. A call that
    /// succeeds under this conversion is a finding.
    ///
    /// Both [`CallResult::Rejected`] and [`CallResult::Failed`] count as refused,
    /// because an authorization failure surfaces as either depending on whether the
    /// entrypoint declares a typed error.
    pub fn expect_rejected(self) -> StepOutcome {
        match self {
            CallResult::Ok(_) => StepOutcome::Violation(
                "call succeeded but must have been refused: a privileged entrypoint may be \
                 missing require_auth, or an input check may be missing"
                    .to_owned(),
            ),
            CallResult::Rejected(reason) => StepOutcome::Rejected(reason),
            CallResult::Failed(reason) => StepOutcome::Rejected(format!("trapped: {reason}")),
            CallResult::LimitExceeded(reason) => StepOutcome::Violation(reason),
        }
    }

    /// Converts into a [`StepOutcome`], requiring a declared contract error.
    ///
    /// Unlike [`CallResult::expect_rejected`], a trap is *not* accepted: this
    /// asserts that the contract refused the input deliberately, rather than
    /// crashing on it.
    pub fn expect_contract_error(self) -> StepOutcome {
        match self {
            CallResult::Ok(_) => StepOutcome::Violation(
                "call succeeded but was expected to return a contract error".to_owned(),
            ),
            CallResult::Rejected(reason) => StepOutcome::Rejected(reason),
            CallResult::Failed(reason) => StepOutcome::Violation(format!(
                "expected a contract error but the call trapped: {reason}"
            )),
            CallResult::LimitExceeded(reason) => StepOutcome::Violation(reason),
        }
    }

    /// True when the call returned a value.
    pub fn is_ok(&self) -> bool {
        matches!(self, CallResult::Ok(_))
    }

    /// True when the call trapped or exceeded a limit.
    pub fn is_failure(&self) -> bool {
        matches!(self, CallResult::Failed(_) | CallResult::LimitExceeded(_))
    }

    /// The returned value, if the call succeeded.
    pub fn ok(self) -> Option<T> {
        match self {
            CallResult::Ok(value) => Some(value),
            _ => None,
        }
    }

    /// The reason the call did not return a value.
    pub fn reason(&self) -> Option<&str> {
        match self {
            CallResult::Ok(_) => None,
            CallResult::Rejected(reason)
            | CallResult::Failed(reason)
            | CallResult::LimitExceeded(reason) => Some(reason),
        }
    }

    /// Requires the call to have succeeded, returning the value.
    ///
    /// Fails the case like [`CallResult::expect_ok`] when it did not.
    pub fn unwrap_ok(self) -> T {
        match self {
            CallResult::Ok(value) => value,
            other => panic!(
                "call had to succeed: {}",
                other.reason().unwrap_or("unknown failure")
            ),
        }
    }
}

/// Everything an action needs in order to drive the contract under test.
///
/// The type parameter is the target's [`World`](crate::Target::World), so actions
/// reach their contract clients through [`Runtime::world`].
pub struct Runtime<'a, W> {
    env: &'a Env,
    world: &'a W,
    journal: Rc<RefCell<Journal>>,
    limits: InvocationResourceLimits,
    policy: ResourcePolicy,
    step: usize,
    scoped: &'a [Address],
}

impl<'a, W> Runtime<'a, W> {
    pub(crate) fn new(
        env: &'a Env,
        world: &'a W,
        journal: Rc<RefCell<Journal>>,
        step: usize,
        config: &FuzzConfig,
        scoped: &'a [Address],
    ) -> Self {
        Self {
            env,
            world,
            journal,
            limits: config.limits.clone(),
            policy: config.resources,
            step,
            scoped,
        }
    }

    /// The Soroban test environment.
    ///
    /// Reach for this to install a specific authorization before a call, to set up
    /// ledger state, or to read events. Calls made directly through a client rather
    /// than through [`Runtime::call`] are not instrumented.
    pub fn env(&self) -> &Env {
        self.env
    }

    /// The deployed world produced by [`Target::setup`](crate::Target::setup).
    pub fn world(&self) -> &W {
        self.world
    }

    /// Zero-based index of the action being executed.
    pub fn step(&self) -> usize {
        self.step
    }

    /// Ledger control for actions that need to move time forward.
    pub fn ledger(&self) -> LedgerCtl<'a> {
        LedgerCtl {
            env: self.env,
            journal: Rc::clone(&self.journal),
        }
    }

    /// The current storage contents, scoped to the target's
    /// [`tracked_contracts`](crate::Target::tracked_contracts).
    pub fn storage(&self) -> StorageSnapshot {
        StorageSnapshot::capture_scoped(self.env, self.scoped)
    }

    /// Resource usage of the most recent contract invocation, if any has run.
    pub fn usage(&self) -> Option<ResourceUsage> {
        ResourceUsage::capture(self.env)
    }

    /// Invokes the contract, recording and classifying the result.
    ///
    /// The closure is a `try_*` client call, whose return type this accepts
    /// directly: a successful call yields [`CallResult::Ok`] holding the value, a
    /// contract error yields [`CallResult::Rejected`], and a trap or an invocation
    /// error yields [`CallResult::Failed`].
    ///
    /// ```ignore
    /// let client = MyContractClient::new(rt.env(), &rt.world().contract);
    /// match rt.call("transfer", || client.try_transfer(&from, &to, &amount)) {
    ///     CallResult::Ok(()) => StepOutcome::ok(),
    ///     other => other.into_step(),
    /// }
    /// ```
    pub fn call<V, C, E>(
        &self,
        label: impl Into<String>,
        f: impl FnOnce() -> Result<Result<V, C>, Result<E, InvokeError>>,
    ) -> CallResult<V>
    where
        C: Debug,
        E: Debug,
    {
        self.measure(label.into(), true, f)
    }

    /// Invokes the contract with no credentials installed, whatever the run's
    /// authorization policy is.
    //
    /// Pair this with [`CallResult::expect_rejected`] to assert that a privileged
    /// entrypoint is protected:
    ///
    /// ```ignore
    /// rt.call_without_auth("mint", || client.try_mint(&admin, &to, &amount))
    ///     .expect_rejected()
    /// ```
    ///
    /// A call made this way that *succeeds* is reported as a violation, which is how
    /// a missing `require_auth` is found. This is worth asserting even under
    /// [`AuthPolicy::MockAll`](crate::AuthPolicy::MockAll): clearing the credentials
    /// for one call tests the negative path that mocking normally hides.
    pub fn call_without_auth<V, C, E>(
        &self,
        label: impl Into<String>,
        f: impl FnOnce() -> Result<Result<V, C>, Result<E, InvokeError>>,
    ) -> CallResult<V>
    where
        C: Debug,
        E: Debug,
    {
        // `set_auths` also disables any mocking, so this is a true negative test.
        self.env.set_auths(&[]);
        self.measure(label.into(), true, f)
    }

    /// Invokes the contract with authorization **recorded instead of enforced**, and
    /// asserts that `address` was required to authorize the call.
    ///
    /// This is the strict form of a negative authorization test. The lenient form —
    /// [`Runtime::call_without_auth`] followed by
    /// [`CallResult::expect_rejected`] — only establishes that the call did not go
    /// through, which is satisfied just as well by a contract that panicked on its
    /// input before it ever looked at authorization. The two are *not*
    /// distinguishable from the error: measured against `soroban-sdk` 27, a failed
    /// `require_auth` and an ordinary Rust `panic!` both surface as
    /// `Err(Ok(Error(Context, InvalidAction)))` from an untyped entrypoint, and as
    /// `Err(Err(InvokeError::Abort))` from a typed one (pinned in
    /// `tests/classification.rs`).
    ///
    /// So this asserts the property positively instead. It switches the host to
    /// recording authorization, runs the call, and then reads the authorization tree
    /// the contract actually demanded: the entrypoint must have succeeded *and* the
    /// tree must name `address`. That is the mechanism the SDK's own documentation
    /// recommends for exactly this question — "a test that uses `mock_all_auths`
    /// without verifying the resulting authorization tree can pass even when a
    /// contract is missing a `require_auth` check".
    ///
    /// # Two things this changes about the run
    ///
    /// * **The call succeeds and its state changes are real.** Recording
    ///   authorization means the credential is never refused, so a correctly
    ///   protected entrypoint runs to completion. The action's model must account for
    ///   that, exactly as it would for any positive call, and an entrypoint that
    ///   panics on its input is reported as a violation rather than as a pass.
    /// * **Authorization stays recorded for the rest of the action**, so a second
    ///   contract call in the same action is also unmocked. The runner restores the
    ///   run's [`AuthPolicy`](crate::AuthPolicy) before the next action.
    ///
    /// ```ignore
    /// // Either of these proves `transfer` is gated on `from`'s authorization; the
    /// // first also proves the balance check did not get in the way.
    /// rt.call_requiring_auth("transfer", &from, || client.try_transfer(&from, &to, &amount))
    /// ```
    pub fn call_requiring_auth<V, C, E>(
        &self,
        label: impl Into<String>,
        address: &Address,
        f: impl FnOnce() -> Result<Result<V, C>, Result<E, InvokeError>>,
    ) -> StepOutcome
    where
        C: Debug,
        E: Debug,
    {
        let label = label.into();
        // Recording mode: every `require_auth` succeeds and is recorded, so the
        // demanded tree is observable. This is what `Env::mock_all_auths` is.
        self.env.mock_all_auths();

        let result = self.measure(label.clone(), true, f);
        match &result {
            CallResult::Ok(_) => {}
            CallResult::LimitExceeded(reason) => return StepOutcome::Violation(reason.clone()),
            other => {
                return StepOutcome::Violation(format!(
                    "call `{label}` had to succeed under recorded authorization, to show that \
                     {who} gates it, but it did not: {} — it is likely failing on its \
                     input or on an earlier check rather than on authorization",
                    other.reason().unwrap_or("unknown failure"),
                    who = display_address(address),
                ));
            }
        }

        // `auths()` reports the tree of the last invocation, which is the call just
        // made: nothing between here and `measure` starts a contract invocation.
        let demanded = self.env.auths();
        if demanded.iter().any(|(who, _)| who == address) {
            return StepOutcome::Ok;
        }

        let names = if demanded.is_empty() {
            "nothing".to_owned()
        } else {
            demanded
                .iter()
                .map(|(who, _)| display_address(who))
                .collect::<Vec<_>>()
                .join(", ")
        };
        StepOutcome::Violation(format!(
            "call `{label}` succeeded under recorded authorization but never demanded \
             authorization from {who}; it demanded {names}. A privileged entrypoint that \
             does not require authorization can be called by anyone.",
            who = display_address(address),
        ))
    }

    /// Like [`Runtime::call`], but never fails the case on a resource-limit breach.
    ///
    /// Use for setup or cleanup calls whose resource cost is not what you are
    /// fuzzing, so a breach in unrelated code does not mask the finding you want.
    pub fn call_unchecked<V, C, E>(
        &self,
        label: impl Into<String>,
        f: impl FnOnce() -> Result<Result<V, C>, Result<E, InvokeError>>,
    ) -> CallResult<V>
    where
        C: Debug,
        E: Debug,
    {
        self.measure(label.into(), false, f)
    }

    /// Installs a credential for exactly one upcoming invocation.
    ///
    /// `Address::require_auth()` authorizes the **whole invocation**, so `fn_name`
    /// and `args` must match what the contract will see, in order. A credential that
    /// authorizes different arguments is refused, which is what makes this stricter
    /// (and more useful) than mocking every authorization:
    ///
    /// ```ignore
    /// rt.authorize(&from, &contract, "transfer", (from.clone(), to.clone(), amount));
    /// rt.call("transfer", || client.try_transfer(&from, &to, &amount)).expect_ok()
    /// ```
    ///
    /// The credential is consumed by that one invocation. The harness clears pending
    /// credentials before every action, so nothing leaks into the next one.
    ///
    /// For a call that authorizes sub-invocations — a contract calling out to another
    /// contract — use [`Runtime::install_auths`] instead, which can express arbitrary
    /// trees.
    pub fn authorize<A>(&self, address: &Address, contract: &Address, fn_name: &str, args: A)
    where
        A: IntoVal<Env, soroban_sdk::Vec<Val>>,
    {
        let args = args.into_val(self.env);
        self.env.mock_auths(&[MockAuth {
            address,
            invoke: &MockAuthInvoke {
                contract,
                fn_name,
                args,
                sub_invokes: &[],
            },
        }]);
    }

    /// Installs raw mock authorizations, for credential trees with sub-invocations.
    ///
    /// [`Runtime::authorize`] covers the common single-invocation case; reach for this
    /// when a contract needs to be authorized for the calls it will make onward.
    pub fn install_auths(&self, auths: &[MockAuth<'_>]) {
        self.env.mock_auths(auths);
    }

    /// Attaches a free-form note to the current step, for debugging reports.
    pub fn note(&self, message: impl Into<String>) {
        let message = message.into();
        self.journal.borrow_mut().push_call(CallRecord {
            label: "<note>".to_owned(),
            outcome: message,
            ..CallRecord::default()
        });
    }

    fn measure<V, C, E>(
        &self,
        label: String,
        enforce: bool,
        f: impl FnOnce() -> Result<Result<V, C>, Result<E, InvokeError>>,
    ) -> CallResult<V>
    where
        C: Debug,
        E: Debug,
    {
        let before = StorageSnapshot::capture_scoped(self.env, self.scoped);
        let result = f();
        let after = StorageSnapshot::capture_scoped(self.env, self.scoped);

        let usage = ResourceUsage::capture(self.env).unwrap_or_default();
        let delta = before.diff(&after);

        let breach = if enforce && matches!(self.policy, ResourcePolicy::Enforce) {
            usage.first_breach(&self.limits)
        } else {
            None
        };

        let outcome = match &result {
            Ok(Ok(_)) => "ok".to_owned(),
            Ok(Err(error)) => format!("unreadable result: {error:?}"),
            Err(Ok(error)) => format!("rejected: {error:?}"),
            Err(Err(error)) => format!("error: {error:?}"),
        };

        self.journal.borrow_mut().push_call(CallRecord {
            label: label.clone(),
            outcome,
            usage,
            delta,
            entries_after: after.total_entries(),
            breach: breach.clone(),
        });

        if let Some(breach) = breach {
            return CallResult::LimitExceeded(format!(
                "call `{label}` exceeded a network limit: {breach}"
            ));
        }

        match result {
            Ok(Ok(value)) => CallResult::Ok(value),
            // The call went through but its return value could not be converted into
            // the Rust type the caller asked for: a bug in the caller, not in the
            // contract, but it must not be mistaken for success.
            Ok(Err(error)) => {
                CallResult::Failed(format!("return value could not be converted: {error:?}"))
            }
            Err(Ok(error)) => CallResult::Rejected(format!("{error:?}")),
            Err(Err(error)) => CallResult::Failed(format!("{error:?}")),
        }
    }
}

/// Ledger state control, for actions that need to move the chain forward.
///
/// TTL behaviour, rent, and time-based logic only show up once the ledger moves, so
/// a fuzz run that never advances the ledger will never find bugs in them.
///
/// Two operations, and the difference between them is the difference between a
/// clock moving and a block closing:
///
/// * [`LedgerCtl::advance`] moves the ledger *within* the current transaction. Use it
///   when an entrypoint's behaviour depends on the current time (an allowance's
///   deadline, a rate that decays).
/// * [`LedgerCtl::close_ledger`] ends the transaction and starts a new ledger. Use it
///   for anything the network applies at a ledger boundary: temporary-entry
///   reclamation, TTL expiry, and time the contract itself only observes across two
///   separate invocations.
///
/// What becomes reachable that was not before is worth stating plainly, because it is
/// exactly the class of bug a single-ledger run cannot find: an allowance whose
/// deadline is in the past reads as zero because the host has reclaimed the expired
/// entry, a temporary entry that has passed its TTL is gone rather than merely stale,
/// and a contract that caches a ledger number on first use keeps serving it until
/// something forces it to re-read.
#[derive(Clone)]
pub struct LedgerCtl<'a> {
    env: &'a Env,
    journal: Rc<RefCell<Journal>>,
}

impl fmt::Debug for LedgerCtl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerCtl")
            .field("sequence", &self.sequence())
            .field("timestamp", &self.timestamp())
            .finish()
    }
}

impl LedgerCtl<'_> {
    /// The current ledger sequence number.
    pub fn sequence(&self) -> u32 {
        self.env.ledger().sequence()
    }

    /// The current ledger timestamp, in seconds since the epoch.
    pub fn timestamp(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// Advances the ledger by `ledgers`, moving the timestamp forward by
    /// [`SECONDS_PER_LEDGER`] per ledger.
    ///
    /// Soroban rejects a transaction whose timestamp does not increase, so the two
    /// are always moved together.
    ///
    /// This moves the clock *within* the current transaction. For a ledger boundary —
    /// where the network applies TTL expiry and temporary-entry reclamation — use
    /// [`LedgerCtl::close_ledger`].
    pub fn advance(&self, ledgers: u32) {
        self.set_sequence_number(self.sequence().saturating_add(ledgers));
        self.set_timestamp(
            self.timestamp()
                .saturating_add(u64::from(ledgers) * SECONDS_PER_LEDGER),
        );
    }

    /// Ends the current transaction and starts the next ledger, `ledgers` later.
    ///
    /// What happens at a ledger boundary is what makes it different from
    /// [`LedgerCtl::advance`]: this is where the network closes the ledger and applies
    /// rent, TTL expiry, and reclamation of expired temporary entries. The contract
    /// sees the same state, but the entries it depends on may have changed underneath
    /// it, and anything it cached about the ledger is now stale.
    ///
    /// The boundary is recorded in the run's journal, so a report shows where time
    /// moved rather than leaving a two-action reproducer looking like a single instant.
    ///
    /// One honest note about fidelity: the test host applies expiry *lazily*, when an
    /// entry is next read, rather than sweeping at close. The consequence is that the
    /// observable difference from [`LedgerCtl::advance`] in this environment is that
    /// the boundary is explicit and journalled, not that state is swept here — an
    /// expired temporary entry disappears on the read that follows, and
    /// `tests/third_party.rs` pins that behaviour against a real contract.
    pub fn close_ledger(&self, ledgers: u32) {
        let from_sequence = self.sequence();
        let to_sequence = from_sequence.saturating_add(ledgers);
        let timestamp = self
            .timestamp()
            .saturating_add(u64::from(ledgers) * SECONDS_PER_LEDGER);

        self.set_sequence_number(to_sequence);
        self.set_timestamp(timestamp);

        self.journal.borrow_mut().push_call(CallRecord {
            label: "<ledger>".to_owned(),
            outcome: format!(
                "ledger closed: sequence {from_sequence} -> {to_sequence}, timestamp {timestamp}"
            ),
            ..CallRecord::default()
        });
    }

    /// Sets the ledger sequence number.
    pub fn set_sequence_number(&self, sequence: u32) {
        self.env.ledger().set_sequence_number(sequence);
    }

    /// Sets the ledger timestamp.
    pub fn set_timestamp(&self, timestamp: u64) {
        self.env.ledger().set_timestamp(timestamp);
    }
}
