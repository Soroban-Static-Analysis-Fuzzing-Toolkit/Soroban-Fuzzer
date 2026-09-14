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

use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Env, InvokeError};

use crate::budget::{InvocationResourceLimits, ResourceUsage};
use crate::config::{FuzzConfig, ResourcePolicy};
use crate::report::{CallRecord, Journal};
use crate::storage::StorageSnapshot;

/// Seconds of ledger time added per ledger when advancing the ledger.
pub const SECONDS_PER_LEDGER: u64 = 5;

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
/// | [`CallResult::expect_rejected`] | Negative tests: authorization that must not be granted |
/// | [`CallResult::expect_contract_error`] | Asserting a specific business error, not a trap |
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
}

impl<'a, W> Runtime<'a, W> {
    pub(crate) fn new(
        env: &'a Env,
        world: &'a W,
        journal: Rc<RefCell<Journal>>,
        step: usize,
        config: &FuzzConfig,
    ) -> Self {
        Self {
            env,
            world,
            journal,
            limits: config.limits.clone(),
            policy: config.resources,
            step,
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
    pub fn ledger(&self) -> LedgerCtl<'_> {
        LedgerCtl { env: self.env }
    }

    /// The current storage contents.
    pub fn storage(&self) -> StorageSnapshot {
        StorageSnapshot::capture(self.env)
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
        let before = StorageSnapshot::capture(self.env);
        let result = f();
        let after = StorageSnapshot::capture(self.env);

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
            writes: delta.writes(),
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
#[derive(Clone, Copy)]
pub struct LedgerCtl<'a> {
    env: &'a Env,
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
    pub fn advance(&self, ledgers: u32) {
        self.set_sequence_number(self.sequence().saturating_add(ledgers));
        self.set_timestamp(
            self.timestamp()
                .saturating_add(u64::from(ledgers) * SECONDS_PER_LEDGER),
        );
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
