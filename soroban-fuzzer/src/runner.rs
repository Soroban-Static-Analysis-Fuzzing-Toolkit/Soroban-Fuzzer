//! The fuzz runner: generation, shrinking, and per-case execution.
//!
//! [`run`] generates action sequences with `proptest` and executes each one against
//! a fresh Soroban test environment. When a case fails, proptest shrinks the
//! sequence to a minimal reproducer and the harness turns it into a
//! [`FailureReport`].
//!
//! Two decisions are worth knowing about:
//!
//! * **Enumeration happens against the model, not the contract.** Action sequences
//!   are generated and shrunk purely from the model's state machine, then replayed
//!   against the contract. This keeps shrinking fast and deterministic: a shrunken
//!   sequence is still valid even though the contract state it produces is unknown
//!   ahead of time.
//!
//! * **Every case gets a fresh environment.** Isolation between cases is what makes
//!   a counterexample meaningful, and it is also why snapshot capture at `Env` drop
//!   is disabled: a run of 128 cases should not litter `test_snapshots/`.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use proptest::test_runner::{Config as ProptestConfig, RngSeed, TestError, TestRunner};
use proptest_state_machine::Sequential;
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::Env;

use crate::config::{AuthPolicy, FuzzConfig, ResourcePolicy};
use crate::invariant::{CheckCtx, Invariant};
use crate::report::{FailureReport, FuzzOutcome, Journal};
use crate::runtime::{Runtime, StepOutcome};
use crate::storage::{StorageSnapshot, StoreKind};
use crate::target::Target;

/// Fuzzes `target` and returns what happened.
///
/// If the configuration does not pin a seed, a fresh one is chosen and reported in
/// the outcome, so every failing case is reproducible.
///
/// ```no_run
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
/// let outcome = run(MyTarget, FuzzConfig::default().cases(64));
/// if let Some(report) = outcome.report() {
///     println!("{report}");
/// }
/// ```
pub fn run<T>(target: T, mut config: FuzzConfig) -> FuzzOutcome
where
    T: Target + Send + Sync + 'static,
{
    if config.seed.is_none() {
        config.seed = Some(fresh_seed());
    }
    let seed = config.seed.unwrap_or_default();

    let target = Arc::new(target);
    let config = Arc::new(config);

    let sequential = {
        let for_init = Arc::clone(&target);
        let for_preconditions = Arc::clone(&target);
        let for_actions = Arc::clone(&target);
        let for_next = Arc::clone(&target);
        Sequential::new(
            (config.min_actions..=config.max_actions).into(),
            move || for_init.init_state(),
            move |state: &T::State, action: &T::Action| {
                for_preconditions.preconditions(state, action)
            },
            move |state: &T::State| for_actions.actions(state),
            move |state: T::State, action: &T::Action| for_next.next_state(state, action),
        )
    };

    let mut proptest_config = ProptestConfig {
        cases: config.cases,
        max_shrink_iters: config.max_shrink_iters,
        verbose: config.verbose,
        rng_seed: RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    };
    if !config.persist_failures {
        // The harness writes its own structured report; do not litter the source
        // tree with proptest's persistence files unless asked to.
        proptest_config.failure_persistence = None;
    }

    let mut runner = TestRunner::new(proptest_config);
    let journal = Rc::new(RefCell::new(Journal::default()));

    // Shrinking works by re-running the failing case, so a failing property panics
    // once per shrink step. Without this guard each of those panics would print a
    // message and a backtrace, burying the report that matters. The panic payload is
    // still captured by proptest and included in the report.
    let _silence = panic_output::Silence::on_current_thread();

    let case_target = Arc::clone(&target);
    let case_config = Arc::clone(&config);
    let case_journal = Rc::clone(&journal);

    let result = runner.run(&sequential, move |(initial, actions, seen)| {
        run_case(
            case_target.as_ref(),
            case_config.as_ref(),
            &case_journal,
            initial,
            actions,
            seen,
        );
        Ok(())
    });

    match result {
        Ok(()) => FuzzOutcome::Passed {
            cases: config.cases,
            seed,
        },
        Err(TestError::Abort(reason)) => FuzzOutcome::Aborted {
            reason: reason.message().to_owned(),
        },
        Err(TestError::Fail(reason, (_state, minimal, _seen))) => {
            let minimal_sequence = minimal
                .iter()
                .map(|action| target.describe(action))
                .collect::<Vec<_>>();
            let report = FailureReport::new(
                reason.message().to_owned(),
                minimal_sequence,
                &journal.borrow(),
                config.as_ref(),
            );
            if let Some(path) = &config.report_path {
                // Reporting must never turn a finding into a different failure.
                let _ = report.write_json(path);
            }
            FuzzOutcome::Failed(Box::new(report))
        }
    }
}

/// Fuzzes `target` and panics with the rendered report if a case fails.
///
/// Intended as the last line of a `#[test]`.
///
/// ```no_run
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
/// #[test]
/// fn contract_holds_its_invariants() {
///     check(MyTarget, FuzzConfig::from_env());
/// }
/// ```
pub fn check<T>(target: T, config: FuzzConfig)
where
    T: Target + Send + Sync + 'static,
{
    run(target, config).assert_ok()
}

/// Executes one generated sequence against a fresh environment.
///
/// `seen_counter` is the shared counter that `proptest-state-machine` uses to tell
/// which transitions were actually executed. It must be incremented before each
/// action; if it is not, the shrinker concludes that every transition went unseen
/// and deletes the whole sequence instead of minimizing it.
fn run_case<T>(
    target: &T,
    config: &FuzzConfig,
    journal: &Rc<RefCell<Journal>>,
    initial: T::State,
    actions: Vec<T::Action>,
    seen_counter: Option<Arc<AtomicUsize>>,
) where
    T: Target + Send + Sync + 'static,
{
    let env = new_env(config);
    let world = target.setup(&env, &initial);
    let invariants = target.invariants();
    journal.borrow_mut().reset();

    let mut model = initial;
    check_invariants(&invariants, &env, &world, &model, None, 0, journal);

    for (index, action) in actions.into_iter().enumerate() {
        if let Some(counter) = seen_counter.as_ref() {
            counter.fetch_add(1, Ordering::SeqCst);
        }

        // Re-apply the policy per action so one action's authorization never leaks
        // into the next.
        apply_auth_policy(&env, config.auth);

        model = target.next_state(model, &action);
        journal
            .borrow_mut()
            .begin_step(index, target.describe(&action));

        let outcome = {
            let mut runtime = Runtime::new(&env, &world, Rc::clone(journal), index, config);
            target.execute(&mut runtime, &action)
        };

        journal.borrow_mut().finish_step(outcome.describe());

        if let StepOutcome::Violation(detail) = &outcome {
            journal
                .borrow_mut()
                .fail("unexpected-error", detail.clone());
            fail_case(journal);
        }

        check_invariants(
            &invariants,
            &env,
            &world,
            &model,
            Some(&action),
            index,
            journal,
        );
    }
}

fn check_invariants<T>(
    invariants: &[Box<dyn Invariant<T>>],
    env: &Env,
    world: &T::World,
    model: &T::State,
    action: Option<&T::Action>,
    step: usize,
    journal: &Rc<RefCell<Journal>>,
) where
    T: Target,
{
    if invariants.is_empty() {
        return;
    }

    // An invariant that writes state would make the whole run meaningless: the
    // contract under test would be mutated by the checker, and a post-action
    // snapshot could never be trusted. Detect it rather than let it produce a
    // confusing, non-reproducible finding.
    let before = StorageSnapshot::capture(env);

    for invariant in invariants {
        if action.is_none() && !invariant.check_initial() {
            continue;
        }
        let ctx = CheckCtx {
            env,
            world,
            model,
            action,
            step,
        };
        if let Err(detail) = invariant.check(&ctx) {
            journal
                .borrow_mut()
                .fail("invariant", format!("{}: {detail}", invariant.name()));
            fail_case(journal);
        }
    }

    let after = StorageSnapshot::capture(env);
    let delta = before.diff(&after);

    // One change is not the checker's doing. The host reclaims an expired temporary
    // entry when it reads it, so an invariant that merely *reads* an allowance can
    // make the entry disappear across this comparison — `tests/third_party.rs` pins
    // exactly that behaviour against a real contract. A temporary disappearance is
    // therefore not evidence of a write. Everything else is: any change to instance
    // or persistent data, and any addition or value update in temporary storage,
    // means the invariant reached a setter, which would make the run's results depend
    // on the checker rather than on the contract.
    let host_reclaimed = delta.instance.is_empty()
        && delta.persistent.is_empty()
        && delta.temporary.added == 0
        && delta.temporary.updated == 0;

    if !delta.is_empty() && !host_reclaimed {
        // Report what changed, per durability, rather than only how many entries did.
        // A bare count is unactionable when the offending invariant is one of several,
        // and it hides the difference between "reached a setter" (values updated) and
        // "reached a lifecycle operation" (entries added or removed).
        let mut changes = Vec::new();
        for kind in StoreKind::ALL {
            let set = delta.of(kind);
            if set.is_empty() {
                continue;
            }
            changes.push(format!(
                "{kind}: {} added, {} removed, {} updated{}",
                set.added,
                set.removed,
                set.updated,
                if set.changed_keys.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", set.changed_keys.join(", "))
                }
            ));
        }
        journal.borrow_mut().fail(
            "invariant",
            format!(
                "checking invariants modified contract state ({}); invariants must be \
                 read-only, so this makes results non-reproducible",
                changes.join("; ")
            ),
        );
        fail_case(journal);
    }
}

/// Fails the case with a message that survives proptest's panic capture.
fn fail_case(journal: &Rc<RefCell<Journal>>) -> ! {
    let message = {
        let journal = journal.borrow();
        match &journal.failure {
            Some(note) => format!("soroban-fuzzer/violation[{}]: {}", note.kind, note.detail),
            None => "soroban-fuzzer/violation: case failed".to_owned(),
        }
    };
    panic!("{message}");
}

/// Creates the environment for one case.
fn new_env(config: &FuzzConfig) -> Env {
    // Snapshot capture at drop writes `test_snapshots/*.json`; a fuzz run creates
    // hundreds of environments, and none of those files would be useful.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });

    if matches!(
        config.resources,
        ResourcePolicy::Enforce | ResourcePolicy::Record
    ) {
        // Take over limit handling so a breach is reported with the measured
        // numbers and the offending action, instead of an opaque host panic.
        env.cost_estimate().disable_resource_limits();
    }

    env
}

fn apply_auth_policy(env: &Env, policy: AuthPolicy) {
    match policy {
        // Clearing the pending entries also disables any mocking a previous action
        // installed, which is what makes `Strict` meaningful.
        AuthPolicy::Strict => env.set_auths(&[]),
        AuthPolicy::MockAll => env.mock_all_auths(),
    }
}

/// Keeps a failing fuzz run from burying its own report under intermediate panics.
///
/// Filtering is scoped to the current thread: the wrapped hook only suppresses output
/// when the running thread has asked for it, so panics on other threads — including
/// other tests running in parallel — are reported normally.
mod panic_output {
    use std::cell::Cell;
    use std::panic::{set_hook, take_hook};
    use std::sync::Once;

    thread_local! {
        static SUPPRESSED: Cell<u32> = const { Cell::new(0) };
    }

    static INSTALL_HOOK: Once = Once::new();

    /// Suppresses default panic output on the current thread for its lifetime.
    pub struct Silence;

    impl Silence {
        pub fn on_current_thread() -> Self {
            INSTALL_HOOK.call_once(|| {
                let previous = take_hook();
                set_hook(Box::new(move |info| {
                    if SUPPRESSED.with(|depth| depth.get()) == 0 {
                        previous(info);
                    }
                }));
            });
            SUPPRESSED.with(|depth| depth.set(depth.get().saturating_add(1)));
            Self
        }
    }

    impl Drop for Silence {
        fn drop(&mut self) {
            SUPPRESSED.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
}

/// A seed for an unpinned run.
///
/// Mixes the clock with a process-local counter so that parallel test threads do not
/// collide, and so a run remains reproducible when the seed is reported.
fn fresh_seed() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos ^ counter.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}
