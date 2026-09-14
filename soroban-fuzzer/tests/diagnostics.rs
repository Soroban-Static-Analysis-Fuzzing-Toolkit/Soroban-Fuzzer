//! Diagnostics about the *run*, as opposed to findings about the contract.
//!
//! "No findings in 200 cases" is only evidence if the generated actions actually
//! reached the contract. If the generator keeps producing calls the contract refuses,
//! the run looks identical to a healthy one while proving very little. These tests pin
//! down the signal that tells the two apart, and the escape hatch that keeps it from
//! crying wolf on targets with deliberate negative tests.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use common::{Vault, VaultClient};
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;

/// A balance large enough that the affordable mode never runs dry.
const FUNDED: i128 = 10_000_000;

struct World {
    contract: Address,
    actors: [Address; 2],
}

/// What the generated transfers are allowed to cost.
#[derive(Clone, Copy, Debug)]
enum Mode {
    /// Amounts the actor can afford, asserted to succeed.
    Affordable,
    /// Amounts far beyond the actor's balance, tolerated as rejections.
    Unaffordable,
}

struct TransferTarget {
    mode: Mode,
    /// Whether the target declares its refusals intentional.
    declared_expected: bool,
}

impl Target for TransferTarget {
    type State = ();
    type Action = i128;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, env: &Env, _initial: &()) -> World {
        let actors = [Address::generate(env), Address::generate(env)];
        let contract = env.register(Vault, (actors[0].clone(), FUNDED));
        World { contract, actors }
    }

    fn actions(&self, _state: &()) -> BoxedStrategy<i128> {
        match self.mode {
            Mode::Affordable => (1i128..=100).boxed(),
            // Strictly more than the starting balance, so every one of these is refused.
            Mode::Unaffordable => (FUNDED + 1..=FUNDED * 2).boxed(),
        }
    }

    fn next_state(&self, _state: (), _action: &i128) {}

    fn execute(&self, rt: &mut Runtime<'_, World>, amount: &i128) -> StepOutcome {
        let contract = rt.world().contract.clone();
        let from = rt.world().actors[0].clone();
        let to = rt.world().actors[1].clone();
        let client = VaultClient::new(rt.env(), &contract);
        rt.authorize(
            &from,
            &contract,
            "transfer",
            (from.clone(), to.clone(), *amount),
        );
        let call = rt.call("transfer", || client.try_transfer(&from, &to, amount));
        match self.mode {
            // The input is valid by construction, so a refusal is a contract bug.
            Mode::Affordable => call.expect_ok(),
            // The refusal is the expected outcome; `into_step` tolerates it.
            Mode::Unaffordable => call.into_step(),
        }
    }

    fn describe(&self, amount: &i128) -> String {
        format!("transfer({amount})")
    }

    fn expects_rejection(&self, _action: &i128) -> bool {
        // Only meaningful in `Unaffordable` mode, where every action is refused.
        self.declared_expected
    }
}

/// A run whose actions are mostly refused without the target saying so warns.
#[test]
fn a_run_that_mostly_generates_unaffordable_actions_warns() {
    let outcome = run(
        TransferTarget {
            mode: Mode::Unaffordable,
            declared_expected: false,
        },
        FuzzConfig::default().cases(16).actions(1, 3).seed(0x0D1A),
    );

    let stats = outcome.stats().expect("the run should have completed");
    assert!(
        stats.unexpected_rejections > 0,
        "the mode under test should produce refusals, got {stats}"
    );
    assert_eq!(
        stats.rejection_ratio(),
        1.0,
        "every action is unaffordable, so every action should be an unexpected rejection: {stats}"
    );

    let warning = outcome
        .warning()
        .expect("a run with 100% unexpected rejections must warn");
    assert!(
        warning.contains("transfer"),
        "the warning should name the action kind the contract kept refusing: {warning}"
    );
    assert!(
        warning.contains("100%"),
        "the warning should state the ratio: {warning}"
    );
}

/// Declaring the refusals intentional silences the warning, and still counts them.
#[test]
fn declaring_a_refusal_expected_silences_the_warning() {
    let outcome = run(
        TransferTarget {
            mode: Mode::Unaffordable,
            declared_expected: true,
        },
        FuzzConfig::default().cases(16).actions(1, 3).seed(0x0D1A),
    );

    assert_eq!(
        outcome.warning(),
        None,
        "a target that declares its refusals must not be warned about them"
    );

    let stats = outcome.stats().expect("the run should have completed");
    assert_eq!(stats.accepted, 0);
    assert_eq!(stats.unexpected_rejections, 0);
    assert!(
        stats.expected_rejections > 0,
        "the refusals should still be counted, just not as unexpected: {stats}"
    );
}

/// A healthy run says nothing.
#[test]
fn a_healthy_run_does_not_warn() {
    // The same reason the warning matters: the same shape of target, with actions that
    // the contract accepts, must be silent — otherwise the warning is noise.
    let outcome = run(
        TransferTarget {
            mode: Mode::Affordable,
            declared_expected: false,
        },
        FuzzConfig::default().cases(16).actions(1, 3).seed(0x0D1A),
    );

    assert_eq!(outcome.warning(), None, "a clean run must not warn");
    let stats = outcome.stats().expect("the run should have completed");
    assert_eq!(stats.unexpected_rejections, 0, "{stats}");
    assert_eq!(
        stats.accepted,
        stats.total(),
        "every action should have been accepted: {stats}"
    );
}

/// Raising the threshold to `None` disables the warning entirely.
#[test]
fn the_warning_can_be_disabled() {
    let outcome = run(
        TransferTarget {
            mode: Mode::Unaffordable,
            declared_expected: false,
        },
        FuzzConfig::default()
            .cases(16)
            .actions(1, 3)
            .rejection_warning_ratio(None)
            .seed(0x0D1A),
    );

    assert_eq!(outcome.warning(), None);
    // The statistics are still reported: disabling the warning must not hide the data.
    let stats = outcome.stats().expect("the run should have completed");
    assert!(stats.unexpected_rejections > 0, "{stats}");
}

// ---------------------------------------------------------------------------
// Generating actions from `arbitrary::Arbitrary`
// ---------------------------------------------------------------------------

/// An action type that already implements `Arbitrary`, the way much Soroban code does.
#[derive(Clone, Debug, arbitrary::Arbitrary)]
enum GeneratedAct {
    Transfer { amount: u16, to: u8 },
    Advance { ledgers: u8 },
}

struct GeneratedWorld {
    contract: Address,
    actors: [Address; 2],
}

struct GeneratedTarget;

impl Target for GeneratedTarget {
    type State = ();
    type Action = GeneratedAct;
    type World = GeneratedWorld;

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, env: &Env, _initial: &()) -> GeneratedWorld {
        let actors = [Address::generate(env), Address::generate(env)];
        let contract = env.register(Vault, (actors[0].clone(), FUNDED));
        GeneratedWorld { contract, actors }
    }

    /// The whole point: no hand-written strategy, just the `Arbitrary` implementation.
    fn actions(&self, _state: &()) -> BoxedStrategy<GeneratedAct> {
        from_arbitrary()
    }

    fn next_state(&self, _state: (), _action: &GeneratedAct) {}

    fn execute(&self, rt: &mut Runtime<'_, GeneratedWorld>, action: &GeneratedAct) -> StepOutcome {
        match action {
            GeneratedAct::Transfer { amount, to } => {
                let contract = rt.world().contract.clone();
                let from = rt.world().actors[0].clone();
                // The generated index is arbitrary, so reduce it into range rather than
                // rejecting draws.
                let to = rt.world().actors[usize::from(*to) % rt.world().actors.len()].clone();
                let amount = i128::from(*amount);
                let client = VaultClient::new(rt.env(), &contract);
                rt.authorize(
                    &from,
                    &contract,
                    "transfer",
                    (from.clone(), to.clone(), amount),
                );
                rt.call("transfer", || client.try_transfer(&from, &to, &amount))
                    .expect_ok()
            }
            GeneratedAct::Advance { ledgers } => {
                rt.ledger().advance(u32::from(*ledgers) % 40);
                StepOutcome::ok()
            }
        }
    }

    fn describe(&self, action: &GeneratedAct) -> String {
        format!("{action:?}")
    }
}

/// A target that fails only after `fail_after` cases have completed.
///
/// The point is to see what a *failure* report says about the cases before it, which is
/// the half of the action ratio that a passing outcome cannot show. Every completed case
/// here generates an action the contract refuses, so a report produced after three of
/// them has something to say.
struct LateFailureTarget {
    executions: Arc<AtomicU64>,
    fail_after: u64,
}

impl Target for LateFailureTarget {
    type State = ();
    type Action = i128;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, env: &Env, _initial: &()) -> World {
        let actors = [Address::generate(env), Address::generate(env)];
        let contract = env.register(Vault, (actors[0].clone(), FUNDED));
        World { contract, actors }
    }

    fn actions(&self, _state: &()) -> BoxedStrategy<i128> {
        // Far beyond the actor's balance, so every one of these is refused.
        (FUNDED + 1..=FUNDED * 2).boxed()
    }

    fn next_state(&self, _state: (), _action: &i128) {}

    fn execute(&self, rt: &mut Runtime<'_, World>, amount: &i128) -> StepOutcome {
        let seen = self.executions.fetch_add(1, Ordering::SeqCst);
        let contract = rt.world().contract.clone();
        let from = rt.world().actors[0].clone();
        let to = rt.world().actors[1].clone();
        let client = VaultClient::new(rt.env(), &contract);
        rt.authorize(
            &from,
            &contract,
            "transfer",
            (from.clone(), to.clone(), *amount),
        );
        let call = rt.call("transfer", || client.try_transfer(&from, &to, amount));

        if seen >= self.fail_after {
            StepOutcome::violation("deliberate failure, so the report has a history")
        } else {
            // Refused, and not declared as expected: counted as an unexpected rejection.
            call.into_step()
        }
    }

    fn describe(&self, amount: &i128) -> String {
        format!("transfer({amount})")
    }
}

/// A failure report carries the action ratio of the cases that led up to it.
///
/// "2,340 cases/s" and "a one-call reproducer" together say nothing about whether the
/// calls reached the contract. A failing run has the same problem as a passing one, so
/// the ratio travels with the report — structurally for a machine to read, and rendered
/// for a person.
#[test]
fn a_failure_report_carries_the_action_ratio_so_far() {
    let outcome = run(
        LateFailureTarget {
            executions: Arc::new(AtomicU64::new(0)),
            fail_after: 3,
        },
        FuzzConfig::default()
            .cases(8)
            .actions(1, 1)
            .seed(0x0D1A_1234),
    );
    let report = outcome.report().expect("the target fails by design");
    assert_eq!(report.kind, "unexpected-error", "{}", report.detail);

    assert!(
        report.stats.unexpected_rejections > 0,
        "the cases before the failure were refusals, so the report should say so: {}",
        report.stats
    );
    assert!(
        report.pretty().contains("before this case"),
        "the rendered report should state what the earlier cases did:\n{}",
        report.pretty()
    );

    let json = report.to_json();
    assert!(
        json.contains("unexpected_rejections"),
        "the JSON report should carry the ratio"
    );
    assert!(
        json.contains("accepted") && json.contains("expected_rejections"),
        "and all three counts, not just the one that is non-zero"
    );
}

// ---------------------------------------------------------------------------
// Replaying a single case
// ---------------------------------------------------------------------------

/// A target that records the actions of every case it executes.
///
/// The log is the point: replaying a case can only be shown to reproduce *that* case
/// by comparing what ran, not merely that a run finished.
#[derive(Clone)]
struct RecordingTarget {
    /// One entry per executed case, holding that case's rendered actions.
    log: Arc<Mutex<Vec<Vec<String>>>>,
}

impl RecordingTarget {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn cases(&self) -> Vec<Vec<String>> {
        self.log.lock().expect("log mutex").clone()
    }
}

impl Target for RecordingTarget {
    type State = ();
    type Action = u64;
    type World = ();

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, _env: &Env, _initial: &()) {}

    fn actions(&self, _state: &()) -> BoxedStrategy<u64> {
        // Wide enough that no two cases are likely to generate the same sequence.
        any::<u64>().boxed()
    }

    fn next_state(&self, _state: (), _action: &u64) {}

    fn execute(&self, rt: &mut Runtime<'_, ()>, action: &u64) -> StepOutcome {
        let mut log = self.log.lock().expect("log mutex");
        if rt.step() == 0 {
            log.push(Vec::new());
        }
        let described = self.describe(action);
        if let Some(case) = log.last_mut() {
            case.push(described);
        }
        StepOutcome::ok()
    }

    fn describe(&self, action: &u64) -> String {
        format!("act({action})")
    }
}

/// Replaying case *N* runs exactly that case, and runs nothing else.
///
/// The equivalence asserted here is the whole contract of the feature: the replayed
/// case has to be the *same* case the full run produced, which only holds because
/// generation is what advances the RNG and every earlier case is therefore generated
/// (and discarded) rather than skipped.
#[test]
fn replaying_a_case_reproduces_exactly_that_case() {
    let seed = 0x11AA_5EED;
    let full_target = RecordingTarget::new();
    let full = run(
        full_target.clone(),
        FuzzConfig::default().cases(8).actions(1, 3).seed(seed),
    );
    assert!(!full.is_failure(), "{full:?}");

    let cases = full_target.cases();
    assert_eq!(cases.len(), 8, "every case should have been recorded");
    // Cases differ from one another, or the comparison below would be vacuous.
    assert!(
        cases
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1,
        "the generated cases should not all be identical: {cases:?}"
    );

    for index in 0..8u32 {
        let replayed_target = RecordingTarget::new();
        let outcome = run(
            replayed_target.clone(),
            // `cases` deliberately differs from the full run: a replay selects one case,
            // so the total is irrelevant to which case it is.
            FuzzConfig::default()
                .cases(64)
                .actions(1, 3)
                .seed(seed)
                .replay_case(index),
        );
        assert!(!outcome.is_failure(), "case {index}: {outcome:?}");
        assert_eq!(
            outcome.stats().map(|stats| stats.total()),
            Some(cases[index as usize].len() as u64),
            "the replayed run should report only its own actions"
        );

        let replayed = replayed_target.cases();
        assert_eq!(replayed.len(), 1, "a replay must run exactly one case");
        assert_eq!(
            replayed[0], cases[index as usize],
            "replaying case {index} must reproduce the case the full run ran there"
        );
    }
}

/// A case index without a seed is refused rather than answered wrongly.
#[test]
fn replaying_without_a_seed_is_refused() {
    let outcome = run(RecordingTarget::new(), FuzzConfig::default().replay_case(3));
    match outcome {
        FuzzOutcome::Aborted { reason } => assert!(
            reason.contains("seed"),
            "the message should say why, and how to fix it: {reason}"
        ),
        other => panic!("a replay without a seed must not silently run: {other:?}"),
    }
}

/// `from_arbitrary` produces actions that actually drive the contract.
///
/// The assertion is not merely that the run finished: a bridge that generated nothing
/// usable would also finish. It is that actions ran, that the contract took them, and
/// that the decoded values reached it.
#[test]
fn actions_can_be_generated_from_arbitrary() {
    let outcome = run(
        GeneratedTarget,
        FuzzConfig::default().cases(32).actions(1, 4).seed(0xA5B1),
    );

    assert!(
        !outcome.is_failure(),
        "the arbitrary-driven target should not fail:\n{outcome:?}"
    );
    let stats = outcome.stats().expect("the run should have completed");
    assert!(
        stats.total() > 0,
        "the bridge must actually generate actions, got {stats}"
    );
    assert_eq!(
        stats.unexpected_rejections, 0,
        "every generated transfer should be affordable, so nothing should be refused: {stats}"
    );
}
