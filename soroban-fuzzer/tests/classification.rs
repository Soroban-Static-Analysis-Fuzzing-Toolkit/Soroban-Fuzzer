//! How failures surface, and how the harness classifies them.
//!
//! The harness has to decide, for every call, whether the contract behaved or
//! misbehaved. That decision rests on the shapes the Soroban test environment
//! produces, which are less uniform than they look — this test pins them down, so a
//! change in the SDK or in the classification is caught rather than silently
//! weakening every detector.

mod common;

use common::{mock_invocation, Vault, VaultClient};
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProbeError {
    Nope = 1,
}

#[contract]
pub struct Probe;

#[contractimpl]
impl Probe {
    /// Fails authorization when no credentials are installed.
    ///
    /// Declares a typed error, so a host failure cannot be mapped onto it.
    pub fn needs_auth_typed(who: Address) -> Result<(), ProbeError> {
        who.require_auth();
        Ok(())
    }

    /// Fails authorization when no credentials are installed.
    ///
    /// Declares no error type, so the SDK reports a host failure as
    /// `soroban_sdk::Error`, in the same shape as a declared error.
    pub fn needs_auth_untyped(who: Address) {
        who.require_auth();
    }

    /// Traps with a plain Rust panic.
    pub fn panics() -> u32 {
        panic!("boom")
    }

    /// Traps with a plain Rust panic, from an entrypoint that declares a typed error.
    pub fn panics_typed() -> Result<u32, ProbeError> {
        panic!("boom")
    }

    /// Checks a business rule *before* requiring authorization.
    ///
    /// This is the shape that makes a lenient negative test pass for the wrong
    /// reason: called with a negative amount and no credentials, it is refused — but
    /// not because anything asked for authorization.
    pub fn check_then_auth(amount: i64, who: Address) -> Result<(), ProbeError> {
        if amount < 0 {
            return Err(ProbeError::Nope);
        }
        who.require_auth();
        Ok(())
    }

    /// Mutates nothing and requires nothing: the classic unprotected entrypoint.
    pub fn unprotected(_who: Address) -> u32 {
        1
    }

    /// Overflows: unchecked arithmetic on an amount.
    pub fn overflows(a: i64, b: i64) -> i64 {
        a + b
    }

    /// Returns a declared error, without trapping.
    pub fn with_error() -> Result<u32, ProbeError> {
        Err(ProbeError::Nope)
    }

    pub fn ok_call() -> u32 {
        7
    }
}

fn new_env() -> Env {
    Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    })
}

fn probe(env: &Env) -> ProbeClient<'_> {
    let id = env.register(Probe, ());
    ProbeClient::new(env, &id)
}

#[test]
fn contract_failure_shapes_are_what_the_harness_assumes() {
    // A successful call.
    {
        let env = new_env();
        assert_eq!(probe(&env).try_ok_call(), Ok(Ok(7)));
    }

    // A declared contract error is distinguishable: the typed error is returned.
    {
        let env = new_env();
        assert_eq!(probe(&env).try_with_error(), Err(Ok(ProbeError::Nope)));
    }

    // A failed authorization whose entrypoint declares a typed error surfaces as an
    // `InvokeError`, because the host failure cannot be mapped onto `ProbeError`.
    {
        let env = new_env();
        let client = probe(&env);
        let who = Address::generate(&env);
        env.set_auths(&[]);
        match client.try_needs_auth_typed(&who) {
            Err(Err(_)) => {}
            other => panic!("expected a host-level failure, got {other:?}"),
        }
    }

    // The *same* authorization failure is not distinguishable by shape when the
    // entrypoint declares no error type: it arrives as `Err(Ok(..))`, exactly like a
    // declared contract error. This is precisely why `expect_rejected` accepts both
    // `Rejected` and `Failed` rather than relying on the variant.
    {
        let env = new_env();
        let client = probe(&env);
        let who = Address::generate(&env);
        env.set_auths(&[]);
        match client.try_needs_auth_untyped(&who) {
            Err(Ok(_)) => {}
            other => panic!("expected a declared-error shape, got {other:?}"),
        }
    }

    // A plain panic and an overflow both fail the call rather than unwinding out of
    // the test: the host catches them so `try_*` can report them.
    {
        let env = new_env();
        let client = probe(&env);
        assert!(client.try_panics().is_err(), "a panic must not escape");
        assert!(
            client.try_overflows(&i64::MAX, &1).is_err(),
            "an overflow must not escape"
        );
    }
}

/// An unauthorized call and a plain Rust panic are the same thing to the error type.
///
/// This is the measurement that decides how a negative authorization test has to be
/// written, and it is worth being blunt about because it is the opposite of what one
/// would assume. A failed `require_auth` is not a distinguishable *kind* of failure in
/// the Soroban test environment:
///
/// * from an entrypoint with no declared error, it arrives as
///   `Err(Ok(Error(Context, InvalidAction)))` — and `is_type(ScErrorType::Auth)` is
///   **false**, so it is not even typed as an authorization error;
/// * from an entrypoint with a declared error, it arrives as `Err(Err(Abort))`, the
///   same `InvokeError` a panic produces;
/// * and in both cases the *identical* error is produced by `panic!`.
///
/// So no amount of inspecting the returned error can tell "refused because the caller
/// was not authorized" from "panicked before it ever checked". That is why
/// [`Runtime::call_requiring_auth`] asserts the property positively, by reading the
/// authorization tree the contract demanded, instead of trying to read it out of a
/// failure. If a future SDK makes these distinguishable, this test fails and the
/// lenient-with-reason option becomes available again.
#[test]
fn an_unauthorized_call_is_indistinguishable_from_a_panic() {
    let env = new_env();
    let client = probe(&env);
    let who = Address::generate(&env);
    env.set_auths(&[]);

    // Untyped: a failed `require_auth` and a panic produce the same value.
    let untyped_denied = format!("{:?}", client.try_needs_auth_untyped(&who));
    let untyped_panic = format!("{:?}", client.try_panics());
    assert_eq!(
        untyped_denied, untyped_panic,
        "if these ever differ, the error carries the distinction again"
    );
    assert!(
        untyped_denied.contains("Error(Context, InvalidAction)"),
        "the recorded shape changed: {untyped_denied}"
    );
    match client.try_needs_auth_untyped(&who) {
        Err(Ok(error)) => assert!(
            !error.is_type(soroban_sdk::xdr::ScErrorType::Auth),
            "an authorization failure is not even typed as one"
        ),
        other => panic!("expected a declared-error shape, got {other:?}"),
    }

    // Typed: both collapse onto `InvokeError::Abort`, losing the cause entirely.
    let typed_denied = format!("{:?}", client.try_needs_auth_typed(&who));
    let typed_panic = format!("{:?}", client.try_panics_typed());
    assert_eq!(typed_denied, "Err(Err(Abort))", "{typed_denied}");
    assert_eq!(
        typed_denied, typed_panic,
        "if these ever differ, the distinction is available after all"
    );
}

// ---------------------------------------------------------------------------
// `call_requiring_auth`: the strict authorization test
// ---------------------------------------------------------------------------

/// Which entrypoint the probe target exercises, and how it is expected to be gated.
#[derive(Clone, Copy, Debug)]
enum Guard {
    /// A protected entrypoint: it requires authorization from `who`.
    Protected,
    /// It checks a business rule first, so bad input is refused before any auth check.
    PanicsOnInput,
    /// It requires nothing at all.
    Unprotected,
}

struct AuthProbeTarget {
    guard: Guard,
}

impl Target for AuthProbeTarget {
    type State = ();
    type Action = ();
    type World = (Address, Address);

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, env: &Env, _initial: &()) -> (Address, Address) {
        let id = env.register(Probe, ());
        (id, Address::generate(env))
    }

    fn actions(&self, _state: &()) -> BoxedStrategy<()> {
        Just(()).boxed()
    }

    fn next_state(&self, _state: (), _action: &()) {}

    fn execute(&self, rt: &mut Runtime<'_, (Address, Address)>, _action: &()) -> StepOutcome {
        let who = rt.world().1.clone();
        let client = ProbeClient::new(rt.env(), &rt.world().0);
        match self.guard {
            Guard::Protected => rt.call_requiring_auth("needs_auth_typed", &who, || {
                client.try_needs_auth_typed(&who)
            }),
            Guard::PanicsOnInput => rt.call_requiring_auth("check_then_auth", &who, || {
                client.try_check_then_auth(&-1, &who)
            }),
            Guard::Unprotected => {
                rt.call_requiring_auth("unprotected", &who, || client.try_unprotected(&who))
            }
        }
    }

    fn tracked_contracts(&self, world: &(Address, Address)) -> Vec<Address> {
        vec![world.0.clone()]
    }
}

fn guard_outcome(guard: Guard) -> FuzzOutcome {
    run(
        AuthProbeTarget { guard },
        FuzzConfig::default().cases(1).actions(1, 1).seed(0x9A17),
    )
}

/// The strict test passes when the entrypoint really does demand the authorization.
#[test]
fn call_requiring_auth_accepts_a_protected_entrypoint() {
    let outcome = guard_outcome(Guard::Protected);
    assert!(
        !outcome.is_failure(),
        "a protected entrypoint must satisfy the strict test:\n{outcome:?}"
    );
}

/// A contract that panics on its input does **not** count as protected.
///
/// This is the case a lenient `expect_rejected` test wrongly accepts: with no
/// credentials the call is refused, so "it refused" is satisfied — but the refusal
/// happened before anything looked at authorization, and the entrypoint may well be
/// callable by anyone who supplies better input.
#[test]
fn call_requiring_auth_rejects_an_entrypoint_that_fails_on_its_input() {
    let outcome = guard_outcome(Guard::PanicsOnInput);
    match outcome {
        FuzzOutcome::Failed(report) => {
            assert!(
                report
                    .detail
                    .contains("had to succeed under recorded authorization"),
                "the finding should say the call never got past its input check: {}",
                report.detail
            );
            assert_eq!(
                report.minimal_sequence.len(),
                1,
                "the reproducer should be the single action: {:?}",
                report.minimal_sequence
            );
        }
        other => panic!("the strict test must reject this, got {other:?}"),
    }
}

/// An entrypoint that requires nothing is reported, and the finding names the address.
#[test]
fn call_requiring_auth_rejects_an_unprotected_entrypoint() {
    let outcome = guard_outcome(Guard::Unprotected);
    match outcome {
        FuzzOutcome::Failed(report) => {
            assert!(
                report.detail.contains("never demanded authorization"),
                "the finding should say no authorization was demanded: {}",
                report.detail
            );
            assert!(
                report.detail.contains("it demanded nothing"),
                "and it should say what was demanded instead: {}",
                report.detail
            );
        }
        other => panic!("an unprotected entrypoint must be reported, got {other:?}"),
    }
}

/// The lenient test accepts what the strict one rejects, which is the whole point.
///
/// Two probes, same contract, same action, one conversion apart: `expect_rejected`
/// cannot see the difference between "refused for authorization" and "refused before
/// checking", so it passes on both. Recorded here so the relationship between the two
/// conversions is a fact rather than a claim in a doc comment.
#[test]
fn the_lenient_test_accepts_the_input_check_that_the_strict_one_rejects() {
    struct LenientTarget;

    impl Target for LenientTarget {
        type State = ();
        type Action = ();
        type World = (Address, Address);

        fn init_state(&self) -> BoxedStrategy<()> {
            constant(())
        }

        fn setup(&self, env: &Env, _initial: &()) -> (Address, Address) {
            let id = env.register(Probe, ());
            (id, Address::generate(env))
        }

        fn actions(&self, _state: &()) -> BoxedStrategy<()> {
            Just(()).boxed()
        }

        fn next_state(&self, _state: (), _action: &()) {}

        fn execute(&self, rt: &mut Runtime<'_, (Address, Address)>, _action: &()) -> StepOutcome {
            let who = rt.world().1.clone();
            let client = ProbeClient::new(rt.env(), &rt.world().0);
            rt.call_without_auth("check_then_auth", || client.try_check_then_auth(&-1, &who))
                .expect_rejected()
        }
    }

    let outcome = run(
        LenientTarget,
        FuzzConfig::default().cases(1).actions(1, 1).seed(0x9A17),
    );
    assert!(
        !outcome.is_failure(),
        "the lenient test is satisfied by a refusal that has nothing to do with \
         authorization, which is exactly why the strict test exists:\n{outcome:?}"
    );
}

#[test]
fn call_results_convert_to_step_outcomes_as_documented() {
    // `into_step` is lenient: the call not succeeding is enough.
    assert_eq!(CallResult::Ok(1).into_step(), StepOutcome::Ok);
    assert!(matches!(
        CallResult::<i32>::Rejected("bad".into()).into_step(),
        StepOutcome::Rejected(_)
    ));
    assert!(matches!(
        CallResult::<i32>::Failed("abort".into()).into_step(),
        StepOutcome::Rejected(_)
    ));
    assert!(CallResult::<i32>::LimitExceeded("cpu".into())
        .into_step()
        .is_violation());

    // `expect_ok` requires success.
    assert_eq!(CallResult::Ok(1).expect_ok(), StepOutcome::Ok);
    assert!(CallResult::<i32>::Rejected("bad".into())
        .expect_ok()
        .is_violation());
    assert!(CallResult::<i32>::Failed("abort".into())
        .expect_ok()
        .is_violation());

    // `expect_rejected` is the negative test: only a refusal is acceptable.
    assert!(CallResult::Ok(1).expect_rejected().is_violation());
    assert!(matches!(
        CallResult::<i32>::Rejected("bad".into()).expect_rejected(),
        StepOutcome::Rejected(_)
    ));
    assert!(matches!(
        CallResult::<i32>::Failed("abort".into()).expect_rejected(),
        StepOutcome::Rejected(_)
    ));
    assert!(CallResult::<i32>::LimitExceeded("cpu".into())
        .expect_rejected()
        .is_violation());

    // `expect_contract_error` is stricter than `expect_rejected`: a trap is a bug.
    assert!(matches!(
        CallResult::<i32>::Rejected("bad".into()).expect_contract_error(),
        StepOutcome::Rejected(_)
    ));
    assert!(CallResult::<i32>::Failed("abort".into())
        .expect_contract_error()
        .is_violation());
}

#[test]
fn the_network_limits_are_the_ones_the_network_enforces() {
    let limits = mainnet_limits();
    // The read-entry ceiling that Soroban contracts are most often caught by.
    assert_eq!(limits.disk_read_entries, 200);
    assert_eq!(limits.write_entries, 200);
    assert!(limits.instructions > 0);
    assert!(limits.mem_bytes > 0);
}

#[test]
fn resource_usage_reports_the_limits_it_exceeds() {
    let limits = mainnet_limits();
    let mut usage = ResourceUsage::default();
    assert!(usage.breaches(&limits).is_empty());
    assert!(usage.first_breach(&limits).is_none());

    usage.instructions = limits.instructions + 5;
    usage.disk_read_entries = limits.disk_read_entries + 1;

    let breaches = usage.breaches(&limits);
    let names: Vec<&str> = breaches.iter().map(|b| b.limit.as_str()).collect();
    assert!(names.contains(&"instructions"), "{names:?}");
    assert!(names.contains(&"disk_read_entries"), "{names:?}");

    // CPU is reported first, so a runaway loop is not reported as its storage side
    // effects.
    let first = usage.first_breach(&limits).expect("a breach");
    assert_eq!(first.limit, "instructions");
    assert_eq!(first.excess(), 5);
    assert!(first.excess_percent() > 100.0);
    assert!(first.to_string().contains("instructions limit exceeded"));
}

#[test]
fn resource_usage_is_captured_for_real_invocations() {
    let env = new_env();
    let admin = Address::generate(&env);
    let contract = env.register(Vault, (admin.clone(), 1_000i128));
    let client = VaultClient::new(&env, &contract);

    // Registration runs the constructor as an invocation, so usage is already
    // available afterwards.
    assert!(ResourceUsage::capture(&env).is_some());

    env.mock_all_auths();
    client.transfer(&admin, &admin, &10);

    let usage = ResourceUsage::capture(&env).expect("usage after an invocation");
    assert!(usage.instructions > 0, "{usage:?}");
    assert!(usage.memory_read_entries > 0, "{usage:?}");
    assert!(usage.ledger_entries() > 0);
    assert!(!usage.is_zero());
}

#[test]
fn storage_snapshots_see_contract_state() {
    let env = new_env();
    let admin = Address::generate(&env);
    let contract = env.register(Vault, (admin.clone(), 1_000i128));

    let before = StorageSnapshot::capture(&env);
    // The constructor writes the admin and the total to instance storage, and the
    // admin's balance to persistent storage.
    let counts = before.counts_for(&contract);
    assert_eq!(counts.instance, 2, "{counts:?}");
    assert_eq!(counts.persistent, 1, "{counts:?}");
    assert_eq!(counts.temporary, 0, "{counts:?}");
    assert_eq!(before.total_entries(), 3);
    // Entries are attributed to the contract, not lumped together.
    assert_eq!(before.counts().total(), 3);

    // A transfer only updates existing balances.
    let client = VaultClient::new(&env, &contract);
    env.mock_all_auths();
    let other = Address::generate(&env);
    client.transfer(&admin, &other, &250);

    let after = StorageSnapshot::capture(&env);
    let delta = before.diff(&after);
    assert_eq!(delta.persistent.updated, 1, "{delta:?}");
    assert_eq!(delta.persistent.added, 1, "{delta:?}");
    assert_eq!(
        delta.instance.writes(),
        0,
        "instance storage should not change"
    );
    assert!(delta.writes() > 0);
    assert!(!delta.is_empty());
    assert_eq!(after.counts_for(&contract).persistent, 2);

    // Re-diffing identical snapshots reports no change.
    assert!(after.diff(&after).is_empty());
}

#[test]
fn storage_keys_are_rendered_for_reports() {
    use soroban_sdk::xdr::ScVal;
    use soroban_sdk::{Symbol, TryIntoVal};

    let env = new_env();
    let symbol: soroban_sdk::Val = Symbol::new(&env, "counter").try_into_val(&env).unwrap();
    let key: ScVal = symbol.try_into_val(&env).unwrap();
    let rendered = soroban_fuzzer::storage::render(&key);
    assert_eq!(
        rendered, "\"counter\"",
        "keys should be readable, got {rendered}"
    );

    assert_eq!(soroban_fuzzer::storage::render(&ScVal::U32(42)), "42");
    assert_eq!(
        soroban_fuzzer::storage::render(&ScVal::LedgerKeyContractInstance),
        "<instance>"
    );
}

#[test]
fn auth_policy_controls_credential_installation() {
    // In strict mode a privileged call is refused; with `mock_all_auths` it is not.
    // The harness applies this per action, so an action can still install its own.
    for policy in [AuthPolicy::Strict, AuthPolicy::MockAll] {
        let env = new_env();
        let id = env.register(Probe, ());
        let client = ProbeClient::new(&env, &id);
        let who = Address::generate(&env);

        match policy {
            AuthPolicy::Strict => env.set_auths(&[]),
            AuthPolicy::MockAll => env.mock_all_auths(),
        }

        let result = client.try_needs_auth_typed(&who);
        match policy {
            AuthPolicy::Strict => assert!(result.is_err(), "strict must refuse"),
            AuthPolicy::MockAll => assert!(result.is_ok(), "mocking must allow"),
        }
    }

    // And an action can override the policy for a single call.
    let env = new_env();
    let id = env.register(Probe, ());
    let client = ProbeClient::new(&env, &id);
    let who = Address::generate(&env);
    env.mock_all_auths();
    env.set_auths(&[]);
    assert!(
        client.try_needs_auth_typed(&who).is_err(),
        "clearing the entries must disable mocking for the next call"
    );
}

#[test]
fn mocked_invocations_are_recorded_in_the_auth_tree() {
    // `auths()` is how a test can check *what* a contract asked to be authorized
    // for, which is what the harness's precise mock_invocation relies on.
    let env = new_env();
    let admin = Address::generate(&env);
    let contract = env.register(Vault, (admin.clone(), 1_000i128));
    let client = VaultClient::new(&env, &contract);
    let other = Address::generate(&env);

    mock_invocation(
        &env,
        &contract,
        "transfer",
        &admin,
        common::args(&env, (admin.clone(), other.clone(), 100i128)),
    );
    assert!(
        client.try_transfer(&admin, &other, &100).is_ok(),
        "the mocked invocation should match"
    );

    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, admin);
}
