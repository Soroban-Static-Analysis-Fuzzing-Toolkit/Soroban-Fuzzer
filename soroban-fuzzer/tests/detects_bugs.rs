//! The harness must find each vulnerability class, and shrink it to a minimal case.
//!
//! A detector that never fires is useless, and a detector that fires with a
//! 40-action reproducer is nearly as bad. These tests assert both that a bug is
//! found and that the reported sequence is the smallest one that still reproduces
//! it.

mod common;

use common::{
    mock_invocation, HoarderVault, HoarderVaultClient, MissingAuthVault, MissingAuthVaultClient,
    ReinitVault, ReinitVaultClient, ResettingVault, ResettingVaultClient, SavingsVault,
    SavingsVaultClient, Vault, VaultClient,
};
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;

// ---------------------------------------------------------------------------
// Missing require_auth
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum MintAct {
    Mint { to: usize, amount: i128 },
}

struct MintWorld {
    contract: Address,
    admin: Address,
    actors: [Address; 2],
}

struct MissingAuthTarget;

impl Target for MissingAuthTarget {
    type State = u32;
    type Action = MintAct;
    type World = MintWorld;

    fn init_state(&self) -> BoxedStrategy<u32> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &u32) -> MintWorld {
        let actors = [Address::generate(env), Address::generate(env)];
        let admin = Address::generate(env);
        let contract = env.register(MissingAuthVault, (admin.clone(), 1_000i128));
        MintWorld {
            contract,
            admin,
            actors,
        }
    }

    fn actions(&self, _state: &u32) -> BoxedStrategy<MintAct> {
        (0usize..2, 1i128..=1_000)
            .prop_map(|(to, amount)| MintAct::Mint { to, amount })
            .boxed()
    }

    fn next_state(&self, state: u32, _action: &MintAct) -> u32 {
        state + 1
    }

    fn execute(&self, rt: &mut Runtime<'_, MintWorld>, action: &MintAct) -> StepOutcome {
        match action {
            MintAct::Mint { to, amount } => {
                let contract = rt.world().contract.clone();
                let admin = rt.world().admin.clone();
                let to_addr = rt.world().actors[*to].clone();
                let client = MissingAuthVaultClient::new(rt.env(), &contract);
                // No credentials at all: this call must be refused.
                rt.call_without_auth("mint", || client.try_mint(&admin, &to_addr, amount))
                    .expect_rejected()
            }
        }
    }

    fn describe(&self, action: &MintAct) -> String {
        match action {
            MintAct::Mint { to, amount } => format!("mint(to=actor{to}, amount={amount})"),
        }
    }
}

#[test]
fn detects_a_missing_require_auth() {
    let outcome = run(
        MissingAuthTarget,
        FuzzConfig::default().cases(4).actions(1, 3).seed(11),
    );

    let report = outcome
        .report()
        .expect("a privileged entrypoint with no require_auth must be detected");

    assert_eq!(report.kind, "unexpected-error", "{}", report.pretty());
    assert!(
        report.detail.contains("must have been refused"),
        "the report should explain that the call should have been refused:\n{detail}",
        detail = report.detail
    );

    // The bug is reachable in one call, so the reproducer must be one call.
    assert_eq!(
        report.minimal_sequence.len(),
        1,
        "expected a one-action reproducer:\n{}",
        report.pretty()
    );

    // The report must attribute the failure to the offending call, with resources.
    let step = report.failing_step().expect("a failing step");
    assert!(
        step.calls.iter().any(|call| call.label == "mint"),
        "the failing step should record the mint call:\n{}",
        report.pretty()
    );

    // And the JSON form must round-trip for CI consumers.
    let json = report.to_json();
    assert!(json.contains("\"kind\": \"unexpected-error\""));
    assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
}

// ---------------------------------------------------------------------------
// Unbounded storage growth
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum RecordAct {
    Record,
}

struct RecordWorld {
    contract: Address,
    actors: [Address; 2],
}

struct StorageTarget;

impl Target for StorageTarget {
    type State = u32;
    type Action = RecordAct;
    type World = RecordWorld;

    fn init_state(&self) -> BoxedStrategy<u32> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &u32) -> RecordWorld {
        let actors = [Address::generate(env), Address::generate(env)];
        let admin = Address::generate(env);
        let contract = env.register(HoarderVault, (admin,));
        RecordWorld { contract, actors }
    }

    fn actions(&self, _state: &u32) -> BoxedStrategy<RecordAct> {
        (0usize..2).prop_map(|_| RecordAct::Record).boxed()
    }

    fn next_state(&self, state: u32, _action: &RecordAct) -> u32 {
        state + 1
    }

    fn execute(&self, rt: &mut Runtime<'_, RecordWorld>, action: &RecordAct) -> StepOutcome {
        match action {
            RecordAct::Record => {
                let contract = rt.world().contract.clone();
                let who = rt.world().actors[0].clone();
                let client = HoarderVaultClient::new(rt.env(), &contract);
                rt.call("record", || client.try_record(&who)).into_step()
            }
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        // The contract starts with two instance entries and adds an entry per call.
        // With a ceiling of three, the second `record` call breaks it.
        vec![StorageGrowthBounded::total(3).boxed()]
    }
}

#[test]
fn detects_unbounded_storage_growth() {
    let outcome = run(
        StorageTarget,
        FuzzConfig::default().cases(8).actions(1, 4).seed(23),
    );

    let report = outcome
        .report()
        .expect("unbounded storage growth must be detected");

    assert_eq!(report.kind, "invariant", "{}", report.pretty());
    assert!(
        report.detail.contains("storage"),
        "the report should name the storage invariant:\n{detail}",
        detail = report.detail
    );
    assert!(
        report.detail.contains("exceeding the ceiling"),
        "the report should state which ceiling was passed:\n{detail}",
        detail = report.detail
    );

    // Two calls are needed to pass a ceiling of three, and no more.
    assert_eq!(
        report.minimal_sequence.len(),
        2,
        "expected a two-action reproducer:\n{}",
        report.pretty()
    );
}

/// A storage-growth finding says *which* entries grew, not merely that storage did.
///
/// "storage grew past 3 entries" tells the reader nothing they can act on. The journal
/// already computes a full delta per call; this asserts it reaches the report, both as
/// structure and as text.
#[test]
fn the_storage_growth_report_names_the_entries_that_grew() {
    let outcome = run(
        StorageTarget,
        FuzzConfig::default().cases(8).actions(1, 4).seed(23),
    );
    let report = outcome
        .report()
        .expect("unbounded storage growth must be detected");

    // Structurally: the changed keys are carried per call, per durability.
    let instance_keys: Vec<&str> = report
        .steps
        .iter()
        .flat_map(|step| &step.calls)
        .flat_map(|call| call.delta.instance.changed_keys.iter())
        .map(String::as_str)
        .collect();
    let persistent_keys: Vec<&str> = report
        .steps
        .iter()
        .flat_map(|step| &step.calls)
        .flat_map(|call| call.delta.persistent.changed_keys.iter())
        .map(String::as_str)
        .collect();

    // `HoarderVault::record` bumps an instance counter and appends a persistent entry.
    assert!(
        instance_keys.iter().any(|key| key.contains("count")),
        "the instance counter should be named; got {instance_keys:?}\n{}",
        report.pretty()
    );
    assert!(
        persistent_keys.iter().any(|key| key.contains("log")),
        "the appended log entry should be named; got {persistent_keys:?}\n{}",
        report.pretty()
    );

    // And in the rendered report, where a reader will actually see it.
    let rendered = report.pretty();
    assert!(
        rendered.contains("storage:"),
        "the report should list what storage each call touched:\n{rendered}"
    );
    assert!(
        rendered.contains("persistent:"),
        "the report should name the durability that grew:\n{rendered}"
    );
    assert!(
        report.to_json().contains("changed_keys"),
        "the JSON report should carry the changed keys"
    );
}

// ---------------------------------------------------------------------------
// Resource-budget blowout
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum TransferAct {
    Transfer { amount: i128 },
}

struct TransferWorld {
    contract: Address,
    admin: Address,
}

struct BudgetTarget;

impl Target for BudgetTarget {
    type State = u32;
    type Action = TransferAct;
    type World = TransferWorld;

    fn init_state(&self) -> BoxedStrategy<u32> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &u32) -> TransferWorld {
        let admin = Address::generate(env);
        let contract = env.register(Vault, (admin.clone(), 1_000i128));
        TransferWorld { contract, admin }
    }

    fn actions(&self, _state: &u32) -> BoxedStrategy<TransferAct> {
        (1i128..=100)
            .prop_map(|amount| TransferAct::Transfer { amount })
            .boxed()
    }

    fn next_state(&self, state: u32, _action: &TransferAct) -> u32 {
        state + 1
    }

    fn execute(&self, rt: &mut Runtime<'_, TransferWorld>, action: &TransferAct) -> StepOutcome {
        match action {
            TransferAct::Transfer { amount } => {
                let contract = rt.world().contract.clone();
                let admin = rt.world().admin.clone();
                let env = rt.env();
                mock_invocation(
                    env,
                    &contract,
                    "transfer",
                    &admin,
                    common::args(env, (admin.clone(), admin.clone(), *amount)),
                );
                let client = VaultClient::new(env, &contract);
                rt.call("transfer", || client.try_transfer(&admin, &admin, amount))
                    .expect_ok()
            }
        }
    }
}

#[test]
fn detects_a_resource_budget_blowout() {
    // A budget no real contract call can fit into, standing in for a call that has
    // outgrown the network's limits.
    let mut limits = mainnet_limits();
    limits.instructions = 50;

    let outcome = run(
        BudgetTarget,
        FuzzConfig::default()
            .cases(4)
            .actions(1, 2)
            .seed(31)
            .limits(limits),
    );

    let report = outcome
        .report()
        .expect("a call over the instruction budget must be detected");

    assert_eq!(report.kind, "unexpected-error", "{}", report.pretty());
    assert!(
        report.detail.contains("network limit"),
        "the report should mention the network limit:\n{detail}",
        detail = report.detail
    );
    assert!(
        report.detail.contains("instructions"),
        "the report should name the exceeded limit:\n{detail}",
        detail = report.detail
    );

    // The measured usage must be attached to the offending call.
    let step = report.failing_step().expect("a failing step");
    let breached = step
        .calls
        .iter()
        .find_map(|call| call.breach.as_ref())
        .expect("the failing call should carry the breach");
    assert_eq!(breached.limit, "instructions");
    assert!(breached.used > breached.allowed);
    assert!(breached.excess() > 0);
    assert!(breached.excess_percent() > 100.0);

    // The measurement itself must be present, not just the breach.
    assert!(
        step.calls.iter().any(|call| call.usage.instructions > 0),
        "resource usage should be recorded for every call"
    );

    assert_eq!(report.minimal_sequence.len(), 1);
}

// ---------------------------------------------------------------------------
// A cumulative quantity that goes backwards
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum FeeAct {
    Accrue {
        amount: i128,
    },
    /// Closes the ledger, starting the next one past the host's sixteen-ledger
    /// temporary TTL.
    CloseLedger {
        ledgers: u32,
    },
}

struct FeeWorld {
    contract: Address,
    admin: Address,
}

struct FeeTarget;

impl Target for FeeTarget {
    type State = u32;
    type Action = FeeAct;
    type World = FeeWorld;

    fn init_state(&self) -> BoxedStrategy<u32> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &u32) -> FeeWorld {
        let admin = Address::generate(env);
        let contract = env.register(ResettingVault, (admin.clone(),));
        FeeWorld { contract, admin }
    }

    fn actions(&self, _state: &u32) -> BoxedStrategy<FeeAct> {
        prop_oneof![
            3 => (1i128..=100).prop_map(|amount| FeeAct::Accrue { amount }),
            // Past the host's own temporary TTL, so the entry is genuinely reclaimed
            // rather than merely left stale.
            1 => (17u32..=40).prop_map(|ledgers| FeeAct::CloseLedger { ledgers }),
        ]
        .boxed()
    }

    fn next_state(&self, state: u32, _action: &FeeAct) -> u32 {
        state + 1
    }

    fn execute(&self, rt: &mut Runtime<'_, FeeWorld>, action: &FeeAct) -> StepOutcome {
        match action {
            FeeAct::Accrue { amount } => {
                let contract = rt.world().contract.clone();
                let admin = rt.world().admin.clone();
                rt.authorize(&admin, &contract, "accrue", (admin.clone(), *amount));
                let client = ResettingVaultClient::new(rt.env(), &contract);
                rt.call("accrue", || client.try_accrue(&admin, amount))
                    .expect_ok()
            }
            FeeAct::CloseLedger { ledgers } => {
                rt.ledger().close_ledger(*ledgers);
                StepOutcome::ok()
            }
        }
    }

    fn describe(&self, action: &FeeAct) -> String {
        match action {
            FeeAct::Accrue { amount } => format!("accrue({amount})"),
            FeeAct::CloseLedger { ledgers } => format!("close_ledger({ledgers})"),
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            // Fees only ever accrue. A ledger boundary that makes the total smaller is
            // the signature of state that did not survive it.
            NonDecreasing::new("fees-collected", |env: &Env, world: &FeeWorld| {
                ResettingVaultClient::new(env, &world.contract).total_fees()
            })
            .boxed(),
        ]
    }
}

#[test]
fn detects_a_cumulative_total_that_goes_backwards() {
    let outcome = run(
        FeeTarget,
        FuzzConfig::default().cases(16).actions(2, 5).seed(61),
    );

    let report = outcome
        .report()
        .expect("a fee total that falls must be detected");

    assert_eq!(report.kind, "invariant", "{}", report.pretty());
    assert!(
        report.detail.contains("fees-collected") && report.detail.contains("went backwards"),
        "the report should name the invariant and what it saw:\n{detail}",
        detail = report.detail
    );

    // One accrual and one ledger boundary is the minimum that can lose the entry, so a
    // longer reproducer means the shrinker left noise in it.
    assert_eq!(
        report.minimal_sequence.len(),
        2,
        "expected a two-action reproducer:\n{}",
        report.pretty()
    );
}

// ---------------------------------------------------------------------------
// Initialization re-opened across a ledger boundary
// ---------------------------------------------------------------------------

/// The model of a correctly guarded vault: an admin, once set, is never replaced.
#[derive(Clone, Debug)]
struct OwnershipModel {
    admin: usize,
}

#[derive(Clone, Debug)]
enum InitAct {
    /// Calls `initialize`, authorized by the actor it names.
    Initialize { as_actor: usize },
    /// Ends the transaction and starts the next ledger.
    CloseLedger { ledgers: u32 },
}

struct InitWorld {
    contract: Address,
    actors: [Address; 2],
}

struct InitTarget;

impl Target for InitTarget {
    type State = OwnershipModel;
    type Action = InitAct;
    type World = InitWorld;

    fn init_state(&self) -> BoxedStrategy<OwnershipModel> {
        constant(OwnershipModel { admin: 0 })
    }

    fn setup(&self, env: &Env, _initial: &OwnershipModel) -> InitWorld {
        let actors = [Address::generate(env), Address::generate(env)];
        // The vault starts out correctly owned: adopting the admin is the deploy path's
        // job, and the bug is in what happens to that ownership later.
        let contract = env.register(ReinitVault, (actors[0].clone(),));
        InitWorld { contract, actors }
    }

    fn actions(&self, _state: &OwnershipModel) -> BoxedStrategy<InitAct> {
        prop_oneof![
            3 => (0usize..2).prop_map(|as_actor| InitAct::Initialize { as_actor }),
            1 => (1u32..=8).prop_map(|ledgers| InitAct::CloseLedger { ledgers }),
        ]
        .boxed()
    }

    fn next_state(&self, state: OwnershipModel, _action: &InitAct) -> OwnershipModel {
        // The specification, not the implementation: an admin is never replaced, however
        // many ledgers pass. A contract that disagrees fails the invariant below.
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, InitWorld>, action: &InitAct) -> StepOutcome {
        match action {
            InitAct::Initialize { as_actor } => {
                let contract = rt.world().contract.clone();
                let actor = rt.world().actors[*as_actor].clone();
                rt.authorize(&actor, &contract, "initialize", (actor.clone(),));
                let client = ReinitVaultClient::new(rt.env(), &contract);
                // Lenient, because the same-ledger refusal is the contract behaving
                // correctly: what is wrong is *succeeding* in a later ledger.
                rt.call("initialize", || client.try_initialize(&actor))
                    .into_step()
            }
            InitAct::CloseLedger { ledgers } => {
                rt.ledger().close_ledger(*ledgers);
                StepOutcome::ok()
            }
        }
    }

    fn describe(&self, action: &InitAct) -> String {
        match action {
            InitAct::Initialize { as_actor } => format!("initialize(as actor{as_actor})"),
            InitAct::CloseLedger { ledgers } => format!("close_ledger({ledgers})"),
        }
    }

    fn expects_rejection(&self, action: &InitAct) -> bool {
        // Re-initializing is supposed to be refused; the negative case is declared so it
        // stays out of the run's rejection ratio. Under a hostile ledger boundary it
        // succeeds, and that is what the invariant catches.
        matches!(action, InitAct::Initialize { .. })
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            FnInvariant::new("admin-never-changes", |ctx: &CheckCtx<'_, Self>| {
                let client = ReinitVaultClient::new(ctx.env, &ctx.world.contract);
                let expected = ctx.world.actors[ctx.model.admin].clone();
                let actual = client.get_admin();
                if actual != expected {
                    return Err(format!(
                        "the stored admin was replaced: the model holds actor{}, the \
                         contract serves {actual:?}",
                        ctx.model.admin
                    ));
                }
                Ok(())
            })
            .boxed(),
        ]
    }
}

#[test]
fn detects_re_initialization_across_a_ledger_boundary() {
    let outcome = run(
        InitTarget,
        FuzzConfig::default().cases(32).actions(2, 6).seed(71),
    );

    let report = outcome
        .report()
        .expect("an initialization guard that a ledger boundary defeats must be detected");

    assert_eq!(report.kind, "invariant", "{}", report.pretty());
    assert!(
        report.detail.contains("admin-never-changes"),
        "the report should name the ownership invariant:\n{detail}",
        detail = report.detail
    );

    // A ledger boundary and one re-initialization: nothing else can replace an admin.
    assert_eq!(
        report.minimal_sequence.len(),
        2,
        "expected a two-action reproducer:\n{}",
        report.pretty()
    );
    let reproducer = report.minimal_sequence.join(" -> ");
    assert!(
        reproducer.contains("close_ledger") && reproducer.contains("initialize"),
        "the reproducer should be a ledger boundary followed by a re-initialization: \
         {reproducer}"
    );
}

// ---------------------------------------------------------------------------
// Shrinking precision
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum DepositAct {
    Deposit { amount: i128 },
}

struct DepositWorld {
    contract: Address,
    admin: Address,
}

/// A target whose invariant only breaks after *two* deposits, so a reproducer
/// longer than two actions is a shrinking failure.
struct ShrinkingTarget;

impl Target for ShrinkingTarget {
    type State = i128;
    type Action = DepositAct;
    type World = DepositWorld;

    fn init_state(&self) -> BoxedStrategy<i128> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &i128) -> DepositWorld {
        let admin = Address::generate(env);
        let contract = env.register(SavingsVault, (admin.clone(),));
        DepositWorld { contract, admin }
    }

    fn actions(&self, _state: &i128) -> BoxedStrategy<DepositAct> {
        (1i128..=100)
            .prop_map(|amount| DepositAct::Deposit { amount })
            .boxed()
    }

    fn next_state(&self, state: i128, action: &DepositAct) -> i128 {
        match action {
            DepositAct::Deposit { amount } => state + amount,
        }
    }

    fn execute(&self, rt: &mut Runtime<'_, DepositWorld>, action: &DepositAct) -> StepOutcome {
        match action {
            DepositAct::Deposit { amount } => {
                let contract = rt.world().contract.clone();
                let admin = rt.world().admin.clone();
                let env = rt.env();
                mock_invocation(
                    env,
                    &contract,
                    "deposit",
                    &admin,
                    common::args(env, (admin.clone(), *amount)),
                );
                let client = SavingsVaultClient::new(env, &contract);
                rt.call("deposit", || client.try_deposit(&admin, amount))
                    .expect_ok()
            }
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        // Two deposits of at most 100 can exceed 150; one cannot.
        vec![
            FnInvariant::new("deposits-stay-small", |ctx: &CheckCtx<'_, Self>| {
                if *ctx.model > 150 {
                    Err(format!("model total reached {}", ctx.model))
                } else {
                    Ok(())
                }
            })
            .boxed(),
        ]
    }
}

#[test]
fn shrinks_to_the_smallest_reproducer() {
    let outcome = run(
        ShrinkingTarget,
        FuzzConfig::default().cases(24).actions(3, 8).seed(47),
    );

    let report = outcome.report().expect("the invariant must be broken");

    assert_eq!(report.kind, "invariant");
    assert_eq!(
        report.minimal_sequence.len(),
        2,
        "two deposits are the minimum that can break the invariant; the shrinker \
         should have removed every other action:\n{}",
        report.pretty()
    );
    assert_eq!(
        report.steps.len(),
        2,
        "the journal should describe exactly the minimized case"
    );

    // The last recorded action is the one after which the invariant broke.
    let failing = report.failing_step().expect("a failing step");
    assert_eq!(failing.index, 1);
    assert_eq!(failing.outcome, "ok");
    assert!(
        report.detail.contains("model total reached"),
        "the report should carry the invariant's own message:\n{detail}",
        detail = report.detail
    );
    // The minimized sequence is the reproducer: the amounts shrink to just past the
    // invariant's threshold.
    let amounts: Vec<i128> = report
        .steps
        .iter()
        .filter_map(|step| {
            step.action
                .trim_start_matches("Deposit { amount: ")
                .trim_end_matches(" }")
                .parse()
                .ok()
        })
        .collect();
    assert_eq!(amounts.len(), 2, "{}", report.pretty());
    assert!(
        amounts.iter().sum::<i128>() > 150,
        "the reproducer must still break the invariant: {amounts:?}"
    );
}

// ---------------------------------------------------------------------------
// Unchecked arithmetic
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum BigDepositAct {
    Deposit { amount: i128 },
}

struct BigDepositWorld {
    contract: Address,
    admin: Address,
}

struct OverflowTarget;

impl Target for OverflowTarget {
    type State = u32;
    type Action = BigDepositAct;
    type World = BigDepositWorld;

    fn init_state(&self) -> BoxedStrategy<u32> {
        constant(0)
    }

    fn setup(&self, env: &Env, _initial: &u32) -> BigDepositWorld {
        let admin = Address::generate(env);
        let contract = env.register(SavingsVault, (admin.clone(),));
        BigDepositWorld { contract, admin }
    }

    fn actions(&self, _state: &u32) -> BoxedStrategy<BigDepositAct> {
        // Amounts anywhere in the i128 range: two of them overflow the contract's
        // unchecked `current + amount`.
        (1i128..=i128::MAX)
            .prop_map(|amount| BigDepositAct::Deposit { amount })
            .boxed()
    }

    fn next_state(&self, state: u32, _action: &BigDepositAct) -> u32 {
        // Counted rather than summed: the *model* must not overflow while the
        // contract does, or the harness would report its own arithmetic.
        state + 1
    }

    fn execute(
        &self,
        rt: &mut Runtime<'_, BigDepositWorld>,
        action: &BigDepositAct,
    ) -> StepOutcome {
        match action {
            BigDepositAct::Deposit { amount } => {
                let contract = rt.world().contract.clone();
                let admin = rt.world().admin.clone();
                let env = rt.env();
                mock_invocation(
                    env,
                    &contract,
                    "deposit",
                    &admin,
                    common::args(env, (admin.clone(), *amount)),
                );
                let client = SavingsVaultClient::new(env, &contract);
                // Every amount is positive, so every deposit must succeed: an
                // overflow is a contract bug, not bad input.
                rt.call("deposit", || client.try_deposit(&admin, amount))
                    .expect_ok()
            }
        }
    }

    fn describe(&self, action: &BigDepositAct) -> String {
        match action {
            BigDepositAct::Deposit { amount } => format!("deposit({amount})"),
        }
    }
}

#[test]
fn detects_unchecked_arithmetic() {
    let outcome = run(
        OverflowTarget,
        FuzzConfig::default().cases(32).actions(2, 6).seed(53),
    );

    let report = outcome
        .report()
        .expect("unchecked arithmetic on an amount must be detected");

    assert_eq!(report.kind, "unexpected-error", "{}", report.pretty());
    assert!(
        report.detail.contains("trapped") || report.detail.contains("rejected"),
        "the report should explain that the call did not succeed:\n{detail}",
        detail = report.detail
    );
    // Two deposits are enough to overflow, and one is not.
    assert_eq!(
        report.minimal_sequence.len(),
        2,
        "expected a two-action reproducer:\n{}",
        report.pretty()
    );
}
