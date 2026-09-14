//! A correctly written contract must pass.
//!
//! This is the test that keeps the harness honest: if a well-behaved contract ever
//! reports a finding, the harness has a false positive and the detectors cannot be
//! trusted.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use common::{mock_invocation, Vault, VaultClient};
use proptest::strategy::Union;
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::Address;

/// Number of actors the model tracks.
const ACTORS: usize = 3;
/// Balance the admin starts with; the whole initial supply.
const INITIAL_SUPPLY: i128 = 1_000;

/// The model: what the contract is supposed to hold, tracked independently.
#[derive(Clone, Debug)]
struct Model {
    balances: [i128; ACTORS],
    ledger: u32,
}

#[derive(Clone, Debug)]
enum Act {
    Transfer {
        from: usize,
        to: usize,
        amount: i128,
    },
    AdvanceLedger {
        ledgers: u32,
    },
}

struct World {
    contract: Address,
    actors: [Address; ACTORS],
}

struct VaultTarget {
    /// Counts executed actions, so the test can prove it actually fuzzed something.
    executions: Arc<AtomicUsize>,
}

impl Target for VaultTarget {
    type State = Model;
    type Action = Act;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<Model> {
        constant(Model {
            balances: [INITIAL_SUPPLY, 0, 0],
            ledger: 0,
        })
    }

    fn setup(&self, env: &Env, initial: &Model) -> World {
        let actors: [Address; ACTORS] = std::array::from_fn(|_| Address::generate(env));
        let supply: i128 = initial.balances.iter().sum();
        // Actor 0 is the admin, and the constructor funds it with the whole supply.
        let contract = env.register(Vault, (actors[0].clone(), supply));
        World { contract, actors }
    }

    fn actions(&self, state: &Model) -> BoxedStrategy<Act> {
        let mut variants: Vec<(u32, BoxedStrategy<Act>)> = vec![(
            1,
            (1u32..=4)
                .prop_map(|ledgers| Act::AdvanceLedger { ledgers })
                .boxed(),
        )];

        // Only generate transfers from an actor that holds a balance; generating an
        // unaffordable transfer would exercise the contract's rejection path rather
        // than the behaviour under test.
        let funded: Vec<usize> = (0..ACTORS).filter(|ix| state.balances[*ix] > 0).collect();
        if !funded.is_empty() {
            let balances = state.balances;
            variants.push((
                6,
                (proptest::sample::select(funded), 0usize..ACTORS)
                    .prop_flat_map(move |(from, to)| {
                        let affordable = balances[from].max(1);
                        (1i128..=affordable).prop_map(move |amount| Act::Transfer {
                            from,
                            to,
                            amount,
                        })
                    })
                    .boxed(),
            ));
        }

        Union::new_weighted(variants).boxed()
    }

    fn next_state(&self, mut state: Model, action: &Act) -> Model {
        match action {
            Act::Transfer { from, to, amount } => {
                state.balances[*from] -= *amount;
                state.balances[*to] += *amount;
            }
            Act::AdvanceLedger { ledgers } => state.ledger += *ledgers,
        }
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, World>, action: &Act) -> StepOutcome {
        self.executions.fetch_add(1, Ordering::Relaxed);

        match action {
            Act::Transfer { from, to, amount } => {
                let contract = rt.world().contract.clone();
                let from_addr = rt.world().actors[*from].clone();
                let to_addr = rt.world().actors[*to].clone();

                // Authorize exactly this invocation for exactly this actor: a contract
                // that authorized the wrong arguments would not pass.
                let env = rt.env();
                mock_invocation(
                    env,
                    &contract,
                    "transfer",
                    &from_addr,
                    common::args(env, (from_addr.clone(), to_addr.clone(), *amount)),
                );

                let client = VaultClient::new(env, &contract);
                rt.call("transfer", || {
                    client.try_transfer(&from_addr, &to_addr, amount)
                })
                .expect_ok()
            }
            Act::AdvanceLedger { ledgers } => {
                rt.ledger().advance(*ledgers);
                StepOutcome::ok()
            }
        }
    }

    fn describe(&self, action: &Act) -> String {
        match action {
            Act::Transfer { from, to, amount } => {
                format!("transfer(actor{from} -> actor{to}, {amount})")
            }
            Act::AdvanceLedger { ledgers } => format!("advance_ledger({ledgers})"),
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            // Total supply is fixed for this target, so it must never change.
            SupplyConserved::new("total-supply-is-fixed", |env: &Env, world: &World| {
                VaultClient::new(env, &world.contract).total()
            })
            .boxed(),
            // The contract's balances must match the model, and must add up to supply.
            FnInvariant::new("balances-match-model", |ctx: &CheckCtx<'_, Self>| {
                let client = VaultClient::new(ctx.env, &ctx.world.contract);

                for (ix, expected) in ctx.model.balances.iter().enumerate() {
                    let actual = client.get_balance(&ctx.world.actors[ix]);
                    if actual != *expected {
                        return Err(format!(
                            "actor {ix}: contract holds {actual}, model expects {expected}"
                        ));
                    }
                }

                let sum: i128 = ctx.model.balances.iter().sum();
                let supply = client.total();
                if supply != sum {
                    return Err(format!(
                        "total supply {supply} does not equal the sum of balances {sum}"
                    ));
                }
                Ok(())
            })
            .boxed(),
            // Nothing in this contract should accumulate storage.
            StorageGrowthBounded::total(16).boxed(),
        ]
    }
}

#[test]
fn a_correct_contract_passes() {
    let executions = Arc::new(AtomicUsize::new(0));
    let target = VaultTarget {
        executions: Arc::clone(&executions),
    };

    let outcome = run(
        target,
        FuzzConfig::default().cases(48).actions(1, 8).seed(0xC0FFEE),
    );

    assert!(
        outcome.is_success(),
        "a correct contract must not report a finding:\n{}",
        outcome
            .report()
            .map(|report| report.pretty())
            .unwrap_or_else(|| format!("{outcome}"))
    );
    assert_eq!(outcome.seed(), Some(0xC0FFEE));
    assert!(
        executions.load(Ordering::Relaxed) > 0,
        "the fuzzer ran but never executed an action"
    );
}

#[test]
fn the_same_seed_reproduces_the_same_run() {
    let first = run(
        VaultTarget {
            executions: Arc::new(AtomicUsize::new(0)),
        },
        FuzzConfig::default().cases(8).actions(1, 4).seed(7),
    );
    let second = run(
        VaultTarget {
            executions: Arc::new(AtomicUsize::new(0)),
        },
        FuzzConfig::default().cases(8).actions(1, 4).seed(7),
    );

    assert!(first.is_success() && second.is_success());
    assert_eq!(first.seed(), second.seed());
    assert_eq!(first.to_string(), second.to_string());
}

#[test]
fn an_unpinned_seed_is_reported() {
    let outcome = run(
        VaultTarget {
            executions: Arc::new(AtomicUsize::new(0)),
        },
        FuzzConfig::default().cases(2).actions(1, 2),
    );

    assert!(
        outcome.seed().is_some(),
        "an unpinned run must still report the seed it used"
    );
}
