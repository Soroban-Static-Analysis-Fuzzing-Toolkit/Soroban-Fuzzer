//! End-to-end example: fuzz a Soroban token with invariant testing.
//!
//! ```bash
//! cargo run --example token_fuzz
//! ```
//!
//! The contract below is a small token with one planted bug: `set_fee_bps` changes
//! the protocol fee without ever calling `require_auth`. The example runs the same
//! target twice:
//!
//! 1. without generating the privileged call, to show a clean run;
//! 2. with it, to show the finding, the minimal reproducer it was shrunk to, and the
//!    resources each call in that reproducer consumed.
//!
//! Note that the second run finds the bug even though the harness has authorization
//! available: the negative test clears credentials for that one call, which is what
//! `auths()`-mocking unit tests never do.
//!
//! The authorized calls install their credentials through [`Runtime::authorize`],
//! which is the built-in shorthand for "this address authorizes this entrypoint with
//! these arguments". Note that no helper of that kind is written here: it is part of
//! the harness, so a target does not have to reimplement it.

use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::Address as _;

/// Where a failing case's JSON report is written.
const REPORT_PATH: &str = "fuzz-report.json";
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

// ---------------------------------------------------------------------------
// The contract under test
// ---------------------------------------------------------------------------

fn key(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}

fn balance_key(env: &Env, who: &Address) -> (Symbol, Address) {
    (key(env, "bal"), who.clone())
}

fn balance(env: &Env, who: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&balance_key(env, who))
        .unwrap_or(0)
}

fn set_balance(env: &Env, who: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&balance_key(env, who), &amount);
}

fn supply(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&key(env, "total"))
        .unwrap_or(0)
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn __constructor(env: Env, admin: Address, initial_supply: i128) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        env.storage()
            .instance()
            .set(&key(&env, "total"), &initial_supply);
        env.storage().instance().set(&key(&env, "fee"), &0u32);
        set_balance(&env, &admin, initial_supply);
    }

    /// Mints new supply. Requires the stored admin's authorization.
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let stored: Address = env.storage().instance().get(&key(&env, "admin")).unwrap();
        if stored != admin {
            panic!("caller is not the admin");
        }
        set_balance(&env, &to, balance(&env, &to) + amount);
        env.storage()
            .instance()
            .set(&key(&env, "total"), &(supply(&env) + amount));
    }

    /// Transfers between balances. Requires the sender's authorization.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance = balance(&env, &from);
        if amount < 0 || from_balance < amount {
            panic!("insufficient balance");
        }
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, balance(&env, &to) + amount);
    }

    /// Sets the protocol fee.
    ///
    /// The planted bug: this is a privileged entrypoint, but it performs neither
    /// `admin.require_auth()` nor an admin check, so anyone can call it.
    pub fn set_fee_bps(env: Env, _admin: Address, bps: u32) {
        env.storage().instance().set(&key(&env, "fee"), &bps);
    }

    /// Views.
    pub fn get_balance(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }

    pub fn total(env: Env) -> i128 {
        supply(&env)
    }

    pub fn fee_bps(env: Env) -> u32 {
        env.storage().instance().get(&key(&env, "fee")).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// The fuzz target
// ---------------------------------------------------------------------------

const ACTORS: usize = 3;

/// The model: what the token should hold, tracked independently of the contract.
#[derive(Clone, Debug)]
struct Model {
    balances: [i128; ACTORS],
}

#[derive(Clone, Debug)]
enum Act {
    Mint {
        to: usize,
        amount: i128,
    },
    Transfer {
        from: usize,
        to: usize,
        amount: i128,
    },
    AdvanceLedger {
        ledgers: u32,
    },
    /// Attempts to set the fee with no credentials whatsoever.
    SetFeeUnauthorized {
        bps: u32,
    },
}

struct World {
    contract: Address,
    admin: Address,
    actors: [Address; ACTORS],
}

struct TokenTarget {
    /// Whether to generate the privileged `set_fee_bps` call.
    fuzz_privileged_fee: bool,
}

impl Target for TokenTarget {
    type State = Model;
    type Action = Act;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<Model> {
        constant(Model {
            balances: [1_000, 0, 0],
        })
    }

    fn setup(&self, env: &Env, initial: &Model) -> World {
        let actors: [Address; ACTORS] = std::array::from_fn(|_| Address::generate(env));
        let initial_supply: i128 = initial.balances.iter().sum();
        let contract = env.register(Token, (actors[0].clone(), initial_supply));
        World {
            contract,
            admin: actors[0].clone(),
            actors,
        }
    }

    fn actions(&self, state: &Model) -> BoxedStrategy<Act> {
        let mut variants: Vec<(u32, BoxedStrategy<Act>)> = vec![
            (
                1,
                (1u32..=4)
                    .prop_map(|ledgers| Act::AdvanceLedger { ledgers })
                    .boxed(),
            ),
            (
                2,
                (0usize..ACTORS, 1i128..=1_000)
                    .prop_map(|(to, amount)| Act::Mint { to, amount })
                    .boxed(),
            ),
        ];

        if self.fuzz_privileged_fee {
            variants.push((
                6,
                (0u32..=10_000)
                    .prop_map(|bps| Act::SetFeeUnauthorized { bps })
                    .boxed(),
            ));
        }

        // Only transfer from an actor that holds something, so the generated input is
        // valid and a rejection would be a real finding rather than an uninteresting
        // input.
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

        proptest::strategy::Union::new_weighted(variants).boxed()
    }

    fn next_state(&self, mut state: Model, action: &Act) -> Model {
        match action {
            Act::Mint { to, amount } => state.balances[*to] += amount,
            Act::Transfer { from, to, amount } => {
                state.balances[*from] -= amount;
                state.balances[*to] += amount;
            }
            // The fee call must be refused, so the model does not change.
            Act::AdvanceLedger { .. } | Act::SetFeeUnauthorized { .. } => {}
        }
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, World>, action: &Act) -> StepOutcome {
        let contract = rt.world().contract.clone();

        match action {
            Act::Mint { to, amount } => {
                let admin = rt.world().admin.clone();
                let to_addr = rt.world().actors[*to].clone();
                // `Runtime::authorize` installs a credential naming this entrypoint and
                // exactly these arguments, which is stricter than mocking every
                // authorization: a credential for different arguments is refused.
                rt.authorize(
                    &admin,
                    &contract,
                    "mint",
                    (admin.clone(), to_addr.clone(), *amount),
                );
                let client = TokenClient::new(rt.env(), &contract);
                rt.call("mint", || client.try_mint(&admin, &to_addr, amount))
                    .expect_ok()
            }

            Act::Transfer { from, to, amount } => {
                let from_addr = rt.world().actors[*from].clone();
                let to_addr = rt.world().actors[*to].clone();
                rt.authorize(
                    &from_addr,
                    &contract,
                    "transfer",
                    (from_addr.clone(), to_addr.clone(), *amount),
                );
                let client = TokenClient::new(rt.env(), &contract);
                rt.call("transfer", || {
                    client.try_transfer(&from_addr, &to_addr, amount)
                })
                .expect_ok()
            }

            Act::AdvanceLedger { ledgers } => {
                rt.ledger().advance(*ledgers);
                StepOutcome::ok()
            }

            Act::SetFeeUnauthorized { bps } => {
                let admin = rt.world().admin.clone();
                let client = TokenClient::new(rt.env(), &contract);
                // No credentials are installed for this call: a fee change must be
                // refused, and a success means the entrypoint is unprotected.
                rt.call_without_auth("set_fee_bps", || client.try_set_fee_bps(&admin, bps))
                    .expect_rejected()
            }
        }
    }

    fn describe(&self, action: &Act) -> String {
        match action {
            Act::Mint { to, amount } => format!("mint(to=actor{to}, amount={amount})"),
            Act::Transfer { from, to, amount } => {
                format!("transfer(actor{from} -> actor{to}, amount={amount})")
            }
            Act::AdvanceLedger { ledgers } => format!("advance_ledger({ledgers})"),
            Act::SetFeeUnauthorized { bps } => {
                format!("set_fee_bps(bps={bps}) without authorization")
            }
        }
    }

    /// Only the token under test has state here, so every snapshot can be scoped to it.
    ///
    /// Capture cost is linear in the entries the environment holds, and the harness
    /// takes two snapshots per instrumented call, so naming the contracts the run
    /// cares about is the single biggest lever on throughput for a contract with real
    /// state. See `cargo bench` for the measurement.
    fn tracked_contracts(&self, world: &World) -> Vec<Address> {
        vec![world.contract.clone()]
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            // The contract's balances must equal the model's, and the total supply
            // must equal the sum of the parts: no coins are created or destroyed by a
            // transfer.
            FnInvariant::new(
                "balances-and-supply-match-model",
                |ctx: &CheckCtx<'_, Self>| {
                    let client = TokenClient::new(ctx.env, &ctx.world.contract);

                    for (ix, expected) in ctx.model.balances.iter().enumerate() {
                        let actual = client.get_balance(&ctx.world.actors[ix]);
                        if actual != *expected {
                            return Err(format!(
                                "actor {ix}: contract holds {actual}, model expects {expected}"
                            ));
                        }
                    }

                    let sum: i128 = ctx.model.balances.iter().sum();
                    let total = client.total();
                    if total != sum {
                        return Err(format!(
                            "total supply {total} does not equal the sum of balances {sum}"
                        ));
                    }
                    Ok(())
                },
            )
            .boxed(),
            // A few storage entries are expected; unbounded growth is not.
            StorageGrowthBounded::total(64).boxed(),
        ]
    }
}

fn summarize(label: &str, outcome: &FuzzOutcome) {
    println!("== {label} ==");
    match outcome {
        FuzzOutcome::Passed {
            cases,
            seed,
            stats,
            warning,
        } => {
            println!("no findings in {cases} cases (seed {seed})");
            // "no findings" is only meaningful if the generated actions reached the
            // contract, so always report what happened to them.
            println!("{stats}");
            if let Some(warning) = warning {
                println!("warning: {warning}");
            }
            println!();
        }
        FuzzOutcome::Failed(report) => {
            println!("{report}");
            // `run` wrote it, because the configuration set `report_path`.
            println!("JSON report written to report path\n");
        }
        FuzzOutcome::Aborted { reason } => println!("run aborted: {reason}\n"),
    }
}

fn main() {
    // Both runs take their configuration from the environment, so a CI job can widen
    // them (`SOROBAN_FUZZ_CASES`, `SOROBAN_FUZZ_MAX_ACTIONS`, `SOROBAN_FUZZ_SEED`)
    // without a code change. The report path is fixed so the file always lands
    // somewhere a CI job can pick up as an artefact.
    let config = || {
        FuzzConfig::from_env()
            .actions(1, 6)
            .report_path(REPORT_PATH)
    };

    // 1. The token's transfer and mint logic, without the privileged fee call.
    let clean = run(
        TokenTarget {
            fuzz_privileged_fee: false,
        },
        config(),
    );
    summarize("transfer and mint only", &clean);

    // 2. The same target, now generating the privileged fee call with no credentials.
    let privileged = run(
        TokenTarget {
            fuzz_privileged_fee: true,
        },
        config(),
    );
    summarize("including the privileged fee call", &privileged);

    if privileged.is_failure() {
        println!(
            "The planted bug in `set_fee_bps` was found: a privileged entrypoint that \
             never calls `require_auth`. Fix it with `admin.require_auth()` plus an \
             admin check, then re-run to confirm the finding is gone."
        );
    }
}
