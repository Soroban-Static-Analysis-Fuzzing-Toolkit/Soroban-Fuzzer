//! Fuzzing a real, unmodified third-party contract.
//!
//! Every other fixture in this crate was written to be fuzzable: its view functions
//! are exactly what the invariants need, and its storage layout was chosen to be easy
//! to read back. That proves the harness works on contracts it was designed around.
//!
//! This file exercises the opposite case. The contract under test is
//! `stellar/soroban-examples`' token, vendored byte-for-byte (see
//! `third-party/soroban-token-example/PROVENANCE.md`). Its interface is fixed by the
//! Soroban token standard rather than by the fuzzer, and it uses shapes the
//! hand-written fixtures do not:
//!
//! * `MuxedAddress` destinations in `transfer`, so the generated client takes
//!   `impl Into<MuxedAddress>` rather than `&Address`;
//! * **temporary** storage with per-entry TTL for allowances, alongside persistent
//!   balances and instance metadata — all three durabilities in one contract;
//! * `soroban_token_sdk` metadata and events, so storage keys are the SDK's rather
//!   than hand-rolled symbols;
//! * global TTL extension on every entrypoint.
//!
//! It also has no `total_supply` view, because the standard token interface does not
//! define one. The conservation-of-supply invariant below therefore does not read it
//! out of the contract: it sums the contract's own persistent balance entries out of
//! the harness's storage snapshot. That is the feature earning its keep on real code
//! — and notice that it only works because entries are attributed to their owning
//! contract, since the composed system in the second half of this file stores i128
//! values of its own.

use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{ScAddress, ScVal};
use soroban_sdk::{
    contract, contractimpl, token, Address, Env, IntoVal, String as SdkString, Symbol,
};
use soroban_token_contract::{Token, TokenClient};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Starting ledger sequence. Fixed so that allowance expiry is modelled exactly.
const START_LEDGER: u32 = 1_000;

/// Deploys the vendored token with `admin` as its administrator.
fn deploy_token(env: &Env, admin: &Address) -> Address {
    env.register(
        Token,
        (
            admin.clone(),
            7u32,
            SdkString::from_str(env, "Example"),
            SdkString::from_str(env, "EXM"),
        ),
    )
}

/// The sum of every persistent `i128` the given contract owns.
///
/// For the token that is exactly its total supply: balances are the only persistent
/// values it writes. The `i128` values of any *other* contract in the same
/// environment are not counted, which is the point of attributing entries to their
/// owner.
fn stored_sum(env: &Env, contract: &Address) -> i128 {
    let owner = ScAddress::from(contract);
    StorageSnapshot::capture(env)
        .entries(StoreKind::Persistent)
        .iter()
        .filter(|((address, _), _)| address == &owner)
        .filter_map(|(_, entry)| match &entry.value {
            ScVal::I128(parts) => Some(i128::from(parts)),
            _ => None,
        })
        .sum()
}

/// The number of entries a contract owns, across all durabilities.
fn entries_of(env: &Env, contract: &Address) -> usize {
    StorageSnapshot::capture(env).counts_for(contract).total()
}

// ===========================================================================
// Part 1: the token on its own
// ===========================================================================

const ACTORS: usize = 3;

#[derive(Clone, Debug)]
struct Model {
    balances: [i128; ACTORS],
    total: i128,
    /// `allowances[from][spender]`, as `(amount, live_until_ledger)`.
    allowances: [[Option<(i128, u32)>; ACTORS]; ACTORS],
    ledger: u32,
}

/// The allowance the contract would report, applying the same expiry rule it does:
/// an allowance whose `live_until_ledger` is behind the current sequence reads as 0.
fn allowance_of(model: &Model, from: usize, spender: usize) -> i128 {
    match model.allowances[from][spender] {
        Some((amount, live_until)) if live_until >= model.ledger => amount,
        _ => 0,
    }
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
    Burn {
        from: usize,
        amount: i128,
    },
    Approve {
        from: usize,
        spender: usize,
        amount: i128,
        live_until: u32,
    },
    TransferFrom {
        spender: usize,
        from: usize,
        to: usize,
        amount: i128,
    },
    AdvanceLedger {
        ledgers: u32,
    },
    /// `mint` with no credentials at all.
    MintWithoutAuth {
        to: usize,
        amount: i128,
    },
    /// `set_admin` with no credentials at all.
    SetAdminWithoutAuth {
        to: usize,
    },
}

struct World {
    contract: Address,
    admin: Address,
    actors: [Address; ACTORS],
}

struct TokenTarget {
    /// Whether the negative (unauthenticated) actions are generated.
    ///
    /// They are always *checked* by the positive tests too — see below — but keeping
    /// them behind a flag lets the negative test shrink to a crisp reproducer.
    negative: bool,
}

impl Target for TokenTarget {
    type State = Model;
    type Action = Act;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<Model> {
        constant(Model {
            balances: [1_000, 0, 0],
            total: 1_000,
            allowances: [[None; ACTORS]; ACTORS],
            ledger: START_LEDGER,
        })
    }

    fn setup(&self, env: &Env, initial: &Model) -> World {
        // Fix the sequence before anything is stored: allowance expiry is modelled
        // against it, so a default of 0 would make expiry untestable.
        env.ledger().set_sequence_number(START_LEDGER);

        let actors: [Address; ACTORS] = std::array::from_fn(|_| Address::generate(env));
        let admin = actors[0].clone();
        let contract = deploy_token(env, &admin);

        // Fund the starting model through the real entrypoint rather than by writing
        // storage directly, so the fixture cannot drift from the contract's own
        // bookkeeping.
        env.mock_all_auths();
        let client = TokenClient::new(env, &contract);
        for (ix, amount) in initial.balances.iter().enumerate() {
            if *amount > 0 {
                client.mint(&actors[ix], amount);
            }
        }
        env.set_auths(&[]);

        World {
            contract,
            admin,
            actors,
        }
    }

    fn actions(&self, state: &Model) -> BoxedStrategy<Act> {
        let mut variants: Vec<(u32, BoxedStrategy<Act>)> = vec![
            (
                2,
                (0usize..ACTORS, 1i128..=500)
                    .prop_map(|(to, amount)| Act::Mint { to, amount })
                    .boxed(),
            ),
            (
                1,
                (1u32..=40)
                    .prop_map(|ledgers| Act::AdvanceLedger { ledgers })
                    .boxed(),
            ),
        ];

        // Transfers only from an actor the model says can afford it, so a rejection
        // would be a real discrepancy rather than an uninteresting input.
        let balances = state.balances;
        let funded: Vec<usize> = (0..ACTORS).filter(|ix| balances[*ix] > 0).collect();
        if !funded.is_empty() {
            variants.push((
                5,
                proptest::sample::select(funded.clone())
                    .prop_flat_map(move |from| {
                        let affordable = balances[from];
                        (0usize..ACTORS, 0i128..=affordable)
                            .prop_map(move |(to, amount)| Act::Transfer { from, to, amount })
                    })
                    .boxed(),
            ));
            variants.push((
                2,
                proptest::sample::select(funded.clone())
                    .prop_flat_map(move |from| {
                        let affordable = balances[from];
                        (0i128..=affordable).prop_map(move |amount| Act::Burn { from, amount })
                    })
                    .boxed(),
            ));
        }

        // Allowances are written for a deadline relative to the *current* sequence, so
        // the generated action is valid when it is generated. `live_for` starts at 1:
        // `write_allowance` extends the entry by exactly `live_until - sequence`, and a
        // zero-length extension is not a case worth generating.
        let ledger = state.ledger;
        variants.push((
            3,
            (0usize..ACTORS, 0usize..ACTORS, 0i128..=100, 1u32..=50)
                .prop_map(move |(from, spender, amount, live_for)| Act::Approve {
                    from,
                    spender,
                    amount,
                    live_until: ledger + live_for,
                })
                .boxed(),
        ));

        // `transfer_from` needs a live allowance *and* a funded sender.
        let spendable: Vec<(usize, usize, i128)> = (0..ACTORS)
            .flat_map(|from| (0..ACTORS).map(move |spender| (from, spender)))
            .filter_map(|(from, spender)| {
                let allowance = allowance_of(state, from, spender);
                let max = allowance.min(state.balances[from]);
                (max > 0).then_some((spender, from, max))
            })
            .collect();
        if !spendable.is_empty() {
            variants.push((
                4,
                proptest::sample::select(spendable)
                    .prop_flat_map(|(spender, from, max)| {
                        (0usize..ACTORS, 0i128..=max).prop_map(move |(to, amount)| {
                            Act::TransferFrom {
                                spender,
                                from,
                                to,
                                amount,
                            }
                        })
                    })
                    .boxed(),
            ));
        }

        if self.negative {
            variants.push((
                6,
                (0usize..ACTORS, 1i128..=500)
                    .prop_map(|(to, amount)| Act::MintWithoutAuth { to, amount })
                    .boxed(),
            ));
            variants.push((
                6,
                (0usize..ACTORS)
                    .prop_map(|to| Act::SetAdminWithoutAuth { to })
                    .boxed(),
            ));
        }

        proptest::strategy::Union::new_weighted(variants).boxed()
    }

    /// Rejects generated actions that the real contract would refuse for reasons
    /// unrelated to the properties under test.
    ///
    /// This is load-bearing, and not only as a generation filter: `proptest`'s
    /// shrinker also consults preconditions, and without them it will happily reduce
    /// a failing case to an action the generator could never have produced — here, a
    /// `burn` from an actor holding nothing, which panics and therefore still
    /// "fails". The reported reproducer would then be about a different bug than the
    /// one that was found. Anything the model knows must hold of the input belongs
    /// here.
    fn preconditions(&self, state: &Model, action: &Act) -> bool {
        match action {
            Act::Mint { .. } | Act::AdvanceLedger { .. } => true,
            // These must be refused, and are valid from any state.
            Act::MintWithoutAuth { .. } | Act::SetAdminWithoutAuth { .. } => true,
            Act::Transfer { from, amount, .. } => *amount <= state.balances[*from],
            Act::Burn { from, amount } => *amount <= state.balances[*from],
            // `write_allowance` panics on a positive amount with a deadline in the
            // past; a zero amount is exempt.
            Act::Approve {
                amount, live_until, ..
            } => *amount == 0 || *live_until > state.ledger,
            Act::TransferFrom {
                spender,
                from,
                amount,
                ..
            } => {
                *amount <= allowance_of(state, *from, *spender) && *amount <= state.balances[*from]
            }
        }
    }

    fn next_state(&self, mut state: Model, action: &Act) -> Model {
        match action {
            Act::Mint { to, amount } => {
                state.balances[*to] += amount;
                state.total += amount;
            }
            Act::Transfer { from, to, amount } => {
                state.balances[*from] -= amount;
                state.balances[*to] += amount;
            }
            Act::Burn { from, amount } => {
                state.balances[*from] -= amount;
                state.total -= amount;
            }
            Act::Approve {
                from,
                spender,
                amount,
                live_until,
            } => {
                state.allowances[*from][*spender] = Some((*amount, *live_until));
            }
            Act::TransferFrom {
                spender,
                from,
                to,
                amount,
            } => {
                // `spend_allowance` writes the remainder back, preserving the deadline.
                if let Some((allowance, live_until)) = state.allowances[*from][*spender] {
                    state.allowances[*from][*spender] = Some((allowance - amount, live_until));
                }
                state.balances[*from] -= amount;
                state.balances[*to] += amount;
            }
            Act::AdvanceLedger { ledgers } => {
                state.ledger += ledgers;
            }
            // These must be refused, so the model does not move.
            Act::MintWithoutAuth { .. } | Act::SetAdminWithoutAuth { .. } => {}
        }
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, World>, action: &Act) -> StepOutcome {
        let contract = rt.world().contract.clone();
        let client = TokenClient::new(rt.env(), &contract);

        match action {
            Act::Mint { to, amount } => {
                let admin = rt.world().admin.clone();
                let to_addr = rt.world().actors[*to].clone();
                // `mint` calls `admin.require_auth()`, and `Address::require_auth`
                // authorizes the whole invocation — so the credential has to name the
                // entrypoint and its exact arguments, not just the caller.
                rt.authorize(&admin, &contract, "mint", (to_addr.clone(), *amount));
                rt.call("mint", || client.try_mint(&to_addr, amount))
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
                rt.call("transfer", || {
                    client.try_transfer(&from_addr, &to_addr, amount)
                })
                .expect_ok()
            }

            Act::Burn { from, amount } => {
                let from_addr = rt.world().actors[*from].clone();
                rt.authorize(&from_addr, &contract, "burn", (from_addr.clone(), *amount));
                rt.call("burn", || client.try_burn(&from_addr, amount))
                    .expect_ok()
            }

            Act::Approve {
                from,
                spender,
                amount,
                live_until,
            } => {
                let from_addr = rt.world().actors[*from].clone();
                let spender_addr = rt.world().actors[*spender].clone();
                rt.authorize(
                    &from_addr,
                    &contract,
                    "approve",
                    (
                        from_addr.clone(),
                        spender_addr.clone(),
                        *amount,
                        *live_until,
                    ),
                );
                rt.call("approve", || {
                    client.try_approve(&from_addr, &spender_addr, amount, live_until)
                })
                .expect_ok()
            }

            Act::TransferFrom {
                spender,
                from,
                to,
                amount,
            } => {
                let spender_addr = rt.world().actors[*spender].clone();
                let from_addr = rt.world().actors[*from].clone();
                let to_addr = rt.world().actors[*to].clone();
                rt.authorize(
                    &spender_addr,
                    &contract,
                    "transfer_from",
                    (
                        spender_addr.clone(),
                        from_addr.clone(),
                        to_addr.clone(),
                        *amount,
                    ),
                );
                rt.call("transfer_from", || {
                    client.try_transfer_from(&spender_addr, &from_addr, &to_addr, amount)
                })
                .expect_ok()
            }

            Act::AdvanceLedger { ledgers } => {
                rt.ledger().advance(*ledgers);
                StepOutcome::ok()
            }

            Act::MintWithoutAuth { to, amount } => {
                let to_addr = rt.world().actors[*to].clone();
                rt.call_without_auth("mint", || client.try_mint(&to_addr, amount))
                    .expect_rejected()
            }

            Act::SetAdminWithoutAuth { to } => {
                let to_addr = rt.world().actors[*to].clone();
                rt.call_without_auth("set_admin", || client.try_set_admin(&to_addr))
                    .expect_rejected()
            }
        }
    }

    fn describe(&self, action: &Act) -> String {
        match action {
            Act::Mint { to, amount } => format!("mint(actor{to}, {amount})"),
            Act::Transfer { from, to, amount } => {
                format!("transfer(actor{from} -> actor{to}, {amount})")
            }
            Act::Burn { from, amount } => format!("burn(actor{from}, {amount})"),
            Act::Approve {
                from,
                spender,
                amount,
                live_until,
            } => format!("approve(actor{from} -> actor{spender}, {amount}, until {live_until})"),
            Act::TransferFrom {
                spender,
                from,
                to,
                amount,
            } => {
                format!("transfer_from(actor{spender} moves {amount} of actor{from} to actor{to})")
            }
            Act::AdvanceLedger { ledgers } => format!("advance_ledger({ledgers})"),
            Act::MintWithoutAuth { to, amount } => {
                format!("mint(actor{to}, {amount}) WITHOUT AUTH")
            }
            Act::SetAdminWithoutAuth { to } => format!("set_admin(actor{to}) WITHOUT AUTH"),
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            // Conservation of value, read out of the contract's own balance entries
            // because the standard token interface has no total-supply view.
            FnInvariant::new(
                "stored-balances-sum-to-the-model-supply",
                |ctx: &CheckCtx<'_, Self>| {
                    let observed = stored_sum(ctx.env, &ctx.world.contract);
                    if observed != ctx.model.total {
                        return Err(format!(
                            "the contract's balance entries sum to {observed}, \
                             the model says the supply is {}",
                            ctx.model.total
                        ));
                    }
                    Ok(())
                },
            )
            .boxed(),
            // Every per-actor balance, against the independent model.
            FnInvariant::new("balances-match-model", |ctx: &CheckCtx<'_, Self>| {
                let client = TokenClient::new(ctx.env, &ctx.world.contract);
                for (ix, expected) in ctx.model.balances.iter().enumerate() {
                    let actual = client.balance(&ctx.world.actors[ix]);
                    if actual != *expected {
                        return Err(format!(
                            "actor {ix}: the contract holds {actual}, the model expects {expected}"
                        ));
                    }
                }
                Ok(())
            })
            .boxed(),
            // Allowances live in temporary storage with an expiry, so this checks the
            // model's expiry rule against the contract's.
            FnInvariant::new("allowances-match-model", |ctx: &CheckCtx<'_, Self>| {
                let client = TokenClient::new(ctx.env, &ctx.world.contract);
                for from in 0..ACTORS {
                    for spender in 0..ACTORS {
                        let expected = allowance_of(ctx.model, from, spender);
                        let actual =
                            client.allowance(&ctx.world.actors[from], &ctx.world.actors[spender]);
                        if actual != expected {
                            return Err(format!(
                                "allowance actor{from} -> actor{spender}: the contract \
                                 reports {actual}, the model expects {expected}"
                            ));
                        }
                    }
                }
                Ok(())
            })
            .boxed(),
            StorageGrowthBounded::total(64).boxed(),
        ]
    }
}

/// The real token holds its invariants under a rich action set, including
/// unauthenticated attempts at `mint` and `set_admin`.
///
/// This is the headline test of this file: the harness has to build a working target
/// over an interface it did not design, model three storage durabilities, drive a
/// `MuxedAddress` entrypoint through the strict authorization policy, and conserve
/// supply as measured from the contract's own entries.
#[test]
fn real_token_holds_its_invariants() {
    let outcome = run(
        TokenTarget { negative: true },
        FuzzConfig::default().cases(256).actions(1, 10).seed(0x7E57),
    );
    assert!(
        !outcome.is_failure(),
        "the unmodified standard token violated an invariant:\n{outcome:?}"
    );
}

/// `mint` and `set_admin` on the real token are actually protected.
///
/// The generated sequences consist only of unauthenticated privileged calls, so the
/// reproducer proptest reports if this ever regresses is a single action.
#[test]
fn real_token_refuses_unauthenticated_privileged_calls() {
    let outcome = run(
        TokenTarget { negative: true },
        FuzzConfig::default().cases(128).actions(1, 1).seed(0xA11E),
    );
    assert!(
        !outcome.is_failure(),
        "a privileged entrypoint accepted a call with no credentials:\n{outcome:?}"
    );
}

/// The harness distinguishes all three storage durabilities in one real contract.
///
/// A direct assertion rather than a fuzz run, because the point is that the snapshot
/// can see temporary entries at all: `approve` writes to temporary storage, and a
/// snapshot that only understood persistent data would silently under-count.
#[test]
fn the_three_storage_durabilities_are_distinguishable() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.ledger().set_sequence_number(START_LEDGER);

    let admin = Address::generate(&env);
    let holder = Address::generate(&env);
    let spender = Address::generate(&env);
    let contract = deploy_token(&env, &admin);
    let client = TokenClient::new(&env, &contract);

    env.mock_all_auths();
    client.mint(&holder, &500i128);
    client.approve(&holder, &spender, &200i128, &(START_LEDGER + 100));
    env.set_auths(&[]);

    let snapshot = StorageSnapshot::capture(&env);
    let counts = snapshot.counts_for(&contract);
    assert!(
        counts.instance > 0,
        "instance storage (admin, metadata, supply bookkeeping) should be visible"
    );
    assert!(
        counts.persistent > 0,
        "the holder's balance is a persistent entry and should be visible"
    );
    assert!(
        counts.temporary > 0,
        "the allowance is a temporary entry and should be visible"
    );

    // And the persisted values are what the contract would report.
    assert_eq!(client.balance(&holder), 500);
    assert_eq!(client.allowance(&holder, &spender), 200);
    assert_eq!(stored_sum(&env, &contract), 500);
}

/// An invariant that *writes* is caught rather than silently corrupting the run.
///
/// The guard exists because an invariant reaching a state-mutating entrypoint makes
/// every subsequent check depend on the checker: the contract is no longer the thing
/// under test. It is asserted here so that the tolerance for host-driven temporary
/// expiry (see below) cannot quietly widen into "invariants may write".
#[test]
fn a_mutating_invariant_is_detected() {
    struct MutatingTarget;

    impl Target for MutatingTarget {
        type State = ();
        type Action = ();
        type World = (Address, Address);

        fn init_state(&self) -> BoxedStrategy<()> {
            constant(())
        }

        fn setup(&self, env: &Env, _initial: &()) -> (Address, Address) {
            env.ledger().set_sequence_number(START_LEDGER);
            let contract = deploy_token(env, &Address::generate(env));
            let holder = Address::generate(env);
            env.mock_all_auths();
            (contract, holder)
        }

        fn actions(&self, _state: &()) -> BoxedStrategy<()> {
            Just(()).boxed()
        }

        fn next_state(&self, _state: (), _action: &()) {}

        fn execute(&self, _rt: &mut Runtime<'_, (Address, Address)>, _action: &()) -> StepOutcome {
            StepOutcome::ok()
        }

        fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
            vec![
                FnInvariant::new("mutating-invariant", |ctx: &CheckCtx<'_, Self>| {
                    // The mistake being guarded against: an invariant that calls a
                    // mutating entrypoint instead of reading one.
                    TokenClient::new(ctx.env, &ctx.world.0).mint(&ctx.world.1, &1i128);
                    Ok(())
                })
                .boxed(),
            ]
        }
    }

    let outcome = run(
        MutatingTarget,
        FuzzConfig::default()
            .cases(1)
            .actions(1, 1)
            .auth(AuthPolicy::MockAll)
            .seed(1),
    );

    match outcome {
        FuzzOutcome::Failed(report) => {
            assert_eq!(report.kind, "invariant", "report was: {}", report.detail);
            assert!(
                report.detail.contains("modified contract state"),
                "report was: {}",
                report.detail
            );
            assert!(
                report.detail.contains("persistent"),
                "the report should name the durability that changed: {}",
                report.detail
            );
        }
        other => panic!("a mutating invariant must be caught, got {other:?}"),
    }
}

/// The one snapshot change a read-only check is allowed to cause, and why it has to
/// be tolerated.
///
/// The host reclaims an expired **temporary** entry when it reads it. The allowance
/// below has a logical deadline one ledger after it is written — which is what the
/// contract enforces, by reporting a zero amount — but the host's own temporary TTL is
/// sixteen ledgers, and past that point the *read itself* removes the entry from the
/// ledger. So an invariant that only reads an allowance can make a temporary entry
/// vanish between two snapshots taken around that check.
///
/// This is the entire shape the read-only guard in `runner::check_invariants`
/// tolerates, and it is asserted here in full: a removal, and nothing else, anywhere.
/// If a future change to the harness widened that tolerance — or if reading temporary
/// state started rewriting entries — this test fails.
#[test]
fn reading_a_reclaimed_allowance_only_removes_it() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.ledger().set_sequence_number(START_LEDGER);

    let admin = Address::generate(&env);
    let holder = Address::generate(&env);
    let spender = Address::generate(&env);
    let contract = deploy_token(&env, &admin);
    let client = TokenClient::new(&env, &contract);

    env.mock_all_auths();
    client.mint(&holder, &100i128);
    client.approve(&holder, &spender, &50i128, &(START_LEDGER + 1));
    env.set_auths(&[]);

    let before = StorageSnapshot::capture(&env);
    assert_eq!(
        before.counts_for(&contract).temporary,
        1,
        "the allowance should be one temporary entry to begin with"
    );

    // Past the host's temporary TTL. The contract's own deadline passed much earlier.
    env.ledger().set_sequence_number(START_LEDGER + 20);
    assert_eq!(
        client.allowance(&holder, &spender),
        0,
        "an allowance past its deadline must read as zero"
    );

    let delta = before.diff(&StorageSnapshot::capture(&env));
    assert_eq!(
        delta.temporary.removed, 1,
        "the host should reclaim the entry on read; got {delta:?}"
    );
    assert_eq!(delta.temporary.added, 0, "nothing may be added: {delta:?}");
    assert_eq!(
        delta.temporary.updated, 0,
        "nothing may be updated: {delta:?}"
    );
    assert!(
        delta.instance.is_empty() && delta.persistent.is_empty(),
        "no instance or persistent state may change: {delta:?}"
    );
}

// ===========================================================================
// Part 2: a second contract composing with the real token
// ===========================================================================

/// A minimal deposit vault: it holds tokens on behalf of users.
///
/// Written to be the *simplest* thing that makes a genuine cross-contract call, so
/// that what the tests below exercise is the harness rather than this contract.
///
/// Note the asymmetry in how it is authorized, which is Soroban's auth model rather
/// than a choice made here:
///
/// * `deposit` moves the *user's* tokens, so the user's authorization must cover the
///   `transfer` the vault makes onward — the auth tree needs a sub-invocation.
/// * `withdraw` moves the *vault's* own tokens, and a contract's `require_auth` is
///   satisfied implicitly when it is the direct caller.
#[contract]
pub struct Vault;

fn vault_key(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}

fn vault_note(env: &Env, user: &Address) -> (Symbol, Address) {
    (vault_key(env, "dep"), user.clone())
}

#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, token: Address) {
        env.storage()
            .instance()
            .set(&vault_key(&env, "token"), &token);
        env.storage()
            .instance()
            .set(&vault_key(&env, "total"), &0i128);
    }

    fn token(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&vault_key(env, "token"))
            .unwrap()
    }

    fn total(env: &Env) -> i128 {
        env.storage()
            .instance()
            .get(&vault_key(env, "total"))
            .unwrap_or(0)
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let token = Self::token(&env);
        let vault = env.current_contract_address();
        token::Client::new(&env, &token).transfer(&user, &vault, &amount);

        let key = vault_note(&env, &user);
        let held: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(held + amount));
        env.storage()
            .instance()
            .set(&vault_key(&env, "total"), &(Self::total(&env) + amount));
    }

    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = vault_note(&env, &user);
        let held: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if held < amount {
            panic!("insufficient deposit");
        }
        env.storage().persistent().set(&key, &(held - amount));

        let token = Self::token(&env);
        let vault = env.current_contract_address();
        token::Client::new(&env, &token).transfer(&vault, &user, &amount);

        env.storage()
            .instance()
            .set(&vault_key(&env, "total"), &(Self::total(&env) - amount));
    }

    pub fn deposits(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&vault_note(&env, &user))
            .unwrap_or(0)
    }

    pub fn held(env: Env) -> i128 {
        Self::total(&env)
    }
}

const USERS: usize = 2;

#[derive(Clone, Debug)]
struct VaultModel {
    /// What each user holds as tokens, outside the vault.
    ///
    /// Tracked because a deposit moves the user's own tokens: without it the
    /// generator would produce deposits the user cannot fund, and the shrinker would
    /// reduce real findings to reproducers that fail for that reason instead.
    liquid: [i128; USERS],
    /// What each user has deposited with the vault.
    deposits: [i128; USERS],
    total: i128,
}

#[derive(Clone, Debug)]
enum VaultAct {
    Deposit {
        user: usize,
        amount: i128,
    },
    Withdraw {
        user: usize,
        amount: i128,
    },
    /// Authorizes the vault invocation but *not* the token transfer it makes onward.
    DepositWithoutSubInvoke {
        user: usize,
        amount: i128,
    },
}

struct VaultWorld {
    token: Address,
    vault: Address,
    users: [Address; USERS],
}

struct VaultTarget;

impl Target for VaultTarget {
    type State = VaultModel;
    type Action = VaultAct;
    type World = VaultWorld;

    fn init_state(&self) -> BoxedStrategy<VaultModel> {
        constant(VaultModel {
            // Each user is funded with 1,000 tokens; user 0 starts with 250 of them
            // already deposited, so the vault starts with a non-empty bookkeeping
            // state to grow and unwind.
            liquid: [750, 1_000],
            deposits: [250, 0],
            total: 250,
        })
    }

    fn setup(&self, env: &Env, initial: &VaultModel) -> VaultWorld {
        env.ledger().set_sequence_number(START_LEDGER);

        let users: [Address; USERS] = std::array::from_fn(|_| Address::generate(env));
        let token = deploy_token(env, &Address::generate(env));
        let vault = env.register(Vault, (token.clone(),));

        // Fund the users and seed the vault through the real entrypoints, so the
        // fixture cannot disagree with the contracts' own bookkeeping. `mock_all_auths`
        // is acceptable here and only here: setup is fixture construction, not the
        // behaviour under test, and every generated action installs its own precise
        // credential instead.
        env.mock_all_auths();
        let token_client = TokenClient::new(env, &token);
        let vault_client = VaultClient::new(env, &vault);
        for (ix, amount) in initial.deposits.iter().enumerate() {
            // Mint the user's whole starting balance, then move the seeded part into
            // the vault, so the model's `liquid` is what is left outside it.
            token_client.mint(&users[ix], &(initial.liquid[ix] + amount));
            if *amount > 0 {
                vault_client.deposit(&users[ix], amount);
            }
        }
        env.set_auths(&[]);

        VaultWorld {
            token,
            vault,
            users,
        }
    }

    fn actions(&self, state: &VaultModel) -> BoxedStrategy<VaultAct> {
        let mut variants: Vec<(u32, BoxedStrategy<VaultAct>)> = Vec::new();

        // A deposit moves the user's own tokens, so it is only generated when the
        // model says they hold enough of them.
        let liquid = state.liquid;
        let solvent: Vec<usize> = (0..USERS).filter(|ix| liquid[*ix] > 0).collect();
        if !solvent.is_empty() {
            let max = liquid.iter().copied().max().unwrap_or(0);
            variants.push((
                5,
                proptest::sample::select(solvent)
                    .prop_flat_map(move |user| {
                        let affordable = liquid[user];
                        (Just(user), 1i128..=affordable)
                    })
                    .prop_map(|(user, amount)| VaultAct::Deposit { user, amount })
                    .boxed(),
            ));
            // The same shape, but with the credential's sub-invocation left out.
            variants.push((
                3,
                (0usize..USERS, 1i128..=200.min(max))
                    .prop_map(|(user, amount)| VaultAct::DepositWithoutSubInvoke { user, amount })
                    .boxed(),
            ));
        }

        let deposits = state.deposits;
        let funded: Vec<usize> = (0..USERS).filter(|ix| deposits[*ix] > 0).collect();
        if !funded.is_empty() {
            variants.push((
                3,
                proptest::sample::select(funded)
                    .prop_flat_map(move |user| {
                        let affordable = deposits[user];
                        (1i128..=affordable)
                            .prop_map(move |amount| VaultAct::Withdraw { user, amount })
                    })
                    .boxed(),
            ));
        }

        if variants.is_empty() {
            variants.push((1, Just(VaultAct::Withdraw { user: 0, amount: 0 }).boxed()));
        }

        proptest::strategy::Union::new_weighted(variants).boxed()
    }

    /// Rejects generated actions the vault would refuse for reasons other than the
    /// properties under test — see the note on the token target's preconditions.
    fn preconditions(&self, state: &VaultModel, action: &VaultAct) -> bool {
        match action {
            VaultAct::Deposit { user, amount } => *amount <= state.liquid[*user],
            VaultAct::Withdraw { user, amount } => *amount <= state.deposits[*user],
            // The rejection this action is looking for has to come from the missing
            // nested authorization, not from the user being unable to pay.
            VaultAct::DepositWithoutSubInvoke { user, amount } => *amount <= state.liquid[*user],
        }
    }

    fn next_state(&self, mut state: VaultModel, action: &VaultAct) -> VaultModel {
        match action {
            VaultAct::Deposit { user, amount } => {
                state.liquid[*user] -= amount;
                state.deposits[*user] += amount;
                state.total += amount;
            }
            VaultAct::Withdraw { user, amount } => {
                state.deposits[*user] -= amount;
                state.liquid[*user] += amount;
                state.total -= amount;
            }
            // Must be refused, so nothing moves.
            VaultAct::DepositWithoutSubInvoke { .. } => {}
        }
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, VaultWorld>, action: &VaultAct) -> StepOutcome {
        let vault = rt.world().vault.clone();
        let token = rt.world().token.clone();
        let env = rt.env();
        let client = vault_client(env, &vault);

        match action {
            VaultAct::Deposit { user, amount } => {
                let user_addr = rt.world().users[*user].clone();
                install_deposit_auth(env, &vault, &token, &user_addr, *amount, true);
                rt.call("deposit", || client.try_deposit(&user_addr, amount))
                    .expect_ok()
            }

            VaultAct::Withdraw { user, amount } => {
                let user_addr = rt.world().users[*user].clone();
                // The vault moves its own tokens, so no sub-invocation is needed: a
                // contract calling out is authorized as the direct caller.
                rt.authorize(&user_addr, &vault, "withdraw", (user_addr.clone(), *amount));
                rt.call("withdraw", || client.try_withdraw(&user_addr, amount))
                    .expect_ok()
            }

            VaultAct::DepositWithoutSubInvoke { user, amount } => {
                let user_addr = rt.world().users[*user].clone();
                // Authorizing the vault invocation but not the token transfer the
                // vault makes onward must be refused. If the token's `transfer` ever
                // stopped calling `require_auth`, this check would start succeeding —
                // which is exactly the regression worth catching.
                install_deposit_auth(env, &vault, &token, &user_addr, *amount, false);
                rt.call("deposit", || client.try_deposit(&user_addr, amount))
                    .expect_rejected()
            }
        }
    }

    fn describe(&self, action: &VaultAct) -> String {
        match action {
            VaultAct::Deposit { user, amount } => format!("deposit(user{user}, {amount})"),
            VaultAct::Withdraw { user, amount } => format!("withdraw(user{user}, {amount})"),
            VaultAct::DepositWithoutSubInvoke { user, amount } => {
                format!("deposit(user{user}, {amount}) authorized WITHOUT the nested transfer")
            }
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        vec![
            FnInvariant::new(
                "vault-bookkeeping-matches-model",
                |ctx: &CheckCtx<'_, Self>| {
                    let vault = vault_client(ctx.env, &ctx.world.vault);
                    for (ix, expected) in ctx.model.deposits.iter().enumerate() {
                        let actual = vault.deposits(&ctx.world.users[ix]);
                        if actual != *expected {
                            return Err(format!(
                            "user {ix}: the vault records {actual}, the model expects {expected}"
                        ));
                        }
                    }
                    if vault.held() != ctx.model.total {
                        return Err(format!(
                            "the vault reports {} held, the model expects {}",
                            vault.held(),
                            ctx.model.total
                        ));
                    }
                    Ok(())
                },
            )
            .boxed(),
            // The two contracts' views of the same users, checked against the model
            // and therefore against each other.
            FnInvariant::new(
                "user-token-balances-match-model",
                |ctx: &CheckCtx<'_, Self>| {
                    let token = TokenClient::new(ctx.env, &ctx.world.token);
                    for (ix, expected) in ctx.model.liquid.iter().enumerate() {
                        let actual = token.balance(&ctx.world.users[ix]);
                        if actual != *expected {
                            return Err(format!(
                                "user {ix}: the token holds {actual}, the model expects {expected}"
                            ));
                        }
                    }
                    Ok(())
                },
            )
            .boxed(),
            // The composition invariant: the vault's bookkeeping must be fully backed
            // by tokens it actually holds. A single unchecked debit would break it.
            FnInvariant::new("vault-is-solvent", |ctx: &CheckCtx<'_, Self>| {
                let token = TokenClient::new(ctx.env, &ctx.world.token);
                let backing = token.balance(&ctx.world.vault);
                let claimed = vault_client(ctx.env, &ctx.world.vault).held();
                if backing != claimed {
                    return Err(format!(
                        "the vault claims {claimed} in deposits but holds {backing} tokens"
                    ));
                }
                Ok(())
            })
            .boxed(),
            // Deposits are per-user persistent entries under the *vault's* address,
            // interleaved in the same ledger with the token's balance entries. A
            // snapshot that mixed them up would break the invariant above.
            StorageGrowthBounded::total(64).boxed(),
        ]
    }
}

/// Builds the credential for `vault.deposit(user, amount)`.
///
/// When `with_sub_invoke` is set the credential also authorizes the
/// `token.transfer(user, vault, amount)` the vault makes onward; the failing test case
/// omits exactly that, so the only difference between the two is the nesting.
fn install_deposit_auth(
    env: &Env,
    vault: &Address,
    token: &Address,
    user: &Address,
    amount: i128,
    with_sub_invoke: bool,
) {
    let deposit_args = (user.clone(), amount).into_val(env);
    let transfer_args = (user.clone(), vault.clone(), amount).into_val(env);

    let sub = MockAuthInvoke {
        contract: token,
        fn_name: "transfer",
        args: transfer_args,
        sub_invokes: &[],
    };
    let subs: &[MockAuthInvoke] = if with_sub_invoke {
        std::slice::from_ref(&sub)
    } else {
        &[]
    };
    let root = MockAuthInvoke {
        contract: vault,
        fn_name: "deposit",
        args: deposit_args,
        sub_invokes: subs,
    };

    env.set_auths(&[]);
    env.mock_auths(&[MockAuth {
        address: user,
        invoke: &root,
    }]);
}

fn vault_client<'a>(env: &'a Env, vault: &Address) -> VaultClient<'a> {
    VaultClient::new(env, vault)
}

/// A two-contract system holds its invariants, with the real token underneath.
#[test]
fn cross_contract_vault_holds_its_invariants() {
    let outcome = run(
        VaultTarget,
        FuzzConfig::default().cases(192).actions(1, 8).seed(0x5A17),
    );
    assert!(
        !outcome.is_failure(),
        "the vault/token composition violated an invariant:\n{outcome:?}"
    );
}

/// Storage is attributed to the contract that owns it.
///
/// The token stores one `i128` per balance and the vault stores one `i128` per
/// depositor, in the same ledger. If the snapshot did not attribute entries to their
/// owner, the vault's solvency invariant would be meaningless — it would be summing
/// balances that belong to the token.
#[test]
fn cross_contract_storage_is_attributed_per_contract() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.ledger().set_sequence_number(START_LEDGER);

    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let token = deploy_token(&env, &admin);
    let vault = env.register(Vault, (token.clone(),));

    env.mock_all_auths();
    TokenClient::new(&env, &token).mint(&user, &1_000i128);
    VaultClient::new(&env, &vault).deposit(&user, &400i128);
    env.set_auths(&[]);

    // The token's own balance entries still sum to the full supply: the user's 600,
    // plus the 400 it now holds on the vault's behalf. Nothing left the token.
    assert_eq!(stored_sum(&env, &token), 1_000);
    // The vault's `i128` entry, in the same ledger, is counted separately — which is
    // what makes the vault's solvency invariant meaningful.
    assert_eq!(stored_sum(&env, &vault), 400);

    assert!(entries_of(&env, &token) > 0);
    assert!(entries_of(&env, &vault) > 0);

    // The composition holds at this point: the vault really is holding the tokens.
    assert_eq!(TokenClient::new(&env, &token).balance(&vault), 400);
    assert_eq!(VaultClient::new(&env, &vault).held(), 400);
}
