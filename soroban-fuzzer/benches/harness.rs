//! Micro-benchmarks for the harness itself.
//!
//! ```bash
//! cargo bench -p soroban-fuzzer
//! ```
//!
//! This is a hand-rolled binary (`harness = false`) rather than a benchmarking
//! framework. What needs to be known about this harness is how fast it can run cases
//! and what a storage snapshot costs as contract state grows, and both are plain
//! wall-clock measurements that do not justify a dependency.
//!
//! Numbers are printed, never asserted: a shared CI runner is far too noisy for a
//! threshold to mean anything, and a benchmark that fails the build on a slow
//! machine teaches people to ignore it.
//!
//! The contract used throughout is the vendored, unmodified `soroban-examples`
//! token, so the numbers describe work the harness actually has to do — registering
//! a real contract, calling a real standard-token entrypoint, and snapshotting real
//! token storage rather than a toy fixture.

use std::hint::black_box;
use std::time::{Duration, Instant};

use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::{Address as _, EnvTestConfig};
// `soroban_sdk::String` shadows `std::string::String`; alias it, or every
// `format!` in this file fails to type-check.
use soroban_sdk::{Address, Env, String as SdkString};
use soroban_token_contract::{Token, TokenClient};

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn format_ns(ns: f64) -> String {
    if ns >= 1e9 {
        format!("{:.3} s/op", ns / 1e9)
    } else if ns >= 1e6 {
        format!("{:.3} ms/op", ns / 1e6)
    } else if ns >= 1e3 {
        format!("{:.3} µs/op", ns / 1e3)
    } else {
        format!("{ns:.1} ns/op")
    }
}

fn rate(elapsed: Duration, iters: u64) -> String {
    let per_sec = iters as f64 / elapsed.as_secs_f64();
    if per_sec >= 1000.0 {
        format!("{per_sec:.0}/s")
    } else {
        format!("{per_sec:.1}/s")
    }
}

/// Runs `body` `iters` times and prints the mean.
///
/// `units` is how many operations of interest one iteration performs, so that the
/// rate column is always quoted in the units the label names: a `run:` iteration
/// executes many cases, and reporting runs per second there would understate the
/// throughput by the case count.
fn measure_units(
    label: &str,
    iters: u64,
    units: u64,
    note: impl Into<String>,
    mut body: impl FnMut(),
) {
    // One warm-up pass: the first `Env::new` in a process pays for lazily
    // initialised host globals, which would otherwise land entirely in the first
    // iteration and skew a short run.
    body();

    let started = Instant::now();
    for _ in 0..iters {
        body();
    }
    let elapsed = started.elapsed();

    let total = iters * units;
    let ns = elapsed.as_nanos() as f64 / total as f64;
    println!(
        "{:<46} {:>8} iters {:>14} {:>16}   {}",
        label,
        iters,
        format_ns(ns),
        rate(elapsed, total),
        note.into(),
    );
}

/// [`measure_units`] for a body that performs exactly one operation.
fn measure(label: &str, iters: u64, note: impl Into<String>, body: impl FnMut()) {
    measure_units(label, iters, 1, note, body);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A fresh environment, as the runner creates for every case.
fn fresh_env() -> Env {
    Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    })
}

/// Registers the vendored token in an existing environment.
fn register_token(env: &Env) -> Address {
    let admin = Address::generate(env);
    env.register(
        Token,
        (
            admin,
            7u32,
            SdkString::from_str(env, "Bench"),
            SdkString::from_str(env, "BNC"),
        ),
    )
}

/// Deploys the vendored token and returns `(env, contract)`.
fn deploy_token() -> (Env, Address) {
    let env = fresh_env();
    let contract = register_token(&env);
    (env, contract)
}

/// Deploys the token and mints a balance to `count` distinct addresses, so that
/// token storage holds `count` persistent entries.
fn deploy_token_with_balances(count: u32) -> (Env, Address) {
    let (env, contract) = deploy_token();
    env.mock_all_auths();
    let client = TokenClient::new(&env, &contract);
    for _ in 0..count {
        let holder = Address::generate(&env);
        client.mint(&holder, &10_000i128);
    }
    (env, contract)
}

/// Deploys the token under test alongside a second, unrelated contract that holds
/// `noise` entries of its own.
///
/// Scoping only pays off when there is something to leave out, and in a real
/// deployment there is: a composed system has several contracts in the same ledger,
/// and every entry any of them holds is an entry a full capture walks. The second
/// token stands in for that, and returning it separately keeps the subject
/// undistinguishable from the noise.
fn deploy_token_beside_noise(count: u32, noise: u32) -> (Env, Address, Address) {
    let env = fresh_env();
    let contract = register_token(&env);
    let other = register_token(&env);

    env.mock_all_auths();
    let subject = TokenClient::new(&env, &contract);
    for _ in 0..count {
        subject.mint(&Address::generate(&env), &10_000i128);
    }
    let nuisance = TokenClient::new(&env, &other);
    for _ in 0..noise {
        nuisance.mint(&Address::generate(&env), &10_000i128);
    }
    (env, contract, other)
}

// ---------------------------------------------------------------------------
// A target over the real token
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Model {
    transfers: u64,
}

#[derive(Clone, Debug)]
enum Act {
    Transfer { amount: i128 },
}

struct World {
    contract: Address,
    actors: [Address; 2],
}

struct TokenTarget {
    /// Invariants add per-step work; measuring with and without shows its cost.
    check_storage: bool,
    /// Whether to scope storage snapshots to the contract under test.
    scoped: bool,
}

impl Target for TokenTarget {
    type State = Model;
    type Action = Act;
    type World = World;

    fn init_state(&self) -> BoxedStrategy<Model> {
        constant(Model::default())
    }

    fn setup(&self, env: &Env, _initial: &Model) -> World {
        let actors = [Address::generate(env), Address::generate(env)];
        let contract = env.register(
            Token,
            (
                actors[0].clone(),
                7u32,
                SdkString::from_str(env, "Bench"),
                SdkString::from_str(env, "BNC"),
            ),
        );
        env.mock_all_auths();
        let client = TokenClient::new(env, &contract);
        client.mint(&actors[0], &1_000_000i128);
        World { contract, actors }
    }

    fn actions(&self, _state: &Model) -> BoxedStrategy<Act> {
        (1i128..=1_000)
            .prop_map(|amount| Act::Transfer { amount })
            .boxed()
    }

    fn next_state(&self, mut state: Model, _action: &Act) -> Model {
        state.transfers += 1;
        state
    }

    fn execute(&self, rt: &mut Runtime<'_, World>, action: &Act) -> StepOutcome {
        let Act::Transfer { amount } = action;
        let contract = rt.world().contract.clone();
        let from = rt.world().actors[0].clone();
        let to = rt.world().actors[1].clone();
        rt.authorize(
            &from,
            &contract,
            "transfer",
            (from.clone(), to.clone(), *amount),
        );
        let client = TokenClient::new(rt.env(), &contract);
        rt.call("transfer", || client.try_transfer(&from, &to, amount))
            .expect_ok()
    }

    /// Scoping the run to the contract under test, or not.
    fn tracked_contracts(&self, world: &World) -> Vec<Address> {
        if self.scoped {
            vec![world.contract.clone()]
        } else {
            Vec::new()
        }
    }

    fn invariants(&self) -> Vec<Box<dyn Invariant<Self>>> {
        if self.check_storage {
            vec![StorageGrowthBounded::total(4096).boxed()]
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Column headings, aligned with the row format used by [`measure_units`].
/// Kept as named items rather than inline literals so the two formats are visibly
/// paired and cannot drift apart without the alignment looking wrong.
const COLUMNS: [&str; 5] = ["benchmark", "iters", "mean", "rate", "note"];

fn main() {
    let rule = "-".repeat(100);
    println!();
    println!("soroban-fuzzer harness benchmarks");
    println!("{rule}");
    println!(
        "{:<46} {:>12} {:>16} {:>16}   {}",
        COLUMNS[0], COLUMNS[1], COLUMNS[2], COLUMNS[3], COLUMNS[4]
    );
    println!("{rule}");

    // --- Environment and deployment -------------------------------------------
    measure("env: create", 5_000, "per case", || {
        black_box(fresh_env());
    });

    measure("env: create + deploy real token", 1_000, "per case", || {
        black_box(deploy_token());
    });

    // --- Snapshot cost as state grows -----------------------------------------
    // `StorageSnapshot::capture` walks every ledger entry, so its cost is the part
    // of the harness most sensitive to contract state. These rows exist to expose
    // that scaling rather than to flatter it.
    for count in [1u32, 16, 64, 256] {
        let (env, _contract) = deploy_token_with_balances(count);
        measure(
            "storage: capture snapshot",
            200,
            format!("{count} persistent entries"),
            || {
                black_box(StorageSnapshot::capture(&env));
            },
        );
    }

    // The same two shapes side by side with another contract in the ledger, which is
    // the case scoping is for. Both rows walk the same environment, so the difference
    // between them is exactly the saving: a full capture pays for the other
    // contract's entries on every call, a scoped one does not.
    for noise in [64u32, 256] {
        let (env, contract, _other) = deploy_token_beside_noise(4, noise);
        let subject = std::slice::from_ref(&contract);
        measure(
            "storage: capture full (4 own + noise)",
            200,
            format!("{noise} entries owned by another contract"),
            || {
                black_box(StorageSnapshot::capture(&env));
            },
        );
        measure(
            "storage: capture scoped to the contract",
            200,
            format!("skipping that contract's {noise} entries"),
            || {
                black_box(StorageSnapshot::capture_scoped(&env, subject));
            },
        );
    }

    // --- Metering and a real entrypoint ---------------------------------------
    let (env, _contract) = deploy_token_with_balances(4);
    measure("metering: read last invocation usage", 20_000, "", || {
        black_box(ResourceUsage::capture(&env));
    });

    // The per-case floor: everything one fuzz case costs before the harness adds
    // anything — a fresh environment, contract registration, a funding call and the
    // action under test, with no snapshots, metering or invariant checks. Comparing
    // this against the `run:` rows below isolates the harness's own overhead.
    measure(
        "case floor: env + deploy + mint + transfer",
        1_000,
        "no harness involved",
        || {
            let (env, contract) = deploy_token();
            env.mock_all_auths();
            let client = TokenClient::new(&env, &contract);
            let a = Address::generate(&env);
            let b = Address::generate(&env);
            client.mint(&a, &1_000i128);
            client.transfer(&a, &b, &1i128);
        },
    );

    // --- End to end -----------------------------------------------------------
    // Every case builds a fresh environment, registers the contract, runs its
    // actions, checks invariants and tears the environment down. This is the number
    // that decides whether a CI budget is realistic.
    let report = |cases: u32, actions: usize, invariants: bool, scoped: bool| {
        let label = format!("run: {cases} cases x {actions} actions");
        let note = match (invariants, scoped) {
            (true, true) => "storage-growth invariant, scoped capture",
            (true, false) => "storage-growth invariant, full capture",
            (false, _) => "no invariants",
        };
        measure_units(&label, 3, cases as u64, note, || {
            let outcome = run(
                TokenTarget {
                    check_storage: invariants,
                    scoped,
                },
                FuzzConfig::default()
                    .cases(cases)
                    .actions(actions, actions)
                    .seed(0xB0A7),
            );
            assert!(
                !outcome.is_failure(),
                "benchmark target must not fail: {outcome:?}"
            );
        });
    };

    report(200, 1, false, false);
    report(200, 1, true, false);
    report(200, 1, true, true);
    report(50, 8, true, true);

    println!("{rule}");
    println!(
        "Rates are per operation as labelled. The `run:` rows are per *case* — each\n\
         case deploys a fresh contract and makes 1 or 8 calls — so the `cases/s`\n\
         column is what to divide a CI budget by. Timings are wall-clock on this\n\
         machine and will differ on yours."
    );
    println!();
}
