//! Every public path of the runtime API, driven through a real fuzz run.
//!
//! Coverage measurement found this file's subject: `Runtime`, `CallResult` and
//! `StepOutcome` are what a *target* is written against, and their error branches were
//! the least-exercised part of the crate — the convenience methods that decide whether a
//! case fails, and the runtime helpers a target calls between invocations. A harness whose
//! convenience API is only exercised by the tests that happen to use it is a harness whose
//! convenience API is unverified.
//!
//! Two properties of the shape are deliberate:
//!
//! * **One path per case.** The action is drawn from the path list and each case gets its
//!   own `Env`, so a path is never affected by what an earlier path did to the ledger,
//!   the credentials or the contract's state.
//! * **The run always succeeds.** Each path's outcome is captured and returned as `Ok`,
//!   because the thing under test is what the runtime *reported*; a case that failed on
//!   the first violation would never reach the rest of the list.
//!
//! A credential in this harness authorizes exactly one invocation — `rt.authorize`
//! installs an `MockAuthInvoke` for the call that follows it — and this file is where that
//! is pinned, because the first version of it assumed otherwise and was wrong.

mod common;

use std::sync::{Arc, Mutex};

use common::{
    MissingAuthVault, MissingAuthVaultClient, SavingsVault, SavingsVaultClient, Vault, VaultClient,
};
use soroban_fuzzer::prelude::*;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env};

/// A balance large enough for a valid transfer, and small enough to be exceeded.
const FUNDED: i128 = 5_000;

/// How many cases to run: enough that every path is drawn many times over, and fixed by
/// the seed, so the test is deterministic.
const CASES: u32 = 256;

struct ApiWorld {
    vault: Address,
    buggy: Address,
    savings: Address,
    actors: [Address; 2],
}

/// One path through the runtime API.
#[derive(Clone, Copy, Debug)]
enum Act {
    /// A valid, precisely authorized transfer: `call`, `ok`, `unwrap_ok`, `expect_ok`.
    Transfer,
    /// A transfer the contract refuses: `is_failure`, `reason`, `expect_rejected`,
    /// `into_step`.
    Refused,
    /// `call_requiring_auth` on an entrypoint that does require authorization.
    AuthRequired,
    /// `call_requiring_auth` on an entrypoint that never demands it — the violation the
    /// helper exists to catch.
    AuthMissing,
    /// `call_requiring_auth` where the call does not reach its authorization at all.
    AuthDoomed,
    /// A declared contract error: `expect_contract_error` accepting it.
    ContractError,
    /// A trap where a contract error was expected: `expect_contract_error` refusing it.
    ErrorExpectedButTrapped,
    /// A success where a contract error was expected: refused as well.
    ErrorExpectedButSucceeded,
    /// A view: `is_ok`, `reason` on a success, `usage`, `storage`.
    View,
    /// `call_unchecked`, for a call whose cost is not the subject.
    Unchecked,
    /// `ledger().advance`, and the accessors and `Debug` impl around it.
    Wait,
    /// `ledger().close_ledger`, which ends the transaction.
    CloseLedger,
    /// `note`, which attaches a line to the current step's journal.
    Note,
    /// `env`, `world` and `step`, the accessors a target reaches for first.
    Accessors,
}

impl Act {
    /// Every path, in the order they are listed: the assertion below depends on this
    /// list, so a new path cannot be added without being checked.
    const ALL: [Act; 14] = [
        Act::Transfer,
        Act::Refused,
        Act::AuthRequired,
        Act::AuthMissing,
        Act::AuthDoomed,
        Act::ContractError,
        Act::ErrorExpectedButTrapped,
        Act::ErrorExpectedButSucceeded,
        Act::View,
        Act::Unchecked,
        Act::Wait,
        Act::CloseLedger,
        Act::Note,
        Act::Accessors,
    ];

    /// The path for a generated index.
    fn at(index: u8) -> Self {
        Act::ALL[usize::from(index) % Act::ALL.len()]
    }

    fn name(self) -> &'static str {
        match self {
            Act::Transfer => "transfer",
            Act::Refused => "refused",
            Act::AuthRequired => "auth-required",
            Act::AuthMissing => "auth-missing",
            Act::AuthDoomed => "auth-doomed",
            Act::ContractError => "contract-error",
            Act::ErrorExpectedButTrapped => "error-expected-but-trapped",
            Act::ErrorExpectedButSucceeded => "error-expected-but-succeeded",
            Act::View => "view",
            Act::Unchecked => "unchecked",
            Act::Wait => "wait",
            Act::CloseLedger => "close-ledger",
            Act::Note => "note",
            Act::Accessors => "accessors",
        }
    }
}

/// What the runtime said on one path, kept for the assertions afterwards.
type Log = Arc<Mutex<Vec<(String, String)>>>;

struct ApiTarget {
    log: Log,
}

impl ApiTarget {
    fn new() -> Self {
        Self {
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn recorded(&self) -> Vec<(String, String)> {
        self.log.lock().expect("the log mutex").clone()
    }

    fn record(&self, path: &str, description: String) {
        self.log
            .lock()
            .expect("the log mutex")
            .push((path.to_owned(), description));
    }
}

impl Target for ApiTarget {
    type State = ();
    type Action = Act;
    type World = ApiWorld;

    fn init_state(&self) -> BoxedStrategy<()> {
        constant(())
    }

    fn setup(&self, env: &Env, _initial: &()) -> ApiWorld {
        let actors = [Address::generate(env), Address::generate(env)];
        ApiWorld {
            vault: env.register(Vault, (actors[0].clone(), FUNDED)),
            buggy: env.register(MissingAuthVault, (actors[0].clone(), FUNDED)),
            savings: env.register(SavingsVault, (actors[0].clone(),)),
            actors,
        }
    }

    fn actions(&self, _state: &()) -> BoxedStrategy<Act> {
        (0u8..Act::ALL.len() as u8).prop_map(Act::at).boxed()
    }

    fn next_state(&self, _state: (), _action: &Act) {}

    fn execute(&self, rt: &mut Runtime<'_, ApiWorld>, action: &Act) -> StepOutcome {
        let from = rt.world().actors[0].clone();
        let to = rt.world().actors[1].clone();
        let vault = rt.world().vault.clone();
        let buggy = rt.world().buggy.clone();
        let savings = rt.world().savings.clone();
        let client = VaultClient::new(rt.env(), &vault);

        let description = match action {
            Act::Transfer => {
                rt.authorize(
                    &from,
                    &vault,
                    "transfer",
                    (from.clone(), to.clone(), 100i128),
                );
                let call = rt.call("transfer", || client.try_transfer(&from, &to, &100));
                let ok = call.is_ok();
                let value = match call.ok() {
                    Some(()) => "some(())".to_owned(),
                    None => "none".to_owned(),
                };

                // A credential authorizes exactly the invocation it was installed for...
                rt.authorize(&from, &vault, "transfer", (from.clone(), to.clone(), 1i128));
                let accepted = rt
                    .call("transfer", || client.try_transfer(&from, &to, &1))
                    .expect_ok();
                // ...so without a fresh one, the same call is refused, which is the
                // branch of `expect_ok` that reports it.
                let exhausted = rt
                    .call("transfer", || client.try_transfer(&from, &to, &1))
                    .expect_ok();

                format!(
                    "is_ok={ok} ok={value} fresh_credential={} no_credential={} view={}",
                    accepted.describe(),
                    exhausted.describe(),
                    rt.call("total", || client.try_total()).unwrap_ok(),
                )
            }
            Act::Refused => {
                // Far more than the balance, so the contract panics `insufficient
                // balance`. Each probe needs its own credential, because the first probe
                // consumes the one installed.
                let probe = || {
                    rt.authorize(
                        &from,
                        &vault,
                        "transfer",
                        (from.clone(), to.clone(), FUNDED * 2),
                    );
                    rt.call("transfer", || {
                        client.try_transfer(&from, &to, &(FUNDED * 2))
                    })
                };
                let first = probe();
                let failure = first.is_failure();
                let reason = first.reason().unwrap_or("none").to_owned();
                format!(
                    "is_failure={failure} reason={reason} expect_rejected={} into_step={}",
                    probe().expect_rejected().describe(),
                    probe().into_step().describe(),
                )
            }
            Act::AuthRequired => {
                let outcome =
                    rt.call_requiring_auth("mint", &from, || client.try_mint(&from, &to, &10));
                format!("{} ({})", outcome.describe(), outcome.is_violation())
            }
            Act::AuthMissing => {
                let buggy_client = MissingAuthVaultClient::new(rt.env(), &buggy);
                let outcome = rt
                    .call_requiring_auth("mint", &from, || buggy_client.try_mint(&from, &to, &10));
                format!("{} ({})", outcome.describe(), outcome.is_violation())
            }
            Act::AuthDoomed => {
                // A call that never reaches its authorization, because the balance check
                // refuses it first.
                let outcome = rt.call_requiring_auth("transfer", &from, || {
                    client.try_transfer(&from, &to, &(FUNDED * 2))
                });
                format!("{} ({})", outcome.describe(), outcome.is_violation())
            }
            Act::ContractError => {
                let savings_client = SavingsVaultClient::new(rt.env(), &savings);
                let probe = || {
                    rt.authorize(&from, &savings, "deposit", (from.clone(), 0i128));
                    rt.call("deposit", || savings_client.try_deposit(&from, &0))
                };
                format!(
                    "expect_contract_error={} expect_rejected={}",
                    probe().expect_contract_error().describe(),
                    probe().expect_rejected().describe(),
                )
            }
            Act::ErrorExpectedButTrapped => {
                // A deposit of `i128::MAX` overflows the contract's unchecked `+` and
                // traps, which is exactly what the strict variant must not accept.
                let savings_client = SavingsVaultClient::new(rt.env(), &savings);
                rt.authorize(&from, &savings, "deposit", (from.clone(), i128::MAX));
                let outcome = rt
                    .call("deposit", || savings_client.try_deposit(&from, &i128::MAX))
                    .expect_contract_error();
                format!("{} ({})", outcome.describe(), outcome.is_violation())
            }
            Act::ErrorExpectedButSucceeded => {
                let savings_client = SavingsVaultClient::new(rt.env(), &savings);
                rt.authorize(&from, &savings, "deposit", (from.clone(), 5i128));
                let outcome = rt
                    .call("deposit", || savings_client.try_deposit(&from, &5))
                    .expect_contract_error();
                format!("{} ({})", outcome.describe(), outcome.is_violation())
            }
            Act::View => {
                let balance = rt
                    .call("get_balance", || client.try_get_balance(&from))
                    .unwrap_ok();
                let usage = rt
                    .usage()
                    .map(|usage| format!("instructions={}", usage.instructions))
                    .unwrap_or_else(|| "no usage recorded".to_owned());
                format!(
                    "balance={balance} reason_is_none={} entries={} {usage}",
                    rt.call("get_balance", || client.try_get_balance(&from))
                        .reason()
                        .is_none(),
                    rt.storage().total_entries(),
                )
            }
            Act::Unchecked => {
                let outcome = rt.call_unchecked("total", || client.try_total());
                let described = outcome
                    .reason()
                    .map(|reason| format!("reason={reason}"))
                    .unwrap_or_else(|| "no reason".to_owned());
                format!("ok={} {described}", outcome.is_ok())
            }
            Act::Wait => {
                let before = (rt.ledger().sequence(), rt.ledger().timestamp());
                rt.ledger().advance(7);
                let after = (rt.ledger().sequence(), rt.ledger().timestamp());
                format!("sequence {before:?} -> {after:?} debug={:?}", rt.ledger())
            }
            Act::CloseLedger => {
                let before = rt.ledger().sequence();
                rt.ledger().close_ledger(3);
                format!("sequence {before} -> {}", rt.ledger().sequence())
            }
            Act::Note => {
                rt.note("a note from the API test");
                format!("step={} noted", rt.step())
            }
            Act::Accessors => format!(
                "step={} sequence={} world_vault={}",
                rt.step(),
                rt.env().ledger().sequence(),
                rt.world().vault == vault,
            ),
        };

        self.record(action.name(), description);
        // Deliberately `Ok`: the violation-producing paths exist to be observed, not to
        // fail this run.
        StepOutcome::ok()
    }

    fn describe(&self, action: &Act) -> String {
        action.name().to_owned()
    }
}

/// Every path runs, every time it runs it says the same thing, and that thing is what
/// the API documents.
#[test]
fn every_runtime_path_is_exercised_and_reports_itself() {
    let target = ApiTarget::new();
    let outcome = run(
        ApiTarget {
            log: Arc::clone(&target.log),
        },
        FuzzConfig::default()
            .cases(CASES)
            .actions(1, 1)
            .seed(0x5EED),
    );
    assert!(
        !outcome.is_failure(),
        "no path fails by design: {outcome:?}"
    );

    let recorded = target.recorded();
    assert_eq!(
        recorded.len(),
        CASES as usize,
        "one path per case, and every case executes its action"
    );

    // Every path ran, and a path is deterministic: the same draw in a fresh environment
    // reports the same thing, which is what makes comparing them meaningful.
    for action in Act::ALL {
        let mut seen = recorded
            .iter()
            .filter(|(path, _)| path == action.name())
            .map(|(_, description)| description.clone());
        let first = seen
            .next()
            .unwrap_or_else(|| panic!("path `{}` was never drawn in {CASES} cases", action.name()));
        for (index, description) in seen.enumerate() {
            assert_eq!(
                description,
                first,
                "path `{}` reported differently on repeat {}",
                action.name(),
                index + 2
            );
        }
    }

    let said = |path: &str| -> String {
        recorded
            .iter()
            .find(|(name, _)| name == path)
            .map(|(_, description)| description.clone())
            .unwrap_or_else(|| panic!("path `{path}` never ran"))
    };

    // A successful call reports success through its accessors, and a credential is
    // consumed by the one invocation it was installed for.
    let ok = said("transfer");
    assert!(ok.contains("is_ok=true"), "{ok}");
    assert!(ok.contains("ok=some(())"), "{ok}");
    assert!(ok.contains("fresh_credential=ok"), "{ok}");
    assert!(
        ok.contains("no_credential=violation: call was rejected but must succeed"),
        "{ok}"
    );
    assert!(
        ok.contains(&format!("view={FUNDED}")),
        "`unwrap_ok` yields the contract's return value: {ok}"
    );

    // A call the contract *panicked* on is reported as a rejection, not as a failure:
    // `is_failure` is false, both lenient conversions report it as rejected and the
    // reason is the SDK's own error. This is measured rather than assumed — an
    // arithmetic trap is classified differently, and `ErrorExpectedButTrapped` below
    // pins that.
    let refused = said("refused");
    assert!(refused.contains("is_failure=false"), "{refused}");
    assert!(
        refused.contains("reason=Error(Context, InvalidAction)"),
        "{refused}"
    );
    assert!(refused.contains("expect_rejected=rejected"), "{refused}");
    assert!(refused.contains("into_step=rejected"), "{refused}");

    // The two are byte-identical from the outside: a call refused because no credential
    // was installed, and a call that panicked inside the contract, report the same thing.
    // `Runtime::call_requiring_auth` exists because of this measurement, and pinning it
    // here means that if a future SDK restores the distinction, this fails and the
    // error-inspecting form becomes viable again.
    let uncredentialed = ok
        .split("no_credential=violation: call was rejected but must succeed: ")
        .nth(1)
        .and_then(|rest| rest.split(" view=").next())
        .expect("the uncredentialed call reports its reason")
        .trim();
    let panicked = refused
        .split("reason=")
        .nth(1)
        .and_then(|rest| rest.split(" expect_rejected").next())
        .expect("the refused call reports its reason")
        .trim();
    assert_eq!(
        uncredentialed, panicked,
        "a failed require_auth and a guest panic are indistinguishable, which is why \
         authorization is asserted positively rather than by inspecting the error"
    );

    // `call_requiring_auth` passes only when the demanded tree names the address.
    let required = said("auth-required");
    assert_eq!(required, "ok (false)", "{required}");

    let missing = said("auth-missing");
    assert!(
        missing.contains("never demanded authorization from"),
        "the missing-authorization path must name what was not demanded: {missing}"
    );
    assert!(missing.ends_with("(true)"), "{missing}");

    let doomed = said("auth-doomed");
    assert!(
        doomed.contains("had to succeed under recorded authorization"),
        "{doomed}"
    );
    assert!(doomed.ends_with("(true)"), "{doomed}");

    // A declared contract error is accepted, and a trap is not, which is the whole reason
    // the strict variant exists.
    let error = said("contract-error");
    assert!(error.contains("expect_contract_error=rejected"), "{error}");
    assert!(error.contains("expect_rejected=rejected"), "{error}");

    let trapped = said("error-expected-but-trapped");
    assert!(
        trapped.contains("expected a contract error but the call trapped"),
        "{trapped}"
    );
    assert!(trapped.ends_with("(true)"), "{trapped}");

    let succeeded = said("error-expected-but-succeeded");
    assert!(
        succeeded.contains("call succeeded but was expected to return a contract error"),
        "{succeeded}"
    );

    // The view path exercises the read-only accessors: no reason on success, metered usage
    // afterwards and a storage snapshot that is not empty.
    let view = said("view");
    assert!(view.contains("reason_is_none=true"), "{view}");
    assert!(view.contains("instructions="), "{view}");
    assert!(
        view.contains(&format!("balance={FUNDED}")),
        "the view returns the balance the fixture deployed: {view}"
    );
    assert!(
        !view.contains("entries=0 "),
        "a deployed contract has entries: {view}"
    );
    assert!(!view.contains("no usage recorded"), "{view}");

    // Ledger control reports the boundary it crossed, and the `Debug` impl renders the
    // ledger it ended at. A fresh environment starts at sequence 0, which is worth
    // stating here: a test that assumed 1 would be asserting a JSON-RPC convention
    // rather than the test host's.
    let wait = said("wait");
    assert!(wait.contains("sequence (0, 0) -> (7, 35)"), "{wait}");
    assert!(
        wait.contains("debug=LedgerCtl { sequence: 7, timestamp: 35 }"),
        "{wait}"
    );
    let close = said("close-ledger");
    assert!(close.contains("sequence 0 -> 3"), "{close}");

    let accessors = said("accessors");
    assert!(accessors.contains("step=0"), "{accessors}");
    assert!(accessors.contains("sequence=0"), "{accessors}");
    assert!(accessors.contains("world_vault=true"), "{accessors}");

    assert!(said("note").contains("noted"), "{}", said("note"));
    assert!(
        said("unchecked").contains("ok=true"),
        "{}",
        said("unchecked")
    );
}

/// `StepOutcome`'s constructors and descriptions are the vocabulary of a target.
#[test]
fn step_outcomes_describe_themselves() {
    assert_eq!(StepOutcome::ok().describe(), "ok");
    assert_eq!(
        StepOutcome::rejected("insufficient balance").describe(),
        "rejected: insufficient balance"
    );
    assert_eq!(
        StepOutcome::violation("supply changed").describe(),
        "violation: supply changed"
    );
    assert!(!StepOutcome::ok().is_violation());
    assert!(!StepOutcome::rejected("refused").is_violation());
    assert!(StepOutcome::violation("bad").is_violation());
}
