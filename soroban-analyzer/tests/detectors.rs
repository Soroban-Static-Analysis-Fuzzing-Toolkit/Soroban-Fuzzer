//! What each detector does on cases the rules' own fixtures do not cover.
//!
//! `tests/rules.rs` proves every rule fires on its trigger and stays quiet on its clean
//! example. This file is the other half: the shapes that were argued about while the
//! detectors were written, pinned so that a later change to a word list or a traversal
//! has to fail a test rather than quietly change what is reported. Most of these are
//! *negative* cases — the value of a static analyser is as much in what it leaves alone,
//! because a rule that fires on correct code is one people learn to skip.

use soroban_analyzer::{Finding, SourceFile};

/// The findings a rule reports for a source fixture.
///
/// Only the named rule's findings are returned: the fixtures below are deliberately
/// minimal, so several rules may match the same snippet, and a test that asserted "exactly
/// one finding" across all of them would be asserting something about the other rules.
fn findings(rule: &str, source: &str) -> Vec<Finding> {
    let file = SourceFile::parse("fixture.rs", source.to_owned())
        .unwrap_or_else(|error| panic!("the fixture must parse: {error}\n\n{source}"));
    soroban_analyzer::Analyzer::embedded()
        .check_file(&file)
        .findings
        .into_iter()
        .filter(|finding| finding.rule == rule)
        .collect()
}

/// True when a rule reported anything for a fixture.
fn fires(rule: &str, source: &str) -> bool {
    !findings(rule, source).is_empty()
}

/// The suppressed findings a source fixture produced, for the named rule.
fn suppressed(rule: &str, source: &str) -> Vec<Finding> {
    let file = SourceFile::parse("fixture.rs", source.to_owned()).expect("the fixture must parse");
    soroban_analyzer::Analyzer::embedded()
        .check_file(&file)
        .suppressed
        .into_iter()
        .filter(|finding| finding.rule == rule)
        .collect()
}

const AUTH: &str = "soroban-missing-require-auth";
const ARITHMETIC: &str = "soroban-unchecked-arithmetic";
const DURABILITY: &str = "soroban-storage-durability";
const LOOP: &str = "soroban-unbounded-storage-loop";
const BUDGET: &str = "soroban-read-budget";

// ---------------------------------------------------------------- authorization

#[test]
fn an_unprotected_writer_is_reported_with_the_address_it_acts_for() {
    let hits = findings(
        AUTH,
        r#"
#[contractimpl]
impl Token {
    pub fn set_admin(env: Env, new_admin: Address) {
        env.storage().instance().set(&Key::Admin, &new_admin);
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    let message = &hits[0].message;
    assert!(message.contains("set_admin"), "{message}");
    assert!(message.contains("`new_admin`"), "{message}");
    assert_eq!(hits[0].location.start.line, 4, "pointing at the entrypoint");
}

#[test]
fn a_view_function_that_takes_an_address_is_not_reported() {
    assert!(
        !fires(
            AUTH,
            r#"
#[contractimpl]
impl Token {
    pub fn balance_of(env: Env, who: Address) -> i128 {
        env.storage().persistent().get(&Key::Balance(who)).unwrap_or(0)
    }
}
"#
        ),
        "reading is not a privileged effect, however many addresses it mentions"
    );
}

#[test]
fn a_constructor_is_never_reported() {
    assert!(!fires(
        AUTH,
        r#"
#[contractimpl]
impl Token {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&Key::Admin, &admin);
    }
}
"#
    ));
}

#[test]
fn a_private_method_is_not_an_entrypoint() {
    // The SDK's macro exports public methods only, so a private writer cannot be called
    // from outside and must not be reported here.
    assert!(!fires(
        AUTH,
        r#"
#[contractimpl]
impl Token {
    fn check(first: bool) {
        let _ = first;
    }
}
"#
    ));
}

#[test]
fn delegation_to_a_helper_in_the_same_file_is_followed() {
    let source = r#"
#[contractimpl]
impl Token {
    pub fn set_fee(env: Env, admin: Address, bps: u32) {
        guard(admin);
        env.storage().instance().set(&Key::Fee, &bps);
    }

    fn guard(who: Address) {
        who.require_auth();
    }
}
"#;
    // The method-call spelling too, since a helper in an impl block is written both ways.
    let via_method = source.replace("guard(admin);", "Self::guard(admin.clone());");
    for spelling in [source.to_owned(), via_method] {
        assert!(
            !fires(AUTH, &spelling),
            "an entrypoint that delegates to an authorizing helper is not unprotected"
        );
    }
}

#[test]
fn an_unprotected_value_movement_is_reported() {
    let hits = findings(
        AUTH,
        r#"
#[contractimpl]
impl Vault {
    pub fn payout(env: Env, to: Address, amount: i128) {
        TokenClient::new(&env, &env.current_contract_address()).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].message.contains("transfer"), "{}", hits[0].message);
}

#[test]
fn a_marker_suppresses_the_finding_and_it_is_still_counted() {
    let source = r#"
#[contractimpl]
impl Registry {
    // soroban-analyzer: allow(soroban-missing-require-auth)
    // Registration is permissionless by design: there is nothing to spend.
    pub fn register(env: Env, who: Address) {
        env.storage().persistent().set(&Key::Member(who), &true);
    }
}
"#;
    assert!(
        !fires(AUTH, source),
        "the marker sits directly above the entrypoint"
    );
    assert_eq!(
        suppressed(AUTH, source).len(),
        1,
        "a suppressed finding is counted rather than dropped"
    );
}

// ---------------------------------------------------------------- arithmetic

#[test]
fn one_finding_per_arithmetic_expression_tree() {
    // `balance + amount + fee` is one unchecked sum, not one per operator: the report
    // should show the expression to fix and not three overlapping highlights.
    let hits = findings(
        ARITHMETIC,
        r#"
#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, balance: i128, amount: i128, fee: i128) {
        let total = balance + amount + fee;
        env.storage().persistent().set(&Key::Total, &total);
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(
        hits[0].message.contains("balance + amount + fee"),
        "{}",
        hits[0].message
    );
}

#[test]
fn a_checked_sum_is_not_reported() {
    assert!(!fires(
        ARITHMETIC,
        r#"
#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, balance: i128, amount: i128) {
        let total = balance.checked_add(amount).unwrap();
        env.storage().persistent().set(&Key::Total, &total);
    }
}
"#
    ));
}

#[test]
fn arithmetic_on_something_that_is_not_an_amount_is_left_alone() {
    // The rule is a word list over identifier segments, and this is that boundary stated
    // as a test: `cursor` and `allowed` are not amounts.
    assert!(!fires(
        ARITHMETIC,
        r#"
#[contractimpl]
impl Counter {
    pub fn bump(env: Env, cursor: u32, allowed: u32) {
        let next = cursor + allowed;
        env.storage().instance().set(&Key::Cursor, &next);
    }
}
"#
    ));
}

#[test]
fn a_compound_assignment_on_an_amount_is_reported() {
    assert!(fires(
        ARITHMETIC,
        r#"
#[contractimpl]
impl Vault {
    pub fn accrue(env: Env, mut interest: i128) {
        interest += 1;
        env.storage().persistent().set(&Key::Interest, &interest);
    }
}
"#
    ));
}

// ---------------------------------------------------------------- durability

#[test]
fn a_balance_in_temporary_storage_is_reported() {
    let hits = findings(
        DURABILITY,
        r#"
#[contractimpl]
impl Token {
    pub fn set(env: Env) {
        env.storage().temporary().set(&DataKey::Balance, &1);
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].message.contains("temporary"), "{}", hits[0].message);
}

#[test]
fn per_account_data_in_instance_storage_is_reported() {
    let hits = findings(
        DURABILITY,
        r#"
#[contractimpl]
impl Token {
    pub fn set(env: Env) {
        env.storage().instance().set(&DataKey::BalanceOf, &1);
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].message.contains("instance"), "{}", hits[0].message);
}

#[test]
fn contract_wide_configuration_in_instance_storage_is_correct() {
    assert!(!fires(
        DURABILITY,
        r#"
#[contractimpl]
impl Token {
    pub fn set(env: Env) {
        env.storage().instance().set(&DataKey::FeeBps, &1);
    }
}
"#
    ));
}

#[test]
fn a_nonce_in_temporary_storage_is_correct() {
    assert!(
        !fires(
            DURABILITY,
            r#"
#[contractimpl]
impl Token {
    pub fn set(env: Env) {
        env.storage().temporary().set(&DataKey::Nonce, &1);
    }
}
"#
        ),
        "temporary storage is what a nonce is for"
    );
}

// ---------------------------------------------------------------- loops

#[test]
fn a_loop_bounded_by_a_parameter_is_reported() {
    let hits = findings(
        LOOP,
        r#"
#[contractimpl]
impl Registry {
    pub fn settle(env: Env, rounds: u32) {
        for i in 0..rounds {
            env.storage().persistent().get(&i);
        }
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(
        hits[0].message.contains("comes from the contract's input"),
        "{}",
        hits[0].message
    );
}

#[test]
fn a_loop_bounded_by_a_stored_count_says_so() {
    let hits = findings(
        LOOP,
        r#"
#[contractimpl]
impl Registry {
    pub fn settle(env: Env) {
        let members: u32 = env.storage().instance().get(&Key::Count).unwrap();
        for i in 0..members {
            env.storage().persistent().get(&i);
        }
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(
        hits[0].message.contains("read from storage"),
        "{}",
        hits[0].message
    );
}

#[test]
fn iterating_a_parameter_without_storage_in_the_body_is_not_reported() {
    assert!(
        !fires(
            LOOP,
            r#"
#[contractimpl]
impl Registry {
    pub fn count(env: Env, items: Vec<u32>) -> u32 {
        let mut total = 0u32;
        for item in items.iter() {
            total = total + item;
        }
        env.storage().instance().set(&Key::Count, &total);
        total
    }
}
"#
        ),
        "register arithmetic over an argument is bounded by nothing that matters"
    );
}

// ---------------------------------------------------------------- read budget

#[test]
fn a_nested_loop_over_the_ceiling_is_reported_with_its_count() {
    let hits = findings(
        BUDGET,
        r#"
#[contractimpl]
impl Batch {
    pub fn sweep(env: Env) {
        for i in 0..20 {
            for j in 0..20 {
                env.storage().persistent().get(&(i, j));
            }
        }
    }
}
"#,
    );
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].message.contains("400"), "{}", hits[0].message);
    assert!(hits[0].message.contains("20 × 20"), "{}", hits[0].message);
}

#[test]
fn a_loop_at_the_ceiling_is_not_reported() {
    assert!(
        !fires(
            BUDGET,
            r#"
#[contractimpl]
impl Batch {
    pub fn sweep(env: Env) {
        for i in 0..10 {
            for j in 0..20 {
                env.storage().persistent().get(&(i, j));
            }
        }
    }
}
"#
        ),
        "exactly at the ceiling is allowed: the check is `more than`"
    );
}

// ---------------------------------------------------------------- cross-cutting

#[test]
fn the_same_input_reports_the_same_findings_twice() {
    // A toolkit that reports differently on two runs of the same tree cannot be used in
    // CI, and the detector order comes from the filesystem, which is the thing most
    // likely to make it vary.
    let source = r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let balance = amount + amount;
        env.storage().temporary().set(&to, &balance);
        for i in 0..20 {
            for j in 0..20 {
                env.storage().persistent().get(&(i, j));
            }
        }
    }
}
"#;
    let first = SourceFile::parse("fixture.rs", source.to_owned()).expect("the fixture parses");
    let second = SourceFile::parse("fixture.rs", source.to_owned()).expect("the fixture parses");
    let analyzer = soroban_analyzer::Analyzer::embedded();
    assert_eq!(
        analyzer.check_file(&first).findings,
        analyzer.check_file(&second).findings
    );
    assert!(
        analyzer.check_file(&first).findings.len() >= 3,
        "this fixture is meant to exercise several rules at once"
    );
}

#[test]
fn every_finding_points_at_a_line_that_exists_in_the_file() {
    let source = r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let balance = amount + amount;
        env.storage().temporary().set(&to, &balance);
    }
}
"#;
    let file = SourceFile::parse("fixture.rs", source.to_owned()).expect("the fixture parses");
    let found = soroban_analyzer::Analyzer::embedded().check_file(&file);
    assert!(!found.findings.is_empty());
    for finding in &found.findings {
        let line = finding.location.start.line;
        assert!(line >= 1 && line <= file.line_count(), "{finding:?}");
        assert_eq!(
            file.line_text(line).trim(),
            finding.source_line,
            "the reported source line must be the one in the file"
        );
    }
}
