//! The estimator, run on a contract it did not design.
//!
//! `third-party/soroban-token-example` is `stellar/soroban-examples`' standard token,
//! vendored byte-for-byte and re-checked against its pinned revision by
//! `third-party/verify.sh`. This test compiles it for `wasm32v1-none` — the target the
//! Soroban SDK supports — and estimates the artefact.
//!
//! The other tests in this crate check the arithmetic against modules whose counts are
//! known. These check the *reading*: whether the export names come out as the contract's
//! interface, whether the host imports are attributed at all, and whether an entrypoint
//! that does more work measures larger than one that does less. A parser that only ever
//! sees hand-assembled modules is a parser that agrees with its author.

mod common;

use common::compiled_token;
use soroban_budget::{estimate, Format, Module};

#[test]
fn the_standard_token_contract_is_estimated() {
    let Some(path) = compiled_token() else {
        return;
    };

    let module = Module::load(&path).expect("the compiled artefact parses");
    let budget = estimate(&module);

    // The interface the contract exports, as `soroban-token-sdk` defines it. If the
    // reading is wrong in any structural way, one of these names is missing or has no
    // body behind it.
    for entrypoint in [
        "__constructor",
        "allowance",
        "approve",
        "balance",
        "burn",
        "burn_from",
        "decimals",
        "mint",
        "set_admin",
        "symbol",
        "transfer",
        "transfer_from",
    ] {
        let entry = budget
            .entry(entrypoint)
            .unwrap_or_else(|| panic!("`{entrypoint}` is exported by the contract: {budget:#?}"));
        assert!(
            entry.instructions > 0,
            "`{entrypoint}` must have a body to count"
        );
        assert!(
            entry.host_calls_total > 0,
            "every token entrypoint talks to the host: {entry:#?}"
        );
    }

    // Memory and the table are exported too, and neither is a function this crate can
    // estimate. A tool that counted them as entrypoints with zero cost would be reporting
    // a number for something it did not read.
    assert!(
        budget.other_exports.contains(&"memory".to_owned()),
        "{:?}",
        budget.other_exports
    );
    assert!(
        !budget.entry("memory").is_some(),
        "a memory export is not an entrypoint"
    );

    // Size ordering is the weakest claim that must still hold: `transfer_from` checks an
    // allowance, moves a balance and extends the TTLs of both, so its static call tree is
    // strictly larger than a metadata getter's.
    let transfer_from = budget.entry("transfer_from").expect("it is exported");
    let decimals = budget.entry("decimals").expect("it is exported");
    assert!(
        transfer_from.instructions > decimals.instructions,
        "transfer_from ({}) should measure larger than decimals ({}):\n{}",
        transfer_from.instructions,
        decimals.instructions,
        budget.render(Format::Text)
    );

    // The metadata getters are leaf-shaped enough to be bounded exactly; if the reader
    // reported every entrypoint as unbounded, the numbers above would mean nothing.
    for getter in ["decimals", "name", "symbol"] {
        let entry = budget.entry(getter).expect("it is exported");
        assert!(
            entry.is_exact(),
            "`{getter}` reads instance metadata and does not loop: {entry:#?}"
        );
    }

    // A lower bound is reported as such, and the two categories partition the exports.
    let exact = budget
        .entries
        .iter()
        .filter(|entry| entry.is_exact())
        .count();
    assert_eq!(exact + budget.unbounded_entries(), budget.entries.len());

    // The report is the deliverable: it must render, and it must say what it is.
    let text = budget.render(Format::Text);
    assert!(text.contains(soroban_budget::WHAT_THIS_IS), "{text}");
    assert!(text.contains("import(s)"), "{text}");
    assert!(
        budget.to_value()["summary"]["exported_functions"].is_number(),
        "the JSON form carries the summary"
    );
}

#[test]
fn the_same_artefact_estimates_the_same_way_twice() {
    // A report that changes between two runs of the same file cannot be diffed, which is
    // the only thing most teams will do with it.
    let Some(path) = compiled_token() else {
        return;
    };

    let first = estimate(&Module::load(&path).expect("it parses"));
    let second = estimate(&Module::load(&path).expect("it parses"));
    assert_eq!(
        first.render(Format::Text),
        second.render(Format::Text),
        "two runs over one artefact must produce one report"
    );
}
