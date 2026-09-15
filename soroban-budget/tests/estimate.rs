//! The estimator's arithmetic, over modules whose every count is known.
//!
//! Each test assembles a module where the right answer is arithmetic rather than
//! opinion: three `nop`s and a call are four operations, a body with a loop is a lower
//! bound, and a body that calls a body that calls a host import attributes the import to
//! the entrypoint at the top.

mod common;

use common::{call, call_indirect, loop_forever, nops, ModuleBuilder};
use soroban_budget::{estimate, Format, Module, Unbounded};

/// Estimates an assembled module and returns the budget.
fn budget(build: &ModuleBuilder) -> soroban_budget::Budget {
    let bytes = build.build();
    let module = Module::parse(&bytes, "assembled.wasm").expect("the fixture parses");
    estimate(&module)
}

#[test]
fn a_body_of_n_operations_counts_n() {
    let mut build = ModuleBuilder::new();
    let index = build.function(&nops(3));
    build.export("three", index);

    let budget = budget(&build);
    let entry = budget.entry("three").expect("the export is estimated");
    assert_eq!(entry.instructions, 3, "{}", budget.render(Format::Text));
    assert!(entry.is_exact(), "no loops, so the count is exact");
    assert_eq!(entry.host_calls_total, 0);
    assert_eq!(entry.functions, 1);
}

#[test]
fn the_call_tree_is_summed_rather_than_the_function_body() {
    // `outer` calls `inner` twice. The right answer is 2 (its own two call sites) + 2x4,
    // because a function called twice is executed twice: a count of *distinct* code
    // would answer 6 and call that the cost.
    let mut build = ModuleBuilder::new();
    let inner = build.function(&nops(4));
    let mut outer_body = call(inner);
    outer_body.extend(call(inner));
    let outer = build.function(&outer_body);
    build.export("outer", outer);

    let budget = budget(&build);
    let entry = budget.entry("outer").expect("the export is estimated");
    assert_eq!(
        entry.instructions,
        2 + 2 * 4,
        "{}",
        budget.render(Format::Text)
    );
    assert_eq!(entry.functions, 2, "two functions are reached");
    assert!(entry.is_exact());
}

#[test]
fn a_reachable_host_import_is_attributed_to_the_entrypoint_that_reaches_it() {
    let mut build = ModuleBuilder::new();
    let host = build.import_host("l", "1");
    assert_eq!(host, 0, "the first import occupies function index 0");

    let leaf = build.function(&call(host));
    let root = build.function(&call(leaf));
    build.export("entry", root);

    let budget = budget(&build);
    let entry = budget.entry("entry").expect("the export is estimated");
    assert_eq!(
        entry.host_calls_total,
        1,
        "the host call is reached through one intermediate function: {}",
        budget.render(Format::Text)
    );
    assert_eq!(entry.host_calls.get("l.1"), Some(&1));
    assert_eq!(
        entry.instructions, 2,
        "the two call sites are counted; the host's own cost is not, because it is not in \
         this module"
    );
}

#[test]
fn a_loop_makes_the_count_a_lower_bound_and_says_why() {
    let mut build = ModuleBuilder::new();
    let index = build.function(&loop_forever());
    build.export("spins", index);

    let budget = budget(&build);
    let entry = budget.entry("spins").expect("the export is estimated");
    assert!(
        !entry.is_exact(),
        "a loop has no static trip count: {}",
        budget.render(Format::Text)
    );
    assert!(entry.unbounded.contains(&Unbounded::Loops));
    assert_eq!(entry.loops, 1);
    assert!(
        budget.render(Format::Text).contains("no upper bound"),
        "{}",
        budget.render(Format::Text)
    );
    assert_eq!(budget.unbounded_entries(), 1);
}

#[test]
fn an_indirect_call_makes_the_count_a_lower_bound_and_says_why() {
    let mut build = ModuleBuilder::new();
    let index = build.function(&call_indirect());
    build.export("dispatch", index);

    let budget = budget(&build);
    let entry = budget.entry("dispatch").expect("the export is estimated");
    assert!(!entry.is_exact());
    assert!(entry.unbounded.contains(&Unbounded::IndirectCalls));
    assert_eq!(entry.indirect_calls, 1);
}

#[test]
fn recursion_is_reported_rather_than_walked_forever() {
    // Two functions calling each other: the cycle is the point, and it is what a walk
    // with no memory of its own path would follow until the stack ran out.
    let mut build = ModuleBuilder::new();
    let first = build.function(&call(1));
    assert_eq!(first, 0, "the first defined function is index 0");
    let second = build.function(&call(0));
    build.export("mutual", second);

    let budget = budget(&build);
    let entry = budget.entry("mutual").expect("the export is estimated");
    assert!(
        entry.unbounded.contains(&Unbounded::Recursion),
        "a cycle in the call graph is not a finite tree: {}",
        budget.render(Format::Text)
    );
    assert!(budget.render(Format::Text).contains("recursion"));
}

#[test]
fn one_function_exported_twice_is_estimated_once() {
    let mut build = ModuleBuilder::new();
    let index = build.function(&nops(2));
    build.export("first", index);
    build.export("second", index);

    let budget = budget(&build);
    assert_eq!(
        budget.entries.len(),
        1,
        "summaries must not double-count one function under two names: {:?}",
        budget.render(Format::Text)
    );
}

#[test]
fn every_entrypoint_is_reported_even_when_nothing_is_exact() {
    let mut build = ModuleBuilder::new();
    let a = build.function(&loop_forever());
    let b = build.function(&loop_forever());
    build.export("a", a);
    build.export("b", b);

    let budget = budget(&build);
    assert_eq!(budget.entries.len(), 2);
    assert_eq!(budget.unbounded_entries(), 2);
    assert!(
        budget.largest_exact().is_none(),
        "there is no exact count to name"
    );
    assert!(budget.smallest().is_some());
}

#[test]
fn the_json_document_carries_the_disclaimer_and_the_reasons() {
    let mut build = ModuleBuilder::new();
    let index = build.function(&loop_forever());
    build.export("spins", index);

    let budget = budget(&build);
    let document = budget.to_value();
    assert_eq!(
        document["what_this_is"],
        soroban_budget::WHAT_THIS_IS,
        "the document says what the numbers are, in a field a consumer cannot miss"
    );
    let entry = &document["entrypoints"][0];
    assert_eq!(entry["name"], "spins");
    assert_eq!(entry["exact"], false);
    assert_eq!(entry["unbounded"][0], "loops");
    assert!(
        entry["unbounded_reasons"][0]["explanation"]
            .as_str()
            .expect("an explanation")
            .contains("trip count"),
        "{document}"
    );
    assert!(document["entrypoints"][0]["instructions"].is_number());
}
