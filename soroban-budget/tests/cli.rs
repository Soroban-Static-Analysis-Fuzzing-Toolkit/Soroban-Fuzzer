//! The binary, end to end: what goes to stdout, and what the exit status says.
//!
//! These assert the two things a pipeline depends on and a unit test cannot see: that a
//! machine format is the *only* thing on stdout, so a redirect produces a document, and
//! that each gate's exit status is what the help text promises. The gates are the part
//! that fails somebody's build, which is why both directions of each are tested — one
//! that must fire, and one that must not.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{call, loop_forever, nops, ModuleBuilder};

/// Runs the estimator with `arguments` from a scratch directory.
fn budget(arguments: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-budget"))
        .args(arguments)
        .current_dir(cwd)
        .output()
        .expect("the binary runs")
}

/// A scratch directory that cleans up after itself.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("soroban-budget-cli-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the scratch directory can be made");
        Self(root)
    }

    /// Writes an assembled module and returns its file name.
    fn module(&self, name: &str, build: &ModuleBuilder) -> String {
        let path = self.0.join(name);
        fs::write(&path, build.build()).expect("the module can be written");
        name.to_owned()
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

/// A module with one exact entrypoint of `operations` operations.
fn exact_module(operations: usize) -> ModuleBuilder {
    let mut build = ModuleBuilder::new();
    let index = build.function(&nops(operations));
    build.export("work", index);
    build
}

/// A module with one entrypoint whose cost cannot be bounded.
fn unbounded_module() -> ModuleBuilder {
    let mut build = ModuleBuilder::new();
    let index = build.function(&loop_forever());
    build.export("spins", index);
    build
}

#[test]
fn a_module_is_estimated_and_the_report_says_what_the_numbers_are() {
    let scratch = Scratch::new("text");
    let name = scratch.module("exact.wasm", &exact_module(7));

    let output = budget(&[&name], scratch.path());
    assert_eq!(exit_code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("work"), "{text}");
    assert!(text.contains("7 instructions"), "{text}");
    assert!(text.contains("exact"), "{text}");
    assert!(
        text.contains("not a CPU prediction"),
        "the report must say what its numbers are, where a reader will see it: {text}"
    );
    assert!(
        output.stderr.is_empty(),
        "text output needs no stderr summary: {:?}",
        stderr(&output)
    );
}

#[test]
fn a_machine_format_leaves_stdout_to_the_document() {
    let scratch = Scratch::new("json");
    let name = scratch.module("exact.wasm", &exact_module(7));

    let output = budget(&["--format", "json", &name], scratch.path());
    let document: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("stdout is nothing but the document");
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["entrypoints"][0]["name"], "work");
    assert_eq!(document["entrypoints"][0]["exact"], true);
    assert!(document["what_this_is"].is_string());
    assert!(
        !stderr(&output).is_empty(),
        "the human-readable summary goes to stderr so it is still visible"
    );
}

#[test]
fn the_gates_fire_when_they_should_and_only_then() {
    let scratch = Scratch::new("gates");
    let exact = scratch.module("exact.wasm", &exact_module(7));
    let unbounded = scratch.module("unbounded.wasm", &unbounded_module());

    // Over the instruction gate: fired, and it names what crossed it.
    let over = budget(&["--fail-over", "5", &exact], scratch.path());
    assert_eq!(exit_code(&over), 1, "{}", stderr(&over));
    assert!(stderr(&over).contains("work"), "{}", stderr(&over));
    assert!(stderr(&over).contains("--fail-over 5"), "{}", stderr(&over));

    // Under it: not fired. A gate that always fires is a gate people turn off.
    let under = budget(&["--fail-over", "100", &exact], scratch.path());
    assert_eq!(exit_code(&under), 0, "{}", stderr(&under));

    // A lower bound is never compared against the instruction gate, because "at least N"
    // above the threshold proves nothing about the count and "at least N" below it proves
    // nothing either.
    let lower_bound = budget(&["--fail-over", "5", &unbounded], scratch.path());
    assert_eq!(
        exit_code(&lower_bound),
        0,
        "a lower bound must not be compared to an instruction gate: {}",
        stderr(&lower_bound)
    );

    // The unbounded gate: fired on the loop, not on the exact module, and it says why.
    let failing = budget(&["--fail-unbounded", &unbounded], scratch.path());
    assert_eq!(exit_code(&failing), 1);
    assert!(stderr(&failing).contains("loops"), "{}", stderr(&failing));

    let passing = budget(&["--fail-unbounded", &exact], scratch.path());
    assert_eq!(exit_code(&passing), 0, "{}", stderr(&passing));
}

#[test]
fn a_gate_that_cannot_be_asked_is_a_usage_error_rather_than_a_pass() {
    let scratch = Scratch::new("usage");
    let name = scratch.module("exact.wasm", &exact_module(1));

    for arguments in [
        vec!["--fail-over", "nope", &name],
        vec!["--fail-over"],
        vec!["--nonsense", &name],
        vec!["--format", "sarif", &name],
        vec![&name, &name],
        vec![],
    ] {
        let output = budget(&arguments, scratch.path());
        assert_eq!(
            exit_code(&output),
            2,
            "{arguments:?} should be a usage error, got: {}",
            stdout(&output)
        );
    }
}

#[test]
fn a_file_that_is_not_a_module_is_an_error_rather_than_an_empty_report() {
    let scratch = Scratch::new("not-a-module");
    fs::write(scratch.path().join("notes.txt"), "this is not Wasm\n").expect("it can be written");

    let output = budget(&["notes.txt"], scratch.path());
    assert_eq!(
        exit_code(&output),
        2,
        "an unreadable artefact is a question that could not be asked"
    );
    assert!(stderr(&output).contains("notes.txt"), "{}", stderr(&output));
}

#[test]
fn an_entry_that_is_not_exported_is_refused_rather_than_reported_as_zero() {
    let scratch = Scratch::new("unknown-entry");
    let name = scratch.module("exact.wasm", &exact_module(3));

    let output = budget(&["--entry", "no_such_entry", &name], scratch.path());
    assert_eq!(exit_code(&output), 2);
    assert!(
        stderr(&output).contains("no_such_entry"),
        "{}",
        stderr(&output)
    );

    // And the entry filter keeps the ones it was given.
    let filtered = budget(&["--entry", "work", &name], scratch.path());
    assert_eq!(exit_code(&filtered), 0);
    assert!(stdout(&filtered).contains("work"));
}

#[test]
fn a_call_tree_is_reported_for_the_entrypoint_that_reaches_it() {
    // The end-to-end shape of the arithmetic test, through the binary: what the entrypoint
    // reaches is what it is charged for.
    let scratch = Scratch::new("call-tree");
    let mut build = ModuleBuilder::new();
    let leaf = build.function(&nops(10));
    let root = build.function(&call(leaf));
    build.export("root", root);
    let name = scratch.module("tree.wasm", &build);

    let output = budget(&[&name], scratch.path());
    let text = stdout(&output);
    assert!(text.contains("11 instructions"), "{text}");
    assert!(text.contains("2 function(s) reached"), "{text}");
}

#[test]
fn help_and_version_need_no_module() {
    let scratch = Scratch::new("help");

    let help = budget(&["--help"], scratch.path());
    assert_eq!(exit_code(&help), 0);
    assert!(stdout(&help).contains("EXIT STATUS"), "{}", stdout(&help));

    let version = budget(&["--version"], scratch.path());
    assert_eq!(exit_code(&version), 0);
    assert!(stdout(&version).contains("soroban-budget"));
}
