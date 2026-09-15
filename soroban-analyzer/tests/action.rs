//! The GitHub Action's script, run for real.
//!
//! A composite action is shell steps and a YAML file, and the only place it normally runs
//! is the one environment nobody can reproduce locally. So its body lives in
//! [`scripts/run-analysis.sh`](../../scripts/run-analysis.sh) and is exercised here with
//! fixtures: the report it writes, what it puts in the step summary and the step outputs,
//! and every exit status it can return.
//!
//! What these cannot check is the YAML around it — the input plumbing, and whether GitHub
//! accepts the file. What they can check is every decision the script makes, which is
//! where the bugs that matter to a pipeline live: whether a baseline that was not checked
//! out fails the run or silently reports everything as new, and whether a run asked not to
//! fail still reports what it found.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A contract with one unprotected privileged entrypoint.
const VULNERABLE: &str = r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&Key::Balance(to), &amount);
    }
}
"#;

/// A contract that authorizes before it acts.
const SAFE: &str = r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        env.storage().persistent().set(&Key::Balance(to), &amount);
    }
}
"#;

/// A scratch repository, cleaned up when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("soroban-analyzer-action-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the scratch directory can be made");
        Self(root)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().expect("a parent")).expect("the directory can be made");
        fs::write(&path, contents).expect("the file can be written");
        path
    }

    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).expect("the file was written")
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

/// The repository root, from this crate's manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives in the repository")
        .to_path_buf()
}

/// Runs the action's script the way the composite action does.
fn run_action(scratch: &Scratch, overrides: &[(&str, &str)]) -> Output {
    let script = repository_root().join("scripts/run-analysis.sh");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .current_dir(scratch.path())
        .env("SOROBAN_ANALYZER", env!("CARGO_BIN_EXE_soroban-analyze"))
        .env("ANALYZE_PATH", ".")
        .env_remove("BASELINE")
        .env_remove("GITHUB_OUTPUT")
        .env_remove("GITHUB_STEP_SUMMARY");

    for (key, value) in overrides {
        command.env(key, value);
    }

    command.output().expect("the script runs")
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

#[test]
fn a_vulnerable_tree_writes_a_sarif_and_fails_the_step() {
    let scratch = Scratch::new("vulnerable");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = run_action(&scratch, &[]);
    assert_eq!(
        exit_code(&output),
        1,
        "a finding at the default gate must fail the step: {}\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("::error::"),
        "the failure is an annotation, so it is visible in the pull request: {:?}",
        stderr(&output)
    );

    let document: serde_json::Value =
        serde_json::from_str(&scratch.read("soroban-analyzer.sarif")).expect("the report is SARIF");
    assert_eq!(document["version"], "2.1.0");
    let uri = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .expect("a uri");
    assert_eq!(
        uri, "src/lib.rs",
        "a code-scanning view resolves this against the repository root, so it must not \
         carry a `./` prefix"
    );
}

#[test]
fn a_clean_tree_passes_and_still_writes_a_report() {
    let scratch = Scratch::new("clean");
    scratch.write("src/lib.rs", SAFE);

    let output = run_action(&scratch, &[]);
    assert_eq!(exit_code(&output), 0, "{}", stderr(&output));
    let document: serde_json::Value =
        serde_json::from_str(&scratch.read("soroban-analyzer.sarif")).expect("the report is SARIF");
    assert!(
        document["runs"][0]["results"]
            .as_array()
            .expect("results")
            .is_empty(),
        "a clean run still produces a valid document, so the upload step has something to send"
    );
}

#[test]
fn findings_can_be_reported_without_failing_the_step() {
    // The adoption path: a team wants the annotations before it can afford the red build.
    let scratch = Scratch::new("adopt");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = run_action(&scratch, &[("FAIL_ON_FINDINGS", "false")]);
    assert_eq!(
        exit_code(&output),
        0,
        "the analyser found something and still exited 0: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("1 finding(s)"),
        "a run asked not to fail still says what it found: {:?}",
        stderr(&output)
    );
}

#[test]
fn a_baseline_excuses_what_it_records_and_admits_when_it_is_stale() {
    let scratch = Scratch::new("baseline");
    scratch.write("src/lib.rs", VULNERABLE);

    // First run: fails, and records nothing.
    assert_eq!(exit_code(&run_action(&scratch, &[])), 1);

    // Record it, the way the adoption command does, then the action passes with a baseline.
    let record = Command::new(env!("CARGO_BIN_EXE_soroban-analyze"))
        .args([
            "--baseline",
            ".soroban-baseline.json",
            "--write-baseline",
            ".",
        ])
        .current_dir(scratch.path())
        .output()
        .expect("the binary runs");
    assert_eq!(record.status.code(), Some(0));

    let adopted = run_action(
        &scratch,
        &[
            ("BASELINE", ".soroban-baseline.json"),
            ("FAIL_ON_FINDINGS", "false"),
        ],
    );
    assert_eq!(exit_code(&adopted), 0, "{}", stderr(&adopted));
    assert!(
        stderr(&adopted).contains("1 baselined"),
        "the run says what it excused rather than hiding it: {:?}",
        stderr(&adopted)
    );

    // And the code-scanning view is told too: the finding is in the document, marked the
    // way SARIF marks a result nobody has to act on. A tool that dropped it would leave a
    // reviewer unable to see the difference between an exception and a clean file.
    let document: serde_json::Value =
        serde_json::from_str(&scratch.read("soroban-analyzer.sarif")).expect("the report is SARIF");
    let results = document["runs"][0]["results"].as_array().expect("results");
    let suppressed = results
        .iter()
        .find(|result| result["suppressions"][0]["justification"].is_string())
        .expect("the baselined finding is still in the document, with its reason");
    assert_eq!(suppressed["suppressions"][0]["kind"], "external");
    assert!(
        suppressed["suppressions"][0]["justification"]
            .as_str()
            .expect("a justification")
            .contains("baseline"),
        "{suppressed}"
    );

    // A baseline that is not there is not a silent pass: every recorded finding would be
    // reported as new, so the run has to fail rather than pretend the tree is clean.
    let missing = run_action(&scratch, &[("BASELINE", "not-checked-out.json")]);
    assert_eq!(
        exit_code(&missing),
        2,
        "a baseline that does not exist is a question the tool could not answer: {}",
        stderr(&missing)
    );

    // And a stale entry is reported.
    scratch.write("src/lib.rs", SAFE);
    let stale = run_action(
        &scratch,
        &[
            ("BASELINE", ".soroban-baseline.json"),
            ("FAIL_ON_FINDINGS", "false"),
        ],
    );
    assert!(
        stderr(&stale).contains("match nothing"),
        "the run tells the caller its baseline has outlived its code: {:?}",
        stderr(&stale)
    );
}

#[test]
fn the_gate_and_the_path_are_what_the_inputs_said() {
    let scratch = Scratch::new("inputs");
    // Medium only: unchecked arithmetic, with authorization in place.
    scratch.write(
        "src/lib.rs",
        r#"
#[contractimpl]
impl Vault {
    pub fn accrue(env: Env, admin: Address, balance: i128, amount: i128) {
        admin.require_auth();
        let sum = balance + amount;
        env.storage().persistent().set(&Key::Total, &sum);
    }
}
"#,
    );

    // The default gate is `high`, so a medium finding passes...
    assert_eq!(exit_code(&run_action(&scratch, &[])), 0);

    // ...and lowering it is an input, not an edit to a file.
    let strict = run_action(&scratch, &[("SEVERITY", "medium")]);
    assert_eq!(exit_code(&strict), 1, "{}", stderr(&strict));

    // A path that is not there is refused before anything is analysed.
    let missing = run_action(&scratch, &[("ANALYZE_PATH", "no-such-directory")]);
    assert_eq!(exit_code(&missing), 2);
    assert!(
        stderr(&missing).contains("nothing at"),
        "{}",
        stderr(&missing)
    );

    // A format or a fail-on-findings the script cannot honour is refused, rather than
    // quietly treated as the default.
    for (key, value) in [("FORMAT", "yaml"), ("FAIL_ON_FINDINGS", "maybe")] {
        let refused = run_action(&scratch, &[(key, value)]);
        assert_eq!(exit_code(&refused), 2, "{key}={value}");
    }
}

#[test]
fn the_step_summary_and_the_step_outputs_are_written_for_a_reviewer() {
    let scratch = Scratch::new("summary");
    scratch.write("src/lib.rs", VULNERABLE);
    let summary = scratch.0.join("summary.md");
    let outputs = scratch.0.join("outputs.txt");
    fs::write(&summary, "").expect("the summary file can be made");

    let output = run_action(
        &scratch,
        &[
            ("FAIL_ON_FINDINGS", "false"),
            ("GITHUB_STEP_SUMMARY", summary.to_str().expect("a path")),
            ("GITHUB_OUTPUT", outputs.to_str().expect("a path")),
        ],
    );
    assert_eq!(exit_code(&output), 0, "{}", stderr(&output));

    let rendered = fs::read_to_string(&summary).expect("the summary was written");
    assert!(
        rendered.contains("1 finding(s)"),
        "the summary leads with the count a reviewer needs: {rendered}"
    );
    assert!(
        rendered.contains("soroban-missing-require-auth") && rendered.contains("src/lib.rs:4"),
        "and the table names the rule and the line: {rendered}"
    );
    assert!(rendered.contains("| Rule |"), "{rendered}");

    let recorded = fs::read_to_string(&outputs).expect("the outputs were written");
    assert!(recorded.contains("findings=1"), "{recorded}");
    assert!(
        recorded.contains("report=soroban-analyzer.sarif"),
        "{recorded}"
    );
    assert!(recorded.contains("exit-status=1"), "{recorded}");
}
