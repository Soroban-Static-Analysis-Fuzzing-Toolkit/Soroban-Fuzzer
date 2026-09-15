//! The binary, end to end: output formats, exit statuses, and the SARIF a CI job consumes.
//!
//! These run the real executable rather than the library, because the parts that are
//! easiest to get wrong are the ones the library never sees: what goes to stdout versus
//! stderr, what the exit status is, and whether the document a code-scanning upload is
//! given is well-formed. A pipeline that silently passes because the tool exited `0` on a
//! finding is worse than no pipeline at all, so the exit status is asserted on every case
//! where it can differ.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// The built binary, which cargo provides for integration tests.
fn analyze(arguments: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-analyze"))
        .args(arguments)
        .current_dir(cwd)
        .output()
        .expect("the binary runs")
}

/// A directory of fixtures, named after the test so parallel tests cannot collide.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("soroban-analyzer-cli-{name}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the scratch directory can be created");
        Self(root)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().expect("a parent")).expect("the directory can be made");
        fs::write(&path, contents).expect("the file can be written");
        path
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

/// A contract with one unprotected privileged entrypoint, and nothing else to report.
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

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

#[test]
fn a_clean_file_exits_zero_and_says_so() {
    let scratch = Scratch::new("clean");
    scratch.write("src/lib.rs", SAFE);

    let output = analyze(&["src"], scratch.path());
    assert_eq!(exit_code(&output), 0);
    assert!(
        stdout(&output).contains("no findings"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_vulnerable_file_exits_one_and_names_the_rule() {
    let scratch = Scratch::new("vulnerable");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = analyze(&["src"], scratch.path());
    assert_eq!(
        exit_code(&output),
        1,
        "a finding at the default gate fails the run"
    );
    let text = stdout(&output);
    assert!(text.contains("soroban-missing-require-auth"), "{text}");
    assert!(text.contains("src/lib.rs:4:"), "{text}");
    assert!(text.contains("fix:"), "a finding says what to do: {text}");
    assert!(
        output.stderr.is_empty(),
        "text output is the only thing on stdout, and nothing goes to stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn the_gate_can_be_lowered_and_raised() {
    let scratch = Scratch::new("gate");
    // Exactly one finding, at medium: unchecked arithmetic on an amount. The entrypoint
    // authorizes, so nothing above medium is reported and the gate alone decides.
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

    let default = analyze(&["src"], scratch.path());
    assert_eq!(
        exit_code(&default),
        0,
        "the default gate is high, so a medium finding does not fail a first run: {}",
        stdout(&default)
    );

    let strict = analyze(&["--severity", "medium", "src"], scratch.path());
    assert_eq!(exit_code(&strict), 1);
    assert!(
        stdout(&strict).contains("soroban-unchecked-arithmetic"),
        "{}",
        stdout(&strict)
    );
}

#[test]
fn json_output_is_a_document_a_program_can_read() {
    let scratch = Scratch::new("json");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = analyze(&["--format", "json", "src"], scratch.path());
    assert_eq!(exit_code(&output), 1);
    let document: Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");

    assert_eq!(document["tool"]["name"], "soroban-analyze");
    assert_eq!(document["summary"]["findings"], 1, "{document}");
    assert_eq!(document["summary"]["worst_severity"], "critical");
    assert_eq!(
        document["findings"][0]["rule"],
        "soroban-missing-require-auth"
    );
    assert_eq!(document["findings"][0]["severity"], "critical");
    assert_eq!(document["findings"][0]["file"], "src/lib.rs");
    assert_eq!(document["findings"][0]["start_line"], 4);
    assert!(document["rules"].as_array().expect("rules").len() >= 5);
}

#[test]
fn sarif_output_is_a_document_a_code_scanner_can_consume() {
    let scratch = Scratch::new("sarif");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = analyze(&["--format", "sarif", "src"], scratch.path());
    let document: Value = serde_json::from_str(&stdout(&output)).expect("stdout is JSON");

    assert_eq!(document["version"], "2.1.0");
    let run = &document["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "soroban-analyze");
    assert!(run["tool"]["driver"]["informationUri"].is_string());

    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), 1, "{document}");
    let result = &results[0];
    assert_eq!(result["ruleId"], "soroban-missing-require-auth");
    assert_eq!(result["level"], "error");
    let region = &result["locations"][0]["physicalLocation"]["region"];
    assert_eq!(region["startLine"], 4);
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/lib.rs"
    );

    // A result whose `ruleIndex` does not address its own rule is a finding reported
    // against the wrong metadata, which is how a code scanner shows the wrong fix.
    let index = result["ruleIndex"].as_u64().expect("a rule index") as usize;
    let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
    assert_eq!(rules[index]["id"], result["ruleId"]);

    // The rule table is present even though one rule fired, so a consumer can render the
    // rationale and the fix for every rule it is shown.
    assert_eq!(
        rules.len(),
        5,
        "every shipped rule is described: {document}"
    );
    let auth_rule = rules
        .iter()
        .find(|rule| rule["id"] == "soroban-missing-require-auth")
        .expect("the fired rule is described");
    assert!(auth_rule["fullDescription"]["text"]
        .as_str()
        .expect("a rationale")
        .contains("require_auth"));
    assert!(auth_rule["help"]["text"].is_string());
    assert!(auth_rule["defaultConfiguration"]["level"].is_string());
}

#[test]
fn machine_formats_keep_stdout_to_the_document_only() {
    // A CI job redirects stdout into a file and uploads it. A courtesy summary on stdout
    // would make the upload corrupt, so the summary goes to stderr instead.
    let scratch = Scratch::new("streams");
    scratch.write("src/lib.rs", VULNERABLE);

    let output = analyze(&["--format", "sarif", "src"], scratch.path());
    serde_json::from_str::<Value>(&stdout(&output)).expect("stdout is nothing but SARIF");
    assert!(
        !output.stderr.is_empty(),
        "the human-readable summary is on stderr so it is still visible"
    );
}

#[test]
fn a_file_that_cannot_be_parsed_fails_the_run() {
    let scratch = Scratch::new("unparseable");
    scratch.write("src/broken.rs", "pub fn oops( {\n");

    let output = analyze(&["src"], scratch.path());
    assert_eq!(
        exit_code(&output),
        1,
        "a run that could not read a file has not answered the question"
    );
    let text = stdout(&output);
    assert!(text.contains("could not be analysed"), "{text}");
    assert!(text.contains("broken.rs"), "{text}");
}

#[test]
fn a_missing_path_is_reported_rather_than_passing() {
    let scratch = Scratch::new("missing");
    let output = analyze(&["does-not-exist"], scratch.path());
    assert_eq!(exit_code(&output), 1);
    assert!(
        stdout(&output).contains("does-not-exist"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_suppressed_finding_does_not_fail_the_run_but_is_still_counted() {
    let scratch = Scratch::new("suppressed");
    scratch.write(
        "src/lib.rs",
        r#"
#[contractimpl]
impl Registry {
    // soroban-analyzer: allow(soroban-missing-require-auth)
    // Permissionless by design.
    pub fn register(env: Env, who: Address) {
        env.storage().persistent().set(&Key::Member(who), &true);
    }
}
"#,
    );

    let output = analyze(&["src"], scratch.path());
    let text = stdout(&output);
    assert_eq!(exit_code(&output), 0, "{text}");
    assert!(text.contains("suppressed by a marker"), "{text}");
}

#[test]
fn list_prints_every_rule() {
    let scratch = Scratch::new("list");
    let output = analyze(&["--list"], scratch.path());
    assert_eq!(exit_code(&output), 0);
    let text = stdout(&output);
    for rule in [
        "soroban-missing-require-auth",
        "soroban-storage-durability",
        "soroban-unbounded-storage-loop",
        "soroban-read-budget",
        "soroban-unchecked-arithmetic",
    ] {
        assert!(text.contains(rule), "`--list` must mention {rule}:\n{text}");
    }
    assert!(text.contains("5 rule(s)"), "{text}");
}

#[test]
fn explain_shows_a_rule_including_both_of_its_fixtures() {
    let scratch = Scratch::new("explain");
    let output = analyze(&["--explain", "soroban-read-budget"], scratch.path());
    assert_eq!(exit_code(&output), 0);
    let text = stdout(&output);
    assert!(text.contains("Storage reads exceed"), "{text}");
    assert!(text.contains("why it is a bug"), "{text}");
    assert!(text.contains("what to do instead"), "{text}");
    assert!(
        text.contains("source that must trigger it"),
        "the fixtures are shown, because they are the rule's specification: {text}"
    );
    assert!(text.contains("must not trigger it"), "{text}");
    assert!(text.contains("for i in 0..15"), "{text}");
}

#[test]
fn an_unknown_rule_is_a_usage_error() {
    let scratch = Scratch::new("explain-unknown");
    let output = analyze(&["--explain", "no-such-rule"], scratch.path());
    assert_eq!(
        exit_code(&output),
        2,
        "a query about a rule that does not exist"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no rule with id"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn bad_arguments_are_refused_rather_than_ignored() {
    let scratch = Scratch::new("bad-arguments");

    for arguments in [
        vec!["--format", "yaml"],
        vec!["--severity", "spicy"],
        vec!["--nonsense"],
        vec!["--format"],
    ] {
        let output = analyze(&arguments, scratch.path());
        assert_eq!(
            exit_code(&output),
            2,
            "{arguments:?} should be a usage error, but got: {}",
            stdout(&output)
        );
        assert!(
            !output.stderr.is_empty(),
            "{arguments:?} should explain itself on stderr"
        );
    }
}

#[test]
fn help_and_version_are_available_without_a_path() {
    let scratch = Scratch::new("help");
    let help = analyze(&["--help"], scratch.path());
    assert_eq!(exit_code(&help), 0);
    assert!(stdout(&help).contains("USAGE"), "{}", stdout(&help));
    assert!(stdout(&help).contains("EXIT STATUS"), "{}", stdout(&help));

    let version = analyze(&["--version"], scratch.path());
    assert_eq!(exit_code(&version), 0);
    assert!(
        stdout(&version).contains("soroban-analyze"),
        "{}",
        stdout(&version)
    );
}

#[test]
fn no_path_means_the_current_directory() {
    let scratch = Scratch::new("default-path");
    scratch.write("lib.rs", VULNERABLE);

    let output = analyze(&[], scratch.path());
    assert_eq!(exit_code(&output), 1);
    assert!(
        stdout(&output).contains("soroban-missing-require-auth"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_baseline_adopts_a_tree_that_already_has_findings() {
    // The adoption path, end to end: the first run fails, recording what it saw is what
    // makes it pass, and the recorded finding stays visible while no longer gating.
    let scratch = Scratch::new("baseline");
    scratch.write("src/lib.rs", VULNERABLE);

    assert_eq!(
        exit_code(&analyze(&["src"], scratch.path())),
        1,
        "the tree starts out failing"
    );

    let recorded = analyze(
        &[
            "--baseline",
            ".soroban-baseline.json",
            "--write-baseline",
            "src",
        ],
        scratch.path(),
    );
    assert_eq!(
        exit_code(&recorded),
        0,
        "recording a finding is the act of deciding not to fail on it yet: {}",
        stdout(&recorded)
    );
    assert!(
        scratch.path().join(".soroban-baseline.json").is_file(),
        "the baseline is written where it was asked for"
    );

    let adopted = analyze(
        &["--baseline", ".soroban-baseline.json", "src"],
        scratch.path(),
    );
    assert_eq!(exit_code(&adopted), 0, "{}", stdout(&adopted));
    assert!(
        stdout(&adopted).contains("the baseline records"),
        "a run still says what it is not failing on: {}",
        stdout(&adopted)
    );

    // And the ratchet holds: a finding written after the baseline is a new one.
    scratch.write("src/added_later.rs", VULNERABLE);
    let regression = analyze(
        &["--baseline", ".soroban-baseline.json", "src"],
        scratch.path(),
    );
    assert_eq!(
        exit_code(&regression),
        1,
        "a finding that is not in the baseline must fail the run: {}",
        stdout(&regression)
    );
    assert!(
        stdout(&regression).contains("added_later.rs"),
        "{}",
        stdout(&regression)
    );
}

#[test]
fn a_baseline_that_no_longer_matches_anything_says_so() {
    let scratch = Scratch::new("baseline-stale");
    scratch.write("src/lib.rs", VULNERABLE);
    analyze(
        &[
            "--baseline",
            ".soroban-baseline.json",
            "--write-baseline",
            "src",
        ],
        scratch.path(),
    );

    // The finding is fixed, so the exception has outlived its code.
    scratch.write("src/lib.rs", SAFE);
    let output = analyze(
        &["--baseline", ".soroban-baseline.json", "src"],
        scratch.path(),
    );
    assert_eq!(exit_code(&output), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("match nothing"),
        "a stale baseline must be reported rather than silently kept: {stderr:?}"
    );
    assert!(
        stderr.contains(".soroban-baseline.json"),
        "the message names the file to re-write: {stderr:?}"
    );
}

#[test]
fn a_baseline_for_another_schema_is_refused_with_a_usage_error() {
    let scratch = Scratch::new("baseline-schema");
    scratch.write("src/lib.rs", VULNERABLE);
    scratch.write("baseline.json", r#"{"schema_version": 9}"#);

    let output = analyze(&["--baseline", "baseline.json", "src"], scratch.path());
    assert_eq!(exit_code(&output), 2);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("9"),
        "the version it cannot read is named: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A contract whose only finding is medium: unchecked arithmetic on an amount.
const MEDIUM_ONLY: &str = r#"
#[contractimpl]
impl Vault {
    pub fn accrue(env: Env, admin: Address, balance: i128, amount: i128) {
        admin.require_auth();
        let sum = balance + amount;
        env.storage().persistent().set(&Key::Total, &sum);
    }
}
"#;

#[test]
fn a_configuration_supplies_defaults_and_the_command_line_beats_it() {
    let scratch = Scratch::new("config");
    scratch.write("src/lib.rs", MEDIUM_ONLY);
    scratch.write(
        ".soroban-analyzer.json",
        r#"{"schema_version": 1, "severity": "medium", "paths": ["src"]}"#,
    );

    // No path and no gate on the command line: both come from the file, so the medium
    // finding fails the run.
    let configured = analyze(&[], scratch.path());
    assert_eq!(
        exit_code(&configured),
        1,
        "the configuration's gate and path are used: {}",
        stdout(&configured)
    );
    assert!(
        stdout(&configured).contains("soroban-unchecked-arithmetic"),
        "{}",
        stdout(&configured)
    );

    // A one-off run with a different gate does not have to edit a repository file.
    let overridden = analyze(&["--severity", "high"], scratch.path());
    assert_eq!(
        exit_code(&overridden),
        0,
        "the command line wins over the configuration: {}",
        stdout(&overridden)
    );
}

#[test]
fn a_rule_disabled_by_configuration_is_counted_and_does_not_gate() {
    let scratch = Scratch::new("config-disabled");
    scratch.write("src/lib.rs", MEDIUM_ONLY);
    scratch.write(
        ".soroban-analyzer.json",
        r#"{"schema_version": 1, "paths": ["src"],
            "disabled_rules": ["soroban-unchecked-arithmetic"]}"#,
    );

    let output = analyze(&[], scratch.path());
    let text = stdout(&output);
    assert_eq!(exit_code(&output), 0, "{text}");
    assert!(
        text.contains("disabled by configuration (soroban-unchecked-arithmetic)"),
        "a disabled rule is visible in every run rather than a silent change to what \
         clean means: {text}"
    );
}

#[test]
fn a_configuration_that_cannot_be_understood_is_a_usage_error() {
    let scratch = Scratch::new("config-broken");
    scratch.write("src/lib.rs", SAFE);

    // A misspelled key, and a rule that does not exist. Both are refused rather than
    // ignored, because an ignored one is a CI job running at a gate nobody chose.
    for configuration in [
        r#"{"schema_version": 1, "severty": "medium"}"#,
        r#"{"schema_version": 1, "disabled_rules": ["soroban-imagined-rule"]}"#,
        r#"{"schema_version": 1, "format": "yaml"}"#,
        r#"not json at all"#,
    ] {
        scratch.write(".soroban-analyzer.json", configuration);
        let output = analyze(&["src"], scratch.path());
        assert_eq!(exit_code(&output), 2, "{configuration}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(".soroban-analyzer.json"),
            "the failure names the file: {stderr:?}"
        );
    }
}

#[test]
fn a_configuration_named_explicitly_is_used_instead_of_a_discovered_one() {
    let scratch = Scratch::new("config-explicit");
    scratch.write("src/lib.rs", MEDIUM_ONLY);
    scratch.write(
        ".soroban-analyzer.json",
        r#"{"schema_version": 1, "severity": "critical"}"#,
    );
    scratch.write(
        "strict.json",
        r#"{"schema_version": 1, "severity": "medium"}"#,
    );

    assert_eq!(
        exit_code(&analyze(&["src"], scratch.path())),
        0,
        "the discovered file's critical gate passes a medium finding"
    );
    assert_eq!(
        exit_code(&analyze(
            &["--config", "strict.json", "src"],
            scratch.path()
        )),
        1,
        "`--config` is how a file elsewhere is used"
    );
}

#[test]
fn jobs_is_validated_and_does_not_change_the_output() {
    let scratch = Scratch::new("jobs");
    for name in ["a", "b", "c", "d", "e"] {
        scratch.write(&format!("src/{name}.rs"), VULNERABLE);
    }

    for arguments in [vec!["--jobs", "0"], vec!["--jobs", "nope"]] {
        assert_eq!(
            exit_code(&analyze(&arguments, scratch.path())),
            2,
            "{arguments:?} is not a thread count"
        );
    }

    let single = analyze(&["--format", "sarif", "--jobs", "1", "src"], scratch.path());
    let parallel = analyze(&["--format", "sarif", "--jobs", "8", "src"], scratch.path());
    assert_eq!(exit_code(&single), 1);
    assert_eq!(
        stdout(&single),
        stdout(&parallel),
        "a run is a function of the tree, not of how many threads read it"
    );
    assert!(
        stdout(&single).contains("src/e.rs"),
        "every file is analysed: {}",
        stdout(&single)
    );
}

#[test]
fn the_sarif_document_is_stable_across_runs() {
    // A code-scanning upload that changes between identical runs produces a new alert for
    // every push. The only thing that may differ between two runs is nothing.
    let scratch = Scratch::new("stable");
    scratch.write("src/a.rs", VULNERABLE);
    scratch.write("src/b.rs", VULNERABLE);

    let first = analyze(&["--format", "sarif", "src"], scratch.path());
    let second = analyze(&["--format", "sarif", "src"], scratch.path());
    assert_eq!(stdout(&first), stdout(&second));
}
