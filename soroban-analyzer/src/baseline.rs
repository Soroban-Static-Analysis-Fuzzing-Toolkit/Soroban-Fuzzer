//! A baseline: the findings a team has already seen, written down so they stop gating CI.
//!
//! A static analyser pointed at a real contract for the first time is a wall of findings,
//! most of which predate the analyser and none of which are going to be fixed this
//! afternoon. A tool that fails the build on all of them is turned off; a tool that
//! reports them and fails only on what is *new* is adopted. That is what a baseline is:
//! the ratchet position, in a file a reviewer can read and a diff can show.
//!
//! # What identifies a finding
//!
//! A baseline entry matches a finding by **rule, file and message**. The line is recorded
//! because a reader wants to know where it was, and is deliberately not part of the
//! identity: a line-number identity would go stale the first time anybody inserted an
//! `use` above it, and a baseline that stops matching on unrelated edits is one that
//! fails CI for a reason nobody can see.
//!
//! The message is what makes the identity survive a move. It is also the part that
//! changes when a rename changes what the analyser has to say — and that is the intended
//! behaviour rather than a limitation: the baseline is a claim that these *occurrences*
//! were reviewed, so a change to what the occurrence is costs one more look. This is not
//! the same identity the SARIF fingerprints use, and the difference is deliberate: an
//! alert in a code-scanning view should follow the line it is about, while an exception
//! should follow the code.
//!
//! # Nothing is dropped quietly
//!
//! Entries that match nothing are counted and reported rather than ignored, by
//! [`Baseline::stale`]. A baseline that has drifted into describing code that no longer
//! exists is a baseline that is hiding less than its owner thinks, and the only moment
//! that is cheap to notice is the moment it happens.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// The baseline file format's version, bumped when a field changes meaning.
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

/// One finding a team has decided not to gate on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineEntry {
    /// The rule that reported it.
    pub rule: String,
    /// The file it was reported in, as the analyser saw the path.
    pub file: String,
    /// The line it was on when the baseline was written. Recorded for a reader, not
    /// used for matching.
    pub line: usize,
    /// The message, which is the part that identifies the occurrence.
    pub message: String,
}

impl BaselineEntry {
    /// The identity a finding and an entry share.
    fn identity(&self) -> String {
        identity(&self.rule, &self.file, &self.message)
    }
}

/// The identity of a finding: what a baseline entry has to agree on to match it.
///
/// NUL-separated rather than concatenated, so that a file named `a` with a message
/// starting `b` cannot collide with a file named `ab`.
fn identity(rule: &str, file: &str, message: &str) -> String {
    format!("{rule}\u{0}{file}\u{0}{message}")
}

/// A baseline file, as it is serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineFile {
    /// The schema version this file was written with.
    schema_version: u32,
    /// The tool and version that wrote it, so a stale baseline can be attributed.
    tool: BaselineTool,
    /// The entries, in the order they were written.
    findings: Vec<BaselineEntry>,
}

/// Which tool wrote a baseline.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineTool {
    /// Always [`crate::TOOL_NAME`]; checked on load.
    name: String,
    /// The version of the tool that wrote the file.
    version: String,
}

/// Just the version, so that a file written for a newer analyser is reported as exactly
/// that rather than as a pile of keys this build does not recognise.
#[derive(Debug, Deserialize)]
struct VersionProbe {
    /// The version the file claims to be written against.
    schema_version: u32,
}

/// The error to report for a baseline that would not parse.
///
/// A future file may legitimately carry keys this build has never heard of, and the
/// useful sentence about it is the version it was written for; for anything else the
/// underlying parse error, with its own line and column, is the useful sentence.
fn unreadable(text: &str, error: serde_json::Error) -> BaselineError {
    match serde_json::from_str::<VersionProbe>(text) {
        Ok(probe) if probe.schema_version != BASELINE_SCHEMA_VERSION => BaselineError(format!(
            "this baseline is schema_version {}, and this build writes and reads version \
             {BASELINE_SCHEMA_VERSION}; re-write it with `--write-baseline`",
            probe.schema_version
        )),
        _ => BaselineError(format!("not a readable baseline: {error}")),
    }
}

/// Why a baseline could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaselineError(String);

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BaselineError {}

/// The findings a run is excused from gating on.
#[derive(Clone, Debug, Default)]
pub struct Baseline {
    entries: Vec<BaselineEntry>,
}

impl Baseline {
    /// Records the findings of a run as a baseline.
    ///
    /// Duplicates are collapsed: two identical findings in one file produce one entry,
    /// and matching one of them excuses both. That is the honest reading of "this
    /// occurrence was reviewed", because the analyser cannot tell them apart either.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut entries = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for finding in findings {
            let entry = BaselineEntry {
                rule: finding.rule.clone(),
                file: finding.file.clone(),
                line: finding.location.start.line,
                message: finding.message.clone(),
            };
            if seen.insert(entry.identity()) {
                entries.push(entry);
            }
        }
        // Sorted for a stable file: a re-write after an unrelated code change should
        // produce a diff about the code, not about the order a walk happened to return.
        entries.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.rule.cmp(&right.rule))
                .then_with(|| left.message.cmp(&right.message))
        });
        Self { entries }
    }

    /// Parses a baseline file.
    ///
    /// A file written for a newer schema is rejected with the version named rather than
    /// reinterpreted under this one's assumptions, for the same reason the rule loader
    /// does it: a baseline that means something different from what its reader thinks is
    /// a way to hide findings without anybody deciding to.
    pub fn parse(text: &str) -> Result<Self, BaselineError> {
        let file: BaselineFile =
            serde_json::from_str(text).map_err(|error| unreadable(text, error))?;
        if file.schema_version != BASELINE_SCHEMA_VERSION {
            return Err(BaselineError(format!(
                "this baseline is schema_version {}, and this build writes and reads \
                 version {BASELINE_SCHEMA_VERSION}; re-write it with `--write-baseline`",
                file.schema_version
            )));
        }
        if file.tool.name != crate::TOOL_NAME {
            return Err(BaselineError(format!(
                "this baseline was written by `{}` rather than `{}`",
                file.tool.name,
                crate::TOOL_NAME
            )));
        }

        Ok(Self {
            entries: file.findings,
        })
    }

    /// Renders a baseline to be written to a file.
    pub fn to_json(&self) -> String {
        let document = BaselineFile {
            schema_version: BASELINE_SCHEMA_VERSION,
            tool: BaselineTool {
                name: crate::TOOL_NAME.to_owned(),
                version: crate::VERSION.to_owned(),
            },
            findings: self.entries.clone(),
        };
        // Pretty-printed on purpose: the file is committed, reviewed and diffed, and a
        // one-line document would make every re-write a single changed line.
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| {
            "{\"schema_version\": 1, \"tool\": {}, \"findings\": []}".to_owned()
        })
    }

    /// Whether this baseline excuses a finding.
    pub fn matches(&self, finding: &Finding) -> bool {
        let identity = identity(&finding.rule, &finding.file, &finding.message);
        self.entries
            .iter()
            .any(|entry| entry.identity() == identity)
    }

    /// How many entries match nothing in `findings`.
    ///
    /// The count, not the entries, because a run's output should say "the baseline has
    /// three entries that no longer match anything" without turning a terminal report
    /// into a file listing. The entries are in the file for anyone who wants them.
    pub fn stale(&self, findings: &[Finding]) -> usize {
        let identities = findings
            .iter()
            .map(|finding| identity(&finding.rule, &finding.file, &finding.message))
            .collect::<std::collections::BTreeSet<_>>();
        self.entries
            .iter()
            .filter(|entry| !identities.contains(&entry.identity()))
            .count()
    }

    /// How many findings this baseline records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the baseline records nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceFile;
    use crate::Analyzer;

    /// A rule, with the fields this module does not care about filled in.
    fn rule(id: &str) -> crate::rules::Rule {
        crate::rules::Rule {
            id: id.to_owned(),
            title: "A rule".to_owned(),
            severity: crate::Severity::High,
            rationale: "Why it is a bug.".to_owned(),
            remediation: "Fix it.".to_owned(),
            references: Vec::new(),
            triggers: String::new(),
            clean: String::new(),
            heuristic: false,
            file: format!("{id}.json"),
        }
    }

    /// A finding for `rule` at `line` in `file`, with `message`.
    fn finding(rule_id: &str, file: &str, line: usize, message: &str) -> Finding {
        let source = "fn f() {}\n".repeat(line + 1);
        let parsed = SourceFile::parse(file, source).expect("the fixture parses");
        let mut location = parsed.location_at(0);
        location.start.line = line;
        Finding::new(
            &rule(rule_id),
            &parsed.display_path(),
            parsed.line_text(line).to_owned(),
            location,
            message.to_owned(),
        )
    }

    #[test]
    fn a_baseline_matches_the_findings_it_was_written_from() {
        let findings = vec![
            finding("a-rule", "src/lib.rs", 3, "an occurrence"),
            finding("b-rule", "src/other.rs", 9, "another"),
        ];
        let baseline = Baseline::from_findings(&findings);
        assert_eq!(baseline.len(), 2);
        for finding in &findings {
            assert!(
                baseline.matches(finding),
                "a baseline must match what it recorded"
            );
        }
    }

    #[test]
    fn matching_survives_the_finding_moving_line() {
        // The whole reason the line is not part of the identity: inserting a `use` above
        // a finding must not resurrect it as a new one.
        let baseline = Baseline::from_findings(&[finding("a-rule", "src/lib.rs", 3, "same text")]);
        assert!(baseline.matches(&finding("a-rule", "src/lib.rs", 40, "same text")));
    }

    #[test]
    fn a_different_message_is_a_different_finding() {
        // A rename changes what the analyser says about an occurrence, and the baseline
        // is a claim about occurrences, so the changed one comes back for a look.
        let baseline = Baseline::from_findings(&[finding("a-rule", "src/lib.rs", 3, "old name")]);
        assert!(!baseline.matches(&finding("a-rule", "src/lib.rs", 3, "new name")));
        assert!(
            !baseline.matches(&finding("another-rule", "src/lib.rs", 3, "old name")),
            "the rule is part of the identity"
        );
        assert!(
            !baseline.matches(&finding("a-rule", "src/elsewhere.rs", 3, "old name")),
            "the file is part of the identity"
        );
    }

    #[test]
    fn the_file_round_trips() {
        let findings = vec![
            finding("a-rule", "src/lib.rs", 3, "one"),
            finding("a-rule", "src/lib.rs", 3, "one"),
            finding("b-rule", "src/z.rs", 1, "two"),
        ];
        let written = Baseline::from_findings(&findings).to_json();
        assert_eq!(
            Baseline::from_findings(&findings).len(),
            2,
            "identical findings collapse to one entry"
        );
        let read = Baseline::parse(&written).expect("what this build writes, it reads");
        assert_eq!(read.len(), 2);
        assert!(read.matches(&findings[0]));
        assert!(read.matches(&findings[2]));
    }

    #[test]
    fn a_newer_schema_is_refused_with_the_version_named() {
        let error = Baseline::parse(
            r#"{"schema_version": 99, "tool": {"name": "soroban-analyze", "version": "9"},
                "findings": []}"#,
        )
        .expect_err("a future baseline must not be reinterpreted");
        assert!(error.to_string().contains("99"), "{error}");
    }

    #[test]
    fn a_baseline_from_another_tool_is_refused() {
        let error = Baseline::parse(
            r#"{"schema_version": 1, "tool": {"name": "something-else", "version": "1"},
                "findings": []}"#,
        )
        .expect_err("it is not this tool's baseline");
        assert!(error.to_string().contains("something-else"), "{error}");
    }

    #[test]
    fn a_typo_in_an_entry_is_an_error_rather_than_a_silent_miss() {
        let error = Baseline::parse(
            r#"{"schema_version": 1, "tool": {"name": "soroban-analyze", "version": "0.1.0"},
                "findings": [{"rule": "a-rule", "file": "a.rs", "line": 1, "mesage": "typo"}]}"#,
        )
        .expect_err("an unknown key must not be ignored");
        assert!(error.to_string().contains("mesage"), "{error}");
    }

    #[test]
    fn entries_that_match_nothing_are_counted() {
        let baseline = Baseline::from_findings(&[
            finding("a-rule", "src/lib.rs", 3, "gone"),
            finding("a-rule", "src/lib.rs", 4, "kept"),
        ]);
        let current = vec![finding("a-rule", "src/lib.rs", 4, "kept")];
        assert_eq!(baseline.stale(&current), 1);
        assert_eq!(baseline.stale(&[]), 2);
    }

    #[test]
    fn a_baseline_from_the_real_analyzer_excuses_everything_it_recorded() {
        // The end-to-end shape: run the shipped detectors, record what they found, and
        // check the baseline excuses it. This is what `--write-baseline` does.
        let analyzer = Analyzer::embedded();
        let file = SourceFile::parse(
            "src/lib.rs",
            r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, to: Address, amount: i128) {
        env.storage().persistent().set(&Key::Balance(to), &amount);
    }
}
"#
            .to_owned(),
        )
        .expect("the fixture parses");

        let findings = analyzer.check_file(&file).findings;
        assert!(!findings.is_empty(), "the fixture must trigger a detector");
        let baseline = Baseline::from_findings(&findings);
        for finding in &findings {
            assert!(baseline.matches(finding));
        }
        assert_eq!(baseline.stale(&findings), 0);
    }
}
