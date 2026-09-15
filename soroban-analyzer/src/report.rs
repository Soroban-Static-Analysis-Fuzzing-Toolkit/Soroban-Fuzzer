//! Rendering findings: for a human, for a machine, and for a pull request.
//!
//! Three formats, and the reason for each is different:
//!
//! * [`Format::Text`] — what someone runs by hand. Grouped by file, worst first, with
//!   the offending line shown so the finding can be judged without opening the file.
//! * [`Format::Json`] — for another tool. A stable, documented shape with the counts
//!   included, so a caller never has to recount.
//! * [`Format::Sarif`] — for GitHub's code-scanning view. Findings land on the diff
//!   lines they are about, which is the difference between an analyser being read and
//!   being scrolled past.
//!
//! Whichever format is used, the exit status is decided here too, from the same
//! severities: [`Report::exit_code`]. A tool whose output and status disagree is one
//! that gets wired into CI incorrectly exactly once.

use core::fmt;
use core::str::FromStr;

use serde_json::{json, Value};

use crate::baseline::Baseline;
use crate::finding::Finding;
use crate::rules::RuleSet;
use crate::severity::Severity;

/// How a report is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable, grouped by file.
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
    /// SARIF 2.1.0, for code scanning.
    Sarif,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "human" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            other => Err(format!(
                "unknown format `{other}`; expected one of: text, json, sarif"
            )),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Sarif => "sarif",
        })
    }
}

/// The SARIF version this emits.
///
/// Pinned rather than configurable: a consumer's schema support is tied to the version,
/// so the version is part of the contract with the consumer, not a rendering choice.
pub const SARIF_VERSION: &str = "2.1.0";

/// The schema of the JSON output, bumped when a field changes meaning.
pub const JSON_SCHEMA_VERSION: u32 = 1;

/// The 200 ledger-entry read ceiling a transaction is bounded by, as a rule-of-thumb
/// figure the read-budget rule is stated against.
///
/// Kept here rather than duplicated in the rule and the detector so the two cannot
/// drift apart in a way that makes the tool's own documentation wrong.
pub const ONE_PASS_READ_CEILING_NOTE: &str =
    "a single invocation may read at most 200 ledger entries";

/// One list of findings as it is rendered into SARIF, and why they were excused.
///
/// Gating findings have no suppression; every other list carries the SARIF mechanism for
/// the decision that excused it. A struct rather than a tuple because the three fields
/// have three different meanings and a tuple of three would have to be read twice.
struct SarifGroup<'a> {
    findings: &'a [Finding],
    suppression: Option<(&'static str, &'static str)>,
}

impl<'a> SarifGroup<'a> {
    /// The findings that gate.
    fn gating(findings: &'a [Finding]) -> Self {
        Self {
            findings,
            suppression: None,
        }
    }

    /// Findings excused by `kind`, with `justification` saying why.
    fn excused(findings: &'a [Finding], kind: &'static str, justification: &'static str) -> Self {
        Self {
            findings,
            suppression: Some((kind, justification)),
        }
    }
}

/// Everything a run produced.
///
/// The findings are in four lists rather than one, because the difference between them
/// is the difference between a build that fails and one that does not, and a report that
/// flattened them would be a report whose exit status nobody could predict. In every
/// case the excused findings are *reported* rather than dropped: a mechanism that hides
/// its own effects is one people stop trusting.
///
/// | List | Means | Gates? |
/// | --- | --- | --- |
/// | [`Report::findings`] | Nobody has excused it | Yes |
/// | [`Report::suppressed`] | An `allow` marker in the source excuses it | No |
/// | [`Report::baselined`] | A baseline file records it as already reviewed | No |
/// | [`Report::disabled`] | Its rule is disabled by configuration | No |
pub struct Report {
    /// Findings nothing excused, in detector order.
    pub findings: Vec<Finding>,
    /// Findings a marker suppressed, kept so they can be counted.
    pub suppressed: Vec<Finding>,
    /// Findings a baseline excused, kept so a run says what it is not failing on.
    pub baselined: Vec<Finding>,
    /// Findings from a rule the configuration disables, kept for the same reason.
    pub disabled: Vec<Finding>,
    /// Files that could not be read or parsed, and other holes in the analysis.
    pub problems: Vec<String>,
    /// The rules, so a finding anywhere in the output can be explained.
    pub rules: RuleSet,
}

impl Report {
    /// Assembles a report from the findings nothing has excused yet.
    ///
    /// The excusing happens in [`Report::with_baseline`] and
    /// [`Report::with_disabled_rules`], so that a caller who wants neither does not have
    /// to say so, and so that the classification of a finding is always the same two
    /// steps in the same order: a baseline first, then the configuration.
    pub fn new(
        findings: Vec<Finding>,
        suppressed: Vec<Finding>,
        problems: Vec<String>,
        rules: RuleSet,
    ) -> Self {
        Self {
            findings,
            suppressed,
            baselined: Vec::new(),
            disabled: Vec::new(),
            problems,
            rules,
        }
    }

    /// Moves the findings the baseline records out of the gating list.
    ///
    /// Order is preserved, so the two lists read in detector order until rendering sorts
    /// them.
    pub fn with_baseline(mut self, baseline: &Baseline) -> Self {
        let (excused, gating): (Vec<Finding>, Vec<Finding>) = self
            .findings
            .into_iter()
            .partition(|finding| baseline.matches(finding));
        self.baselined = excused;
        self.findings = gating;
        self
    }

    /// Moves the findings of disabled rules out of the gating list.
    ///
    /// Applied after the baseline, so a finding that is both in the baseline and from a
    /// disabled rule is reported as baselined — the more specific of the two claims, and
    /// the one a reviewer would check first.
    pub fn with_disabled_rules(mut self, ids: &[String]) -> Self {
        if ids.is_empty() {
            return self;
        }
        let (excused, gating): (Vec<Finding>, Vec<Finding>) = self
            .findings
            .into_iter()
            .partition(|finding| ids.iter().any(|id| id == &finding.rule));
        self.disabled = excused;
        self.findings = gating;
        self
    }

    /// The severity of the worst finding, if there is one.
    pub fn worst(&self) -> Option<Severity> {
        self.findings
            .iter()
            .map(|finding| finding.severity(&self.rules))
            .max()
    }

    /// How many findings there are at or above `threshold`.
    pub fn count_at_or_above(&self, threshold: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity(&self.rules) >= threshold)
            .count()
    }

    /// How many findings there are at each severity, **worst first**.
    ///
    /// Worst first, rather than in [`Severity::ALL`]'s order, because both consumers
    /// read it as a summary and the interesting end is the top: `1 high, 1 info` is a
    /// line someone can act on, and `1 info, 1 high` is the same numbers buried.
    pub fn counts_by_severity(&self) -> Vec<(Severity, usize)> {
        Severity::ALL
            .into_iter()
            .rev()
            .map(|severity| {
                let count = self
                    .findings
                    .iter()
                    .filter(|finding| finding.severity(&self.rules) == severity)
                    .count();
                (severity, count)
            })
            .collect()
    }

    /// The process exit status for this run, given the severity gate.
    ///
    /// `1` means "the tree has something at or above the gate, or part of it could not be
    /// analysed"; `0` means "nothing to report". Problems count as failures because a
    /// run that silently skipped a file it could not parse has not answered the question
    /// it was asked. `2` is reserved for usage errors, which the CLI raises itself.
    pub fn exit_code(&self, threshold: Severity) -> i32 {
        if !self.problems.is_empty() || self.count_at_or_above(threshold) > 0 {
            1
        } else {
            0
        }
    }

    /// Renders the report in `format`.
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Text => self.render_text(),
            Format::Json => self.render_json(),
            Format::Sarif => self.render_sarif(),
        }
    }

    /// The rules whose findings a configuration excused, sorted and deduplicated.
    pub fn disabled_rule_ids(&self) -> Vec<&str> {
        let ids = self
            .disabled
            .iter()
            .map(|finding| finding.rule.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        ids.into_iter().collect()
    }

    /// Findings in file, line, column order, whatever order they arrived in.
    ///
    /// The excused lists are rendered in this order rather than in the order the parallel
    /// walk happened to produce them, so that two runs over the same tree produce the
    /// same document — which is the property `--jobs` must not cost.
    fn by_position(findings: &[Finding]) -> Vec<&Finding> {
        let mut ordered = findings.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.location.start.line.cmp(&right.location.start.line))
                .then_with(|| left.location.start.column.cmp(&right.location.start.column))
                .then_with(|| left.rule.cmp(&right.rule))
        });
        ordered
    }

    /// Findings ordered for reading: worst first, then by file, line and column.
    fn ordered(&self) -> Vec<&Finding> {
        let mut ordered = self.findings.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            let left_severity = left.severity(&self.rules);
            let right_severity = right.severity(&self.rules);
            right_severity
                .cmp(&left_severity)
                .then_with(|| left.file.cmp(&right.file))
                .then_with(|| left.location.start.line.cmp(&right.location.start.line))
                .then_with(|| left.location.start.column.cmp(&right.location.start.column))
                .then_with(|| left.rule.cmp(&right.rule))
        });
        ordered
    }

    fn render_text(&self) -> String {
        let mut out = String::new();
        for finding in self.ordered() {
            let severity = finding.severity(&self.rules);
            out.push_str(&format!(
                "{}:{}:{}: {severity}: {}\n",
                finding.file,
                finding.location.start.line,
                finding.location.start.column,
                finding.rule
            ));
            if !finding.source_line.is_empty() {
                out.push_str(&format!("    {}\n", finding.source_line));
                // Point at the column rather than the start of the line, because a
                // finding on a long line is otherwise hard to place. The caret is
                // clamped to the line so it always lands on something.
                let indent = finding.location.start.column.saturating_sub(1);
                let max_indent = finding.source_line.chars().count();
                out.push_str(&" ".repeat(indent.min(max_indent)));
                out.push_str("^ ");
            } else {
                out.push_str("    ");
            }
            out.push_str(&format!("{}\n", finding.message));
            out.push_str(&format!("    fix: {}\n", finding.remediation));
            out.push('\n');
        }

        let mutually = self
            .counts_by_severity()
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(severity, count)| format!("{count} {severity}"))
            .collect::<Vec<_>>()
            .join(", ");

        let files = self
            .findings
            .iter()
            .map(|finding| finding.file.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len();

        if self.findings.is_empty() {
            out.push_str("no findings\n");
        } else {
            out.push_str(&format!(
                "{} finding{} ({mutually}) in {files} file{}\n",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                if files == 1 { "" } else { "s" },
            ));
        }
        if !self.baselined.is_empty() {
            out.push_str(&format!(
                "{} finding{} the baseline records and this run does not fail on\n",
                self.baselined.len(),
                if self.baselined.len() == 1 { "" } else { "s" },
            ));
        }
        if !self.disabled.is_empty() {
            let ids = self.disabled_rule_ids().join(", ");
            out.push_str(&format!(
                "{} finding{} from {} disabled by configuration ({ids})\n",
                self.disabled.len(),
                if self.disabled.len() == 1 { "" } else { "s" },
                if ids.contains(',') { "rules" } else { "a rule" },
            ));
        }
        if !self.suppressed.is_empty() {
            let ids = self
                .suppressed
                .iter()
                .map(|finding| finding.rule.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "{} finding{} suppressed by a marker ({ids})\n",
                self.suppressed.len(),
                if self.suppressed.len() == 1 { "" } else { "s" },
            ));
        }
        if !self.problems.is_empty() {
            out.push_str(&format!(
                "{} file{} could not be analysed:\n",
                self.problems.len(),
                if self.problems.len() == 1 { "" } else { "s" },
            ));
            for problem in &self.problems {
                out.push_str(&format!("    {problem}\n"));
            }
        }
        out
    }

    /// One finding as JSON, with the severity resolved from its rule.
    fn finding_json(&self, finding: &Finding) -> Value {
        json!({
            "rule": finding.rule,
            "severity": finding.severity(&self.rules).as_str(),
            "message": finding.message,
            "remediation": finding.remediation,
            "file": finding.file,
            "start_line": finding.location.start.line,
            "start_column": finding.location.start.column,
            "byte_offset": finding.location.start.offset,
            "byte_length": finding.location.len(),
            "source_line": finding.source_line,
        })
    }

    fn render_json(&self) -> String {
        let document = json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "tool": {
                "name": crate::TOOL_NAME,
                "version": crate::VERSION,
            },
            "summary": {
                "findings": self.findings.len(),
                "suppressed": self.suppressed.len(),
                "baselined": self.baselined.len(),
                "disabled": self.disabled.len(),
                "problems": self.problems.len(),
                "worst_severity": self.worst().map(|severity| severity.as_str()),
                "by_severity": self
                    .counts_by_severity()
                    .into_iter()
                    .filter(|(_, count)| *count > 0)
                    .map(|(severity, count)| json!({ "severity": severity.as_str(), "count": count }))
                    .collect::<Vec<_>>(),
                "rules": self.rules.len(),
            },
            "findings": self.ordered().into_iter().map(|finding| self.finding_json(finding)).collect::<Vec<_>>(),
            "suppressed": Self::by_position(&self.suppressed).into_iter().map(|finding| self.finding_json(finding)).collect::<Vec<_>>(),
            "baselined": Self::by_position(&self.baselined).into_iter().map(|finding| self.finding_json(finding)).collect::<Vec<_>>(),
            "disabled": Self::by_position(&self.disabled).into_iter().map(|finding| self.finding_json(finding)).collect::<Vec<_>>(),
            "problems": self.problems,
            "rules": self.rules.iter().map(|rule| json!({
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.as_str(),
            })).collect::<Vec<_>>(),
        });
        // Pretty-printed: this output is read by people debugging a pipeline at least as
        // often as by a program, and no program minds the newlines.
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_owned())
    }

    /// How a severity maps onto SARIF's three levels.
    ///
    /// `warning` for medium and low rather than `note`, because both are defects a
    /// reviewer is expected to act on, and GitHub renders `note` as a passing comment
    /// rather than as an annotation on the diff.
    fn sarif_level(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical | Severity::High => "error",
            Severity::Medium | Severity::Low => "warning",
            Severity::Info => "note",
        }
    }

    fn render_sarif(&self) -> String {
        let rules = self.rules.iter().collect::<Vec<_>>();

        // `ruleIndex` is what binds a result to its rule without repeating it, and it has
        // to be the position in the array below, not the rule's own ordering.
        let rule_index =
            |id: &str| -> Option<usize> { rules.iter().position(|rule| rule.id == id) };

        let driver_rules = rules
            .iter()
            .map(|rule| {
                let mut properties = json!({
                    "severity": rule.severity.as_str(),
                    "tags": ["security", "soroban"],
                });
                // Only set `precision` where the rule's own rationale says the check is a
                // heuristic; claiming high precision for a word-list match would be a lie
                // told in a machine-readable field.
                if let Some(object) = properties.as_object_mut() {
                    object.insert(
                        "precision".to_owned(),
                        json!(if rule.heuristic { "medium" } else { "high" }),
                    );
                }
                let mut entry = json!({
                    "id": rule.id,
                    "name": rule.id,
                    "shortDescription": { "text": rule.title },
                    "fullDescription": { "text": rule.rationale },
                    "help": { "text": rule.remediation },
                    "defaultConfiguration": { "level": Self::sarif_level(rule.severity) },
                    "properties": properties,
                });
                if let Some(reference) = rule.references.first() {
                    if let Some(object) = entry.as_object_mut() {
                        object.insert("helpUri".to_owned(), json!(reference));
                    }
                }
                entry
            })
            .collect::<Vec<_>>();

        // Every finding a run has is in this document, excused or not, each excused one
        // carrying the SARIF mechanism for the reason it was excused: `inSource` for an
        // `allow` marker, since the decision is written in the source file itself, and
        // `external` for a baseline or a configuration, which live outside it. The
        // alternative — omitting them — would make the code-scanning view unable to
        // distinguish "nothing here" from "three exceptions, in a file you can edit".
        let mut results = Vec::new();
        let groups = [
            SarifGroup::gating(&self.findings),
            SarifGroup::excused(
                &self.suppressed,
                "inSource",
                "excused by a `soroban-analyzer: allow(...)` marker in the source",
            ),
            SarifGroup::excused(
                &self.baselined,
                "external",
                "recorded in the baseline file, which this run does not fail on",
            ),
            SarifGroup::excused(
                &self.disabled,
                "external",
                "a rule disabled by configuration",
            ),
        ];

        for SarifGroup {
            findings,
            suppression,
        } in groups
        {
            // The gating findings are rendered worst-first for a reader; the excused ones
            // in position order, because their order is about the file rather than about
            // severity.
            let ordered = if suppression.is_none() {
                self.ordered()
            } else {
                Self::by_position(findings)
            };

            for finding in ordered {
                let severity = finding.severity(&self.rules);
                let location = json!({
                    "physicalLocation": {
                        "artifactLocation": { "uri": finding.file },
                        "region": {
                            "startLine": finding.location.start.line,
                            "startColumn": finding.location.start.column,
                        },
                    },
                });
                let mut result = json!({
                    "ruleId": finding.rule,
                    "level": Self::sarif_level(severity),
                    "message": { "text": finding.message },
                    "locations": [location],
                    // GitHub deduplicates by fingerprint, so without one the same finding
                    // reappears as a new alert on every push. The rule id and the location
                    // are what identify it; the message is not included, because it names
                    // identifiers that a rename would change. A baseline entry, which has
                    // to survive the code moving, uses the opposite trade — see
                    // `crate::baseline`.
                    "partialFingerprints": {
                        "sorobanAnalyzer/v1": format!(
                            "{}:{}:{}:{}",
                            finding.rule,
                            finding.file,
                            finding.location.start.line,
                            finding.location.start.column
                        ),
                    },
                });
                if let Some(object) = result.as_object_mut() {
                    if let Some(index) = rule_index(&finding.rule) {
                        object.insert("ruleIndex".to_owned(), json!(index));
                    }
                    if let Some((kind, justification)) = suppression {
                        object.insert(
                            "suppressions".to_owned(),
                            json!([{ "kind": kind, "justification": justification }]),
                        );
                    }
                }
                results.push(result);
            }
        }

        let document = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": crate::TOOL_NAME,
                        "version": crate::VERSION,
                        "informationUri": crate::REPOSITORY,
                        "rules": driver_rules,
                    }
                },
                "results": results,
                // Suppressed findings are reported as tool notifications rather than
                // dropped, so a SARIF consumer can still see that a marker excused
                // something — which is the point of counting them.
                "invocations": [{
                    "executionSuccessful": self.problems.is_empty(),
                    "toolExecutionNotifications": self.problems.iter().map(|problem| json!({
                        "level": "error",
                        "message": { "text": problem },
                    })).collect::<Vec<_>>(),
                }],
            }],
        });
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Finding;
    use crate::rules::Rule;
    use crate::source::SourceFile;

    fn rule(id: &str, severity: Severity) -> Rule {
        Rule {
            id: id.to_owned(),
            title: format!("Rule {id}"),
            severity,
            rationale: "Because the pattern loses funds in a way no other tool sees.".to_owned(),
            remediation: "Do the safe thing instead.".to_owned(),
            references: vec!["https://example.invalid/why".to_owned()],
            triggers: String::new(),
            clean: String::new(),
            heuristic: false,
            file: format!("{id}.json"),
        }
    }

    fn rules() -> RuleSet {
        let mut set = RuleSet::default();
        set.insert_for_tests(rule("rule-high", Severity::High));
        set.insert_for_tests(rule("rule-info", Severity::Info));
        set
    }

    fn finding(rules: &RuleSet, id: &str, line: usize) -> Finding {
        let file = SourceFile::parse(
            "src/lib.rs",
            "fn f() {}\nfn g() {}\nfn h() {}\nfn i() {}\n".to_owned(),
        )
        .expect("the fixture parses");
        let rule = rules.get(id).expect("the rule exists");
        Finding::new(
            rule,
            &file.display_path(),
            file.line_text(line).to_owned(),
            file.location_at(0),
            format!("found {id}"),
        )
    }

    fn report() -> Report {
        let rules = rules();
        Report::new(
            vec![
                finding(&rules, "rule-high", 1),
                finding(&rules, "rule-info", 3),
            ],
            Vec::new(),
            Vec::new(),
            rules,
        )
    }

    #[test]
    fn the_exit_code_follows_the_gate() {
        let report = report();
        assert_eq!(report.exit_code(Severity::High), 1);
        assert_eq!(
            report.exit_code(Severity::Critical),
            0,
            "nothing is critical"
        );
        assert_eq!(report.count_at_or_above(Severity::High), 1);
        assert_eq!(
            report.count_at_or_above(Severity::Low),
            1,
            "the info finding is below the low gate"
        );
        assert_eq!(report.count_at_or_above(Severity::Info), 2);
        assert_eq!(report.worst(), Some(Severity::High));
        assert_eq!(
            report.counts_by_severity(),
            vec![
                (Severity::Critical, 0),
                (Severity::High, 1),
                (Severity::Medium, 0),
                (Severity::Low, 0),
                (Severity::Info, 1),
            ],
            "worst first, and zeros included so a caller can plot it"
        );
    }

    #[test]
    fn an_unanalysable_file_fails_the_run_even_with_no_findings() {
        let report = Report::new(
            Vec::new(),
            Vec::new(),
            vec!["src/broken.rs: line 2, column 5: expected `;`".to_owned()],
            rules(),
        );
        assert_eq!(
            report.exit_code(Severity::Info),
            1,
            "a run that could not read a file has not answered the question"
        );
    }

    #[test]
    fn text_output_shows_worst_first_and_says_what_to_do() {
        let text = report().render(Format::Text);
        let high = text.find("rule-high").expect("the high finding is shown");
        let info = text.find("rule-info").expect("the info finding is shown");
        assert!(high < info, "worst first:\n{text}");
        assert!(text.contains("fix: Do the safe thing instead."), "{text}");
        assert!(
            text.contains("2 findings (1 high, 1 info) in 1 file"),
            "{text}"
        );
    }

    #[test]
    fn text_output_says_so_when_there_is_nothing_to_report() {
        let report = Report::new(Vec::new(), Vec::new(), Vec::new(), rules());
        assert!(report.render(Format::Text).contains("no findings"));
    }

    #[test]
    fn suppressed_findings_are_counted_in_the_text_output() {
        let rules = rules();
        let report = Report::new(
            Vec::new(),
            vec![finding(&rules, "rule-high", 2)],
            Vec::new(),
            rules,
        );
        let text = report.render(Format::Text);
        assert!(
            text.contains("1 finding suppressed by a marker (rule-high)"),
            "{text}"
        );
        assert_eq!(
            report.exit_code(Severity::Info),
            0,
            "a suppressed finding must not fail a run"
        );
    }

    #[test]
    fn a_baselined_finding_is_reported_but_does_not_gate() {
        let rules = rules();
        let baseline = Baseline::from_findings(&[finding(&rules, "rule-high", 1)]);
        let report = report().with_baseline(&baseline);

        assert_eq!(
            report.findings.len(),
            1,
            "only the unrecorded finding gates"
        );
        assert_eq!(report.baselined.len(), 1);
        assert_eq!(
            report.exit_code(Severity::High),
            0,
            "a baselined finding must not fail the run: a baseline that does not ratchet \
             is a tool people turn off"
        );

        let text = report.render(Format::Text);
        assert!(
            text.contains("1 finding the baseline records and this run does not fail on"),
            "a run says what it is not failing on: {text}"
        );

        let document: Value = serde_json::from_str(&report.render(Format::Json)).unwrap();
        assert_eq!(document["summary"]["findings"], 1, "{document}");
        assert_eq!(document["summary"]["baselined"], 1);
        assert_eq!(document["baselined"][0]["rule"], "rule-high");
    }

    #[test]
    fn a_finding_from_a_disabled_rule_is_reported_but_does_not_gate() {
        let report = report().with_disabled_rules(&["rule-high".to_owned()]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.disabled_rule_ids(), vec!["rule-high"]);
        assert_eq!(report.exit_code(Severity::High), 0);
        assert!(report
            .render(Format::Text)
            .contains("from a rule disabled by configuration (rule-high)"));

        let document: Value = serde_json::from_str(&report.render(Format::Json)).unwrap();
        assert_eq!(document["summary"]["disabled"], 1);
        assert_eq!(document["disabled"][0]["rule"], "rule-high");
    }

    #[test]
    fn the_baseline_is_applied_before_the_configuration() {
        // A finding that is both recorded and from a disabled rule is reported as
        // baselined: the more specific claim, and the one a reviewer would check first.
        let rules = rules();
        let baseline = Baseline::from_findings(&[finding(&rules, "rule-high", 1)]);
        let report = report()
            .with_baseline(&baseline)
            .with_disabled_rules(&["rule-high".to_owned()]);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.baselined.len(), 1);
        assert!(report.disabled.is_empty(), "{:?}", report.disabled);
    }

    #[test]
    fn every_excused_finding_reaches_a_code_scanner_as_a_suppression() {
        // A code-scanning view that never sees an exception cannot tell "nothing here"
        // from "three of them, in a file you can edit". A marker is `inSource`, because
        // the decision is written in the source; a baseline and a configuration are
        // `external`, because they live outside it. One rule per category, so the test
        // names all four kinds of finding a run can have.
        let mut rules = RuleSet::default();
        rules.insert_for_tests(rule("rule-baselined", Severity::High));
        rules.insert_for_tests(rule("rule-gating", Severity::Medium));
        rules.insert_for_tests(rule("rule-marker", Severity::Low));
        rules.insert_for_tests(rule("rule-disabled", Severity::Info));

        let baseline = Baseline::from_findings(&[finding(&rules, "rule-baselined", 1)]);
        let report = Report::new(
            vec![
                finding(&rules, "rule-baselined", 1),
                finding(&rules, "rule-gating", 2),
                finding(&rules, "rule-disabled", 4),
            ],
            vec![finding(&rules, "rule-marker", 3)],
            Vec::new(),
            rules,
        )
        .with_baseline(&baseline)
        .with_disabled_rules(&["rule-disabled".to_owned()]);

        let document: Value = serde_json::from_str(&report.render(Format::Sarif)).unwrap();
        let results = document["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            4,
            "every finding is in the document: {document}"
        );
        assert_eq!(results[0]["ruleId"], "rule-gating");
        assert!(
            results[0]["suppressions"].is_null(),
            "the gating finding is the only one nobody excused"
        );
        assert_eq!(results[1]["ruleId"], "rule-marker");
        assert_eq!(results[1]["suppressions"][0]["kind"], "inSource");
        assert_eq!(results[2]["ruleId"], "rule-baselined");
        assert_eq!(results[2]["suppressions"][0]["kind"], "external");
        assert!(results[2]["suppressions"][0]["justification"]
            .as_str()
            .expect("a justification")
            .contains("baseline"));
        assert_eq!(results[3]["ruleId"], "rule-disabled");
        assert!(results[3]["suppressions"][0]["justification"]
            .as_str()
            .expect("a justification")
            .contains("disabled"));
    }

    #[test]
    fn json_output_is_valid_and_carries_the_counts() {
        let document: Value = serde_json::from_str(&report().render(Format::Json))
            .expect("the JSON output must parse");
        assert_eq!(document["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(document["summary"]["findings"], 2);
        assert_eq!(document["summary"]["worst_severity"], "high");
        assert_eq!(document["findings"][0]["rule"], "rule-high", "{document}");
        assert_eq!(document["findings"][0]["severity"], "high");
        assert!(document["findings"][0]["start_line"].is_number());
    }

    #[test]
    fn sarif_output_is_valid_and_places_findings_on_lines() {
        let document: Value = serde_json::from_str(&report().render(Format::Sarif))
            .expect("the SARIF output must parse");
        assert_eq!(document["version"], SARIF_VERSION);
        let run = &document["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], crate::TOOL_NAME);
        let results = run["results"].as_array().expect("results is an array");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "rule-high");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
        let region = &results[0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 1);
        assert!(region["startColumn"].is_number());
        assert!(results[0]["partialFingerprints"]["sorobanAnalyzer/v1"].is_string());

        // Every result's `ruleIndex` must address the rule it names, or a consumer
        // reports the finding against the wrong rule's metadata.
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules is an array");
        for result in results {
            let index = result["ruleIndex"].as_u64().expect("a rule index") as usize;
            assert_eq!(rules[index]["id"], result["ruleId"]);
        }
    }

    #[test]
    fn an_empty_run_still_emits_a_valid_sarif_document() {
        let report = Report::new(Vec::new(), Vec::new(), Vec::new(), rules());
        let document: Value =
            serde_json::from_str(&report.render(Format::Sarif)).expect("it parses");
        assert!(document["runs"][0]["results"]
            .as_array()
            .expect("results is an array")
            .is_empty());
        assert_eq!(
            document["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .expect("rules is an array")
                .len(),
            2,
            "the rule table ships even when nothing fired, so alerts can be explained"
        );
    }

    #[test]
    fn formats_parse_by_name() {
        assert_eq!("SARIF".parse::<Format>().unwrap(), Format::Sarif);
        assert_eq!("json".parse::<Format>().unwrap(), Format::Json);
        let err = "yaml".parse::<Format>().unwrap_err();
        assert!(err.contains("text, json, sarif"), "{err}");
    }

    #[test]
    fn problems_are_reported_to_the_sarif_consumer() {
        let report = Report::new(
            Vec::new(),
            Vec::new(),
            vec!["src/broken.rs: boom".to_owned()],
            rules(),
        );
        let document: Value = serde_json::from_str(&report.render(Format::Sarif)).unwrap();
        assert_eq!(
            document["runs"][0]["invocations"][0]["executionSuccessful"],
            false
        );
        assert_eq!(
            document["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"]
                ["text"],
            "src/broken.rs: boom"
        );
    }
}
