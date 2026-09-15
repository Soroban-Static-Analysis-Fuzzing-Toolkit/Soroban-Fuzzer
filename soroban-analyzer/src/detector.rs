//! The detector trait, and the engine that runs detectors over files.

use proc_macro2::Span;

use crate::finding::Finding;
use crate::rules::{Rule, RuleError, RuleSet};
use crate::source::{Location, SourceFile};

/// A vulnerability class, expressed as a check over one parsed file.
///
/// A detector is deliberately narrow. It receives a parsed file and a sink, decides
/// what in it matches the pattern it encodes, and reports it. It does not know its own
/// severity, does not choose its own wording for the fix, and does not decide whether
/// to exit non-zero — all three live in the rule metadata and the engine, so that a
/// pull request adding a detector cannot quietly change how findings are graded.
///
/// Implementors should be conservative. A detector that fires on correct code trains
/// people to ignore findings, and the crate's contribution standard reflects that: a
/// detector needs a fixture proving it fires *and* one proving it stays quiet.
///
/// The [`Send`] and [`Sync`] bounds are what let [`crate::analyze_paths`] check files on
/// several threads, and they are on the trait rather than on the engine so that the
/// guarantee holds for every implementation: a detector that could not be shared would
/// be a detector that silently made the tool single-threaded. A detector holds no state
/// of its own — it is handed a file and a sink — so the bounds cost nothing to satisfy.
pub trait Detector: Send + Sync {
    /// The rule this detector implements.
    ///
    /// Must match a rule metadata file's `id`. A mismatch is a configuration error the
    /// engine reports rather than tolerates, because a finding whose rule cannot be
    /// looked up has no severity and no remediation.
    fn id(&self) -> &'static str;

    /// Examines one file and reports what it finds.
    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>);
}

/// What a detector is given to work with.
pub struct DetectorCtx<'a> {
    file: &'a SourceFile,
    rule: &'a Rule,
}

impl<'a> DetectorCtx<'a> {
    /// The parsed file under examination.
    pub fn file(&self) -> &'a SourceFile {
        self.file
    }

    /// The detector's own rule metadata.
    pub fn rule(&self) -> &'a Rule {
        self.rule
    }
}

/// Where a detector reports findings.
///
/// The sink is what keeps a detector from getting the incidental things wrong: the file
/// name, the rule id, the remediation text and any `allow` suppression are all applied
/// here, so a detector writes only the part it actually knows — where, and what.
pub struct Findings<'a> {
    rule: &'a Rule,
    file: &'a SourceFile,
    reported: Vec<Finding>,
    suppressed: Vec<Finding>,
}

impl<'a> Findings<'a> {
    fn new(rule: &'a Rule, file: &'a SourceFile) -> Self {
        Self {
            rule,
            file,
            reported: Vec::new(),
            suppressed: Vec::new(),
        }
    }

    /// Reports a finding at `span`.
    ///
    /// The span should be the smallest node that shows the problem — the arithmetic
    /// expression rather than the function containing it — because a finding that
    /// highlights forty lines is one a reviewer skips.
    pub fn report(&mut self, span: Span, message: impl Into<String>) {
        self.report_at(self.file.location(span), message);
    }

    /// Reports a finding at an already-computed location.
    pub fn report_at(&mut self, location: Location, message: impl Into<String>) {
        let message = message.into();
        let finding = Finding::new(
            self.rule,
            &self.file.display_path(),
            source_line(self.file, &location),
            location,
            message,
        );
        if crate::suppress::is_suppressed(self.file, &self.rule.id, location.start.offset) {
            self.suppressed.push(finding);
        } else {
            self.reported.push(finding);
        }
    }
}

/// The text of the line a location starts on, without surrounding whitespace.
fn source_line(file: &SourceFile, location: &Location) -> String {
    file.line_text(location.start.line).trim().to_owned()
}

/// What one file produced.
#[derive(Clone, Debug, Default)]
pub struct FileFindings {
    /// Findings the detectors reported and no `allow` marker suppressed.
    pub findings: Vec<Finding>,
    /// Findings an `allow` marker suppressed.
    ///
    /// Kept rather than discarded so that a run can say how many there were. A
    /// suppression mechanism that hides its own effects is one people stop trusting,
    /// and one that reports them keeps deliberate exceptions visible in review.
    pub suppressed: Vec<Finding>,
}

/// The detector set plus the rules behind it.
pub struct Analyzer {
    detectors: Vec<Box<dyn Detector>>,
    rules: RuleSet,
}

impl Analyzer {
    /// Builds the analyser from the detectors and rules compiled into this binary.
    ///
    /// Rule-loading errors are dropped here rather than surfaced, because this
    /// constructor is infallible by design: a rule that will not load is a defect in
    /// this repository, caught by the crate's own tests and by [`Analyzer::validate`],
    /// not something a caller of a static analyser should have to handle.
    /// [`load_embedded_rules`] is the reporting form, and the CLI uses that one.
    pub fn embedded() -> Self {
        let (rules, _) = RuleSet::embedded();
        Self {
            detectors: crate::detectors::all(),
            rules,
        }
    }

    /// Builds an analyser from an explicit pair, for tests and for callers that want a
    /// subset.
    pub fn new(detectors: Vec<Box<dyn Detector>>, rules: RuleSet) -> Self {
        Self { detectors, rules }
    }

    /// The registered detectors.
    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }

    /// The loaded rules.
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Checks that every rule has a detector and every detector has a rule.
    ///
    /// Both directions matter. A detector without a rule cannot be graded or explained;
    /// a rule without a detector is metadata for a check that does not exist, which is
    /// how a rule quietly stops being enforced. The crate's tests assert this is empty;
    /// the CLI treats a non-empty result as a broken installation.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();

        for detector in &self.detectors {
            if self.rules.get(detector.id()).is_none() {
                problems.push(format!(
                    "detector `{}` has no rule metadata; add rules/{}.json",
                    detector.id(),
                    detector.id()
                ));
            }
        }

        for rule in self.rules.iter() {
            if !self
                .detectors
                .iter()
                .any(|detector| detector.id() == rule.id)
            {
                problems.push(format!(
                    "rule `{}` (in {}) has no detector; a rule nothing implements is not \
                     enforced",
                    rule.id, rule.file
                ));
            }
        }

        problems.sort();
        problems.dedup();
        problems
    }

    /// Runs every detector over one parsed file.
    ///
    /// Takes `&self`, so one analyser checks many files; the [`Detector`] bounds are what
    /// make that safe to do from several threads at once.
    ///
    /// Detectors whose rule is missing are skipped rather than run: their findings would
    /// have no severity, and reporting them as `info` would understate a real defect.
    /// [`Analyzer::validate`] is what reports that situation.
    pub fn check_file(&self, file: &SourceFile) -> FileFindings {
        let mut result = FileFindings::default();
        for detector in &self.detectors {
            let Some(rule) = self.rules.get(detector.id()) else {
                continue;
            };
            let ctx = DetectorCtx { file, rule };
            let mut sink = Findings::new(rule, file);
            detector.check(&ctx, &mut sink);
            result.findings.extend(sink.reported);
            result.suppressed.extend(sink.suppressed);
        }
        result
    }
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::embedded()
    }
}

/// Loads the rule metadata that ships with this binary, reporting every problem at once.
///
/// The CLI calls this before doing any work, because a binary whose rules cannot be
/// loaded cannot say anything meaningful about a contract.
pub fn load_embedded_rules() -> Result<RuleSet, Vec<RuleError>> {
    let (rules, errors) = RuleSet::embedded();
    if errors.is_empty() {
        Ok(rules)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::SCHEMA_VERSION;

    fn rule_json(id: &str) -> String {
        format!(
            r#"{{
                "schema_version": {SCHEMA_VERSION},
                "id": "{id}",
                "title": "A rule",
                "severity": "low",
                "rationale": "Long enough to explain why this is a bug and why nothing else finds it.",
                "remediation": "Fix it.",
                "examples": {{ "triggers": "fn a() {{}}", "clean": "fn b() {{}}" }}
            }}"#
        )
    }

    struct AlwaysReports;

    impl Detector for AlwaysReports {
        fn id(&self) -> &'static str {
            "always"
        }

        fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
            for item in &ctx.file().ast.items {
                sink.report(
                    syn::spanned::Spanned::span(item),
                    format!("reported by {}", ctx.rule().id),
                );
            }
        }
    }

    #[test]
    fn a_detector_finding_carries_the_rules_grading() {
        let source = rule_json("always");
        let (rules, _) = RuleSet::from_sources(&["always.json"], &[source.as_str()]);
        let analyzer = Analyzer::new(vec![Box::new(AlwaysReports)], rules);
        let file = SourceFile::parse("a.rs", "fn one() {}\nfn two() {}\n".to_owned()).unwrap();

        let found = analyzer.check_file(&file);
        assert_eq!(found.findings.len(), 2);
        assert_eq!(found.findings[0].rule, "always");
        assert_eq!(found.findings[0].remediation, "Fix it.");
        assert_eq!(
            found.findings[0].severity(analyzer.rules()),
            crate::severity::Severity::Low
        );
        assert_eq!(found.findings[0].location.start.line, 1);
        assert_eq!(found.findings[1].location.start.line, 2);
    }

    #[test]
    fn validation_reports_both_directions() {
        let always = rule_json("always");
        let orphan = rule_json("orphan");
        let (rules, _) = RuleSet::from_sources(
            &["always.json", "orphan.json"],
            &[always.as_str(), orphan.as_str()],
        );
        let analyzer = Analyzer::new(vec![Box::new(AlwaysReports)], rules);
        let problems = analyzer.validate();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("orphan"), "{problems:?}");
        assert!(problems[0].contains("no detector"), "{problems:?}");
    }

    #[test]
    fn a_detector_without_a_rule_is_reported_and_skipped() {
        let (rules, _) = RuleSet::from_sources(&[], &[] as &[&str]);
        let analyzer = Analyzer::new(vec![Box::new(AlwaysReports)], rules);
        let problems = analyzer.validate();
        assert!(problems[0].contains("no rule metadata"), "{problems:?}");

        let file = SourceFile::parse("a.rs", "fn one() {}\n".to_owned()).unwrap();
        assert!(
            analyzer.check_file(&file).findings.is_empty(),
            "a finding that cannot be graded must not be reported as if graded"
        );
    }

    #[test]
    fn the_embedded_analyzer_is_self_consistent() {
        let analyzer = Analyzer::embedded();
        let problems = analyzer.validate();
        assert!(problems.is_empty(), "{problems:#?}");
        assert!(!analyzer.detectors().is_empty());
        assert!(load_embedded_rules().is_ok());
    }
}
