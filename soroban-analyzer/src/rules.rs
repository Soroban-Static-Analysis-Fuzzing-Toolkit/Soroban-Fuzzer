//! Rule metadata: the versioned, declarative half of a detector.
//!
//! A detector is two files. The code in `src/detectors/` says *what shape* to look for;
//! the JSON in `rules/` says what the rule is called, how bad it is, why it exists, how
//! to fix it, and — most usefully — a source snippet that must trigger it and one that
//! must not. The engine loads the metadata, attaches it to every finding the detector
//! reports, and refuses to run a rule it cannot make sense of.
//!
//! # Why the examples are in the metadata
//!
//! The two snippets are not documentation. They are the rule's own fixtures, parsed and
//! run by `tests/rules.rs` on every commit, which is what turns "a detector with no
//! fixture proving it fires, and one proving it does not over-fire, is not mergeable"
//! from a rule in a document into something CI enforces. A contributor writing a
//! detector therefore writes its fixtures as part of writing the rule, and cannot
//! forget them.
//!
//! # Schema versioning
//!
//! [`SCHEMA_VERSION`] is checked on load. The point is that the format can change
//! without silently changing what existing rules *mean*: a rule file written for a
//! newer schema is rejected with a message naming the version rather than being
//! interpreted under the old assumptions.

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// The rule metadata schema this build understands.
///
/// Bump this when a change to the format would make an existing rule file mean
/// something different, so that a stale file is rejected instead of reinterpreted.
pub const SCHEMA_VERSION: u32 = 1;

/// A rule file that could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleError {
    /// Which file, as far as it can be told.
    pub file: String,
    /// What is wrong with it.
    pub problem: String,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.problem)
    }
}

/// One rule's metadata, as loaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Rule {
    /// Stable identifier, e.g. `soroban-missing-require-auth`. Detectors name it.
    pub id: String,
    /// Human title, for the rules table.
    pub title: String,
    /// How bad an occurrence is.
    pub severity: Severity,
    /// Why the pattern is a bug, and why it is Soroban-specific.
    pub rationale: String,
    /// What to do instead. Attached to every finding.
    pub remediation: String,
    /// Links to standards, upstream issues or write-ups.
    pub references: Vec<String>,
    /// Source that **must** produce at least one finding.
    pub triggers: String,
    /// Source that must produce **none**.
    pub clean: String,
    /// True when the check rests on naming heuristics rather than on structure.
    ///
    /// A rule that matches on words — an identifier containing `balance` — is right
    /// often enough to be useful and wrong often enough that a reader should be told,
    /// in a machine-readable field rather than only in prose. It is reported as the
    /// rule's SARIF `precision`, and asserted in this crate's tests to stay honest.
    pub heuristic: bool,
    /// The metadata file this came from, for error messages.
    #[serde(skip)]
    pub file: String,
}

/// The shape of a rule file on disk, kept separate from [`Rule`] so that a missing
/// field can be reported by name rather than as a serde default.
#[derive(Deserialize)]
struct RuleFile {
    schema_version: u32,
    id: String,
    title: String,
    severity: Severity,
    rationale: String,
    remediation: String,
    #[serde(default)]
    references: Vec<String>,
    /// Defaulted rather than required: most rules are structural, and making every rule
    /// state that a word list is involved would be noise.
    #[serde(default)]
    heuristic: bool,
    examples: RuleExamples,
}

#[derive(Deserialize)]
struct RuleExamples {
    /// Source that must trigger the rule.
    triggers: String,
    /// Source that must not.
    clean: String,
}

/// Every loaded rule, keyed by id.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    rules: BTreeMap<String, Rule>,
}

impl RuleSet {
    /// The rules embedded in the binary by `build.rs`, with anything that would not load.
    ///
    /// A tuple rather than a `Result`, and the errors rather than a panic: the caller
    /// decides whether an unloadable rule is fatal, and the CLI reports all of them at
    /// once instead of failing on the first.
    pub fn embedded() -> (Self, Vec<RuleError>) {
        Self::from_sources(
            crate::rules_index::RULE_NAMES,
            crate::rules_index::RULE_SOURCES,
        )
    }

    /// Parses `(file name, contents)` pairs, keeping every rule that loads.
    ///
    /// Errors are returned alongside the set rather than aborting, so a caller can
    /// report all of a broken batch at once instead of one per run.
    pub fn from_sources(names: &[&str], sources: &[&str]) -> (Self, Vec<RuleError>) {
        let mut rules = BTreeMap::new();
        let mut errors = Vec::new();

        for (index, source) in sources.iter().enumerate() {
            let name = names.get(index).copied().unwrap_or("<embedded>");
            match parse_rule(name, source) {
                Ok(rule) => {
                    if rules.contains_key(&rule.id) {
                        errors.push(RuleError {
                            file: name.to_owned(),
                            problem: format!(
                                "duplicate rule id `{}`: ids must be unique, because a finding \
                                 names its rule by id",
                                rule.id
                            ),
                        });
                    } else {
                        rules.insert(rule.id.clone(), rule);
                    }
                }
                Err(error) => errors.push(error),
            }
        }

        (Self { rules }, errors)
    }

    /// Every rule, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }

    /// The number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when there are no rules, which is always a mistake rather than a state.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Looks a rule up by id.
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.get(id)
    }

    /// The rule ids, in order.
    pub fn ids(&self) -> Vec<&str> {
        self.rules.keys().map(String::as_str).collect()
    }

    /// Inserts a rule directly.
    ///
    /// Test-only: production paths go through [`RuleSet::from_sources`], which is where
    /// every validation lives. A constructor that skipped validation would let a test
    /// assert behaviour on a rule the loader would have rejected.
    #[cfg(test)]
    pub(crate) fn insert_for_tests(&mut self, rule: Rule) {
        self.rules.insert(rule.id.clone(), rule);
    }
}

impl fmt::Display for RuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for rule in self.iter() {
            writeln!(f, "{} [{}] {}", rule.id, rule.severity, rule.title)?;
            writeln!(f, "    {}", rule.rationale)?;
            writeln!(f, "    fix: {}", rule.remediation)?;
            for reference in &rule.references {
                writeln!(f, "    see: {reference}")?;
            }
        }
        Ok(())
    }
}

/// Parses one rule file, checking everything the engine depends on.
fn parse_rule(file: &str, source: &str) -> Result<Rule, RuleError> {
    let fail = |problem: String| RuleError {
        file: file.to_owned(),
        problem,
    };

    let raw: RuleFile = serde_json::from_str(source)
        .map_err(|err| fail(format!("could not be parsed as a rule file: {err}")))?;

    if raw.schema_version != SCHEMA_VERSION {
        return Err(fail(format!(
            "rule schema version {} is not supported by this build, which understands \
             {SCHEMA_VERSION}. A rule written for another schema must be migrated rather \
             than reinterpreted.",
            raw.schema_version
        )));
    }
    if raw.id.trim().is_empty() {
        return Err(fail("has an empty id".to_owned()));
    }
    if raw.title.trim().is_empty() {
        return Err(fail(format!("rule `{}` has an empty title", raw.id)));
    }
    // A rationale is what a reviewer reads next to a finding, so an empty one makes the
    // finding unarguable. A sentence is the floor, not a style preference.
    if raw.rationale.trim().len() < 40 {
        return Err(fail(format!(
            "rule `{}` has a rationale of {} characters: it has to explain why the pattern \
             is a bug and why general Rust tooling misses it",
            raw.id,
            raw.rationale.trim().len()
        )));
    }
    if raw.remediation.trim().is_empty() {
        return Err(fail(format!(
            "rule `{}` has no remediation; a finding that does not say what to do instead \
             is not actionable",
            raw.id
        )));
    }
    if raw.examples.triggers.trim().is_empty() || raw.examples.clean.trim().is_empty() {
        return Err(fail(format!(
            "rule `{}` needs both examples: one that must trigger it and one that must not",
            raw.id
        )));
    }

    Ok(Rule {
        id: raw.id,
        title: raw.title,
        severity: raw.severity,
        rationale: raw.rationale.trim().to_owned(),
        remediation: raw.remediation.trim().to_owned(),
        references: raw.references,
        triggers: raw.examples.triggers,
        clean: raw.examples.clean,
        heuristic: raw.heuristic,
        file: file.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "schema_version": 1,
        "id": "x-y",
        "title": "A rule",
        "severity": "high",
        "rationale": "This explains why the pattern is a bug and why nothing else catches it.",
        "remediation": "Do the safe thing.",
        "examples": { "triggers": "fn a() {}", "clean": "fn b() {}" }
    }"#;

    #[test]
    fn a_valid_rule_loads() {
        let (set, errors) = RuleSet::from_sources(&["x-y.json"], &[VALID]);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(set.len(), 1);
        let rule = set.get("x-y").expect("the rule should be present");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.file, "x-y.json");
    }

    #[test]
    fn an_unsupported_schema_version_is_refused_by_name() {
        let source = VALID.replace("\"schema_version\": 1", "\"schema_version\": 99");
        let (set, errors) = RuleSet::from_sources(&["x-y.json"], &[source.as_str()]);
        assert!(set.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].problem.contains("99"), "{errors:?}");
        assert!(errors[0].problem.contains("migrated"), "{errors:?}");
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let (set, errors) = RuleSet::from_sources(&["a.json", "b.json"], &[VALID, VALID]);
        assert_eq!(set.len(), 1, "the first one is kept");
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].problem.contains("duplicate rule id"),
            "{errors:?}"
        );
    }

    #[test]
    fn a_thin_rationale_is_refused() {
        let source = VALID.replace(
            "This explains why the pattern is a bug and why nothing else catches it.",
            "It is bad.",
        );
        let (_, errors) = RuleSet::from_sources(&["x-y.json"], &[source.as_str()]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].problem.contains("rationale"), "{errors:?}");
    }

    #[test]
    fn missing_examples_are_refused() {
        let source = VALID.replace(r#""triggers": "fn a() {}"#, r#""triggers": ""#);
        let (_, errors) = RuleSet::from_sources(&["x-y.json"], &[source.as_str()]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].problem.contains("both examples"), "{errors:?}");
    }

    #[test]
    fn an_unknown_severity_is_refused_with_the_allowed_set() {
        // The rejection comes from the deserializer, whose message already names the
        // value it saw and every value it accepts, so this asserts the message a reader
        // actually gets rather than a second one written here.
        let source = VALID.replace(r#""severity": "high""#, r#""severity": "spicy""#);
        let (_, errors) = RuleSet::from_sources(&["x-y.json"], &[source.as_str()]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].problem.contains("spicy"), "{errors:?}");
        assert!(errors[0].problem.contains("critical"), "{errors:?}");
        assert!(errors[0].problem.contains("low"), "{errors:?}");
    }

    #[test]
    fn a_heuristic_rule_must_say_so() {
        let source = VALID.replace(
            r#""title": "A rule","#,
            r#""title": "A rule", "heuristic": true,"#,
        );
        let (set, errors) = RuleSet::from_sources(&["x-y.json"], &[source.as_str()]);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(set.get("x-y").expect("loaded").heuristic);

        let (set, errors) = RuleSet::from_sources(&["x-y.json"], &[VALID]);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            !set.get("x-y").expect("loaded").heuristic,
            "structural rules are precise by default"
        );
    }

    #[test]
    fn the_embedded_rules_load() {
        let (set, errors) = RuleSet::embedded();
        assert!(errors.is_empty(), "{errors:#?}");
        assert!(!set.is_empty(), "this crate ships rules");
    }
}
