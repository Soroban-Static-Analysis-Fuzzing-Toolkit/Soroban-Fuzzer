//! What a detector produces: a place in the source, and something to say about it.

use core::fmt;

use serde::Serialize;

use crate::rules::Rule;
use crate::severity::Severity;
use crate::source::Location;

/// One thing a detector found.
///
/// A finding carries no severity or rationale of its own: those come from its
/// [`Rule`], so a rule's severity cannot drift between its metadata and a detector.
/// What a finding adds is *where* and *what specifically*, which is the part that
/// cannot be centralised.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// The id of the rule that produced it.
    pub rule: String,
    /// One-line description of the pattern, naming the specifics of this occurrence.
    pub message: String,
    /// How to fix it, from the rule's metadata.
    pub remediation: String,
    /// The file it was found in, as it was given on the command line.
    pub file: String,
    /// Where it is: byte span, line and column.
    pub location: Location,
    /// The line as it appears in the file, whitespace-trimmed, for a terminal report.
    pub source_line: String,
}

impl Finding {
    /// Builds a finding, taking severity-independent text from its rule.
    pub(crate) fn new(
        rule: &Rule,
        file: &str,
        source_line: String,
        location: Location,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule: rule.id.clone(),
            message: message.into(),
            remediation: rule.remediation.clone(),
            file: file.to_owned(),
            location,
            source_line,
        }
    }

    /// The severity of the rule behind this finding.
    pub fn severity(&self, rules: &crate::rules::RuleSet) -> Severity {
        rules
            .get(&self.rule)
            .map(|rule| rule.severity)
            .unwrap_or(Severity::Info)
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}: {}",
            self.file,
            self.location.start.line,
            self.location.start.column,
            self.rule,
            self.message
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceFile;

    fn rule() -> Rule {
        Rule {
            id: "test-rule".to_owned(),
            title: "A test rule".to_owned(),
            severity: Severity::High,
            rationale: "Because.".to_owned(),
            remediation: "Do the other thing.".to_owned(),
            references: Vec::new(),
            triggers: String::new(),
            clean: String::new(),
            heuristic: false,
            file: "test-rule.json".to_owned(),
        }
    }

    #[test]
    fn a_finding_reads_as_file_line_column_rule_and_message() {
        let file = SourceFile::parse("src/lib.rs", "fn f() {}\n".to_owned()).unwrap();
        let item = &file.ast.items[0];
        let finding = Finding::new(
            &rule(),
            &file.display_path(),
            "fn f() {}".to_owned(),
            file.location(syn::spanned::Spanned::span(item)),
            "something specific",
        );
        assert_eq!(
            finding.to_string(),
            "src/lib.rs:1:1: test-rule: something specific"
        );
    }
}
