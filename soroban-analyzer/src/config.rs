//! Reading a project's configuration: the choices a team makes once, in a file.
//!
//! A command line is for what changes between runs; a file is for what is true of a
//! repository. A team adopting this analyser has a gate, a report format, a baseline and
//! one or two rules they have decided not to enforce yet, and all four of those are the
//! second kind. `.soroban-analyzer.json` is where they go.
//!
//! # Why JSON, and why so few keys
//!
//! JSON because it is already a dependency and because it is the same document the
//! analyser emits — one format for what goes in and what comes out is one format to
//! document. The key set is small on purpose:
//!
//! * `severity`, `format`, `paths` and `baseline` are the command line's own flags,
//!   written down. The command line wins over the file, so a one-off run does not have
//!   to edit a repository file to be stricter than it.
//! * `disabled_rules` is the only thing there is no flag for, and it exists because a
//!   team sometimes needs to stop enforcing one rule while it decides whether the rule
//!   is right. A disabled rule is **counted and reported**, exactly like an `allow`
//!   marker, so turning one off is visible in every run's output rather than a silent
//!   change to what "clean" means.
//!
//! There is deliberately no key for changing a rule's severity. A detector cannot
//! re-grade a pattern it did not invent, and a configuration file cannot either: the
//! severity of a pattern is a statement about Soroban that belongs with the rule's
//! rationale, in review, under version control in this repository — not in a downstream
//! project's preferences. A rule that is wrong is wrong for everybody; until that is
//! settled, disable it and say so.
//!
//! # Failing loudly
//!
//! An unknown key is an error, not something to skip. `"severty": "medium"` that is
//! quietly ignored is a CI job running at a gate nobody chose, which is the same failure
//! the command line's unknown-flag rule prevents. Unknown rule ids are errors for the
//! matching reason: a disabled rule that does not exist is a typo that leaves the rule
//! enabled while its author believes otherwise.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::report::Format;
use crate::rules::RuleSet;
use crate::severity::Severity;

/// The name this analyser looks for when `--config` is not given.
pub const CONFIG_FILE_NAME: &str = ".soroban-analyzer.json";

/// The configuration schema's version, bumped when a key changes meaning.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Just the version, so that a file written for a newer analyser is reported as exactly
/// that rather than as a pile of keys this build does not recognise.
#[derive(Debug, Deserialize)]
struct VersionProbe {
    /// The version the file claims to be written against.
    schema_version: u32,
}

/// The error to report for a configuration that would not parse.
///
/// A future file may legitimately carry keys this build has never heard of, and the
/// useful sentence about it is the version it was written for; for anything else the
/// underlying parse error, with its own line and column, is the useful sentence.
fn unreadable(text: &str, error: serde_json::Error) -> ConfigError {
    match serde_json::from_str::<VersionProbe>(text) {
        Ok(probe) if probe.schema_version != CONFIG_SCHEMA_VERSION => {
            version_error(probe.schema_version)
        }
        _ => ConfigError(format!("not a readable configuration: {error}")),
    }
}

/// What to say about a configuration written for another version.
fn version_error(version: u32) -> ConfigError {
    ConfigError(format!(
        "this configuration is schema_version {version}, and this build reads version \
         {CONFIG_SCHEMA_VERSION}"
    ))
}

/// Why a configuration file could not be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// The file as it is written, before it is resolved into a [`Config`].
///
/// Every field is optional so that a file states only what it disagrees with. `deny_unknown_fields`
/// is what turns a typo into an error.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    /// The schema version this file was written against.
    schema_version: u32,
    /// What to analyse when no path is given on the command line.
    #[serde(default)]
    paths: Option<Vec<String>>,
    /// The default report format.
    #[serde(default)]
    format: Option<String>,
    /// The default exit gate.
    #[serde(default)]
    severity: Option<String>,
    /// The baseline to excuse known findings with, relative to this file.
    #[serde(default)]
    baseline: Option<String>,
    /// Rules this project does not enforce.
    #[serde(default)]
    disabled_rules: Vec<String>,
}

/// A resolved configuration: what a file asked for, checked against what exists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// Paths to analyse, relative to the configuration file's directory.
    pub paths: Option<Vec<PathBuf>>,
    /// The default report format.
    pub format: Option<Format>,
    /// The default exit gate.
    pub severity: Option<Severity>,
    /// The baseline file, resolved to a path on disk.
    pub baseline: Option<PathBuf>,
    /// Rules not to enforce.
    pub disabled_rules: Vec<String>,
    /// Where this configuration came from, for messages. `None` when it is a default.
    pub source: Option<PathBuf>,
}

impl Config {
    /// Parses a configuration file's text.
    ///
    /// `rules` is the set of rules that exist, so that a `disabled_rules` entry naming
    /// nothing can be refused rather than accepted as a rule that will never match.
    /// `directory` is what relative paths in the file are relative *to*: the directory
    /// holding the file, not the directory the process happens to be in, so that a
    /// configuration means the same thing however it is run.
    pub fn parse(text: &str, directory: &Path, rules: &RuleSet) -> Result<Self, ConfigError> {
        let file: ConfigFile =
            serde_json::from_str(text).map_err(|error| unreadable(text, error))?;
        if file.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(version_error(file.schema_version));
        }

        let format = file
            .format
            .as_deref()
            .map(str::parse::<Format>)
            .transpose()
            .map_err(ConfigError)?;

        let severity = file
            .severity
            .as_deref()
            .map(str::parse::<Severity>)
            .transpose()
            .map_err(ConfigError)?;

        let unknown = file
            .disabled_rules
            .iter()
            .filter(|id| rules.get(id.trim()).is_none())
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(ConfigError(format!(
                "`disabled_rules` names {} this build does not have: {}; run `{tool} --list` \
                 for the rules that exist",
                if unknown.len() == 1 {
                    "a rule"
                } else {
                    "rules"
                },
                unknown.join(", "),
                tool = crate::TOOL_NAME,
            )));
        }

        let resolve = |path: &str| {
            let path = Path::new(path);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                directory.join(path)
            }
        };

        Ok(Self {
            paths: file
                .paths
                .map(|paths| paths.iter().map(|path| resolve(path)).collect()),
            format,
            severity,
            baseline: file.baseline.as_deref().map(resolve),
            disabled_rules: file
                .disabled_rules
                .iter()
                .map(|id| id.trim().to_owned())
                .collect(),
            source: None,
        })
    }

    /// Reads a configuration file, naming it in any error.
    pub fn read(path: &Path, rules: &RuleSet) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| ConfigError(format!("{}: {error}", path.display())))?;
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        let mut config = Self::parse(&text, directory, rules)
            .map_err(|error| ConfigError(format!("{}: {error}", path.display())))?;
        config.source = Some(path.to_path_buf());
        Ok(config)
    }

    /// Reads `.soroban-analyzer.json` from `directory`, if there is one.
    ///
    /// Discovery is deliberately shallow: the configuration belongs to the directory a
    /// command is run from, and searching upward would mean an analyser run in a
    /// subdirectory silently picking up a parent's gate. A configuration that is not in
    /// front of you is one whose effect you cannot predict, so `--config` is how a file
    /// elsewhere is named.
    pub fn discover(directory: &Path, rules: &RuleSet) -> Result<Option<Self>, ConfigError> {
        let path = directory.join(CONFIG_FILE_NAME);
        if !path.is_file() {
            return Ok(None);
        }
        Self::read(&path, rules).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::load_embedded_rules;

    fn rules() -> RuleSet {
        load_embedded_rules().expect("this build's rules load")
    }

    #[test]
    fn a_file_stating_nothing_is_valid() {
        let config = Config::parse(r#"{"schema_version": 1}"#, Path::new("/repo"), &rules())
            .expect("an empty configuration is a legitimate one");
        assert_eq!(config, Config::default());
    }

    #[test]
    fn the_flags_are_read_and_checked() {
        let config = Config::parse(
            r#"{
                "schema_version": 1,
                "format": "sarif",
                "severity": "medium",
                "paths": ["src", "tests"],
                "baseline": ".soroban-baseline.json",
                "disabled_rules": ["soroban-read-budget"]
            }"#,
            Path::new("/repo"),
            &rules(),
        )
        .expect("the fixture is a valid configuration");

        assert_eq!(config.format, Some(Format::Sarif));
        assert_eq!(config.severity, Some(Severity::Medium));
        assert_eq!(config.disabled_rules, vec!["soroban-read-budget"]);
        assert_eq!(
            config.paths,
            Some(vec![
                PathBuf::from("/repo/src"),
                PathBuf::from("/repo/tests")
            ]),
            "paths resolve against the configuration file's directory"
        );
        assert_eq!(
            config.baseline,
            Some(PathBuf::from("/repo/.soroban-baseline.json"))
        );
    }

    #[test]
    fn an_unknown_key_is_an_error_rather_than_a_typo_that_silently_does_nothing() {
        let error = Config::parse(
            r#"{"schema_version": 1, "severty": "medium"}"#,
            Path::new("/repo"),
            &rules(),
        )
        .expect_err("a misspelled key must not be ignored");
        assert!(error.to_string().contains("severty"), "{error}");
    }

    #[test]
    fn a_rule_that_does_not_exist_cannot_be_disabled() {
        let error = Config::parse(
            r#"{"schema_version": 1, "disabled_rules": ["soroban-imaginary-rule"]}"#,
            Path::new("/repo"),
            &rules(),
        )
        .expect_err("disabling a rule that does not exist is a typo, not a preference");
        assert!(
            error.to_string().contains("soroban-imaginary-rule"),
            "{error}"
        );
    }

    #[test]
    fn a_bad_severity_or_format_names_what_is_allowed() {
        let severity = Config::parse(
            r#"{"schema_version": 1, "severity": "spicy"}"#,
            Path::new("/repo"),
            &rules(),
        )
        .expect_err("it is not a severity");
        assert!(severity.to_string().contains("critical"), "{severity}");

        let format = Config::parse(
            r#"{"schema_version": 1, "format": "yaml"}"#,
            Path::new("/repo"),
            &rules(),
        )
        .expect_err("it is not a format");
        assert!(format.to_string().contains("sarif"), "{format}");
    }

    #[test]
    fn a_newer_schema_is_refused_with_the_version_named() {
        let error = Config::parse(r#"{"schema_version": 42}"#, Path::new("/repo"), &rules())
            .expect_err("a configuration written for a newer analyser is not this one's");
        assert!(error.to_string().contains("42"), "{error}");
    }

    #[test]
    fn discovery_finds_a_file_and_says_nothing_when_there_is_none() {
        let directory = std::env::temp_dir().join("soroban-analyzer-config-discovery");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the scratch directory can be made");

        assert!(Config::discover(&directory, &rules())
            .expect("a missing file is not an error")
            .is_none());

        std::fs::write(
            directory.join(CONFIG_FILE_NAME),
            r#"{"schema_version": 1, "severity": "low"}"#,
        )
        .expect("the file can be written");
        let found = Config::discover(&directory, &rules())
            .expect("the file parses")
            .expect("the file was found");
        assert_eq!(found.severity, Some(Severity::Low));
        assert_eq!(found.source, Some(directory.join(CONFIG_FILE_NAME)));

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_error_names_the_file_it_came_from() {
        let directory = std::env::temp_dir().join("soroban-analyzer-config-error");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the scratch directory can be made");
        let path = directory.join(CONFIG_FILE_NAME);
        std::fs::write(&path, r#"{"schema_version": 1, "nonsense": true}"#)
            .expect("the file can be written");

        let error = Config::read(&path, &rules()).expect_err("the key is unknown");
        assert!(
            error.to_string().contains(CONFIG_FILE_NAME),
            "a configuration failure must say which file: {error}"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }
}
