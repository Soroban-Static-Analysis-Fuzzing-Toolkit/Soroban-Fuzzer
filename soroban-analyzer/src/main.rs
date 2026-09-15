//! The `soroban-analyze` command-line interface.
//!
//! # Exit status, and why it is what it is
//!
//! | Status | Means |
//! | --- | --- |
//! | `0` | Nothing at or above the gate, and every file was analysed |
//! | `1` | Something at or above the gate, or a file that could not be analysed |
//! | `2` | The analyser could not run: bad arguments, unreadable rules, a bad configuration |
//!
//! The gate defaults to `high`, so a first run over a real contract reports without
//! failing the build; `--severity medium` is how a team tightens it once the findings at
//! the top are dealt with. A file that failed to parse exits `1` rather than `0` on
//! purpose: a run that skipped half a tree has not answered the question it was asked,
//! and a silent `0` is how a tool gets trusted for something it did not do.
//!
//! # Adopting on a tree that already has findings
//!
//! `--baseline FILE` reads a recorded set of findings and stops failing on them, and
//! `--write-baseline` records the current run into that file, so the first run on an
//! existing contract is:
//!
//! ```text
//! soroban-analyze --baseline .soroban-baseline.json --write-baseline .
//! ```
//!
//! which exits `0` and writes down what it saw. From then on only new findings gate, and
//! the exceptions are a file in the diff rather than a habit. Baseline entries that match
//! nothing are counted and reported, so a baseline cannot quietly outlive its code.
//!
//! # Where the settings come from
//!
//! Values are resolved in one order, and the command line is always the most specific:
//! a flag beats `.soroban-analyzer.json` in the current directory (or the file named by
//! `--config`), which beats the defaults. A one-off run therefore never has to edit a
//! repository file to be stricter than it, and a repository's settings do not have to be
//! retyped into CI. See [`soroban_analyzer::config`] for what the file may say.
//!
//! Usage is hand-parsed rather than pulled from a crate. The surface is ten flags, and a
//! security tool that a contributor runs on a source tree should have as few
//! dependencies as it can.

use std::path::PathBuf;
use std::process::ExitCode;

use soroban_analyzer::{
    analyze_paths, detectors, load_embedded_rules, Analyzer, Baseline, Config, Format, Report,
    Severity, TOOL_NAME, VERSION,
};

const USAGE: &str = "\
soroban-analyze — static analysis for Soroban smart contracts

USAGE:
    soroban-analyze [OPTIONS] [PATH]...

    PATH may be a file or a directory. Directories are searched recursively for .rs
    files; `target`, `.git`, `node_modules`, `.cargo` and `vendor` are skipped. With no
    PATH, the paths in the configuration are used, and failing that the current
    directory is analysed.

OPTIONS:
    -f, --format <FORMAT>      text (default), json, or sarif
    -s, --severity <LEVEL>     exit non-zero at or above: info, low, medium, high
                               (default), critical
    -j, --jobs <N>             threads to check files with (default: one per core)
        --config <FILE>        a configuration file, instead of ./.soroban-analyzer.json
        --baseline <FILE>      do not fail on findings recorded in this file
        --write-baseline       record this run's findings in the baseline file first,
                               which is how a tree with existing findings is adopted
    -l, --list                 list the rules and exit
        --explain <RULE-ID>    explain one rule, with the source that must and must not
                               trigger it, and exit
    -h, --help                 print this help and exit
    -V, --version              print the version and exit

EXIT STATUS:
    0  nothing to report, and everything was analysed
    1  a finding at or above the gate, or a file that could not be analysed
    2  the analyser could not run (bad arguments, unreadable rules or configuration)

EXAMPLES:
    soroban-analyze src/
    soroban-analyze --format sarif --severity medium . > results.sarif
    soroban-analyze --baseline .soroban-baseline.json --write-baseline .
    soroban-analyze --explain soroban-missing-require-auth
";

/// What the command line asked for.
#[derive(Debug)]
struct Options {
    paths: Vec<PathBuf>,
    /// `None` when the flag was not given, so the configuration can speak.
    format: Option<Format>,
    /// `None` when the flag was not given, for the same reason.
    severity: Option<Severity>,
    /// `None` uses one thread per available core.
    jobs: Option<usize>,
    config: Option<PathBuf>,
    /// `None` when the flag was not given, so the configuration can name one.
    baseline: Option<PathBuf>,
    write_baseline: bool,
    action: Action,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Analyze,
    Help,
    Version,
    List,
    Explain(String),
}

fn main() -> ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();

    let options = match parse(&arguments) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{TOOL_NAME}: {message}");
            eprintln!("try `{TOOL_NAME} --help`");
            return ExitCode::from(2);
        }
    };

    match options.action {
        Action::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Action::Version => {
            println!("{TOOL_NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Action::List => list_rules(),
        Action::Explain(ref id) => explain(id),
        Action::Analyze => analyze(&options),
    }
}

/// Parses the arguments, rejecting anything it does not understand.
///
/// Unknown flags are an error rather than ignored: a typo in `--severity` that silently
/// left the gate at its default is a CI job that passes when it should not.
fn parse(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options {
        paths: Vec::new(),
        format: None,
        severity: None,
        jobs: None,
        config: None,
        baseline: None,
        write_baseline: false,
        action: Action::Analyze,
    };
    // Set once `--` has been seen, after which everything is a path.
    let mut only_paths = false;

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;

        if only_paths {
            options.paths.push(PathBuf::from(argument));
            continue;
        }
        if argument == "--" {
            only_paths = true;
            continue;
        }

        // `--flag=value` and `--flag value` are both accepted, because both are in the
        // wild and neither is worth an argument about.
        let (flag, inline) = match argument.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (argument, None),
        };

        let mut value = |name: &str| -> Result<String, String> {
            if let Some(value) = inline.clone() {
                return Ok(value);
            }
            let next = arguments
                .get(index)
                .ok_or_else(|| format!("{name} needs a value"))?
                .clone();
            index += 1;
            Ok(next)
        };

        match flag {
            "-h" | "--help" => options.action = Action::Help,
            "-V" | "--version" => options.action = Action::Version,
            "-l" | "--list" => options.action = Action::List,
            "--explain" => options.action = Action::Explain(value("--explain")?),
            "-f" | "--format" => options.format = Some(value("--format")?.parse()?),
            "-s" | "--severity" => options.severity = Some(value("--severity")?.parse()?),
            "-j" | "--jobs" => options.jobs = Some(parse_jobs(&value("--jobs")?)?),
            "--config" => options.config = Some(PathBuf::from(value("--config")?)),
            "--baseline" => options.baseline = Some(PathBuf::from(value("--baseline")?)),
            "--write-baseline" => options.write_baseline = true,
            _ if flag.starts_with('-') => {
                return Err(format!("unrecognised option `{flag}`"));
            }
            _ => options.paths.push(PathBuf::from(argument)),
        }
    }

    // Whether `--write-baseline` has a file to write is checked after the configuration
    // is read rather than here, because the configuration may be the thing naming it.
    Ok(options)
}

/// Parses `--jobs`, refusing zero rather than silently meaning "one".
fn parse_jobs(value: &str) -> Result<usize, String> {
    let jobs = value
        .trim()
        .parse::<usize>()
        .map_err(|_| format!("`--jobs` needs a number of threads, got `{value}`"))?;
    if jobs == 0 {
        return Err("`--jobs` must be at least 1; a run cannot use no threads".to_owned());
    }
    Ok(jobs)
}

/// How many threads a run uses when nothing says otherwise.
fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
}

/// Loads the rules, or reports why this build cannot run.
fn rules() -> Result<soroban_analyzer::RuleSet, ExitCode> {
    match load_embedded_rules() {
        Ok(rules) => Ok(rules),
        Err(errors) => {
            eprintln!("{TOOL_NAME}: this build's rules could not be loaded:");
            for error in errors {
                eprintln!("    {error}");
            }
            Err(ExitCode::from(2))
        }
    }
}

/// Runs the analyser over every path and renders one report.
fn analyze(options: &Options) -> ExitCode {
    let rules = match rules() {
        Ok(rules) => rules,
        Err(code) => return code,
    };
    let analyzer = Analyzer::new(detectors::all(), rules);

    // A detector whose rule is missing, or a rule nothing implements, means the binary
    // is not what it says it is. Refusing to run is the only honest response.
    let problems = analyzer.validate();
    if !problems.is_empty() {
        eprintln!("{TOOL_NAME}: this build is inconsistent:");
        for problem in problems {
            eprintln!("    {problem}");
        }
        return ExitCode::from(2);
    }

    let config = match resolve_config(options, analyzer.rules()) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{TOOL_NAME}: {message}");
            return ExitCode::from(2);
        }
    };

    // The command line wins `format` and `severity`; the configuration supplies what it
    // was not told. `paths` follows the same rule, with the current directory as the last
    // resort so that a bare `soroban-analyze` still does something predictable.
    let format = options.format.or(config.format).unwrap_or_default();
    let severity = options
        .severity
        .or(config.severity)
        .unwrap_or(Severity::High);
    let paths = if !options.paths.is_empty() {
        options.paths.clone()
    } else if let Some(configured) = &config.paths {
        configured.clone()
    } else {
        vec![PathBuf::from(".")]
    };
    let baseline_path = options.baseline.clone().or_else(|| config.baseline.clone());

    if options.write_baseline && baseline_path.is_none() {
        eprintln!(
            "{TOOL_NAME}: `--write-baseline` needs a file: pass `--baseline FILE`, or set \
             `baseline` in the configuration"
        );
        return ExitCode::from(2);
    }

    let (findings, suppressed, walk_problems) =
        analyze_paths(&analyzer, &paths, options.jobs.unwrap_or_else(default_jobs));

    // An unwritten baseline is the findings as they are; a written one is the same, and
    // applying it in the same run is the point — the adoption command exits `0` because
    // everything it found has just been recorded.
    let baseline = match (&baseline_path, options.write_baseline) {
        (Some(path), true) => {
            let baseline = Baseline::from_findings(&findings);
            if let Err(error) = std::fs::write(path, baseline.to_json()) {
                eprintln!("{TOOL_NAME}: {}: {error}", path.display());
                return ExitCode::from(2);
            }
            eprintln!(
                "{TOOL_NAME}: wrote {} baseline entr{} to {}",
                baseline.len(),
                if baseline.len() == 1 { "y" } else { "ies" },
                path.display()
            );
            Some(baseline)
        }
        (Some(path), false) => match std::fs::read_to_string(path) {
            Ok(text) => match Baseline::parse(&text) {
                Ok(baseline) => Some(baseline),
                Err(error) => {
                    eprintln!("{TOOL_NAME}: {}: {error}", path.display());
                    return ExitCode::from(2);
                }
            },
            Err(error) => {
                eprintln!("{TOOL_NAME}: {}: {error}", path.display());
                return ExitCode::from(2);
            }
        },
        (None, _) => None,
    };

    // Reported before the excusing happens, so the count is over everything the run
    // found: an entry that matches a finding the configuration now disables is still an
    // entry that matched something.
    if let Some(baseline) = &baseline {
        let stale = baseline.stale(&findings);
        if stale > 0 {
            eprintln!(
                "{TOOL_NAME}: {} baseline entr{} at {} match nothing in this run; re-write it \
                 with `--write-baseline`",
                stale,
                if stale == 1 { "y" } else { "ies" },
                baseline_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
            );
        }
    }

    let mut report = Report::new(
        findings,
        suppressed,
        walk_problems,
        analyzer.rules().clone(),
    );
    if let Some(baseline) = &baseline {
        report = report.with_baseline(baseline);
    }
    report = report.with_disabled_rules(&config.disabled_rules);

    // The report is the only thing on stdout: it is the artefact, and a caller piping
    // SARIF into a file should get SARIF and nothing else.
    println!("{}", report.render(format));
    if format != Format::Text {
        eprintln!(
            "{TOOL_NAME}: {} finding(s), {} suppressed, {} baselined, {} disabled, {} unanalysable",
            report.findings.len(),
            report.suppressed.len(),
            report.baselined.len(),
            report.disabled.len(),
            report.problems.len()
        );
    }

    ExitCode::from(u8::try_from(report.exit_code(severity)).unwrap_or(1))
}

/// Reads the configuration, from `--config` or from the current directory.
fn resolve_config(options: &Options, rules: &soroban_analyzer::RuleSet) -> Result<Config, String> {
    if let Some(path) = &options.config {
        return Config::read(path, rules).map_err(|error| error.to_string());
    }
    let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    Config::discover(&directory, rules)
        .map(|found| found.unwrap_or_default())
        .map_err(|error| error.to_string())
}

/// Prints the rules this build ships.
fn list_rules() -> ExitCode {
    let rules = match rules() {
        Ok(rules) => rules,
        Err(code) => return code,
    };

    let width = rules
        .iter()
        .map(|rule| rule.id.len())
        .max()
        .unwrap_or_default();
    for rule in rules.iter() {
        println!(
            "{:width$}  {:8}  {}",
            rule.id,
            rule.severity,
            rule.title,
            width = width
        );
    }
    println!("\n{} rule(s)", rules.len());
    ExitCode::SUCCESS
}

/// Prints one rule in full, including the fixtures the crate's tests run.
fn explain(id: &str) -> ExitCode {
    let rules = match rules() {
        Ok(rules) => rules,
        Err(code) => return code,
    };

    let Some(rule) = rules.get(id.trim()) else {
        eprintln!("{TOOL_NAME}: no rule with id `{id}`; try `{TOOL_NAME} --list`");
        return ExitCode::from(2);
    };

    println!("{}", rule.title);
    println!("  id:       {}", rule.id);
    println!("  severity: {}", rule.severity);
    if rule.heuristic {
        println!(
            "  precision: heuristic (the check matches on names or shapes, not on structure alone)"
        );
    }
    println!("\nwhy it is a bug\n{}", indent(&rule.rationale));
    println!("\nwhat to do instead\n{}", indent(&rule.remediation));
    if !rule.references.is_empty() {
        println!("\nreferences");
        for reference in &rule.references {
            println!("  {reference}");
        }
    }
    println!("\nsource that must trigger it\n{}", indent(&rule.triggers));
    println!("\nsource that must not trigger it\n{}", indent(&rule.clean));
    ExitCode::SUCCESS
}

/// Indents a block of text by four spaces, for reading under a heading.
fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("    {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
