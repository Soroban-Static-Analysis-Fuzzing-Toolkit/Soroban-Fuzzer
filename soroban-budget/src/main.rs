//! The `soroban-budget` command-line interface.
//!
//! # Exit status
//!
//! | Status | Means |
//! | --- | --- |
//! | `0` | The module was read, and nothing crossed a gate that was asked for |
//! | `1` | An entrypoint crossed `--fail-over`, or could not be bounded under `--fail-unbounded` |
//! | `2` | The estimator could not run: bad arguments, or a file that is not a module |
//!
//! # Gates
//!
//! Everything this reports is a fact about the module, and facts do not fail builds on
//! their own. Two flags turn the facts into a gate, and neither is on by default because
//! the right threshold is a property of the contract and its callers rather than of this
//! tool:
//!
//! * `--fail-over N` fails the run when an entrypoint's instruction count exceeds `N`.
//!   Only an exact count is compared: a lower bound that exceeds the threshold has
//!   certainly done so, and a lower bound that does not might still have.
//! * `--fail-unbounded` fails the run when any entrypoint cannot be bounded exactly,
//!   which is how a team with no unbounded entrypoints keeps it that way.
//!
//! A run that finds something is `1`, not `2`: the module was read and the answer is
//! "yes, this one". `2` means the question could not be asked.

use std::path::PathBuf;
use std::process::ExitCode;

use soroban_budget::{estimate, Format, Module, TOOL_NAME, VERSION};

const USAGE: &str = "\
soroban-budget — static resource-budget estimation for compiled Soroban contracts

USAGE:
    soroban-budget [OPTIONS] <MODULE.wasm>

    MODULE.wasm is a compiled contract, as `cargo build --target wasm32v1-none
    --release` produces it. The estimator reads it; it does not deploy or run it.

OPTIONS:
    -f, --format <FORMAT>      text (default) or json
        --entry <NAME>         report only this exported function; may be repeated
        --fail-over <N>        exit 1 when an exactly counted entrypoint needs more
                               than N Wasm instructions
        --fail-unbounded       exit 1 when any entrypoint cannot be bounded exactly
    -h, --help                 print this help and exit
    -V, --version              print the version and exit

EXIT STATUS:
    0  the module was read, and nothing crossed a gate
    1  an entrypoint crossed a gate that was asked for
    2  the estimator could not run (bad arguments, or an unreadable module)

EXAMPLES:
    soroban-budget contract.wasm
    soroban-budget --format json --fail-over 20000 contract.wasm
    soroban-budget --entry transfer --entry approve contract.wasm
";

/// What the command line asked for.
#[derive(Debug)]
struct Options {
    path: PathBuf,
    format: Format,
    entries: Vec<String>,
    fail_over: Option<usize>,
    fail_unbounded: bool,
    action: Action,
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Estimate,
    Help,
    Version,
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
        Action::Estimate => run(&options),
    }
}

/// Parses the arguments, rejecting anything it does not understand.
fn parse(arguments: &[String]) -> Result<Options, String> {
    let mut path: Option<PathBuf> = None;
    let mut format = Format::Text;
    let mut entries = Vec::new();
    let mut fail_over = None;
    let mut fail_unbounded = false;
    let mut action = Action::Estimate;
    let mut only_paths = false;

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        index += 1;

        if only_paths {
            set_path(&mut path, argument)?;
            continue;
        }
        if argument == "--" {
            only_paths = true;
            continue;
        }

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
            "-h" | "--help" => action = Action::Help,
            "-V" | "--version" => action = Action::Version,
            "-f" | "--format" => format = value("--format")?.parse()?,
            "--entry" => entries.push(value("--entry")?),
            "--fail-over" => {
                let raw = value("--fail-over")?;
                fail_over = Some(raw.trim().parse::<usize>().map_err(|_| {
                    format!("`--fail-over` needs a number of instructions, got `{raw}`")
                })?);
            }
            "--fail-unbounded" => fail_unbounded = true,
            _ if flag.starts_with('-') => return Err(format!("unrecognised option `{flag}`")),
            _ => set_path(&mut path, argument)?,
        }
    }

    if action == Action::Estimate && path.is_none() {
        return Err("no module to estimate".to_owned());
    }

    Ok(Options {
        path: path.unwrap_or_default(),
        format,
        entries,
        fail_over,
        fail_unbounded,
        action,
    })
}

/// Records the module path, refusing a second one.
fn set_path(path: &mut Option<PathBuf>, argument: &str) -> Result<(), String> {
    if path.is_some() {
        return Err(format!(
            "one module at a time: `{argument}` is a second path"
        ));
    }
    *path = Some(PathBuf::from(argument));
    Ok(())
}

/// Estimates a module and applies the gates.
fn run(options: &Options) -> ExitCode {
    let module = match Module::load(&options.path) {
        Ok(module) => module,
        Err(error) => {
            eprintln!("{TOOL_NAME}: {error}");
            return ExitCode::from(2);
        }
    };

    let mut budget = estimate(&module);

    if !options.entries.is_empty() {
        let wanted = &options.entries;
        let missing = wanted
            .iter()
            .filter(|name| budget.entry(name).is_none())
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            eprintln!(
                "{TOOL_NAME}: {} is not exported by this module: {}",
                if missing.len() == 1 {
                    "this name"
                } else {
                    "these names"
                },
                missing.join(", ")
            );
            return ExitCode::from(2);
        }
        budget
            .entries
            .retain(|entry| wanted.iter().any(|name| name == &entry.name));
    }

    // The report is the only thing on stdout, so a pipeline can redirect it.
    println!("{}", budget.render(options.format));

    let mut failed = false;

    if let Some(limit) = options.fail_over {
        let over = budget
            .entries
            .iter()
            .filter(|entry| entry.is_exact() && entry.instructions > limit)
            .map(|entry| format!("{} ({} instructions)", entry.name, entry.instructions))
            .collect::<Vec<_>>();
        if !over.is_empty() {
            eprintln!(
                "{TOOL_NAME}: over the `--fail-over {limit}` gate: {}",
                over.join(", ")
            );
            failed = true;
        }
    }

    if options.fail_unbounded {
        let unbounded = budget
            .entries
            .iter()
            .filter(|entry| !entry.is_exact())
            .map(|entry| {
                format!(
                    "{} ({})",
                    entry.name,
                    entry
                        .unbounded
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect::<Vec<_>>();
        if !unbounded.is_empty() {
            eprintln!(
                "{TOOL_NAME}: `--fail-unbounded` and {} cannot be bounded exactly: {}",
                if unbounded.len() == 1 {
                    "this entrypoint".to_owned()
                } else {
                    format!("{} entrypoints", unbounded.len())
                },
                unbounded.join(", ")
            );
            failed = true;
        }
    }

    if options.format != Format::Text {
        eprintln!(
            "{TOOL_NAME}: {} exported function(s), {} exactly bounded, {} lower bound(s) only",
            budget.entries.len(),
            budget
                .entries
                .iter()
                .filter(|entry| entry.is_exact())
                .count(),
            budget.unbounded_entries()
        );
    }

    ExitCode::from(if failed { 1 } else { 0 })
}
