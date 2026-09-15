//! Rendering a budget: for a human, and for a program.
//!
//! Every render — text or JSON — carries the same disclaimer as the numbers, because
//! the failure mode of an estimator is not being wrong, it is being *believed*: a count
//! labelled "instructions" that a reader takes for a CPU prediction is worse than no
//! count at all. The text form says what it is in its header; the JSON form says it in a
//! field of its own, so a consumer has to ignore something explicit rather than infer
//! something wrong.

use core::fmt;
use core::str::FromStr;

use serde_json::{json, Value};

use crate::estimate::Budget;

/// How a budget is rendered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable.
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
}

impl FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "text" | "human" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            other => Err(format!(
                "unknown format `{other}`; expected one of: text, json"
            )),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Text => "text",
            Format::Json => "json",
        })
    }
}

/// The schema of the JSON output, bumped when a field changes meaning.
pub const JSON_SCHEMA_VERSION: u32 = 1;

/// What the numbers are, said once, so both renderings say the same thing.
pub const WHAT_THIS_IS: &str = "Wasm instructions in the static call tree: a structural \
measurement, not a CPU prediction. The network meters host calls and instruction types \
at its own weights, and charges for work this count does not include.";

impl Budget {
    /// Renders the budget in `format`.
    pub fn render(&self, format: Format) -> String {
        match format {
            Format::Text => self.render_text(),
            Format::Json => self.render_json(),
        }
    }

    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}\n", self.path));
        out.push_str(&format!(
            "  {} bytes, {} host import(s), {} function(s) defined, {} exported function(s)\n",
            self.bytes,
            self.imports,
            self.functions,
            self.entries.len()
        ));
        out.push_str(&format!("  note: {WHAT_THIS_IS}\n\n"));

        if self.entries.is_empty() {
            out.push_str("no exported functions\n");
            return out;
        }

        let width = self
            .entries
            .iter()
            .map(|entry| entry.name.len())
            .max()
            .unwrap_or_default();

        for entry in &self.entries {
            let bound = if entry.is_exact() {
                "exact".to_owned()
            } else {
                format!(
                    "at least ({} in the way)",
                    entry
                        .unbounded
                        .iter()
                        .map(|reason| reason.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            out.push_str(&format!(
                "  {:width$}  {:>8} instructions  {bound}\n",
                entry.name,
                entry.instructions,
                width = width
            ));
            out.push_str(&format!(
                "  {:width$}  {} function(s) reached, {} host call(s)\n",
                "",
                entry.functions,
                entry.host_calls_total,
                width = width
            ));
            for reason in &entry.unbounded {
                out.push_str(&format!(
                    "  {:width$}    no upper bound: {}: {}\n",
                    "",
                    reason.as_str(),
                    reason.explanation(),
                    width = width
                ));
            }
        }

        let unbounded = self.unbounded_entries();
        out.push_str(&format!(
            "\n{} of {} exported function(s) can be bounded exactly\n",
            self.entries.len() - unbounded,
            self.entries.len()
        ));
        if unbounded > 0 {
            out.push_str(&format!(
                "{} cannot: the count shown for those is a lower bound, not an upper one\n",
                unbounded
            ));
        }
        if !self.other_exports.is_empty() {
            out.push_str(&format!(
                "also exported (not functions): {}\n",
                self.other_exports.join(", ")
            ));
        }
        out
    }

    fn render_json(&self) -> String {
        let document = json!({
            "schema_version": JSON_SCHEMA_VERSION,
            "tool": {
                "name": crate::TOOL_NAME,
                "version": crate::VERSION,
            },
            "what_this_is": WHAT_THIS_IS,
            "module": {
                "path": self.path,
                "bytes": self.bytes,
                "imports": self.imports,
                "functions": self.functions,
                "other_exports": self.other_exports,
            },
            "summary": {
                "exported_functions": self.entries.len(),
                "exactly_bounded": self.entries.len() - self.unbounded_entries(),
                "lower_bounds_only": self.unbounded_entries(),
            },
            "entrypoints": self.entries.iter().map(|entry| json!({
                "name": entry.name,
                "instructions": entry.instructions,
                "exact": entry.is_exact(),
                "unbounded": entry.unbounded.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
                "unbounded_reasons": entry.unbounded.iter().map(|reason| json!({
                    "reason": reason.as_str(),
                    "explanation": reason.explanation(),
                })).collect::<Vec<_>>(),
                "functions_reached": entry.functions,
                "host_calls_total": entry.host_calls_total,
                "host_calls": entry.host_calls,
                "loops": entry.loops,
                "indirect_calls": entry.indirect_calls,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_owned())
    }

    /// The JSON document as a value, for callers that would rather not re-parse.
    pub fn to_value(&self) -> Value {
        serde_json::from_str(&self.render_json()).unwrap_or(Value::Null)
    }
}
