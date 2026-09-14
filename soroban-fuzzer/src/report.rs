//! Failure journals, reports and run outcomes.
//!
//! Every action a fuzz run executes is recorded in a [`Journal`]. When a case
//! fails, proptest shrinks the sequence to a minimum and the journal of that final,
//! minimal case becomes the body of a [`FailureReport`]: the exact call sequence,
//! the resources each call consumed, what storage it touched, and what went wrong.

use core::fmt;
use std::fmt::Write as _;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::budget::{LimitBreach, ResourceUsage};
use crate::config::FuzzConfig;

/// What one contract invocation did, as recorded by the harness.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallRecord {
    /// Label supplied by the target when it made the call.
    pub label: String,
    /// `"ok"`, `"rejected: <error>"` or `"error: <host error>"`.
    pub outcome: String,
    /// Resources the invocation consumed.
    pub usage: ResourceUsage,
    /// Ledger entries the invocation wrote.
    pub writes: usize,
    /// Total tracked storage entries after the invocation.
    pub entries_after: usize,
    /// A network limit the invocation exceeded, if any.
    pub breach: Option<LimitBreach>,
}

/// One action of a fuzz case, plus every call it made.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StepRecord {
    /// Zero-based position of the action in the sequence.
    pub index: usize,
    /// Rendered description of the action.
    pub action: String,
    /// `"ok"`, `"rejected: …"`, `"violation: …"` or `"pending"`.
    pub outcome: String,
    /// Contract invocations made by this action, in order.
    pub calls: Vec<CallRecord>,
}

impl StepRecord {
    /// Resources consumed by this step, summed over its calls.
    pub fn usage(&self) -> ResourceUsage {
        let mut total = ResourceUsage::default();
        for call in &self.calls {
            total.instructions += call.usage.instructions;
            total.mem_bytes = total.mem_bytes.max(call.usage.mem_bytes);
            total.disk_read_entries = total
                .disk_read_entries
                .saturating_add(call.usage.disk_read_entries);
            total.memory_read_entries = total
                .memory_read_entries
                .saturating_add(call.usage.memory_read_entries);
            total.write_entries = total.write_entries.saturating_add(call.usage.write_entries);
            total.disk_read_bytes = total
                .disk_read_bytes
                .saturating_add(call.usage.disk_read_bytes);
            total.write_bytes = total.write_bytes.saturating_add(call.usage.write_bytes);
            total.contract_events_size_bytes = total
                .contract_events_size_bytes
                .saturating_add(call.usage.contract_events_size_bytes);
        }
        total
    }

    /// Ledger entries written across this step's calls.
    pub fn writes(&self) -> usize {
        self.calls.iter().map(|call| call.writes).sum()
    }

    /// The first breach recorded by this step, if any.
    pub fn breach(&self) -> Option<&LimitBreach> {
        self.calls.iter().find_map(|call| call.breach.as_ref())
    }
}

/// Why a case failed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureNote {
    /// Machine-readable category: `invariant`, `resource-limit`,
    /// `unexpected-error`, `unexpected-rejection` or `panic`.
    pub kind: String,
    /// Human-readable explanation.
    pub detail: String,
    /// Index of the action that failed, when the failure is attributable to one.
    pub step: Option<usize>,
}

/// Ordered record of everything a single fuzz case did.
///
/// The journal is reset at the start of every case, so after a run it holds the
/// final (minimized) failing case.
#[derive(Clone, Debug, Default)]
pub struct Journal {
    /// One record per action, in execution order.
    pub steps: Vec<StepRecord>,
    /// Set when the case failed.
    pub failure: Option<FailureNote>,
}

impl Journal {
    /// Starts a new case.
    pub fn reset(&mut self) {
        self.steps.clear();
        self.failure = None;
    }

    /// Records the start of an action.
    pub fn begin_step(&mut self, index: usize, action: String) {
        self.steps.push(StepRecord {
            index,
            action,
            outcome: "pending".to_owned(),
            calls: Vec::new(),
        });
    }

    /// Sets the outcome of the most recently started action.
    pub fn finish_step(&mut self, outcome: impl Into<String>) {
        if let Some(step) = self.steps.last_mut() {
            step.outcome = outcome.into();
        }
    }

    /// Records a contract invocation against the current action.
    pub fn push_call(&mut self, record: CallRecord) {
        if let Some(step) = self.steps.last_mut() {
            step.calls.push(record);
        } else {
            // A call made outside of any action (for example during setup):
            // attribute it to a synthetic step so it is not silently dropped.
            self.steps.push(StepRecord {
                index: 0,
                action: "<setup>".to_owned(),
                outcome: "ok".to_owned(),
                calls: vec![record],
            });
        }
    }

    /// Marks the case as failed.
    pub fn fail(&mut self, kind: impl Into<String>, detail: impl Into<String>) {
        let step = self.steps.last().map(|step| step.index);
        self.failure = Some(FailureNote {
            kind: kind.into(),
            detail: detail.into(),
            step,
        });
    }

    /// True when the case has been marked as failed.
    pub fn has_failure(&self) -> bool {
        self.failure.is_some()
    }

    /// Total ledger entries written across the case.
    pub fn total_writes(&self) -> usize {
        self.steps.iter().map(StepRecord::writes).sum()
    }

    /// The largest instruction count consumed by any single action.
    pub fn peak_usage(&self) -> ResourceUsage {
        let mut peak = ResourceUsage::default();
        for step in &self.steps {
            let usage = step.usage();
            peak.instructions = peak.instructions.max(usage.instructions);
            peak.mem_bytes = peak.mem_bytes.max(usage.mem_bytes);
            peak.disk_read_entries = peak.disk_read_entries.max(usage.disk_read_entries);
            peak.memory_read_entries = peak.memory_read_entries.max(usage.memory_read_entries);
            peak.write_entries = peak.write_entries.max(usage.write_entries);
            peak.disk_read_bytes = peak.disk_read_bytes.max(usage.disk_read_bytes);
            peak.write_bytes = peak.write_bytes.max(usage.write_bytes);
            peak.contract_events_size_bytes = peak
                .contract_events_size_bytes
                .max(usage.contract_events_size_bytes);
        }
        peak
    }
}

/// The configuration a report was produced under.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Number of cases requested.
    pub cases: u32,
    /// Minimum actions per sequence.
    pub min_actions: usize,
    /// Maximum actions per sequence.
    pub max_actions: usize,
    /// Fixed seed, if the run pinned one.
    pub seed: Option<u64>,
    /// Authorization policy in effect.
    pub auth: String,
    /// Resource policy in effect.
    pub resources: String,
}

/// A minimal, reproducible description of a failing case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    /// Machine-readable category, mirroring [`FailureNote::kind`].
    pub kind: String,
    /// What went wrong.
    pub detail: String,
    /// proptest's own description of the failure.
    pub reason: String,
    /// Seed that reproduces the failure, when known.
    pub seed: Option<u64>,
    /// The minimized action sequence, rendered.
    pub minimal_sequence: Vec<String>,
    /// Full journal of the minimized case.
    pub steps: Vec<StepRecord>,
    /// Configuration the run used.
    pub config: ReportConfig,
}

impl FailureReport {
    /// Builds a report from a finished journal.
    pub fn new(
        reason: String,
        minimal_sequence: Vec<String>,
        journal: &Journal,
        config: &FuzzConfig,
    ) -> Self {
        // A panic inside `execute` never reaches `finish_step`, so mark the step
        // that was in flight rather than leaving it looking unstarted.
        let mut steps = journal.steps.clone();
        if let Some(pending) = steps.iter_mut().find(|step| step.outcome == "pending") {
            pending.outcome = "<panicked>".to_owned();
        }

        let note = journal.failure.clone().unwrap_or(FailureNote {
            kind: "panic".to_owned(),
            detail: reason.clone(),
            step: steps.last().map(|step| step.index),
        });
        Self {
            kind: note.kind,
            detail: note.detail,
            reason,
            seed: config.seed,
            minimal_sequence,
            steps,
            config: config.summary(),
        }
    }

    /// The action that failed, if the failure is attributable to one.
    pub fn failing_step(&self) -> Option<&StepRecord> {
        let note = self
            .steps
            .iter()
            .find(|step| step.outcome.starts_with("violation") || step.breach().is_some());
        note.or_else(|| self.steps.last())
    }

    /// Renders the report as a multi-line, human-readable summary.
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        out.push_str("soroban-fuzzer: failing case\n");
        let _ = writeln!(out, "  kind:   {}", self.kind);
        let _ = writeln!(out, "  detail: {}", self.detail);
        match self.seed {
            Some(seed) => {
                let _ = writeln!(
                    out,
                    "  seed:   {seed}  (reproduce with FuzzConfig::default().seed({seed}))"
                );
            }
            None => {
                out.push_str("  seed:   <unpinned; set FuzzConfig::seed for a reproducible run>\n")
            }
        }
        let _ = writeln!(
            out,
            "  cases:  {} requested, actions {min}..={max}, auth {auth}",
            self.config.cases,
            min = self.config.min_actions,
            max = self.config.max_actions,
            auth = self.config.auth,
        );
        let _ = writeln!(
            out,
            "  minimal sequence ({} action{}):",
            self.minimal_sequence.len(),
            if self.minimal_sequence.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for (ix, action) in self.minimal_sequence.iter().enumerate() {
            let _ = writeln!(out, "    {}. {action}", ix + 1);
        }

        if !self.steps.is_empty() {
            out.push_str("  execution:\n");
            for step in &self.steps {
                let usage = step.usage();
                let _ = writeln!(
                    out,
                    "    #{} {} -> {}",
                    step.index + 1,
                    step.action,
                    step.outcome
                );
                if !step.calls.is_empty() || usage.instructions > 0 {
                    let _ = writeln!(
                        out,
                        "        cpu={} mem={}B reads={} writes={} entries={}",
                        usage.instructions,
                        usage.mem_bytes,
                        usage.disk_read_entries + usage.memory_read_entries,
                        usage.write_entries,
                        usage.ledger_entries(),
                    );
                }
                for call in &step.calls {
                    let _ = writeln!(
                        out,
                        "        call `{}`: {} [cpu={}, writes={}]",
                        call.label, call.outcome, call.usage.instructions, call.writes
                    );
                    if let Some(breach) = &call.breach {
                        let _ = writeln!(out, "          ! {breach}");
                    }
                }
            }
        }
        out
    }

    /// Serializes the report to pretty-printed JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|err| format!("{{\"error\": \"failed to serialize report: {err}\"}}"))
    }

    /// Writes the report as JSON, creating parent directories as needed.
    pub fn write_json(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(path, self.to_json())
    }
}

impl fmt::Display for FailureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pretty())
    }
}

/// The result of a fuzz run.
#[derive(Clone, Debug)]
pub enum FuzzOutcome {
    /// No failing case was found.
    Passed {
        /// Number of cases that ran.
        cases: u32,
        /// Seed the run used, so a flake can be reproduced.
        seed: u64,
    },
    /// A failing case was found and minimized.
    Failed(Box<FailureReport>),
    /// The run could not complete, for example because generation was rejected too
    /// often. This is a harness problem, not a contract finding.
    Aborted {
        /// Why the run aborted.
        reason: String,
    },
}

impl FuzzOutcome {
    /// True when a failing case was found.
    pub fn is_failure(&self) -> bool {
        matches!(self, FuzzOutcome::Failed(_))
    }

    /// True when the run completed without finding a failure.
    pub fn is_success(&self) -> bool {
        matches!(self, FuzzOutcome::Passed { .. })
    }

    /// The failure report, if a failing case was found.
    pub fn report(&self) -> Option<&FailureReport> {
        match self {
            FuzzOutcome::Failed(report) => Some(report),
            _ => None,
        }
    }

    /// The seed the run used, when known.
    pub fn seed(&self) -> Option<u64> {
        match self {
            FuzzOutcome::Passed { seed, .. } => Some(*seed),
            FuzzOutcome::Failed(report) => report.seed,
            FuzzOutcome::Aborted { .. } => None,
        }
    }

    /// Panics with the rendered report unless the run passed.
    ///
    /// Intended as the last line of a `#[test]`.
    pub fn assert_ok(&self) {
        match self {
            FuzzOutcome::Passed { .. } => {}
            FuzzOutcome::Failed(report) => panic!("\n{}", report.pretty()),
            FuzzOutcome::Aborted { reason } => {
                panic!("soroban-fuzzer: run aborted: {reason}")
            }
        }
    }
}

impl fmt::Display for FuzzOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FuzzOutcome::Passed { cases, seed } => {
                write!(f, "passed ({cases} cases, seed {seed})")
            }
            FuzzOutcome::Failed(_) => f.write_str("failed"),
            FuzzOutcome::Aborted { reason } => write!(f, "aborted: {reason}"),
        }
    }
}
