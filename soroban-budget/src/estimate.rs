//! What a compiled contract can be said to cost without running it.
//!
//! # What is counted, and what that is worth
//!
//! For every function the module exports, this walks the **static call tree** and sums
//! the Wasm instructions of everything reachable from it. Host calls are counted by
//! name rather than costed, because the price of a host call is the host's, not the
//! module's.
//!
//! The result is a *lower bound* on the work an invocation does, and an exact count
//! only when the entrypoint cannot loop, cannot call indirectly and does not recurse.
//! Each of those three makes an upper bound impossible to compute statically, and rather
//! than print a number and hope, the estimate names which one it hit:
//!
//! | Reason | Why a bound is impossible |
//! | --- | --- |
//! | Loops | The trip count is an input. A loop over storage has no static bound at all. |
//! | Indirect calls | The target depends on a value in a table, so the callee set is not the call site's. |
//! | Recursion | The call graph has a cycle, so the tree is not finite. |
//!
//! The estimator deliberately does **not** reinterpret any of these as a rule: "this
//! entrypoint loops" is not a vulnerability, and an estimator that graded one would be
//! guessing about intent. It reports what is there and says what it could not see, which
//! is the same position the analyser takes on the rules it calls heuristic.
//!
//! # Why this is not a CPU prediction
//!
//! Soroban meters CPU instructions with its own weights — per Wasm instruction, per host
//! call, per byte moved — and it charges for work this count does not include, such as
//! deserializing arguments and passing them through the host. So a number here is a
//! structural measurement of the module, and comparing two contracts' numbers is
//! meaningful, while reading one as "this call will cost N CPU" is not. [`crate::report`]
//! states that in the output itself, where a reader will see it.

use std::collections::{BTreeMap, BTreeSet};

use crate::module::Module;

/// Why an entrypoint's cost cannot be bounded from the module alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Unbounded {
    /// A loop in the reachable code: the trip count is an input.
    Loops,
    /// A `call_indirect` in the reachable code: the callee is chosen at run time.
    IndirectCalls,
    /// A cycle in the call graph: the reachable tree is not finite.
    Recursion,
}

impl Unbounded {
    /// A short name for reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Unbounded::Loops => "loops",
            Unbounded::IndirectCalls => "indirect calls",
            Unbounded::Recursion => "recursion",
        }
    }

    /// What a reader should understand from it.
    pub fn explanation(self) -> &'static str {
        match self {
            Unbounded::Loops => "the trip count is an input, so no static bound exists",
            Unbounded::IndirectCalls => {
                "the callee is chosen from a table at run time, so the call site does not \
                 name the work"
            }
            Unbounded::Recursion => {
                "the call graph has a cycle, so the reachable tree is not finite"
            }
        }
    }
}

/// What one exported entrypoint costs, as far as the module says.
#[derive(Clone, Debug)]
pub struct EntryEstimate {
    /// The exported name.
    pub name: String,
    /// Wasm instructions in the static call tree.
    ///
    /// Exact when [`EntryEstimate::unbounded`] is empty; a lower bound otherwise.
    pub instructions: usize,
    /// Distinct functions reached, including the entrypoint itself.
    pub functions: usize,
    /// Host calls in the tree, by import name, each call site counted.
    pub host_calls: BTreeMap<String, usize>,
    /// Total host calls across all names.
    pub host_calls_total: usize,
    /// Why the count is not an upper bound; empty when it is exact.
    pub unbounded: BTreeSet<Unbounded>,
    /// Loop sites reached.
    pub loops: usize,
    /// `call_indirect` sites reached.
    pub indirect_calls: usize,
}

impl EntryEstimate {
    /// Whether the instruction count is an exact static count rather than a lower bound.
    pub fn is_exact(&self) -> bool {
        self.unbounded.is_empty()
    }
}

/// What a module costs, entrypoint by entrypoint.
#[derive(Clone, Debug)]
pub struct Budget {
    /// The path the module was read from.
    pub path: String,
    /// The module's size in bytes.
    pub bytes: usize,
    /// Host functions the module imports.
    pub imports: usize,
    /// Functions the module defines.
    pub functions: usize,
    /// One estimate per exported function, in export order.
    pub entries: Vec<EntryEstimate>,
    /// Exported things that are not functions, such as memory.
    pub other_exports: Vec<String>,
}

impl Budget {
    /// The estimate for one entrypoint.
    pub fn entry(&self, name: &str) -> Option<&EntryEstimate> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    /// How many entrypoints have no static upper bound.
    pub fn unbounded_entries(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| !entry.is_exact())
            .count()
    }

    /// The largest exact instruction count, if any entrypoint is exact.
    pub fn largest_exact(&self) -> Option<&EntryEstimate> {
        self.entries
            .iter()
            .filter(|entry| entry.is_exact())
            .max_by_key(|entry| entry.instructions)
    }

    /// The smallest instruction count, exact or not — the schedule a stranger can force.
    pub fn smallest(&self) -> Option<&EntryEstimate> {
        self.entries.iter().min_by_key(|entry| entry.instructions)
    }
}

/// Estimates every entrypoint of a module.
pub fn estimate(module: &Module) -> Budget {
    let mut entries = Vec::new();
    let mut reported = BTreeSet::new();

    for (name, index) in &module.exports {
        // A module can export one function under two names; estimating it twice would
        // double-count in every summary, so the second name is a note rather than a row.
        if !reported.insert(*index) {
            continue;
        }
        entries.push(estimate_entry(module, name, *index));
    }

    Budget {
        path: module.path.clone(),
        bytes: module.bytes,
        imports: module.imports.len(),
        functions: module.functions.len(),
        entries,
        other_exports: module.other_exports.clone(),
    }
}

/// Walks the call tree from one entrypoint, accumulating what it costs and what it hides.
fn estimate_entry(module: &Module, name: &str, root: usize) -> EntryEstimate {
    let mut estimate = EntryEstimate {
        name: name.to_owned(),
        instructions: 0,
        functions: 0,
        host_calls: BTreeMap::new(),
        host_calls_total: 0,
        unbounded: BTreeSet::new(),
        loops: 0,
        indirect_calls: 0,
    };

    // Depth-first over the call *tree*, not the call graph: a function reached from two
    // branches is counted twice, which is what makes this a count of executed
    // instructions rather than of distinct code. The path is the recursion detector, so
    // a self-call through any number of intermediate functions is caught.
    let mut seen = BTreeSet::new();
    walk(module, root, &mut estimate, &mut Vec::new(), &mut seen, 0);
    estimate.functions = seen.len();
    estimate
}

/// How deep the walk goes before it calls the graph recursive and stops.
///
/// A guard rather than a claim: a call graph deeper than this is not something the
/// Soroban SDK's generated code produces, and reporting `recursion` for it is the
/// conservative answer — the estimate declines to be exact rather than trusting a
/// stack it cannot afford to walk.
const MAX_DEPTH: usize = 64;

/// Walks one reachable function, accumulating into `estimate`.
fn walk(
    module: &Module,
    index: usize,
    estimate: &mut EntryEstimate,
    path: &mut Vec<usize>,
    seen: &mut BTreeSet<usize>,
    depth: usize,
) {
    if path.contains(&index) || depth > MAX_DEPTH {
        estimate.unbounded.insert(Unbounded::Recursion);
        return;
    }

    let Some(facts) = module.function(index) else {
        // An export naming an imported function, or a call to one: legal Wasm, and there
        // is no body here to count, only a host call to attribute.
        if let Some(import) = module.host_import(index) {
            *estimate.host_calls.entry(import.full_name()).or_insert(0) += 1;
            estimate.host_calls_total += 1;
        }
        return;
    };

    seen.insert(index);
    estimate.instructions += facts.instructions;
    estimate.loops += facts.loops;
    estimate.indirect_calls += facts.indirect_calls;
    if facts.loops > 0 {
        estimate.unbounded.insert(Unbounded::Loops);
    }
    if facts.indirect_calls > 0 {
        estimate.unbounded.insert(Unbounded::IndirectCalls);
    }

    for host in &facts.host_calls {
        let name = module
            .host_import(*host)
            .map(|import| import.full_name())
            .unwrap_or_else(|| format!("function {host}"));
        *estimate.host_calls.entry(name).or_insert(0) += 1;
        estimate.host_calls_total += 1;
    }

    path.push(index);
    for call in &facts.calls {
        walk(module, *call, estimate, path, seen, depth + 1);
    }
    path.pop();
}
