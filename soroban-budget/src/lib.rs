//! Static resource-budget estimation for compiled Soroban contracts.
//!
//! The other two components of this toolkit answer questions about a contract's source:
//! whether a privileged entrypoint asks who is calling, whether a loop over storage is
//! bounded, whether a call can read more ledger entries than an invocation may. This one
//! reads the **compiled Wasm** — the artefact that actually runs — and reports what each
//! entrypoint costs in a way that does not require deploying it.
//!
//! ```no_run
//! use soroban_budget::{estimate, Format, Module};
//!
//! let module = Module::load("contract.wasm").expect("the module reads");
//! let budget = estimate(&module);
//! println!("{}", budget.render(Format::Text));
//!
//! for entry in &budget.entries {
//!     if !entry.is_exact() {
//!         println!("{} cannot be bounded statically", entry.name);
//!     }
//! }
//! ```
//!
//! # What it reports, and what that is worth
//!
//! For every exported function: the Wasm instructions in its static call tree, the host
//! functions it calls, and whether the count is an exact static count or merely a lower
//! bound. It is a lower bound whenever the reachable code loops, calls indirectly, or
//! recurses, because each of those makes an upper bound impossible to compute from the
//! module alone — and the report names which one it hit rather than printing a number and
//! letting a reader assume it is the whole story.
//!
//! This is a *structural* measurement, not a CPU prediction. Soroban meters host calls
//! and instruction types at its own weights, and charges for argument marshalling this
//! count does not see. Comparing two contracts, or the same contract before and after a
//! change, is what the numbers are for.
//!
//! # Why it is a separate crate
//!
//! The analyser reads Rust, this reads Wasm, and the fuzzer runs the contract. None of
//! the three needs the others, and the dependency they would share if they were one crate
//! — a Wasm parser, `syn`, and the SDK's test environment — is large enough that keeping
//! them apart is worth more than the convenience of one binary. It is also the reason
//! each can be adopted on its own: a team that only wants this one installs this one.
//!
//! # Limits, stated before the numbers
//!
//! - **Host cost is not modelled.** A call into the host that reads a ledger entry costs
//!   more than one that computes: this crate counts the call and stops there.
//! - **Indirect calls do not name their targets.** Resolving a `call_indirect` to the
//!   functions it could reach needs the type section and the table's element segment;
//!   until that is done, such an entrypoint is reported as not exactly bounded.
//! - **Metre weights are not applied.** There is no honest way to turn a count of
//!   operations into an instruction count without the network's own table, and inventing
//!   one would be a number that looks precise and is not.
//! - **A module that will not parse is an error, not a finding.** This reads the
//!   artefact a deployment would carry; if it cannot be read, nothing here is meaningful.
//!
//! # Feature flags
//!
//! None. The crate reads a file, walks a call graph and prints a report.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]
#![forbid(unsafe_code)]

/// The tool's name, as it appears in reports and on the command line.
pub const TOOL_NAME: &str = "soroban-budget";

/// This build's version, taken from the manifest so the two cannot disagree.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the tool lives, so a report can be traced back to its source.
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

pub mod estimate;
pub mod module;
pub mod report;

pub use estimate::{estimate, Budget, EntryEstimate, Unbounded};
pub use module::{FunctionFacts, HostImport, Module, WasmError};
pub use report::{Format, JSON_SCHEMA_VERSION, WHAT_THIS_IS};

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest possible module: a magic number and a version, no sections.
    const EMPTY_MODULE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn a_module_with_no_code_is_an_error_rather_than_a_clean_report() {
        let error = Module::parse(&EMPTY_MODULE, "empty.wasm")
            .expect_err("a module with no functions cannot be estimated");
        assert!(error.to_string().contains("empty.wasm"), "{error}");
    }

    #[test]
    fn something_that_is_not_wasm_says_so() {
        let error =
            Module::parse(b"not wasm at all", "text.wasm").expect_err("this is not a module");
        assert!(error.to_string().contains("text.wasm"), "{error}");
    }
}
