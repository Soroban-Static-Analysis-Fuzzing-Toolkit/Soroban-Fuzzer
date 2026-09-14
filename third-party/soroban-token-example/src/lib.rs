#![no_std]

mod admin;
mod allowance;
mod balance;
mod contract;
mod metadata;
mod storage_types;
mod test;

pub use crate::contract::TokenClient;

// --- vendoring addition, see PROVENANCE.md ---
// Upstream re-exports only the generated client. The contract type itself must be
// reachable to register the contract in the test environment, so it is re-exported
// here. Additive only: no contract logic or visibility is changed.
pub use crate::contract::Token;
