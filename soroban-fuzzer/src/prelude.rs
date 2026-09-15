//! Everything needed to write a target, in one import.
//!
//! ```
//! use soroban_fuzzer::prelude::*;
//! ```
//!
//! This brings in the harness API plus proptest's combinators, so a target file
//! needs no other imports beyond `soroban_sdk` itself.

pub use core::fmt::Debug;

pub use soroban_sdk::Env;

pub use crate::arbitrary_bridge::{from_arbitrary, from_arbitrary_with};
pub use crate::budget::{mainnet_limits, InvocationResourceLimits, LimitBreach, ResourceUsage};
pub use crate::config::{AuthPolicy, FuzzConfig, ResourcePolicy};
pub use crate::invariant::{
    CheckCtx, FnInvariant, Invariant, NonDecreasing, StorageGrowthBounded, SupplyConserved,
    SupplyReader,
};
pub use crate::report::{ActionStats, FailureReport, FuzzOutcome, Journal, StepRecord};
pub use crate::runner::{check, run};
pub use crate::runtime::{CallResult, LedgerCtl, Runtime, StepOutcome};
pub use crate::storage::{
    ChangeSet, Entry, EntryCounts, EntryKey, EntryMap, StorageDelta, StorageSnapshot, StoreKind,
};
pub use crate::target::{constant, Target};

/// proptest's prelude, re-exported: `Just`, `any`, `prop_oneof!`, `Strategy`,
/// `BoxedStrategy`, `prop::collection`, and the assertion macros.
pub use proptest::prelude::*;
