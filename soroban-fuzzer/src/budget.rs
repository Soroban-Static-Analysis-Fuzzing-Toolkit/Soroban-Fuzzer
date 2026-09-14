//! Resource-budget instrumentation for Soroban contract invocations.
//!
//! Soroban contracts execute inside a metered host: every invocation is bounded by
//! the network's instruction, memory, ledger-entry and byte limits. A contract that
//! happily passes a unit test can still be un-deployable because a single call
//! exceeds those caps.
//!
//! This module exposes the host's own accounting ([`ResourceUsage`]) together with
//! the canonical network caps ([`mainnet_limits`]) so a fuzzing run can flag calls
//! that would never land on chain — including the 200 read-entry ceiling.
//!
//! Measured values are a close approximation of what a real transaction consumes,
//! not an exact prediction. See the note on [`ResourceUsage`].

use core::fmt;

use serde::{Deserialize, Serialize};
use soroban_sdk::testutils::cost_estimate::NetworkInvocationResourceLimits;
use soroban_sdk::Env;

pub use soroban_env_host::{InvocationResourceLimits, InvocationResources};

/// Returns the Stellar Mainnet invocation resource limits as snapshotted by the
/// `soroban-sdk` release this crate is built against.
///
/// Use these as the baseline for [`crate::FuzzConfig::limits`], tweaking individual
/// fields when you want a stricter budget than the network enforces.
pub fn mainnet_limits() -> InvocationResourceLimits {
    InvocationResourceLimits::mainnet()
}

/// The resources consumed by a single top-level contract invocation.
///
/// Values are read straight from the host's invocation metering. They are a good
/// approximation of a real transaction's footprint but not an exact prediction:
/// costs related to transaction size, the return value, and XDR round-trips are not
/// modelled, and contracts registered natively (rather than as Wasm) hide VM
/// instantiation and execution costs.
///
/// Treat a reported breach as a strong signal, and a reported non-breach as
/// reassurance rather than proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Modelled CPU instructions.
    pub instructions: i64,
    /// Modelled peak memory, in bytes.
    pub mem_bytes: i64,
    /// Ledger entries that had to be read from disk (obtains a transaction footprint).
    pub disk_read_entries: u32,
    /// Ledger entries read from the in-memory live state.
    pub memory_read_entries: u32,
    /// Ledger entries written because they were modified.
    pub write_entries: u32,
    /// Bytes read from disk.
    pub disk_read_bytes: u32,
    /// Bytes written to the ledger.
    pub write_bytes: u32,
    /// Total size of the contract events emitted.
    pub contract_events_size_bytes: u32,
}

impl ResourceUsage {
    /// Reads the usage of the last top-level invocation.
    ///
    /// Returns `None` if no invocation has been metered yet, which is the case
    /// before the first contract call of a test case.
    pub fn capture(env: &Env) -> Option<Self> {
        env.host()
            .get_last_invocation_resources()
            .map(|r| Self::from_resources(&r))
    }

    /// Like [`ResourceUsage::capture`], defaulting to all-zero usage.
    pub fn capture_or_default(env: &Env) -> Self {
        Self::capture(env).unwrap_or_default()
    }

    /// Builds a usage record from the host's raw resource struct.
    pub fn from_resources(resources: &InvocationResources) -> Self {
        Self {
            instructions: resources.instructions,
            mem_bytes: resources.mem_bytes,
            disk_read_entries: resources.disk_read_entries,
            memory_read_entries: resources.memory_read_entries,
            write_entries: resources.write_entries,
            disk_read_bytes: resources.disk_read_bytes,
            write_bytes: resources.write_bytes,
            contract_events_size_bytes: resources.contract_events_size_bytes,
        }
    }

    /// Total transaction footprint: disk reads + memory reads + writes.
    ///
    /// This is the quantity limited by `ledger_entries` on the network, and it is
    /// the number that most often decides whether an invocation can be submitted.
    pub fn ledger_entries(&self) -> u32 {
        self.disk_read_entries
            .saturating_add(self.memory_read_entries)
            .saturating_add(self.write_entries)
    }

    /// True when nothing has been metered.
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// Every limit that this usage exceeds.
    pub fn breaches(&self, limits: &InvocationResourceLimits) -> Vec<LimitBreach> {
        let mut breaches = Vec::new();
        check(
            &mut breaches,
            "instructions",
            self.instructions,
            limits.instructions,
        );
        check(&mut breaches, "mem_bytes", self.mem_bytes, limits.mem_bytes);
        check(
            &mut breaches,
            "disk_read_entries",
            i64::from(self.disk_read_entries),
            i64::from(limits.disk_read_entries),
        );
        // `memory_read_entries` has no individual ceiling on the network; it is
        // bounded through the total ledger-entry footprint checked below.
        check(
            &mut breaches,
            "write_entries",
            i64::from(self.write_entries),
            i64::from(limits.write_entries),
        );
        check(
            &mut breaches,
            "ledger_entries",
            i64::from(self.ledger_entries()),
            i64::from(limits.ledger_entries),
        );
        check(
            &mut breaches,
            "disk_read_bytes",
            i64::from(self.disk_read_bytes),
            i64::from(limits.disk_read_bytes),
        );
        check(
            &mut breaches,
            "write_bytes",
            i64::from(self.write_bytes),
            i64::from(limits.write_bytes),
        );
        check(
            &mut breaches,
            "contract_events_size_bytes",
            i64::from(self.contract_events_size_bytes),
            i64::from(limits.contract_events_size_bytes),
        );
        breaches
    }

    /// The first (most structural) limit exceeded, if any.
    ///
    /// Reported in a fixed order that starts with CPU and memory so that a runaway
    /// loop is reported as an instruction breach rather than the storage side
    /// effects it caused.
    pub fn first_breach(&self, limits: &InvocationResourceLimits) -> Option<LimitBreach> {
        self.breaches(limits).into_iter().next()
    }
}

fn check(out: &mut Vec<LimitBreach>, name: &'static str, used: i64, allowed: i64) {
    if used > allowed {
        out.push(LimitBreach {
            limit: name.to_owned(),
            used,
            allowed,
        });
    }
}

/// A single network limit that an invocation exceeded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitBreach {
    /// Name of the exceeded limit, as it appears in `stellar network settings`.
    pub limit: String,
    /// The value the invocation consumed.
    pub used: i64,
    /// The network ceiling for that value.
    pub allowed: i64,
}

impl LimitBreach {
    /// How far over the limit the invocation went.
    pub fn excess(&self) -> i64 {
        self.used.saturating_sub(self.allowed)
    }

    /// The excess as a percentage of the limit (`150` means 2.5x the limit).
    pub fn excess_percent(&self) -> f64 {
        if self.allowed <= 0 {
            return f64::INFINITY;
        }
        (self.used as f64 / self.allowed as f64) * 100.0
    }
}

impl fmt::Display for LimitBreach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} limit exceeded: {} of {} allowed ({} over, {:.0}% of limit)",
            self.limit,
            self.used,
            self.allowed,
            self.excess(),
            self.excess_percent()
        )
    }
}
