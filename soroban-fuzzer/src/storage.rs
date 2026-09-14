//! Ledger-state snapshots and diffs.
//!
//! Invariants frequently need to reason about *storage*: how many entries a
//! contract holds, whether an action wrote anything, or whether a loop is quietly
//! growing instance storage without bound.
//!
//! [`StorageSnapshot`] captures every contract-data entry in the test host and
//! [`StorageSnapshot::diff`] turns two snapshots into a [`StorageDelta`] reporting
//! writes per storage durability.
//!
//! Snapshots are read directly from the host's stored entries rather than through
//! `soroban_sdk::testutils::storage::{Instance, Persistent, Temporary}`, because
//! those helpers only work from inside a contract invocation
//! (`Instance::all` panics outside of one) and report entries globally without
//! attributing them to a contract. Reading the host directly works at any point in
//! a fuzz action and keeps entries keyed by owning contract.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{ContractDataDurability, LedgerEntryData, LedgerKey, ScAddress, ScVal};
use soroban_sdk::{Address, Env};

/// Which storage durability an entry lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    /// Storage attached to the contract's instance entry.
    Instance,
    /// Persistent contract data: rent-paying, and restorable after expiry.
    Persistent,
    /// Temporary contract data: expires without being restorable.
    Temporary,
}

impl StoreKind {
    /// All durabilities, in report order.
    pub const ALL: [StoreKind; 3] = [
        StoreKind::Instance,
        StoreKind::Persistent,
        StoreKind::Temporary,
    ];

    /// Human-readable name, matching the SDK's `storage::*` module names.
    pub fn as_str(self) -> &'static str {
        match self {
            StoreKind::Instance => "instance",
            StoreKind::Persistent => "persistent",
            StoreKind::Temporary => "temporary",
        }
    }
}

impl std::fmt::Display for StoreKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Entry counts for one contract or for the whole ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryCounts {
    /// Instance entries.
    pub instance: usize,
    /// Persistent entries.
    pub persistent: usize,
    /// Temporary entries.
    pub temporary: usize,
}

impl EntryCounts {
    /// Total entries across all durabilities.
    pub fn total(&self) -> usize {
        self.instance + self.persistent + self.temporary
    }

    /// Entries in the given durability.
    pub fn of(&self, kind: StoreKind) -> usize {
        match kind {
            StoreKind::Instance => self.instance,
            StoreKind::Persistent => self.persistent,
            StoreKind::Temporary => self.temporary,
        }
    }
}

/// A single storage entry: its value plus a pre-rendered label for reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The stored value, in its XDR form so that values are comparable and hashable
    /// regardless of how the host represents them.
    pub value: ScVal,
    /// The key rendered for humans, as it appears in failure reports.
    pub label: String,
}

/// Storage key: the owning contract plus the contract-data key.
pub type EntryKey = (ScAddress, ScVal);

/// All entries of one durability, keyed by [`EntryKey`].
pub type EntryMap = BTreeMap<EntryKey, Entry>;

fn empty_map() -> &'static EntryMap {
    static EMPTY: OnceLock<EntryMap> = OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// A point-in-time view of all contract data in the test host.
///
/// Entries are keyed by owning contract address and storage key, so two contracts
/// using the same key never collide.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageSnapshot {
    entries: BTreeMap<StoreKind, EntryMap>,
}

impl StorageSnapshot {
    /// Captures the current contents of the host's ledger storage.
    ///
    /// Never panics: if the host cannot enumerate its entries, an empty snapshot is
    /// returned, which degrades to "no storage observed" rather than failing a run.
    pub fn capture(env: &Env) -> Self {
        let mut entries: BTreeMap<StoreKind, EntryMap> = BTreeMap::new();

        let Ok(stored) = env.host().get_stored_entries() else {
            return Self { entries };
        };

        for (key, value) in stored {
            let LedgerKey::ContractData(data_key) = key.as_ref() else {
                continue;
            };
            let Some((entry, _live_until)) = value else {
                continue;
            };
            let LedgerEntryData::ContractData(data) = &entry.data else {
                continue;
            };

            match &data.key {
                // A contract instance entry carries its instance storage inline.
                ScVal::LedgerKeyContractInstance => {
                    if let ScVal::ContractInstance(instance) = &data.val {
                        if let Some(map) = &instance.storage {
                            let slot = entries.entry(StoreKind::Instance).or_default();
                            for pair in map.0.iter() {
                                slot.insert(
                                    (data.contract.clone(), pair.key.clone()),
                                    Entry {
                                        value: pair.val.clone(),
                                        label: render(&pair.key),
                                    },
                                );
                            }
                        }
                    }
                }
                key => {
                    let kind = match data_key.durability {
                        ContractDataDurability::Persistent => StoreKind::Persistent,
                        ContractDataDurability::Temporary => StoreKind::Temporary,
                    };
                    entries.entry(kind).or_default().insert(
                        (data.contract.clone(), key.clone()),
                        Entry {
                            value: data.val.clone(),
                            label: render(key),
                        },
                    );
                }
            }
        }

        Self { entries }
    }

    /// All entries in a durability, keyed by `(contract, key)`.
    pub fn entries(&self, kind: StoreKind) -> &EntryMap {
        match self.entries.get(&kind) {
            Some(map) => map,
            None => empty_map(),
        }
    }

    /// Entry counts across all contracts.
    pub fn counts(&self) -> EntryCounts {
        EntryCounts {
            instance: self.entries(StoreKind::Instance).len(),
            persistent: self.entries(StoreKind::Persistent).len(),
            temporary: self.entries(StoreKind::Temporary).len(),
        }
    }

    /// Total number of tracked entries.
    pub fn total_entries(&self) -> usize {
        self.counts().total()
    }

    /// Entry counts for a single contract.
    pub fn counts_for(&self, contract: &Address) -> EntryCounts {
        let sc = ScAddress::from(contract);
        EntryCounts {
            instance: count_for(self.entries(StoreKind::Instance), &sc),
            persistent: count_for(self.entries(StoreKind::Persistent), &sc),
            temporary: count_for(self.entries(StoreKind::Temporary), &sc),
        }
    }

    /// Computes what changed between this snapshot and a later one.
    pub fn diff(&self, after: &StorageSnapshot) -> StorageDelta {
        StorageDelta {
            instance: diff_kind(
                self.entries(StoreKind::Instance),
                after.entries(StoreKind::Instance),
            ),
            persistent: diff_kind(
                self.entries(StoreKind::Persistent),
                after.entries(StoreKind::Persistent),
            ),
            temporary: diff_kind(
                self.entries(StoreKind::Temporary),
                after.entries(StoreKind::Temporary),
            ),
        }
    }
}

fn count_for(entries: &EntryMap, contract: &ScAddress) -> usize {
    entries.keys().filter(|(addr, _)| addr == contract).count()
}

/// What changed in a single durability between two snapshots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeSet {
    /// Entries that appeared.
    pub added: usize,
    /// Entries that disappeared.
    pub removed: usize,
    /// Entries whose value changed.
    pub updated: usize,
    /// Rendered keys of changed entries, capped at [`ChangeSet::MAX_REPORTED_KEYS`].
    pub changed_keys: Vec<String>,
}

impl ChangeSet {
    /// Maximum number of changed keys retained for reporting.
    pub const MAX_REPORTED_KEYS: usize = 12;

    /// Number of entries written (added, removed or updated).
    pub fn writes(&self) -> usize {
        self.added + self.removed + self.updated
    }

    /// True when nothing changed.
    pub fn is_empty(&self) -> bool {
        self.writes() == 0
    }
}

/// What changed across all durabilities between two snapshots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDelta {
    /// Instance storage changes.
    pub instance: ChangeSet,
    /// Persistent storage changes.
    pub persistent: ChangeSet,
    /// Temporary storage changes.
    pub temporary: ChangeSet,
}

impl StorageDelta {
    /// Total entries written across all durabilities.
    pub fn writes(&self) -> usize {
        self.instance.writes() + self.persistent.writes() + self.temporary.writes()
    }

    /// True when no storage changed.
    pub fn is_empty(&self) -> bool {
        self.writes() == 0
    }

    /// Changes for one durability.
    pub fn of(&self, kind: StoreKind) -> &ChangeSet {
        match kind {
            StoreKind::Instance => &self.instance,
            StoreKind::Persistent => &self.persistent,
            StoreKind::Temporary => &self.temporary,
        }
    }
}

fn diff_kind(before: &EntryMap, after: &EntryMap) -> ChangeSet {
    let mut changed = ChangeSet::default();

    for (key, entry) in after {
        match before.get(key) {
            None => {
                changed.added += 1;
                push_key(&mut changed, &entry.label);
            }
            Some(old) if old.value != entry.value => {
                changed.updated += 1;
                push_key(&mut changed, &entry.label);
            }
            Some(_) => {}
        }
    }
    for (key, entry) in before {
        if !after.contains_key(key) {
            changed.removed += 1;
            push_key(&mut changed, &entry.label);
        }
    }

    changed
}

fn push_key(changed: &mut ChangeSet, label: &str) {
    if changed.changed_keys.len() < ChangeSet::MAX_REPORTED_KEYS {
        changed.changed_keys.push(label.to_owned());
    }
}

/// Renders a storage key into a compact, human-readable string.
pub fn render(value: &ScVal) -> String {
    let mut out = String::new();
    write_scval(&mut out, value);
    truncate(out, 96)
}

fn write_scval(out: &mut String, value: &ScVal) {
    match value {
        ScVal::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        ScVal::Void => out.push_str("void"),
        ScVal::U32(n) => {
            let _ = write!(out, "{n}");
        }
        ScVal::I32(n) => {
            let _ = write!(out, "{n}");
        }
        ScVal::U64(n) => {
            let _ = write!(out, "{n}");
        }
        ScVal::I64(n) => {
            let _ = write!(out, "{n}");
        }
        ScVal::U128(parts) => {
            let _ = write!(out, "{parts}");
        }
        ScVal::I128(parts) => {
            let _ = write!(out, "{parts}");
        }
        ScVal::U256(parts) => {
            let _ = write!(out, "{parts}");
        }
        ScVal::I256(parts) => {
            let _ = write!(out, "{parts}");
        }
        ScVal::Timepoint(t) => {
            let _ = write!(out, "{t:?}");
        }
        ScVal::Duration(d) => {
            let _ = write!(out, "{d:?}");
        }
        ScVal::Bytes(b) => {
            let _ = write!(out, "bytes({})", b.0.len());
        }
        ScVal::String(s) => {
            let _ = write!(out, "\"{}\"", s.0);
        }
        ScVal::Symbol(s) => {
            let _ = write!(out, "\"{}\"", s.0);
        }
        ScVal::Vec(None) => out.push_str("[]"),
        ScVal::Vec(Some(items)) => {
            out.push('[');
            for (ix, item) in items.0.iter().enumerate() {
                if ix > 0 {
                    out.push_str(", ");
                }
                write_scval(out, item);
            }
            out.push(']');
        }
        ScVal::Map(None) => out.push_str("{}"),
        ScVal::Map(Some(entries)) => {
            out.push('{');
            for (ix, entry) in entries.0.iter().enumerate() {
                if ix > 0 {
                    out.push_str(", ");
                }
                write_scval(out, &entry.key);
                out.push_str(": ");
                write_scval(out, &entry.val);
            }
            out.push('}');
        }
        ScVal::Address(addr) => {
            let _ = write!(out, "{addr}");
        }
        ScVal::LedgerKeyContractInstance => out.push_str("<instance>"),
        ScVal::ContractInstance(_) => out.push_str("<contract-instance>"),
        other => {
            let _ = write!(out, "{other:?}");
        }
    }
}

fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s;
    out.truncate(end);
    out.push('…');
    out
}
