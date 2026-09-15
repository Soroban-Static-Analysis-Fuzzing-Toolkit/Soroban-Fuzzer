//! Contract fixtures shared by the integration tests.
//!
//! There is one correctly written contract and three deliberately buggy ones, each
//! exhibiting a distinct Soroban vulnerability class that the harness must detect.

#![allow(dead_code)]

use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};
use soroban_sdk::{contract, contracterror, contractimpl, Address, Env, IntoVal, Symbol, Val, Vec};

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn key(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}

fn balance_key(env: &Env, who: &Address) -> (Symbol, Address) {
    (key(env, "bal"), who.clone())
}

/// Reads a balance. Must be called from inside the contract.
fn balance(env: &Env, who: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&balance_key(env, who))
        .unwrap_or(0)
}

/// Writes a balance. Must be called from inside the contract.
fn set_balance(env: &Env, who: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&balance_key(env, who), &amount);
}

/// Reads total supply. Must be called from inside the contract.
fn total_supply(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&key(env, "total"))
        .unwrap_or(0)
}

/// Installs a credential for exactly one upcoming invocation of `fn_name`.
///
/// Using a precise authorization rather than `mock_all_auths` means the test also
/// catches a contract that demands authorization for arguments it was not given.
pub fn mock_invocation(
    env: &Env,
    contract: &Address,
    fn_name: &str,
    address: &Address,
    args: Vec<Val>,
) {
    env.mock_auths(&[MockAuth {
        address,
        invoke: &MockAuthInvoke {
            contract,
            fn_name,
            args,
            sub_invokes: &[],
        },
    }]);
}

/// Builds the argument vector for a mocked invocation.
pub fn args<T: IntoVal<Env, Vec<Val>>>(env: &Env, value: T) -> Vec<Val> {
    value.into_val(env)
}

// ---------------------------------------------------------------------------
// A correctly written vault: every privileged path requires authorization
// ---------------------------------------------------------------------------

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn __constructor(env: Env, admin: Address, supply: i128) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        env.storage().instance().set(&key(&env, "total"), &supply);
        set_balance(&env, &admin, supply);
    }

    /// Mints, requiring authorization from the stored admin.
    ///
    /// Note the two distinct checks: the caller must have authorized the call *and*
    /// must be the admin. Missing the first is the classic Soroban bug.
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {
        admin.require_auth();
        let stored: Address = env.storage().instance().get(&key(&env, "admin")).unwrap();
        if stored != admin {
            panic!("caller is not the admin");
        }
        set_balance(&env, &to, balance(&env, &to) + amount);
        env.storage()
            .instance()
            .set(&key(&env, "total"), &(total_supply(&env) + amount));
    }

    /// Moves `amount` from `from` to `to`, requiring authorization from `from`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance = balance(&env, &from);
        if amount < 0 || from_balance < amount {
            panic!("insufficient balance");
        }
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, balance(&env, &to) + amount);
    }

    /// Views.
    pub fn get_balance(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }

    pub fn total(env: Env) -> i128 {
        total_supply(&env)
    }
}

// ---------------------------------------------------------------------------
// Bug 1: a privileged entrypoint with no require_auth
// ---------------------------------------------------------------------------

#[contract]
pub struct MissingAuthVault;

#[contractimpl]
impl MissingAuthVault {
    pub fn __constructor(env: Env, admin: Address, supply: i128) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        env.storage().instance().set(&key(&env, "total"), &supply);
        set_balance(&env, &admin, supply);
    }

    /// Anyone can mint: `require_auth` is missing entirely.
    pub fn mint(env: Env, _admin: Address, to: Address, amount: i128) {
        set_balance(&env, &to, balance(&env, &to) + amount);
        env.storage()
            .instance()
            .set(&key(&env, "total"), &(total_supply(&env) + amount));
    }

    pub fn get_balance(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }
}

// ---------------------------------------------------------------------------
// Bug 2: unbounded storage growth
// ---------------------------------------------------------------------------

#[contract]
pub struct HoarderVault;

#[contractimpl]
impl HoarderVault {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        env.storage().instance().set(&key(&env, "count"), &0u32);
    }

    /// Records every caller in a new storage entry and never prunes.
    ///
    /// A single call adds an entry to both instance and persistent storage, so the
    /// entry count grows without bound as the contract is used.
    pub fn record(env: Env, who: Address) {
        let count: u32 = env.storage().instance().get(&key(&env, "count")).unwrap();
        env.storage()
            .instance()
            .set(&key(&env, "count"), &(count + 1));
        env.storage()
            .persistent()
            .set(&(key(&env, "log"), count), &who);
    }
}

// ---------------------------------------------------------------------------
// Bug 3: unchecked arithmetic on an amount
// ---------------------------------------------------------------------------

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VaultError {
    BadAmount = 1,
}

#[contract]
pub struct SavingsVault;

#[contractimpl]
impl SavingsVault {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        set_balance(&env, &admin, 1_000);
    }

    /// Adds an amount to the caller's balance with an unchecked `+`.
    ///
    /// Large amounts overflow `i128`, which traps in the test environment instead of
    /// being handled. A production contract needs `checked_add`.
    pub fn deposit(env: Env, who: Address, amount: i128) -> Result<(), VaultError> {
        who.require_auth();
        if amount <= 0 {
            return Err(VaultError::BadAmount);
        }
        let current = balance(&env, &who);
        set_balance(&env, &who, current + amount);
        Ok(())
    }

    pub fn get_balance(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }
}

// ---------------------------------------------------------------------------
// Bug 4: a cumulative quantity kept in storage that does not survive
// ---------------------------------------------------------------------------

#[contract]
pub struct ResettingVault;

#[contractimpl]
impl ResettingVault {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&key(&env, "admin"), &admin);
        env.storage().temporary().set(&key(&env, "fees"), &0i128);
    }

    /// Adds to the cumulative fee total.
    ///
    /// The total is a number the contract's own accounting rests on, and it is written
    /// to **temporary** storage: the host reclaims the entry once its TTL passes, and
    /// after that the total reads as zero. Nothing in the contract fails — it serves a
    /// smaller number than it served a ledger ago, which is the whole bug.
    pub fn accrue(env: Env, admin: Address, amount: i128) {
        admin.require_auth();
        let fees: i128 = env
            .storage()
            .temporary()
            .get(&key(&env, "fees"))
            .unwrap_or(0);
        env.storage()
            .temporary()
            .set(&key(&env, "fees"), &(fees + amount));
    }

    /// Reads the cumulative fee total.
    pub fn total_fees(env: Env) -> i128 {
        env.storage()
            .temporary()
            .get(&key(&env, "fees"))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Bug 5: initialization re-opened across a ledger boundary
// ---------------------------------------------------------------------------

#[contract]
pub struct ReinitVault;

#[contractimpl]
impl ReinitVault {
    /// Deploys the vault with an admin, and records the ledger it happened in.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage()
            .instance()
            .set(&key(&env, "initialized_at"), &env.ledger().sequence());
        env.storage().instance().set(&key(&env, "admin"), &admin);
    }

    /// Initializes the vault, at most once per ledger.
    ///
    /// The guard compares the ledger the vault was initialized in against the current
    /// one instead of asking whether an admin already exists. Crossing a ledger boundary
    /// therefore re-opens initialization, and whoever calls it next replaces the admin —
    /// a privilege takeover that needs no credential beyond their own. This is the class
    /// a single-ledger test cannot see and a `close_ledger` scenario can.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        let ledger = env.ledger().sequence();
        let initialized_at: u32 = env
            .storage()
            .instance()
            .get(&key(&env, "initialized_at"))
            .unwrap_or(0);
        if initialized_at == ledger {
            panic!("already initialized");
        }
        env.storage()
            .instance()
            .set(&key(&env, "initialized_at"), &ledger);
        env.storage().instance().set(&key(&env, "admin"), &admin);
    }

    /// The currently stored admin.
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&key(&env, "admin")).unwrap()
    }

    /// A privileged action, to show what the stored admin is for.
    pub fn take_fees(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&key(&env, "admin")).unwrap();
        admin.require_auth();
        set_balance(&env, &to, balance(&env, &to) + amount);
    }

    /// A view, so a target can watch a balance without a credential.
    pub fn get_balance(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }
}
