// `soroban-missing-require-auth`: a privileged entrypoint that never asks who is calling.
//
// # Why this is the highest-value check in the crate
//
// On Soroban, authorization is not ambient. Calling a contract passes the caller's
// address only if someone signed for it, and a contract that does not call
// `require_auth` on an address has not established anything about it — the address it
// was handed is just a number the caller typed. A token's `transfer(from, to, amount)`
// that authorizes nothing lets anyone move anyone's balance, and the host will not
// object, because from the host's point of view nothing was claimed.
//
// This is why the check is not "does this entrypoint call `require_auth`" — a read-only
// view function legitimately does not — but "does this entrypoint *change something*
// without asking". Change means a storage write or a value movement, both of which are
// decided syntactically here.
//
// # The two blind spots, stated rather than hidden
//
// * **Delegation is resolved one level deep, in one file.** If the entrypoint calls a
//   helper in the same file, and that helper authorizes, the entrypoint is not flagged.
//   If the authorization lives two calls away, or in another file, it is not seen, and
//   the entrypoint *is* flagged. That is a false positive, and a deliberate one: the
//   alternative is to not report at all, and an unprotected `mint` is not something to
//   be quiet about.
// * **An authorization call anywhere in the body counts**, including one inside an
//   `if` that can be false, or one on a *different* address than the affected one. So
//   `if nobody { return; } else { who.require_auth(); }` passes, and a `withdraw(from,
//   to)` that authorizes `from` but moves `to`'s balance passes too. Checking which
//   address is authorized against which was touched needs types and data flow, and
//   saying nothing would be worse than saying this much.

use crate::detector::{Detector as DetectorBehaviour, DetectorCtx, Findings};
use crate::syntax::{self, Durability};

/// The detector.
pub struct Detector;

impl DetectorBehaviour for Detector {
    fn id(&self) -> &'static str {
        "soroban-missing-require-auth"
    }

    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
        let file = ctx.file();
        let authorizing = syntax::local_fns_that_authorize(file);

        for entry in syntax::contract_fns(file) {
            if entry.is_exempt() {
                // `__constructor` runs at deploy time, when there is no caller to
                // authorize; `_`-prefixed names are the SDK's own hooks.
                continue;
            }
            if syntax::calls_require_auth(entry.block) {
                continue;
            }
            if delegates_to_an_authorizing_helper(&entry, &authorizing) {
                continue;
            }

            let writes = syntax::storage_writes(entry.block);
            let movements = syntax::value_movements(entry.block);
            if writes.is_empty() && movements.is_empty() {
                // Nothing is changed, so there is nothing to authorize. This is the
                // check that keeps every `balance_of(env, who)` view out of the report.
                continue;
            }

            sink.report(
                entry.span,
                describe(&entry, &writes, &movements),
            );
        }
    }
}

/// True when the entrypoint calls a function in this file that authorizes.
///
/// Both spellings are considered: a method call (`self.helper()`, `guard.check()`) and a
/// free function call (`helper()`), because the same helper is written either way
/// depending on whether it was put in the impl block.
fn delegates_to_an_authorizing_helper(
    entry: &syntax::ContractFn<'_>,
    authorizing: &std::collections::BTreeSet<String>,
) -> bool {
    if authorizing.is_empty() {
        return false;
    }
    syntax::called_methods(entry.block)
        .into_iter()
        .chain(syntax::called_functions(entry.block))
        .any(|called| authorizing.contains(&called))
}

/// The finding's message, naming what the entrypoint does and which address it should
/// have been authorized against.
fn describe(
    entry: &syntax::ContractFn<'_>,
    writes: &[&syn::ExprMethodCall],
    movements: &[&syn::ExprMethodCall],
) -> String {
    let label = syntax::entrypoint_label(entry);

    let mut effects = Vec::new();
    if !writes.is_empty() {
        effects.push(describe_writes(writes));
    }
    if !movements.is_empty() {
        effects.push(describe_movements(movements));
    }
    let effect = effects.join(" and ");

    let addresses = entry.address_parameters();
    if addresses.is_empty() {
        format!(
            "{label} {effect} but never calls `require_auth`: it takes no address to \
             authorize, so any account can invoke it and change this state"
        )
    } else {
        let named = addresses
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{label} {effect} but never calls `require_auth`: any account can invoke it \
             and pass any value for {named}, so the operation runs without the approval \
             it is supposed to rest on"
        )
    }
}

fn describe_writes(writes: &[&syn::ExprMethodCall]) -> String {
    let durabilities = writes
        .iter()
        .filter_map(|call| syntax::durability(call))
        .map(Durability::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    match durabilities.len() {
        0 => "writes storage".to_owned(),
        1 => format!(
            "writes {} storage",
            durabilities.iter().next().copied().unwrap_or("")
        ),
        _ => format!(
            "writes {} storage",
            durabilities.into_iter().collect::<Vec<_>>().join(" and ")
        ),
    }
}

fn describe_movements(movements: &[&syn::ExprMethodCall]) -> String {
    let methods = movements
        .iter()
        .map(|call| format!("`{}`", call.method))
        .collect::<std::collections::BTreeSet<_>>();
    format!(
        "moves value with {}",
        methods.into_iter().collect::<Vec<_>>().join(", ")
    )
}
