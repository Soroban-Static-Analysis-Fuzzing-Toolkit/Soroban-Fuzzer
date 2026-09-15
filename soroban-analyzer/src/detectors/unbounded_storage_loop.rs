// `soroban-unbounded-storage-loop`: a loop whose trip count the contract does not bound.
//
// # The bug, in Soroban's terms
//
// A Soroban transaction has a fixed budget: instructions, memory, bytes read, and the
// number of ledger entries it touches. A loop whose count comes from an argument, from
// a collection the caller supplied, or from a value in storage has no place in that
// budget until the transaction is already running. The input that makes it exceed the
// budget is an input the contract accepts, and the failure mode is that the call traps
// — after the caller has paid for it, on a network where the caller cannot know the
// count in advance.
//
// This is the shape the issue calls "unbounded loops over storage", and it is worth
// separating from the two rules next to it:
//
// * [`super::read_budget`] counts reads it can bound *statically* and reports a total
//   over the ceiling. It deliberately skips the loops this rule reports, because a count
//   that cannot be computed is not a count.
// * [`super::unchecked_arithmetic`] is about a value overflowing; this is about a count
//   of iterations.
//
// # What "touches storage" means here
//
// The loop body must contain at least one storage call — `get`, `has`, `set`, `remove`,
// `update` or a TTL extension. A loop over an argument that only does arithmetic in
// registers is fast and bounded by nothing that matters, so it is not reported. That is
// also this rule's precision limit, and it is why the rule is marked `heuristic: true`:
// a body that calls a *function* which reads storage is invisible to it, and so is a
// collection built locally and iterated once. Both directions are pinned by fixtures.

use syn::spanned::Spanned as _;
use syn::Expr;

use crate::detector::{Detector as DetectorBehaviour, DetectorCtx, Findings};
use crate::syntax;

/// The detector.
pub struct Detector;

impl DetectorBehaviour for Detector {
    fn id(&self) -> &'static str {
        "soroban-unbounded-storage-loop"
    }

    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
        let file = ctx.file();

        for entry in syntax::contract_fns(file) {
            if entry.is_exempt() {
                continue;
            }

            // A count read out of storage is a distinct, worse case than one taken from an
            // argument: neither the caller nor the contract's author can see it from with
            // the call, and it grows with use.
            let from_storage = syntax::storage_derived_bindings(entry.block);
            let mut reported: Vec<core::ops::Range<usize>> = Vec::new();

            syntax::for_each_expr_in_block(entry.block, &mut |_, expr| {
                if !syntax::is_loop(expr) {
                    return;
                }
                // A statically known bound is not "unbounded"; whether it is *too large*
                // is the read-budget rule's question, which counts rather than guesses.
                if syntax::static_loop_bound(expr).is_some() {
                    return;
                }
                let range = expr.span().byte_range();
                if syntax::span_contained_in(&range, &reported) {
                    return;
                }
                let Some(body) = syntax::loop_body(expr) else {
                    return;
                };
                if syntax::storage_calls(body).is_empty() {
                    return;
                }

                reported.push(range);
                sink.report(expr.span(), message(&file.snippet_inline(expr.span()), expr, &from_storage));
            });
        }
    }
}

/// The finding's message: what the loop is, where its count comes from, and what it costs.
fn message(snippet: &str, loop_expr: &Expr, from_storage: &std::collections::BTreeSet<String>) -> String {
    let origin = match syntax::loop_header(loop_expr) {
        Some(header) => {
            let storage_bound = syntax::identifiers(header)
                .into_iter()
                .find(|name| from_storage.contains(name));
            match storage_bound {
                Some(name) => format!(
                    "the number of iterations is `{name}`, read from storage, so it is whatever \
                     a previous call left there"
                ),
                None => "the number of iterations comes from the contract's input, so the \
                         caller chooses it"
                    .to_owned(),
            }
        }
        None => "this loop has no condition the analyser can bound, so it runs until it \
                 breaks out"
            .to_owned(),
    };

    format!(
        "`{snippet}` touches storage inside the loop and {origin}: a Soroban invocation may \
         read at most 200 ledger entries and has a fixed instruction budget, so a large \
         enough count makes this call trap after it is submitted"
    )
}
