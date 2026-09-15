// `soroban-unchecked-arithmetic`: `+`, `-` or `*` on a value that looks like money.
//
// # Why this is Soroban-specific
//
// In Rust generally, `a + b` on integers is a decision you can look up: debug builds
// panic and release builds wrap, unless the profile says otherwise. On Soroban there is
// no such ambiguity — contracts are deployed with `overflow-checks = true` (the SDK's
// own template sets it, and this repository's workspace profile matches it), so `a + b`
// that overflows **traps**, and a trapped invocation is a failed invocation.
//
// The consequence is not a wrong balance. It is a denial of service with a precise
// trigger: a token whose `transfer` computes `balance - amount` without checking can be
// made to fail by any holder of a balance, and a contract that sums a vector of fees
// can be made un-callable by one large entry. Worse, the failing call is the one that
// would *stop* the problem, so a contract can reach a state it cannot be recovered from
// by the usual path.
//
// # Why it is only a warning-level finding
//
// A trap loses no funds, which is why this rule sits below the authorization rules
// rather than at the top: it is a liveness bug, not a theft. That ordering is
// deliberate and is stated in one place, [`crate::severity`].
//
// # The heuristic, and its boundary
//
// "Looks like money" is a word list over identifier segments — `balance`, `amount`,
// `supply`, `fee` and friends. The rule is therefore `heuristic: true` in its metadata,
// which reaches SARIF consumers as a `precision` of `medium`. Two consequences worth
// knowing: arithmetic on a value named `x` is not reported, and arithmetic on a value
// named `price_per_share_count` is. Segment matching rather than substring matching
// keeps `allowed` from reading as `allow`, but it cannot make a word list complete.

use std::collections::BTreeSet;

use syn::spanned::Spanned as _;
use syn::{Expr, ExprBinary};

use crate::detector::{Detector as DetectorBehaviour, DetectorCtx, Findings};
use crate::syntax;

/// The detector.
pub struct Detector;

impl DetectorBehaviour for Detector {
    fn id(&self) -> &'static str {
        "soroban-unchecked-arithmetic"
    }

    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
        let file = ctx.file();

        for entry in syntax::contract_fns(file) {
            if entry.is_exempt() {
                continue;
            }

            // Reported spans, so that `balance + amount + fee` is one finding rather
            // than one per node in the same expression tree. The walk hands the outermost
            // expression first, so an inner node is always inside something already seen.
            let mut reported: Vec<core::ops::Range<usize>> = Vec::new();

            syntax::for_each_expr_in_block(entry.block, &mut |ancestors, expr| {
                let Some(operator) = syntax::arithmetic_op(expr) else {
                    return;
                };
                let Some(binary) = syntax::as_binary(expr) else {
                    return;
                };
                let range = expr.span().byte_range();
                if syntax::span_contained_in(&range, &reported) {
                    return;
                }
                if guarded(ancestors) {
                    return;
                }
                let Some(operands) = amount_operands(binary) else {
                    return;
                };

                reported.push(range);
                sink.report(
                    expr.span(),
                    format!(
                        "`{operator}` on {} is unchecked arithmetic: `{}` overflows rather \
                         than wrapping, and a contract with overflow checks on panics, \
                         failing the whole invocation",
                        describe_operands(&operands),
                        file.snippet_inline(expr.span()),
                    ),
                );
            });
        }
    }
}

/// True when a checked-equivalent call is already in the ancestry.
///
/// This is the one place the detector is lenient, and knowingly: `a.checked_add(b)` has
/// no arithmetic node at all, so the only way an arithmetic node can be inside a
/// `checked_*` call is as an argument — `x.checked_mul(a + b)` — and the argument is
/// still unchecked. Treating the ancestor as a guard avoids reporting the same intent
/// twice when someone has already reached for the checked family, at the cost of missing
/// that case. It is stated here rather than discovered by whoever reads the fixture next.
fn guarded(ancestors: &[&Expr]) -> bool {
    ancestors.iter().any(|ancestor| match ancestor {
        Expr::MethodCall(call) => syntax::is_checked_arithmetic(call),
        _ => false,
    })
}

/// The amount-like identifiers on the two sides of an arithmetic expression.
///
/// `None` when neither side names a value, which is the common case in the code this
/// rule is meant to leave alone: index arithmetic, counters, bit twiddling.
fn amount_operands(binary: &ExprBinary) -> Option<BTreeSet<String>> {
    let operands = syntax::identifiers(&binary.left)
        .into_iter()
        .chain(syntax::identifiers(&binary.right))
        .filter(|name| syntax::looks_like_amount(name))
        .collect::<BTreeSet<_>>();
    if operands.is_empty() {
        None
    } else {
        Some(operands)
    }
}

fn describe_operands(operands: &BTreeSet<String>) -> String {
    let names = operands
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    format!("a value that looks like an amount ({names})")
}
