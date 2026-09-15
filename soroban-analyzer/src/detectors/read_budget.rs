// `soroban-read-budget`: a static read-count estimate that exceeds the invocation ceiling.
//
// (Ordinary comments rather than `//!` documentation: a detector file is pulled in with
// `include!`, and rustc rejects inner attributes that arrive through a macro expansion.)
//
// # What is counted, and what that buys
//
// Every storage call in an entrypoint is one ledger entry read or written, and a
// Soroban invocation is bounded — the network charges per entry and refuses a
// transaction that asks for too many. The exact figure is a network parameter that can
// be re-tuned, and this rule states the one it is written against in one place:
// [`READ_CEILING`]. What the rule does is multiply: a read inside a loop of 20 costs 20,
// and twenty of those inside another loop of 20 costs 400 — a number the contract's
// author can compute and the caller cannot.
//
// This is the check that catches the shape the issue describes as "read-count
// estimation against the 200-read ceiling", and it is deliberately the *narrowest*
// reading of it: the estimate is only produced where every enclosing loop has a
// statically known trip count. Where one does not, the count is not estimated at all and
// is reported by [`super::unbounded_storage_loop`] instead. A finding from this rule
// therefore means "as written, this call cannot land", which is a claim strong enough to
// gate a merge on — and it is why the finding's message says how the number was reached,
// so a reader can check the arithmetic against the source.
//
// # Where the estimate is loose, in both directions
//
// * A `while i < 42` is counted as 42 iterations even if `i` starts at 40. That
//   over-estimates, which is the wrong direction for a gate, and is why the rule is
//   marked `heuristic: true`.
// * A read performed by a *called function* is not counted, because the call graph is
//   not built. The estimate is a floor on the reads in the entrypoint's own body.

use syn::Expr;

use crate::detector::{Detector as DetectorBehaviour, DetectorCtx, Findings};
use crate::syntax;

/// Ledger entries a single invocation may read.
///
/// The network's per-transaction read limit, as stated by the Soroban fee model. It is a
/// protocol parameter rather than a constant of the SDK, so it lives here with its
/// provenance rather than being buried in the detector: if the network raises it, this is
/// the one line that changes, and the rule's fixtures move with it.
pub const READ_CEILING: u64 = 200;

/// The detector.
pub struct Detector;

impl DetectorBehaviour for Detector {
    fn id(&self) -> &'static str {
        "soroban-read-budget"
    }

    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
        for entry in syntax::contract_fns(ctx.file()) {
            if entry.is_exempt() {
                continue;
            }
            let estimate = estimate_reads(entry.block);
            if estimate.total <= READ_CEILING {
                continue;
            }
            sink.report(entry.span, estimate.describe(&entry));
        }
    }
}

/// The result of counting one entrypoint's storage reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Estimate {
    /// Reads whose cost was multiplied out, summed.
    total: u64,
    /// How many storage calls contributed to `total`.
    sites: usize,
    /// One multiplier list per read site that contributed, so the widest can be named.
    factors: Vec<Vec<u64>>,
    /// Reads inside a loop whose trip count is not statically known, so not counted.
    unbounded_sites: usize,
}

impl Estimate {
    /// The message, naming the arithmetic it performed so a reader can check it.
    fn describe(&self, entry: &syntax::ContractFn<'_>) -> String {
        let label = syntax::entrypoint_label(entry);
        let busiest = self
            .factors
            .iter()
            .max_by_key(|factors| factors.iter().fold(1u64, |a, b| a.saturating_mul(*b)))
            .cloned()
            .unwrap_or_default();
        let shape = if busiest.is_empty() {
            "with no loop around it".to_owned()
        } else {
            format!(
                "the busiest of them inside {} nested iteration{}",
                busiest
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(" × "),
                if busiest.len() == 1 { "" } else { "s" }
            )
        };

        let mut message = format!(
            "{label} reads storage up to {} times: {} read site{}, {shape}. A Soroban \
             invocation may read at most {READ_CEILING} ledger entries, so this call cannot \
             land as written",
            self.total,
            self.sites,
            if self.sites == 1 { "" } else { "s" },
        );
        if self.unbounded_sites > 0 {
            message.push_str(&format!(
                ". A further {} read{} sits inside a loop whose count is not known here, so \
                 it is not part of that total",
                self.unbounded_sites,
                if self.unbounded_sites == 1 { "" } else { "s" },
            ));
        }
        message
    }
}

/// Counts the storage reads in a block, multiplying out the loops around each one.
fn estimate_reads(block: &syn::Block) -> Estimate {
    let mut estimate = Estimate::default();

    syntax::for_each_expr_in_block(block, &mut |ancestors, expr| {
        let Expr::MethodCall(call) = expr else {
            return;
        };
        if !syntax::is_storage_read(call) {
            return;
        }

        // The loops around this read, each contributing the number of times it runs the
        // read. One loop with an unknown count makes the whole product unknown, so the
        // read is excluded rather than guessed at.
        let mut factors = Vec::new();
        let mut bounded = true;
        for ancestor in ancestors {
            if !syntax::is_loop(ancestor) {
                continue;
            }
            match syntax::static_loop_bound(ancestor) {
                Some(count) => factors.push(count),
                None => {
                    bounded = false;
                    break;
                }
            }
        }

        if !bounded {
            estimate.unbounded_sites += 1;
            return;
        }

        // Saturating rather than wrapping: a product that overflows is one that exceeds
        // the ceiling by any measure, and the ceiling is what it is compared against.
        let cost = factors
            .iter()
            .try_fold(1u64, |product, factor| product.checked_mul(*factor))
            .unwrap_or(u64::MAX);
        estimate.total = estimate.total.saturating_add(cost);
        estimate.sites += 1;
        estimate.factors.push(factors);
    });

    estimate
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts the reads in the first entrypoint of a fixture.
    ///
    /// The fixtures are raw strings with real newlines because they are Rust source: a
    /// test that builds its input out of escape sequences is a test whose input nobody
    /// can read, which for a static analyser is a meaningful loss.
    fn estimate_of(source: &str) -> Estimate {
        let file =
            crate::source::SourceFile::parse("t.rs", source.to_owned()).expect("the fixture parses");
        let entry = syntax::contract_fns(&file)
            .into_iter()
            .next()
            .expect("the fixture has an entrypoint");
        estimate_reads(entry.block)
    }

    #[test]
    fn straight_line_reads_cost_one_each() {
        let estimate = estimate_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        env.storage().persistent().get(&A);
        env.storage().persistent().has(&B);
    }
}
"#,
        );
        assert_eq!(estimate.total, 2, "{estimate:?}");
        assert_eq!(estimate.sites, 2);
        assert!(estimate.factors.iter().all(Vec::is_empty));
    }

    #[test]
    fn nested_loops_multiply() {
        let estimate = estimate_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        for i in 0..20 {
            for j in 0..20 {
                env.storage().persistent().get(&A);
            }
        }
    }
}
"#,
        );
        assert_eq!(estimate.total, 400, "{estimate:?}");
        assert_eq!(estimate.factors, vec![vec![20, 20]]);
    }

    #[test]
    fn an_unknown_bound_is_excluded_rather_than_guessed() {
        let estimate = estimate_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env, n: u32) {
        for i in 0..n {
            env.storage().persistent().get(&A);
        }
        env.storage().persistent().get(&B);
    }
}
"#,
        );
        assert_eq!(
            estimate.total, 1,
            "only the read outside the loop can be counted: {estimate:?}"
        );
        assert_eq!(estimate.unbounded_sites, 1);
    }

    #[test]
    fn a_write_is_not_counted_as_a_read() {
        let estimate = estimate_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        env.storage().persistent().set(&A, &1);
        env.storage().persistent().extend_ttl(&A, 1, 2);
    }
}
"#,
        );
        assert_eq!(estimate.total, 0, "{estimate:?}");
    }

    #[test]
    fn a_while_loop_is_counted_from_its_comparison() {
        let estimate = estimate_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env) {
        let mut i = 0;
        while i < 12 {
            env.storage().persistent().get(&A);
            i += 1;
        }
    }
}
"#,
        );
        assert_eq!(
            estimate.total, 12,
            "an over-estimate is the safe direction for a ceiling: {estimate:?}"
        );
    }

    /// The message the detector would report for the first entrypoint of a fixture.
    fn message_of(source: &str) -> String {
        let file =
            crate::source::SourceFile::parse("t.rs", source.to_owned()).expect("the fixture parses");
        let entry = syntax::contract_fns(&file)
            .into_iter()
            .next()
            .expect("the fixture has an entrypoint");
        estimate_reads(entry.block).describe(&entry)
    }

    #[test]
    fn the_message_names_the_arithmetic_it_performed() {
        // 15 x 20 plus 7, so the two sites are added rather than multiplied together.
        let source = r#"
#[contractimpl]
impl C {
    pub fn sweep(env: Env) {
        for i in 0..15 {
            for j in 0..20 {
                env.storage().persistent().get(&A);
            }
        }
        for i in 0..7 {
            env.storage().persistent().get(&A);
        }
    }
}
"#;
        assert_eq!(estimate_of(source).total, 307);

        let message = message_of(source);
        assert!(message.contains("sweep"), "{message}");
        assert!(message.contains("307"), "{message}");
        assert!(message.contains("15 × 20"), "{message}");
        assert!(message.contains("200"), "{message}");
    }

    #[test]
    fn reads_inside_an_unknown_loop_are_reported_as_excluded() {
        let message = message_of(
            r#"
#[contractimpl]
impl C {
    pub fn f(env: Env, n: u32) {
        for i in 0..n {
            env.storage().persistent().get(&A);
        }
    }
}
"#,
        );
        assert!(message.contains("not known here"), "{message}");
    }
}
