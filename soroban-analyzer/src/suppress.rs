//! Suppressing a finding deliberately, in the code, where a reviewer will see it.
//!
//! Every static analyser has patterns that are correct in context. A Soroban entrypoint
//! that writes storage without requiring authorization is usually a bug — and sometimes
//! it is a permissionless entrypoint by design. Without a way to say so, the only
//! options are to live with a false positive or to turn the rule off, and turning a rule
//! off is how a tool stops being run.
//!
//! So a marker, on the comment lines directly above the item, or in the file's leading
//! comment block:
//!
//! ```text
//! // soroban-analyzer: allow(soroban-missing-require-auth)
//! pub fn open_registration(env: Env) { /* deliberately unauthenticated */ }
//! ```
//!
//! ```text
//! // soroban-analyzer: allow-file(all) // this file is generated
//! ```
//!
//! Two properties make this safe to rely on. Suppressions are **counted and reported**,
//! so a run never quietly loses a finding, and the marker has to live next to the code
//! it excuses, so a reviewer sees the exception in the diff that introduces it.

use std::collections::BTreeSet;

use syn::spanned::Spanned as _;
use syn::visit::Visit;

use crate::source::SourceFile;

/// The prefix every marker starts with.
const PREFIX: &str = "soroban-analyzer:";

/// How far above an item to look for a marker.
///
/// Bounded on purpose: an unbounded scan would let a marker buried a hundred lines away
/// — or inside an unrelated comment — silently excuse a finding.
const LOOK_UP_LINES: usize = 12;

/// Which scope a marker applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// Applies to the item whose comment block it sits in.
    Item,
    /// Applies to the whole file.
    File,
}

/// A parsed marker.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Marker {
    scope: Scope,
    /// Rule ids it excuses, or `None` for `all`.
    rules: Option<BTreeSet<String>>,
}

impl Marker {
    /// True when this marker excuses `rule_id`.
    fn excuses(&self, rule_id: &str) -> bool {
        match &self.rules {
            None => true,
            Some(rules) => rules.contains(rule_id),
        }
    }
}

/// Parses the markers in one comment line, if any.
///
/// Unknown marker text is ignored rather than treated as an error: a comment is prose
/// first, and a tool that rejects files because someone wrote something that looks like
/// a marker would be worse than one that ignores it.
fn parse_markers(line: &str) -> Vec<Marker> {
    let trimmed = line.trim_start_matches(|c: char| c == '/' || c.is_whitespace());
    let Some(rest) = trimmed.strip_prefix(PREFIX) else {
        return Vec::new();
    };

    let mut markers = Vec::new();
    for (scope, name) in [(Scope::File, "allow-file"), (Scope::Item, "allow")] {
        let Some(args) = rest.trim_start().strip_prefix(name) else {
            continue;
        };
        let args = args.trim_start();
        let Some(args) = args.strip_prefix('(') else {
            continue;
        };
        let Some((list, _)) = args.split_once(')') else {
            continue;
        };
        let list = list.trim();
        let rules = if list.eq_ignore_ascii_case("all") {
            None
        } else {
            let ids = list
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>();
            if ids.is_empty() {
                continue;
            }
            Some(ids)
        };
        markers.push(Marker { scope, rules });
    }
    markers
}

/// True when a marker excuses `rule_id` for whatever contains `offset`.
pub fn is_suppressed(file: &SourceFile, rule_id: &str, offset: usize) -> bool {
    // File scope first: it is the cheaper check and the broader one.
    if file
        .leading_comment_lines()
        .iter()
        .flat_map(|line| parse_markers(line))
        .any(|marker| marker.scope == Scope::File && marker.excuses(rule_id))
    {
        return true;
    }

    enclosing_items(file, offset).into_iter().any(|start| {
        comment_block_above(file, start).into_iter().any(|line| {
            parse_markers(line)
                .into_iter()
                .any(|marker| marker.scope == Scope::Item && marker.excuses(rule_id))
        })
    })
}

/// Byte offsets at which the items containing `offset` begin, innermost or outermost.
///
/// Every enclosing item is considered, not just the innermost, so a marker above an
/// `impl` block excuses findings anywhere inside it. That is the useful granularity for
/// a contract's whole privileged surface, and a per-method marker is still available for
/// the exception.
fn enclosing_items(file: &SourceFile, offset: usize) -> Vec<usize> {
    let mut collector = ItemRanges {
        offset,
        starts: Vec::new(),
    };
    collector.visit_file(&file.ast);
    collector.starts.sort_unstable();
    collector.starts.dedup();
    collector.starts
}

struct ItemRanges {
    offset: usize,
    starts: Vec<usize>,
}

impl ItemRanges {
    fn consider(&mut self, span: proc_macro2::Span) {
        let range = span.byte_range();
        if range.start <= self.offset && self.offset < range.end {
            self.starts.push(range.start);
        }
    }
}

impl<'ast> Visit<'ast> for ItemRanges {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        self.consider(item.span());
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        self.consider(item.span());
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        self.consider(item.span());
        syn::visit::visit_trait_item(self, item);
    }
}

/// The contiguous `//` comment lines immediately above a byte offset.
fn comment_block_above(file: &SourceFile, offset: usize) -> Vec<&str> {
    let start_line = file.location_at(offset).start.line;
    let mut lines = Vec::new();
    let mut line = start_line.saturating_sub(1);
    let lowest = start_line.saturating_sub(LOOK_UP_LINES + 1);
    while line > lowest && line >= 1 {
        let text = file.line_text(line).trim();
        if !text.starts_with("//") {
            break;
        }
        lines.push(text);
        line -= 1;
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(text: &str) -> SourceFile {
        SourceFile::parse("t.rs", text.to_owned()).expect("the fixture must parse")
    }

    fn first_item_offset(f: &SourceFile) -> usize {
        f.ast.items[0].span().byte_range().start
    }

    #[test]
    fn a_marker_above_an_item_suppresses_only_that_rule() {
        let f = file("// soroban-analyzer: allow(rule-a)\nfn f() {}\n");
        let offset = first_item_offset(&f);
        assert!(is_suppressed(&f, "rule-a", offset));
        assert!(
            !is_suppressed(&f, "rule-b", offset),
            "a marker names the rules it excuses"
        );
    }

    #[test]
    fn a_marker_can_name_several_rules_or_all_of_them() {
        let f = file("// soroban-analyzer: allow(rule-a, rule-b)\nfn f() {}\n");
        let offset = first_item_offset(&f);
        assert!(is_suppressed(&f, "rule-a", offset));
        assert!(is_suppressed(&f, "rule-b", offset));
        assert!(!is_suppressed(&f, "rule-c", offset));

        let f = file("// soroban-analyzer: allow(all)\nfn f() {}\n");
        assert!(is_suppressed(&f, "anything", first_item_offset(&f)));
    }

    #[test]
    fn a_marker_above_an_impl_covers_its_methods() {
        let f = file(
            "// soroban-analyzer: allow(rule-a)\n\
             impl T {\n    fn a() { let x = 1; }\n}\n",
        );
        let inner = f.text.find("let x").expect("the statement is there");
        assert!(
            is_suppressed(&f, "rule-a", inner),
            "a finding inside a method is excused by a marker above the impl"
        );
    }

    #[test]
    fn a_file_marker_needs_the_file_scope_spelling() {
        let f = file("// soroban-analyzer: allow-file(rule-a)\nfn f() {}\n");
        assert!(is_suppressed(&f, "rule-a", first_item_offset(&f)));
        assert!(!is_suppressed(&f, "rule-b", first_item_offset(&f)));

        // An item marker must not be read as a file marker.
        let f = file("// soroban-analyzer: allow(rule-a)\nfn f() {}\nfn g() {}\n");
        let second = f.ast.items[1].span().byte_range().start;
        assert!(
            !is_suppressed(&f, "rule-a", second),
            "an item marker stops at the item it sits above"
        );
    }

    #[test]
    fn a_marker_further_up_than_the_limit_does_not_apply() {
        let mut text = String::from("// soroban-analyzer: allow(rule-a)\n");
        for _ in 0..(LOOK_UP_LINES + 2) {
            text.push_str("// filler\n");
        }
        text.push_str("fn f() {}\n");
        let f = file(&text);
        assert!(!is_suppressed(&f, "rule-a", first_item_offset(&f)));
    }

    #[test]
    fn a_non_comment_line_stops_the_search() {
        let f = file("// soroban-analyzer: allow(rule-a)\nconst SEPARATOR: u8 = 0;\nfn f() {}\n");
        let offset = f.ast.items[1].span().byte_range().start;
        assert!(
            !is_suppressed(&f, "rule-a", offset),
            "code between the marker and the item means the marker is not about that item"
        );
    }

    #[test]
    fn ordinary_prose_that_looks_like_a_marker_is_ignored() {
        let f = file("// soroban-analyzer: allow-everything-please\nfn f() {}\n");
        assert!(!is_suppressed(&f, "rule-a", first_item_offset(&f)));
        assert!(parse_markers("// nothing to see here").is_empty());
        assert!(parse_markers("// soroban-analyzer: allow()").is_empty());
    }
}
