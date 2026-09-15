//! Shared queries over a parsed file.
//!
//! Detectors are meant to read as a statement of the pattern they encode, so the
//! incidental work — finding the entrypoints of a contract, telling a storage write
//! from a storage read, deciding whether an identifier looks like an amount — lives
//! here instead. Every function is deliberately conservative: where a query cannot tell
//! for sure, it says no, and the rule that depends on it documents the resulting blind
//! spot.

use std::collections::BTreeSet;

use syn::spanned::Spanned as _;
use syn::visit::Visit;
use syn::{Expr, ExprBinary, ExprMethodCall, ImplItem, Item, Signature, Stmt};

use crate::source::SourceFile;

/// The three storage durabilities, as spelled in the SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Durability {
    /// `storage().instance()` — attached to the contract, bumped as a whole.
    Instance,
    /// `storage().persistent()` — rent-paying, restorable after expiry.
    Persistent,
    /// `storage().temporary()` — expires and is gone.
    Temporary,
}

impl Durability {
    /// The accessor name as written in source.
    pub fn as_str(self) -> &'static str {
        match self {
            Durability::Instance => "instance",
            Durability::Persistent => "persistent",
            Durability::Temporary => "temporary",
        }
    }
}

/// One entrypoint of a `#[contractimpl]` block.
pub struct ContractFn<'a> {
    /// The Rust function name.
    pub name: String,
    /// Its signature.
    pub sig: &'a Signature,
    /// Its body.
    pub block: &'a syn::Block,
    /// True for `__constructor`, which runs at deploy time and cannot authorize.
    pub is_constructor: bool,
    /// The byte span of the signature, for reporting.
    pub span: proc_macro2::Span,
}

impl ContractFn<'_> {
    /// True for functions the analyser should skip entirely.
    ///
    /// Constructors cannot call `require_auth` — there is no caller to authorize — so
    /// flagging one for not authorizing anything would be a guaranteed false positive.
    /// Names beginning with an underscore are the SDK's own hooks and internal helpers.
    pub fn is_exempt(&self) -> bool {
        self.is_constructor || self.name.starts_with('_')
    }

    /// The identifiers of this entrypoint's parameters whose type is (or references)
    /// an `Address`.
    ///
    /// Used to report which argument a missing authorization is *about*, which is the
    /// difference between "this entrypoint is unprotected" and something a reader can
    /// check against the contract's intent.
    pub fn address_parameters(&self) -> Vec<String> {
        let mut names = Vec::new();
        for input in &self.sig.inputs {
            let syn::FnArg::Typed(pat_type) = input else {
                continue;
            };
            if !type_is_address(&pat_type.ty) {
                continue;
            }
            if let syn::Pat::Ident(ident) = pat_type.pat.as_ref() {
                names.push(ident.ident.to_string());
            }
        }
        names
    }
}

/// True when a type is, or refers to, an `Address`.
fn type_is_address(ty: &syn::Type) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Address")
            {
                self.found = true;
            }
            syn::visit::visit_path(self, path);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_type(ty);
    finder.found
}

/// True when an attribute's last path segment is `name`.
pub fn has_attribute(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    })
}

/// Every entrypoint of every `#[contractimpl]` block in the file.
///
/// Deliberately syntactic: a `#[contractimpl]` block is recognised by its attribute
/// rather than by resolving what the macro expands to, which keeps the analyser usable
/// on a file that has not been compiled.
///
/// # What counts as an entrypoint
///
/// The SDK's own `impl_pub_methods` exports **every public method** of a
/// `#[contractimpl]` block, and every method at all when the block implements a trait.
/// So that is the rule here, and it is the macro's behaviour rather than a guess: an
/// earlier version of this function required a `self` receiver, which no exported
/// Soroban entrypoint has — every one takes `env: Env` first — and would have made every
/// detector in this crate silently blind. A private method is a helper and receives no
/// incoming call, so it is not an entrypoint.
pub fn contract_fns(file: &SourceFile) -> Vec<ContractFn<'_>> {
    let mut found = Vec::new();

    for item in &file.ast.items {
        let Item::Impl(block) = item else {
            continue;
        };
        if !has_attribute(&block.attrs, "contractimpl") {
            continue;
        }
        // A trait impl gets the `pub` for free: `impl_pub_methods` accepts every method
        // when `trait_` is set, because trait methods cannot carry a visibility.
        let inherits_visibility = block.trait_.is_some();
        for impl_item in &block.items {
            let ImplItem::Fn(function) = impl_item else {
                continue;
            };
            if !inherits_visibility && !matches!(function.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let name = function.sig.ident.to_string();
            let is_constructor = name == "__constructor";
            found.push(ContractFn {
                name,
                sig: &function.sig,
                block: &function.block,
                is_constructor,
                span: function.sig.span(),
            });
        }
    }

    found
}

/// How an entrypoint is named in a finding's message.
///
/// One function rather than a `format!` at each call site, so that every detector names
/// an entrypoint the same way and a reader can match a message to a function by name.
pub fn entrypoint_label(entry: &ContractFn<'_>) -> String {
    format!("`{}`", entry.name)
}

/// Names of the functions declared in this file whose bodies call `require_auth`.
///
/// This is the "one level deep" resolution the missing-authorization rule documents:
/// a contract that delegates its authorization to a helper in the same file is not
/// flagged, because the check is there, just not inline.
pub fn local_fns_that_authorize(file: &SourceFile) -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    // Generic over the iterator rather than taking a slice so that a nested item — a
    // function declared inside a function — can be visited without allocating a vector
    // for it on the way.
    fn visit_items<'a>(items: impl IntoIterator<Item = &'a Item>, names: &mut BTreeSet<String>) {
        for item in items {
            match item {
                Item::Fn(function) => {
                    if calls_require_auth(&function.block) {
                        names.insert(function.sig.ident.to_string());
                    }
                    visit_items(function.block.stmts.iter().filter_map(stmt_as_item), names);
                }
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        visit_items(items.iter(), names);
                    }
                }
                Item::Impl(block) => {
                    for member in &block.items {
                        if let ImplItem::Fn(function) = member {
                            if calls_require_auth(&function.block) {
                                names.insert(function.sig.ident.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn stmt_as_item(stmt: &Stmt) -> Option<&Item> {
        match stmt {
            Stmt::Item(item) => Some(item),
            _ => None,
        }
    }

    visit_items(file.ast.items.iter(), &mut names);
    names
}

/// True when the block calls `require_auth`, `require_auth_for_args`, or
/// `__check_auth` on anything.
///
/// All three are authorization: the first two ask the host for a credential, and a
/// contract that calls its own account hook is making the same decision by hand.
pub fn calls_require_auth(block: &syn::Block) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            let name = call.method.to_string();
            if matches!(
                name.as_str(),
                "require_auth" | "require_auth_for_args" | "__check_auth"
            ) {
                self.found = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_block(block);
    finder.found
}

/// Method names called anywhere in a block.
pub fn called_methods(block: &syn::Block) -> Vec<String> {
    struct Finder {
        names: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            self.names.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut finder = Finder { names: Vec::new() };
    finder.visit_block(block);
    finder.names
}

/// Names of free functions called anywhere in a block, including `Self::name` forms.
pub fn called_functions(block: &syn::Block) -> Vec<String> {
    struct Finder {
        names: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = call.func.as_ref() {
                if let Some(segment) = path.path.segments.last() {
                    self.names.push(segment.ident.to_string());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut finder = Finder { names: Vec::new() };
    finder.visit_block(block);
    finder.names
}

/// True when the expression is a call to `something.storage()`.
fn is_storage_accessor(expr: &Expr) -> bool {
    matches!(expr, Expr::MethodCall(call) if call.method == "storage")
}

/// True when anything in the receiver chain is a `storage()` call.
///
/// Matching on the receiver chain rather than on an `Env` type is what makes this work
/// without type information: `env.storage().instance().set(..)` and
/// `self.env.storage()...` both qualify, and a method called `set` on something else
/// does not.
pub fn is_storage_method(call: &ExprMethodCall) -> bool {
    let method = call.method.to_string();
    if !matches!(
        method.as_str(),
        "set" | "get" | "has" | "remove" | "update" | "extend_ttl" | "extend_ttl_for_code"
    ) {
        return false;
    }
    receiver_chain_has_storage(&call.receiver)
}

/// True when the chain of receivers rooted at `expr` includes `storage()`.
fn receiver_chain_has_storage(expr: &Expr) -> bool {
    if is_storage_accessor(expr) {
        return true;
    }
    if let Expr::MethodCall(inner) = expr {
        return receiver_chain_has_storage(&inner.receiver);
    }
    if let Expr::Field(inner) = expr {
        return receiver_chain_has_storage(&inner.base);
    }
    false
}

/// The durability a storage call operates on, if it names one.
///
/// The accessor sits in the receiver chain — `env.storage().persistent().set(..)` — so
/// this walks outwards from the call until it finds `instance()`, `persistent()` or
/// `temporary()`, stopping at the first one because that is the innermost accessor the
/// compiler would use.
pub fn durability(call: &ExprMethodCall) -> Option<Durability> {
    fn find(expr: &Expr) -> Option<Durability> {
        if let Expr::MethodCall(inner) = expr {
            let durability = match inner.method.to_string().as_str() {
                "instance" => Some(Durability::Instance),
                "persistent" => Some(Durability::Persistent),
                "temporary" => Some(Durability::Temporary),
                _ => None,
            };
            return durability.or_else(|| find(&inner.receiver));
        }
        if let Expr::Field(inner) = expr {
            return find(&inner.base);
        }
        None
    }
    find(&call.receiver)
}

/// True when the storage call writes: `set`, `remove` or `update`.
pub fn is_storage_write(call: &ExprMethodCall) -> bool {
    is_storage_method(call)
        && matches!(
            call.method.to_string().as_str(),
            "set" | "remove" | "update"
        )
}

/// True when the storage call reads: `get` or `has`.
pub fn is_storage_read(call: &ExprMethodCall) -> bool {
    is_storage_method(call) && matches!(call.method.to_string().as_str(), "get" | "has")
}

/// True when the storage call extends an entry's time to live.
pub fn is_ttl_extension(call: &ExprMethodCall) -> bool {
    is_storage_method(call) && call.method.to_string().starts_with("extend_ttl")
}

fn collect_method_calls(
    block: &syn::Block,
    keep: impl Fn(&ExprMethodCall) -> bool,
) -> Vec<&ExprMethodCall> {
    struct Finder<'a, F> {
        keep: F,
        found: Vec<&'a ExprMethodCall>,
    }
    impl<'ast, F: Fn(&ExprMethodCall) -> bool> Visit<'ast> for Finder<'ast, F> {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if (self.keep)(call) {
                self.found.push(call);
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut finder = Finder {
        keep,
        found: Vec::new(),
    };
    finder.visit_block(block);
    finder.found
}

/// Every storage write in a block.
pub fn storage_writes(block: &syn::Block) -> Vec<&ExprMethodCall> {
    collect_method_calls(block, is_storage_write)
}

/// Every storage read in a block.
pub fn storage_reads(block: &syn::Block) -> Vec<&ExprMethodCall> {
    collect_method_calls(block, is_storage_read)
}

/// Storage calls of any kind, in source order.
pub fn storage_calls(block: &syn::Block) -> Vec<&ExprMethodCall> {
    collect_method_calls(block, is_storage_method)
}

/// True when the call moves value: a token transfer, mint, burn or approval.
///
/// Restricted to calls made on something that looks like a generated client, because
/// `transfer` is also a perfectly ordinary method name on a user's own types. The
/// restriction is a documented blind spot: a token moved through a wrapper the analyser
/// cannot recognise is not counted as a value movement.
pub fn is_value_moving(call: &ExprMethodCall) -> bool {
    let method = call.method.to_string();
    if !matches!(
        method.as_str(),
        "transfer" | "transfer_from" | "mint" | "burn" | "approve" | "clawback"
    ) {
        return false;
    }
    receiver_looks_like_client(&call.receiver)
}

/// True when the receiver is a `*::Client::new(..)` call or an identifier named like a
/// client.
///
/// Both spellings of the generated client are recognised: `token::Client::new(..)`, which
/// is what `#[contractclient]` emits, and `TokenClient::new(..)`, which is the name the
/// same macro produces for a token interface. Matching only the exact segment `Client`
/// missed the second, and the fixtures for the value-movement rule are what caught it.
fn receiver_looks_like_client(expr: &Expr) -> bool {
    match expr {
        Expr::Call(call) => match call.func.as_ref() {
            Expr::Path(path) => path.path.segments.iter().any(|segment| {
                let name = segment.ident.to_string();
                name == "Client" || name.ends_with("Client")
            }),
            _ => false,
        },
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| is_client_like(&segment.ident.to_string())),
        Expr::Field(field) => receiver_looks_like_client(&field.base),
        Expr::MethodCall(inner) => receiver_looks_like_client(&inner.receiver),
        _ => false,
    }
}

fn is_client_like(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered == "client" || lowered.ends_with("_client") || lowered.starts_with("token")
}

/// Every value-moving call in a block.
pub fn value_movements(block: &syn::Block) -> Vec<&ExprMethodCall> {
    collect_method_calls(block, is_value_moving)
}

/// Names of the segments an identifier is made of.
///
/// Split on anything that is not alphanumeric — which is what makes a path work: the
/// interesting half of `DataKey::Allowance` and `self.env.balance` is the last segment,
/// and neither would be found by matching the whole string. Split again inside a run of
/// alphanumerics at a lower-to-upper transition, so `totalSupply` reads as `total` and
/// `supply`.
///
/// Segment matching rather than substring matching, because `allowed` must not read as
/// `allow` and `format` must not read as `amount`.
pub fn segments(name: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut previous_lowercase = false;

    for ch in name.chars() {
        if !ch.is_alphanumeric() {
            push_segment(&mut segments, &mut current);
            previous_lowercase = false;
            continue;
        }
        if ch.is_uppercase() && previous_lowercase {
            push_segment(&mut segments, &mut current);
        }
        previous_lowercase = ch.is_lowercase() || ch.is_ascii_digit();
        current.push(ch);
    }
    push_segment(&mut segments, &mut current);
    segments
}

/// Moves `current` into `segments` lowercased, if it holds anything.
fn push_segment(segments: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        segments.push(current.to_ascii_lowercase());
        current.clear();
    }
}

/// Words that make a value look like an amount of money or a supply.
///
/// Used by two rules — unchecked arithmetic and durability misuse — as the signal that
/// an operation is about value rather than about a counter. Being a heuristic is the
/// point: the rules state it and the fixtures pin both directions.
const AMOUNT_WORDS: [&str; 22] = [
    "amount",
    "balance",
    "balances",
    "supply",
    "allowance",
    "total",
    "fee",
    "fees",
    "value",
    "price",
    "share",
    "shares",
    "asset",
    "assets",
    "debt",
    "reserve",
    "deposit",
    "principal",
    "interest",
    "cap",
    "collateral",
    "liquidity",
];

/// True when an identifier's segments include a word that suggests value.
pub fn looks_like_amount(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|segment| AMOUNT_WORDS.contains(&segment.as_str()))
}

/// Words that make stored data look like it must survive.
const DURABLE_WORDS: [&str; 12] = [
    "balance",
    "balances",
    "supply",
    "total",
    "admin",
    "owner",
    "treasury",
    "reserve",
    "principal",
    "collateral",
    "config",
    "allowance",
];

/// True when an identifier names data that must not expire.
pub fn looks_like_must_survive(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|segment| DURABLE_WORDS.contains(&segment.as_str()))
}

/// Words that make stored data look short-lived.
const EPHEMERAL_WORDS: [&str; 8] = [
    "nonce",
    "sig",
    "signature",
    "signatures",
    "expiry",
    "expiring",
    "temporary",
    "session",
];

/// True when an identifier names data that is worthless once it has expired.
pub fn looks_like_ephemeral(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|segment| EPHEMERAL_WORDS.contains(&segment.as_str()))
}

/// Words that make stored data look like it belongs to one account rather than to the
/// contract as a whole.
///
/// This is the distinction between instance and persistent storage that the SDK's own
/// documentation draws: instance storage is a single entry loaded with the contract on
/// every invocation, so it is for contract-wide configuration, and per-account data put
/// there is both unshardable and unbounded.
const PER_ACCOUNT_WORDS: [&str; 14] = [
    "user",
    "users",
    "account",
    "accounts",
    "holder",
    "holders",
    "sender",
    "recipient",
    "balance",
    "balances",
    "allowance",
    "allowances",
    "deposit",
    "position",
];

/// True when an identifier names per-account data.
pub fn looks_like_per_account(name: &str) -> bool {
    segments(name)
        .iter()
        .any(|segment| PER_ACCOUNT_WORDS.contains(&segment.as_str()))
}

/// Every identifier mentioned in an expression, in source order.
pub fn identifiers(expr: &Expr) -> Vec<String> {
    struct Finder {
        names: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
            self.names.push(ident.to_string());
        }
    }
    let mut finder = Finder { names: Vec::new() };
    finder.visit_expr(expr);
    finder.names
}

/// True when the expression contains a storage access anywhere inside it.
pub fn contains_storage_access(expr: &Expr) -> bool {
    struct Finder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if is_storage_method(call) {
                self.found = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut finder = Finder { found: false };
    finder.visit_expr(expr);
    finder.found
}

/// The name bound by a `let` whose initialiser reads storage.
///
/// This is the shape a storage-bounded loop usually takes:
///
/// ```ignore
/// let count: u32 = env.storage().instance().get(&COUNT).unwrap();
/// for i in 0..count { /* ... */ }
/// ```
///
/// The bound is `count`, a local, and nothing in the loop mentions storage at all —
/// which is why a detector that only looked inside the loop would miss it.
pub fn storage_derived_bindings(block: &syn::Block) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for stmt in &block.stmts {
        let Stmt::Local(local) = stmt else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        if !contains_storage_access(&init.expr) {
            continue;
        }
        collect_pattern_names(&local.pat, &mut names);
    }

    // A binding that is arithmetic on a storage-derived value is still storage-derived:
    // `let end = start + 10;` bounds a loop by a stored value too.
    let mut grew = true;
    while grew {
        grew = false;
        for stmt in &block.stmts {
            let Stmt::Local(local) = stmt else {
                continue;
            };
            let Some(init) = &local.init else {
                continue;
            };
            if identifiers(&init.expr)
                .iter()
                .any(|name| names.contains(name))
            {
                let before = names.len();
                collect_pattern_names(&local.pat, &mut names);
                grew |= names.len() > before;
            }
        }
    }

    names
}

fn collect_pattern_names(pat: &syn::Pat, out: &mut BTreeSet<String>) {
    struct Finder<'a> {
        out: &'a mut BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
            self.out.insert(pat.ident.to_string());
            syn::visit::visit_pat_ident(self, pat);
        }
    }
    let mut finder = Finder { out };
    finder.visit_pat(pat);
}

/// A statically known trip count, for a loop whose bound is a literal or a constant
/// range.
///
/// Returns `None` for anything the analyser cannot pin down at compile time, which
/// includes every argument-derived bound. `None` means "unknown", not "unbounded": the
/// callers decide how to describe that.
pub fn static_loop_bound(expr: &Expr) -> Option<u64> {
    match expr {
        // `for i in 0..N` and `for i in 0..=N`.
        Expr::ForLoop(for_loop) => range_length(&for_loop.expr),
        // `while i < N`, plus the same comparison written the other way round.
        Expr::While(while_loop) => comparison_bound(&while_loop.cond),
        _ => None,
    }
}

fn range_length(iterator: &Expr) -> Option<u64> {
    let Expr::Range(range) = iterator else {
        return None;
    };
    let start = range.start.as_deref().and_then(literal_u64).unwrap_or(0);
    let end = range.end.as_deref().and_then(literal_u64)?;
    let length = if matches!(range.limits, syn::RangeLimits::Closed(_)) {
        end.checked_add(1)? - start
    } else {
        end.checked_sub(start)?
    };
    Some(length)
}

fn comparison_bound(cond: &Expr) -> Option<u64> {
    let Expr::Binary(binary) = cond else {
        return None;
    };
    if !matches!(
        binary.op,
        syn::BinOp::Lt(_) | syn::BinOp::Le(_) | syn::BinOp::Gt(_) | syn::BinOp::Ge(_)
    ) {
        return None;
    }
    literal_u64(&binary.right).or_else(|| literal_u64(&binary.left))
}

fn literal_u64(expr: &Expr) -> Option<u64> {
    let Expr::Lit(literal) = expr else {
        return None;
    };
    let syn::Lit::Int(int) = &literal.lit else {
        return None;
    };
    int.base10_parse().ok()
}

/// Calls each expression in a tree together with its ancestors, outermost first.
///
/// The ancestor stack is what lets a detector ask questions that are about position
/// rather than shape: "is this arithmetic inside a `checked_add` argument", "how many
/// times does this read happen given the loops around it".
pub fn for_each_expr_in_block<'ast>(
    block: &'ast syn::Block,
    visit: &mut dyn FnMut(&[&'ast Expr], &'ast Expr),
) {
    let mut walker = Walker {
        stack: Vec::new(),
        visit,
    };
    walker.visit_block(block);
}

struct Walker<'a, 'v> {
    stack: Vec<&'a Expr>,
    visit: &'v mut dyn FnMut(&[&'a Expr], &'a Expr),
}

impl<'ast> Visit<'ast> for Walker<'ast, '_> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        (self.visit)(&self.stack, expr);
        self.stack.push(expr);
        syn::visit::visit_expr(self, expr);
        self.stack.pop();
    }
}

/// The operator of a binary arithmetic expression, if it is one.
pub fn arithmetic_op(expr: &Expr) -> Option<&'static str> {
    let Expr::Binary(binary) = expr else {
        return None;
    };
    match binary.op {
        syn::BinOp::Add(_) | syn::BinOp::AddAssign(_) => Some("+"),
        syn::BinOp::Sub(_) | syn::BinOp::SubAssign(_) => Some("-"),
        syn::BinOp::Mul(_) | syn::BinOp::MulAssign(_) => Some("*"),
        _ => None,
    }
}

/// The binary expression behind an arithmetic node.
pub fn as_binary(expr: &Expr) -> Option<&ExprBinary> {
    match expr {
        Expr::Binary(binary) if arithmetic_op(expr).is_some() => Some(binary),
        _ => None,
    }
}

/// True when the call's method is one of the checked arithmetic families.
pub fn is_checked_arithmetic(call: &ExprMethodCall) -> bool {
    let name = call.method.to_string();
    name.starts_with("checked_")
        || name.starts_with("saturating_")
        || name.starts_with("overflowing_")
        || name.starts_with("wrapping_")
}

/// True when `range` lies inside one of the ranges already reported.
///
/// Used by detectors that walk an expression tree to report the outermost node of a
/// thing rather than every node in it: a `balance + amount + fee` is one unchecked sum,
/// not two, and a loop inside a loop is one iteration structure, not two. The ranges are
/// byte ranges as `Span::byte_range` produces them, so a detector can pass one straight
/// through.
pub fn span_contained_in(
    range: &core::ops::Range<usize>,
    reported: &[core::ops::Range<usize>],
) -> bool {
    reported
        .iter()
        .any(|seen| seen.start <= range.start && range.end <= seen.end)
}

/// True when an expression is one of the three loop forms.
pub fn is_loop(expr: &Expr) -> bool {
    matches!(expr, Expr::ForLoop(_) | Expr::While(_) | Expr::Loop(_))
}

/// The body of a loop, or `None` for anything else.
pub fn loop_body(expr: &Expr) -> Option<&syn::Block> {
    match expr {
        Expr::ForLoop(loop_) => Some(&loop_.body),
        Expr::While(loop_) => Some(&loop_.body),
        Expr::Loop(loop_) => Some(&loop_.body),
        _ => None,
    }
}

/// The expression a loop's trip count comes from: the iterator of a `for`, the
/// condition of a `while`.
///
/// `None` for a bare `loop`, whose bound is a `break` inside the body if it exists at
/// all. Not attempting to find one is deliberate: a `break` condition is a data flow
/// question, and answering it wrongly here would mis-count the read budget.
pub fn loop_header(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::ForLoop(loop_) => Some(&loop_.expr),
        Expr::While(loop_) => Some(&loop_.cond),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(text: &str) -> SourceFile {
        SourceFile::parse("t.rs", text.to_owned()).expect("the fixture must parse")
    }

    #[test]
    fn segments_split_snake_and_camel_case() {
        assert_eq!(segments("fee_bps"), vec!["fee", "bps"]);
        assert_eq!(segments("totalSupply"), vec!["total", "supply"]);
        assert_eq!(segments("userBalance2"), vec!["user", "balance2"]);
        assert_eq!(segments("allowed"), vec!["allowed"]);
        assert_eq!(
            segments("DataKey::Balance"),
            vec!["data", "key", "balance"],
            "a path is every one of its segments"
        );
    }

    #[test]
    fn amount_words_match_segments_not_substrings() {
        assert!(looks_like_amount("total_supply"));
        assert!(looks_like_amount("userBalance"));
        assert!(
            !looks_like_amount("allowed"),
            "`allowed` is not an amount, though it contains `allow`"
        );
        assert!(
            !looks_like_amount("format"),
            "`format` contains neither `fee` nor `amount` as a segment"
        );
        assert!(!looks_like_amount("counter"));
    }

    #[test]
    fn a_contract_impl_yields_its_public_methods() {
        // The fixture is the shape real contracts are written in: no `self` receiver
        // anywhere, `env` first. The private method is the one that is not exported —
        // matching the SDK's `impl_pub_methods`, which filters on visibility.
        let f = file(
            "#[contractimpl]\n\
             impl C {\n\
             \x20   pub fn __constructor(env: Env) {}\n\
             \x20   pub fn maybe(env: Env) -> u32 { 1 }\n\
             \x20   fn helper(env: Env) -> u32 { 2 }\n\
             \x20   pub fn other(env: Env, who: Address) {}\n\
             }\n",
        );
        let names = contract_fns(&f)
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec!["__constructor", "maybe", "other"],
            "a private method is a helper and receives no call"
        );
        let entries = contract_fns(&f);
        assert!(entries[0].is_exempt(), "a constructor cannot authorize");
        assert!(!entries[1].is_exempt());
        assert!(
            !entries[2].is_exempt(),
            "a public method taking an address is exactly what must be checked"
        );
    }

    #[test]
    fn a_trait_impl_exports_its_methods_without_visibility() {
        let f = file(
            "#[contractimpl]\n\
             impl SomeTrait for C {\n\
             \x20   fn from_trait(env: Env) {}\n\
             }\n",
        );
        let names = contract_fns(&f)
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["from_trait"]);
    }

    #[test]
    fn contract_fns_are_found_only_inside_contractimpl() {
        let f = file("impl C {\n    pub fn not_a_contract_method(env: Env) {}\n}\n");
        assert!(contract_fns(&f).is_empty());
    }

    #[test]
    fn an_underscore_prefixed_method_is_exempt() {
        let f = file(
            "#[contractimpl]\n\
             impl C {\n\
             \x20   pub fn _check_auth(env: Env) {}\n\
             }\n",
        );
        let entries = contract_fns(&f);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_exempt(), "underscore hooks are SDK plumbing");
        assert_eq!(entrypoint_label(&entries[0]), "`_check_auth`");
    }

    #[test]
    fn a_function_cannot_be_named_with_only_an_underscore() {
        // The SDK's macro machinery is sometimes described as allowing `fn _(..)` for an
        // entrypoint whose exported name comes from `export_if`. Rust does not accept
        // that spelling, so there is no unnamed-entrypoint case to model here — which is
        // why this type has no field for one.
        assert!(
            SourceFile::parse("t.rs", "impl C {\n    fn _(env: Env) {}\n}\n".to_owned()).is_err(),
            "if this ever parses, the analyser needs to model unnamed entrypoints"
        );
    }

    #[test]
    fn address_parameters_are_recognised_through_references() {
        let f = file(
            "#[contractimpl]\n\
             impl C {\n\
             \x20   pub fn mint(env: Env, admin: Address, to: &Address, amount: i128) {}\n\
             }\n",
        );
        let entries = contract_fns(&f);
        assert_eq!(entries[0].address_parameters(), vec!["admin", "to"]);
    }

    #[test]
    fn storage_writes_reads_and_durabilities_are_distinguished() {
        let f = file(
            "fn f(env: Env) {\n\
             \x20   env.storage().instance().set(&a, &1);\n\
             \x20   let x = env.storage().persistent().get(&b);\n\
             \x20   env.storage().temporary().remove(&c);\n\
             \x20   other.set(&a, &1);\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let writes = storage_writes(&function.block);
        assert_eq!(writes.len(), 2, "set and remove, but not `other.set`");
        assert_eq!(durability(writes[0]), Some(Durability::Instance));
        assert_eq!(durability(writes[1]), Some(Durability::Temporary));

        let reads = storage_reads(&function.block);
        assert_eq!(reads.len(), 1);
        assert_eq!(durability(reads[0]), Some(Durability::Persistent));
    }

    #[test]
    fn durability_is_found_through_a_field_receiver() {
        let f = file(
            "fn f(env: Env, s: S) {\n\
             \x20   env.storage().persistent().set(&a, &1);\n\
             \x20   s.storage().temporary().set(&b, &1);\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let writes = storage_writes(&function.block);
        assert_eq!(durability(writes[0]), Some(Durability::Persistent));
        assert_eq!(
            durability(writes[1]),
            Some(Durability::Temporary),
            "a storage handle held in a field is still storage"
        );
    }

    #[test]
    fn per_account_and_durable_words_are_distinct_signals() {
        assert!(looks_like_per_account("DataKey::Allowance"));
        assert!(looks_like_per_account("user_balance"));
        assert!(looks_like_must_survive("DataKey::Balance"));
        assert!(!looks_like_per_account("FeeBps"), "contract-wide config");
        assert!(!looks_like_must_survive("Nonce"));
    }

    #[test]
    fn value_movement_needs_a_client_like_receiver() {
        let f = file(
            "fn f(env: Env) {\n\
             \x20   TokenClient::new(&env, &t).transfer(&a, &b);\n\
             \x20   client.transfer(&a, &b);\n\
             \x20   bookkeeping.transfer(&a, &b);\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let moves = value_movements(&function.block);
        assert_eq!(
            moves.len(),
            2,
            "a `transfer` on something not client-shaped is not a token movement"
        );
    }

    #[test]
    fn storage_derived_bindings_follow_arithmetic() {
        let f = file(
            "fn f(env: Env, given: u32) {\n\
             \x20   let count: u32 = env.storage().instance().get(&K).unwrap();\n\
             \x20   let end = count + 10;\n\
             \x20   let guard = given * 2;\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let derived = storage_derived_bindings(&function.block);
        assert!(derived.contains("count"), "{derived:?}");
        assert!(derived.contains("end"), "{derived:?}");
        assert!(
            !derived.contains("guard"),
            "an argument bound is not storage-derived"
        );
    }

    #[test]
    fn static_loop_bounds_are_read_from_literals_only() {
        let f = file(
            "fn f(x: u32) {\n\
             \x20   for i in 0..10 {}\n\
             \x20   while i < 42 {}\n\
             \x20   for j in 0..x {}\n\
             \x20   for k in items.iter() {}\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let bounds = function
            .block
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Expr(expr, _) => Some(static_loop_bound(expr)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(bounds, vec![Some(10), Some(42), None, None]);
    }

    #[test]
    fn key_expressions_are_read_from_the_whole_expression() {
        let f = file(
            "fn f(user: Address, env: Env) {\n\
             \x20   env.storage()\n\
             \x20       .persistent()\n\
             \x20       .set(&DataKey::Balance(user.clone()), &1);\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let writes = storage_writes(&function.block);
        let args = &writes[0].args;
        let key = args.first().expect("set takes a key");
        let names = identifiers(key);
        assert!(names.iter().any(|name| name == "Balance"), "{names:?}");
        assert!(names.iter().any(|name| name == "user"), "{names:?}");
    }

    #[test]
    fn require_auth_is_found_through_the_whole_body() {
        let f = file("fn f(who: Address) {\n    who.require_auth();\n}\n");
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        assert!(calls_require_auth(&function.block));

        let f = file("fn f(who: Address) {\n    if x { who.require_auth(); }\n}\n");
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        assert!(
            calls_require_auth(&function.block),
            "a guard does not make the call invisible"
        );
    }

    #[test]
    fn loop_helpers_pick_out_the_body_and_the_bound() {
        let f = file(
            "fn f(items: V, env: Env) {\n\
             \x20   for item in items.iter() { env.storage().persistent().get(&item); }\n\
             \x20   while i < 10 { i += 1; }\n\
             \x20   loop { break; }\n\
             }\n",
        );
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let loops = function
            .block
            .stmts
            .iter()
            .filter_map(|stmt| match stmt {
                Stmt::Expr(expr, _) if is_loop(expr) => Some(expr),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(loops.len(), 3);
        assert!(loop_body(loops[0]).is_some());
        assert!(
            loop_header(loops[0]).is_some_and(|header| !contains_storage_access(header)),
            "a for loop's iterator is not its body"
        );
        assert!(
            !storage_calls(loop_body(loops[0]).expect("a body")).is_empty(),
            "a read inside the body is found from the body"
        );
        assert!(
            loop_header(loops[1]).is_some(),
            "a while loop has a condition"
        );
        assert!(
            loop_header(loops[2]).is_none(),
            "a bare loop's bound is a break, which is not analysed"
        );
    }

    #[test]
    fn containment_recognises_inner_spans() {
        let reported = [10..40, 100..120];
        assert!(span_contained_in(&(12..20), &reported));
        assert!(span_contained_in(&(10..40), &reported));
        assert!(!span_contained_in(&(0..10), &reported));
        assert!(!span_contained_in(&(30..45), &reported));
        assert!(!span_contained_in(&(12..20), &[]));
    }

    #[test]
    fn for_each_expr_sees_ancestors_outermost_first() {
        let f = file("fn f() {\n    let x = a + b;\n}\n");
        let Item::Fn(function) = &f.ast.items[0] else {
            panic!()
        };
        let mut seen = None;
        for_each_expr_in_block(&function.block, &mut |ancestors, expr| {
            if arithmetic_op(expr) == Some("+") {
                seen = Some(ancestors.len());
            }
        });
        assert!(seen.is_some(), "the addition should be visited");
    }
}
