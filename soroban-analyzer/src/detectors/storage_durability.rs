// `soroban-storage-durability`: data that has to survive, stored where it cannot.
//
// # Why durability is a bug class, not a style choice
//
// Soroban gives an entry three choices, and they are not interchangeable:
//
// | Durability | Behaviour |
// | --- | --- |
// | `temporary` | Expires after its TTL and is **reclaimed**. There is no archive and no restore. |
// | `persistent` | Expires too, but is **archived** — the entry can be restored, and rent can be paid to keep it alive. |
// | `instance` | One entry for the whole contract, loaded on **every** invocation, bumped as a unit. |
//
// Two mistakes follow directly. Writing a balance into `temporary` storage means the
// balance silently disappears — the host reclaims the entry, and reading it afterwards
// finds nothing, which most contracts turn into a default of zero. And writing
// per-account data into `instance` storage means every call to the contract loads all of
// it: it is the one entry that cannot be sharded, so the contract gets slower and more
// expensive with each user, and eventually the entry itself is too large to load.
//
// # What it matches on
//
// The *name of the key* being written, which is the only thing available without types
// or a schema. `DataKey::Balance(user)` in temporary storage is a balance; the word list
// that decides so is in [`crate::syntax`], and this rule is marked `heuristic: true`
// because of it. A key called `K1` is not analysed at all — which is also why the rule's
// message quotes the key it matched, so a reader can see what it reacted to.

use syn::spanned::Spanned as _;
use syn::{Expr, ExprMethodCall};

use crate::detector::{Detector as DetectorBehaviour, DetectorCtx, Findings};
use crate::syntax::{self, Durability};

/// The detector.
pub struct Detector;

impl DetectorBehaviour for Detector {
    fn id(&self) -> &'static str {
        "soroban-storage-durability"
    }

    fn check(&self, ctx: &DetectorCtx<'_>, sink: &mut Findings<'_>) {
        let file = ctx.file();

        for entry in syntax::contract_fns(file) {
            if entry.is_exempt() {
                continue;
            }
            for write in syntax::storage_writes(entry.block) {
                let Some(durability) = syntax::durability(write) else {
                    continue;
                };
                let Some(key) = key_expression(write) else {
                    continue;
                };
                let names = syntax::identifiers(key);
                let key_text = file.snippet_inline(key.span());

                match durability {
                    // A key that names something which must outlive its TTL, in the one
                    // durability where it cannot.
                    Durability::Temporary => {
                        if let Some(word) = names.iter().find(|name| syntax::looks_like_must_survive(name))
                        {
                            sink.report(
                                key.span(),
                                format!(
                                    "`{key_text}` is written to temporary storage, but its key \
                                     names `{word}`: temporary entries expire and are \
                                     reclaimed with no archive and no restore, so the value \
                                     is gone rather than recoverable"
                                ),
                            );
                        }
                    }
                    // Per-account data in the one entry that every call loads.
                    Durability::Instance => {
                        if let Some(word) = names.iter().find(|name| syntax::looks_like_per_account(name))
                        {
                            sink.report(
                                key.span(),
                                format!(
                                    "`{key_text}` holds per-account data (`{word}`) in instance \
                                     storage: instance storage is a single entry loaded with \
                                     the contract on every invocation, so this grows without \
                                     bound as accounts arrive and is paid for by every other \
                                     call"
                                ),
                            );
                        }
                    }
                    // Persistent storage is the one that can hold anything: it expires,
                    // but it is restorable and it is sharded per key.
                    Durability::Persistent => {}
                }
            }
        }
    }
}

/// The key an entry is written under: the first argument of `set`/`remove`/`update`.
fn key_expression(call: &ExprMethodCall) -> Option<&Expr> {
    call.args.first()
}
