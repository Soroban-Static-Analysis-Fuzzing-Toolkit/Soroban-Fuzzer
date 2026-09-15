# soroban-budget

**Static resource-budget estimation for compiled Soroban contracts.**

The other two components of this toolkit read a contract's Rust source. This one reads the
**compiled Wasm** — the artefact a deployment actually carries — and reports what each
entrypoint costs, without deploying it, without a test environment, and without trusting
the source to be what the compiler emitted.

```console
$ soroban-budget target/wasm32v1-none/release/soroban_token_contract.wasm
target/wasm32v1-none/release/soroban_token_contract.wasm
  29380 bytes, 19 host import(s), 91 function(s) defined, 13 exported function(s)
  note: Wasm instructions in the static call tree: a structural measurement, not a CPU
        prediction. The network meters host calls and instruction types at its own
        weights, and charges for work this count does not include.

  transfer            8344 instructions  at least (loops in the way)
                  43 function(s) reached, 100 host call(s)
                    no upper bound: loops: the trip count is an input, so no static bound exists
  transfer_from      12465 instructions  at least (loops in the way)
                  45 function(s) reached, 148 host call(s)
                    no upper bound: loops: the trip count is an input, so no static bound exists
  decimals             178 instructions  exact
                   8 function(s) reached, 3 host call(s)

3 of 13 exported function(s) can be bounded exactly
10 cannot: the count shown for those is a lower bound, not an upper one
```

## Install

```
cargo install --path soroban-budget
```

Or run it from a checkout: `cargo run -p soroban-budget -- contract.wasm`.

## Use

```
soroban-budget [OPTIONS] <MODULE.wasm>
```

| Option | Meaning |
| --- | --- |
| `-f, --format <FORMAT>` | `text` (default) or `json` |
| `--entry <NAME>` | report only this exported function; repeatable |
| `--fail-over <N>` | exit `1` when an exactly counted entrypoint needs more than `N` instructions |
| `--fail-unbounded` | exit `1` when any entrypoint cannot be bounded exactly |

Exit status: `0` when the module was read and nothing crossed a gate, `1` when something
did, `2` when the estimator could not run — bad arguments, or a file that is not a module.
Facts do not fail builds on their own, which is why both gates are opt-in: the right
threshold is a property of the contract and its callers, not of this tool.

`--fail-over` compares only *exact* counts. A lower bound above the threshold has certainly
crossed it; a lower bound below it might still be over, so counting it would be a claim the
measurement does not support.

## What it reports, and what that is worth

For every exported function: the Wasm instructions in its **static call tree**, the host
functions it reaches, and whether that count is exact or merely a lower bound.

- **Call tree, not call graph.** A function reached from two branches is counted twice,
  which is what makes the number a count of work rather than of distinct code.
- **A lower bound whenever the code loops, calls indirectly or recurses**, because each of
  those makes an upper bound impossible to compute from the module alone. The report names
  which one it hit instead of printing a number and leaving a reader to assume it is the
  whole story.
- **Exact** when none of the three is present, which for this token is the metadata
  getters: `decimals`, `name` and `symbol` read instance storage and do nothing else.

### It is not a CPU prediction

Soroban meters CPU instructions with its own weights — per instruction type, per host
call, per byte moved — and charges for work this count does not include, such as argument
marshalling. So this is a *structural* measurement of the module. Comparing two contracts,
or one contract before and after a change, is what the numbers are for; reading a single
number as "this call will cost N CPU" is not, and the report says so in its own output
rather than in this file alone.

What it is genuinely for: knowing which entrypoint is the expensive one, seeing a call
tree grow between two revisions of a pull request, and bounding work that must not grow
without someone deciding it should.

## Validated against a real contract

`tests/compiled_contract.rs` compiles `stellar/soroban-examples`' standard token —
vendored byte-for-byte under [`third-party/soroban-token-example/`](../third-party/) and
re-checked against its pinned revision by `third-party/verify.sh` — for
`wasm32v1-none`, and estimates the artefact.

It asserts what would be wrong if the reader were wrong in any structural way: that all
twelve of the token's entrypoints are found with a body behind each, that a `memory`
export is not reported as an entrypoint, that `transfer_from` (an allowance check, two
balance moves and a TTL extension) measures strictly larger than `decimals`, and that the
metadata getters are exactly bounded. A parser that only ever sees hand-assembled modules
is a parser that agrees with whoever wrote it, which is why the arithmetic is tested
against assembled modules and the *reading* against a compiler's output.

Building that artefact needs the `wasm32v1-none` target. Without it the tests skip and say
so; CI sets `SOROBAN_REQUIRE_WASM_FIXTURE=1`, which turns the skip into a failure, because
a skip in CI is a green build that measured nothing.

Two facts about the real artefact are worth knowing, because they shaped the design:

- **Host imports are deliberately unreadable.** The token imports from modules named `l`,
  `m`, `i`, `a` and `x`, with field names like `1`, `_` and `9`. A tool that decided "this
  one is a storage read" from the name would be guessing, so imports are reported as they
  are written and counted, never interpreted.
- **Loops are everywhere, and that is not a finding.** The SDK's own generated code loops
  in string and collection handling, so most entrypoints cannot be bounded exactly. "This
  entrypoint loops" is not a vulnerability, and an estimator that graded one would be
  guessing about intent.

## What it cannot see

- **Host cost is not modelled.** A host call that reads a ledger entry costs more than one
  that computes. This counts the call and stops.
- **Indirect calls do not name their targets.** Resolving a `call_indirect` to the
  functions it could reach needs the type section and the table's element segment; until
  that is done, such an entrypoint is reported as not exactly bounded rather than guessed.
- **Metre weights are not applied**, and no conversion to CPU instructions is offered,
  because there is no honest one without the network's own table.
- **Dead code is counted.** Instructions in a reachable function are counted whether or not
  a path would execute them; the number is an upper bound of the *static* tree and a lower
  bound of what the tree can do at run time, and the two meet exactly when nothing loops.
- **A module that will not parse is an error, not a finding.** If the artefact cannot be
  read, nothing here is meaningful.

## How it is put together

| Module | Responsibility |
| --- | --- |
| `module` | Reading the Wasm: imports, exports, and each function body's calls, loops and branches — the only part that knows the binary format |
| `estimate` | The cost model: the static call tree, the host-call attribution, and the three reasons an upper bound is impossible |
| `report` | Text and JSON rendering, both carrying the statement of what the numbers are |

The parser is `wasmparser`, the same crate `soroban-env-host` links, pinned to the version
the SDK already resolves. A second implementation of a binary format is a second opinion,
and the resource a contract consumes is measured by the network's parser, not by ours.

The crate has no feature flags and no unsafe code.

## Testing

```
cargo test -p soroban-budget
```

Nine tests over assembled modules — a body of *n* operations counts *n*, a call tree is
summed rather than a body, a host import is attributed to the entrypoint that reaches it, a
loop and an indirect call each make the count a lower bound and say why, mutual recursion
is reported instead of followed — and two over the compiled token. `tests/common/mod.rs`
holds the assembler that builds the synthetic modules; it encodes real Wasm sections, so
the parser is reading what it will read in production.

## Licence

Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
