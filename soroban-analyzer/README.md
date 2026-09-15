# soroban-analyzer

Static analysis for Soroban smart contracts, over the contract's Rust source.

Where a general linter sees well-typed code, this sees the things that are only bugs on
Soroban: an entrypoint that changes state without asking who is calling, a balance in the
one storage class that is reclaimed rather than archived, a loop whose trip count the
caller chooses, arithmetic that traps because contracts deploy with overflow checks on,
and a routine that reads more ledger entries than an invocation is allowed to.

It is the static-analysis half of the [Soroban Static Analysis & Fuzzing
Toolkit](../README.md); the [fuzzer](../soroban-fuzzer/README.md) is the other half, and
the two are for different things. The fuzzer finds the inputs that break a contract you
can run. This finds the patterns that break a contract you have not run yet, on branches
your property tests never reached.

```
$ soroban-analyze src/
src/lib.rs:41:5: critical: soroban-missing-require-auth
    pub fn mint(env: Env, admin: Address, to: Address, amount: i128) {
    ^ any account can invoke it and pass any value for `admin`, `to`, so the
      operation runs without the approval it is supposed to rest on
    fix: Call `require_auth()` on the address the operation is for, before the effect

2 findings (1 critical, 1 high) in 1 file
```

## Install

```
cargo install --path soroban-analyzer
```

Or run it from a checkout without installing: `cargo run -p soroban-analyzer -- src/`.

## Use

```
soroban-analyze [OPTIONS] [PATH]...
```

`PATH` may be a file or a directory. Directories are searched recursively for `.rs`
files; `target`, `.git`, `node_modules`, `.cargo` and `vendor` are skipped. With no
`PATH`, the current directory is analysed.

| Option | Meaning |
| --- | --- |
| `-f, --format <FORMAT>` | `text` (default), `json`, or `sarif` |
| `-s, --severity <LEVEL>` | exit non-zero at or above `info`, `low`, `medium`, `high` (default) or `critical` |
| `-j, --jobs <N>` | check files with `N` threads (default: one per core) |
| `--config <FILE>` | read settings from `FILE` instead of `./.soroban-analyzer.json` |
| `--baseline <FILE>` | do not fail on the findings `FILE` records |
| `--write-baseline` | record this run's findings in the baseline file first |
| `-l, --list` | list the rules |
| `--explain <RULE-ID>` | explain one rule, including the source that must and must not trigger it |

Exit status: `0` when nothing is at or above the gate and everything was analysed, `1`
when something is, or when a file could not be parsed, and `2` when the analyser itself
could not run — bad arguments, unreadable rules, or a configuration it cannot understand.
A file that failed to parse exits `1` rather than `0` on purpose: a run that skipped half
a tree has not answered the question it was asked.

### Adopting it on a tree that already has findings

A first run over a contract older than this tool reports everything at once, and a gate
that fails on all of it is a tool that gets switched off. Record what is there once, and
from then on only new findings gate:

```bash
soroban-analyze --baseline .soroban-baseline.json --write-baseline .
```

That writes every current finding to the file and exits `0` — the run has just decided
what it is not going to fail on — and the file is committed like any other review
artefact. Afterwards, `soroban-analyze --baseline .soroban-baseline.json .` fails only on
findings the file does not record, and says what it excused rather than hiding it:

```
1 finding (1 high) in 1 file
2 findings the baseline records and this run does not fail on
```

An entry matches a finding by **rule, file and message**. The line is recorded for a
reader and deliberately not part of the identity, so inserting a line above a finding does
not resurrect it; a rename that changes what the analyser says about an occurrence does,
which is the point — the baseline is a claim that those occurrences were reviewed, and a
change to what they are costs one more look.

Entries that match nothing are counted on stderr, so a baseline cannot quietly outlive its
code:

```
soroban-analyze: 2 baseline entries at .soroban-baseline.json match nothing in this run;
re-write it with `--write-baseline`
```

The file is versioned, records the tool and version that wrote it, and a baseline written
for a newer schema is refused with the version named rather than reinterpreted under this
one's assumptions.

### Settings that belong to the repository

A command line is for what changes between runs; `.soroban-analyzer.json` is for what is
true of a repository. `--config FILE` names one elsewhere, and any command-line flag beats
the file, so a one-off stricter run never has to edit a repository file:

```json
{
  "schema_version": 1,
  "paths": ["src"],
  "severity": "medium",
  "format": "sarif",
  "baseline": ".soroban-baseline.json",
  "disabled_rules": ["soroban-unbounded-storage-loop"]
}
```

Relative paths resolve against the configuration file's directory rather than the working
directory, so the file means the same thing however it is invoked. Discovery is shallow —
the file in the directory the tool is run from, or the one `--config` names — because a
configuration found by searching upward is one whose effect nobody can predict.

Two things are deliberately absent. There is no key for a rule's **severity**: a detector
cannot re-grade a pattern it did not invent, and a downstream project's preferences cannot
either — a pattern's severity is a statement about Soroban that belongs with the rule's
rationale, in this repository, under review. There is also nothing that silences a rule
without a trace: `disabled_rules` is counted and reported in every run, exactly like an
`allow` marker, so turning a rule off is visible rather than a silent change to what
"clean" means. An unknown key, or a `disabled_rules` entry naming a rule that does not
exist, is an error rather than something to skip — a misspelled `"severty"` that is
quietly ignored is a CI job running at a gate nobody chose.

### It is a function of the tree, not of the machine

`--jobs` changes how long a run takes and nothing else. Files are ordered before they are
read, results are merged back in that order, and every report sorts what it renders, so
two runs over the same tree produce byte-identical output whether `--jobs` is 1 or 64 —
which is what makes it safe to put in a pipeline that compares two runs. Detectors are
required to be `Send + Sync` for this; a detector that could not be shared would silently
make the tool single-threaded.

### In CI, into a pull request

The toolkit ships a GitHub Action ([`action.yml`](../action.yml)) that builds this crate,
runs it, writes the report, uploads it to code scanning and summarises the findings in the
run — including the baseline and gate inputs described above:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: soroban-security/soroban-toolkit@v1
    with:
      path: .
      severity: medium
      baseline: .soroban-baseline.json
      fail-on-findings: 'false'
```

Its body lives in [`scripts/run-analysis.sh`](../scripts/run-analysis.sh), where it can be
run and tested without a runner; `tests/action.rs` asserts every exit status it can return.

The `sarif` format is SARIF 2.1.0, so GitHub's code-scanning view annotates the diff
lines that the findings are about:

```yaml
- run: cargo run -p soroban-analyzer -- --format sarif --severity medium . > sarif.json
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif.json
```

Each rule's severity maps onto a SARIF level (`critical` and `high` are errors, `medium`
and `low` are warnings, `info` is a note), and each finding carries a fingerprint so the
same finding is one alert rather than a new one on every push.

## Rules

Five rules ship today, one per detector. The severity is the rule's, not the detector's —
a detector cannot re-grade a pattern it did not invent.

| Rule | Severity | What it catches |
| --- | --- | --- |
| `soroban-missing-require-auth` — *Privileged entrypoint never requires authorization* | critical | A public entrypoint that writes storage or moves value without calling `require_auth` on the address it acts for. On Soroban an address is a claim until it is authorized, so anyone can invoke the entrypoint for anyone. |
| `soroban-storage-durability` — *Stored data whose durability does not match its lifetime* | high | A balance or other must-survive value in `temporary` storage, where it is reclaimed rather than archived, or per-account data in `instance` storage, which is one entry loaded on every call. |
| `soroban-unbounded-storage-loop` — *Loop over storage with a trip count the contract does not bound* | high | A loop over storage whose count comes from an argument, a caller-supplied collection or a stored value. The input that exceeds the invocation budget is one the contract accepts. |
| `soroban-read-budget` — *Storage reads exceed the per-invocation ceiling* | high | A statically computable read count above the 200 entries an invocation may read — a read inside two loops of 20 costs 400, and no input makes that call cheaper. |
| `soroban-unchecked-arithmetic` — *Unchecked arithmetic on a token amount* | medium | `+`, `-` or `*` on a value that looks like money. With overflow checks on, an overflowing sum traps rather than wrapping, which is a denial of service with a trigger the attacker chooses. |

`soroban-analyze --explain <RULE-ID>` prints a rule's rationale, its remediation and both
of its fixtures.

### Why the severities are ordered this way

Authorization and lost state are above iteration cost, which is above a trap. That is a
statement about what the network does: with `overflow-checks = true` a Soroban contract
panics on overflow rather than minting value, so unchecked arithmetic costs an invocation
rather than funds. The licence for that ordering is in
[`src/severity.rs`](src/severity.rs), and it is the only place it is decided.

### Honest precision

Three rules say `"heuristic": true` in their metadata, which reaches SARIF consumers as a
rule `precision` of `medium` rather than `high`: `soroban-unchecked-arithmetic` and
`soroban-storage-durability` match on identifier and key names, and
`soroban-unbounded-storage-loop` treats "no literal bound" as "unbounded". A rule that
matched on names claiming exactness would be lying in a machine-readable field. Each
rule's rationale says where it can be wrong, and the crate's tests fail if a rule's
rationale and its `heuristic` flag disagree.

## Suppressing a finding

A pattern that is correct in context is excused in the code, where a reviewer sees it:

```rust
// soroban-analyzer: allow(soroban-missing-require-auth)
// Registration is permissionless by design: there is nothing to spend.
pub fn register(env: Env, who: Address) { /* ... */ }
```

The marker goes on the comment lines directly above the item, or above the whole `impl`
block to cover its methods. `// soroban-analyzer: allow-file(...)` excuses a whole file,
and `allow(all)` excuses every rule. Suppressed findings are **counted and reported**
rather than dropped, so a run never quietly loses one, and the exception lives in the
diff that introduces it.

## What it cannot see

These checks parse the source; they do not type-check it, do not follow calls across
files and do not read the compiled Wasm. Each rule states its own blind spots, and the
project-level ones are worth knowing up front:

- **Delegation is followed one level deep, in one file.** An entrypoint whose
  authorization lives two calls away, or in another file, is reported as unprotected. That
  is a false positive, and a deliberate one: the alternative is to say nothing about an
  unprotected `mint`.
- **An authorization call anywhere in the body counts**, even inside an `if` that can be
  false, and even when it authorizes a different address than the one acted on. Deciding
  which address was authorized against which was touched needs types and data flow.
- **Names are a heuristic.** `looks_like_amount` is a word list, so `balance + amount` is
  reported and `x + y` is not, whatever they hold.
- **Instruction and memory budgets are not estimated.** The read ceiling is the one
  resource limit a syntactic count can speak to; instruction count is not, and this crate
  does not try. [`soroban-budget`](../soroban-budget/) measures a **compiled** contract's
  instruction count and host calls instead — and reports a lower bound wherever a loop
  makes an upper one impossible, which is the same honesty this rule practises with its
  static read count.
- **`unchecked` means unchecked.** `wrapping_*` and `saturating_*` count as handled,
  because whether clamping is correct for a balance is a question about the contract, not
  about the expression.
- **No model validation.** There is no check that the expression a rule matches on is the
  expression that matters — only that the pattern is present.

## Adding a detector

One detector per pull request, and no shared list to edit: `build.rs` generates the
registry from the files in the tree, so two contributor pull requests never touch the same
line.

1. `src/detectors/<name>.rs` — a `pub struct Detector` implementing
   [`Detector`](src/detector.rs), naming its rule from `id()`.
2. `rules/<id>.json` — the rule's metadata: id, title, severity, rationale, remediation,
   references, and **both fixtures**: source that must trigger the rule and source that
   must not.

Neither file is optional, and the fixtures are not documentation.
[`tests/rules.rs`](tests/rules.rs) parses and runs every rule's own examples on every
commit, so a detector that fires on its clean example, or does not fire on its triggering
one, fails the build. That is what turns the contribution standard — *a detector with no
fixture proving it fires, and one proving it does not over-fire, is not mergeable* — from
a sentence in a document into something CI enforces. Add the rule to the table above,
which is also asserted by a test.

The rule schema is versioned (`"schema_version": 1`). A rule written for a newer schema is
rejected with a message naming the version rather than reinterpreted under the old
assumptions, and the check happens on load, so a stale rule file cannot silently mean
something different.

## How it is put together

| Module | Responsibility |
| --- | --- |
| `baseline` | The recorded findings a run does not gate on, their identity, and the entries that no longer match anything |
| `config` | `.soroban-analyzer.json`: parsing, validation, and the precedence the command line wins |
| `source` | A parsed file, and the mapping from syntax-tree spans to line and column |
| `syntax` | Shared queries: contract entrypoints, storage reads and writes, durability, loop bounds, name segments |
| `detector` | The `Detector` trait, the engine that runs detectors, and the sink that applies grading and suppression |
| `finding` | What a detector produces: a place in the source, and something to say about it — with no severity of its own, so a rule cannot drift from its metadata |
| `detectors/` | One file per rule, pulled in by the generated registry |
| `rules` | Rule metadata: loading, versioning, and the validation a rule must pass |
| `suppress` | The `allow` markers and the scope they apply to |
| `report` | Text, JSON and SARIF rendering, and the exit-status gate |
| `walk` | Which files to analyse |

Two design decisions are load-bearing. A detector **cannot** set its own severity or
wording: it reports where and what, and the rule supplies the rest, so a pull request
adding a detector cannot quietly re-grade an existing pattern. And findings are sorted
deterministically — worst first, then by file, line and column — from a detector order the
build generates by sorted file name, so two runs over the same tree produce byte-identical
output and a diff of two runs is about the code, whatever `--jobs` was set to.

## Testing

```
cargo test -p soroban-analyzer
```

159 tests in five layers: 97 unit tests inside the modules, `tests/detectors.rs` (22) for
the cases each detector was argued about — mostly the ones it must *not* fire on —
`tests/rules.rs` (10) for the rule fixtures and the registry invariants, `tests/cli.rs` (24)
for the binary's output formats, exit statuses, baselines and SARIF structure, and
`tests/action.rs` (6) for `scripts/run-analysis.sh`, the body of the GitHub Action — a
composite action's shell is otherwise only ever exercised on a runner. Coverage is
measured in CI.

## Licence

Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
