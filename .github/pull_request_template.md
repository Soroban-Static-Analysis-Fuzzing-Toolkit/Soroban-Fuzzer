<!--
Keep one change per pull request: see CONTRIBUTING.md for why. A scoped addition can
be reviewed on its own merits; a scoped addition plus a refactor cannot, and will sit.
-->

## What this changes

<!-- One or two sentences. What is different for a user of the toolkit? -->

Closes #

## What proves it

<!--
Name the test that fails without this change, and paste its failure from before the
fix. A change with no such test is a claim rather than a fix.
-->

```
the failing output, before the fix
```

## Checklist

- [ ] **A test fails without this change.** I ran it before the fix and saw it fail,
      and it now passes. (This is the one thing that keeps a detector honest.)
- [ ] `cargo test --workspace` passes, **and** `cargo test --workspace --release` does,
      so the change holds under the optimisation settings Soroban deploys with.
- [ ] `cargo fmt --all` and
      `cargo clippy --workspace --all-targets --all-features -- -D warnings` are clean.
- [ ] New public items are documented, and every rustdoc example compiles (the doctests
      are part of the suite).
- [ ] `./third-party/verify.sh` passes, if anything under `third-party/` is touched —
      and it will fail if vendored code was edited, which is the intent.
- [ ] No behaviour change for existing targets, *or* the change is described above and
      the description says what a target author has to do about it.

### If this adds a detector

- [ ] A positive fixture produces exactly the expected finding, and a negative fixture
      produces none. Both are tests.
- [ ] The rule metadata file is added and its rationale is worth reading in a review
      comment — it is what a reviewer will see when the finding appears on their PR.

### If this adds a bug-class test or changes the harness

- [ ] The test asserts the **minimal reproducer's length and the finding's kind**, not
      merely that a failure occurred. A test that only checks "it failed" stayed green
      through a shrinking bug that deleted entire sequences.
- [ ] Any new guard is tested by a case that *should* trip it, not only by the cases
      that should not.

## Notes for the reviewer

<!--
Anything that surprised you, and anything you deliberately did not do. Trade-offs you
chose and why are the most useful thing in this section — including the ones you are
not sure about.
-->
