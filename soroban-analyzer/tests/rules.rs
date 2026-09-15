//! Runs every rule's own fixtures, and checks the rules against the registry.
//!
//! This file is the contribution standard, in executable form. The crate's stated model
//! is one detector per pull request, and the thing that decides whether a pull request
//! is mergeable is written down in the READMEs as *a detector with no fixture proving it
//! fires, and one proving it does not over-fire, is not mergeable*. A rule declares those
//! two fixtures in its own metadata, so the standard is enforced here — on every rule,
//! including the ones added by a pull request that never touches this file.
//!
//! Everything in this module is generic over the rules. Adding a rule cannot require
//! editing a list here, because there are no rule names in this file at all: it asks the
//! embedded registry what exists and holds each one to the same four claims.

use std::collections::BTreeSet;

use soroban_analyzer::{analyze_path, Analyzer, SourceFile};

/// The analyser as a user gets it: every detected and every rule that ships.
fn analyzer() -> Analyzer {
    Analyzer::embedded()
}

#[test]
fn every_rule_has_a_detector_and_every_detector_a_rule() {
    let problems = analyzer().validate();
    assert!(
        problems.is_empty(),
        "the registry and the rule metadata disagree:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_rule_is_named_after_its_own_file() {
    // The rule id is what a finding carries, what a `allow(...)` marker names, and what
    // `--explain` is given, so a rule whose file name disagrees with its id is a rule
    // that cannot be found from any of the three.
    for rule in analyzer().rules().iter() {
        assert_eq!(
            rule.file,
            format!("{}.json", rule.id),
            "the rule id and its file name must agree"
        );
    }
}

#[test]
fn every_rules_examples_are_valid_rust() {
    // Checked first and separately, so that a fixture with a syntax error reports which
    // rule it belongs to instead of failing inside the test that runs it.
    for rule in analyzer().rules().iter() {
        for (name, source) in [("triggers", &rule.triggers), ("clean", &rule.clean)] {
            if let Err(error) = SourceFile::parse("example.rs", source.clone()) {
                panic!(
                    "rule `{}` (in {}) has an `examples.{name}` that is not valid Rust: {error}",
                    rule.id, rule.file
                );
            }
        }
    }
}

#[test]
fn every_rule_fires_on_its_own_triggering_example() {
    for rule in analyzer().rules().iter() {
        let file = SourceFile::parse("example.rs", rule.triggers.clone())
            .expect("checked by every_rules_examples_are_valid_rust");
        let found = analyzer().check_file(&file);
        let hits = found
            .findings
            .iter()
            .filter(|finding| finding.rule == rule.id)
            .collect::<Vec<_>>();

        assert!(
            !hits.is_empty(),
            "rule `{}` (in {}) did not fire on its own `examples.triggers`. A rule that \
             cannot demonstrate its own pattern is not enforcing anything.\n\nThe \
             fixture was:\n{}",
            rule.id,
            rule.file,
            rule.triggers
        );

        // A finding that cannot say where it is, or which line it is on, is one a
        // reviewer cannot act on even though the detector fired.
        for hit in hits {
            assert!(
                hit.location.start.line >= 1 && !hit.message.is_empty(),
                "rule `{}` produced a finding with no line or no message: {hit:?}",
                rule.id
            );
        }
    }
}

#[test]
fn no_rule_fires_on_its_own_clean_example() {
    for rule in analyzer().rules().iter() {
        let file = SourceFile::parse("example.rs", rule.clean.clone())
            .expect("checked by every_rules_examples_are_valid_rust");
        let found = analyzer().check_file(&file);
        let hits = found
            .findings
            .iter()
            .filter(|finding| finding.rule == rule.id)
            .collect::<Vec<_>>();

        assert!(
            hits.is_empty(),
            "rule `{}` (in {}) fired on its own `examples.clean`, which is the fixture \
             that proves it does not over-fire. Findings:\n{}\n\nThe fixture was:\n{}",
            rule.id,
            rule.file,
            hits.iter()
                .map(|hit| format!("    {hit} — {}", hit.message))
                .collect::<Vec<_>>()
                .join("\n"),
            rule.clean
        );
    }
}

#[test]
fn the_two_examples_of_a_rule_are_different() {
    // A clean fixture that is a copy of the triggering one would pass the test above
    // only if the rule stopped working, so the two are required to differ. This is the
    // cheapest possible guard against a copy-pasted rule being merged.
    for rule in analyzer().rules().iter() {
        assert_ne!(
            rule.triggers.trim(),
            rule.clean.trim(),
            "rule `{}` has the same source for both examples",
            rule.id
        );
    }
}

#[test]
fn every_rule_is_documented() {
    // The README's rule table is what a user reads before running anything, and a rule
    // that is not in it is a rule nobody knows they are being held to. Checked from the
    // crate's own README, which is also the crate's docs.rs landing page.
    let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
        .expect("the crate ships a README");

    for rule in analyzer().rules().iter() {
        assert!(
            readme.contains(&rule.id),
            "rule `{}` is not mentioned in soroban-analyzer/README.md",
            rule.id
        );
        assert!(
            readme.contains(&rule.title),
            "rule `{}` is mentioned in the README, but not by its title (`{}`), so a \
             reader cannot tell what it checks",
            rule.id,
            rule.title
        );
    }
}

#[test]
fn a_heuristic_rule_is_marked_as_one() {
    // `heuristic` reaches SARIF consumers as the rule's `precision`. Leaving it false on
    // a word-list check would tell a machine that a heuristic is exact, which is worse
    // than not reporting precision at all — so this asserts the flag is set on the rules
    // whose rationale says the check rests on names.
    for rule in analyzer().rules().iter() {
        let says_so = rule.rationale.contains("word list") || rule.rationale.contains("heuristic");
        assert_eq!(
            says_so,
            rule.heuristic,
            "rule `{}` {} a heuristic in its rationale but has `heuristic: {}`",
            rule.id,
            if says_so {
                "describes"
            } else {
                "does not describe"
            },
            rule.heuristic
        );
    }
}

#[test]
fn the_rules_cover_the_documented_vulnerability_classes() {
    // The five patterns the toolkit is scoped to. This is the one place rule ids appear
    // in a test, and it is here so that deleting a rule is a decision rather than an
    // accident: the ids are the contract with the project's own description.
    let analyzer = analyzer();
    let expected = BTreeSet::from([
        "soroban-missing-require-auth",
        "soroban-read-budget",
        "soroban-storage-durability",
        "soroban-unbounded-storage-loop",
        "soroban-unchecked-arithmetic",
    ]);
    let actual = analyzer.rules().ids().into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "the shipped rules changed; update this list only deliberately"
    );
}

#[test]
fn analysing_a_directory_reports_problems_instead_of_losing_them() {
    // One unparseable file must not take the rest of the tree with it, and must not be
    // silently skipped either: it comes back as a problem, and the CLI turns that into a
    // non-zero exit.
    let root = std::env::temp_dir().join("soroban-analyzer-rules-mixed");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("the scratch directory can be created");
    std::fs::write(root.join("broken.rs"), "pub fn oops( {\n").expect("the file can be written");
    std::fs::write(
        root.join("vulnerable.rs"),
        concat!(
            "#[contractimpl]\n",
            "impl Token {\n",
            "    pub fn mint(env: Env, to: Address, amount: i128) {\n",
            "        env.storage().persistent().set(&to, &amount);\n",
            "    }\n",
            "}\n"
        ),
    )
    .expect("the file can be written");

    let (findings, suppressed, problems) = analyze_path(&analyzer(), &root);
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule == "soroban-missing-require-auth"),
        "the parseable file was still analysed: {findings:?}"
    );
    assert!(suppressed.is_empty(), "{suppressed:?}");
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("broken.rs"), "{problems:?}");

    let _ = std::fs::remove_dir_all(&root);
}
