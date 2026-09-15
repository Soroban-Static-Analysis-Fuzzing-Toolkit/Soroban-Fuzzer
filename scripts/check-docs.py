#!/usr/bin/env python3
"""Holds the documentation to the code, by re-measuring what it claims.

This project's landing page is a table of measured facts, and its READMEs make
statements of the form "five rules ship today" and "160 tests". Those are the
sentences that go stale first: a number in prose is updated by whoever remembers
to, and nothing fails when they do not. So the numbers that *can* be measured are
measured here, on every commit, and a stale one is a build failure rather than a
discovery a reader makes later.

Four checks, each of which caught something real when it was written:

1. **Relative links resolve.** A document that points at `soroban-analyzer/` is
   making a claim about the tree, and a moved file turns it into a lie. This is
   the check that would have caught the fuzzer's README still saying the static
   analyser was a separate component "not in this repository yet".
2. **The test counts are the test counts.** The landing page's `Tests` row is
   compared against `cargo test -- --list`, split into tests and doctests the way
   the row states them.
3. **"Five rules ship today" is five rules.** The count word in the analyser's
   README is compared against `rules/*.json`.4. **Every module is in the map.** Each `src/*.rs` is named in its crate's "How it is put
   together" table, because a module nobody documented is a module a reader has to
   reverse-engineer.
5. **The Action's inputs are the ones it uses.** `action.yml` declares inputs and refers to
   them as `inputs.<name>`; a misspelling is a workflow input that silently arrives empty,
   which is the same class of failure as an ignored configuration key. Every file it runs
   by path has to exist too, since a composite action's file references are resolved on a
   runner rather than at review time.

Run from anywhere: `python3 scripts/check-docs.py`. It needs `cargo` on `PATH`
for check 2, and exits non-zero with the measurement in the message so the fix
is always to write down what was measured.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Vendored upstream code keeps its own documentation, in upstream's style, and is
# not this project's to keep honest. `target/` is build output.
SKIPPED_DIRS = {"target", "third-party", ".git"}

# A module list that a new file has to join. `lib.rs` and `main.rs` are the crate
# and the binary rather than modules with a responsibility of their own, and
# `src/detectors/` is one row in the table however many detectors live in it —
# that is the whole point of the generated registry.
MODULE_MAPS = {
    "soroban-analyzer/src": ("soroban-analyzer/README.md", {"lib.rs", "main.rs", "detectors"}),
    "soroban-fuzzer/src": ("README.md", {"lib.rs", "main.rs", "detectors"}),
    "soroban-budget/src": ("soroban-budget/README.md", {"lib.rs", "main.rs", "detectors"}),
}

# The packages whose tests the landing page's row counts.
PACKAGES = ["soroban-analyzer", "soroban-fuzzer", "soroban-budget"]

FAILURES: list[str] = []


def fail(check: str, message: str) -> None:
    FAILURES.append(f"{check}: {message}")


def markdown_files() -> list[Path]:
    files = []
    for path in sorted(ROOT.rglob("*.md")):
        if any(part in SKIPPED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        files.append(path)
    return files


def check_links() -> None:
    """Every relative link in every document resolves."""
    link = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)>\s]+)>?")
    checked = 0
    for document in markdown_files():
        text = document.read_text(encoding="utf-8")
        for target in link.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            # `path#anchor` and `path "title"` both name a file; the anchor and the
            # title are not part of the path.
            target = target.split("#", 1)[0].split('"', 1)[0].strip()
            if not target:
                continue
            checked += 1
            resolved = (document.parent / target).resolve()
            if not resolved.exists():
                where = document.relative_to(ROOT)
                fail(
                    "links",
                    f"{where} links to `{target}`, which does not exist "
                    f"(resolved to {resolved})",
                )
    print(f"links: {checked} relative link(s) across {len(markdown_files())} document(s)")


def listed_tests(package: str) -> tuple[int, int, list[str]]:
    """Counts `(tests, doctests)` for a package, plus anything that went wrong."""
    try:
        listed = subprocess.run(
            ["cargo", "test", "-p", package, "--", "--list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return (0, 0, ["cargo is not on PATH, so the test counts cannot be measured"])

    if listed.returncode != 0:
        return (0, 0, [f"`cargo test -p {package} -- --list` failed:\n{listed.stderr.strip()}"])

    tests = doctests = 0
    for line in listed.stdout.splitlines():
        if not line.endswith(": test"):
            continue
        # A doctest's name is the file it lives in, `.../src/lib.rs - (line 12)`.
        # A unit test's name is a Rust path and never contains a `.rs` file name.
        if ".rs" in line:
            doctests += 1
        else:
            tests += 1
    return (tests, doctests, [])


def check_test_counts() -> None:
    """The landing page's `Tests` row is re-counted from the suites."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = re.search(
        r"(\d+) across the three crates \((\d+) analyser, (\d+) fuzzer, (\d+) budget\) "
        r"plus (\d+) doctests",
        readme,
    )
    if row is None:
        fail(
            "tests",
            "the README's `Tests` row is not in the form the check parses "
            "(`N across the three crates (A analyser, F fuzzer, B budget) plus D "
            "doctests`), so it cannot be held to the suites",
        )
        return

    (
        claimed_total,
        claimed_analyser,
        claimed_fuzzer,
        claimed_budget,
        claimed_doctests,
    ) = (int(group) for group in row.groups())

    problems: list[str] = []
    measured: dict[str, tuple[int, int]] = {}
    for package in PACKAGES:
        tests, doctests, errors = listed_tests(package)
        problems.extend(errors)
        measured[package] = (tests, doctests)
    if problems:
        for problem in problems:
            fail("tests", problem)
        return

    analyser_tests, analyser_doctests = measured["soroban-analyzer"]
    fuzzer_tests, fuzzer_doctests = measured["soroban-fuzzer"]
    budget_tests, budget_doctests = measured["soroban-budget"]
    actual = {
        "analyser tests": (claimed_analyser, analyser_tests),
        "fuzzer tests": (claimed_fuzzer, fuzzer_tests),
        "budget tests": (claimed_budget, budget_tests),
        "doctests": (
            claimed_doctests,
            analyser_doctests + fuzzer_doctests + budget_doctests,
        ),
        # The row counts tests and doctests separately; `N across the three crates`
        # is the tests alone, which is the arithmetic the row itself states.
        "total": (claimed_total, analyser_tests + fuzzer_tests + budget_tests),
    }
    for name, (claimed, real) in actual.items():
        if claimed != real:
            fail("tests", f"README.md claims {claimed} {name}; the suites have {real}")

    print(
        f"tests: {analyser_tests} analyser + {fuzzer_tests} fuzzer + {budget_tests} budget + "
        f"{analyser_doctests + fuzzer_doctests + budget_doctests} doctests"
    )


NUMBER_WORDS = {
    "no": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}


def check_rule_count() -> None:
    """The analyser's stated rule count is the number of rule files."""
    readme = (ROOT / "soroban-analyzer/README.md").read_text(encoding="utf-8")
    rules = list((ROOT / "soroban-analyzer/rules").glob("*.json"))
    if not rules:
        fail("rules", "there are no `soroban-analyzer/rules/*.json` files at all")
        return

    stated = re.search(r"(\w+) rules ship today", readme)
    if stated is None:
        fail("rules", "soroban-analyzer/README.md no longer states how many rules ship")
        return

    word = stated.group(1).lower()
    if word not in NUMBER_WORDS:
        fail("rules", f"`{word} rules ship today` is not a count this check understands")
        return

    if NUMBER_WORDS[word] != len(rules):
        fail(
            "rules",
            f"soroban-analyzer/README.md says `{word} rules ship today`; "
            f"there are {len(rules)} rule files",
        )
    print(f"rules: {len(rules)} rule file(s), stated as `{word}`")


def check_modules_are_mapped() -> None:
    """Every module file is named in the map of the crate it belongs to."""
    for directory, (document, excluded) in MODULE_MAPS.items():
        text = (ROOT / document).read_text(encoding="utf-8")
        modules = sorted(
            path.name
            for path in (ROOT / directory).glob("*.rs")
            if path.name not in excluded
        )
        if not modules:
            fail("modules", f"{directory} has no module files, which cannot be right")
            continue
        # A module is documented either by file name (`walk.rs`, the shape the
        # landing page's layout tree uses) or by module name (`` `walk` ``, the shape
        # a table of responsibilities uses). Either is a reader being told what it
        # is for; not mentioning it at all is not.
        missing = [
            name
            for name in modules
            if name not in text and f"`{name.removesuffix('.rs')}`" not in text
        ]
        for name in missing:
            fail(
                "modules",
                f"{directory}/{name} is not mentioned in {document}; "
                f"add it to that document's map of the crate",
            )
        print(f"modules: {len(modules)} in {directory}, {len(modules) - len(missing)} documented")


def check_action() -> None:
    """The composite Action's inputs and file references are self-consistent."""
    path = ROOT / "action.yml"
    if not path.is_file():
        fail("action", "there is no action.yml at the repository root")
        return
    text = path.read_text(encoding="utf-8")

    # Declared inputs: the two-space-indented keys of the `inputs:` mapping.
    body = text.split("\ninputs:\n", 1)
    if len(body) != 2:
        fail("action", "action.yml has no `inputs:` section for this check to read")
        return
    section = re.split(r"^[a-z]+:\s*$", body[1], maxsplit=1, flags=re.MULTILINE)[0]
    declared = set(re.findall(r"^  ([A-Za-z0-9_-]+):", section, flags=re.MULTILINE))
    used = set(re.findall(r"inputs\.([A-Za-z0-9_-]+)", text))

    for name in sorted(used - declared):
        fail(
            "action",
            f"action.yml refers to `inputs.{name}`, which it does not declare, so a "
            f"workflow using it would pass an empty value",
        )
    for name in sorted(declared - used):
        fail(
            "action",
            f"action.yml declares `{name}` and never uses it, so the input does nothing",
        )

    # Every path the Action runs from its own checkout has to be there.
    referenced = set(re.findall(r"github\.action_path\s*\}\}/(\S+)", text))
    referenced |= set(re.findall(r"\./(scripts/[\w./-]+)", text))
    for relative in sorted(referenced):
        relative = relative.strip('"\'')
        # `target/` is what the Action's own build step produces, so it is expected to be
        # absent from a fresh checkout; everything else it runs has to be committed.
        if relative.startswith("target/"):
            continue
        if not (ROOT / relative).exists():
            fail("action", f"action.yml runs `{relative}`, which does not exist")

    print(f"action: {len(declared)} input(s) declared and used, {len(referenced)} path(s) present")


def main() -> int:
    check_links()
    check_test_counts()
    check_rule_count()
    check_modules_are_mapped()
    check_action()

    if FAILURES:
        print(f"\n{len(FAILURES)} documentation problem(s):", file=sys.stderr)
        for failure in FAILURES:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nThe fix is to write down what was measured, not to loosen the check.",
            file=sys.stderr,
        )
        return 1
    print("\ndocumentation matches the code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
