#!/usr/bin/env bash
#
# Runs the analyser the way a pull request wants it run: one SARIF document on disk, a
# summary in the job log, and an exit status that means what the workflow asked it to.
#
# This lives in a script rather than inline in `action.yml` so that it can be run and
# tested without GitHub. `soroban-analyzer/tests/action.rs` invokes it with fixtures and
# asserts every branch below, because a composite action's shell steps are otherwise only
# exercised in the one environment nobody can reproduce locally.
#
# Inputs, all through the environment:
#
#   SOROBAN_ANALYZER    Path to the `soroban-analyze` binary. Required.
#   ANALYZE_PATH        File or directory to analyse. Default `.`.
#   SEVERITY            Gate: info, low, medium, high (default), critical.
#   FORMAT             Report format for the file written: sarif (default) or json.
#   OUTPUT_FILE         Where the machine-readable report goes.
#   BASELINE            Baseline file to excuse known findings with. Optional.
#   FAIL_ON_FINDINGS    `true` (default) to exit non-zero when the gate is crossed.
#   GITHUB_OUTPUT       Set by the runner; the step's outputs are appended to it.
#   GITHUB_STEP_SUMMARY Set by the runner; the human-readable summary goes there.
#
# Exit status: the analyser's, except that a run asked not to fail on findings returns 0
# — and a run of the analyser that could not run at all (status 2) always fails, because
# a workflow that continues after the tool failed has published a green tick over nothing.

set -uo pipefail

fail() {
  echo "::error::$*" >&2
  exit 2
}

: "${SOROBAN_ANALYZER:?SOROBAN_ANALYZER must point at the soroban-analyze binary}"
ANALYZE_PATH="${ANALYZE_PATH:-.}"
SEVERITY="${SEVERITY:-high}"
FORMAT="${FORMAT:-sarif}"
OUTPUT_FILE="${OUTPUT_FILE:-soroban-analyzer.${FORMAT}}"
FAIL_ON_FINDINGS="${FAIL_ON_FINDINGS:-true}"

case "$FORMAT" in
  sarif|json) ;;
  *) fail "format must be sarif or json, got '$FORMAT'" ;;
esac
case "$FAIL_ON_FINDINGS" in
  true|false) ;;
  *) fail "fail-on-findings must be true or false, got '$FAIL_ON_FINDINGS'" ;;
esac

if [ ! -e "$ANALYZE_PATH" ]; then
  fail "there is nothing at '$ANALYZE_PATH' to analyse"
fi

# A baseline is loaded by path; when one is configured but missing, the analyser fails —
# which is the right answer. A workflow whose baseline was not checked out would otherwise
# report every recorded finding as new.
arguments=(--format "$FORMAT" --severity "$SEVERITY" "$ANALYZE_PATH")
if [ -n "${BASELINE:-}" ]; then
  arguments=(--format "$FORMAT" --severity "$SEVERITY" --baseline "$BASELINE" "$ANALYZE_PATH")
fi

# stdout is the document, so it is redirected rather than echoed. stderr carries the
# counts and anything that went wrong, and is echoed for the job log.
status=0
"$SOROBAN_ANALYZER" "${arguments[@]}" >"$OUTPUT_FILE" 2>analysis.stderr || status=$?

# Everything the script says goes to stderr, and stdout is left alone: the document is in
# a file, and a step that writes to stdout is a step whose output is interleaved with the
# tool's.
echo "soroban-analyze exited $status" >&2
sed 's/^/  /' analysis.stderr >&2

if [ "$status" -eq 2 ]; then
  fail "the analyser could not run, so this workflow has not checked anything"
fi

findings=0
if command -v python3 >/dev/null 2>&1; then
  findings=$(python3 - "$OUTPUT_FILE" "$FORMAT" <<'PY'
import json
import sys

path, fmt = sys.argv[1], sys.argv[2]
try:
    document = json.load(open(path))
except (OSError, ValueError):
    print(0)
    raise SystemExit(0)

if fmt == "sarif":
    results = document.get("runs", [{}])[0].get("results", [])
    # Suppressed results are in the document so a scanner can show the exception; they
    # are not findings anybody has to act on.
    gating = [result for result in results if not result.get("suppressions")]
    print(len(gating))
else:
    print(document.get("summary", {}).get("findings", 0))
PY
  )
fi

# The step summary is what a reviewer reads in the pull request's checks tab before
# following a single annotation into the diff.
summary="${GITHUB_STEP_SUMMARY:-}"
if [ -n "$summary" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$OUTPUT_FILE" "$FORMAT" "$SEVERITY" "$ANALYZE_PATH" >>"$summary" <<'PY'
import json
import sys

path, fmt, severity, analysed = sys.argv[1:5]

document = json.load(open(path))
if fmt == "sarif":
    run = document.get("runs", [{}])[0]
    rules = {rule["id"]: rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
    results = [result for result in run.get("results", []) if not result.get("suppressions")]
    findings = [
        {
            "rule": result.get("ruleId", ""),
            "level": result.get("level", ""),
            "file": result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "line": result["locations"][0]["physicalLocation"]["region"]["startLine"],
            "message": result.get("message", {}).get("text", ""),
        }
        for result in results
    ]
    summary = document.get("runs", [{}])[0].get("tool", {}).get("driver", {})
    tool = f"{summary.get('name', 'soroban-analyze')} {summary.get('version', '')}".strip()
else:
    tool = f"{document.get('tool', {}).get('name', 'soroban-analyze')} {document.get('tool', {}).get('version', '')}".strip()
    findings = [
        {
            "rule": finding["rule"],
            "level": finding["severity"],
            "file": finding["file"],
            "line": finding["start_line"],
            "message": finding["message"],
        }
        for finding in document.get("findings", [])
    ]

print(f"## {tool}: {len(findings)} finding(s) at or above `{severity}` in `{analysed}`")
print()
if not findings:
    print("Nothing at or above the gate.")
else:
    print("| Rule | Level | Location | Finding |")
    print("| --- | --- | --- | --- |")
    for item in findings[:50]:
        message = item["message"].replace("|", "\\|")
        print(f"| `{item['rule']}` | {item['level']} | `{item['file']}:{item['line']}` | {message} |")
    if len(findings) > 50:
        print()
        print(f"...and {len(findings) - 50} more, in the SARIF uploaded to code scanning.")
PY
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "findings=$findings"
    echo "report=$OUTPUT_FILE"
    echo "exit-status=$status"
  } >>"$GITHUB_OUTPUT"
fi

if [ "$status" -eq 1 ] && [ "$FAIL_ON_FINDINGS" = "true" ]; then
  echo "::error::soroban-analyze found $findings finding(s) at or above '$SEVERITY'" >&2
  exit 1
fi

# A run asked not to fail still reports what it found, in the log and the summary.
echo "soroban-analyze: $findings finding(s) at or above '$SEVERITY' (report: $OUTPUT_FILE)" >&2
exit 0
