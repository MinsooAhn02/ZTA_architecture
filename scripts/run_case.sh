#!/usr/bin/env bash
# Single curl-based ZTA test runner.
# Replaces the per-target `kubectl run … --restart=Never` pattern that
# repeated in ~19 Makefile recipes.
#
# Usage:
#   scripts/run_case.sh CASE EXPECT_RE CLIENT METHOD URL DETAIL [HEADER ...]
#
#   CASE       Summary row label.
#   EXPECT_RE  Extended regex matched against the 3-digit status
#              (e.g. "403" or "403|000|503").
#   CLIENT     Pod selector to exec into (curl-client | rogue-client | wrongsa-client),
#              or "-" to run curl directly on this host.
#   METHOD     GET | POST | …
#   URL        Full URL.
#   DETAIL     Free-form text recorded in the summary row.
#   HEADER…    Zero or more "Name: value" header strings.
#
# Optional env:
#   BODY     POST/PUT body string (sets -d "$BODY").
#   TIMEOUT  curl --max-time value (default 10).
#   SUMMARY  Path to summary file (default .test-summary.log).
#
# Output: EXPECT / RESULT / STATUS lines + summary append.
# Exit: 0 iff STATUS=PASS.

set -uo pipefail

CASE="${1:?usage: run_case.sh CASE EXPECT_RE CLIENT METHOD URL DETAIL [HEADER ...]}"
EXPECT_RE="${2:?missing EXPECT_RE}"
CLIENT="${3:?missing CLIENT}"
METHOD="${4:?missing METHOD}"
URL="${5:?missing URL}"
DETAIL="${6:-}"
shift 6 || true

TIMEOUT="${TIMEOUT:-10}"
SUMMARY="${SUMMARY:-.test-summary.log}"
BODY="${BODY:-}"

touch "$SUMMARY"

# Build curl argv as an array — no eval, no shell-injection risk.
CURL_ARGV=(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" -X "$METHOD")
for h in "$@"; do
    CURL_ARGV+=(-H "$h")
done
if [ -n "$BODY" ]; then
    CURL_ARGV+=(-d "$BODY")
fi
CURL_ARGV+=("$URL")

if [ "$CLIENT" = "-" ]; then
    RAW=$("${CURL_ARGV[@]}" 2>/dev/null || true)
else
    # kubectl exec preserves argv; pass each curl arg as a separate parameter.
    RAW=$(kubectl exec "deploy/${CLIENT}" -c curl -- "${CURL_ARGV[@]}" 2>/dev/null || true)
fi

RESULT=$(printf '%s' "$RAW" | tr -d '\r' | grep -Eo '[0-9]{3}' | tail -n1)
[ -z "$RESULT" ] && RESULT="ERR"

if printf '%s' "$RESULT" | grep -Eq "^(${EXPECT_RE})$"; then
    STATUS="PASS"
else
    STATUS="FAIL"
fi

echo "EXPECT: ${EXPECT_RE}"
echo "RESULT: ${RESULT}"
echo "STATUS: ${STATUS}"
# Summary uses `|` as field separator; convert `|` inside EXPECT_RE to `,`
# so multi-value expects (e.g. "403|000|503") render as one column.
EXPECT_FOR_SUMMARY="${EXPECT_RE//|/,}"
echo "${CASE}|${EXPECT_FOR_SUMMARY}|${RESULT}|${STATUS}|${DETAIL}" >> "$SUMMARY"

[ "$STATUS" = "PASS" ]
