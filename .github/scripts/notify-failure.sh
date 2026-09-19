#!/usr/bin/env bash
# Report a failed SCHEDULED workflow run as an issue on this repository.
#
# The problem this solves: a scheduled run that fails looks exactly like one
# that passed - silence. build.yml's weekly re-scan was red for five consecutive
# weeks (2026-08-17 .. 2026-09-14) on four reachable Go stdlib advisories and
# nobody learned of it, because nothing surfaces a red Monday-morning cron.
# A scan that fails silently is worse than no scan: it reads as reassurance.
#
# Deliberately files into THIS repo with `github.token`. Filing into
# constellus-planning, where the backlog lives, would need a fine-grained PAT -
# a credential that expires, whose expiry breaks the alerting path, and whose
# breakage is visible only through the alert that is no longer arriving. An
# alert nobody has to authenticate to write is the more reliable alert, and
# reliability is the entire point here.
#
# Usage:  notify-failure.sh
# Env:    GH_TOKEN       github.token, needs `issues: write`
#         WORKFLOW_FILE  e.g. build.yml - names the alert, one per workflow
#         LABEL          e.g. ci-health:build - the dedupe key (see below)
#         NEEDS_JSON     ${{ toJSON(needs) }} - which jobs actually went wrong
#
# Dedupe is by LABEL, not by title search. `gh issue list --search` is full-text
# and fuzzy: it happily matches a near-miss title and would comment on the wrong
# issue. A label is an exact match, and it makes the alerts filterable besides.
#
# This script does NOT close the issue when a later run passes. A flaky job that
# alternates red/green would auto-close its own alert every other week, which is
# how a recurring failure gets buried. A human closes it.
#
# If this script itself fails the notify job goes red, which is once again only
# visible in the Actions tab - the irreducible base case. GitHub's built-in
# "scheduled workflow failed" email to the cron's last committer stays the
# backstop for that one case; it is not sufficient on its own, which is why this
# exists, but it is not nothing either.

set -euo pipefail

: "${GH_TOKEN:?notify-failure.sh needs GH_TOKEN}"
: "${GITHUB_REPOSITORY:?}"
: "${WORKFLOW_FILE:?notify-failure.sh needs WORKFLOW_FILE}"
: "${LABEL:?notify-failure.sh needs LABEL}"
needs_json="${NEEDS_JSON:-{\}}"

title="CI: scheduled run of ${WORKFLOW_FILE} is failing"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
now="$(date -u +'%Y-%m-%d %H:%M UTC')"

# Which jobs actually went wrong. `skipped` is excluded on purpose: when an
# upstream job fails its dependants are skipped, and listing those as failures
# would bury the one job that broke. It also keeps cloud-ranges.yml's `build`,
# which is skipped on pull requests by design, from ever reading as a fault.
bad="$(printf '%s' "$needs_json" | jq -r '
  to_entries
  | map(select(.value.result != "success" and .value.result != "skipped"))
  | map("`\(.key)` (\(.value.result))")
  | join(", ")')"
if [ -z "$bad" ]; then
  # Reached via cancelled(): a run that hits the 6h limit is cancelled, not
  # failed, and its jobs may carry no failure result at all.
  bad="_no failed job reported - the run was cancelled or timed out_"
fi

body="$(mktemp)"
cat > "$body" <<EOF
A **scheduled** run of \`${WORKFLOW_FILE}\` did not succeed.

| | |
|---|---|
| run | ${run_url} |
| attempt | ${GITHUB_RUN_ATTEMPT:-1} |
| jobs | ${bad} |
| commit | \`${GITHUB_SHA}\` |
| when | ${now} |

Scheduled runs are the unattended path: nobody is watching Actions when this
fires, which is the whole reason it is reported here. Subsequent failures are
added to this issue as comments rather than filed as new issues.

Close this once the cause is fixed - it is not closed automatically, because a
flaky run passing once is not the same as the problem being solved.
EOF

# The label is the dedupe key, so it has to exist before the first alert can be
# filed. Create it on demand rather than relying on someone having set the repo
# up by hand - a missing label would fail the alert, silently, on the one run
# that needed it.
if ! gh label list --repo "$GITHUB_REPOSITORY" --limit 200 --json name -q '.[].name' \
     | grep -qxF "$LABEL"; then
  gh label create "$LABEL" --repo "$GITHUB_REPOSITORY" \
    --color "b60205" \
    --description "A scheduled run of ${WORKFLOW_FILE} is failing"
fi

existing="$(gh issue list --repo "$GITHUB_REPOSITORY" \
  --state open --label "$LABEL" --limit 1 --json number -q '.[0].number // empty')"

if [ -n "$existing" ]; then
  gh issue comment "$existing" --repo "$GITHUB_REPOSITORY" --body-file "$body"
  echo "commented on existing #${existing}"
  echo "Reported on existing issue #${existing}." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
else
  url="$(gh issue create --repo "$GITHUB_REPOSITORY" \
    --title "$title" --label "$LABEL" --body-file "$body")"
  echo "opened $url"
  echo "Opened ${url}." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
fi
