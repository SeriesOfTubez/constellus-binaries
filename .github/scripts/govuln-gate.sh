#!/usr/bin/env bash
# Evaluate govulncheck's reachable findings against a per-binary allowlist.
#
# The gate stays deny-by-default: any reachable vulnerability fails the build
# unless it is named in GOVULN_ALLOW *and* its review date is still in the
# future. An allowlist entry is an accepted risk with an expiry, not a mute
# button - when the date passes the build fails until someone looks again.
#
# Usage:  govuln-gate.sh <reachable-ids-file>
# Env:    GOVULN_ALLOW  space-separated "GO-YYYY-NNNN:YYYY-MM-DD" entries
#
# Exit 0 = every reachable finding is allowed and unexpired (or there are none).
# Exit 1 = something must be looked at.

set -euo pipefail

reachable_file="${1:?usage: govuln-gate.sh <reachable-ids-file>}"
today="${GOVULN_TODAY:-$(date -u +%Y-%m-%d)}"
allow_raw="${GOVULN_ALLOW:-}"

fail=0
note() { echo "$*"; }
summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "$*" >> "$GITHUB_STEP_SUMMARY" || true; }

declare -A allow_until=()
for entry in $allow_raw; do
  id="${entry%%:*}"
  until_date="${entry#*:}"
  if [ "$id" = "$entry" ] || [ -z "$until_date" ]; then
    echo "::error::GOVULN_ALLOW entry '$entry' is malformed - expected GO-YYYY-NNNN:YYYY-MM-DD"
    exit 1
  fi
  if ! printf '%s' "$until_date" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
    echo "::error::GOVULN_ALLOW entry '$entry' has a non-date expiry '$until_date'"
    exit 1
  fi
  allow_until["$id"]="$until_date"
done

reachable=()
if [ -s "$reachable_file" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && reachable+=("$line")
  done < "$reachable_file"
fi

note "govulncheck reachable findings: ${#reachable[@]}"
note "allowlist entries: ${#allow_until[@]} (today=$today)"

# 1. Every reachable finding must be allowed, and not past its review date.
for id in "${reachable[@]:-}"; do
  [ -z "$id" ] && continue
  if [ -z "${allow_until[$id]:-}" ]; then
    echo "::error::$id is reachable and not allowlisted - fix it, or add a reviewed GOVULN_ALLOW entry"
    summary "- ❌ \`$id\` reachable, not allowlisted"
    fail=1
  elif [[ "$today" > "${allow_until[$id]}" ]]; then
    echo "::error::$id allowlist entry expired on ${allow_until[$id]} - re-review it rather than extending blindly"
    summary "- ⏰ \`$id\` allowlist expired ${allow_until[$id]}"
    fail=1
  else
    note "allowed: $id until ${allow_until[$id]}"
    summary "- ⚠️ \`$id\` accepted until ${allow_until[$id]}"
  fi
done

# 2. A stale entry - allowlisted but no longer reachable - is good news, and
#    should be removed. Warn rather than fail: upstream fixing something must
#    not break the build.
for id in "${!allow_until[@]}"; do
  found=0
  for r in "${reachable[@]:-}"; do
    [ "$r" = "$id" ] && found=1 && break
  done
  if [ "$found" -eq 0 ]; then
    echo "::warning::$id is allowlisted but no longer reachable - drop it from GOVULN_ALLOW"
    summary "- ✅ \`$id\` no longer reachable, remove from GOVULN_ALLOW"
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "govulncheck gate: FAILED"
  exit 1
fi
echo "govulncheck gate: passed"
