#!/usr/bin/env bash
# Server-side copy of the pre-commit checks, for commits that never passed through the local hook
# (GitHub web merges/edits, cloud sessions without core.hooksPath).
# Usage: scripts/ci-check.sh <base-sha> <head-sha>   (base may be empty or all zeros: only head is checked)
# Regexes are read from scripts/hooks/pre-commit, including USERPATH when present.
set -u -o pipefail

base=${1:-}
head=${2:-HEAD}
hook="$(dirname "$0")/hooks/pre-commit"

error() {
  echo "ci-check: $*" >&2
  exit 2
}

# Read literal pattern assignments without executing the hook's contents.
[ -r "$hook" ] || error "Cannot read hook rules."
SECRET= TZLEAK= RELAY= USERPATH=
while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}
  case "$line" in
    SECRET=*|TZLEAK=*|RELAY=*|USERPATH=*)
      name=${line%%=*}
      value=${line#*=}
      [[ "$value" =~ ^\'([^\']*)\'$ ]] || error "Invalid rule assignment: $name"
      printf -v "$name" '%s' "${BASH_REMATCH[1]}"
      ;;
  esac
done < "$hook"
for v in SECRET TZLEAK RELAY; do
  if [ -z "${!v:-}" ]; then
    echo "✖ ci-check: 无法从 $hook 读取规则 $v" >&2
    exit 2
  fi
done

rules=(SECRET TZLEAK RELAY)
[ -z "${USERPATH:-}" ] || rules+=(USERPATH)
for name in "${rules[@]}"; do
  printf '\n' | grep -E "${!name}" >/dev/null
  rc=$?
  [ "$rc" -le 1 ] || error "Invalid pattern: $name"
done

head=$(git rev-parse --verify --end-of-options "$head^{commit}") || error "Invalid head commit."

if [ -z "$base" ] || [ -z "${base//0/}" ]; then
  range="$head"
  commits="$head"
else
  base=$(git rev-parse --verify --end-of-options "$base^{commit}") || error "Invalid base commit."
  range="$base..$head"
  commits=$(git rev-list --reverse "$range") || error "Cannot enumerate commits."
fi

fail=0
# Inspect each commit: deleting forbidden content later must not hide its history.
while IFS= read -r commit; do
  [ -n "$commit" ] || continue
  diff=$(git diff-tree --root --no-commit-id -r -m --first-parent -U0 --no-color "$commit") || error "Cannot read commit diff."
  added=$(printf '%s\n' "$diff" | sed -n '/^+++ /d; /^+/p') || error "Cannot extract added lines."
  for name in "${rules[@]}"; do
    options=(-E)
    [ "$name" != RELAY ] || options+=(-i)
    # Consume all input; grep -q may cause SIGPIPE with pipefail on large diffs.
    printf '%s\n' "$added" | grep "${options[@]}" "${!name}" >/dev/null
    rc=$?
    [ "$rc" -le 1 ] || error "Pattern scan failed: $name"
    if [ "$rc" -eq 0 ]; then
      echo "ci-check: $name rule matched in commit $commit" >&2
      fail=1
    fi
  done
  dates=$(git show -s --format='%ai|%ci' "$commit") || error "Cannot read commit timestamps."
  if [[ ! "$dates" =~ \+0000\|.*\+0000$ ]]; then
    echo "ci-check: Non-UTC author or committer timestamp in $commit" >&2
    fail=1
  fi
done <<< "$commits"

# Files that .gitignore blocks but were force-added anyway.
forced=$(git ls-files -ci --exclude-standard) || error "Cannot check ignored tracked files."
if [ -n "$forced" ]; then
  echo "✖ ci-check: 以下文件被 .gitignore 拦截却仍被跟踪（疑似 git add -f）：" >&2
  printf '  %s\n' "$forced" >&2
  fail=1
fi

[ $fail -eq 0 ] && echo "✔ ci-check: 通过（$range）"
exit $fail
