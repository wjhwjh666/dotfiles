#!/usr/bin/env bash
# Bounded regression cases for ci-check.sh; no extra Git repository or real credentials.
set -eu
scratch=$(mktemp -d)
trap 'rm -f "$scratch/ci-check.sh" "$scratch/hooks/pre-commit" "$scratch/result"; rmdir "$scratch/hooks" "$scratch"' EXIT
mkdir "$scratch/hooks"
cp "$(dirname "$0")/ci-check.sh" "$scratch/ci-check.sh"
cat > "$scratch/hooks/pre-commit" <<'RULES'
SECRET='FORBIDDEN_SECRET'
TZLEAK='FORBIDDEN_TIMEZONE'
RELAY='FORBIDDEN_RELAY'
USERPATH='FORBIDDEN_USERPATH'
RULES

git() {
  case "$1" in
    rev-parse)
      [ "$CASE" != invalid_ref ] || return 128
      printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      ;;
    rev-list)
      [ "$CASE" != list_failure ] || return 128
      printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      ;;
    diff-tree)
      [ "$CASE" != diff_failure ] || return 128
      if [ "$CASE" = history_secret ] && [[ "${!#}" = a* ]]; then
        printf '+FORBIDDEN_SECRET\n'
      elif [ "$CASE" = userpath ]; then
        printf '+FORBIDDEN_USERPATH\n'
      elif [ "$CASE" = relay ]; then
        printf '+forbidden_relay\n'
      elif [ "$CASE" = timezone_content ]; then
        printf '+FORBIDDEN_TIMEZONE\n'
      else
        printf '+normal content\n'
      fi
      ;;
    show)
      [ "$CASE" != metadata_failure ] || return 128
      if [ "$CASE" = timezone_metadata ]; then
        printf '2026-10-09 00:00:00 +0000|2026-10-09 00:00:00 +0100\n'
      else
        printf '2026-10-09 00:00:00 +0000|2026-10-09 00:00:00 +0000\n'
      fi
      ;;
    ls-files)
      [ "$CASE" != ignored_failure ] || return 128
      [ "$CASE" != ignored_file ] || printf 'settings.json\n'
      return 0
      ;;
    *) return 128 ;;
  esac
}
export -f git

count=0
run_case() {
  local expected="$2" rc=0
  CASE="$1" bash "$scratch/ci-check.sh" fixture-base fixture-head > "$scratch/result" 2>&1 || rc=$?
  if [ "$rc" -ne "$expected" ]; then
    printf 'FAIL %s: expected %s, got %s\n' "$1" "$expected" "$rc"
    cat "$scratch/result"
    exit 1
  fi
  printf 'PASS %s\n' "$1"
  count=$((count + 1))
}
run_case clean 0
run_case invalid_ref 2
run_case list_failure 2
run_case diff_failure 2
run_case metadata_failure 2
run_case ignored_failure 2
run_case history_secret 1
run_case userpath 1
run_case relay 1
run_case timezone_content 1
run_case timezone_metadata 1
run_case ignored_file 1

# Windows clones may check the hook out with CRLF line endings.
sed -i 's/$/\r/' "$scratch/hooks/pre-commit"
run_case clean 0
sed -i 's/\r$//' "$scratch/hooks/pre-commit"

# PR 12 can run before PR 11 introduces the optional path rule.
sed -i '/^USERPATH=/d' "$scratch/hooks/pre-commit"
run_case clean 0
printf "SECRET='[bad'\n" >> "$scratch/hooks/pre-commit"
run_case invalid_pattern 2
sed -i '/^SECRET=/d' "$scratch/hooks/pre-commit"
run_case missing_rule 2
printf '%s regression cases passed.\n' "$count"
