#!/usr/bin/env bash
# Server-side copy of the pre-commit checks, for commits that never passed through the local hook
# (GitHub web merges/edits, cloud sessions without core.hooksPath).
# Usage: scripts/ci-check.sh <base-sha> <head-sha>   (base may be empty or all zeros: only head is checked)
# Regexes are read from scripts/hooks/pre-commit so the two never drift apart.
set -u

base=${1:-}
head=${2:-HEAD}
hook="$(dirname "$0")/hooks/pre-commit"

eval "$(grep -E '^(SECRET|TZLEAK|RELAY)=' "$hook")"
for v in SECRET TZLEAK RELAY; do
  if [ -z "${!v:-}" ]; then
    echo "✖ ci-check: 无法从 $hook 读取规则 $v" >&2
    exit 2
  fi
done

if [ -z "$base" ] || [ -z "${base//0/}" ]; then
  range="$head"
  diff_base="$(git hash-object -t tree /dev/null)"
else
  range="$base..$head"
  diff_base="$base"
fi

fail=0
added=$(git diff -U0 --no-color "$diff_base" "$head" | grep -E '^\+' | grep -vE '^\+\+\+ ')

if printf '%s\n' "$added" | grep -qE "$SECRET"; then
  echo "✖ ci-check: 新增内容含疑似密钥" >&2
  fail=1
fi

if printf '%s\n' "$added" | grep -qE "$TZLEAK"; then
  echo "✖ ci-check: 新增内容含本地时区/位置信息" >&2
  fail=1
fi

if printf '%s\n' "$added" | grep -qiE "$RELAY"; then
  echo "✖ ci-check: 新增内容含中转切换工具名称（本机只走官方订阅）" >&2
  fail=1
fi

# Every new commit (author and committer) must be stamped +0000.
if [ "$range" = "$head" ]; then
  commits=$(git log -1 --format='%h %ai|%ci' "$head")
else
  commits=$(git log --format='%h %ai|%ci' "$range")
fi
bad=$(printf '%s\n' "$commits" | grep -vE '^[0-9a-f]+ [^|]*\+0000\|.*\+0000$' | grep -v '^$')
if [ -n "$bad" ]; then
  echo "✖ ci-check: 以下提交时区不是 +0000（多半是网页合并/编辑，或本机未设 TZ=UTC0）：" >&2
  printf '  %s\n' "$bad" >&2
  fail=1
fi

# Files that .gitignore blocks but were force-added anyway.
forced=$(git ls-files -ci --exclude-standard)
if [ -n "$forced" ]; then
  echo "✖ ci-check: 以下文件被 .gitignore 拦截却仍被跟踪（疑似 git add -f）：" >&2
  printf '  %s\n' "$forced" >&2
  fail=1
fi

[ $fail -eq 0 ] && echo "✔ ci-check: 通过（$range）"
exit $fail
