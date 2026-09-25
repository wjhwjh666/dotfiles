# -*- coding: utf-8 -*-
"""L3 rule inject (v1) -- UserPromptSubmit.

CLAUDE.md is advisory, and in a long session its middle sections are exactly
what compaction summarises away first -- which is where the红线 live. This
re-states them as a system reminder on every prompt, so they sit at the fresh
end of the context window instead of the stale end.

Deliberately excludes anything the hard guards already enforce mechanically
(plaintext credentials -> l3_content_guard, registry/partition/force-push ->
l3_bash_guard). Repeating those in soft text buys nothing and is billed every
single turn. What stays is only what no hook can catch: sourcing, honest
reporting of incomplete or failed work, and the two user红线 with no mechanical
equivalent, plus the causal-attribution discipline from 错题本 #013/#014 -- no hook
can force a control group before I assert causation.

Never blocks. Any error exits 0 with no output.
"""

import json
import sys

RULES = (
    "L3 每回合重申："
    "结论只能来自刚读到的文件或命令输出，凭印象的先验证；"
    "范围没做完、测试挂了、步骤跳过了必须明说并附输出；"
    "不嗅探用户真实 IP；删除或覆盖前先读一眼目标；"
    "断言「A 导致 B」前先构造一个没有 A 的对照，同类修法连挂两次就换层面查。"
)


def main():
    sys.stdin.read()          # 读掉 stdin，避免上游写入时 broken pipe
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": RULES}}, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)
