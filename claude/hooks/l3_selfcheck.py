"""L3 self-check (v5) -- SessionStart.

This is the piece the previous two deployments lacked. The L3 layer did not fail
because the guards were wrong; it failed because settings.json got reset and
NOTHING NOTICED for weeks. So every session now:

  1. verifies that EACH guard is still wired to the event it belongs to;
  2. keeps a known-good snapshot of the `hooks` block in ~/.claude/sentinels/;
  3. RESTORES the hooks block automatically if wiring has gone missing;
  4. reports the result into context so a silent regression becomes visible.

v5 fixes a hole found by a sandboxed replay of v4: it asked only whether the
`PreToolUse` KEY existed. A config that kept PreToolUse but had every L3 entry
stripped out of it -- leaving just the third-party RTK hook -- still reported
"全部就位", and then overwrote the snapshot with that stub. The one recovery
source was destroyed by the health check itself, so the later restore put back
an empty shell and called it a success. Two rules follow from that:

  * wiring is verified per guard script, not per event key;
  * the snapshot is refreshed ONLY from a fully healthy config, and is used for
    recovery ONLY when the snapshot itself is fully healthy.

Never blocks. SessionStart cannot deny anything, and a self-check that wedges
startup would be worse than the problem it detects.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from l3_common import (  # noqa: E402
    CLAUDE_DIR,
    EXPECTED_WIRING,
    SENTINEL_DIR,
    guard_canary_passes,
    log,
    missing_wiring,
)

SETTINGS = os.path.join(CLAUDE_DIR, "settings.json")
SNAPSHOT = os.path.join(SENTINEL_DIR, "l3-hooks.snapshot.json")
GUARDS = ("l3_common.py", "l3_bash_guard.py", "l3_content_guard.py",
          "l3_selfcheck.py", "l3_stop_gate.py", "l3_rule_inject.py")
CLAUDE_MD = os.path.join(CLAUDE_DIR, "CLAUDE.md")

def emit(context):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    }, ensure_ascii=False))


def main():
    notes = []
    os.makedirs(SENTINEL_DIR, exist_ok=True)

    try:
        with open(SETTINGS, encoding="utf-8") as fh:
            settings = json.load(fh)
    except Exception as exc:
        emit("L3 自检: 无法读取 settings.json (%s)。L3 强制层状态未知。" % exc)
        return

    hooks = settings.get("hooks") or {}
    gaps = missing_wiring(hooks)

    if not gaps:
        # healthy -> and ONLY now may the snapshot be refreshed
        try:
            tmp = SNAPSHOT + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"savedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
                           "hooks": hooks}, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, SNAPSHOT)
        except Exception:
            pass
    else:
        # REGRESSION -- restore, but never from a snapshot that is itself broken
        saved = None
        try:
            with open(SNAPSHOT, encoding="utf-8") as fh:
                saved = json.load(fh)
        except Exception:
            saved = None

        if saved and not missing_wiring(saved.get("hooks")):
            try:
                settings["hooks"] = saved["hooks"]
                tmp = SETTINGS + ".l3tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(settings, fh, ensure_ascii=False, indent=2)
                os.replace(tmp, SETTINGS)
                notes.append("⚠️ L3 接线曾缺失 (%s)，已从 %s 的快照自动恢复。"
                             "请查明是什么改了 settings.json。"
                             % (", ".join(gaps), saved.get("savedAt", "?")))
                log("RESTORE", "hooks restored, gaps were: %s" % ", ".join(gaps))
            except Exception as exc:
                notes.append("🔴 L3 接线缺失 (%s) 且恢复失败 (%s) —— 守卫没在跑。"
                             % (", ".join(gaps), exc))
        else:
            notes.append("🔴 L3 接线缺失 (%s)，且快照本身也不完整，无法自动恢复 —— "
                         "这些守卫当前执行率为 0。" % ", ".join(gaps))
            log("BROKEN", "gaps: %s ; snapshot unusable" % ", ".join(gaps))

    missing = [g for g in GUARDS
               if not os.path.exists(os.path.join(CLAUDE_DIR, "hooks", g))]
    if missing:
        notes.append("🔴 守卫脚本缺失: %s —— 对应规则未生效。" % ", ".join(missing))

    # 文件在、接线也在，仍然可能一条都拦不住：把主循环改成空迭代或者让 deny()
    # 不再退出，语法合法、大小几乎不变，上面两项检查全部报绿。
    # **这是会话开始时最该问的问题**——如果守卫在上一次会话里被改坏了，
    # 这里是第一个能说出来的地方。None 表示判断不了（解释器起不来之类），按放行处理。
    if guard_canary_passes() is False:
        notes.append("🔴 守卫文件和接线都在，但它**不再拦截**本该拦下的命令"
                     "（金丝雀放行了）—— 判定逻辑被改坏了，当前等于没有防护。"
                     "跑 `python ~/.claude/hooks/l3_regression.py` 定位。")

    if not os.path.exists(CLAUDE_MD):
        notes.append("⚠️ ~/.claude/CLAUDE.md 不存在，MEMORY.md 的「核心指令」是死链。")

    emit("L3 自检: " + ("；".join(notes) if notes
                        else "全部就位（守卫文件 %d/%d、%d 条接线逐项校验通过）。"
                             % (len(GUARDS), len(GUARDS),
                                sum(len(v) for v in EXPECTED_WIRING.values()))))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(0)
