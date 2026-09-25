# -*- coding: utf-8 -*-
"""L3 stop gate (v1) -- Stop hook. The POSITIVE gate.

The three existing guards are all negative gates: they block dangerous actions.
Nothing ever checked that what got produced is actually intact. This closes the
turn only when the things this machine has historically broken are still sound:

  1. the L3 wiring itself (settings.json parses, PreToolUse present, guards on disk);
  2. every critical config file still parses;
  3. every file written or edited this turn still parses (.json / .py);
  4. every MEMORY file written this turn still points at things that exist;
  5. if any guard file changed this turn, the guards STILL BLOCK what they should.

Check 5 exists because 1 and 3 together still miss the worst case: a guard whose
syntax is fine and whose file is present, but whose logic no longer denies
anything. It is deliberately entry-agnostic -- it looks at the final state on
disk, so it does not care whether the edit came through Write/Edit (which the
content guard sees) or through bash (which it does not).

Check 4 exists because a memory naming a file that is gone reads as
authoritative and is not -- a 2026-09-14 audit found 48 such references that had
accumulated over months, each one written by a past turn that nobody checked.
Catching it at the turn that introduces it is the only cheap moment.

Blocking contract: exit 2, reason from hookSpecificOutput.blockReason.
Fail-open: any internal error exits 0. A gate that wedges every turn is worse
than the regression it detects.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HOME = os.path.expanduser("~")
CLAUDE_DIR = os.path.join(HOME, ".claude")
GUARDS = ("l3_common.py", "l3_bash_guard.py", "l3_content_guard.py",
          "l3_selfcheck.py", "l3_stop_gate.py", "l3_rule_inject.py")
CRITICAL_JSON = (os.path.join(CLAUDE_DIR, "settings.json"),
                 os.path.join(HOME, ".claude.json"))
MAX_FILES = 40


def block(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "Stop", "blockReason": reason}}, ensure_ascii=False))
    sys.stderr.write(reason)
    sys.exit(2)


def check_syntax(path):
    """Return an error string, or None if the file is fine / not checkable."""
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".json":
            with open(path, encoding="utf-8") as fh:
                json.load(fh)
        elif ext == ".py":
            with open(path, encoding="utf-8") as fh:
                compile(fh.read(), path, "exec")
    except UnicodeDecodeError:
        return None                      # 非 UTF-8，不归本门禁管
    except Exception as exc:
        return "%s: %s" % (path, exc)
    return None


MEMORY_LINT = os.path.join(CLAUDE_DIR, "tools", "memory_lint.py")
MAX_MEMORY_FILES = 12


def _load_memory_lint():
    """Import tools/memory_lint.py by path, or None. Never raises."""
    if not os.path.exists(MEMORY_LINT):
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_l3_memory_lint", MEMORY_LINT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod if hasattr(mod, "lint_file") else None
    except Exception:
        return None


def check_memory_refs(paths):
    """Dead references introduced into memory files during THIS turn.

    Scope is deliberately tight: only .md under a directory named memory*, only
    files this turn actually wrote, and no salvage search (that walk takes
    minutes and a Stop hook has to be instant). Anything unexpected returns an
    empty list -- this check is worth having, not worth wedging a turn over.
    """
    mem = [p for p in paths
           if p.lower().endswith(".md")
           and re.search(r"[\\/]memory[^\\/]*[\\/]", p.replace("/", os.sep) + os.sep,
                         re.I)][:MAX_MEMORY_FILES]
    if not mem:
        return []
    ml = _load_memory_lint()
    if ml is None:
        return []

    problems, names_cache = [], {}
    for p in mem:
        try:
            dead = [r for r in ml.lint_file(p, do_salvage=False)
                    if r.get("status") == "dead"]
            d = os.path.dirname(p)
            if d not in names_cache:
                names_cache[d] = ml.known_names(d)
            broken = ml.lint_links(p, names_cache[d])
        except Exception:
            continue
        base = os.path.basename(p)
        for r in dead:
            problems.append("%s L%s 指向不存在的 %s" % (base, r.get("line"), r.get("ref")))
        for r in broken:
            problems.append("%s L%s 链接到不存在的 %s" % (base, r.get("line"), r.get("ref")))
    if problems:
        problems.append("若该引用是**故意**提到已消失之物，在那一行末尾加 "
                        "`<!-- memlint:ignore 原因 -->` 豁免（必须写原因）。")
    return problems


WRITERS = ("Write", "Edit", "NotebookEdit", "MultiEdit")
# A turn is short; the transcript is not. A Stop hook that reads a 100 MB file
# is a Stop hook that gets uninstalled.
MAX_TAIL_BYTES = 2 * 1024 * 1024


def _is_real_user_turn(row):
    """A user row that is an actual prompt, not a tool_result fed back in."""
    if row.get("type") != "user":
        return False
    content = (row.get("message") or {}).get("content")
    if isinstance(content, str):
        return bool(content.strip())
    if isinstance(content, list):
        return not any(isinstance(b, dict) and b.get("type") == "tool_result"
                       for b in content)
    return False


def files_from_transcript(transcript_path):
    """Paths written this turn, recovered from the transcript's tail.

    Never raises: this gate runs on every turn, and a gate that throws is a gate
    that gets switched off.
    """
    if not transcript_path or not os.path.exists(transcript_path):
        return []
    try:
        size = os.path.getsize(transcript_path)
        with open(transcript_path, encoding="utf-8", errors="replace") as fh:
            if size > MAX_TAIL_BYTES:
                fh.seek(size - MAX_TAIL_BYTES)
                fh.readline()              # drop the partial first line
            lines = fh.readlines()
    except Exception:
        return []

    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue

    start = 0
    for i in range(len(rows) - 1, -1, -1):
        if _is_real_user_turn(rows[i]):
            start = i
            break

    out = []
    for row in rows[start:]:
        if row.get("type") != "assistant":
            continue
        content = (row.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            if block.get("name") not in WRITERS:
                continue
            ti = block.get("input") or {}
            p = ti.get("file_path") or ti.get("notebook_path")
            if p and p not in out:
                out.append(p)
            if len(out) >= MAX_FILES:
                return out
    return out


# --- 守卫有效性（入口无关） --------------------------------------------------
# 内容守卫的 GUARD_INEFFECTIVE 只盯 Write / Edit / NotebookEdit 三个入口。
# 用 bash 改守卫——`cat > l3_bash_guard.py <<EOF`、`python patch.py`——
# 完全不经过它，**而那恰恰是本机最常用的改法**（2026-09-15 这一整天的守卫改动
# 全是走 bash patch 的）。第 3 项检查也帮不上忙：它的文件清单来自 transcript 里
# 的 Write/Edit 调用，bash 写的文件压根不在里面。
#
# 这道检查放在回合结束、只看磁盘上的最终状态，因此不关心是谁怎么改的。
GUARD_FINGERPRINT = os.path.join(CLAUDE_DIR, "sentinels", "guard-fingerprint.json")

def _guard_fingerprint():
    out = {}
    for g in GUARDS:
        p = os.path.join(CLAUDE_DIR, "hooks", g)
        try:
            st = os.stat(p)
            out[g] = [int(st.st_mtime), st.st_size]
        except OSError:
            out[g] = None
    return out


def check_guards_effective():
    """守卫文件一有变动，就验证它们还拦不拦。

    **「语法没坏」不等于「还拦得住」。** 第 3 项只做 py_compile，而把
    `for toks in statements(raw):` 改成 `for toks in []:` 语法完全合法、
    文件大小几乎不变、`deny(` 一个没少——守卫从此零拦截，所有健康检查报绿。
    有效性只能用行为证明。

    指纹（mtime + size）没变就直接返回，所以常态下只是几次 stat；
    只有真改过守卫的那一回合才付 ~380ms（实测差值 379ms）。全程 fail-open。

    **覆盖范围要说清楚，别把这一项当成"验证了全部守卫"。** 指纹盯的是 GUARDS
    里全部六个 `l3_*.py`，但金丝雀只能证明**拦截型**那条链路还活着
    （bash 守卫 + 它依赖的 l3_common）。剩下三个各有各的验法，不在这里：

      * `l3_content_guard` —— 它自己有 GUARD_INEFFECTIVE，会在被 Write/Edit 时自验；
      * `l3_rule_inject` —— 不拦任何东西，金丝雀对它无意义；
        由回归套的 rule_inject_cases 验"真的注入了内容"
        （此前唯一那条用例只看 exit code，把 RULES 改空照样绿）；
      * `l3_stop_gate` 自己 —— 改坏了它就不运行，**这一项无法自证**，
        只能靠 SessionStart 的 selfcheck 和回归套兜。

    换句话说：指纹变化是**触发条件**，不是覆盖声明。
    """
    try:
        now = _guard_fingerprint()
        prev = None
        try:
            with open(GUARD_FINGERPRINT, encoding="utf-8") as fh:
                prev = json.load(fh)
        except Exception:
            prev = None
        if prev == now:
            return []

        # 金丝雀本体在 l3_common：SessionStart 的 selfcheck 也要问同一个问题，
        # 两处各写一份必然漂移——改了这边忘了那边，而两边都不会报错。
        #
        # import 失败本身就是一条结论，不能静默跳过：**每个守卫都依赖 l3_common**
        # （deny 就住在里面），它坏了就是全线失效，而这里恰恰是少数几个能说出来的地方。
        try:
            # 模块顶部已经把 hooks/ 放进 sys.path，这里直接导入。
            from l3_common import guard_canary_passes
        except Exception as exc:
            return ["l3_common 导入失败 (%s) —— **每一个守卫都依赖它**，"
                    "当前极可能全线失效。先确认这个文件没被改坏。" % exc]
        ok = guard_canary_passes()
        if ok is False:
            return ["守卫文件这一回合变过，而改完之后它**不再拦截**本该拦下的命令"
                    "（金丝雀放行了）。语法能过、大小正常、deny() 还在，"
                    "说明是判定逻辑被改坏了。先跑 "
                    "`python ~/.claude/hooks/l3_regression.py` 定位。"]
        if ok is None:
            return []          # 判断不了就别拦，fail-open

        # 只在验证通过后才刷新指纹：没通过就留着旧的，下一回合会重新验。
        try:
            os.makedirs(os.path.dirname(GUARD_FINGERPRINT), exist_ok=True)
            with open(GUARD_FINGERPRINT, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(now, fh)
        except Exception:
            pass
        return []
    except Exception:
        return []          # fail-open


def main():
    raw = sys.stdin.read()
    data = json.loads(raw) if raw.strip() else {}

    # 2026-09-15 本机实测的 Stop payload 字段（探针已拆除）：
    #   session_id / transcript_path / cwd / scratchpad_dir / prompt_id /
    #   permission_mode / effort / hook_event_name / stop_hook_active /
    #   last_assistant_message / background_tasks / session_crons
    # **没有 tool_calls** —— 见下面第 3 项为什么要从 transcript 重建。

    # 防死循环：本回合已经因为 Stop hook 被拦过一次，就不再拦
    if data.get("stop_hook_active"):
        sys.exit(0)

    problems = []

    # 1. L3 接线仍在
    settings_path = os.path.join(CLAUDE_DIR, "settings.json")
    try:
        with open(settings_path, encoding="utf-8") as fh:
            settings = json.load(fh)
        if not (settings.get("hooks") or {}).get("PreToolUse"):
            problems.append("settings.json 里没有 PreToolUse —— L3 守卫当前执行率为 0")
    except Exception as exc:
        problems.append("settings.json 解析失败 (%s) —— L3 会被静默忽略" % exc)

    missing = [g for g in GUARDS
               if not os.path.exists(os.path.join(CLAUDE_DIR, "hooks", g))]
    if missing:
        problems.append("守卫脚本缺失: " + ", ".join(missing))

    # 2. 关键配置文件仍可解析
    for p in CRITICAL_JSON:
        if os.path.exists(p):
            err = check_syntax(p)
            if err:
                problems.append("关键配置损坏 -> " + err)

    # 3. 本回合写过的文件仍可解析
    #
    # The Stop payload has no tool_calls field -- the docs list transcript_path
    # and last_assistant_message, not tool_calls -- so this loop used to run
    # zero times on every real turn while still reporting success. tool_calls is
    # tried first anyway: the regression suite supplies it, and a future client
    # that provides it should be believed over a file on disk.
    candidates = []
    for call in (data.get("tool_calls") or []):
        if call.get("tool_name") not in WRITERS:
            continue
        ti = call.get("tool_input") or {}
        p = ti.get("file_path") or ti.get("notebook_path")
        if p:
            candidates.append(p)
    if not candidates:
        candidates = files_from_transcript(data.get("transcript_path"))

    seen = []
    for p in candidates:
        if p not in seen and os.path.exists(p):
            seen.append(p)
        if len(seen) >= MAX_FILES:
            break
    for p in seen:
        err = check_syntax(p)
        if err:
            problems.append("本回合写坏了 -> " + err)

    # 4. 本回合写过的记忆文件，其引用仍然指向真实存在的东西
    problems.extend(check_memory_refs(seen))

    # 5. 守卫改过的话，它还拦不拦（入口无关，看磁盘最终状态）
    problems.extend(check_guards_effective())

    if problems:
        block("L3-STOP_GATE | 这一回合留下了未修复的问题，先修好再结束：\n  - "
              + "\n  - ".join(problems)
              + "\n(修好后再次结束即可放行；本门禁不会连续拦第二次。)")

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)          # fail-open
