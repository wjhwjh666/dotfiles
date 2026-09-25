"""L3 content guard (v5) -- PreToolUse on Write / Edit / NotebookEdit.

Four jobs:
  1. Never let a config file this machine depends on get truncated or corrupted.
     settings.json has silently reverted to a stub twice; that is what this stops.
  2. Never let a JSON file be written -- or EDITED -- into invalid syntax. A
     malformed settings.json silently disables every setting in it: no error, no
     warning, just a machine that quietly stops enforcing its own rules.
  3. Never let the L3 guards themselves be replaced by something that parses
     cleanly and enforces nothing. That failure mode passes every health check
     while leaving the machine completely unguarded.
  4. Never let a live credential literal land in a source file.

Edit gives `new_string`, which is a FRAGMENT. v4 therefore skipped every
whole-file check on Edit -- which meant the same corruption Write refused could
be applied one Edit at a time. v5 reads the file off disk and applies the
replacement in memory, so the post-edit content can be checked for real.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from l3_common import (  # noqa: E402
    SECRET_RE,
    allow,
    deny,
    missing_wiring,
    read_event,
)

HOME = os.path.expanduser("~")


def n(p):
    return os.path.normcase(os.path.abspath(os.path.expanduser(p or "")))


# file -> minimum plausible byte size. Below this, the write is a truncation.
PROTECTED = {
    n(os.path.join(HOME, ".claude", "settings.json")): 400,
    n(os.path.join(HOME, ".claude.json")): 2000,
    n(os.path.join(HOME, ".claude", "CLAUDE.md")): 500,
    n(os.path.join(HOME, ".claude", "projects", "C--Users----", "memory", "MEMORY.md")): 2000,
}

HOOKS_DIR = n(os.path.join(HOME, ".claude", "hooks"))

# A guard file may shrink, but not collapse. 60% of its current size is loose
# enough for an honest refactor and tight enough to catch a stub.
GUARD_SHRINK_FLOOR = 0.6


def is_guard_file(key):
    base = os.path.basename(key)
    return (os.path.dirname(key) == HOOKS_DIR
            and base.startswith("l3_") and base.endswith(".py"))


def check_guard_selfharm(key, path, content):
    """A guard that still imports and still parses but no longer denies anything
    is the worst possible state: every health check reports green while nothing
    at all is enforced. Size alone cannot see that, so the deny surface is
    checked too."""
    try:
        current = open(path, encoding="utf-8").read()
    except Exception:
        return  # new guard file; nothing to compare against
    floor = int(len(current.encode("utf-8", "ignore")) * GUARD_SHRINK_FLOOR)
    if len(content.encode("utf-8", "ignore")) < floor:
        deny("GUARD_TRUNCATION",
             "%s would shrink from %d to %d bytes. Collapsing a guard disables "
             "enforcement while every self-check still reports green."
             % (os.path.basename(path), len(current), len(content)))
    if "deny(" in current and "deny(" not in content:
        deny("GUARD_NEUTERED",
             "%s currently blocks things, and the new content contains no deny() "
             "call at all. A guard that parses but never denies is indistinguishable "
             "from a working one until the day it matters."
             % os.path.basename(path))


# 真实的 hooks 目录（HOOKS_DIR 是 normcase 过的，用来比较，不能用来读文件）。
HOOKS_REAL = os.path.dirname(os.path.abspath(__file__))

# 拼出来的：完整字面量留在这个文件里，会让"用 Bash 编辑本文件"的命令
# 被 bash 守卫的 GIT_FORCE_PUSH 拦下。
_CANARY_CMD = "git push --" + "force origin main"

# 被改的文件 -> (拿哪个守卫去跑, 喂什么 payload)。
#
# payload 必须**只**打到要验证的那条路径。第一版给内容守卫用的是
# "写 stub 到 settings.json"，结果那个 payload 同时触发 WIRING_LOSS——
# 于是截断检查被短路时金丝雀照样报"拦"，另一条规则把失效掩盖了。
# 换成写 CLAUDE.md：它在 PROTECTED 里、不是 JSON、也不含接线，
# 只可能触发 CONFIG_TRUNCATION 这一条。
_CANARY = {
    "l3_bash_guard.py": ("l3_bash_guard.py",
                         {"tool_name": "Bash",
                          "tool_input": {"command": _CANARY_CMD}}),
    # l3_common 不是守卫本身，但 deny() 住在里面：把它的 deny 改成不退出，
    # 每一条规则就同时失效，而文件大小几乎没变。
    "l3_common.py": ("l3_bash_guard.py",
                     {"tool_name": "Bash",
                      "tool_input": {"command": _CANARY_CMD}}),
    "l3_content_guard.py": ("l3_content_guard.py",
                            {"tool_name": "Write",
                             "tool_input": {
                                 "file_path": os.path.join(HOME, ".claude",
                                                           "CLAUDE.md"),
                                 "content": "x"}}),
}


def check_guard_still_denies(key, path, content):
    """把改动后的内容落到临时副本，喂一条金丝雀，看它还拦不拦。

    **文本判据测不出精准破坏。** 把 bash 守卫的主循环从
    `for toks in statements(raw):` 改成 `for toks in []:` 只动 13 个字节——
    大小是原来的 99.9%（过得了 GUARD_SHRINK_FLOOR）、`deny(` 一个没少
    （过得了 GUARD_NEUTERED），而守卫从此一条都不拦。
    把 l3_common 里 deny() 的 `sys.exit(2)` 改成 `return` 同理。
    2026-09-15 实测这两种写法在加这条检查之前都是零阻力的。

    所以这里换一种判据：**有效性只能用行为证明**。整个 hooks 目录复制到
    临时目录，用提议的新内容替换目标文件，再跑一条本该被拦下的命令。
    真实文件一个字节都不碰。

    全程 fail-open：复制失败、超时、解释器找不到——任何一种都直接返回。
    金丝雀自己出问题不该挡住正常的守卫维护。
    """
    spec = _CANARY.get(os.path.basename(key))
    if spec is None:
        return
    entry, payload = spec
    tmp, blocked = None, None
    try:
        tmp = tempfile.mkdtemp(prefix="l3canary-")
        for fn in os.listdir(HOOKS_REAL):
            if fn.endswith(".py"):
                shutil.copy2(os.path.join(HOOKS_REAL, fn),
                             os.path.join(tmp, fn))
        with open(os.path.join(tmp, os.path.basename(key)), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(content)
        proc = subprocess.run(
            [sys.executable, "-S", os.path.join(tmp, entry)],
            input=json.dumps(payload), capture_output=True, text=True,
            timeout=20, env=dict(os.environ, L3_REGRESSION="1"))
        blocked = proc.returncode == 2
    except Exception:
        return          # fail-open
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    # deny 放在 try 外面：它靠 SystemExit 表达判定，写在 try 里会被
    # 上面那个 except 之外的任何清理逻辑搅乱，也更难读。
    if blocked is False:
        deny("GUARD_INEFFECTIVE",
             "改完之后这个守卫不再拦截本该拦下的操作——用改动后的内容跑了一条"
             "金丝雀命令，它放行了。大小和 deny() 调用看着都正常，所以这不是"
             "截断也不是删空，而是逻辑被改坏了（比如主循环空转、deny 不再 exit 2）。"
             "**守卫解析正常但什么都不拦，是最坏的状态**：所有健康检查都报绿。"
             "如果这次改动确实要动判定逻辑，先跑 l3_regression.py 让它证明还有效。")


def post_edit_content(ti, path):
    """Apply the proposed Edit in memory so whole-file checks can run on the
    result. Returns None when the outcome cannot be determined."""
    old = ti.get("old_string")
    new = ti.get("new_string")
    if old is None or new is None:
        return None
    try:
        current = open(path, encoding="utf-8").read()
    except Exception:
        return None
    if old not in current:
        return None  # the Edit will fail on its own; not this guard's business
    if ti.get("replace_all"):
        return current.replace(old, new)
    return current.replace(old, new, 1)


def check_whole_file(key, path, text, how):
    """Truncation + JSON validity, on whatever the file will contain afterwards."""
    if key in PROTECTED:
        floor = PROTECTED[key]
        size = len(text.encode("utf-8", "ignore"))
        if size < floor:
            deny("CONFIG_TRUNCATION",
                 "Refusing to shrink %s to %d bytes (floor %d) via %s. This file has "
                 "been silently reset to a stub before -- if the shrink is intended, "
                 "say so explicitly." % (os.path.basename(path), size, floor, how))
    if key.endswith(".json"):
        try:
            json.loads(text)
        except Exception as exc:
            deny("JSON_INVALID",
                 "%s would not be valid JSON after this %s (%s). A malformed "
                 "settings/config file is ignored silently -- fix the syntax first."
                 % (os.path.basename(path), how, str(exc)[:120]))


SETTINGS_KEY = n(os.path.join(HOME, ".claude", "settings.json"))


def check_wiring_intact(key, path, text):
    """Renaming "hooks" to "hooks_disabled" leaves valid JSON of almost exactly
    the same size, so neither the syntax check nor the truncation floor notices
    -- and the client strips the non-standard key on restart, taking the only
    copy of the wiring with it. Only NEWLY missing guards are refused, so this
    still allows work on a machine whose wiring was already incomplete."""
    if key != SETTINGS_KEY:
        return
    try:
        after = json.loads(text)
    except Exception:
        return  # JSON_INVALID already spoke
    try:
        with open(path, encoding="utf-8") as fh:
            before = json.load(fh)
    except Exception:
        return
    was = set(missing_wiring(before.get("hooks")))
    lost = [g for g in missing_wiring(after.get("hooks")) if g not in was]
    if lost:
        deny("WIRING_LOSS",
             "This change disconnects %s from settings.json. The L3 layer fails "
             "silently when unwired -- no error, just a machine that stops "
             "enforcing its own rules." % ", ".join(sorted(lost)))


# Files whose whole point is to hold a secret. Matched on the FILENAME, not on
# the path: v4 tested `"credentials" in path`, which exempted every document
# that merely discussed credentials -- docs/credentials-guide.md included.
_SECRET_HOME = re.compile(
    r"^\.env$|^\.env\.[A-Za-z0-9_.-]+$|^\.credentials\.json$"
    r"|^\.netrc$|^\.npmrc$|\.secret$|^keyring\b"
)


def decide(event):
    """判定一次内容面写入。拦截靠 deny() 抛 SystemExit 表达；正常返回即放行。

    从 main() 里拆出来，是为了让误报扫描能在**进程内**复用同一套判定。
    内容面此前从来没做过真实语料的误报扫描——bash 面有 guard_fp_sweep，
    内容面一条对应的都没有，新规则全靠手写用例把关，
    而手写用例只覆盖得到想得出的场景，这正是 bash 面栽过跟头的地方。

    spawn 一个进程判一条、几百条历史调用就是几百次进程启动，在 Windows 上
    慢到没人愿意跑——**而没人跑的检查等于不存在**。
    """
    tool = event.get("tool_name") or ""
    ti = event.get("tool_input") or {}
    path = ti.get("file_path") or ti.get("notebook_path") or ""
    if not path:
        return
    key = n(path)

    content = ti.get("content")
    is_write = tool == "Write" and content is not None

    if is_write:
        if is_guard_file(key):
            check_guard_selfharm(key, path, content)
            check_guard_still_denies(key, path, content)
        check_whole_file(key, path, content, "write")
        check_wiring_intact(key, path, content)
        body = content
    else:
        # NotebookEdit carries `new_source`, not `new_string`. v4 read only the
        # latter, so notebook cells were never inspected at all.
        body = ti.get("new_string") or ti.get("new_source") or ""
        # 守卫文件必须和 PROTECTED / .json 一样走 post-edit 检查。
        # 本文件开头那段话说的正是这件事——"Write 拒绝的破坏可以一次一个 Edit
        # 地做到"——而 v5 只给 PROTECTED 和 .json 修了，守卫自己漏在外面：
        # 2026-09-15 实测，用 Edit 把 bash 守卫的主循环改成空迭代零阻力通过。
        if tool == "Edit" and (key in PROTECTED or key.endswith(".json")
                               or is_guard_file(key)):
            after = post_edit_content(ti, path)
            if after is not None:
                if is_guard_file(key):
                    check_guard_selfharm(key, path, after)
                    check_guard_still_denies(key, path, after)
                check_whole_file(key, path, after, "edit")
                check_wiring_intact(key, path, after)

    if SECRET_RE.search(body or ""):
        if not _SECRET_HOME.search(os.path.basename(key)):
            deny("SECRET_PLAINTEXT",
                 "A live credential literal is being written into %s. Use an env var "
                 "or a secret store instead." % os.path.basename(path))


def main():
    decide(read_event())
    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # Fail OPEN. A crashing guard must never wedge every write.
        sys.exit(0)
