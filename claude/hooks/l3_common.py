"""L3 guard shared library (v5).

Protocol facts this file encodes -- do not "simplify" them away:
  * PreToolUse blocks with stdout JSON + exit code 2. exit 3 is a non-blocking
    error and will NOT stop the tool call.
  * Input arrives as JSON on stdin, never as argv.
  * No jq on this machine, so everything stays in the stdlib.
"""

import json
import os
import re
import sys

HOME = os.path.expanduser("~")
CLAUDE_DIR = os.path.join(HOME, ".claude")
SENTINEL_DIR = os.path.join(CLAUDE_DIR, "sentinels")
LOG_PATH = os.path.join(CLAUDE_DIR, "logs", "l3-guard.log")


# --- guard wiring ------------------------------------------------------------
# Which guard must be reachable from which event. Matched by script name inside
# the hook entry, never by a marker key -- the client strips non-standard keys
# from settings.json on restart, which is how __RTK_HOOK__ disappeared.
# Defined here so the session self-check and the content guard cannot drift
# apart about what "wired up" means.
EXPECTED_WIRING = {
    "PreToolUse": ("l3_bash_guard.py", "l3_content_guard.py"),
    "SessionStart": ("l3_selfcheck.py",),
    "UserPromptSubmit": ("l3_rule_inject.py",),
    "Stop": ("l3_stop_gate.py",),
}


def missing_wiring(hooks):
    """Guards that EXPECTED_WIRING demands but the given hooks block lacks."""
    gaps = []
    for event, guards in EXPECTED_WIRING.items():
        blob = json.dumps((hooks or {}).get(event) or [], ensure_ascii=False)
        blob = blob.replace("\\\\", "/")
        for guard in guards:
            if guard not in blob:
                gaps.append("%s/%s" % (event, guard))
    return gaps


# --- credential shapes -------------------------------------------------------
# One definition, imported by both guards. Two private copies had already
# drifted: the shell guard and the content guard disagreed about what counts as
# a secret, so the same key was refused on the network and waved through into a
# source file.
SECRET_RE = re.compile(
    r"sk-ant-[A-Za-z0-9_\-]{20,}"          # Anthropic
    r"|sk-proj-[A-Za-z0-9_\-]{20,}"        # OpenAI project
    r"|gh[pousr]_[A-Za-z0-9]{30,}"         # GitHub
    r"|AKIA[0-9A-Z]{16}"                   # AWS access key id
    r"|AIza[0-9A-Za-z_\-]{30,}"            # Google
    r"|xox[baprs]-[0-9A-Za-z\-]{20,}"      # Slack
    r"|hf_[A-Za-z0-9]{30,}"                # Hugging Face
    r"|gsk_[A-Za-z0-9]{40,}"               # Groq
    r"|xai-[A-Za-z0-9]{40,}"               # xAI
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"  # any PEM private key block
)


def read_event():
    """Parse the hook payload from stdin. Never raises -- a guard that dies on
    malformed input would fail closed on every single tool call."""
    try:
        raw = sys.stdin.read()
    except Exception:
        return {}
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def log(tag, message):
    # The regression suite fires every deny rule on purpose. Letting those
    # runs append to l3-guard.log would make a real incident indistinguishable
    # from a test pass when someone reads the log later.
    if os.environ.get("L3_REGRESSION") == "1":
        return
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write("[%s] %s\n" % (tag, message.replace("\n", " ")))
    except Exception:
        pass


def deny(tag, reason):
    """Block the tool call. stdout JSON + exit 2 is the only shape that works."""
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "L3-%s | %s" % (tag, reason),
        }
    }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.flush()
    log("DENY/" + tag, reason)
    sys.exit(2)


def allow():
    sys.exit(0)


# --- 守卫有效性的行为判据 -----------------------------------------------------
# 拼出来的：完整字面量留在这个文件里，会让「用 bash 编辑本文件」的命令被
# GIT_FORCE_PUSH 拦下。
_CANARY_CMD = "git push --" + "force origin main"


def guard_canary_passes(timeout=20):
    """跑一条本该被拦的命令，问 bash 守卫还拦不拦。

    返回 True（还拦）/ False（不拦了）/ None（判断不了，调用方按 fail-open 处理）。

    **「语法没坏」「文件还在」都不等于「还拦得住」。** 把主循环
    `for toks in statements(raw):` 改成 `for toks in []:` 只动十几个字节，
    语法合法、大小几乎不变、`deny(` 一个没少——而守卫从此零拦截，
    所有文本判据一律报绿。有效性只能用行为证明。

    放在这里是因为**有三个时机都要问这个问题**，各写一份必然漂移：
      * SessionStart（l3_selfcheck）—— 会话开始时确认守卫真的活着；
      * Stop（l3_stop_gate）—— 回合结束时看磁盘最终状态，入口无关；
      * 编辑守卫文件时（l3_content_guard）—— 那一处判的是「改动后的内容」，
        需要临时副本，所以它有自己的实现，不走这个函数。
    """
    import subprocess
    guard = os.path.join(CLAUDE_DIR, "hooks", "l3_bash_guard.py")
    if not os.path.isfile(guard):
        return None
    try:
        proc = subprocess.run(
            [sys.executable, "-S", guard],   # 同 settings.json：省 ~300ms
            input=json.dumps({"tool_name": "Bash",
                              "tool_input": {"command": _CANARY_CMD}}),
            capture_output=True, text=True, timeout=timeout,
            env=dict(os.environ, L3_REGRESSION="1"))
    except Exception:
        return None
    return proc.returncode == 2


# --- statement-boundary splitting -------------------------------------------
# v1/v2 used naive substring matching and shot themselves: `rg -n "curl|Auto"
# settings.json` was read as secret exfiltration because the *search pattern*
# contained "curl". A dangerous verb only counts when it starts a statement.

_SPLIT = re.compile(r"(?:\|\||&&|[;|&\n])")


def statements(command):
    """Split a shell command into statements and return each one's token list."""
    out = []
    for chunk in _SPLIT.split(command or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        # strip leading env assignments and `sudo`/`time`-style prefixes
        toks = chunk.split()
        while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0])
                        or toks[0] in ("sudo", "time", "nohup", "command", "exec")):
            toks.pop(0)
        if toks:
            out.append(toks)
    return out


def head_is(toks, *names):
    """True when the statement's executable is one of `names` (path-insensitive)."""
    if not toks:
        return False
    exe = toks[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if exe.endswith(suffix):
            exe = exe[: -len(suffix)]
    return exe in names


def has_flag(toks, *flags):
    return any(t in flags for t in toks[1:])
