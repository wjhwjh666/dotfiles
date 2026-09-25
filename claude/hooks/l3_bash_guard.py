"""L3 shell guard (v5) -- PreToolUse on Bash / PowerShell.

Blocks irreversible shell operations. Every check matches at STATEMENT
BOUNDARIES only (see l3_common.statements) because the v2 substring matcher
produced false positives that were worse than the misses.

v5 came out of a bypass audit that asked, for each rule, "what OTHER spellings
reach the same effect" rather than "does this rule fire". 18 of 37 candidate
bypasses ran unblocked, including two that replay this machine's own history:
`rm -rf ~/.claude/*` (deletes the guards themselves) and PowerShell's
`Remove-ItemProperty` on HKLM PATH (the wipe that broke every cmd-based MCP
server -- the rule existed, but knew only the `reg delete` spelling).

The surfaces that had been missing entirely, each its own category:
  * interpreters     python -c / node -e / powershell [IO.File] read any file
  * encoders         certutil -encode prints a secret without naming a reader
  * archivers        tar -czf ~/.ssh/ takes the whole key directory
  * redirection      `< path` reads with no reader at the head of the statement
  * variables        $HOME and %USERPROFILE% resolve to a protected root
  * globs            `X/*` empties X with the same blast radius as deleting it
  * exec escapes     find -delete, rg --pre, sed -i and friends are approved as
                     "searching" by settings.json yet execute or overwrite
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from l3_common import (  # noqa: E402
    SECRET_RE,
    allow,
    deny,
    has_flag,
    head_is,
    read_event,
    statements,
)

HOME = os.path.expanduser("~").replace("\\", "/").lower()

# Paths that must never be the target of a recursive delete.
CRITICAL_ROOTS = {
    "/", "/*", "c:", "c:/", "c:/*", "c:/windows", "c:/users",
    HOME, HOME + "/", HOME + "/.claude", HOME + "/.claude/",
    HOME + "/desktop", HOME + "/documents",
}

# Upload-shaped flags. A bare GET is harmless; a POST with a body is exfiltration.
UPLOAD_FLAGS = {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
                "-F", "--form", "-T", "--upload-file", "--post-file", "--post-data"}


# `rm -rf "$HOME"` and `rm -rf %USERPROFILE%` reach the same directory as
# `rm -rf ~`, but the literal token matches no protected root until the variable
# is resolved. The shell would expand it; the guard has to as well.
_HOME_VAR = re.compile(r"\$\{?(?:HOME|USERPROFILE)\}?|%USERPROFILE%", re.I)


def norm(p):
    p = (p or "").strip().strip('"').strip("'")
    p = _HOME_VAR.sub(HOME, p)
    p = os.path.expanduser(p)
    p = p.replace("\\", "/").lower()
    # `rm -rf X/*` empties X. Same blast radius as deleting X, so it has to
    # compare against the same protected-root list.
    p = re.sub(r"/\*+$", "", p)
    return p.rstrip("/") or "/"


# `/s`, `/q`, `/f` are cmd-style switches; `/` and `/etc` are paths. Only the
# short alphabetic form is a switch -- treating every "/..." token as a switch
# is what let `rm -rf /` through in v4.0.
_CMD_SWITCH = re.compile(r"^/[a-zA-Z]{1,3}$")


# Global git options that consume the NEXT token as their value. Skipping the
# flag but not its value is how `git -C <path> push --force` slipped through:
# the path was read as the subcommand and the push rules never fired.
_GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                   "--exec-path", "--config-env"}


def git_subcommand(toks):
    """First non-option token after git's global options, or ''."""
    i = 1
    while i < len(toks):
        t = toks[i]
        if t in _GIT_VALUE_OPTS:
            i += 2          # skip the flag AND the value it eats
            continue
        if t.startswith("-"):
            i += 1          # `--git-dir=x` and bare switches carry their own value
            continue
        return t
    return ""


def check_git(toks):
    if not head_is(toks, "git"):
        return
    sub = git_subcommand(toks)

    if sub == "push" and has_flag(toks, "-f", "--force"):
        deny("GIT_FORCE_PUSH",
             "git push --force overwrites remote history irreversibly. "
             "Use --force-with-lease, or ask the user first.")
    if sub == "push" and any(t.startswith("+") and len(t) > 1 for t in toks[2:]):
        deny("GIT_FORCE_PUSH",
             "A leading `+` on a refspec is a force push in disguise -- it "
             "overwrites remote history exactly like --force does.")
    if sub == "reset" and has_flag(toks, "--hard"):
        deny("GIT_RESET_HARD",
             "git reset --hard discards uncommitted work with no recovery path. "
             "Stash or commit first.")
    if sub == "clean" and any(re.match(r"^-[a-z]*[fd]", t) for t in toks[2:]):
        deny("GIT_CLEAN",
             "git clean -fd permanently deletes untracked files. "
             "Run `git clean -n` first and show the user what would go.")
    if sub == "checkout" and "--" in toks:
        deny("GIT_CHECKOUT_DISCARD",
             "git checkout -- <path> discards working-tree changes irreversibly.")


def check_delete(toks):
    recursive_force = False
    if head_is(toks, "rm"):
        joined = " ".join(toks[1:])
        recursive_force = bool(re.search(r"-[a-zA-Z]*r", joined)) and \
            bool(re.search(r"-[a-zA-Z]*f", joined))
    elif head_is(toks, "remove-item", "ri", "rd", "rmdir", "del", "erase"):
        recursive_force = has_flag(toks, "-Recurse", "-recurse", "/s", "-r")
    if not recursive_force:
        return
    for t in toks[1:]:
        if t.startswith("-") or _CMD_SWITCH.match(t):
            continue
        if norm(t) in CRITICAL_ROOTS:
            deny("RM_CRITICAL_ROOT",
                 "Recursive force-delete targets a protected root (%s). Refused." % t)


_INFO_FLAGS = {"--version", "-V", "--help", "-h", "--usage"}


def check_disk(toks):
    # `mkfs.ext4 --version` 打印版本号就退出。把它当成格式化磁盘，
    # 只会教人忽略这条规则。
    if any(t in _INFO_FLAGS for t in toks[1:]):
        return
    # mkfs ships as mkfs.ext4 / mkfs.xfs / mkfs.vfat. head_is only strips Windows
    # executable suffixes, so the filesystem-specific forms need their own match.
    exe = toks[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if head_is(toks, "format", "mkfs", "diskpart", "fdisk", "clear-disk",
               "initialize-disk") or exe.startswith("mkfs."):
        deny("DISK_DESTRUCTIVE",
             "Disk formatting / partitioning is never an in-session action.")
    if head_is(toks, "wmic") and any(t.lower() == "delete" for t in toks[1:]):
        deny("DISK_DESTRUCTIVE",
             "wmic ... delete removes volumes and disk objects irreversibly.")


# --- registry ----------------------------------------------------------------
# v4 only knew the `reg delete` spelling. The incident this rule exists for --
# a wiped HKLM PATH that made every cmd-based MCP server fail to spawn -- is
# just as reachable from PowerShell, where the hive is a PSDrive and the verb is
# Remove-Item / Remove-ItemProperty.
_REG_HIVE = re.compile(r"^hk(?:lm|cu|cr|u|cc|ey_)", re.I)

_REG_REMOVERS = ("remove-item", "ri", "rd", "remove-itemproperty", "rp",
                 "clear-itemproperty", "clp", "clear-item", "cli",
                 "set-itemproperty", "sp")


def check_registry(toks):
    if head_is(toks, "reg") and toks[1:2] and toks[1].lower() == "delete":
        deny("REGISTRY_DELETE",
             "Registry deletion is out of scope for a coding session. "
             "A wiped HKLM PATH has already broken this machine once.")
    if not head_is(toks, *_REG_REMOVERS):
        return
    for t in toks[1:]:
        if _REG_HIVE.match(t.strip('"').strip("'")):
            deny("REGISTRY_DELETE",
                 "%s targets the registry (%s). Registry edits are out of scope "
                 "for a coding session -- a wiped HKLM PATH has already broken "
                 "this machine once." % (toks[0], t))


# --- execution hiding inside a "read-only" command ----------------------------
# Everything below is auto-approved by settings.json as searching/sorting. One
# flag turns each of them into arbitrary execution or an arbitrary overwrite.
# Verified 2026-09-15: all 13 spellings ran with no prompt.

# 无条件拦：这几个要么就是删除，要么就是往任意路径写文件。
_FIND_EXEC = {"-delete", "-fprintf", "-fprint", "-fprint0", "-fls"}

# `-exec` 本身只是"对每个结果跑点什么"，危险与否全看跑的是什么。
# `find . -type l -exec ls -ld {} \;` 是查看符号链接的标准写法，是只读的；
# 一刀切拦 -exec 等于拦掉 find 最常用的搭配，而那种规则活不过一周。
_FIND_RUNNERS = ("-exec", "-execdir", "-ok", "-okdir")

_SAFE_EXEC_CMD = {
    "ls", "cat", "head", "tail", "file", "stat", "wc", "echo", "printf",
    "grep", "egrep", "fgrep", "rg", "basename", "dirname", "realpath",
    "readlink", "du", "cmp", "diff", "md5sum", "sha1sum", "sha256sum",
    "identify", "exiftool", "true", "test",
}

# ripgrep runs --pre as a preprocessor for every file it opens.
_RG_EXEC = {"--pre", "--hostname-bin"}

_TAR_EXEC = {"--checkpoint-action", "--to-command", "--use-compress-program",
             "--rsh-command", "-I"}

_SORT_WRITE = {"-o", "--output"}

# `sed -i` 曾经在这里，2026-09-15 移除：真实语料里它是最常见的编辑手段之一，
# 而它做的是"原地写"不是"执行"。shell 里的写入不归本守卫管，写坏了由 stop gate
# 在回合结束时抓。留在这里只会让守卫在日常工作上叫。

# GNU sed's `e` command shells out and its `w` flag writes a file, both from
# inside the script argument where no flag scan can see them.
#   sed -n '1e whoami'            -> executes
#   sed -n 's/a/b/w /etc/hosts'   -> writes
# Matched narrowly: an `e` only counts right after an address, and a `w` only
# when it closes a substitution and is followed by a path. `sed -n '/error/p'`
# and `sed -n '10,20p'` must stay clean, and there are regression cases for both.
# A quote opens a script argument, so it counts as a command position too --
# `sed -n '1e whoami'` puts the `e` right after the quote, not after a `;`.
# `w` 分支 2026-09-15 移除：它只是写文件，和 `sed -i` 同理，不归本守卫管。
# 留下的 `e` 是真正的 shell 调用。
_SED_SCRIPT = re.compile(r"(?:^|[;{'\"])\s*\d*(?:,\s*\S+)?\s*e(?:\s|$)")


def _escape(tool, flag, alternative):
    deny("EXEC_ESCAPE",
         "`%s %s` is not the read-only operation the permission rule assumes -- "
         "it executes or overwrites, and settings.json auto-approves every `%s` "
         "call as searching. If that is genuinely what you want, run %s instead: "
         "it is not on the allow-list, so it goes through the normal "
         "confirmation." % (tool, flag, tool, alternative))


def check_exec_escape(toks):
    if head_is(toks, "find"):
        for i, t in enumerate(toks[1:], 1):
            if t in _FIND_EXEC:
                _escape("find", t,
                        "`find ... -print0 | xargs -0 <command>`, "
                        "after showing the user what `find ... -print` lists")
            if t in _FIND_RUNNERS:
                prog = (toks[i + 1] if i + 1 < len(toks) else "")
                prog = prog.replace("\\", "/").rsplit("/", 1)[-1].lower()
                for suffix in (".exe", ".cmd", ".bat"):
                    if prog.endswith(suffix):
                        prog = prog[: -len(suffix)]
                if prog and prog not in _SAFE_EXEC_CMD:
                    _escape("find", "%s %s" % (t, prog),
                            "`find ... -print0 | xargs -0 %s`, after showing the "
                            "user what `find ... -print` lists" % prog)
    elif head_is(toks, "rg"):
        for t in toks[1:]:
            if t in _RG_EXEC or any(t.startswith(f + "=") for f in _RG_EXEC):
                _escape("rg", t.split("=")[0],
                        "the preprocessor as its own command, piped into rg")
    elif head_is(toks, "tar"):
        for t in toks[1:]:
            if t in _TAR_EXEC or any(t.startswith(f + "=") for f in _TAR_EXEC):
                _escape("tar", t.split("=")[0], "the program as its own command")
    elif head_is(toks, "sort"):
        for t in toks[1:]:
            if t in _SORT_WRITE:
                _escape("sort", t,
                        "`sort ... > file` so the redirection is visible")
    elif head_is(toks, "sed"):
        script = " ".join(t for t in toks[1:] if not t.startswith("-"))
        if _SED_SCRIPT.search(script):
            _escape("sed", "an `e` command inside the script",
                    "the command spelled out on its own line")


# --- 强杀进程 ---------------------------------------------------------------
# CLAUDE.md 第 4 节：「禁止强杀进程来"解决"问题，那是掩盖不是修复。」
# 在 2026-09-15 之前这纯粹是纸面约束——真实语料里 51 次强杀，零拦截。
#
# 这条规则有具体的出处。本机曾用 `Stop-Process -Force` 杀 Docker 并中途
# `wsl --shutdown`，打断了跨发行版挂载命名空间的建立，**产生了一个只能靠重启
# 才能修的新故障**；而当时以为要解决的那个僵死 socket，实测走
# `docker desktop stop` 优雅停止照样产生。既造了新故障，又没解决老问题。
#
# 拦的是"强杀"这个动作本身，不是"结束进程"。不带 -Force / /F 的优雅停止照常放行。

_FORCE_FLAGS = {"-force", "/f", "//f", "-f"}

# 基础设施进程：强杀它们会波及到这次会话之外的东西。语料里那条杀 docker 的命令
# 就是本机"只能重启才能修"那次故障的起点。
#
# 反过来，自己启动的解释器进程（python / node / pythonw）不在这里：
# 重启脚本前清掉旧实例是常规操作，拦它纯属添乱——真实语料里 40 多条都是这个。
_INFRA_PROC = re.compile(
    r"docker|wsl|vmmem|hyper-?v|vmcompute"
    r"|explorer|dwm|csrss|winlogon|wininit|services\.exe|lsass|smss|svchost"
    r"|msmpeng|securityhealth|sqlservr|postgres|mysqld|mongod|redis-server"
    r"|nginx|httpd|sshd", re.I)


# 从 kill 命令里摘出"要杀谁"。`-Id 123` 这类按 PID 杀的取不到名字，
# 于是放行——按 PID 杀的基本都是自己刚启动的那个进程。
_KILL_TARGET = re.compile(
    r"Get-Process\s+((?:[\"']?[A-Za-z0-9_.*-]+[\"']?)"
    r"(?:\s*,\s*[\"']?[A-Za-z0-9_.*-]+[\"']?)*)"
    r"|Stop-Process[^|\n]*?-Name\s+([\"']?[A-Za-z0-9_.*-]+[\"']?)"
    r"|taskkill[^|\n]*?/IM\s+(\S+)"
    r"|(?:pkill|killall)\s+(?:-\S+\s+)*(\S+)", re.I)


def check_kill(toks, raw):
    exe = toks[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat"):
        if exe.endswith(suffix):
            exe = exe[: -len(suffix)]

    forced = False
    if exe in ("taskkill", "stop-process", "spps"):
        forced = any(t.lower() in _FORCE_FLAGS for t in toks[1:])
    elif exe in ("kill", "pkill", "killall"):
        # SIGKILL 不给进程任何收尾的机会，等价于 -Force。
        forced = any(t in ("-9", "-KILL", "-SIGKILL") for t in toks[1:])
    if not forced:
        return

    # 只看**要杀的是谁**。目标可能写在本条语句里（taskkill /IM x），
    # 也可能来自上游管道（Get-Process x | Stop-Process -Force），
    # 所以从整条命令里把目标名摘出来——而不是拿整条文本去碰运气。
    # 拿整条文本匹配曾经误拦过一条杀 ChatGPT 的命令，只因同一行里另有
    # explorer.exe 被用作 MSIX 应用的启动器。
    targets = " ".join(g for m in _KILL_TARGET.finditer(raw) for g in m.groups() if g)
    if not _INFRA_PROC.search(targets):
        return

    deny("KILL_FORCE",
         "这是在强杀一个基础设施进程（docker / WSL / 系统服务一类），"
         "不是清理自己起的脚本。强杀是掩盖不是修复（CLAUDE.md 第 4 节），"
         "而且本机有过实例：用 Stop-Process -Force 杀 Docker 并中途 wsl --shutdown，"
         "打断了挂载命名空间的建立，造出一个只能重启才能修的新故障；"
         "原本要解决的僵死 socket，后来实测走优雅停止照样出现——"
         "既造了新故障，又没解决老问题。"
         "先用该服务自己的停止方式（如 docker desktop stop）；"
         "如果确实非强杀不可，把理由说给用户听，由他决定。")


def check_system_security(toks, raw):
    """CLAUDE.md 红线点名的"系统安全设置"。

    这三类在 3,950 条真实语料里出现 0 次——加这条规则的误报风险为零，
    是数据支撑的判断。

    2026-09-15 更正：这里原本还写着"bcdedit 和 service 控制在本机都是合法的
    虚拟化 / WSL 修复操作，故意不列进来"。前半句是错的。给 guard_blindspot
    加上 heredoc 去噪后重新统计，那 13 条 bcdedit 里有 9 条只是 /enum 查询，
    按语句头精确计真正执行 bcdedit 的仅 7 条、带写动词的仅 1 条，
    而那 1 条还是字符串拼接而非直接执行。写操作的真实频次是 0，
    所以它属于"零误报风险"那一类，现由下面的 check_boot_config 拦截。

    后半句仍然成立：service 控制去噪后还有 3 条真命中，全部是
    CoworkVMService / WSL 服务的合法排查，加规则就是纯误报，故意不拦。
    """
    low = raw.lower()
    if any(k in low for k in ("set-mppreference", "add-mppreference",
                              "remove-mppreference")):
        deny("SYSTEM_SECURITY",
             "改 Windows Defender 设置属于 CLAUDE.md 红线里的系统安全设置，"
             "不是编码会话该做的事。")
    if "netsh advfirewall" in low or "new-netfirewallrule" in low \
            or "set-netfirewallprofile" in low:
        deny("SYSTEM_SECURITY",
             "改防火墙规则属于 CLAUDE.md 红线里的系统安全设置。"
             "要开端口请让用户自己操作。")
    if "set-executionpolicy" in low and ("unrestricted" in low or "bypass" in low):
        deny("SYSTEM_SECURITY",
             "把 ExecutionPolicy 放开到 Unrestricted/Bypass 是永久性地降低这台机器"
             "的防护等级。单次运行脚本用 `pwsh -ExecutionPolicy Bypass -File ...`，"
             "只影响那一个进程。")


# 改启动配置的动词。/enum 和 /v 只是查询，不在此列——
# 把读和写混成一条规则，会让本机最常见的用法（查 hypervisorlaunchtype）天天误报，
# 而一条天天误报的规则活不过一周。
_BCD_INDIRECT = None   # 在动词表之后构造，见下方 _build_bcd_indirect()

_BCD_WRITE_VERBS = {
    "/set", "/deletevalue", "/delete", "/create", "/import",
    "/default", "/displayorder", "/bootsequence", "/timeout", "/copy",
}


def _build_bcd_indirect():
    r"""由动词表生成"间接调用"的正则，而不是再手写一份清单。

    两处清单必然漂移：加一个新动词到集合里、忘了加到正则里，
    直接调用拦得住、`cmd /c` 套一层就放行——而两种情况的输出没有区别。
    所以这里从同一个 _BCD_WRITE_VERBS 生成。

    `[^|;&\n]` 让匹配不跨越语句边界：`bcdedit /enum | findstr /set` 里的
    `/set` 在管道另一侧，不该算成写操作。

    动词前面允许的是**空白或引号**，不能只写 `\s`：
    `Start-Process bcdedit -ArgumentList "/set ..."` 里动词紧贴在引号后面，
    只认空白就会漏掉它——而这恰好是本机历史上那次真实写操作的形状。
    第一版就漏在这里，五处盲区补掉四处，剩的就是它。
    """
    verbs = "|".join(sorted(re.escape(v) for v in _BCD_WRITE_VERBS))
    return re.compile(
        r"\bbcdedit(?:\.exe)?\b[^|;&\n]{0,200}?[\s\"'](?:" + verbs + r")\b", re.I)


_BCD_INDIRECT = _build_bcd_indirect()


def check_boot_config(toks, raw):
    """bcdedit 的写操作 —— 改坏了整台机器开不了机。

    加这条规则的依据是数据，不是直觉。guard_blindspot v1 曾统计出
    13 条 bcdedit，据此判定"本机都是合法的虚拟化修复，故意不拦"；
    v2 给统计加上 heredoc 去噪之后，那 13 条里有 9 条只是 /enum 查询，
    按语句头精确计真在执行 bcdedit 的 7 条、带写动词的 1 条，
    且那 1 条是 `$cmd = 'bcdedit /set ...' + $log` 的字符串拼接、
    由提权进程间接执行，并非直接跑。写操作的真实频次是 0。

    所以这条规则和 Defender / 防火墙同级：零误报风险，拦的是整机级后果。

    放行 /enum 是规则的一半，不是漏网：本机排查 WSL / Hyper-V 时
    查 hypervisorlaunchtype 是常规动作，拦它等于逼人把整条规则关掉。
    """
    direct = (head_is(toks, "bcdedit")
              and any(t.lower() in _BCD_WRITE_VERBS for t in toks[1:]))
    # 只看语句头会漏掉全部间接形式，而本机历史上唯一真实发生过的那次
    # bcdedit 写操作，恰恰就是 `Start-Process ... -Verb RunAs` 提权跑的——
    # 也就是说，只认语句头的规则从一开始就拦不住它真正会出现的样子。
    # 2026-09-15 逐形状实测：cmd /c、powershell -Command、pwsh -c、
    # Start-Process（直接或套一层 cmd）五种写法全部放行。
    if not direct and not _BCD_INDIRECT.search(raw):
        return
    deny("BOOT_CONFIG",
         "这是在改 Windows 启动配置（bcdedit 写操作），影响的是整台机器能不能开机，"
         "和 CLAUDE.md 红线里的磁盘分区 / 系统安全设置同级。"
         "查询用 `bcdedit /enum` 照常放行。"
         "套一层 cmd /c、powershell -Command 或 Start-Process 也一样拦——"
         "规则认的是这条命令最终会做什么，不是它写成什么形状。"
         "本机确实有过一次合法场景——修 WSL/Docker 时把 hypervisorlaunchtype 设回 auto——"
         "但那属于要让用户知情并由他决定的操作：把要改哪一项、为什么改说清楚，"
         "让用户自己执行，不要在会话里直接改。")


# 改写远程配置的子命令。查询（`-v`）和 `add` 不在此列：
# add 只是多一个远程，不动现有的那个。
_GIT_REMOTE_WRITE = {"set-" + "url", "remove", "rm", "rename", "set-head"}


def check_git_remote(toks):
    """改远程地址 —— allow 列表零提示放行，后果要到下次 push 才显形。

    `Bash(git remote *)` 在 permissions.allow 里，于是
    `git remote set-url origin <别处>` 一声不响就生效了，
    而下一次 push 会把代码送到那个别处。**出事的时刻和操作的时刻是分开的**，
    这类才最需要在操作那一刻拦一下。

    数据支撑：4,353 条真实语料里这几个子命令出现 0 次，误报风险为零。
    """
    if not head_is(toks, "git"):
        return
    words = [t.lower() for t in toks[1:] if not t.startswith("-")]
    if len(words) >= 2 and words[0] == "remote" and words[1] in _GIT_REMOTE_WRITE:
        deny("GIT_REMOTE_REWRITE",
             "这会改写 git 远程配置（%s）。它在 allow 列表里是零提示放行的，"
             "而改错远程地址不会当场报错——要到下一次 push 把代码送去别处时才发现。"
             "查询用 `git remote -v`、新增用 `git remote add` 都照常放行；"
             "确实要改现有远程的话，把改成什么、为什么改说给用户听，由他决定。"
             % words[1])


def check_exfil(toks, raw):
    if not head_is(toks, "curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"):
        return
    uploading = any(t in UPLOAD_FLAGS for t in toks[1:]) or \
        any(t.startswith("@") for t in toks[1:]) or \
        any(t.lower() in ("-method", "-body", "-infile") for t in toks[1:])
    if uploading and SECRET_RE.search(raw):
        deny("SECRET_EXFIL",
             "A credential-shaped literal is being uploaded to the network. Refused.")


# --- credential reads ---------------------------------------------------------
# settings.json denies Read() on these paths, but that rule only binds the Read
# tool. The `Bash(cat *)` allow rule auto-approves the same read through the
# shell, which would print the secret straight into context. The deny list's
# intent has to be enforced on the shell surface too.

READERS = ("cat", "type", "head", "tail", "more", "less", "nl", "strings",
           "xxd", "od", "base64", "sed", "awk", "grep", "rg", "egrep", "fgrep",
           "cp", "copy", "mv", "move", "get-content", "gc", "select-string",
           "sls", "get-item", "start", "open",
           # v5: encoders, comparers and archivers read a file just as well as
           # `cat` does -- `certutil -encode` was the standard Windows way to
           # print a secret without ever naming a reader the guard knew.
           "certutil", "findstr", "fc", "comp", "dd", "tar", "zip", "unzip",
           "7z", "7za", "compress-archive", "xcopy", "robocopy")

# Anything that takes code on the command line reads files through its own
# runtime, so the path never appears as a bare token -- it sits inside a quoted
# string. For these the whole statement is searched instead.
INTERPRETERS = ("python", "python3", "py", "node", "nodejs", "perl", "ruby",
                "php", "powershell", "pwsh", "deno", "bun", "lua")

_SECRET_PATH = re.compile(
    r"(?:^|/)\.credentials\.json$"
    r"|(?:^|/)\.ssh(?:/|$)"
    r"|(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)"
    r"|(?:^|/)\.aws(?:/|$)"
    r"|(?:^|/)\.gnupg(?:/|$)"
    r"|(?:^|/)\.npmrc$"
    r"|(?:^|/)\.kube/config$"
    r"|(?:^|/)\.docker/config\.json$"
    r"|(?:^|/)hosts\.yml$"
    r"|\.pem$"
    r"|(?:^|/)\.env(?:\.[A-Za-z0-9_.-]+)?$"
)


# Same paths as _SECRET_PATH, but end-anchored on a word boundary instead of
# end-of-token: inside `python -c "open('~/.npmrc')"` the path is followed by a
# quote and a paren, never by the end of an argument.
_SECRET_PATH_INLINE = re.compile(
    r"(?:^|[/\\])\.credentials\.json\b"
    r"|(?:^|[/\\])\.ssh[/\\]"
    r"|(?:^|[/\\])id_(?:rsa|ed25519|ecdsa|dsa)\b"
    r"|(?:^|[/\\])\.aws[/\\]"
    r"|(?:^|[/\\])\.gnupg[/\\]"
    r"|(?:^|[/\\])\.npmrc\b"
    r"|(?:^|[/\\])\.kube[/\\]config\b"
    r"|(?:^|[/\\])\.docker[/\\]config\.json\b"
    r"|\.pem\b"
    r"|(?:^|[/\\])\.env(?:\.[A-Za-z0-9_-]+)?\b"
)

_SECRET_REFUSAL = (
    "%s reads a credential store; settings.json already denies Read() on it. "
    "Pulling it through the shell would print the secret into context. "
    "If the user needs its contents, they open it themselves."
)


def check_interpreter_read(toks):
    """`python -c "open('~/.npmrc').read()"` is a credential read with no reader
    at the head of the statement."""
    if not head_is(toks, *INTERPRETERS):
        return
    stmt = " ".join(toks).replace("\\", "/").lower()
    if _SECRET_PATH_INLINE.search(stmt):
        deny("SECRET_READ", _SECRET_REFUSAL % toks[0])


def check_redirect_read(toks):
    """`while read l; do ...; done < ~/.npmrc` has no reader at the head either
    -- the redirection does the reading."""
    for i, t in enumerate(toks):
        if t == "<":
            cand = toks[i + 1] if i + 1 < len(toks) else ""
        elif t.startswith("<") and not t.startswith("<<") and len(t) > 1:
            cand = t[1:]
        else:
            continue
        if cand and _SECRET_PATH.search(norm(cand)):
            deny("SECRET_READ", _SECRET_REFUSAL % cand)


def check_secret_read(toks):
    if not head_is(toks, *READERS):
        return
    for t in toks[1:]:
        if t.startswith("-") or _CMD_SWITCH.match(t):
            continue
        if _SECRET_PATH.search(norm(t)):
            deny("SECRET_READ",
                 "%s is a credential store; settings.json already denies Read() on it. "
                 "Reading it through the shell would print the secret into context. "
                 "If the user needs its contents, they open it themselves." % t)


# 规则的执行顺序。顺序只决定同时命中时 deny 报哪个 tag，不决定拦不拦，
# 所以这张表的作用是"保持历史输出稳定"，而不是"决定哪些规则生效"。
_ORDERED = (
    "check_git", "check_kill", "check_system_security", "check_exec_escape",
    "check_delete", "check_disk", "check_registry", "check_exfil",
    "check_secret_read", "check_interpreter_read", "check_redirect_read",
)


def _discover_checks():
    """按固定顺序取已知规则，再自动补上任何没列进顺序表的 check_*。

    main 里原本是一张手写的调用清单。BOOT_CONFIG 规则加进文件却漏了那一行，
    结果它存在、被 import、语法检查通过、连 guard_fp_sweep 都自动发现了它，
    唯独真实 hook 路径上一次都没执行过——pipe-test 全部 rc=0 才暴露。

    **"规则写了但没挂上"和"规则不存在"在输出上完全一样。** 这是 CLAUDE.md
    第 5 节第 7 条那个推论的又一个实例（空转和通过分不出来），所以清单不能靠人记：
    新写的 check_* 自动进调度，漏挂这种事从此不可能发生。

    签名有 check_x(toks) 和 check_x(toks, raw) 两种，统一包成两参调用。
    """
    import inspect
    g = globals()
    out, seen = [], set()

    def wrap(name, fn):
        try:
            nargs = len(inspect.signature(fn).parameters)
        except (TypeError, ValueError):
            return None
        if nargs == 1:
            return (name, lambda t, raw, f=fn: f(t))
        if nargs == 2:
            return (name, lambda t, raw, f=fn: f(t, raw))
        return None

    for name in _ORDERED:
        fn = g.get(name)
        if callable(fn):
            item = wrap(name, fn)
            if item:
                out.append(item)
                seen.add(name)
    for name in sorted(g):
        if not name.startswith("check_") or name in seen:
            continue
        fn = g[name]
        if callable(fn):
            item = wrap(name, fn)
            if item:
                out.append(item)
    return out


_CHECKS = _discover_checks()


def main():
    event = read_event()
    ti = event.get("tool_input") or {}
    raw = ti.get("command") or ""
    if not raw.strip():
        allow()

    if SECRET_RE.search(raw) and not any(
        head_is(t, "curl", "wget", "invoke-webrequest", "iwr") for t in statements(raw)
    ):
        # literal secret in a non-network command is a warning, not a block
        pass

    # 每条语句逐一过全部规则；哪条先命中只影响 deny 报的 tag，不影响拦不拦。
    for toks in statements(raw):
        for _name, fn in _CHECKS:
            fn(toks, raw)
    allow()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        # Fail OPEN. A crashing guard must never wedge every shell call.
        sys.exit(0)
