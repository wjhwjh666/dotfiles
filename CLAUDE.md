# CLAUDE.md — dotfiles 仓库声明

## 📌 唯一存储仓库声明

**`wjhwjh666/dotfiles` 是本机（Win11）唯一的 Git 存储仓库。**

- 本机所有需要 Git 的存储操作（配置备份、报告、脚本、文档）一律提交到本仓库，不再新建其他仓库。
- 本机克隆路径：`%USERPROFILE%\dotfiles`（Git Bash：`~/dotfiles`）。
- 用户主目录 `%USERPROFILE%` **不是** Git 仓库。不要在 `~` 下执行 `git init`，也不要把整个 `~/.claude`、`~/.local` 提交进来。
- 时间一律按 UTC 记录（提交时间、报告日期），不暴露本机时区与地理位置。本机需设置用户环境变量 `TZ=UTC0`，提交时间才会是 `+0000`；校验命令：`git log -1 --format=%ad --date=iso`，结尾应为 `+0000`。
- 2026-09-25 起生效。原仓库 `wjhwjh666/---` 因会话记录中泄露 `sk-` 密钥，已删除。

## 📁 目录约定

| 目录/文件 | 存放内容 |
|-----------|---------|
| 根目录 `.ruff.toml` `.prettierrc.json` `eslint.config.js` | 全局格式化 / lint 配置 |
| 根目录 `vscode-*.json` | VS Code 设置与扩展清单 |
| `reports/trending/YYYY-MM-DD.md` | GitHub 热点简报 |
| `reports/inspect/YYYY-MM-DD.md` | 仓库 / 本机巡检报告 |
| `reports/eco/YYYY-MM-DD.md` | 生态扩充周报 |
| `claude/` | 需要备份的 Claude Code 配置（**只放手工挑选的文件**，比如 CLAUDE.md、hooks、skills） |
| `scripts/` | 本机工具脚本 |

日期一律用 UTC。

## 🔀 Git 规则

| 操作 | 规则 |
|------|------|
| 新建分支、commit、push | ✅ 允许，分支名用 `claude/<主题>` |
| 开 PR | ✅ 一律开 **draft PR**，由用户审核合并 |
| 直接推送 `master` | ❌ 禁止 |
| `--force` / `reset --hard` / 改写历史 | ❌ 禁止（用户明确要求时除外） |
| 删除分支、删除仓库 | ❌ 禁止，由用户本人操作 |

## 🔐 密钥红线（提交前必查）

1. **禁止提交**：API Key（`sk-*`、`ghp_*`、`github_pat_*`）、私钥、`.credentials.json`、`auth.json`、`settings.json`，以及会话记录（`projects/`、`*.jsonl`、`file-history/`）。`.gitignore` 已拦截这些，**不得用 `git add -f` 绕过**。
2. **提交前自动拦截**：`scripts/hooks/pre-commit` 在每次 commit 时检查三项，任一命中即阻止提交：
   - 新增内容含疑似密钥
   - 新增内容含本地时区或位置信息
   - 提交时区不是 `+0000`

   每个 clone 启用一次：`git config core.hooksPath scripts/hooks`。**禁止用 `--no-verify` 绕过。**
3. 报告里出现密钥时，最多保留前 4 位，其余打码。
4. 密钥一律用 `$ENV_VAR` 引用，不写进代码。
