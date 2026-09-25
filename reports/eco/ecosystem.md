# 🧭 生态表

> 每日热点日报的"关系"一栏、每周生态评估的去重判断都对照这张表。由每周生态评估任务维护，**不超过 12 行**，超出时淘汰价值最低的一行并在当周周报里说明。
> 初版建于 2026-09-25（UTC），只收录仓库内报告（`reports/eco/2026-09-25.md`、`reports/trending/2026-09-25.md`）里有据可查的条目。Star 取自 2026-09-25 GitHub Trending 抓取。
> 本机 `~/.claude/CLAUDE.md` 生态表里的其他条目，云端会话看不到，需要本机补录。

| # | 项目 | Star | 一句话 | 与本机配置的关系 | 结论 |
|---|------|------|--------|-----------------|------|
| 1 | [obra/superpowers](https://github.com/obra/superpowers) | 291.4K | Agent 技能框架 + 开发方法论 | 已在用（方法论） | 已在用 |
| 2 | [affaan-m/ECC](https://github.com/affaan-m/ECC) | 267.1K | Agent harness 优化系统（技能、记忆、安全） | 已在用（武器库） | 已在用 |
| 3 | [alibaba/open-code-review](https://github.com/alibaba/open-code-review) | 41.0K | 规则 + LLM 混合的代码审查 | 现有配置没有 PR 审查工具，填补空白 | 接入（只写了方案，未安装） |
| 4 | [vectorize-io/hindsight](https://github.com/vectorize-io/hindsight) | 28.4K | 会学习的 Agent 长期记忆，自带 MCP | 与 `claude-mem` 部分重叠 | 观望 |
| 5 | [akitaonrails/ai-memory](https://github.com/akitaonrails/ai-memory) | 8.4K | Claude Code ↔ Codex 跨 CLI 共享记忆 | 与 `claude-mem` 部分重叠，但能跨厂商 | 观望 |
| 6 | [Fission-AI/OpenSpec](https://github.com/Fission-AI/OpenSpec) | 70.3K | 规格驱动开发（SDD） | 与 CLAUDE.md 的"理解确认门禁"理念重叠 | 观望 |
| 7 | [superdesigndev/treg](https://github.com/superdesigndev/treg) | 3.3K | Agent 工具的统一 API 代理 | 与 MCP Hub 部分重叠；`curl \| sh` 安装、第三方经手凭据 | 不需要 |
