---
name: attribution
description: Show which project files Claude changed — through its file tools or through shell commands — and whether each one is still exactly as Claude's last recorded change left it or was changed afterwards, plus since when AI activity has been tracked. Use when the user wants to separate their own hands-on work from AI-written code, e.g. for a copyright registration, a client, or an authorship dispute.
allowed-tools: Bash(node:*)
---

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/ledger.js" attribution
```

Explain the result to the user in their language:

- **Coverage first.** Say since when tracking has been active, how many prompts came before that, and in which sessions it was off. Changes from those periods are unknown.
- **Identical to Claude's last recorded change.** The current file is exactly what Claude left, line endings aside. The output says whether that change came from a file tool or a shell command.
- **Changed after Claude's last recorded change.** Something other than Claude's recorded changes altered the file afterwards: the user, a formatter, another tool or another person. Suggest `git log -p -- <file>` to show who changed what and when.
- **Files with no change by Claude recorded.** These are only that. They are not proof of human authorship: they include anything from before tracking, generated or vendored files, other tools and other people's commits.

Always pass on the caveat the command prints. This is supporting evidence to read together with git history, not proof of who wrote what.
