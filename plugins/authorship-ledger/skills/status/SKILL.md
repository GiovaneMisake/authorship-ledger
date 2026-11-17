---
name: status
description: Show where the authorship ledger is stored and how many prompts, sessions and anchors it holds. Use when the user asks if their prompts are being recorded or where the record is.
allowed-tools: Bash(node:*)
---

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/ledger.js" status
```

Summarize the output for the user in one short paragraph, in their language. If the ledger has not been created yet, explain that it is created automatically on the next prompt they send in this project.
