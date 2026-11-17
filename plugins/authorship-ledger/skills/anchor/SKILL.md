---
name: anchor
description: Anchor the current state of the authorship ledger to an external, trusted timestamp — writes a snapshot of the chain head and, if the OpenTimestamps client is installed, stamps it on the Bitcoin blockchain. Use when the user wants proof of the date their prompts existed, before sharing/publishing work, or at milestones.
allowed-tools: Bash(node:*) Bash(git status:*) Bash(git add:*)
---

1. Run:

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/ledger.js" anchor
   ```

2. Report the snapshot path and head hash. If an `.ots` proof was created, explain that it becomes fully verifiable after a few hours (`ots upgrade <file>.ots`, then `ots verify <file>.ots`).

3. If no proof was created, offer the free options the script printed (install `opentimestamps-client` with pip, or upload the `.txt` at opentimestamps.org).

4. Suggest committing `.authorship/` so the snapshot is also in git history; you may `git add .authorship` but **ask the user before committing or pushing**.
