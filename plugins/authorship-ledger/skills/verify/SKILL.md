---
name: verify
description: Verify the integrity of the authorship ledger (hash chain of the user's prompts in .authorship/ledger.jsonl, checked against every anchor). Use when the user asks whether their prompt log / authorship evidence is intact or untampered.
allowed-tools: Bash(node:*)
---

Run the verifier from the project root (if the ledger is somewhere unexpected, add `--project <dir>`):

```bash
node "${CLAUDE_PLUGIN_ROOT}/scripts/ledger.js" verify
```

Then tell the user, in their language, starting with the ledger path it printed:

- **`OK`**: number of entries, date span, head hash and how many anchors matched. If there are no anchors, explain that without one, deleting the newest entries or rebuilding the whole chain would go unnoticed, and suggest `/authorship-ledger:anchor`.
- **Warnings** (e.g. partial data documented by a `recovery` entry): explain that this is consistent with an interrupted write (crash, timeout, power loss) and that recording continued — but that it can't by itself rule out deletion of the newest entries; only a comparison with an earlier anchor, the git history or a backup can. Say whether an anchor exists after that point.
- **`INTEGRITY CHECK FAILED`**: list each problem plainly (modified entry, missing/reordered entries, broken chain, invalid lines, an anchor that no longer matches = truncation or rewrite). Point to earlier anchors, git history and backups as the way to recover a trustworthy copy.

**Never edit, "repair" or rewrite `ledger.jsonl`**: any change destroys its value as evidence.
