---
name: report
description: Generate a Markdown "Human Authorship Report" from the prompt ledger — summary, integrity status, chain head and a timeline of every prompt the user wrote. Use when the user wants evidence of their authorship, ideation or creative contribution to an AI-assisted project (copyright, IP, contracts, disputes, portfolio).
argument-hint: "[output-file]"
allowed-tools: Bash(node:*)
---

1. Generate the report (default location `.authorship/AUTHORSHIP-REPORT.md`; if the user passed a path in `$ARGUMENTS`, use it with `--out`):

   ```bash
   node "${CLAUDE_PLUGIN_ROOT}/scripts/ledger.js" report
   ```

2. Read the generated file and add, **in a clearly separated section at the end titled "Author's contribution — narrative summary"**, a short factual synthesis of what the human contributed, based only on the prompts: the original idea and goals, design decisions, constraints, corrections and creative choices they made, citing prompt numbers (`#12`, `#31`). Do not invent contributions or exaggerate them, and do not edit the generated sections above it.

3. Tell the user where the report is, whether integrity passed, and remind them that:
   - the ledger is tamper-*evident* relative to its anchors; proof of *when* comes from external anchors — `/authorship-ledger:anchor` (OpenTimestamps), a git remote, or sending the head hash to a third party (e-mail, notary, PEC in Italy);
   - copyright protects expression, not ideas, and in several jurisdictions (e.g. the US Copyright Office's 2025 guidance) prompts alone are generally not enough for authorship — the record is strongest alongside their own edits and design work;
   - this is technical evidence, not legal advice.
