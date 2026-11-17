# Changelog

## 1.1.0 — 2026-11-17

### Added
- **Automatic anchors.** A chain-head snapshot is taken at the end of every session that added entries. In long sessions, one is also taken when the last anchor is older than `autoAnchorHours` (default 24). If the OpenTimestamps client is installed, each snapshot is stamped in the background. A broken chain is never anchored. Set `autoAnchor: false` to turn this off.
- **Claude activity tracking.** Hooks record Claude's file edits (`ai_edit`: path, hash of the text written, hash of the file afterwards — never content). They also record its shell commands (`ai_command`), together with the hashes of the files each command changed, found by comparing `git status` before (PreToolUse) and after (PostToolUse). Set `trackAiActivity: false` to turn this off.
- **`/authorship-ledger:attribution`** and a report section. For every file Claude changed, it shows whether the file is still exactly what Claude's last recorded change left, was changed afterwards, or was deleted. It also states coverage: since when tracking has been active, how many prompts came before it, and sessions where it was off.
- `session_start` entries record the plugin version and whether tracking and auto-anchoring were on.
- `verify` and `status` report how many anchors have no OpenTimestamps proof.
- `.authorship/.gitignore` for transient hook files.

### Changed
- Shell commands and their descriptions are stored with the project path replaced by `<project>` and the home directory by `~`. Redaction now also covers `*_PASS=`, `--password <x>` and `mysql -p<x>`.
- Anchor files now contain `ledger_sha256_to_head`, the hash of the ledger bytes up to and including the head entry. It is computed from the same read as the head (it replaces `ledger_sha256`).
- File hashes are computed on raw bytes (binary-safe), with CRLF normalized.
- Appends read only the end of the ledger (256 KB, with a fallback to a full read), so hooks stay fast as the ledger grows.

### Fixed
- **Windows:** under contention, opening the lock file could fail with `EPERM` while another process was deleting it, and that prompt was silently not recorded. Fixed: such errors are now retried. A freshly created lock without a PID is no longer mistaken for one whose owner died.

## 1.0.0 — 2026-11-17
- First release: hash-chained prompt ledger with crash-safe recovery, anchors checked by `verify`, Markdown authorship report, secret redaction with HMAC proof (`check`), and a multi-session lock.
