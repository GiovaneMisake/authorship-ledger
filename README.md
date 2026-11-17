# 🛡️ Authorship Ledger — document *your* part in AI-assisted work

**A Claude Code plugin that keeps a tamper-evident, timestamped record of every prompt you write, so your human creative direction of AI-assisted work is documented — automatically.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Claude Code plugin](https://img.shields.io/badge/Claude%20Code-plugin-d97757)](https://code.claude.com/docs/en/plugins)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-blue)](plugins/authorship-ledger/scripts/ledger.js)

🇮🇹 [Leggi in italiano](#-italiano)

---

When you build with AI, *"who is the author?"* matters — for copyright, client contracts, employment disputes, investors, or simply your portfolio. Copyright offices and new laws increasingly agree that **protection follows human creative contribution**. Much of that contribution — your goals, design decisions, constraints, corrections — lives in your prompts, and prompts vanish into chat history.

Authorship Ledger captures them **as you type**, in your project, in a format designed to be evidence:

- 📝 **Every prompt, automatically** — a `UserPromptSubmit` hook appends each prompt with timestamp, session, author (git identity), branch and commit.
- 🔗 **Hash-chained** — each entry contains the SHA-256 of the previous one, so editing, deleting or reordering entries breaks the chain and `verify` reports it.
- ⏱️ **Automatic anchors & trusted timestamps** — a snapshot of the chain head is taken at the end of every session (and every 24 h in long sessions), with no action needed. `verify` checks every snapshot, so truncation or a rewritten chain is caught too. If the free [OpenTimestamps](https://opentimestamps.org) client is installed, each snapshot is also stamped on the Bitcoin blockchain.
- 🤖 **What Claude changed, file by file** — Claude's file edits are recorded as hashes (never content). Its shell commands are recorded too, together with the hashes of the files each command changed, found by comparing git status before and after. `attribution` then shows which files are still exactly as Claude's last recorded change left them and which were changed afterwards. Your git history shows who made those later changes. Your hands-on changes to the output matter a lot for copyright, and this shows where they can be.
- 📄 **Authorship report** — one command produces a Markdown report: summary, integrity status, timeline of your prompts, file attribution and a narrative of your creative contribution.
- 🧯 **Crash-safe & append-only** — an interrupted write never stops recording: the next prompt adds a `recovery` entry documenting the damaged bytes. Existing lines are never rewritten.
- 🔒 **Local & private** — nothing leaves your machine. The one exception: if you install the OpenTimestamps client, the hash of each anchor snapshot (never its content) is sent to OpenTimestamps servers. Common secret formats (API keys, tokens, JWTs, private keys, passwords in config or URLs) are redacted before writing.
- 🪶 **Zero dependencies** — one Node.js script. Each hook takes roughly 0.1–0.2 s; shell commands run two of them (a git status before and after). The hooks print nothing to Claude's context and never make a prompt or tool call fail.

## Install

In Claude Code:

```
/plugin marketplace add GiovaneMisake/authorship-ledger
/plugin install authorship-ledger@authorship-ledger
```

Restart Claude Code (or run `/reload-plugins`). From the next prompt on, everything is recorded.

Requires Node.js ≥ 18 on your `PATH`.

## Commands

| Command | What it does |
|---|---|
| `/authorship-ledger:status` | Where the ledger is, whether recording is on, how many prompts/sessions/anchors |
| `/authorship-ledger:verify` | Recomputes the whole hash chain, checks every anchor, reports any tampering |
| `/authorship-ledger:report [file]` | Writes the Human Authorship Report (default `.authorship/AUTHORSHIP-REPORT.md`) |
| `/authorship-ledger:anchor` | Snapshots the chain head now (it also happens automatically); stamps it with OpenTimestamps if `ots` is installed |
| `/authorship-ledger:attribution` | Files Claude changed (file tools or shell): identical to Claude's last change, changed afterwards, or deleted, plus since when tracking covers the project |

You can also just ask Claude: *"generate a report documenting my authorship of this project"*.

## What gets written

```
your-project/
└── .authorship/
    ├── ledger.jsonl          ← the evidence (one hash-chained JSON entry per line, append-only)
    ├── PROMPTS.md            ← human-readable copy
    ├── AUTHORSHIP-REPORT.md  ← generated on demand
    ├── anchors/              ← head snapshots (+ .ots blockchain proofs)
    ├── .gitattributes        ← keeps bytes exact, prevents merge markers in the ledger
    └── config.json           ← optional settings
```

A ledger entry:

```json
{"v":1,"seq":42,"ts":"2026-11-17T13:49:24.391Z","type":"prompt","session_id":"…",
 "prompt":"Make the shop owner haggle based on reputation…","prompt_sha256":"…","chars":48,
 "author":{"name":"Jane Dev","email":"jane@…","os_user":"jane","host":"laptop"},
 "project":"card-shop","cwd":".","git":{"branch":"main","head":"7a25196…"},
 "prev_hash":"…","hash":"…"}
```

Claude's activity, in the same chain:

```json
{"seq":43,"type":"ai_edit","tool":"Edit","file":"src/shop.js","written_sha256":"…","written_chars":812,
 "file_sha256_after":"…","session_id":"…","prev_hash":"…","hash":"…", …}
{"seq":44,"type":"ai_command","tool":"Bash","command":"npm test","description":"Run tests", …}
```

`file_sha256_after` is the SHA-256 of the whole file right after Claude's edit, with CRLF normalized to LF so line-ending changes don't count.

`hash = SHA-256(canonical JSON of the entry without "hash")` with keys sorted recursively, so anyone can re-implement the verifier in a few lines.

Prompts that had secrets redacted carry no plain `prompt_sha256` (it would let someone brute-force a short password). They carry a `prompt_hmac` keyed by a random local secret in `~/.config/authorship-ledger/key`, which never goes into the ledger, so **you** can still prove the exact original text, for example from Claude Code's transcript:

```bash
node "<plugin>/scripts/ledger.js" check 42 < original-prompt.txt   # → MATCH / NO MATCH
```

Back that key file up privately; without it redacted prompts can't be matched.

## What it proves — and what it doesn't

- ✅ **Internal consistency.** Changing, removing or reordering any entry *before the newest one* breaks the chain.
- ✅ **Nothing changed since an anchor.** If the newest entries are deleted, or someone rebuilds the entire chain with forged content, `verify` catches it **only by comparing against an anchor made earlier**. Anchors are taken automatically at the end of each session. ⚠️ An anchor file sits next to the ledger, so whoever rewrites the ledger could regenerate the anchors too. Only an OpenTimestamps proof (`.ots`), a pushed commit or a copy held by someone else is independent of your machine. `verify` and `status` tell you how many anchors lack an `.ots` proof. Background stamping fails silently when `ots` isn't on the PATH or you are offline.
- ✅ **Which files are still exactly what Claude left.** `attribution` compares each file with Claude's last recorded change, whether made with its file tools or with a shell command. ⚠️ What it can't tell you:
  - *who* changed a file afterwards: you, a formatter, another tool, or a teammate. Your git history answers that.
  - anything from before tracking began, for example a ledger started with v1.0. The report states since when tracking covers the project, and in which sessions it was off.
  - shell changes outside a git repo, or commands that touched more than 500 files.

  "No change by Claude recorded" is therefore **not** proof that a file is human-written.
- ❌ **Dates on their own.** Timestamps in the file are written by your computer. Trust in *when* comes from things outside your control: OpenTimestamps proofs, a git remote's history, or a copy sent to a third party.
- ❌ **Authorship on its own.** Copyright protects *expression*, not ideas. The [US Copyright Office (2025)](https://www.copyright.gov/ai/) concluded that prompts alone generally do not give enough control over the output to make the user its author; what counts is human expressive input, selection/arrangement and modification. Italy's AI law (L. 132/2025) likewise protects works that result from the author's intellectual effort, even when made with AI tools. The ledger documents your creative direction — it is strongest **together with** your own edits and design work in git.

## Making the evidence strong

1. **Install the OpenTimestamps client** (`pip install opentimestamps-client`). Then every automatic anchor also gets a free Bitcoin-anchored proof. Run `/authorship-ledger:anchor` by hand at milestones too: before publishing, before sending work to a client, at a release.
2. **Keep a copy you don't control** — push it to a remote, and for high stakes send the head hash to a third party (e-mail to yourself and a lawyer, a notary, or a PEC message in Italy).
3. **Keep your own edits in git**, so your hands-on contribution is documented too.

### Committing the ledger — read this if you use branches

Once `.authorship/ledger.jsonl` is tracked by git, switching branches swaps the file for that branch's copy, and prompts recorded on two branches fork the chain. Pick one:

- **Recommended:** keep the ledger outside the project's working tree, e.g. in a private repo just for ledgers:
  ```bash
  export AUTHORSHIP_LEDGER_DIR="$HOME/authorship-ledgers/my-project"
  ```
  then commit and push that folder whenever you like.
- **Or** add `.authorship/` to the project's `.gitignore` and back it up elsewhere.
- **Or**, if you only work on one branch, commit `.authorship/` from that branch only.

> ⚠️ **Public repos:** committed prompts are public — and each entry contains your git name/e-mail, OS user name and host name. Use a private location, or turn the personal fields off (see below).

## Configuration

Create `.authorship/config.json` (all optional, defaults shown):

```json
{
  "enabled": true,
  "redactSecrets": true,
  "recordAuthorEmail": true,
  "recordMachineInfo": true,
  "humanReadableLog": true,
  "trackAiActivity": true,
  "autoAnchor": true,
  "autoAnchorHours": 24
}
```

| Setting | Effect |
|---|---|
| `enabled: false` | Stop recording in this project |
| `recordAuthorEmail: false` | Don't store your git e-mail |
| `recordMachineInfo: false` | Don't store OS user name and host name |
| `humanReadableLog: false` | Don't write `PROMPTS.md` |
| `trackAiActivity: false` | Don't record Claude's file edits and shell commands |
| `autoAnchor: false` | Only anchor when you run `/authorship-ledger:anchor` |
| `autoAnchorHours` | In long sessions, anchor when the last anchor is older than this (default 24) |

Environment variables: `AUTHORSHIP_LEDGER_DIR` (ledger location), `AUTHORSHIP_LEDGER_KEY_FILE` (HMAC key location), `AUTHORSHIP_LEDGER_DISABLED=1` (turn recording off everywhere), `AUTHORSHIP_LEDGER_DEBUG=1` (print hook errors to stderr).

Redaction is pattern-based and best-effort: it covers the common formats listed above, not every possible secret. Avoid pasting credentials into prompts.

## FAQ

**Doesn't Claude Code already keep transcripts?** Yes, in `~/.claude/projects/`. But they are deleted after 30 days by default (`cleanupPeriodDays`), live outside your project, are plain files anyone can edit unnoticed, and mix your words with Claude's. The ledger is permanent, sits in the project, is tamper-evident and anchored, and separates what you asked from what Claude did. Keeping transcripts longer (raise `cleanupPeriodDays`) is a good complement: with `check` you can match a redacted prompt against them.

**Does it record Claude's answers?** Not the text. It records what Claude *did*: which files it edited (as hashes) and which commands it ran.

**Does auto-anchoring leave processes running?** When `ots` is installed, each automatic anchor starts a detached `ots stamp` that ends by itself once the OpenTimestamps calendars answer or time out. If you are offline often, you may see a few of them linger. Set `autoAnchor: false` and anchor by hand if you'd rather not.

**Multiple sessions at once?** A file lock keeps one consistent chain across parallel sessions; a lock left behind by a crashed process is detected and cleared.

**Is this legal advice?** No. It's a technical tool that produces well-organized evidence. Ask a lawyer for your case.

## Development

```bash
node --test tests/ledger.test.js
```

Contributions welcome: other AI coding tools, signing entries with SSH/GPG keys, RFC 3161 timestamping, PDF reports.

---

## 🇮🇹 Italiano

**Un plugin per Claude Code che tiene un registro a prova di manomissione, con marca temporale, di ogni richiesta che scrivi all'AI, per documentare automaticamente il tuo contributo creativo.**

Quando sviluppi con l'intelligenza artificiale, la domanda *"chi è l'autore?"* conta: diritto d'autore, contratti con i clienti, rapporti di lavoro, investitori. La legge italiana sull'AI (L. 132/2025) tutela le opere che sono frutto del lavoro intellettuale dell'autore anche se create con strumenti di AI. Gran parte di quel contributo umano — obiettivi, scelte, vincoli, correzioni — sta nei tuoi prompt, che di solito si perdono nella cronologia.

Authorship Ledger li salva **mentre scrivi**, nel tuo progetto:

- 📝 **Ogni richiesta, automaticamente**, con data/ora, sessione, autore (identità git), branch e commit.
- 🔗 **Catena di hash SHA-256**: modifiche, cancellazioni o riordini rompono la catena e `verify` li segnala.
- ⏱️ **Ancoraggi automatici** a fine sessione (e ogni 24 ore nelle sessioni lunghe), con marca temporale gratuita sulla blockchain Bitcoin tramite [OpenTimestamps](https://opentimestamps.org) se il client è installato; `verify` confronta il registro con ogni ancoraggio.
- 🤖 **Cosa ha fatto Claude e cosa hai fatto tu**: le modifiche di Claude ai file vengono registrate come impronte (mai il contenuto), insieme ai comandi che esegue. Registra anche, per ogni comando, quali file ha cambiato. `attribution` mostra file per file cosa è ancora esattamente come l'ha lasciato Claude e cosa è stato cambiato dopo; chi l'ha cambiato lo dice la tua storia git. Non è una prova che un file sia scritto da un umano: vale solo da quando il tracciamento è attivo, e il report indica da quando.
- 📄 **Report di paternità** in Markdown con cronologia dei prompt, attribuzione dei file e sintesi del tuo contributo creativo.
- 🔒 **Locale e privato**: nessuna connessione di rete; chiavi, token e password nei formati comuni vengono oscurati.

### Installazione

```
/plugin marketplace add GiovaneMisake/authorship-ledger
/plugin install authorship-ledger@authorship-ledger
```

### Comandi

- `/authorship-ledger:status` — stato del registro
- `/authorship-ledger:verify` — verifica la catena e gli ancoraggi
- `/authorship-ledger:report` — genera il report di paternità
- `/authorship-ledger:anchor` — fissa subito lo stato attuale con una marca temporale (avviene anche in automatico)
- `/authorship-ledger:attribution` — quali file sono ancora come li ha lasciati Claude e quali hai cambiato tu

### Cosa dimostra (e cosa no)

La catena rende evidente ogni modifica interna; la cancellazione delle ultime voci o la riscrittura dell'intera catena si scoprono solo confrontando con un ancoraggio precedente. La **data** è affidabile solo grazie a riscontri esterni (OpenTimestamps, push su un repository remoto, **PEC** o notaio). Il diritto d'autore tutela l'espressione, non le idee: i prompt da soli potrebbero non bastare, perciò conserva in git anche le tue modifiche al codice.

Se usi più branch, tieni il registro fuori dal progetto (`AUTHORSHIP_LEDGER_DIR`) o escludilo con `.gitignore`. Attenzione ai repository pubblici: i prompt, il tuo nome/e-mail git e il nome del computer sarebbero visibili.

*Strumento tecnico, non consulenza legale.*

## License

[MIT](LICENSE)
