#!/usr/bin/env node
/*
 * Authorship Ledger — tamper-evident log of the human prompts that drive
 * AI-assisted development, kept as evidence of human authorship/ideation.
 *
 * Zero dependencies. Node >= 18.
 *
 * Subcommands:
 *   record            (hook: UserPromptSubmit) append the prompt read from stdin JSON
 *   session           (hook: SessionStart)     append a session-start marker
 *   verify            check the hash chain and every anchor
 *   status            short summary of the ledger
 *   report [--out F]  write a Markdown authorship report
 *   anchor            snapshot the chain head (and stamp it with OpenTimestamps if `ots` is installed)
 * Every CLI subcommand accepts --project <dir>.
 *
 * Hooks MUST never break the user's session: every hook path swallows errors,
 * prints nothing to stdout and exits 0.
 *
 * The file is append-only: this script never rewrites existing lines. If the
 * tail is unreadable (interrupted write, merge conflict, hand edit) the next
 * append first writes a `recovery` entry that records the hash of the bad
 * bytes and continues the chain from the last valid entry.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const LEDGER_VERSION = 1;
const DIR_NAME = '.authorship';
const GENESIS = '0'.repeat(64);
const LOCK_WAIT_MS = 5000;
const LOCK_STALE_MS = 3000;

// ---------------------------------------------------------------- helpers

function sha256(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Deterministic JSON: keys sorted recursively, so hashes are reproducible. */
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort()
      .filter((k) => value[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  }
  return JSON.stringify(value);
}

function entryHash(entry) {
  const { hash, ...rest } = entry; // eslint-disable-line no-unused-vars
  return sha256(canonical(rest));
}

function git(args, cwd) {
  try {
    return execFileSync('git', args, { cwd, stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 })
      .toString().trim() || undefined;
  } catch (_) {
    return undefined;
  }
}

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i > -1 ? process.argv[i + 1] : undefined;
}

/** Nearest ancestor of `start` (inclusive) that already holds a ledger. */
function findExistingLedger(start) {
  let dir = path.resolve(start);
  for (;;) {
    if (fs.existsSync(path.join(dir, DIR_NAME, 'ledger.jsonl'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) return undefined;
    dir = up;
  }
}

/**
 * Where the project (and its ledger) lives. Same order for hooks and CLI so
 * both always look at the same file:
 *   --project > CLAUDE_PROJECT_DIR > git top level if it holds a ledger
 *   > nearest existing .authorship/ > git top level > cwd
 * AUTHORSHIP_LEDGER_DIR overrides only the ledger folder, not the project root.
 */
function projectRoot(cwd) {
  const base = path.resolve(cwd || process.cwd());
  const flag = argValue('--project');
  if (flag) return path.resolve(flag);
  if (process.env.CLAUDE_PROJECT_DIR) return path.resolve(process.env.CLAUDE_PROJECT_DIR);
  const top = git(['rev-parse', '--show-toplevel'], base);
  const topResolved = top && path.resolve(top);
  if (topResolved && fs.existsSync(path.join(topResolved, DIR_NAME, 'ledger.jsonl'))) return topResolved;
  return findExistingLedger(base) || topResolved || base;
}

function paths(cwd) {
  const root = projectRoot(cwd);
  const dir = process.env.AUTHORSHIP_LEDGER_DIR
    ? path.resolve(process.env.AUTHORSHIP_LEDGER_DIR)
    : path.join(root, DIR_NAME);
  return {
    root,
    dir,
    ledger: path.join(dir, 'ledger.jsonl'),
    human: path.join(dir, 'PROMPTS.md'),
    readme: path.join(dir, 'README.md'),
    gitattributes: path.join(dir, '.gitattributes'),
    config: path.join(dir, 'config.json'),
    lock: path.join(dir, '.lock'),
    anchors: path.join(dir, 'anchors'),
  };
}

function loadConfig(p) {
  const defaults = {
    enabled: true,
    redactSecrets: true,
    recordAuthorEmail: true,
    recordMachineInfo: true,
    humanReadableLog: true,
  };
  try {
    return { ...defaults, ...JSON.parse(fs.readFileSync(p.config, 'utf8')) };
  } catch (_) {
    return defaults;
  }
}

// ---------------------------------------------------------------- redaction

const SECRET_PATTERNS = [
  [/\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g, '[REDACTED:api-key]'],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g, '[REDACTED:stripe-key]'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}/g, '[REDACTED:github-token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{40,}/g, '[REDACTED:github-token]'],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, '[REDACTED:gitlab-token]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED:aws-key]'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, '[REDACTED:slack-token]'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED:google-key]'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '[REDACTED:jwt]'],
  [/(\bBearer\s+)(?=[A-Za-z0-9._~+/-]*\d)[A-Za-z0-9._~+/-]{16,}=*/gi, '$1[REDACTED]'],
  [/(\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,200}:)[^\s@/]{1,200}@/gi, '$1[REDACTED]@'],
  // key = value / "key": "value". Group 3 is the value; `skip` keeps code such as
  // `pwd = os.getcwd()` or `token = tokenizer.encode(x)` from being mangled.
  [/((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)["']?\s*[:=]\s*)(["']?)([^\s"'()[\]{},;]{6,})\2/gi,
    '$1$2[REDACTED]$2',
    (args) => {
      const value = args[3];
      const after = args[args.length - 1].charAt(args[args.length - 2] + args[0].length);
      if (!args[2] && (after === '(' || after === '[')) return true; // function call / indexing
      return !args[2] && /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(value); // attribute access
    }],
];

const PK_MAX_WITHOUT_END = 4096;

/** Linear-time private key redaction (a regex here can go quadratic). */
function redactPrivateKeys(text) {
  const BEGIN = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/g;
  let out = '';
  let pos = 0;
  let count = 0;
  let m;
  while ((m = BEGIN.exec(text))) {
    const bodyStart = m.index + m[0].length;
    const endMarker = text.indexOf('PRIVATE KEY-----', bodyStart);
    out += text.slice(pos, m.index) + '[REDACTED:private-key]';
    count++;
    if (endMarker === -1) {
      // No END marker: redact the key-looking body only — up to a blank line or 4 KB.
      const blank = text.slice(bodyStart, bodyStart + PK_MAX_WITHOUT_END).search(/\r?\n\s*\r?\n/);
      pos = blank === -1 ? Math.min(text.length, bodyStart + PK_MAX_WITHOUT_END) : bodyStart + blank;
    } else {
      pos = endMarker + 'PRIVATE KEY-----'.length;
    }
    BEGIN.lastIndex = Math.max(pos, bodyStart);
  }
  return { text: out + text.slice(pos), count };
}

function redact(text) {
  const pk = redactPrivateKeys(text);
  let out = pk.text;
  let count = pk.count;
  for (const [re, rep, skip] of SECRET_PATTERNS) {
    out = out.replace(re, (...args) => {
      if (skip && skip(args)) return args[0];
      count++;
      return rep.replace(/\$(\d)/g, (_, d) => (typeof args[d] === 'string' ? args[d] : ''));
    });
  }
  return { text: out, count };
}

// ---------------------------------------------------------------- local key (HMAC)

/**
 * Redacted prompts can't keep a plain SHA-256 of the original (a short secret
 * could be brute-forced). They keep an HMAC keyed by a local secret that never
 * goes into the ledger, so the owner can still prove what they typed
 * (`ledger.js check <seq>`), while nobody else can test guesses.
 */
function keyFile() {
  return process.env.AUTHORSHIP_LEDGER_KEY_FILE
    || path.join(os.homedir(), '.config', 'authorship-ledger', 'key');
}

function localKey(create) {
  const f = keyFile();
  try {
    return fs.readFileSync(f, 'utf8').trim();
  } catch (_) {
    if (!create) return undefined;
  }
  fs.mkdirSync(path.dirname(f), { recursive: true });
  const k = crypto.randomBytes(32).toString('hex');
  try {
    fs.writeFileSync(f, k + '\n', { flag: 'wx', mode: 0o600 });
    return k;
  } catch (e) {
    if (e.code === 'EEXIST') return fs.readFileSync(f, 'utf8').trim(); // created concurrently
    throw e;
  }
}

function hmac(key, s) {
  return crypto.createHmac('sha256', key).update(s, 'utf8').digest('hex');
}

// ---------------------------------------------------------------- locking

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/**
 * Take a stale lock out of the way by renaming it first, so that of several
 * waiters only one moves it — and if what got moved is not the stale lock we
 * inspected (another waiter already replaced it with a fresh one), put it back.
 */
function breakStaleLock(p, seen) {
  const aside = `${p.lock}.stale-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.renameSync(p.lock, aside); // throws if someone else already moved it
  const moved = fs.statSync(aside);
  if (moved.mtimeMs === seen.mtimeMs && moved.size === seen.size && moved.ino === seen.ino) {
    fs.unlinkSync(aside);
  } else {
    try { fs.linkSync(aside, p.lock); } catch (_) { /* a newer lock exists: leave it */ }
    fs.unlinkSync(aside);
  }
}

/** Cross-process lock so parallel sessions don't fork the chain. */
function withLock(p, fn) {
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd;
  for (;;) {
    try {
      fd = fs.openSync(p.lock, 'wx');
      fs.writeSync(fd, String(process.pid));
      break;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        const st = fs.statSync(p.lock);
        const age = Date.now() - st.mtimeMs;
        const owner = parseInt(fs.readFileSync(p.lock, 'utf8'), 10);
        // Stale when the owner died, or when it has held the lock implausibly long.
        // (A lock just created may not have its PID written yet: give it 200 ms.)
        if (age > LOCK_STALE_MS || (age > 200 && !pidAlive(owner))) breakStaleLock(p, st);
      } catch (_) { /* raced with another process: retry */ }
      if (Date.now() > deadline) throw new Error('ledger lock timeout');
      sleepMs(20);
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(fd); } catch (_) { /* ignore */ }
    try { fs.unlinkSync(p.lock); } catch (_) { /* ignore */ }
  }
}

// ---------------------------------------------------------------- reading

function isEntry(o) {
  return o && typeof o === 'object' && !Array.isArray(o)
    && typeof o.hash === 'string' && Number.isInteger(o.seq) && typeof o.prev_hash === 'string';
}

/** Parse the ledger into ordered items: {line, entry} or {line, raw} for unusable lines. */
function readItems(p) {
  if (!fs.existsSync(p.ledger)) return { items: [], text: '' };
  const text = fs.readFileSync(p.ledger, 'utf8');
  const items = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\r$/, '');
    if (!line.trim()) return;
    let o;
    try { o = JSON.parse(line); } catch (_) { o = undefined; }
    items.push(isEntry(o) ? { line: i + 1, entry: o } : { line: i + 1, raw: line });
  });
  return { items, text };
}

const entriesOf = (items) => items.filter((x) => x.entry).map((x) => x.entry);

function readAnchors(p) {
  let files = [];
  try { files = fs.readdirSync(p.anchors).filter((f) => f.endsWith('.txt')).sort(); } catch (_) { return []; }
  return files.map((f) => {
    const body = fs.readFileSync(path.join(p.anchors, f), 'utf8');
    const field = (k) => { const m = body.match(new RegExp('^' + k + ':\\s*(\\S+)', 'm')); return m && m[1]; };
    return { file: f, seq: parseInt(field('head_seq'), 10), hash: field('head_hash') };
  });
}

// ---------------------------------------------------------------- verification

/**
 * Returns { problems, warnings }. Problems mean the evidence was altered or is
 * inconsistent; warnings are documented, benign irregularities (e.g. a write
 * interrupted by a crash, recorded by a recovery entry).
 */
function verifyItems(items, anchors) {
  const problems = [];
  const warnings = [];
  let prev = null;
  let pending = []; // unusable lines since the last valid entry

  const rangeOf = (list) => (list.length === 1 ? `line ${list[0].line}` : `lines ${list[0].line}-${list[list.length - 1].line}`);
  // A crash mid-write leaves a *prefix* of an entry. A line that is a whole
  // entry (ends with "}" and carries its hash) but doesn't parse was altered.
  const looksComplete = (list) => list.filter((x) => /\}\s*$/.test(x.raw) && x.raw.includes('"hash":"'));

  for (const it of items) {
    if (!it.entry) { pending.push(it); continue; }
    const e = it.entry;
    const where = `line ${it.line} (seq ${e.seq})`;

    if (pending.length) {
      const documented = e.type === 'recovery'
        && e.corrupt_lines === pending.length
        && e.corrupt_sha256 === sha256(pending.map((x) => x.raw).join('\n'));
      const altered = looksComplete(pending);
      if (altered.length) {
        problems.push(`${rangeOf(altered)}: a complete entry that no longer parses — altered, not an interrupted write`);
      } else if (documented) {
        warnings.push(`${rangeOf(pending)}: unreadable partial data, documented by recovery entry seq ${e.seq} — consistent with an interrupted write, but deletion of the newest entries can only be ruled out against an anchor`);
      } else {
        problems.push(`${rangeOf(pending)}: not valid ledger entries`);
      }
      pending = [];
    } else if (e.type === 'recovery') {
      problems.push(`${where}: recovery entry with nothing to recover`);
    }

    const expectedSeq = prev ? prev.seq + 1 : 1;
    if (e.seq !== expectedSeq) problems.push(`${where}: expected seq ${expectedSeq} — entries missing, duplicated or reordered`);
    const expectedPrev = prev ? prev.hash : GENESIS;
    if (e.prev_hash !== expectedPrev) problems.push(`${where}: prev_hash does not match the previous entry — chain broken`);
    if (entryHash(e) !== e.hash) problems.push(`${where}: content was modified (hash mismatch)`);
    if (e.type === 'prompt' && typeof e.prompt_sha256 === 'string' && !e.redactions
        && typeof e.prompt === 'string' && sha256(e.prompt) !== e.prompt_sha256) {
      problems.push(`${where}: prompt text does not match prompt_sha256`);
    }
    prev = e;
  }
  if (pending.length) {
    const altered = looksComplete(pending);
    if (altered.length) problems.push(`${rangeOf(altered)}: a complete entry that no longer parses — altered, not an interrupted write`);
    else warnings.push(`${rangeOf(pending)}: unreadable trailing data (e.g. an interrupted write); the next prompt will document it with a recovery entry`);
  }

  // Anchors make truncation and whole-chain rewrites detectable.
  const bySeq = new Map();
  for (const it of items) if (it.entry && !bySeq.has(it.entry.seq)) bySeq.set(it.entry.seq, it.entry);
  for (const a of anchors || []) {
    if (!Number.isInteger(a.seq) || !a.hash) { problems.push(`anchor ${a.file}: unreadable`); continue; }
    const e = bySeq.get(a.seq);
    if (!e) problems.push(`anchor ${a.file}: entry seq ${a.seq} is missing — the ledger was truncated after this anchor`);
    else if (e.hash !== a.hash) problems.push(`anchor ${a.file}: entry seq ${a.seq} differs from the anchored one — the ledger was rewritten`);
  }
  return { problems, warnings };
}

// ---------------------------------------------------------------- writing

const LEDGER_README = `# .authorship — human authorship ledger

Written by the **authorship-ledger** Claude Code plugin. Every prompt the
human author typed into Claude Code is appended to \`ledger.jsonl\` as a
hash-chained entry (each entry contains the SHA-256 of the previous one).

What this proves: editing, deleting or reordering an entry breaks the chain
and is reported by \`/authorship-ledger:verify\`. Removing the newest entries,
or rewriting the whole chain, is only detectable by comparing with an anchor
(\`anchors/\`), the git history or a copy held by a third party — so anchor and
push regularly.

- \`ledger.jsonl\` — the evidence. Append-only: never edit it.
- \`PROMPTS.md\`   — human-readable copy.
- \`anchors/\`     — chain-head snapshots, optionally with OpenTimestamps \`.ots\` proofs.
- \`config.json\`  — optional settings: enabled, redactSecrets, recordAuthorEmail,
                    recordMachineInfo, humanReadableLog.

If you commit this folder, commit it from ONE branch only: switching branches
would swap ledger.jsonl and fork the chain. See the plugin README.
`;

function ensureDir(p) {
  if (!fs.existsSync(p.dir)) fs.mkdirSync(p.dir, { recursive: true });
  if (!fs.existsSync(p.readme)) fs.writeFileSync(p.readme, LEDGER_README);
  // Keep bytes exact (OpenTimestamps proofs, hashes) and never let git write
  // conflict markers into the ledger.
  if (!fs.existsSync(p.gitattributes)) fs.writeFileSync(p.gitattributes, '* -text -merge\n');
}

function author(cwd, cfg) {
  const a = { name: git(['config', 'user.name'], cwd), email: git(['config', 'user.email'], cwd) };
  if (!cfg.recordAuthorEmail) delete a.email;
  if (cfg.recordMachineInfo) {
    try { a.os_user = os.userInfo().username; } catch (_) { /* unavailable */ }
    a.host = os.hostname();
  }
  return a;
}

function context(p, cwd) {
  return {
    project: path.basename(p.root),
    cwd: (() => {
      const rel = path.relative(p.root, cwd);
      if (path.isAbsolute(rel) || rel === '..' || rel.startsWith('..' + path.sep)) return '<outside project>';
      return rel.split(path.sep).join('/') || '.';
    })(),
    git: { branch: git(['rev-parse', '--abbrev-ref', 'HEAD'], cwd), head: git(['rev-parse', 'HEAD'], cwd) },
  };
}

function seal(fields, prev) {
  const entry = {
    v: LEDGER_VERSION,
    seq: prev ? prev.seq + 1 : 1,
    ts: new Date().toISOString(),
    ...fields,
    prev_hash: prev ? prev.hash : GENESIS,
  };
  entry.hash = entryHash(entry);
  return entry;
}

function append(p, cfg, fields, humanBlock) {
  ensureDir(p);
  return withLock(p, () => {
    const { items, text } = readItems(p);
    let lastIdx = -1;
    for (let i = items.length - 1; i >= 0; i--) if (items[i].entry) { lastIdx = i; break; }
    let prev = lastIdx >= 0 ? items[lastIdx].entry : null;
    const badTail = items.slice(lastIdx + 1);

    let out = text && !text.endsWith('\n') ? '\n' : ''; // never glue onto a partial line
    if (badTail.length) {
      const rec = seal({
        type: 'recovery',
        reason: 'unreadable lines after the last valid entry (interrupted write, merge conflict or manual edit)',
        corrupt_lines: badTail.length,
        corrupt_sha256: sha256(badTail.map((x) => x.raw).join('\n')),
      }, prev);
      out += JSON.stringify(rec) + '\n';
      prev = rec;
    }
    const entry = seal(fields, prev);
    out += JSON.stringify(entry) + '\n';
    fs.appendFileSync(p.ledger, out);

    if (cfg.humanReadableLog && humanBlock) {
      if (!fs.existsSync(p.human)) {
        fs.writeFileSync(p.human, '# Prompt log (human-readable copy of ledger.jsonl)\n\n'
          + '> Generated by authorship-ledger. The authoritative, tamper-evident record is `ledger.jsonl`.\n\n');
      }
      fs.appendFileSync(p.human, humanBlock(entry));
    }
    return entry;
  });
}

function readStdinJson() {
  try {
    const raw = fs.readFileSync(0, 'utf8');
    return raw.trim() ? JSON.parse(raw) : {};
  } catch (_) {
    return {};
  }
}

function fence(text) {
  const longest = (text.match(/`+/g) || []).reduce((m, s) => Math.max(m, s.length), 0);
  const f = '`'.repeat(Math.max(3, longest + 1));
  return `${f}text\n${text}\n${f}`;
}

function hookSetup(input) {
  if (process.env.AUTHORSHIP_LEDGER_DISABLED === '1') return null;
  const cwd = path.resolve(input.cwd || process.cwd());
  const p = paths(cwd);
  const cfg = loadConfig(p);
  if (cfg.enabled === false) return null;
  return { cwd, p, cfg };
}

// ---------------------------------------------------------------- commands

function cmdRecord() {
  const input = readStdinJson();
  const prompt = typeof input.prompt === 'string' ? input.prompt : '';
  if (!prompt.trim()) return;
  const s = hookSetup(input);
  if (!s) return;
  const red = s.cfg.redactSecrets ? redact(prompt) : { text: prompt, count: 0 };
  append(s.p, s.cfg, {
    type: 'prompt',
    session_id: input.session_id,
    prompt: red.text,
    // An unsalted hash of a prompt whose secret was removed would let anyone
    // brute-force a short secret: redacted prompts get a keyed HMAC instead.
    prompt_sha256: red.count ? undefined : sha256(prompt),
    prompt_hmac: red.count ? (() => { try { return hmac(localKey(true), prompt); } catch (_) { return undefined; } })() : undefined,
    redactions: red.count || undefined,
    chars: red.text.length,
    author: author(s.cwd, s.cfg),
    ...context(s.p, s.cwd),
  }, (e) => `## #${e.seq} — ${e.ts}\n\n`
    + `session \`${e.session_id || '?'}\` · author ${e.author.name || e.author.os_user || '?'}`
    + ` · hash \`${e.hash.slice(0, 16)}…\`\n\n${fence(e.prompt)}\n\n`);
}

function cmdSession() {
  const input = readStdinJson();
  const s = hookSetup(input);
  if (!s) return;
  append(s.p, s.cfg, {
    type: 'session_start',
    session_id: input.session_id,
    source: input.source,
    model: typeof input.model === 'string' ? input.model : (input.model && input.model.id) || undefined,
    author: author(s.cwd, s.cfg),
    ...context(s.p, s.cwd),
    tool: 'claude-code',
  }, (e) => `---\n\n### Session \`${e.session_id || '?'}\` started — ${e.ts}`
    + `${e.source ? ` (${e.source})` : ''}${e.model ? ` · model ${e.model}` : ''}\n\n`);
}

function cmdVerify() {
  const p = paths();
  const { items } = readItems(p);
  const entries = entriesOf(items);
  if (!items.length) {
    console.log(`No ledger yet at ${p.ledger}`);
    return 0;
  }
  const anchors = readAnchors(p);
  const { problems, warnings } = verifyItems(items, anchors);
  console.log(`Ledger: ${p.ledger}`);
  if (problems.length) {
    console.log(`INTEGRITY CHECK FAILED — ${problems.length} problem(s):`);
    problems.forEach((x) => console.log('  - ' + x));
  } else {
    console.log(`OK — ${entries.length} entries, hash chain intact, ${anchors.length} anchor(s) match.`);
  }
  if (warnings.length) {
    console.log(`Warnings (${warnings.length}):`);
    warnings.forEach((x) => console.log('  - ' + x));
  }
  if (entries.length) {
    console.log(`First:  ${entries[0].ts}`);
    console.log(`Last:   ${entries[entries.length - 1].ts}`);
    console.log(`Head hash: ${entries[entries.length - 1].hash}`);
  }
  if (!anchors.length) console.log('Note: no anchors yet — run /authorship-ledger:anchor so truncation and rewrites become detectable.');
  return problems.length ? 1 : 0;
}

function cmdStatus() {
  const p = paths();
  const { items } = readItems(p);
  const entries = entriesOf(items);
  const prompts = entries.filter((e) => e.type === 'prompt');
  const sessions = new Set(entries.map((e) => e.session_id).filter(Boolean));
  const cfg = loadConfig(p);
  console.log(`Ledger:   ${p.ledger}${fs.existsSync(p.ledger) ? '' : ' (not created yet)'}`);
  console.log(`Recording: ${cfg.enabled === false || process.env.AUTHORSHIP_LEDGER_DISABLED === '1' ? 'DISABLED' : 'on'}`);
  console.log(`Entries:  ${entries.length} (${prompts.length} prompts, ${sessions.size} sessions)`);
  if (entries.length) {
    const head = entries[entries.length - 1];
    console.log(`Span:     ${entries[0].ts} → ${head.ts}`);
    console.log(`Head:     ${head.hash}`);
  }
  const anchors = readAnchors(p);
  console.log(`Anchors:  ${anchors.length}${anchors.length ? ' (latest ' + anchors[anchors.length - 1].file + ')' : ''}`);
  return 0;
}

function cmdReport() {
  const p = paths();
  const { items } = readItems(p);
  const entries = entriesOf(items);
  const anchors = readAnchors(p);
  const { problems, warnings } = verifyItems(items, anchors);
  const prompts = entries.filter((e) => e.type === 'prompt');
  const bySession = new Map();
  for (const e of entries) {
    const k = e.session_id || 'unknown';
    if (!bySession.has(k)) bySession.set(k, []);
    bySession.get(k).push(e);
  }
  const authors = [...new Set(prompts.map((e) => {
    const a = e.author || {};
    return a.name ? a.name + (a.email ? ` <${a.email}>` : '') : a.os_user;
  }).filter(Boolean))];
  const head = entries[entries.length - 1];
  let otsCount = 0;
  try { otsCount = fs.readdirSync(p.anchors).filter((f) => f.endsWith('.ots')).length; } catch (_) { /* none */ }
  const totalChars = prompts.reduce((s, e) => s + (e.chars || 0), 0);

  const out = [];
  out.push('# Human Authorship Report', '');
  out.push(`Generated: ${new Date().toISOString()} by authorship-ledger`, '');
  out.push('## Summary', '');
  out.push('| | |\n|---|---|');
  out.push(`| Project | \`${path.basename(p.root)}\` |`);
  out.push(`| Author(s) | ${authors.join(', ') || 'n/a'} |`);
  out.push(`| Prompts recorded | ${prompts.length} (${totalChars} characters of human input) |`);
  out.push(`| Sessions | ${bySession.size} |`);
  out.push(`| Period | ${entries.length ? entries[0].ts + ' → ' + head.ts : 'n/a'} |`);
  out.push(`| Integrity | ${problems.length ? '**FAILED** (' + problems.length + ' problems)' : 'hash chain intact, anchors match'}${warnings.length ? `, ${warnings.length} warning(s)` : ''} |`);
  out.push(`| Chain head (SHA-256) | \`${head ? head.hash : 'n/a'}\` |`);
  out.push(`| External anchors | ${anchors.length} snapshot(s), ${otsCount} OpenTimestamps proof(s) |`);
  out.push('');
  if (problems.length || warnings.length) {
    out.push('### Integrity findings', '');
    problems.forEach((x) => out.push('- **problem:** ' + x));
    warnings.forEach((x) => out.push('- warning: ' + x));
    out.push('');
  }
  out.push('## What this evidence shows — and what it does not', '');
  out.push('- Each line of `.authorship/ledger.jsonl` is a JSON entry whose `hash` is the SHA-256 of its other fields serialized with recursively sorted keys; `prev_hash` links it to the preceding entry. Editing, deleting or reordering an entry breaks the chain.');
  out.push('- Removing the newest entries or rebuilding the whole chain is only detectable against an anchor made earlier (`.authorship/anchors/`, optionally stamped with OpenTimestamps), the git history, or a copy held by a third party. Dates are only as trustworthy as those external anchors.');
  out.push('- To re-check: run `node scripts/ledger.js verify` from the authorship-ledger plugin (or re-implement the rule above), and `ots verify <file>.ots` for each proof.');
  out.push('');
  out.push('## Timeline of human prompts', '');
  for (const [sid, list] of bySession) {
    out.push(`### Session \`${sid}\` — ${list[0].ts}`, '');
    for (const e of list) {
      if (e.type !== 'prompt') continue;
      out.push(`**#${e.seq}** · ${e.ts} · \`${e.hash.slice(0, 12)}\`${e.redactions ? ' · secrets redacted' : ''}`, '');
      out.push(fence(e.prompt), '');
    }
  }
  out.push('---', '');
  out.push('_This report documents the human direction given to an AI assistant. It is technical evidence, not legal advice. Copyright protects expression, not ideas, and in several jurisdictions prompts alone may not be enough for authorship; this record is strongest alongside your own edits and design work._', '');

  const target = path.resolve(argValue('--out') || path.join(p.dir, 'AUTHORSHIP-REPORT.md'));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, out.join('\n'));
  console.log(`Ledger: ${p.ledger}`);
  console.log(`Report written: ${target}`);
  console.log(`${prompts.length} prompts, ${bySession.size} sessions, integrity ${problems.length ? 'FAILED' : 'OK'}${warnings.length ? ` (${warnings.length} warnings)` : ''}.`);
  return problems.length ? 1 : 0;
}

function cmdAnchor() {
  const p = paths();
  const { items } = readItems(p);
  const entries = entriesOf(items);
  console.log(`Ledger: ${p.ledger}`);
  if (!entries.length) { console.log('Nothing to anchor: the ledger is empty.'); return 0; }
  const { problems } = verifyItems(items, readAnchors(p));
  if (problems.length) { console.log('Refusing to anchor: integrity check failed. Run verify.'); return 1; }
  const head = entries[entries.length - 1];
  ensureDir(p);
  fs.mkdirSync(p.anchors, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(p.anchors, `${stamp}-seq${head.seq}.txt`);
  fs.writeFileSync(file, [
    'authorship-ledger anchor',
    `created: ${new Date().toISOString()}`,
    `entries: ${entries.length}`,
    `head_seq: ${head.seq}`,
    `head_ts: ${head.ts}`,
    `head_hash: ${head.hash}`,
    `ledger_sha256: ${sha256(fs.readFileSync(p.ledger, 'utf8'))}`,
    '',
  ].join('\n'));
  console.log(`Anchor snapshot: ${file}`);
  console.log(`Head hash: ${head.hash}`);
  let stamped = false;
  try {
    execFileSync('ots', ['stamp', file], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 30000 });
    stamped = fs.existsSync(file + '.ots');
  } catch (_) { /* ots not installed or offline */ }
  if (stamped) {
    console.log(`OpenTimestamps proof: ${file}.ots (Bitcoin confirmation takes a few hours; run \`ots upgrade\` later)`);
  } else {
    console.log('OpenTimestamps client not found or offline — snapshot saved without a blockchain proof.');
    console.log('For a free trusted timestamp: `pip install opentimestamps-client` then `ots stamp "' + file + '"`,');
    console.log('or upload the .txt file at https://opentimestamps.org . Committing and pushing it to git also helps.');
  }
  return 0;
}

/** `check <seq>`: does the text on stdin match what was typed for that entry? */
function cmdCheck() {
  const seq = parseInt(process.argv[3], 10);
  const p = paths();
  const e = entriesOf(readItems(p).items).find((x) => x.seq === seq && x.type === 'prompt');
  if (!e) { console.log(`No prompt with seq ${process.argv[3]} in ${p.ledger}`); return 2; }
  const text = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
  let ok;
  if (e.prompt_sha256) {
    ok = sha256(text) === e.prompt_sha256;
  } else if (e.prompt_hmac) {
    const key = localKey(false);
    if (!key) { console.log(`Cannot check: the local key ${keyFile()} is missing.`); return 2; }
    ok = hmac(key, text) === e.prompt_hmac;
  } else {
    console.log('This entry has no hash of the original text to check against.');
    return 2;
  }
  console.log(ok ? `MATCH — the text is exactly what was typed at seq ${seq} (${e.ts}).` : `NO MATCH for seq ${seq}.`);
  return ok ? 0 : 1;
}

// ---------------------------------------------------------------- main

const HOOK_CMDS = { record: cmdRecord, session: cmdSession };
const CLI_CMDS = { verify: cmdVerify, status: cmdStatus, report: cmdReport, anchor: cmdAnchor, check: cmdCheck };

module.exports = { canonical, entryHash, verifyItems, redact, sha256 };

if (require.main === module) {
  const cmd = process.argv[2];
  if (HOOK_CMDS[cmd]) {
    try {
      HOOK_CMDS[cmd]();
    } catch (e) {
      if (process.env.AUTHORSHIP_LEDGER_DEBUG) process.stderr.write(String(e && e.stack) + '\n');
    }
    process.exit(0);
  } else if (CLI_CMDS[cmd]) {
    process.exit(CLI_CMDS[cmd]() || 0);
  } else {
    console.log('usage: ledger.js <record|session|verify|status|report [--out file]|anchor|check <seq>> [--project dir]');
    process.exit(cmd ? 2 : 0);
  }
}
