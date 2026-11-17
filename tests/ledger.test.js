'use strict';
// Run with: node --test tests/ledger.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawn, spawnSync } = require('child_process');

const SCRIPT = path.join(__dirname, '..', 'plugins', 'authorship-ledger', 'scripts', 'ledger.js');
const { entryHash } = require(SCRIPT);

const tmpProject = () => fs.mkdtempSync(path.join(os.tmpdir(), 'authorship-test-'));

const KEY_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'authorship-key-')), 'key');

function baseEnv(extra) {
  const env = { ...process.env, AUTHORSHIP_LEDGER_KEY_FILE: KEY_FILE, ...extra };
  for (const k of ['AUTHORSHIP_LEDGER_DIR', 'AUTHORSHIP_LEDGER_DISABLED']) if (!(extra && k in extra)) delete env[k];
  return env;
}

/** Run as Claude Code would: CLAUDE_PROJECT_DIR set unless projectEnv === null. */
function run(dir, args, stdin, { cwd = dir, projectEnv = dir, env = {} } = {}) {
  const e = baseEnv(env);
  if (projectEnv === null) delete e.CLAUDE_PROJECT_DIR; else e.CLAUDE_PROJECT_DIR = projectEnv;
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd, env: e, input: stdin || '', encoding: 'utf8' });
}

const hook = (dir, cmd, payload, opts) => run(dir, [cmd], JSON.stringify({ cwd: dir, session_id: 's1', ...payload }), opts);
const ledgerOf = (dir) => path.join(dir, '.authorship', 'ledger.jsonl');
const lines = (dir) => fs.readFileSync(ledgerOf(dir), 'utf8').trim().split('\n');
const entries = (dir) => lines(dir).map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);

test('hooks print nothing and always exit 0', () => {
  const dir = tmpProject();
  const r = hook(dir, 'record', { prompt: 'Build a card shop game' });
  assert.strictEqual(r.status, 0);
  assert.strictEqual(r.stdout, '');
  const bad = run(dir, ['record'], 'not json');
  assert.strictEqual(bad.status, 0);
  assert.strictEqual(bad.stdout, '');
});

test('records session + prompts as a valid chain', () => {
  const dir = tmpProject();
  hook(dir, 'session', { source: 'startup', model: 'claude-opus-5-5' });
  hook(dir, 'record', { prompt: 'first idea' });
  hook(dir, 'record', { prompt: 'second idea with ```code```' });
  const es = entries(dir);
  assert.deepStrictEqual(es.map((e) => e.seq), [1, 2, 3]);
  assert.strictEqual(es[1].prev_hash, es[0].hash);
  assert.strictEqual(es[0].model, 'claude-opus-5-5');
  assert.strictEqual(es[1].cwd, '.');
  assert.ok(!path.isAbsolute(es[1].cwd));
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 0, v.stdout);
  assert.match(v.stdout, /OK — 3 entries/);
  assert.match(fs.readFileSync(path.join(dir, '.authorship', 'PROMPTS.md'), 'utf8'), /second idea/);
  assert.strictEqual(fs.readFileSync(path.join(dir, '.authorship', '.gitattributes'), 'utf8'), '* -text -merge\n');
});

test('empty prompts are skipped', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: '   ' });
  assert.ok(!fs.existsSync(ledgerOf(dir)));
});

test('detects a modified entry', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'original' });
  hook(dir, 'record', { prompt: 'another' });
  const l = lines(dir);
  l[0] = l[0].replace('original', 'forged!!');
  fs.writeFileSync(ledgerOf(dir), l.join('\n') + '\n');
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1);
  assert.match(v.stdout, /modified/);
});

test('detects a deleted entry in the middle', () => {
  const dir = tmpProject();
  ['a', 'b', 'c'].forEach((p) => hook(dir, 'record', { prompt: p }));
  const l = lines(dir);
  fs.writeFileSync(ledgerOf(dir), [l[0], l[2]].join('\n') + '\n');
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1);
  assert.match(v.stdout, /chain broken|missing/);
});

test('anchors detect tail truncation and full-chain rewrites', () => {
  const dir = tmpProject();
  ['a', 'b', 'c'].forEach((p) => hook(dir, 'record', { prompt: p }));
  assert.strictEqual(run(dir, ['anchor']).status, 0);
  const original = fs.readFileSync(ledgerOf(dir), 'utf8');

  // truncation: drop the last entry
  const l = original.trim().split('\n');
  fs.writeFileSync(ledgerOf(dir), l.slice(0, 2).join('\n') + '\n');
  let v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1, v.stdout);
  assert.match(v.stdout, /truncated/);

  // rewrite: forge entry 1 and recompute every hash
  let prev = '0'.repeat(64);
  const forged = l.map((line, i) => {
    const e = JSON.parse(line);
    if (i === 0) e.prompt = 'someone else\'s idea';
    delete e.prompt_sha256;
    e.prev_hash = prev;
    e.hash = entryHash(e);
    prev = e.hash;
    return JSON.stringify(e);
  });
  fs.writeFileSync(ledgerOf(dir), forged.join('\n') + '\n');
  v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1, v.stdout);
  assert.match(v.stdout, /rewritten/);
});

test('a corrupt tail never stops recording (recovery entry)', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'before crash' });
  fs.appendFileSync(ledgerOf(dir), '{"v":1,"seq":2,"ts":"x'); // interrupted write, no newline
  hook(dir, 'record', { prompt: 'after crash 1' });
  hook(dir, 'record', { prompt: 'after crash 2' });
  const es = entries(dir);
  assert.deepStrictEqual(es.map((e) => e.type), ['prompt', 'recovery', 'prompt', 'prompt']);
  assert.strictEqual(es[3].prompt, 'after crash 2');
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 0, v.stdout);
  assert.match(v.stdout, /Warnings \(1\)/);
  assert.match(v.stdout, /documented by recovery entry/);
});

test('undocumented garbage in the middle is a problem', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'a' });
  hook(dir, 'record', { prompt: 'b' });
  const l = lines(dir);
  fs.writeFileSync(ledgerOf(dir), [l[0], '<<<<<<< HEAD', l[1]].join('\n') + '\n');
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1, v.stdout);
  assert.match(v.stdout, /not valid ledger entries/);
});

test('CLI finds the ledger from a subdirectory without CLAUDE_PROJECT_DIR', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'from the root' });
  const sub = path.join(dir, 'src', 'deep');
  fs.mkdirSync(sub, { recursive: true });
  const s = run(dir, ['status'], '', { cwd: sub, projectEnv: null });
  assert.match(s.stdout, /1 prompts/);
  assert.ok(s.stdout.includes(ledgerOf(dir)), s.stdout);
  const v = run(dir, ['verify', '--project', dir], '', { cwd: os.tmpdir(), projectEnv: null });
  assert.strictEqual(v.status, 0, v.stdout);
});

test('redacts secrets and drops the brute-forceable hash', () => {
  const dir = tmpProject();
  const cases = [
    'use key sk-ant-abcdefghijklmnopqrstuvwxyz123456 please',
    'config {"password": "hunter22"}',
    'db postgres://admin:s3cretpass@localhost/db',
    'header Authorization: Bearer abcdefghijklmnop1234567890',
    'stripe sk_live_abcdefghijklmnop1234',
    'gitlab glpat-abcdefghijklmnopqrstu',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- done',
  ];
  cases.forEach((prompt) => hook(dir, 'record', { prompt }));
  const es = entries(dir);
  const leaked = ['abcdefghijklmnopqrstuvwxyz123456', 'hunter22', 's3cretpass', 'abcdefghijklmnop1234567890', 'sk_live_abc', 'glpat-abc', 'MIIabc'];
  es.forEach((e, i) => {
    assert.match(e.prompt, /REDACTED/, cases[i]);
    assert.ok(!e.prompt.includes(leaked[i]), e.prompt);
    assert.strictEqual(e.prompt_sha256, undefined);
  });
  assert.match(es[6].prompt, / done$/);
  hook(dir, 'record', { prompt: 'nothing secret' });
  const last = entries(dir).pop();
  assert.strictEqual(last.prompt_sha256, crypto.createHash('sha256').update('nothing secret').digest('hex'));
  assert.strictEqual(run(dir, ['verify']).status, 0);
});

test('redaction leaves ordinary code alone and keeps JSON quotes', () => {
  const { redact } = require(SCRIPT);
  for (const code of [
    'pwd = os.getcwd()',
    'token = tokenizer.encode(text)',
    "password = request.form['password']",
    'token = getToken()',
    'the Bearer tokensareconfusingtome',
  ]) {
    assert.strictEqual(redact(code).text, code, code);
  }
  assert.strictEqual(redact('{"api_key": "abc123xyz"}').text, '{"api_key": "[REDACTED]"}');
  assert.strictEqual(redact('password = hunter22').text, 'password = [REDACTED]');
  const prose = 'files start with -----BEGIN PRIVATE KEY----- usually\n\nkeep this paragraph';
  assert.match(redact(prose).text, /keep this paragraph$/);
});

test('redacted prompts can still be proven by their owner (HMAC)', () => {
  const dir = tmpProject();
  const prompt = 'deploy with password=hunter22 to staging';
  hook(dir, 'record', { prompt });
  const e = entries(dir)[0];
  assert.strictEqual(e.prompt_sha256, undefined);
  assert.match(e.prompt_hmac, /^[0-9a-f]{64}$/);
  assert.strictEqual(run(dir, ['check', '1'], prompt + '\n').status, 0);
  assert.strictEqual(run(dir, ['check', '1'], 'deploy with password=hunter23 to staging').status, 1);
  hook(dir, 'record', { prompt: 'plain text' });
  assert.strictEqual(run(dir, ['check', '2'], 'plain text').status, 0);
});

test('a damaged complete entry is a problem, not an interrupted write', () => {
  const dir = tmpProject();
  ['one', 'two', 'three secret idea'].forEach((p) => hook(dir, 'record', { prompt: p }));
  const l = lines(dir);
  l[2] = l[2].replace('"type":', '"type"'); // one character removed: whole line, unparseable
  fs.writeFileSync(ledgerOf(dir), l.join('\n') + '\n');
  let v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1, v.stdout);
  hook(dir, 'record', { prompt: 'four' }); // hook writes a recovery entry
  v = run(dir, ['verify']);
  assert.strictEqual(v.status, 1, v.stdout);
  assert.match(v.stdout, /altered, not an interrupted write/);
});

test('cwd outside the project is not stored as an absolute path', () => {
  const dir = tmpProject();
  const other = tmpProject();
  hook(dir, 'record', { prompt: 'x', cwd: other });
  assert.strictEqual(entries(dir)[0].cwd, '<outside project>');
});

test('private-key redaction stays fast on hostile input', () => {
  const { redact } = require(SCRIPT);
  const hostile = '-----BEGIN RSA PRIVATE KEY-----\n'.repeat(20000);
  const t = Date.now();
  const r = redact(hostile);
  assert.ok(Date.now() - t < 1000, `took ${Date.now() - t} ms`);
  assert.ok(!r.text.includes('BEGIN'));
});

test('a stale lock from a dead process is broken quickly', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'first' });
  const lock = path.join(dir, '.authorship', '.lock');
  fs.writeFileSync(lock, '999999'); // PID that is not running
  const old = new Date(Date.now() - 1000);
  fs.utimesSync(lock, old, old);
  const t = Date.now();
  hook(dir, 'record', { prompt: 'second' });
  assert.ok(Date.now() - t < 2500, `took ${Date.now() - t} ms`);
  assert.strictEqual(entries(dir).length, 2);
});

test('recording can be disabled per project or by env', () => {
  const dir = tmpProject();
  fs.mkdirSync(path.join(dir, '.authorship'));
  fs.writeFileSync(path.join(dir, '.authorship', 'config.json'), '{"enabled": false}');
  hook(dir, 'record', { prompt: 'secret project' });
  assert.ok(!fs.existsSync(ledgerOf(dir)));
  const dir2 = tmpProject();
  hook(dir2, 'record', { prompt: 'x' }, { env: { AUTHORSHIP_LEDGER_DISABLED: '1' } });
  assert.ok(!fs.existsSync(ledgerOf(dir2)));
});

test('parallel writers keep one consistent chain', async () => {
  const dir = tmpProject();
  const env = baseEnv({ CLAUDE_PROJECT_DIR: dir });
  await Promise.all(Array.from({ length: 24 }, (_, i) => new Promise((resolve) => {
    const c = spawn(process.execPath, [SCRIPT, 'record'], { cwd: dir, env });
    c.on('exit', resolve);
    c.stdin.end(JSON.stringify({ cwd: dir, session_id: 'p' + i, prompt: 'parallel ' + i }));
  })));
  assert.strictEqual(lines(dir).length, 24);
  assert.strictEqual(run(dir, ['verify']).status, 0);
});

test('report and anchor', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'idea for report' });
  const a = run(dir, ['anchor']);
  assert.strictEqual(a.status, 0, a.stdout);
  assert.ok(fs.readdirSync(path.join(dir, '.authorship', 'anchors')).some((f) => f.endsWith('.txt')));
  const r = run(dir, ['report']);
  assert.strictEqual(r.status, 0, r.stdout);
  const md = fs.readFileSync(path.join(dir, '.authorship', 'AUTHORSHIP-REPORT.md'), 'utf8');
  assert.match(md, /Human Authorship Report/);
  assert.match(md, /idea for report/);
  assert.match(md, /1 snapshot/);
});

const toolHook = (dir, tool_name, tool_input, opts) => hook(dir, 'tool', { tool_name, tool_input }, opts);
const anchorFiles = (dir) => {
  try { return fs.readdirSync(path.join(dir, '.authorship', 'anchors')).filter((f) => f.endsWith('.txt')); } catch (_) { return []; }
};

test('records Claude edits (hashes only) and shell commands', () => {
  const dir = tmpProject();
  const file = path.join(dir, 'src', 'game.js');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, 'const secretSauce = 42;\r\n');
  const r = toolHook(dir, 'Write', { file_path: file, content: 'const secretSauce = 42;\n' });
  assert.strictEqual(r.stdout, '');
  toolHook(dir, 'Bash', { command: 'curl -H "Authorization: Bearer abcdef1234567890abcdef" x', description: 'call api' });
  toolHook(dir, 'Read', { file_path: file }); // ignored
  const es = entries(dir);
  assert.deepStrictEqual(es.map((e) => e.type), ['ai_edit', 'ai_command']);
  assert.strictEqual(es[0].file, 'src/game.js');
  assert.strictEqual(es[0].file_sha256_after, crypto.createHash('sha256').update('const secretSauce = 42;\n').digest('hex'));
  assert.ok(!JSON.stringify(es[0]).includes('secretSauce'));
  assert.match(es[1].command, /Bearer \[REDACTED\]/);
  assert.strictEqual(run(dir, ['verify']).status, 0);
});

test('attribution separates files changed after Claude', () => {
  const dir = tmpProject();
  execFileSync('git', ['init', '-q'], { cwd: dir });
  const w = (name, text) => { fs.writeFileSync(path.join(dir, name), text); return path.join(dir, name); };
  toolHook(dir, 'Write', { file_path: w('ai.js', 'ai code\n'), content: 'ai code\n' });
  toolHook(dir, 'Edit', { file_path: w('mixed.js', 'ai code\n'), old_string: 'x', new_string: 'ai code' });
  toolHook(dir, 'Write', { file_path: w('gone.js', 'tmp\n'), content: 'tmp\n' });
  w('mixed.js', 'ai code\nplus my own work\n');
  fs.unlinkSync(path.join(dir, 'gone.js'));
  w('human.js', 'written by hand\n');
  execFileSync('git', ['add', 'ai.js', 'mixed.js', 'human.js'], { cwd: dir });
  const a = run(dir, ['attribution']);
  assert.strictEqual(a.status, 0, a.stdout);
  assert.match(a.stdout, /ai\.js — 1 change\(s\) via file tool.*identical to Claude's last recorded change/);
  assert.match(a.stdout, /mixed\.js — 1 change\(s\) via file tool.*changed after Claude's last recorded change/);
  assert.match(a.stdout, /gone\.js.*deleted after Claude changed it/);
  assert.match(a.stdout, /no change by Claude recorded since tracking began: 1/);
  run(dir, ['report']);
  const md = fs.readFileSync(path.join(dir, '.authorship', 'AUTHORSHIP-REPORT.md'), 'utf8');
  assert.match(md, /AI activity and file attribution/);
  assert.match(md, /`human\.js`/);
});

test('shell commands: files they change are attributed to Claude, earlier human edits are not', () => {
  const dir = tmpProject();
  const g = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  g('init', '-q');
  g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
  fs.writeFileSync(path.join(dir, 'a.txt'), 'original\n');
  fs.writeFileSync(path.join(dir, 'mine.txt'), 'original\n');
  g('add', '.'); g('commit', '-qm', 'init');
  fs.writeFileSync(path.join(dir, 'mine.txt'), 'edited by the human before the command\n');

  const payload = { tool_name: 'Bash', tool_use_id: 'tu1', tool_input: { command: 'sed -i s/original/by-claude/ a.txt' } };
  hook(dir, 'tool-pre', payload);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'by-claude\n'); // what the command does
  fs.writeFileSync(path.join(dir, 'new.txt'), 'created by the command\n');
  hook(dir, 'tool', payload);

  const e = entries(dir).find((x) => x.type === 'ai_command');
  assert.strictEqual(e.files_tracked, true);
  assert.deepStrictEqual(Object.keys(e.files_changed).sort(), ['a.txt', 'new.txt']);
  assert.ok(!fs.existsSync(path.join(dir, '.authorship', '.pending', 'tu1.json')));
  const a = run(dir, ['attribution']);
  assert.match(a.stdout, /a\.txt — 1 change\(s\) via shell.*identical/);
  assert.ok(!/mine\.txt — /.test(a.stdout), a.stdout);
  fs.writeFileSync(path.join(dir, 'a.txt'), 'by-claude\nthen improved by hand\n');
  assert.match(run(dir, ['attribution']).stdout, /a\.txt — .*changed after Claude's last recorded change/);
});

test('shell commands: secrets and local paths are scrubbed', () => {
  const dir = tmpProject();
  const home = os.homedir();
  const command = `cd "${dir}" && mysql -u root -pHunter2pass db && export DB_PASS=abcdefgh && cat "${path.join(home, 'notes.txt')}" && tool --password s3cr3tvalue`;
  toolHook(dir, 'Bash', { command, description: 'login with password=hunter22' });
  const e = entries(dir)[0];
  for (const leaked of ['Hunter2pass', 'abcdefgh', 's3cr3tvalue', 'hunter22', dir, home]) {
    assert.ok(!e.command.includes(leaked) && !e.description.includes(leaked), `leaked ${leaked}: ${e.command} | ${e.description}`);
  }
  assert.match(e.command, /cd "<project>"/);
  assert.match(e.command, /~[\\/]notes\.txt/);
});

test('reports say when AI activity was not tracked (e.g. ledgers from v1.0)', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'old prompt, before v1.1' });
  let a = run(dir, ['attribution']);
  assert.match(a.stdout, /no tracked session recorded/);
  hook(dir, 'session', { source: 'startup' });
  hook(dir, 'record', { prompt: 'new prompt' });
  a = run(dir, ['attribution']);
  assert.match(a.stdout, /tracking since entry #2/);
  assert.match(a.stdout, /1 prompt\(s\) were recorded before that/);
  const dir2 = tmpProject();
  fs.mkdirSync(path.join(dir2, '.authorship'));
  fs.writeFileSync(path.join(dir2, '.authorship', 'config.json'), '{"trackAiActivity": false}');
  hook(dir2, 'session', { source: 'startup' });
  assert.match(run(dir2, ['attribution']).stdout, /turned OFF in 1 session/);
});

test('verify points out anchors without an OpenTimestamps proof', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'x' });
  run(dir, ['anchor']);
  const v = run(dir, ['verify']);
  assert.strictEqual(v.status, 0);
  assert.match(v.stdout, /1 of 1 anchor\(s\) have no OpenTimestamps proof/);
  const txt = fs.readFileSync(path.join(dir, '.authorship', 'anchors', anchorFiles(dir)[0]), 'utf8');
  const prefix = fs.readFileSync(ledgerOf(dir), 'utf8');
  assert.ok(txt.includes(`ledger_sha256_to_head: ${crypto.createHash('sha256').update(prefix).digest('hex')}`));
});

test('file hashes are binary-safe and ignore CRLF', () => {
  const dir = tmpProject();
  const a = path.join(dir, 'a.bin');
  const b = path.join(dir, 'b.bin');
  fs.writeFileSync(a, Buffer.from([0xff, 0xfe, 0x00, 0x01]));
  fs.writeFileSync(b, Buffer.from([0xfe, 0xff, 0x00, 0x01]));
  toolHook(dir, 'Write', { file_path: a, content: 'x' });
  toolHook(dir, 'Write', { file_path: b, content: 'x' });
  const [ea, eb] = entries(dir);
  assert.notStrictEqual(ea.file_sha256_after, eb.file_sha256_after);
  const c = path.join(dir, 'c.txt');
  fs.writeFileSync(c, 'l1\r\nl2\r\n');
  toolHook(dir, 'Write', { file_path: c, content: 'x' });
  assert.strictEqual(entries(dir)[2].file_sha256_after, crypto.createHash('sha256').update('l1\nl2\n').digest('hex'));
});

test('AI tracking can be turned off', () => {
  const dir = tmpProject();
  fs.mkdirSync(path.join(dir, '.authorship'));
  fs.writeFileSync(path.join(dir, '.authorship', 'config.json'), '{"trackAiActivity": false}');
  toolHook(dir, 'Bash', { command: 'ls' });
  assert.ok(!fs.existsSync(ledgerOf(dir)));
});

test('auto-anchor at session end, only when there is something new', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'idea' });
  assert.strictEqual(anchorFiles(dir).length, 0);
  hook(dir, 'session-end', {});
  assert.strictEqual(anchorFiles(dir).length, 1);
  hook(dir, 'session-end', {});
  assert.strictEqual(anchorFiles(dir).length, 1, 'no new entries → no new anchor');
  hook(dir, 'record', { prompt: 'more' });
  hook(dir, 'session-end', {});
  assert.strictEqual(anchorFiles(dir).length, 2);
  assert.strictEqual(run(dir, ['verify']).status, 0);
});

test('auto-anchor during long sessions after autoAnchorHours', () => {
  const dir = tmpProject();
  fs.mkdirSync(path.join(dir, '.authorship'));
  fs.writeFileSync(path.join(dir, '.authorship', 'config.json'), '{"autoAnchorHours": 0}');
  hook(dir, 'record', { prompt: 'one' });
  assert.strictEqual(anchorFiles(dir).length, 1);
  const dir2 = tmpProject();
  hook(dir2, 'record', { prompt: 'one' });
  assert.strictEqual(anchorFiles(dir2).length, 0, 'default 24h: no anchor yet');
  const dir3 = tmpProject();
  fs.mkdirSync(path.join(dir3, '.authorship'));
  fs.writeFileSync(path.join(dir3, '.authorship', 'config.json'), '{"autoAnchor": false}');
  hook(dir3, 'record', { prompt: 'one' });
  hook(dir3, 'session-end', {});
  assert.strictEqual(anchorFiles(dir3).length, 0);
});

test('auto-anchor never anchors a broken chain', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'a' });
  hook(dir, 'record', { prompt: 'b' });
  const l = lines(dir);
  l[0] = l[0].replace('"a"', '"z"');
  fs.writeFileSync(ledgerOf(dir), l.join('\n') + '\n');
  hook(dir, 'session-end', {});
  assert.strictEqual(anchorFiles(dir).length, 0);
});

test('appends stay correct when the last entry is larger than the tail chunk', () => {
  const dir = tmpProject();
  hook(dir, 'record', { prompt: 'small' });
  hook(dir, 'record', { prompt: 'x'.repeat(400 * 1024) });
  hook(dir, 'record', { prompt: 'after big' });
  fs.appendFileSync(ledgerOf(dir), '{"partial":');
  hook(dir, 'record', { prompt: 'after crash' });
  const es = entries(dir);
  assert.deepStrictEqual(es.map((e) => e.seq), [1, 2, 3, 4, 5]);
  assert.strictEqual(es[3].type, 'recovery');
  assert.strictEqual(run(dir, ['verify']).status, 0);
});

test('module exports do not run the CLI', () => {
  const out = execFileSync(process.execPath, ['-e', `const m=require(${JSON.stringify(SCRIPT)});console.log(typeof m.verifyItems)`]).toString();
  assert.strictEqual(out.trim(), 'function');
});
