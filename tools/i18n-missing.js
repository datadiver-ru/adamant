'use strict';
/**
 * Строки интерфейса, которых нет в английском словаре public/i18n-en.js.
 * Ищет T('…'), F('…') в public/app.js; t('…'), tx('…') в server/*.js; Msg '…' в server/ps/fix.ps1.
 *   node tools/i18n-missing.js         - список недостающих
 *   node tools/i18n-missing.js --json  - то же в виде JSON-заготовки
 * Этот же сбор строк использует тест test/i18n.test.js.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

function unquote(q, s) {
  return s.replace(/\\(.)/g, (m, c) => (c === 'n' ? '\n' : c === q ? q : c === '\\' ? '\\' : m));
}

function collect() {
  const keys = new Set();
  const scan = (file, re) => {
    const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
    for (const m of src.matchAll(re)) keys.add(unquote(m[1], m[2]));
  };
  const JS = /\b(?:T|F|t|tx)\(\s*(['"])((?:\\.|(?!\1).)*)\1/g;
  scan('public/app.js', JS);
  for (const f of fs.readdirSync(path.join(ROOT, 'server')).filter((n) => n.endsWith('.js'))) scan('server/' + f, JS);
  const ps = fs.readFileSync(path.join(ROOT, 'server/ps/fix.ps1'), 'utf8');
  for (const m of ps.matchAll(/\bMsg\s+'((?:''|[^'])*)'/g)) keys.add(m[1].replace(/''/g, "'"));
  keys.delete('');
  return [...keys];
}

function dictionary() {
  const src = fs.readFileSync(path.join(ROOT, 'public/i18n-en.js'), 'utf8');
  return JSON.parse(src.slice(src.indexOf('{', src.indexOf('window.ADAMANT_EN')), src.lastIndexOf('}') + 1));
}

/** Строки без русских букв переводить не нужно (имена, команды, «{0}: {1}»). */
const needsTranslation = (k) => /[А-Яа-яЁё]/.test(k);

if (require.main === module) {
  const d = dictionary();
  const missing = collect().filter((k) => needsTranslation(k) && !Object.hasOwn(d, k)).sort();
  if (process.argv.includes('--json')) console.log(JSON.stringify(Object.fromEntries(missing.map((k) => [k, ''])), null, 1));
  else console.log(missing.length ? missing.join('\n') : 'Все строки переведены.');
}

module.exports = { collect, dictionary, needsTranslation };
