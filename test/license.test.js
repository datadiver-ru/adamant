'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const lic = require('../server/license');

const kp = crypto.generateKeyPairSync('ed25519');
const pub = kp.publicKey;
const pem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });

test('лицензия: выпуск и проверка', () => {
  const key = lic.issue({ licensee: 'Иван', expires: '2030-01-01' }, pem);
  assert.match(key, /^ADAMANT1\./);
  const p = lic.parse(key, { pub, now: Date.parse('2029-06-01') });
  assert.equal(p.licensee, 'Иван');
  assert.equal(p.expired, false);
  assert.equal(lic.parse(key, { pub, now: Date.parse('2030-01-02') }).expired, true);
  assert.equal(lic.status(p).edition, 'full');
  assert.equal(lic.status({ ...p, expired: true }).edition, 'free', 'просроченный ключ = бесплатная версия');
  assert.equal(lic.status(null).edition, 'free');
  assert.ok(Object.values(lic.status(p).features).every(Boolean));
  assert.ok(Object.values(lic.status(null).features).every((x) => !x));
});

test('лицензия: подделки отклоняются', () => {
  assert.throws(() => lic.parse('', { pub }));
  assert.throws(() => lic.parse('ODEM1.xxxxxxxxxxxx.' + 'a'.repeat(86), { pub }));
  const key = lic.issue({ licensee: 'Иван' }, pem);
  assert.throws(() => lic.parse(key.slice(0, -2) + (key.endsWith('AA') ? 'BA' : 'AA'), { pub }));
  assert.throws(() => lic.parse(key, { pub: lic.publicKey() }), 'ключ из чужой пары не подходит к встроенному открытому ключу');
  // Подписанный, но не той редакции.
  const odd = lic.issue({ licensee: 'X', edition: 'pro' }, pem);
  assert.throws(() => lic.parse(odd, { pub }));
});

test('встроенный открытый ключ - Ed25519, закрытого ключа в проекте нет', () => {
  assert.equal(lic.publicKey().asymmetricKeyType, 'ed25519');
  const fs = require('node:fs');
  const path = require('node:path');
  const root = path.join(__dirname, '..');
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (['node_modules', '.git', 'data', 'dist'].includes(e.name) ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(root)) {
    if (!/\.(js|json|pem|md|ps1|txt)$/.test(f)) continue;
    assert.ok(!fs.readFileSync(f, 'utf8').includes('BEGIN ' + 'PRIVATE KEY'), f);
  }
});
