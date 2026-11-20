'use strict';
/**
 * Правило автора (19.11.2026): в репозитории, описаниях выпусков и на сайте нет упоминаний оплаты -
 * ни цен, ни звёзд, ни «купить/покупка/оплата», ни подписок и продления. Нейтрально можно:
 * «ключ полной версии», «получить полную версию».
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const FILES = ['public/app.js', 'public/i18n-en.js', 'README.md', 'SECURITY.md', 'CHANGELOG.md', 'scripts/build-dist.js', 'server/license.js', 'server/app.js'];
const BAD = /купи|покуп|оплат|звёзд|звезд|⭐|Telegram Stars|\bbuy\b|purchas|\bprice|\d+\s*(₽|руб)|продлени|renewal/i;

test('нигде в программе и документах нет слов об оплате', () => {
  for (const f of FILES) {
    const lines = fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n');
    lines.forEach((l, i) => assert.doesNotMatch(l, BAD, `${f}:${i + 1}: ${l.trim().slice(0, 120)}`));
  }
});
