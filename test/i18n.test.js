'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { collect, dictionary, needsTranslation } = require('../tools/i18n-missing');
const { render, tx } = require('../server/i18n');

const placeholders = (s) => (String(s).match(/\{\d+\}/g) || []).sort().join(',');

test('английский словарь: перевод есть у каждой строки интерфейса', () => {
  const d = dictionary();
  const missing = collect().filter((k) => needsTranslation(k) && !Object.hasOwn(d, k));
  assert.deepEqual(missing, [], 'запустите node tools/i18n-missing.js');
});

test('английский словарь: подстановки {0}… совпадают, переводы не пустые и без русских букв', () => {
  for (const [k, v] of Object.entries(dictionary())) {
    assert.equal(typeof v, 'string', k);
    assert.ok(v.trim() || !k.trim(), `пустой перевод: ${k}`);
    assert.equal(placeholders(v), placeholders(k), `подстановки: ${k}`);
    assert.doesNotMatch(v, /[А-Яа-яЁё]/, `русские буквы в переводе: ${k}`);
  }
});

test('сообщения с вложенными аргументами переводятся на сервере', () => {
  const d = dictionary();
  const m = tx('Брандмауэр: профиль {0}', 'Public');
  assert.equal(render('ru', m), 'Брандмауэр: профиль Public');
  assert.equal(render('en', m), d['Брандмауэр: профиль {0}'].replace('{0}', 'Public'));
  assert.equal(render('en', tx('Профиль «{0}» выключен', tx('общедоступная сеть'))), d['Профиль «{0}» выключен'].replace('{0}', d['общедоступная сеть']));
});

test('скрипты окна разбираются без ошибок (повторные имена и опечатки ломают всё окно)', () => {
  const vm = require('node:vm');
  const fs = require('node:fs');
  const path = require('node:path');
  for (const f of ['public/app.js', 'public/i18n-en.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    assert.doesNotThrow(() => new vm.Script(src, { filename: f }), f);
  }
});
