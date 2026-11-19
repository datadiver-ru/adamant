'use strict';
/** Знакомство при первом запуске и «Первые шаги»: флаги в настройках, только true/false. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../server/store');

test('настройки: знакомство и «Первые шаги» запоминаются, мусор не сохраняется', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-welcome-'));
  try {
    const store = createStore(dir);
    assert.equal(store.settings().introDone, undefined, 'новый человек ещё не видел знакомство');
    store.saveSettings({ introDone: true, stepsHidden: true });
    assert.equal(store.settings().introDone, true);
    assert.equal(store.settings().stepsHidden, true);
    store.saveSettings({ introDone: 'yes', stepsHidden: 1, junk: '<script>' });
    const s = store.settings();
    assert.equal(s.introDone, true);
    assert.equal(s.stepsHidden, true);
    assert.equal(s.junk, undefined);
    store.saveSettings({ stepsHidden: false });
    assert.equal(store.settings().stepsHidden, false, '«Показать знакомство снова» возвращает шаги');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('окно: знакомство само показывается только при первом запуске, без проверки', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(src, /if \(!S\.data\.settings\.introDone && !report\(\)\) setTimeout\(welcomeModal/);
  for (const img of ['kira-keeper.jpg', 'kira-sword.jpg', 'kira-knight.jpg']) {
    assert.ok(src.includes(`img/${img}`));
    assert.ok(fs.existsSync(path.join(__dirname, '..', 'public', 'img', img)), img);
  }
});
