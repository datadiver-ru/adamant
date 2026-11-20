'use strict';
/** «Проверить обновления»: один запрос на GitHub по кнопке, без настоящей сети. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const update = require('../server/update');
const { OPEN_TARGETS } = require('../server/guides');
const { createApp } = require('../server/app');
const { createStore } = require('../server/store');

const rel = (tag, over) => ({ tag_name: tag, draft: false, prerelease: true, html_url: `https://github.com/datadiver-ru/adamant/releases/tag/${tag}`, published_at: '2026-11-19T12:00:00Z', ...over });

test('обновления: номер версии, самый новый выпуск, черновики и чужие теги не считаются', async () => {
  assert.deepEqual(update.parseVersion('v1.2.10'), [1, 2, 10]);
  assert.equal(update.parseVersion('v1.2'), null);
  assert.equal(update.parseVersion('latest'), null);
  const list = [rel('v1.2.2'), rel('v1.10.0', { draft: true }), rel('v1.2.10'), rel('nightly'), rel('v1.2.9')];
  assert.equal(update.newest(list).v.join('.'), '1.2.10', 'сравнение по числам, а не по тексту');
  const calls = [];
  const fetch = async (url) => { calls.push(url); return list; };
  const r = await update.check({ version: '1.2.2', fetch });
  assert.deepEqual(r, { current: '1.2.2', latest: '1.2.10', newer: true, beta: true, publishedAt: '2026-11-19T12:00:00Z', page: 'https://github.com/datadiver-ru/adamant/releases/tag/v1.2.10' });
  assert.deepEqual(calls, ['https://api.github.com/repos/datadiver-ru/adamant/releases?per_page=20'], 'один запрос, без своей версии в адресе');
  assert.equal((await update.check({ version: '1.2.10', fetch })).newer, false);
  assert.equal((await update.check({ version: '1.3.0', fetch })).newer, false, 'своя версия новее выпущенной');
  // Ссылка на чужой сайт из ответа не отдаётся.
  assert.equal((await update.check({ version: '1.0.0', fetch: async () => [rel('v2.0.0', { html_url: 'https://evil.example/x' })] })).page, null);
  await assert.rejects(update.check({ version: '1.2.2', fetch: async () => { throw new Error('ENOTFOUND'); } }), /Не удалось связаться с GitHub/);
  await assert.rejects(update.check({ version: '1.2.2', fetch: async () => ({ message: 'rate limit' }) }), /не вернул ни одного выпуска/);
});

test('обновления: запрос только на api.github.com по https, страница загрузки - только свой сайт', async () => {
  await assert.rejects(update.getJson('http://api.github.com/x'));
  await assert.rejects(update.getJson('https://evil.example/repos'));
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'update.js'), 'utf8');
  assert.doesNotMatch(src, /process\.env|userInfo|os\.hostname|require\('node:os'\)/, 'никаких сведений о компьютере');
  assert.deepEqual(OPEN_TARGETS.download.cmd.slice(1), ['https://datadiver-ru.github.io/adamant.html']);
  assert.deepEqual(OPEN_TARGETS['download-en'].cmd.slice(1), ['https://datadiver-ru.github.io/en/adamant.html']);
  // «Получить полную версию» ведёт в бот с ключами, а не в канал.
  assert.deepEqual(OPEN_TARGETS['shop-bot'].cmd.slice(1), ['https://t.me/datadiver_shop_bot']);
  assert.ok(fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8').includes("const buyFull = () => api('/api/open', { target: 'shop-bot' })"));
});

test('сервер: «Проверить обновления» - только по запросу окна, ошибка сети понятна', async () => {
  const KEY = 'update-test-key-0123456789';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-upd-'));
  let calls = 0;
  let fail = false;
  const updateFetch = async () => { calls += 1; if (fail) throw new Error('offline'); return [rel('v1.2.3')]; };
  const app = createApp({ store: createStore(dir), key: KEY, version: '1.2.2', runner: {}, updateFetch });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  const api = (route) => new Promise((res, rej) => {
    const data = Buffer.from('{}');
    const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: route, headers: { Host: `127.0.0.1:${port}`, 'X-Adamant-Key': KEY, 'Content-Type': 'application/json', 'Content-Length': data.length } }, (s) => {
      const c = [];
      s.on('data', (x) => c.push(x));
      s.on('end', () => res({ status: s.statusCode, json: JSON.parse(Buffer.concat(c).toString() || 'null') }));
    });
    r.on('error', rej);
    r.end(data);
  });
  try {
    assert.equal(calls, 0, 'сам при запуске не проверяет');
    const ok = await api('/api/update/check');
    assert.equal(ok.status, 200);
    assert.equal(ok.json.latest, '1.2.3');
    assert.equal(ok.json.newer, true);
    fail = true;
    const bad = await api('/api/update/check');
    assert.equal(bad.status, 502);
    assert.match(bad.json.error, /Не удалось связаться с GitHub/);
    assert.equal(calls, 2);
  } finally {
    await new Promise((r) => app.server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
