'use strict';
/**
 * «Уничтожить данные» (server/wipe.js) и регистрация камня (server/stones.js).
 * Всё во временных папках; DPAPI, закрытие процессов и UAC - поддельные. Настоящие данные компьютера не трогаются.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createVault, KEY_FILE } = require('../server/vault');
const { createStore } = require('../server/store');
const { createCanary, NAMES } = require('../server/canary');
const wipe = require('../server/wipe');
const stones = require('../server/stones');

const ROOT = path.join(__dirname, '..');
const FAKE = Buffer.from('FAKE');
const fakeProtect = async (b) => Buffer.concat([FAKE, Buffer.from(b.map((x) => x ^ 0x5a))]);
const fakeUnprotect = async (b) => {
  if (!b.subarray(0, 4).equals(FAKE)) throw new Error('not ours');
  return Buffer.from(b.subarray(4).map((x) => x ^ 0x5a));
};
const noSleep = async () => {};

/** Папка данных с ключом, отчётом, приманками, старым ключом в unreadable-*, профилем окна. */
async function world() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-wipe-'));
  const dataDir = path.join(base, 'data');
  const docs = path.join(base, 'docs');
  fs.mkdirSync(docs);
  fs.writeFileSync(path.join(docs, 'мой отчёт.docx'), 'настоящий документ');
  const vault = createVault({ dataDir, protect: fakeProtect, unprotect: fakeUnprotect });
  await vault.open();
  const store = createStore(dataDir, { vault });
  store.write('report.json', { at: '2026-11-20T10:00:00.000Z', facts: { meta: { computer: 'SECRET-PC' } } });
  store.write('telegram.json', { token: '123:SECRET' });
  store.saveSettings({ lang: 'ru' });
  const canary = createCanary({ dataDir, store, dirs: [docs], hide: () => {} });
  await canary.arm();
  fs.mkdirSync(path.join(dataDir, 'unreadable-20261120-101010'));
  fs.writeFileSync(path.join(dataDir, 'unreadable-20261120-101010', KEY_FILE), '{"old":"key"}');
  fs.mkdirSync(path.join(dataDir, 'window', 'Default', 'Cache'), { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'window', 'Default', 'Cache', 'data_1'), 'открытый кэш окна');
  const pd = path.join(base, 'ProgramData');
  const env = { USERPROFILE: path.join(base, 'home'), LOCALAPPDATA: path.join(base, 'home', 'AppData', 'Local'), ProgramData: pd };
  return { base, dataDir, docs, vault, store, canary, env, root: path.join(base, 'prog') };
}

test('слово подтверждения: УНИЧТОЖИТЬ или DESTROY, без учёта регистра и пробелов', () => {
  for (const w of ['УНИЧТОЖИТЬ', ' уничтожить ', 'Destroy']) assert.ok(wipe.wordOk(w), w);
  for (const w of ['', 'да', 'УНИЧТОЖ', null, undefined, 'DELETE']) assert.ok(!wipe.wordOk(w), String(w));
});

test('папка данных: корень диска, профиль, AppData, папку программы и чужую папку удалять нельзя', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-wipe-dir-'));
  const home = path.join(base, 'home');
  const env = { USERPROFILE: home, LOCALAPPDATA: path.join(home, 'AppData', 'Local'), APPDATA: path.join(home, 'AppData', 'Roaming') };
  const root = path.join(base, 'prog');
  const no = (d) => assert.throws(() => wipe.checkDataDir(d, { env, root }), undefined, d);
  no('');
  no('data');
  no(path.parse(base).root);
  no(home);
  no(path.join(home, 'AppData'));
  no(path.join(home, 'AppData', 'Local'));
  no(path.join(home, 'Documents'));
  no(root);
  no(base); // в ней лежит папка программы
  const foreign = path.join(base, 'photos', 'отпуск');
  fs.mkdirSync(foreign, { recursive: true });
  fs.writeFileSync(path.join(foreign, 'IMG_1.jpg'), 'x');
  assert.throws(() => wipe.checkDataDir(foreign, { env, root }), /не похоже/);
  const ours = path.join(home, 'AppData', 'Local', 'Adamant');
  wipe.checkDataDir(ours, { env, root }); // ещё нет - можно
  fs.mkdirSync(ours, { recursive: true });
  fs.writeFileSync(path.join(ours, 'settings.json'), '{}');
  wipe.checkDataDir(ours, { env, root });
  wipe.checkDataDir(path.join(root, 'data'), { env, root }); // запуск из исходников: data рядом с программой
});

test('wipeAll: сначала приманки и ключи, потом закрыть программу, потом удалить папку; чужие файлы на месте', async () => {
  const w = await world();
  const order = [];
  const r = await wipe.wipeAll({
    dataDir: w.dataDir, root: w.root, env: w.env, unprotect: fakeUnprotect, sleep: noSleep,
    stopProcs: async () => {
      order.push('procs');
      // К этому моменту ключей уже нет, а файлы ещё есть.
      assert.ok(!fs.existsSync(path.join(w.dataDir, KEY_FILE)));
      assert.ok(!fs.existsSync(path.join(w.dataDir, 'unreadable-20261120-101010', KEY_FILE)));
      assert.ok(fs.existsSync(path.join(w.dataDir, 'report.json')));
      for (const n of NAMES) assert.ok(!fs.existsSync(path.join(w.docs, n)), `приманка ${n} уже убрана`);
    },
    stopServer: async () => { order.push('server'); },
  });
  // Значок и процессы - раньше просьбы серверу: иначе значок перезапустил бы сервер.
  assert.deepEqual(order, ['procs', 'server']);
  assert.equal(r.ok, true);
  assert.equal(r.keysDestroyed, true);
  assert.deepEqual(r.filesLeft, []);
  assert.equal(r.decoysRemoved, NAMES.length);
  assert.ok(!fs.existsSync(w.dataDir), 'папки данных нет');
  assert.equal(fs.readFileSync(path.join(w.docs, 'мой отчёт.docx'), 'utf8'), 'настоящий документ');
  assert.deepEqual(fs.readdirSync(w.docs), ['мой отчёт.docx']);
});

test('wipeAll: занятый файл - в filesLeft, но ключ уничтожен и ok', async () => {
  const w = await world();
  const busy = path.join(w.dataDir, 'window', 'Default', 'Cache', 'data_1');
  const lockedFs = { ...fs, unlinkSync: (p) => { if (p === busy) { const e = new Error('EBUSY'); e.code = 'EBUSY'; throw e; } return fs.unlinkSync(p); } };
  const r = await wipe.wipeAll({ dataDir: w.dataDir, root: w.root, env: w.env, fs: lockedFs, unprotect: fakeUnprotect, sleep: noSleep });
  assert.equal(r.ok, true);
  assert.equal(r.keysDestroyed, true);
  assert.deepEqual(r.filesLeft, [busy]);
  // Открытый файл перед удалением затёрт.
  assert.notEqual(fs.readFileSync(busy, 'utf8'), 'открытый кэш окна');
  assert.ok(!fs.existsSync(path.join(w.dataDir, 'report.json')));
});

test('wipeAll: ключ не удалился - ok:false', async () => {
  const w = await world();
  const keyFile = path.join(w.dataDir, KEY_FILE);
  const lockedFs = { ...fs, unlinkSync: (p) => { if (p === keyFile) { const e = new Error('EPERM'); e.code = 'EPERM'; throw e; } return fs.unlinkSync(p); } };
  const r = await wipe.wipeAll({ dataDir: w.dataDir, root: w.root, env: w.env, fs: lockedFs, unprotect: fakeUnprotect, sleep: noSleep });
  assert.equal(r.ok, false);
  assert.equal(r.keysDestroyed, false);
  assert.ok(r.filesLeft.includes(keyFile));
  // Содержимое ключа всё равно затёрто случайными байтами.
  assert.throws(() => JSON.parse(fs.readFileSync(keyFile, 'utf8')));
});

test('wipeAll: записи отката и ответы помощника - только с --admin; отказ в UAC виден в ответе', async () => {
  const w = await world();
  const undo = path.join(w.env.ProgramData, 'Adamant', 'undo');
  const out = path.join(w.env.ProgramData, 'Adamant', 'helper', 'out');
  fs.mkdirSync(undo, { recursive: true });
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'security.json'), '{}');
  const a = await wipe.wipeAll({ dataDir: w.dataDir, root: w.root, env: w.env, unprotect: fakeUnprotect, sleep: noSleep });
  assert.deepEqual(a.filesLeft, [undo, out]);

  const w2 = await world();
  w2.env.ProgramData = w.env.ProgramData;
  let asked = 0;
  const b = await wipe.wipeAll({ dataDir: w2.dataDir, root: w2.root, env: w2.env, admin: true, unprotect: fakeUnprotect, sleep: noSleep,
    runAdmin: async () => { asked++; const e = new Error('отклонён'); e.code = 'CANCELLED'; throw e; } });
  assert.equal(asked, 1);
  assert.equal(b.admin, 'cancelled');
  assert.equal(b.ok, true);
  assert.deepEqual(b.filesLeft, [undo, out]);

  const w3 = await world();
  const c = await wipe.wipeAll({ dataDir: w3.dataDir, root: w3.root, env: w3.env, admin: true, unprotect: fakeUnprotect, sleep: noSleep, runAdmin: async () => ({ ok: true, removed: 3, left: [] }) });
  assert.deepEqual(c.filesLeft, []);
});

test('createWiper (кнопка в окне): приманки, ключ и забыть его в памяти; остальное - отдельный процесс', async () => {
  const w = await world();
  let spawned = 0;
  let stopped = 0;
  const wiper = wipe.createWiper({ dataDir: w.dataDir, root: w.root, env: w.env, vault: w.vault, canary: w.canary, stopWatchers: () => { stopped++; }, spawnCli: () => { spawned++; }, delayMs: 0 });
  const r = await wiper.run({ admin: false });
  assert.equal(r.ok, true);
  assert.equal(r.keysDestroyed, true);
  assert.equal(r.decoysRemoved, NAMES.length);
  assert.equal(stopped, 1);
  assert.equal(w.vault.state().state, 'wiped');
  assert.ok(!w.vault.ready());
  assert.ok(!fs.existsSync(path.join(w.dataDir, KEY_FILE)));
  // Запись после уничтожения - только в память, на диск ничего не попадает.
  w.store.write('history.json', [{ secret: 'after-wipe' }]);
  assert.ok(!fs.existsSync(path.join(w.dataDir, 'history.json')));
  await new Promise((res) => setTimeout(res, 20));
  assert.equal(spawned, 1);
});

test('POST /api/wipe: без слова - отказ; со словом - уничтожение, дальше программа ничего не запускает', async () => {
  const { createApp } = require('../server/app');
  const http = require('node:http');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-wipe-api-'));
  const calls = [];
  const app = createApp({ store: createStore(dir), key: 'k', version: '1.0.0-test', runner: {}, wiper: { run: async (o) => { calls.push(o); return { ok: true, keysDestroyed: true, decoysRemoved: 0, adminLeft: [] }; } } });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  const post = (route, body) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: route, method: 'POST', headers: { 'X-Adamant-Key': 'k', 'Content-Type': 'application/json', Host: `127.0.0.1:${port}` } }, (res) => {
      let t = '';
      res.on('data', (c) => { t += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: t ? JSON.parse(t) : null }));
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
  try {
    assert.equal((await post('/api/wipe', { word: 'да' })).status, 400);
    assert.equal((await post('/api/wipe', {})).status, 400);
    assert.equal(calls.length, 0);
    const r = await post('/api/wipe', { word: ' уничтожить ', admin: true });
    assert.equal(r.status, 200);
    assert.equal(r.body.keysDestroyed, true);
    assert.deepEqual(calls, [{ admin: true }]);
    assert.equal(app.state.busy, 'wiped');
    assert.equal((await post('/api/wipe', { word: 'УНИЧТОЖИТЬ' })).status, 409);
  } finally {
    await new Promise((r) => app.server.close(r));
  }
});

test('wipe.js из командной строки: неверный вызов - код 2; иначе одна строка JSON и папки нет', () => {
  let code = 0;
  let out = '';
  try { execFileSync(process.execPath, [path.join(ROOT, 'server', 'wipe.js')], { encoding: 'utf8' }); } catch (e) { code = e.status; out = e.stdout; }
  assert.equal(code, 2);
  assert.equal(JSON.parse(out).ok, false);

  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-wipe-cli-'));
  const dataDir = path.join(base, 'data');
  fs.mkdirSync(dataDir);
  fs.writeFileSync(path.join(dataDir, 'settings.json'), '{"lang":"ru"}');
  fs.writeFileSync(path.join(dataDir, KEY_FILE), '{"v":1}');
  fs.writeFileSync(path.join(dataDir, 'report.json'), Buffer.concat([Buffer.from('ADMENC1\0', 'latin1'), Buffer.alloc(64, 1)]));
  const text = execFileSync(process.execPath, [path.join(ROOT, 'server', 'wipe.js'), '--wipe-all', '--yes', `--data=${dataDir}`], { encoding: 'utf8', timeout: 90_000 });
  const lines = text.trim().split(/\r?\n/);
  assert.equal(lines.length, 1, text);
  const r = JSON.parse(lines[0]);
  assert.equal(r.ok, true);
  assert.equal(r.keysDestroyed, true);
  assert.ok(Array.isArray(r.filesLeft));
  assert.ok(!r.filesLeft.some((f) => f.startsWith(dataDir)), JSON.stringify(r.filesLeft));
  assert.ok(!fs.existsSync(dataDir));
});

test('регистрация камня: %LOCALAPPDATA%\\DataDiver\\stones\\adamant.json по договору, без лишних перезаписей', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-stone-'));
  const env = { LOCALAPPDATA: base };
  const dataDir = path.join(base, 'Adamant');
  const root = path.join(base, 'Programs', 'Adamant');
  assert.equal(stones.register({ dataDir, version: '1.2.6', root, node: 'C:\\node.exe', env }), true);
  const file = path.join(base, 'DataDiver', 'stones', 'adamant.json');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(j, { id: 'adamant', name: 'Адамант', version: '1.2.6', wipe: ['C:\\node.exe', path.join(root, 'server', 'wipe.js'), '--wipe-all', '--yes', `--data=${dataDir}`], dataDirs: [dataDir] });
  assert.equal(stones.register({ dataDir, version: '1.2.6', root, node: 'C:\\node.exe', env }), false);
  assert.equal(stones.register({ dataDir, version: '1.2.7', root, node: 'C:\\node.exe', env }), true);
  assert.equal(stones.register({ dataDir, version: '1', root, env: {} }), false);
});

test('сценарии: wipe-procs закрывает только свои процессы, wipe-admin не идёт по ссылкам; удаление программы убирает регистрацию', () => {
  const procs = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'wipe-procs.ps1'), 'utf8');
  for (const s of ['tray\\.ps1', 'index\\.js.*--data=', '--user-data-dir=', '$p.ProcessId -eq $self', '[regex]::Escape']) assert.ok(procs.includes(s), s);
  assert.doesNotMatch(procs, /Remove-Item|Set-ItemProperty|New-Item/);
  const admin = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'wipe-admin.ps1'), 'utf8');
  for (const s of ['ReparsePoint', 'GetOwner', "Join-Path $Base 'undo'", "'helper\\out'"]) assert.ok(admin.includes(s), s);
  assert.doesNotMatch(admin, /Set-MpPreference|Disable-|Stop-Service|schtasks/);
  const un = fs.readFileSync(path.join(ROOT, 'windows', 'uninstall-app.ps1'), 'utf8');
  assert.ok(un.includes("DataDiver\\stones\\adamant.json"));
  const idx = fs.readFileSync(path.join(ROOT, 'server', 'index.js'), 'utf8');
  assert.ok(idx.includes('register({ dataDir: cfg.dataDir'));
});
