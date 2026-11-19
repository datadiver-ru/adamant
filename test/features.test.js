'use strict';
/**
 * Версия 1.2: расширения браузеров, скачанные файлы, роутер (UPnP), обновление программ (winget),
 * Страж в реальном времени, «Тревога» и уведомления в Telegram. Всё - без настоящей системы, сети и Telegram.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { render } = require('../server/i18n');
const rulesBrowser = require('../server/rules-browser');
const rulesDownloads = require('../server/rules-downloads');
const upnp = require('../server/upnp');
const winget = require('../server/winget');
const { classify, createRealtime, exeOf } = require('../server/realtime');
const { createTelegram, TOKEN_RE } = require('../server/telegram');
const { createApp } = require('../server/app');
const { createStore } = require('../server/store');
const licenseLib = require('../server/license');

const NOW = Date.parse('2026-11-18T12:00:00.000Z');
const ru = (m) => render('ru', m);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-feat-'));

// ---------------------------------------------------------------- Расширения браузеров

const ext = (over) => ({ id: 'a'.repeat(32), name: 'Ext', version: '1.0', enabled: true, location: 1, store: true, perms: [], ...over });
const browsers = (exts, policies = [], domain = false) => ({ browsers: { list: [{ id: 'chrome', name: 'Google Chrome', profiles: [{ profile: 'Default', extensions: exts }] }], policies, domain } });

test('расширения: в обход магазина, принудительные, доступ ко всем сайтам, всё в порядке', () => {
  const ids = (f) => rulesBrowser.evaluate(f, { now: NOW }).map((x) => `${x.id}:${x.sev}`);
  assert.deepEqual(ids(browsers([ext()])), ['browser-ext-ok:ok']);
  assert.deepEqual(ids(browsers([ext({ unpacked: true, location: 4, store: false })])), ['browser-ext-sideloaded:high']);
  assert.deepEqual(ids(browsers([ext({ updateHost: 'evil.example' })])), ['browser-ext-sideloaded:high']);
  assert.deepEqual(ids(browsers([ext({ updateHost: 'clients2.google.com' })])), ['browser-ext-ok:ok']);
  assert.deepEqual(ids(browsers([ext({ store: false, location: 3 })])), ['browser-ext-sideloaded:high'], 'поставлено другой программой');
  // Принудительное расширение: дома - важно, в домене - совет.
  const pol = [{ browser: 'chrome', forced: [{ id: 'b'.repeat(32), host: 'evil.example' }], values: { HomepageLocation: 'https://start.example/' } }];
  assert.deepEqual(ids(browsers([ext()], pol)), ['browser-ext-forced:high', 'browser-policy-hijack:high']);
  assert.deepEqual(ids(browsers([ext()], pol, true)), ['browser-ext-forced:advice', 'browser-policy-hijack:advice']);
  // Все сайты + опасные возможности - совет, с пометкой о свежей установке.
  const broad = rulesBrowser.evaluate(browsers([ext({ perms: ['<all_urls>', 'cookies', 'webRequest'], installed: '2026-11-15T10:00:00Z' })]), { now: NOW });
  assert.equal(broad[0].id, 'browser-ext-broad');
  assert.match(ru(broad[0].evidence[0]), /все сайты/);
  assert.match(ru(broad[0].evidence[0]), /поставлено 3 дн\. назад/);
  // Все сайты без опасных возможностей - не находка; выключенное - не находка.
  assert.deepEqual(ids(browsers([ext({ perms: ['<all_urls>'] }), ext({ perms: ['<all_urls>', 'cookies'], enabled: false })])), ['browser-ext-ok:ok']);
  // Раздел не собрался - «не удалось проверить».
  assert.equal(rulesBrowser.evaluate({ errors: { browsers: 'x' } }, { now: NOW })[0].sev, 'unknown');
});

// ---------------------------------------------------------------- Скачанные файлы

const dl = (over) => ({ path: 'C:\\Users\\u\\Downloads\\' + (over.name || 'f.exe'), name: 'f.exe', ext: '.exe', zone: 3, sig: 'valid', ...over });

test('скачанные: только файлы из интернета; опасные, без подписи, в порядке', () => {
  const ev = (items) => rulesDownloads.evaluate({ downloads: { items } });
  assert.deepEqual(ev([dl({})]).map((f) => f.id), ['dl-ok']);
  assert.deepEqual(ev([dl({ sig: 'unsigned', zone: 0 })]).map((f) => f.id), ['dl-ok'], 'без отметки «из интернета» не смотрим');
  const r = ev([dl({ name: 'report.pdf.exe', double: true }), dl({ name: 'setup.exe', sig: 'unsigned', host: 'example.com' }), dl({ name: 'x.lnk', ext: '.lnk', sig: null }), dl({ name: 'disk.iso', ext: '.iso', sig: null })]);
  assert.deepEqual(r.map((f) => `${f.id}:${f.sev}`), ['dl-danger:high', 'dl-unsigned:advice']);
  assert.deepEqual(r[0].files.map((x) => x.name), ['report.pdf.exe', 'x.lnk']);
  assert.deepEqual(r[1].files.map((x) => x.name), ['setup.exe', 'disk.iso']);
  assert.match(ru(r[1].evidence[0]), /с сайта example\.com/);
  // Кнопки работают только с путями из находок.
  assert.equal(rulesDownloads.allowedPath(r, r[0].files[0].path).name, 'report.pdf.exe');
  assert.equal(rulesDownloads.allowedPath(r, 'C:\\Windows\\System32\\cmd.exe'), null);
  assert.equal(rulesDownloads.allowedPath(r, ''), null);
  assert.equal(rulesDownloads.fileReason({ ext: '.exe', sig: 'bad' }).sev, 'high');
  assert.equal(rulesDownloads.fileReason({ ext: '.exe', rtlo: true }).sev, 'high');
});

// ---------------------------------------------------------------- Роутер (UPnP)

test('UPnP: ответ SSDP только от адреса своей сети и со своим адресом описания', () => {
  const msg = (loc) => `HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: ${loc}\r\nSERVER: test\r\n\r\n`;
  assert.deepEqual(upnp.parseSsdp(msg('http://192.168.1.1:1900/desc.xml'), '192.168.1.1'), { location: 'http://192.168.1.1:1900/desc.xml', server: 'test' });
  assert.equal(upnp.parseSsdp(msg('http://192.168.1.1:1900/desc.xml'), '192.168.1.7'), null, 'адрес описания не совпадает с отправителем');
  assert.equal(upnp.parseSsdp(msg('http://8.8.8.8/desc.xml'), '8.8.8.8'), null, 'не частный адрес');
  assert.equal(upnp.parseSsdp('HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nLOCATION: http://192.168.1.5/\r\n', '192.168.1.5'), null);
  const d = upnp.parseDescription('<root><device><friendlyName>R</friendlyName><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>', 'http://192.168.1.1:1900/desc.xml');
  assert.ok(d);
});

test('UPnP: находки - выключен, включён без портов, опасный проброс, «серый» адрес', () => {
  assert.equal(upnp.findings(null).length, 0);
  assert.equal(upnp.findings({ found: false })[0].id, 'router-upnp-off');
  const base = { found: true, host: '192.168.1.1', manufacturer: 'Test', model: 'R1', readable: true, externalIp: '100.64.3.4' };
  const on = upnp.findings({ ...base, mappings: [] })[0];
  assert.equal(on.id, 'router-upnp-on');
  assert.equal(on.sev, 'advice');
  assert.ok(on.evidence.some((e) => /серый/.test(ru(e))));
  const rdp = upnp.findings({ ...base, externalIp: '203.0.113.5', mappings: [{ proto: 'TCP', external: 3389, client: '192.168.1.10', internal: 3389, description: 'x', enabled: true }] }, { own: ['192.168.1.10'], listen: [{ port: 3389, proto: 'tcp', proc: 'svchost' }] })[0];
  assert.equal(rdp.id, 'router-upnp-ports');
  assert.equal(rdp.sev, 'critical');
  assert.ok(rdp.evidence.some((e) => /этот компьютер, svchost/.test(ru(e))));
  const game = upnp.findings({ ...base, mappings: [{ proto: 'UDP', external: 27015, client: '192.168.1.11', internal: 27015, enabled: true }] })[0];
  assert.equal(game.sev, 'advice');
  assert.equal(upnp.grayAddress('10.0.0.1'), true);
  assert.equal(upnp.grayAddress('203.0.113.5'), false);
});

// ---------------------------------------------------------------- winget

const WINGET = [
  '   - \r   \\ \r',
  'Name                 Id                    Version      Available    Source',
  '------------------------------------------------------------------------------',
  'Example Browser      Example.Browser       120.0.1      121.0.2      winget\r',
  'Tool With Spaces Pro Vendor.Tool.Pro       2.3          2.4.1        winget',
  'Short                Short.App             < 1.0        1.5          winget',
  '3 upgrades available.',
  '',
  'The following packages have an upgrade available, but require explicit targeting for upgrade:',
  'Name    Id          Version Available Source',
  '--------------------------------------------',
  'Pinned  Pin.App     1.0     2.0       winget',
].join('\n');

test('winget: таблица по столбцам заголовка, крутилка и строка итога не мешают', () => {
  const items = winget.parseUpgrade(WINGET);
  assert.deepEqual(items.map((x) => [x.name, x.id, x.version, x.available]), [
    ['Example Browser', 'Example.Browser', '120.0.1', '121.0.2'],
    ['Tool With Spaces Pro', 'Vendor.Tool.Pro', '2.3', '2.4.1'],
    ['Short', 'Short.App', '< 1.0', '1.5'],
    ['Pinned', 'Pin.App', '1.0', '2.0'],
  ]);
  assert.deepEqual(winget.parseUpgrade(''), []);
  assert.equal(winget.ID_RE.test('Vendor.App'), true);
  assert.equal(winget.ID_RE.test('a b'), false);
  assert.equal(winget.ID_RE.test('--force'), false);
});

// ---------------------------------------------------------------- Страж в реальном времени

test('Страж в реальном времени: что тревожит, а что - шум', () => {
  const own = { autorun: { name: 'Adamant', command: '"C:\\Windows\\System32\\wscript.exe" "C:\\A\\windows\\adamant.vbs" --tray' }, helperDir: 'C:\\Program Files\\Adamant\\Helper' };
  const c = (o) => classify(o, own);
  assert.match(ru(c({ kind: 'autostart', change: 'added', key: 'HKCU-Run|Evil', to: 'C:\\Users\\u\\AppData\\evil.exe' }).text), /Новая программа в автозагрузке: Evil/);
  assert.equal(c({ kind: 'autostart', change: 'added', key: 'HKCU-Run|Adamant', to: own.autorun.command }), null, 'свой автозапуск');
  assert.ok(c({ kind: 'autostart', change: 'added', key: 'HKCU-Run|Adamant', to: 'C:\\evil.exe' }), 'чужая команда под нашим именем');
  assert.equal(c({ kind: 'autostart', change: 'changed', key: 'HKCU-Run|App', from: '"C:\\App\\1.0\\app.exe" -m', to: '"C:\\App\\1.1\\app.exe" -m' }), null, 'обновилась версия программы');
  assert.ok(c({ kind: 'autostart', change: 'changed', key: 'HKCU-Run|App', from: '"C:\\App\\app.exe"', to: 'C:\\Temp\\other.exe' }));
  assert.equal(c({ kind: 'autostart', change: 'removed', key: 'HKCU-Run|App', from: 'x' }), null);
  assert.ok(c({ kind: 'services', change: 'added', key: 'EvilSvc', to: 'C:\\evil.exe' }));
  assert.equal(c({ kind: 'services', change: 'changed', key: 'Svc', from: 'C:\\P\\1\\svc.exe', to: 'C:\\P\\2\\svc.exe' }), null);
  assert.match(ru(c({ kind: 'svcstart', change: 'changed', key: 'WinDefend', from: '2', to: '4' }).text), /Microsoft Defender/);
  assert.equal(c({ kind: 'svcstart', change: 'changed', key: 'WinDefend', from: '4', to: '2' }), null);
  assert.ok(c({ kind: 'tasks', change: 'added', key: '\\Updater', to: 'C:\\evil.exe' }));
  assert.equal(c({ kind: 'tasks', change: 'added', key: '\\Adamant\\Full', to: 'powershell.exe -File "C:\\Program Files\\Adamant\\Helper\\helper-run.ps1"' }), null, 'задача своего помощника');
  assert.ok(c({ kind: 'tasks', change: 'added', key: '\\Adamant\\Fake', to: 'C:\\evil.exe' }), 'чужая задача в нашей папке');
  assert.equal(c({ kind: 'tasks', change: 'changed', key: '\\X', from: 'a', to: 'b' }), null);
  assert.ok(c({ kind: 'admins', change: 'added', key: 'hacker' }));
  assert.equal(c({ kind: 'admins', change: 'removed', key: 'old' }), null);
  assert.ok(c({ kind: 'defender', change: 'changed', key: 'realtime', from: 'on', to: 'off' }));
  assert.equal(c({ kind: 'defender', change: 'changed', key: 'realtime', from: 'off', to: 'on' }), null);
  assert.ok(c({ kind: 'hosts', change: 'changed', key: 'file', from: 'a', to: 'b' }));
  assert.ok(c({ kind: 'proxy', change: 'added', key: 'server', to: '127.0.0.1:8888' }));
  assert.equal(c({ kind: 'nope', change: 'added' }), null);
  assert.equal(c(null), null);
  assert.equal(exeOf('"C:\\a b\\X.EXE" /s'), 'x.exe');
  assert.equal(exeOf('C:\\Windows\\app.exe -k'), 'app.exe');
});

function fakeSpawn() {
  const kids = [];
  const fn = (cmd, args) => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.pid = 0;
    child.args = args;
    child.kill = () => { child.killed = true; child.emit('exit', 0); };
    kids.push(child);
    return child;
  };
  return { fn, kids };
}

test('Страж в реальном времени: пачка тревог, тишина во время своих изменений, остановка', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const sp = fakeSpawn();
  const alerts = [];
  let quiet = false;
  const rt = createRealtime({ onAlert: (items) => alerts.push(items), quiet: () => quiet, spawnFn: sp.fn, script: 'watch.ps1' });
  rt.start();
  assert.equal(sp.kids.length, 1);
  assert.ok(sp.kids[0].args.includes('-ParentPid'));
  const line = (o) => rt._line(JSON.stringify(o));
  line({ ready: true, count: 10 });
  assert.deepEqual(rt.status(), { running: true, ready: true });
  line({ kind: 'admins', change: 'added', key: 'hacker' });
  line({ kind: 'proxy', change: 'added', key: 'server', to: '1.2.3.4:8080' });
  line({ kind: 'autostart', change: 'removed', key: 'HKCU-Run|x', from: 'y' });
  rt._line('мусор');
  t.mock.timers.tick(3000);
  assert.equal(alerts.length, 1);
  assert.deepEqual(alerts[0].map((x) => x.kind), ['admins', 'proxy']);
  quiet = true;
  line({ kind: 'admins', change: 'added', key: 'other' });
  t.mock.timers.tick(3000);
  assert.equal(alerts.length, 1, 'во время своего исправления не тревожим');
  // Процесс упал - перезапуск с паузой; остановка - без перезапуска.
  sp.kids[0].emit('exit', 1);
  assert.equal(sp.kids.length, 1);
  t.mock.timers.tick(30_000);
  assert.equal(sp.kids.length, 2);
  rt.stop();
  assert.equal(sp.kids[1].killed, true);
  t.mock.timers.tick(10 * 60_000);
  assert.equal(sp.kids.length, 2);
  assert.equal(rt.status().running, false);
});

test('watch.ps1 и panic.ps1: UTF-8 с BOM; watch только читает', () => {
  for (const f of ['watch.ps1', 'panic.ps1', 'files.ps1']) {
    const b = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', f));
    assert.deepEqual([...b.subarray(0, 3)], [0xef, 0xbb, 0xbf], f);
  }
  const w = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'watch.ps1'), 'utf8');
  assert.doesNotMatch(w, /\b(Set-|Remove-|New-Item|Disable-|Enable-|Stop-|Start-Process)/);
  const p = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'panic.ps1'), 'utf8');
  assert.match(p, /Get-NetAdapter -Physical/);
  assert.doesNotMatch(p, /Stop-Process|Remove-Item/, '«Тревога» ничего не завершает и не удаляет');
});

// ---------------------------------------------------------------- Telegram

const TOKEN = '123456789:' + 'A'.repeat(35);
function fakeTelegram(updates = []) {
  const calls = [];
  const post = async (base, token, method, body) => {
    calls.push({ base, token, method, body });
    if (token !== TOKEN) { const e = new Error('Unauthorized'); e.code = 'TOKEN'; throw e; }
    if (method === 'getUpdates') return updates;
    return { message_id: calls.length };
  };
  return { post, calls };
}

test('Telegram: выключено по умолчанию, ключ, чат, проверка, события, забыть', async () => {
  const dir = tmp();
  const fk = fakeTelegram([{ message: { chat: { id: 42, type: 'private', first_name: 'Тест' }, text: 'hi' } }, { message: { chat: { id: -5, type: 'group' } } }]);
  const tg = createTelegram({ dataDir: dir, post: fk.post, now: () => NOW });
  assert.equal(tg.status().enabled, false);
  assert.equal((await tg.notifyAlert('guard', 'x')).sent, false, 'выключено - ничего не уходит');
  assert.equal(fk.calls.length, 0);
  assert.throws(() => tg.save({ token: 'not-a-token' }), (e) => e.code === 'FORMAT');
  assert.throws(() => tg.save({ enabled: true }), (e) => e.code === 'SETUP');
  tg.save({ token: TOKEN });
  assert.equal(tg.status().tokenHint, '…AAAA');
  assert.equal(JSON.stringify(tg.status()).includes(TOKEN), false, 'ключ не отдаётся в окно');
  const found = await tg.findChat();
  assert.equal(found.found, true);
  assert.equal(found.chatName, 'Тест');
  await tg.test();
  assert.equal(fk.calls.at(-1).method, 'sendMessage');
  assert.equal(fk.calls.at(-1).body.chat_id, 42);
  tg.save({ enabled: true, events: { guard: false } });
  assert.equal((await tg.notifyAlert('guard', 'x')).sent, false, 'событие выключено');
  const n = fk.calls.length;
  await tg.notifyAlert('canary', 'Тревога');
  assert.equal(fk.calls.length, n + 1);
  assert.match(fk.calls.at(-1).body.text, /Адамант: Тревога/);
  // Файл - только для владельца, ключ внутри.
  assert.ok(fs.readFileSync(path.join(dir, 'telegram.json'), 'utf8').includes(TOKEN));
  tg.save({ forget: true });
  assert.deepEqual([tg.status().hasToken, tg.status().enabled, tg.status().chat], [false, false, false]);
  assert.equal(TOKEN_RE.test(TOKEN), true);
});

test('Telegram: «Пока вас не было» - каждый тревожный отрезок один раз, старые при включении не приходят', async () => {
  const dir = tmp();
  const fk = fakeTelegram([{ message: { chat: { id: 7, type: 'private' } } }]);
  const tg = createTelegram({ dataDir: dir, post: fk.post, now: () => NOW });
  tg.save({ token: TOKEN });
  await tg.findChat();
  const span = (id, level, reasons) => ({ id, level, reasons, confirmed: false, headline: { k: 'Пока вас не было: {0}', a: [id] } });
  const rep = (spans) => ({ spans });
  tg.save({ enabled: true });
  assert.deepEqual(tg.notifyAway(rep([span('old', 'alarm', ['failed'])])), [], 'было до включения');
  const sent = tg.notifyAway(rep([span('old', 'alarm', ['failed']), span('new', 'alarm', ['failed']), span('calm', 'calm', [])]));
  assert.equal(sent.length, 1);
  await Promise.all(sent);
  assert.match(fk.calls.at(-1).body.text, /new/);
  assert.equal(tg.notifyAway(rep([span('new', 'alarm', ['failed'])])).length, 0, 'второй раз не шлём');
  assert.equal(tg.notifyAway(rep([span('new', 'alarm', ['failed', 'usb'])])).length, 1, 'новая причина - новое сообщение');
});

// ---------------------------------------------------------------- Сервер: новые маршруты

const LIC = require('node:crypto').generateKeyPairSync('ed25519');
const LIC_PUB = LIC.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const LIC_PEM = LIC.privateKey.export({ type: 'pkcs8', format: 'pem' });
const KEY = 'test-key-feat-0123456789';

function call(port, method, route, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, method, path: route, headers: { Host: `127.0.0.1:${port}`, 'X-Adamant-Key': KEY, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}) } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* ignore */ } resolve({ status: res.statusCode, json }); });
    });
    req.on('error', reject);
    req.end(data || undefined);
  });
}

async function setup({ free = false } = {}) {
  const dir = tmp();
  const store = createStore(dir);
  if (!free) store.write('license.json', { key: licenseLib.issue({ licensee: 'Тест' }, LIC_PEM) });
  const calls = { panic: [], trash: [], avScan: [], reveal: [], upgrade: [], notify: [] };
  const runner = {
    collect: async () => ({}),
    adapters: async () => [],
    router: async () => ({ found: true, host: '192.168.1.1', readable: true, mappings: [{ proto: 'TCP', external: 445, client: '192.168.1.20', internal: 445, enabled: true }] }),
    avScan: async (f) => { calls.avScan.push(f); return { code: 2, threats: 1, clean: false, failed: false }; },
    reveal: (f) => calls.reveal.push(f),
    trash: async (f) => { calls.trash.push(f); return { ok: true }; },
    wingetList: async () => [{ name: 'A', id: 'Vendor.A', version: '1', available: '2' }, { name: 'B', id: 'Vendor.B', version: '1', available: '3' }],
    wingetUpgrade: async (id) => { calls.upgrade.push(id); return { id, ok: id === 'Vendor.A', reason: id === 'Vendor.A' ? null : 'running', hex: null }; },
    panic: async (mode, names) => { calls.panic.push([mode, names]); return mode === 'isolate' ? { ok: true, adapters: [{ name: 'Ethernet' }, { name: 'Wi-Fi' }], failed: [], processes: [{ pid: 1, name: 'x.exe', path: 'C:\\x.exe', signature: 'NotSigned' }] } : { ok: true, adapters: names.map((n) => ({ name: n })), failed: [] }; },
  };
  const app = createApp({ store, key: KEY, version: 't', runner, now: () => NOW, licensePublicKey: LIC_PUB, notify: (a) => calls.notify.push(a.kind),
    autorun: { name: 'Adamant', command: 'wscript.exe adamant.vbs --tray', set: async () => {} } });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  return { app, store, calls, api: (m, r, b) => call(port, m, r, b), close: () => new Promise((r) => app.server.close(r)) };
}

test('сервер: роутер, скачанные файлы только из находок, обновление программ', async () => {
  const s = await setup();
  try {
    const r = await s.api('POST', '/api/net/router', {});
    assert.equal(r.status, 200);
    assert.equal(r.json.findings[0].id, 'router-upnp-ports');
    assert.equal(r.json.findings[0].sev, 'critical');
    assert.equal((await s.api('GET', '/api/state')).json.router.findings[0].id, 'router-upnp-ports');
    // Файлы: только пути из находок последней проверки.
    const file = 'C:\\Users\\u\\Downloads\\a.pdf.exe';
    s.store.write('report.json', { at: new Date(NOW).toISOString(), facts: {}, findings: [{ id: 'dl-danger', cat: 'downloads', sev: 'high', files: [{ path: file, name: 'a.pdf.exe', why: 'x' }] }], summary: {} });
    for (const route of ['/api/downloads/scan', '/api/downloads/reveal', '/api/downloads/trash']) {
      assert.equal((await s.api('POST', route, { path: 'C:\\Windows\\System32\\cmd.exe' })).status, 400, route);
    }
    assert.deepEqual([s.calls.avScan, s.calls.reveal, s.calls.trash], [[], [], []]);
    const sc = await s.api('POST', '/api/downloads/scan', { path: file });
    assert.deepEqual(sc.json, { name: 'a.pdf.exe', threats: 1, clean: false });
    assert.equal((await s.api('POST', '/api/downloads/trash', { path: file })).json.ok, true);
    assert.deepEqual(s.calls.trash, [file]);
    // winget: сначала список; обновляются только программы из списка.
    assert.equal((await s.api('POST', '/api/apps/upgrade', { ids: ['Vendor.A'] })).status >= 400, true, 'без списка нельзя');
    const list = await s.api('POST', '/api/apps/list', {});
    assert.equal(list.json.items.length, 2);
    assert.equal((await s.api('POST', '/api/apps/upgrade', { ids: ['Other.Unknown'] })).status >= 400, true);
    const up = await s.api('POST', '/api/apps/upgrade', { ids: ['Vendor.A', 'Vendor.B'] });
    assert.equal(up.status, 200);
    for (let i = 0; i < 50 && (await s.api('GET', '/api/apps')).json.progress.running; i += 1) await new Promise((res) => setTimeout(res, 10));
    const st = (await s.api('GET', '/api/apps')).json;
    assert.deepEqual(s.calls.upgrade, ['Vendor.A', 'Vendor.B']);
    assert.deepEqual(st.progress.results.map((x) => x.ok), [true, false]);
    assert.deepEqual(st.list.items.map((x) => x.id), ['Vendor.B'], 'обновлённая программа ушла из списка');
  } finally {
    await s.close();
  }
});

test('сервер: «Тревога» отключает и возвращает сеть, Telegram - до отключения', async () => {
  const s = await setup();
  try {
    assert.equal((await s.api('POST', '/api/panic', { mode: 'restore' })).status, 409, 'нечего возвращать');
    const on = await s.api('POST', '/api/panic', { mode: 'isolate' });
    assert.equal(on.status, 200);
    assert.equal(on.json.panic.active, true);
    assert.deepEqual(s.calls.notify, ['panic']);
    assert.equal((await s.api('POST', '/api/panic', { mode: 'isolate' })).status, 409, 'уже отключено');
    const st = (await s.api('GET', '/api/state')).json;
    assert.equal(st.panic.active, true);
    assert.equal(st.panic.processes[0].name, 'x.exe');
    const off = await s.api('POST', '/api/panic', { mode: 'restore' });
    assert.equal(off.status, 200);
    assert.deepEqual(s.calls.panic.at(-1), ['restore', ['Ethernet', 'Wi-Fi']], 'включаем только то, что выключили');
    assert.equal(off.json.panic.active, false);
  } finally {
    await s.close();
  }
});

test('сервер: тревога Стража - журнал, текст для трея на языке пользователя, тишина после исправления', async () => {
  const s = await setup();
  try {
    s.app.raiseAlert({ kind: 'guard', items: [{ kind: 'admins', change: 'added', key: 'hacker', text: { k: 'Новый администратор компьютера: {0}', a: ['hacker'] } }, { kind: 'proxy', change: 'added', key: 'server', text: 'x' }] });
    const tray = (await s.api('GET', '/api/tray')).json;
    assert.equal(tray.alertInfo[0].kind, 'guard');
    assert.equal(tray.alertInfo[0].text, 'Страж: Новый администратор компьютера: hacker (и ещё 1)');
    assert.equal(s.store.read('realtime-log.json', []).length, 2);
    assert.deepEqual(s.calls.notify, ['guard']);
    await s.api('POST', '/api/settings', { lang: 'en' });
    assert.equal((await s.api('GET', '/api/tray')).json.alertInfo[0].text, 'Guard: New computer administrator: hacker (and 1 more)');
    assert.equal(s.app.isQuiet(), false, 'смена языка - не изменение системы');
  } finally {
    await s.close();
  }
});

test('сервер: свои изменения не тревожат Стража; настройка «Страж в реальном времени»', async () => {
  const s = await setup();
  try {
    assert.equal(s.app.isQuiet(), false);
    await s.api('POST', '/api/settings', { background: true });
    assert.equal(s.app.isQuiet(), true, 'после включения автозапуска - две минуты тишины');
    assert.equal(s.app.ownChanges().autorun.name, 'Adamant');
    assert.equal(s.store.settings().realtime, true, 'по умолчанию включён (работает только в полной версии)');
    assert.equal((await s.api('POST', '/api/settings', { realtime: false })).json.realtime, false);
  } finally {
    await s.close();
  }
});
