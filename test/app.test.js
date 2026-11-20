'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createApp } = require('../server/app');
const { createStore } = require('../server/store');
const { bad, good, NOW } = require('./fixtures/facts');

const KEY = 'test-key-0123456789abcdef';

// Свой ключ автора для тестов: по умолчанию тесты идут в полной версии, opts.free - в бесплатной.
const licenseLib = require('../server/license');
const LIC = require('node:crypto').generateKeyPairSync('ed25519');
const LIC_PUB = LIC.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const LIC_PEM = LIC.privateKey.export({ type: 'pkcs8', format: 'pem' });
const fullKey = (over = {}) => licenseLib.issue({ licensee: 'Тест', ...over }, LIC_PEM);

function request(port, { method = 'GET', route = '/', headers = {}, body, host } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({
      host: '127.0.0.1', port, method, path: route,
      headers: { Host: host || `127.0.0.1:${port}`, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': data.length } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* не JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function setup(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-test-'));
  const store = createStore(dir);
  if (!opts.free) store.write('license.json', { key: fullKey() });
  const calls = { fix: [], collect: [], autorun: [], open: [], bluetooth: [] };
  let facts = opts.facts || bad();
  const btRaw = () => (opts.bluetooth || { format: 'adamant-bluetooth', at: '2026-11-18T12:00:00.000Z', seconds: 10, radio: { present: true, on: true }, paired: [{ name: 'BadUSB test', mac: 'a1b2c3d4e5f6', hid: true, status: 'OK' }], nearby: [{ addr: '112233445566', rssi: -50, n: 3, mf: ['004C:1219'] }] });
  const runner = {
    collect: async (full) => { calls.collect.push(full); if (opts.cancel && full) { const e = new Error('отменено'); e.code = 'CANCELLED'; throw e; } return { ...facts, isAdmin: !!full }; },
    adapters: async () => [{ alias: 'Ethernet', address: '192.168.7.10', prefix: 24, gateway: '192.168.7.1', hardware: true, virtual: false, status: 'Up' }],
    neighbors: async () => (opts.neighbors || []),
    traffic: async () => (opts.traffic || { format: 'adamant-traffic', adapters: [], tcp: [], at: '2026-11-18T12:00:00.000Z' }),
    bluetooth: async (sec) => { calls.bluetooth.push(sec); return btRaw(); },
    probe: async (ip, port) => (ip === '192.168.7.1' && port === 80 ? 'open' : 'filtered'),
    httpInfo: async () => null,
    fix: async (args) => { calls.fix.push(args); return args[1] === 'apply' ? { ok: true, record: '0f8fad5b-d9cb-469f-a165-70867728950e', changes: [{ what: 'x', from: 'a', to: 'b' }] } : { ok: true, changes: [] }; },
  };
  const app = createApp({
    store, key: KEY, version: '1.0.0-test', runner, now: () => NOW,
    autorun: { set: async (on) => calls.autorun.push(on) }, openTarget: (t) => calls.open.push(t),
    drills: opts.drills, canary: opts.canary, away: opts.away, helper: opts.helper, licensePublicKey: LIC_PUB,
  });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  const api = (method, route, body, extra = {}) => request(port, { method, route, body, headers: { 'X-Adamant-Key': KEY, ...extra } });
  return { app, port, api, calls, store, dir, setFacts: (f) => { facts = f; }, close: () => new Promise((r) => app.server.close(r)) };
}

test('без ключа, с чужим ключом или чужим Host - отказ', async () => {
  const s = await setup();
  try {
    assert.equal((await request(s.port, { route: '/api/state' })).status, 401);
    assert.equal((await request(s.port, { route: '/api/state', headers: { 'X-Adamant-Key': 'wrong' } })).status, 401);
    assert.equal((await request(s.port, { route: '/api/state', headers: { 'X-Adamant-Key': KEY }, host: 'evil.example:80' })).status, 421);
    assert.equal((await request(s.port, { route: '/api/state', headers: { 'X-Adamant-Key': KEY }, host: `rebind.example:${s.port}` })).status, 421);
    assert.equal((await s.api('GET', '/api/state')).status, 200);
    // Статус без ключа - только имя и версия.
    const st = await request(s.port, { route: '/api/status' });
    assert.deepEqual(st.json, { app: 'adamant', version: '1.0.0-test' });
  } finally {
    await s.close();
  }
});

test('ничего не кэшируется: no-store на всех ответах, у окна почти нулевой кэш', async () => {
  const s = await setup();
  try {
    await s.api('POST', '/api/check', {}, { Origin: `http://127.0.0.1:${s.port}` });
    const all = [
      await s.api('GET', '/api/state'),
      await request(s.port, { route: '/' }),
      await request(s.port, { route: '/app.js' }),
      await request(s.port, { route: '/api/state' }), // 401
      await request(s.port, { route: '/api/status' }),
      await s.api('GET', '/report.html'),
    ];
    for (const r of all) assert.equal(r.headers['cache-control'], 'no-store', `${r.status} ${r.text.slice(0, 40)}`);
    assert.ok(all[0].json.report, 'отчёт в ответе есть - тем важнее, чтобы он не оседал в кэше окна');
  } finally {
    await s.close();
  }
  const launch = fs.readFileSync(path.join(__dirname, '..', 'server', 'launch.js'), 'utf8');
  assert.ok(launch.includes("'--disk-cache-size=1', '--media-cache-size=1'"), 'флаги окна против дискового кэша');
});

test('POST: только JSON и только со своего Origin', async () => {
  const s = await setup();
  try {
    const form = await request(s.port, { method: 'POST', route: '/api/check', headers: { 'X-Adamant-Key': KEY, 'Content-Type': 'text/plain' } });
    assert.equal(form.status, 415);
    const cross = await s.api('POST', '/api/check', {}, { Origin: 'http://evil.example' });
    assert.equal(cross.status, 403);
    const same = await s.api('POST', '/api/check', {}, { Origin: `http://127.0.0.1:${s.port}` });
    assert.equal(same.status, 200);
  } finally {
    await s.close();
  }
});

test('страница отдаётся со строгой CSP, неизвестные файлы - 404', async () => {
  const s = await setup();
  try {
    const r = await request(s.port, { route: '/' });
    assert.equal(r.status, 200);
    assert.match(r.headers['content-security-policy'], /script-src 'self'/);
    assert.match(r.headers['content-security-policy'], /connect-src 'self'/);
    assert.match(r.text, /<div id="app">/);
    assert.equal((await request(s.port, { route: '/../package.json' })).status, 404);
    assert.equal((await request(s.port, { route: '/server/app.js' })).status, 404);
    // Картинки окна: значок и камень из public/img.
    for (const route of ['/favicon.png', '/img/diamond.png']) {
      const img = await request(s.port, { route });
      assert.equal(img.status, 200, route);
      assert.equal(img.headers['content-type'], 'image/png', route);
    }
    assert.equal((await request(s.port, { route: '/img/../../package.json' })).status, 404);
  } finally {
    await s.close();
  }
});

test('проверка сохраняет отчёт; полная проверка переносит сведения администратора', async () => {
  const s = await setup();
  try {
    const f = bad();
    f.boot.bcdFirmware = 'Firmware Boot Manager\n---\nidentifier {fwbootmgr}\ndisplayorder {bootmgr}\n';
    s.setFacts(f);
    const full = await s.api('POST', '/api/check', { full: true });
    assert.equal(full.status, 200);
    assert.equal(full.json.full, true);
    assert.ok(full.json.findings.length > 10);
    assert.ok(full.json.newAlerts.includes('firewall-off'));
    const f2 = bad();
    s.setFacts(f2);
    const normal = await s.api('POST', '/api/check', { full: false });
    assert.equal(normal.json.full, false);
    assert.ok(normal.json.fullAt, 'сведения администратора перенесены');
    assert.ok(normal.json.facts.boot.bcdFirmware);
    assert.equal(normal.json.newAlerts.length, 0, 'повторные находки - не новые');
    const state = await s.api('GET', '/api/state');
    assert.equal(state.json.report.at, normal.json.at);
  } finally {
    await s.close();
  }
});

test('отказ в окне UAC - понятная ошибка, а не сбой', async () => {
  const s = await setup({ cancel: true });
  try {
    const r = await s.api('POST', '/api/check', { full: true });
    assert.equal(r.status, 400);
    assert.equal(r.json.code, 'CANCELLED');
  } finally {
    await s.close();
  }
});

test('исправление: план, применение, запись в журнал, откат', async () => {
  const s = await setup();
  try {
    assert.equal((await s.api('POST', '/api/fix/plan', { id: 'firewall-on' })).status, 409, 'без проверки исправлять нечего');
    await s.api('POST', '/api/check', {});
    const plan = await s.api('POST', '/api/fix/plan', { id: 'firewall-on' });
    assert.equal(plan.status, 200);
    assert.equal(plan.json.changes.length, 3);
    assert.equal(s.calls.fix.length, 0, 'план ничего не применяет');
    assert.equal((await s.api('POST', '/api/fix/plan', { id: 'format-c' })).status, 400);
    const ap = await s.api('POST', '/api/fix/apply', { id: 'firewall-on' });
    assert.equal(ap.status, 200);
    assert.deepEqual(s.calls.fix[0], ['-Action', 'apply', '-Id', 'firewall-on']);
    const j = (await s.api('GET', '/api/state')).json.journal;
    assert.equal(j.length, 1);
    assert.equal(j[0].record, '0f8fad5b-d9cb-469f-a165-70867728950e');
    assert.equal((await s.api('POST', '/api/fix/undo', { record: 'ffffffff-ffff-ffff-ffff-ffffffffffff' })).status, 404, 'откат только записей из журнала');
    const un = await s.api('POST', '/api/fix/undo', { record: j[0].record });
    assert.equal(un.status, 200);
    assert.deepEqual(s.calls.fix[1], ['-Action', 'undo', '-Record', j[0].record]);
    assert.ok((await s.api('GET', '/api/state')).json.journal[0].undoneAt);
    assert.equal((await s.api('POST', '/api/fix/undo', { record: j[0].record })).status, 409, 'второй откат запрещён');
  } finally {
    await s.close();
  }
});

test('отключение автозагрузки: аргумент проверяется по сведениям', async () => {
  const s = await setup();
  try {
    await s.api('POST', '/api/check', {});
    assert.equal((await s.api('POST', '/api/fix/apply', { id: 'autostart-off', arg: { loc: 'HKCU-Run', name: 'Нет такой' } })).status, 400);
    assert.equal(s.calls.fix.length, 0);
    assert.equal((await s.api('POST', '/api/fix/apply', { id: 'autostart-off', arg: { loc: 'HKCU-Run', name: 'Updater' } })).status, 200);
    const arg = JSON.parse(Buffer.from(s.calls.fix[0][5], 'base64').toString('utf8'));
    assert.deepEqual(arg, { loc: 'HKCU-Run', name: 'Updater', userSid: bad().autostart.userSid });
  } finally {
    await s.close();
  }
});

test('открыть окно Windows - только из списка', async () => {
  const s = await setup();
  try {
    assert.equal((await s.api('POST', '/api/open', { target: 'windowsupdate' })).status, 200);
    assert.equal((await s.api('POST', '/api/open', { target: 'cmd.exe' })).status, 400);
    assert.equal((await s.api('POST', '/api/open', { target: 'constructor' })).status, 400);
    assert.deepEqual(s.calls.open, ['windowsupdate']);
    const g = await s.api('POST', '/api/guide', { id: 'bios-password' });
    assert.equal(g.status, 200);
    assert.ok(g.json.steps.length > 3);
  } finally {
    await s.close();
  }
});

test('сеть: подсети и проверка только выбранной своей подсети', async () => {
  const s = await setup();
  try {
    const subs = (await s.api('GET', '/api/net/subnets')).json;
    assert.deepEqual(subs.map((x) => x.id), ['192.168.7.0/24']);
    assert.equal((await s.api('POST', '/api/net/scan', { selected: ['8.8.8.0/24'] })).status, 400);
    const r = await s.api('POST', '/api/net/scan', { selected: ['192.168.7.0/24'] });
    assert.equal(r.status, 200);
    assert.equal(r.json.result.hosts[0].ip, '192.168.7.1');
    assert.equal(r.json.findings[0].id, 'lan-router-http');
  } finally {
    await s.close();
  }
});

test('сеть и трафик: обновление по запросу, адреса сайтов только в памяти, знакомые устройства на диске', async () => {
  const s = await setup({
    neighbors: [{ ip: '192.168.7.1', mac: '50-FF-20-A1-89-C8', state: 'Reachable', ifIndex: 5 }],
    traffic: {
      format: 'adamant-traffic', at: '2026-11-18T12:00:00.000Z',
      adapters: [{ alias: 'Ethernet', description: 'Realtek', ifIndex: 5, status: 'Up', media: '802.3', ipv4: ['192.168.7.10'], gateway: '192.168.7.1', category: 'Private' }],
      tcp: [{ la: '192.168.7.10', lp: 50000, ra: '93.184.216.34', rp: 443, state: 'Established', pid: 9 }],
      procs: { 9: { name: 'firefox', path: 'C:\\Program Files\\Mozilla Firefox\\firefox.exe' } },
      dns: [{ name: 'example.com', ip: '93.184.216.34' }],
    },
  });
  try {
    assert.deepEqual((await s.api('GET', '/api/net/traffic')).json, { traffic: null });
    const r = await s.api('POST', '/api/net/traffic', {});
    assert.equal(r.status, 200);
    assert.equal(r.json.outgoing[0].remotes[0].host, 'example.com');
    assert.equal(r.json.devices[0].gateway, true);
    assert.equal((await s.api('GET', '/api/net/traffic')).json.traffic.at, r.json.at);
    const files = fs.readdirSync(s.store.dataDir);
    assert.ok(files.includes('net-devices.json'));
    assert.ok(!files.some((f) => /traffic/.test(f)), 'соединения и адреса сайтов на диск не пишутся');
    const dev = JSON.parse(fs.readFileSync(path.join(s.store.dataDir, 'net-devices.json'), 'utf8'));
    assert.deepEqual(Object.keys(dev.devices), ['50-FF-20-A1-89-C8']);

    // Подпись устройства: хранится по MAC, переживает обновление, пустая - убирает.
    const lb = await s.api('POST', '/api/net/device-label', { mac: '50:ff:20:a1:89:c8', label: '  Роутер\u0007 в  коридоре  ' });
    assert.equal(lb.status, 200);
    assert.deepEqual(lb.json, { mac: '50-FF-20-A1-89-C8', label: 'Роутер в коридоре' });
    assert.equal((await s.api('GET', '/api/net/traffic')).json.traffic.devices[0].label, 'Роутер в коридоре');
    const again = await s.api('POST', '/api/net/traffic', {});
    assert.equal(again.json.devices[0].label, 'Роутер в коридоре');
    assert.equal(again.json.devices[0].isNew, false);
    assert.equal((await s.api('POST', '/api/net/device-label', { mac: 'не MAC', label: 'x' })).status, 400);
    assert.equal((await s.api('POST', '/api/net/device-label', { mac: '50-FF-20-A1-89-C8', label: { x: 1 } })).status, 400);
    assert.equal((await s.api('POST', '/api/net/device-label', { mac: '50-FF-20-A1-89-C8', label: '' })).json.label, null);
    const dev2 = JSON.parse(fs.readFileSync(path.join(s.store.dataDir, 'net-devices.json'), 'utf8'));
    assert.equal(dev2.devices['50-FF-20-A1-89-C8'].label, undefined);
    assert.ok(dev2.devices['50-FF-20-A1-89-C8'].first, 'дата первого появления сохраняется');
  } finally {
    await s.close();
  }
});

test('настройки: язык и работа в фоне (автозапуск включается только при изменении)', async () => {
  const s = await setup({ facts: good() });
  try {
    assert.equal((await s.api('POST', '/api/settings', { lang: 'en' })).json.lang, 'en');
    assert.equal((await s.api('POST', '/api/settings', { lang: 'de' })).json.lang, 'en');
    assert.deepEqual(s.calls.autorun, []);
    assert.equal((await s.api('POST', '/api/settings', { background: true })).json.background, true);
    await s.api('POST', '/api/settings', { background: true });
    assert.deepEqual(s.calls.autorun, [true]);
    const tray = (await s.api('GET', '/api/tray')).json;
    assert.equal(tray.exit, false);
    assert.equal(tray.lang, 'en');
  } finally {
    await s.close();
  }
});

test('отчёт HTML: экранирование и английский язык', async () => {
  const s = await setup();
  try {
    const f = bad();
    f.meta.computer = '<img src=x onerror=alert(1)>';
    s.setFacts(f);
    await s.api('POST', '/api/check', {});
    const r = await s.api('GET', '/api/report.html');
    assert.equal(r.status, 200);
    assert.match(r.headers['content-disposition'], /attachment; filename="adamant-report-[A-Za-z0-9._-]+\.html"/);
    assert.ok(!r.text.includes('<img src=x'), 'имя компьютера экранировано');
    assert.ok(r.text.includes('&lt;img'));
    assert.ok(!/<script/i.test(r.text), 'в отчёте нет скриптов');
    await s.api('POST', '/api/settings', { lang: 'en' });
    const en = await s.api('GET', '/api/report.html');
    assert.match(en.text, /<html lang="en">/);
  } finally {
    await s.close();
  }
});

test('индекс, Страж, учения, приманки и тревоги', async () => {
  const ran = [];
  const canaryCalls = [];
  const drills = {
    run: async (ids) => { ran.push(ids); return { at: new Date(NOW).toISOString(), results: [], passed: 1, total: 1, headline: 'ok' }; },
    last: () => null,
  };
  const canary = {
    arm: async () => canaryCalls.push('arm'), watch: () => canaryCalls.push('watch'),
    stop: () => canaryCalls.push('stop'), disarm: async () => canaryCalls.push('disarm'),
    status: () => ({ armed: canaryCalls.includes('arm') && !canaryCalls.includes('disarm'), files: [] }),
  };
  const s = await setup({ drills, canary });
  try {
    const r = await s.api('POST', '/api/check', { full: false });
    assert.equal(r.status, 200);
    assert.ok(r.json.score && typeof r.json.score.value === 'number', 'в отчёте есть индекс');
    assert.ok(r.json.guard && r.json.guard.first, 'первая проверка - Страж запоминает систему');
    let st = (await s.api('GET', '/api/state')).json;
    assert.equal(st.history.length, 1);
    assert.ok(st.guard && st.guard.weekly && typeof st.guard.weekly.calm === 'boolean');
    assert.ok(Array.isArray(st.drillList) && st.drillList.some((d) => d.id === 'eicar'));
    assert.equal((await s.api('POST', '/api/guard/ack', { ids: 'x' })).status, 400);
    assert.equal((await s.api('POST', '/api/guard/ack', { ids: ['nope'] })).status, 200);

    assert.equal((await s.api('POST', '/api/drills/run', {})).status, 200);
    assert.equal(ran.length, 1);

    assert.equal((await s.api('POST', '/api/canary', { on: true })).status, 200);
    assert.deepEqual(canaryCalls, ['arm', 'watch']);
    assert.equal((await s.api('GET', '/api/state')).json.settings.canary, true);
    await s.api('POST', '/api/canary', { on: false });
    assert.deepEqual(canaryCalls.slice(2), ['stop', 'disarm']);

    // Тревога видна в окне (heartbeat) и в трее; «Понятно» её снимает.
    s.app.raiseAlert({ kind: 'canary', files: [{ path: 'D:/docs/decoy.docx', change: 'modified' }] });
    assert.equal((await s.api('POST', '/api/heartbeat', {})).json.alerts, 1);
    assert.equal((await s.api('GET', '/api/tray')).json.alerts.length, 1);
    await s.api('POST', '/api/alerts/ack', {});
    st = (await s.api('GET', '/api/state')).json;
    assert.equal(st.alerts.length, 0);
  } finally {
    await s.close();
  }
});

test('«Пока вас не было» и помощник администратора: маршруты', async () => {
  const events = [];
  const away = {
    event: (e) => { if (e.kind === 'bad') { const x = new Error('kind'); x.status = 400; throw x; } events.push(e); return { ok: true, recorded: true }; },
    photoDone: (b) => ({ ok: true, saved: b.ok }),
    acknowledge: (ids) => ({ ok: true, confirmed: ids.length }),
    photoData: (id) => (id === 'a'.repeat(32) ? 'data:image/jpeg;base64,AA==' : null),
    photoRequest: () => ({ id: 'b'.repeat(32) }),
    report: () => ({ enabled: true, spans: [], last: null }),
  };
  const helperCalls = [];
  const helper = {
    status: async () => ({ installed: helperCalls.includes('install'), trusted: true }),
    install: async ({ userSid }) => { helperCalls.push('install'); return { ok: true, userSid }; },
    uninstall: async () => { const e = new Error('UAC'); e.code = 'CANCELLED'; throw e; },
    refresh: async () => { const e = new Error('нет'); e.code = 'HELPER_UNAVAILABLE'; throw e; },
    readFull: async () => null,
    readSecurity: async () => null,
  };
  const s = await setup({ away, helper });
  try {
    assert.equal((await s.api('POST', '/api/away/event', { kind: 'lock', at: new Date(NOW).toISOString() })).status, 200);
    assert.equal((await s.api('POST', '/api/away/event', { kind: 'bad' })).status, 400, 'неверное событие - 400, а не сбой');
    assert.equal(events.length, 1);
    assert.equal((await s.api('POST', '/api/away/photo-data', { id: 'a'.repeat(32) })).json.data, 'data:image/jpeg;base64,AA==');
    assert.equal((await s.api('POST', '/api/away/ack', { ids: ['x'] })).json.confirmed, 1);
    // Трей получает запрос фото, только если слежение включено в настройках.
    let tray = (await s.api('GET', '/api/tray')).json;
    assert.equal(tray.away, false);
    await s.api('POST', '/api/settings', { away: true, awayPhoto: true });
    tray = (await s.api('GET', '/api/tray')).json;
    assert.equal(tray.away, true);
    assert.equal(tray.photo, 'b'.repeat(32));
    assert.ok((await s.api('GET', '/api/state')).json.away.enabled);

    // Без помощника полная проверка идёт как раньше (через UAC); сведения помощника подмешиваются без сбоев.
    const r = await s.api('POST', '/api/check', { full: true });
    assert.equal(r.status, 200);
    assert.equal(s.calls.collect.at(-1), true);
    const inst = await s.api('POST', '/api/helper/install', {});
    assert.equal(inst.status, 200);
    assert.equal(inst.json.status.installed, true);
    const un = await s.api('POST', '/api/helper/uninstall', {});
    assert.equal(un.status, 400);
    assert.equal(un.json.code, 'CANCELLED');
  } finally {
    await s.close();
  }
});

test('Bluetooth: проверка по кнопке, результат только в памяти, попадает в чек-лист', async () => {
  const s = await setup();
  try {
    assert.deepEqual((await s.api('GET', '/api/bluetooth')).json, { bluetooth: null });
    const r = await s.api('POST', '/api/bluetooth', {});
    assert.equal(r.status, 200);
    assert.equal(r.json.findings.find((f) => f.id === 'bt-attack-paired').sev, 'critical');
    assert.equal((await s.api('GET', '/api/bluetooth')).json.bluetooth.at, r.json.at);
    const files = fs.readdirSync(s.dir);
    assert.ok(!files.some((f) => /bluetooth/i.test(f)), 'адреса устройств рядом на диск не пишутся');
    const cl = await s.api('GET', '/api/checklist');
    assert.equal(cl.json.items.find((i) => i.id === 'bluetooth').state, 'todo');
  } finally {
    await s.close();
  }
});

test('чек-лист: состояние по проверке и отметки пользователя', async () => {
  const s = await setup();
  try {
    let cl = await s.api('GET', '/api/checklist');
    assert.equal(cl.status, 200);
    assert.equal(cl.json.checked, false);
    assert.ok(cl.json.groups.length >= 5);
    assert.ok(cl.json.items.every((i) => i.state === null && i.marked === null), 'до проверки программа ничего не знает');
    await s.api('POST', '/api/check', { full: false });
    cl = await s.api('GET', '/api/checklist');
    assert.equal(cl.json.checked, true);
    assert.ok(cl.json.items.some((i) => i.state === 'todo'), 'по плохим фактам есть что сделать');
    // Отметка пользователя.
    const m = await s.api('POST', '/api/checklist', { id: 'backup', done: true });
    assert.equal(m.status, 200);
    assert.ok(m.json.items.find((i) => i.id === 'backup').marked);
    assert.ok(s.store.read('checklist.json', null).done.backup);
    const un = await s.api('POST', '/api/checklist', { id: 'backup', done: false });
    assert.equal(un.json.items.find((i) => i.id === 'backup').marked, null);
    // Неизвестный пункт и неверное значение - отказ.
    assert.equal((await s.api('POST', '/api/checklist', { id: 'nope', done: true })).status, 400);
    assert.equal((await s.api('POST', '/api/checklist', { id: '__proto__', done: true })).status, 400);
    assert.equal((await s.api('POST', '/api/checklist', { id: 'backup', done: 'yes' })).status, 400);
  } finally {
    await s.close();
  }
});

test('бесплатная версия: платные разделы закрыты на сервере, угрозы не прячутся', async () => {
  const s = await setup({ free: true });
  try {
    const st = (await s.api('GET', '/api/state')).json;
    assert.equal(st.license.edition, 'free');
    assert.deepEqual(st.license.features, { bluetooth: false, entry: false, drills: false, away: false, realtime: false, panic: false, telegram: false, ports: false });
    assert.equal(st.bitlockerPlan, null, 'мастер «Защита входа» закрыт');
    assert.equal(st.away, null);
    for (const [route, body] of [['/api/drills/run', { ids: ['eicar'] }], ['/api/canary', { on: true }], ['/api/settings', { away: true }], ['/api/settings', { awayPhoto: true }], ['/api/away/event', { kind: 'lock' }],
      ['/api/settings', { realtime: true }], ['/api/panic', { mode: 'isolate' }], ['/api/telegram', { token: '123456789:' + 'A'.repeat(35) }], ['/api/telegram', { enabled: true }], ['/api/telegram/find-chat', {}], ['/api/telegram/test', {}]]) {
      const r = await s.api('POST', route, body);
      assert.equal(r.status, 402, route);
      assert.equal(r.json.code, 'PAID');
    }
    assert.equal(s.store.settings().away, false);
    // Выключать можно всегда.
    assert.equal((await s.api('POST', '/api/canary', { on: false })).status === 402, false);
    assert.equal((await s.api('POST', '/api/settings', { away: false, lang: 'ru' })).status, 200);
    // Bluetooth: только сопряжённые, без прослушивания эфира, но тревога об устройстве для атак есть.
    const bt = await s.api('POST', '/api/bluetooth', {});
    assert.equal(bt.status, 200);
    assert.deepEqual(s.calls.bluetooth, [0]);
    assert.equal(bt.json.limited, true);
    assert.deepEqual(bt.json.nearby, []);
    assert.deepEqual(bt.json.paired, []);
    assert.deepEqual(bt.json.findings.map((f) => f.id), ['bt-attack-paired']);
    assert.equal(bt.json.counts.paired, 1);
  } finally {
    await s.close();
  }
});

test('ключ полной версии: проверка подписи, срока, включение и снятие', async () => {
  const s = await setup({ free: true });
  try {
    const bad = async (key) => (await s.api('POST', '/api/license', { key })).status;
    assert.equal(await bad('мусор'), 400);
    assert.equal(await bad(123), 400);
    // Ключ, подписанный чужим ключом.
    const other = require('node:crypto').generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
    assert.equal(await bad(licenseLib.issue({ licensee: 'Пират' }, other)), 400);
    // Подменённые данные при верной подписи.
    const [p, b, sig] = fullKey().split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url')), licensee: 'Другой' })).toString('base64url');
    assert.equal(await bad([p, forged, sig].join('.')), 400);
    assert.equal(await bad(fullKey({ expires: '2020-01-01' })), 400, 'просроченный ключ не принимается');
    assert.equal((await s.api('GET', '/api/license')).json.edition, 'free');
    // Верный ключ (с переносами строк, как из письма).
    const key = fullKey({ licensee: 'Иван П.', expires: '2099-12-31' });
    const ok = await s.api('POST', '/api/license', { key: key.slice(0, 40) + '\n' + key.slice(40) });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.edition, 'full');
    assert.equal(ok.json.licensee, 'Иван П.');
    assert.equal(ok.json.expires, '2099-12-31');
    assert.equal(s.store.read('license.json', null).key, key);
    assert.notEqual((await s.api('POST', '/api/drills/run', { ids: [] })).status, 402);
    await s.api('POST', '/api/bluetooth', {});
    assert.deepEqual(s.calls.bluetooth, [10], 'в полной версии - 10 секунд прослушивания');
    // Снять ключ.
    const off = await s.api('POST', '/api/license', { key: null });
    assert.equal(off.json.edition, 'free');
    assert.equal((await s.api('POST', '/api/drills/run', { ids: [] })).status, 402);
  } finally {
    await s.close();
  }
});
