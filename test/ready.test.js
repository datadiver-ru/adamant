'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const rules = require('../server/rules');
const ready = require('../server/rules-ready');
const { guide, GUIDES } = require('../server/guides');
const { render } = require('../server/i18n');
const { good, bad, NOW } = require('./fixtures/facts');
const F = require('./fixtures/ready');

const byId = (list) => new Map(list.map((f) => [f.id, f]));
const mine = (list) => list.filter((f) => /^(app|wifi|ready|priv)-/.test(f.id));
const text = (m) => render('ru', m);
const run = (patch) => ready.evaluate({ ...good(), ...patch }, { now: NOW });
const expectSev = (list, expect) => {
  const ids = byId(list);
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}: ${[...ids.keys()].join(', ')}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
};

// ---------------------------------------------------------------- netsh

test('netsh (английский): профили - защита и автоподключение', () => {
  const home = ready.parseNetshProfile(F.EN_PROFILE_HOME);
  assert.equal(home.name, 'HomeNet');
  assert.deepEqual(home.ssids, ['HomeNet']);
  assert.deepEqual(home.auth, ['WPA2-Personal', 'WPA2-Personal']);
  assert.deepEqual(home.cipher, ['CCMP', 'GCMP']);
  assert.equal(home.auto, true);
  assert.equal(home.security, 'ok');
  const cafe = ready.parseNetshProfile(F.EN_PROFILE_CAFE);
  assert.equal(cafe.name, 'Cafe Free WiFi');
  assert.equal(cafe.security, 'open');
  assert.equal(cafe.auto, true);
  const hotel = ready.parseNetshProfile(F.EN_PROFILE_HOTEL_MANUAL);
  assert.equal(hotel.security, 'open');
  assert.equal(hotel.auto, false);
});

test('netsh (русский): профили - WPA3, WEP, TKIP, открытая', () => {
  const home = ready.parseNetshProfile(F.RU_PROFILE_HOME);
  assert.equal(home.name, 'Дом_5G');
  assert.equal(home.security, 'ok');
  assert.equal(home.auto, true);
  const dacha = ready.parseNetshProfile(F.RU_PROFILE_DACHA_WEP);
  assert.equal(dacha.security, 'wep');
  assert.equal(dacha.auto, false);
  assert.deepEqual(dacha.ssids, ['Dacha']);
  assert.equal(ready.parseNetshProfile(F.RU_PROFILE_OFFICE_TKIP).security, 'tkip');
  const v = ready.parseNetshProfile(F.RU_PROFILE_VOKZAL_OPEN);
  assert.equal(v.security, 'open');
  assert.equal(v.auto, true);
  assert.equal(ready.parseNetshProfile('').security, 'unknown');
});

test('netsh: текущее подключение на английском и русском', () => {
  const [en] = ready.parseNetshInterfaces(F.EN_INTERFACES_OPEN);
  assert.equal(en.connected, true);
  assert.equal(en.ssid, 'Cafe Free WiFi');
  assert.equal(en.profile, 'Cafe Free WiFi');
  assert.equal(en.security, 'open');
  const [off] = ready.parseNetshInterfaces(F.EN_INTERFACES_DISCONNECTED);
  assert.equal(off.connected, false, '«disconnected» - не подключено');
  const [ru] = ready.parseNetshInterfaces(F.RU_INTERFACES_CONNECTED);
  assert.equal(ru.name, 'Беспроводная сеть');
  assert.equal(ru.connected, true);
  assert.equal(ru.ssid, 'Дом_5G', 'SSID, а не BSSID');
  assert.equal(ru.security, 'ok');
  assert.equal(ready.parseNetshInterfaces(F.RU_INTERFACES_OPEN)[0].security, 'open');
  assert.deepEqual(ready.parseNetshInterfaces(F.EN_NO_WIFI), []);
});

test('Wi-Fi: открытая сеть сейчас - важно, открытая с автоподключением - совет (английский)', () => {
  const list = run({ wifi: F.wifiBadEn() });
  expectSev(list, { 'wifi-open-now': 'high', 'wifi-open-auto': 'advice' });
  assert.ok(!byId(list).has('wifi-ok'));
  assert.equal(byId(list).get('wifi-open-now').guide, 'wifi-forget');
  assert.match(text(byId(list).get('wifi-open-auto').evidence[0]), /Cafe Free WiFi/);
  expectSev(run({ wifi: F.wifiGoodEn() }), { 'wifi-ok': 'ok' });
  assert.equal(mine(run({ wifi: F.wifiGoodEn() })).filter((f) => f.id.startsWith('wifi-') && f.sev !== 'ok').length, 0, 'открытая сеть без автоподключения - не находка');
});

test('Wi-Fi: WEP и TKIP - важно (русский)', () => {
  const list = run({ wifi: F.wifiBadRu() });
  expectSev(list, { 'wifi-open-now': 'high', 'wifi-weak': 'high', 'wifi-open-auto': 'advice' });
  const ev = byId(list).get('wifi-weak').evidence.map(text);
  assert.ok(ev.some((e) => /Дача.*WEP/.test(e)), ev.join('; '));
  assert.ok(ev.some((e) => /Офис.*TKIP/.test(e)), ev.join('; '));
  assert.ok(byId(list).get('wifi-open-auto').evidence.map(text).some((e) => /Вокзал_Free/.test(e)));
  expectSev(run({ wifi: F.wifiGoodRu() }), { 'wifi-ok': 'ok' });
});

test('Wi-Fi: нет адаптера или службы - находок нет; непонятный язык - «не видно»', () => {
  const none = (w) => mine(run({ wifi: w })).filter((f) => f.id.startsWith('wifi-'));
  assert.deepEqual(none({ service: 'Running', interfaces: F.EN_NO_WIFI, profiles: [], profilesText: F.EN_NO_WIFI }), []);
  assert.deepEqual(none({ service: 'missing', interfaces: null, profiles: [] }), []);
  assert.deepEqual(none({ service: 'Stopped', interfaces: null, profiles: [] }), []);
  const odd = none({ service: 'Running', interfaces: '', profiles: [{ name: 'X', text: 'Profil X\n    Nom : X\n    Authentifizierung : WPA2' }] });
  assert.equal(odd.length, 1);
  assert.equal(odd[0].id, 'wifi-unknown');
  assert.equal(odd[0].sev, 'unknown');
});

// ---------------------------------------------------------------- Программы

test('программы: заброшенные и с известными дырами - правильные находки и важность', () => {
  const list = run({ software: F.softwareBad() });
  expectSev(list, {
    'app-flash': 'high', 'app-silverlight': 'high', 'app-quicktime': 'high', 'app-java-old': 'high', 'app-java8': 'advice',
    'app-python2': 'high', 'app-7zip': 'high', 'app-winrar': 'high', 'app-putty': 'advice', 'app-anydesk': 'high',
    'app-teamviewer': 'advice', 'app-zoom': 'high', 'app-vlc': 'advice', 'app-notepadpp': 'advice', 'app-reader-old': 'high',
    'app-office-old': 'high', 'app-browser-chrome': 'advice', 'app-browser-yandex': 'advice',
  });
  const ids = byId(list);
  assert.ok(!ids.has('app-ok'));
  assert.ok(list.every((f) => f.sev !== 'critical'), 'критично - только для настоящей активной опасности');
  for (const f of list.filter((x) => x.id.startsWith('app-'))) {
    assert.equal(f.cat, 'updates', f.id);
    assert.equal(f.guide, 'app-update', f.id);
    assert.ok(f.evidence.length, f.id);
  }
  // Две установки 7-Zip: одна находка с худшей важностью и обеими версиями.
  const z = ids.get('app-7zip').evidence.map(text);
  assert.equal(z.length, 2);
  assert.ok(z.every((e) => /нужна не ниже 25\.01/.test(e)), z.join('; '));
  assert.match(text(ids.get('app-winrar').evidence[0]), /WinRAR 6\.02.*6\.02\.0.*нужна не ниже 7\.13/);
  assert.ok(ids.get('app-flash').evidence.map(text).some((e) => /Flash\.ocx/.test(e)), 'встроенный Flash в System32');
  assert.match(text(ids.get('app-office-old').evidence[0]), /2025-10-14/);
});

test('программы: свежие версии - «в порядке» с датой таблицы', () => {
  const list = run({ software: F.softwareGood() });
  const apps = list.filter((f) => f.id.startsWith('app-'));
  assert.deepEqual(apps.map((f) => f.id), ['app-ok'], JSON.stringify(apps));
  assert.match(text(apps[0].text), new RegExp(ready.TABLE_DATE));
  assert.match(ready.TABLE_DATE, /^\d{4}-\d{2}-\d{2}$/);
});

test('программы: Office 2021 - без поддержки только после 13.10.2026; версии сравниваются по числам', () => {
  const sw = { count: 1, items: [{ name: 'Microsoft Office профессиональный плюс 2021 - ru-ru', version: '16.0.20326.20318' }] };
  assert.equal(byId(ready.evaluate({ software: sw }, { now: NOW })).get('app-office-old').sev, 'high');
  assert.ok(!byId(ready.evaluate({ software: sw }, { now: Date.parse('2026-06-01') })).has('app-office-old'));
  assert.equal(ready.cmpVer('9.20.00.0', '24.09'), -1);
  assert.equal(ready.cmpVer('7.13.0', '7.13'), 0);
  assert.equal(ready.cmpVer('ad 8.0.8', '8.0.8'), 0);
  assert.equal(ready.cmpVer('15.40.8', '15.8.3'), 1);
  assert.deepEqual(ready.verParts('7.1.9 (48550)'), [7, 1, 9]);
  // Zoom другого издателя (плагин, клон) - не трогаем.
  assert.ok(!byId(ready.evaluate({ software: { items: [{ name: 'Zoom', version: '5.0.0', publisher: 'Other' }] } }, { now: NOW })).has('app-zoom'));
});

// ---------------------------------------------------------------- Готовность к беде

test('готовность: копий нет и точки выключены - важно и совет', () => {
  const list = run({ readiness: F.readinessBad() });
  expectSev(list, { 'ready-no-backup': 'high', 'ready-restore-off': 'advice' });
  assert.equal(byId(list).get('ready-no-backup').guide, 'backup');
  assert.equal(byId(list).get('ready-restore-off').guide, 'restore-points');
  assert.ok(list.filter((f) => f.id.startsWith('ready-')).every((f) => f.cat === 'readiness'));
});

test('готовность: OneDrive копирует папки, точки свежие - в порядке', () => {
  const list = run({ readiness: F.readinessGood() });
  expectSev(list, { 'ready-backup-ok': 'ok', 'ready-restore-ok': 'ok' });
  const ev = byId(list).get('ready-backup-ok').evidence.map(text);
  assert.ok(ev.some((e) => /Рабочий стол/.test(e)) && ev.some((e) => /Документы/.test(e)) && !ev.some((e) => /Изображения/.test(e)), ev.join('; '));
});

test('готовность: программа копирования, облако без папок, старая история файлов', () => {
  // Macrium Reflect в списке программ - копия есть.
  expectSev(run({ readiness: F.readinessBad(), software: F.softwareGood() }), { 'ready-backup-ok': 'ok' });
  // Только Яндекс Диск - неясно.
  const sw = F.softwareGood();
  sw.items = sw.items.filter((x) => !/Macrium/.test(x.name));
  expectSev(run({ readiness: F.readinessBad(), software: sw }), { 'ready-backup-check': 'advice' });
  // OneDrive вошёл, но папки не в нём - тоже неясно, не «важно».
  const od = F.readinessBad();
  od.oneDrive = { accounts: [{ account: 'Personal', folder: 'C:\\Users\\user\\OneDrive' }], roots: [] };
  const l2 = run({ readiness: od });
  expectSev(l2, { 'ready-backup-check': 'advice' });
  assert.ok(!byId(l2).has('ready-no-backup'));
  // «C:\Users\user\OneDriveX» не считается папкой OneDrive.
  const near = F.readinessBad();
  near.oneDrive = { accounts: [], roots: ['C:\\Users\\user\\One'] };
  near.knownFolders.documents = 'C:\\Users\\user\\OneDriveX\\Documents';
  expectSev(run({ readiness: near }), { 'ready-no-backup': 'high' });
  // История файлов: копия 60 дней назад.
  const fh = F.readinessBad();
  fh.fileHistory = { configured: true, lastBackup: F.daysAgo(60), policyDisabled: null };
  const l3 = run({ readiness: fh });
  expectSev(l3, { 'ready-filehistory-old': 'advice' });
  assert.ok(!byId(l3).has('ready-no-backup'));
  fh.fileHistory.lastBackup = F.daysAgo(2);
  expectSev(run({ readiness: fh }), { 'ready-backup-ok': 'ok' });
});

test('готовность: точки восстановления - без прав «не видно», с правами - число и возраст', () => {
  const r = F.readinessGood();
  r.restore = { ...r.restore, rpSessionInterval: null, lastCreated: null };
  const u = byId(run({ readiness: r })).get('ready-restore-unknown');
  assert.equal(u.sev, 'unknown');
  assert.match(text(u.text), /Проверить полностью/);
  // Полная проверка: системный диск не защищён.
  r.restore = { ...r.restore, rpSessionInterval: 1, protectedDrives: ['D:'], points: 3 };
  expectSev(run({ readiness: r }), { 'ready-restore-off': 'advice' });
  r.restore = { ...r.restore, protectedDrives: ['C:'], points: 0 };
  expectSev(run({ readiness: r }), { 'ready-restore-none': 'advice' });
  r.restore = { ...r.restore, points: 2, lastPoint: F.daysAgo(90) };
  expectSev(run({ readiness: r }), { 'ready-restore-old': 'advice' });
  r.restore = { ...r.restore, lastPoint: F.daysAgo(90), lastSkipped: F.daysAgo(1) };
  expectSev(run({ readiness: r }), { 'ready-restore-ok': 'ok' });
  r.restore = { ...r.restore, policyDisableSR: 1 };
  expectSev(run({ readiness: r }), { 'ready-restore-off': 'advice' });
});

// ---------------------------------------------------------------- Приватность

test('приватность: программа из временной папки включала камеру - важно; камера и микрофон сейчас включены - совет', () => {
  const list = run({ privacy: F.privacyBad() });
  expectSev(list, { 'priv-suspicious': 'high', 'priv-camera-inuse': 'advice', 'priv-mic-inuse': 'advice', 'priv-camera-recent': 'ok', 'priv-mic-recent': 'ok' });
  const ids = byId(list);
  assert.equal(text(ids.get('priv-suspicious').title), 'Незнакомая программа включала камеру');
  const ev = ids.get('priv-suspicious').evidence.map(text);
  assert.ok(ev.some((e) => /AppData\\Local\\Temp\\svc_update\.exe - камера/.test(e)), ev.join('; '));
  assert.ok(ev.some((e) => /Downloads\\recorder\.exe - микрофон/.test(e)), ev.join('; '));
  assert.ok(ev.some((e) => /tool\.exe - местоположение.*нет подписи/.test(e)), ev.join('; '));
  const cam = ids.get('priv-camera-inuse').evidence.map(text);
  assert.equal(cam.length, 1, 'оборванная запись девятидневной давности - не «сейчас»');
  assert.match(cam[0], /Zoom\.exe/);
  assert.match(text(ids.get('priv-mic-inuse').evidence[0]), /MSTeams/);
  assert.ok(list.filter((f) => f.id.startsWith('priv-')).every((f) => f.cat === 'privacy'));
});

test('приватность: обычные программы - список «в порядке» с датами; давно не пользовались - «в порядке»', () => {
  const list = run({ privacy: F.privacyGood() });
  assert.ok(!list.some((f) => f.id.startsWith('priv-') && f.sev !== 'ok'), JSON.stringify(list));
  const rc = byId(list).get('priv-camera-recent').evidence.map(text);
  assert.equal(rc.length, 2, 'запись 40-дневной давности не входит');
  assert.ok(rc.every((e) => /\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(e)));
  assert.match(rc[0], /Microsoft\.WindowsCamera/);
  const q = byId(run({ privacy: F.privacyQuiet() }));
  assert.equal(q.get('priv-ok').sev, 'ok');
  assert.ok(q.get('priv-ok').evidence.map(text).includes('Доступ к камере выключен'));
});

// ---------------------------------------------------------------- Вместе с остальными правилами

test('старые отчёты без новых разделов: находок нет; ошибка сбора - одна «не видно»', () => {
  assert.deepEqual(mine(rules.evaluate(good(), { now: NOW })), []);
  assert.deepEqual(mine(rules.evaluate(bad(), { now: NOW })), []);
  assert.deepEqual(ready.evaluate({}, { now: NOW }), []);
  const f = good();
  f.errors = { software: 'Access denied', wifi: 'x', readiness: 'y', privacy: 'z' };
  const list = mine(rules.evaluate(f, { now: NOW }));
  assert.deepEqual(list.map((x) => x.id).sort(), ['app-unknown', 'priv-unknown', 'ready-unknown', 'wifi-unknown']);
  assert.ok(list.every((x) => x.sev === 'unknown'));
});

test('хороший компьютер с новыми разделами: ни одной критичной и важной; плохой - важные находки есть', () => {
  const g = { ...good(), software: F.softwareGood(), wifi: F.wifiGoodRu(), readiness: F.readinessGood(), privacy: F.privacyGood() };
  const s = rules.summarize(rules.evaluate(g, { now: NOW }));
  assert.equal(s.critical, 0);
  assert.equal(s.high, 0, JSON.stringify(rules.evaluate(g, { now: NOW }).filter((x) => x.sev === 'high')));
  const b = { ...bad(), software: F.softwareBad(), wifi: F.wifiBadRu(), readiness: F.readinessBad(), privacy: F.privacyBad() };
  const ids = byId(rules.evaluate(b, { now: NOW }));
  for (const id of ['app-flash', 'wifi-open-now', 'wifi-weak', 'ready-no-backup', 'priv-suspicious']) assert.equal(ids.get(id).sev, 'high', id);
});

test('PowerShell отдал одиночный объект вместо массива - правила это переносят', () => {
  const sw = F.softwareBad();
  sw.items = sw.items[0];
  const p = F.privacyBad();
  p.webcam.apps = p.webcam.apps[0];
  const w = F.wifiBadEn();
  w.profiles = w.profiles[1];
  const r = F.readinessGood();
  r.oneDrive.accounts = r.oneDrive.accounts[0];
  r.oneDrive.roots = r.oneDrive.roots[0];
  let list;
  assert.doesNotThrow(() => { list = run({ software: sw, privacy: p, wifi: w, readiness: r }); });
  expectSev(list, { 'app-flash': 'high', 'priv-suspicious': 'high', 'wifi-open-auto': 'advice', 'ready-backup-ok': 'ok' });
});

test('инструкции: у каждой находки есть инструкция, кнопки - только из списка окон', () => {
  for (const id of ['app-update', 'wifi-forget', 'backup', 'restore-points', 'privacy-camera']) {
    assert.ok(GUIDES[id], id);
    const g = guide(id, good());
    assert.ok(text(g.title) && text(g.intro) && g.steps.length >= 3, id);
    assert.ok(g.open.length && g.open.every((o) => o.id && o.label), id);
  }
  const b = { ...bad(), software: F.softwareBad(), wifi: F.wifiBadRu(), readiness: F.readinessBad(), privacy: F.privacyBad() };
  for (const f of mine(rules.evaluate(b, { now: NOW }))) {
    if (f.guide) assert.ok(GUIDES[f.guide], `${f.id}: нет инструкции ${f.guide}`);
    for (const m of [f.title, f.text, ...f.evidence]) assert.ok(text(m).length > 0 && !/\{\d\}/.test(text(m)), `${f.id}: ${JSON.stringify(m)}`);
  }
});

test('сценарии разделов: пароли Wi-Fi не читаются, Win32_Product не используется', () => {
  const dir = path.join(__dirname, '..', 'server', 'ps', 'sections');
  for (const name of ['software.ps1', 'readiness.ps1', 'privacy.ps1']) {
    const src = fs.readFileSync(path.join(dir, name), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    assert.doesNotMatch(src, /key\s*=\s*clear/i, name);
    assert.doesNotMatch(src, /Win32_Product/i, name);
  }
  const wifi = fs.readFileSync(path.join(dir, 'readiness.ps1'), 'utf8');
  assert.match(wifi, /key content\|содержимое ключа/i, 'строки с ключом вырезаются');
});
