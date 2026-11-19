'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const ps = require('../server/ps');
const { render } = require('../server/i18n');
const H = require('../server/helper');

const ROOT = path.join(__dirname, '..');
const NOW = Date.parse('2026-11-18T12:00:00Z');
const ADMINS = 'S-1-5-32-544';
const SYSTEM = 'S-1-5-18';
const USERS = 'S-1-5-32-545';
const ME = 'S-1-5-21-1111111111-2222222222-3333333333-1001';
const OTHER = 'S-1-5-21-1111111111-2222222222-3333333333-1002';
const FULL = 2032127; // FullControl
const RX = 1179817; // ReadAndExecute
const MODIFY = 1245631;
const msg = (m) => render('ru', m);

const ace = (sid, rights, extra = {}) => ({ sid, allow: true, rights, inherited: false, inheritOnly: false, ...extra });
const secureDir = (p, reader = USERS) => ({ path: p, exists: true, dir: true, reparse: false, owner: ADMINS, protected: true, acl: [ace(ADMINS, FULL), ace(SYSTEM, FULL), ace(reader, RX)] });
const secureFile = (p, name, sha256, reader = USERS) => ({ path: p, name, exists: true, dir: false, reparse: false, owner: ADMINS, acl: [ace(ADMINS, FULL), ace(SYSTEM, FULL), ace(reader, RX)], sha256 });

function env(dir) {
  return { ProgramW6432: path.join(dir, 'pf'), ProgramData: path.join(dir, 'pd'), SystemRoot: 'C:\\Windows' };
}

/** Ответ helper-install.ps1 -Check для правильно установленного помощника. */
function goodCheck(e, { bundled = H.bundledHashes(ps.PS_DIR) } = {}) {
  const P = H.paths(e);
  const files = [...bundled].map(([name, sha256]) => secureFile(path.win32.join(P.program, name.replace(/\//g, '\\')), name, sha256));
  files.push(secureFile(path.win32.join(P.program, 'helper.json'), 'helper.json', 'x'));
  files.push({ ...secureDir(path.win32.join(P.program, 'ps')), name: 'ps' }, { ...secureDir(path.win32.join(P.program, 'ps', 'sections')), name: 'ps/sections' });
  return {
    format: 'adamant-helper-check', version: H.HELPER_VERSION, at: new Date(NOW).toISOString(), user: ME, isAdmin: false,
    program: { parent: secureDir(P.programParent), dir: secureDir(P.program), files },
    manifest: { format: 'adamant-helper', version: H.HELPER_VERSION, readerSid: ME, files: [...bundled].map(([name, sha256]) => ({ name, sha256 })) },
    out: { dir: secureDir(P.out, ME), files: [{ name: 'full.json', path: path.win32.join(P.out, 'full.json'), exists: false }] },
    tasks: H.TASKS.map((x) => ({ name: x.name, mode: x.mode, exists: true, enabled: true, actions: 1, command: P.powershell, arguments: P.taskArgs(x.mode), userId: 'SYSTEM' })),
  };
}

// ---------------------------------------------------------------- права и владелец

test('помощник: права папки - владелец администраторы, писать может только администратор', () => {
  assert.equal(H.aclProblem(secureDir('C:\\x'), 'x'), null);
  assert.match(msg(H.aclProblem({ ...secureDir('C:\\x'), owner: ME }, 'x')), /владелец/);
  assert.match(msg(H.aclProblem({ ...secureDir('C:\\x'), acl: [ace(ADMINS, FULL), ace(USERS, MODIFY)] }, 'x')), /не только администратор/);
  // Отдельные биты: запись, дозапись, удаление, смена прав, GENERIC_WRITE (бывает в записях «только для вложенных»).
  for (const bit of [0x2, 0x4, 0x40, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000]) {
    assert.ok(H.aclProblem({ ...secureDir('C:\\x'), acl: [ace(USERS, bit, { inheritOnly: true })] }, 'x'), `бит ${bit.toString(16)}`);
  }
  // GENERIC_READ|GENERIC_EXECUTE приходит из PowerShell отрицательным int - это не запись.
  assert.equal(H.aclProblem({ ...secureDir('C:\\x'), acl: [ace(USERS, -1610612736)] }, 'x'), null);
  // Запрещающие записи не дают прав.
  assert.equal(H.aclProblem({ ...secureDir('C:\\x'), acl: [{ sid: USERS, allow: false, rights: FULL }] }, 'x'), null);
  assert.match(msg(H.aclProblem({ ...secureDir('C:\\x'), reparse: true }, 'x')), /ссылка/);
  assert.match(msg(H.aclProblem({ path: 'C:\\x', exists: true, error: 'Отказано в доступе' }, 'x')), /не удалось прочитать права/);
  assert.match(msg(H.aclProblem({ exists: false }, 'x')), /нет/);
  assert.equal(H.WRITE_MASK, 0x500D0156);
});

test('помощник: исправно установленный помощник - доверяем, не устарел', () => {
  const e = env('C:\\t');
  const r = H.evaluate(goodCheck(e), { env: e, bundled: H.bundledHashes(ps.PS_DIR) });
  assert.equal(r.installed, true);
  assert.equal(r.trusted, true, msg(r.problem));
  assert.equal(r.outdated, false);
  assert.equal(r.readerSid, ME);
  assert.equal(r.tasks.length, 2);
});

test('помощник: не установлен / непонятный ответ проверки', () => {
  const e = env('C:\\t');
  const none = { format: 'adamant-helper-check', program: { parent: { exists: false }, dir: { exists: false }, files: [] }, manifest: null, out: { dir: { exists: false }, files: [] }, tasks: H.TASKS.map((x) => ({ name: x.name, exists: false })) };
  const r = H.evaluate(none, { env: e });
  assert.equal(r.installed, false);
  assert.equal(r.trusted, false);
  assert.equal(msg(r.problem), 'Помощник не установлен');
  const bad = H.evaluate({ error: 'x' }, { env: e });
  assert.equal(bad.trusted, false);
  assert.match(msg(bad.problem), /Не удалось проверить помощника/);
});

test('помощник: подмена папки ответов, файлов и заданий - не доверяем', () => {
  const e = env('C:\\t');
  const bundled = H.bundledHashes(ps.PS_DIR);
  const ev = (mut) => { const c = goodCheck(e); mut(c); return H.evaluate(c, { env: e, bundled }); };

  // Папку ответов создал обычный пользователь (до установки или вместо неё).
  let r = ev((c) => { c.out.dir.owner = ME; });
  assert.equal(r.trusted, false);
  assert.match(msg(r.problem), /владелец/);
  // В папку ответов может писать пользователь.
  r = ev((c) => { c.out.dir.acl.push(ace(ME, MODIFY)); });
  assert.equal(r.trusted, false);
  // Файл ответа доступен на запись.
  r = ev((c) => { c.out.files = [{ ...secureFile('x', 'full.json', ''), acl: [ace(ADMINS, FULL), ace(ME, MODIFY)] }]; });
  assert.equal(r.trusted, false);
  // Сценарий в Program Files изменён после установки.
  r = ev((c) => { c.program.files[0].sha256 = '0'.repeat(64); });
  assert.equal(r.trusted, false);
  assert.match(msg(r.problem), /изменён после установки/);
  // Лишний файл рядом со сценариями.
  r = ev((c) => { c.program.files.push(secureFile('x', 'ps/sections/evil.ps1', 'ab')); });
  assert.equal(r.trusted, false);
  assert.match(msg(r.problem), /Лишний файл/);
  // Задание запускает что-то другое.
  r = ev((c) => { c.tasks[0].arguments = '-File C:\\Users\\x\\evil.ps1'; });
  assert.equal(r.trusted, false);
  assert.match(msg(r.problem), /изменено/);
  r = ev((c) => { c.tasks[1].userId = OTHER; });
  assert.equal(r.trusted, false, 'задание от имени обычной учётной записи');
  // Имя SYSTEM на другом языке Windows - не тревога.
  r = ev((c) => { c.tasks[1].userId = 'NT-AUTORITÄT\\SYSTEM'; });
  assert.equal(r.trusted, true, msg(r.problem));
  // Задания нет.
  r = ev((c) => { c.tasks[1].exists = false; });
  assert.equal(r.trusted, false);
  assert.match(msg(r.problem), /Нет задания/);
  // Задание не видно этой учётной записи - судим по файлам и папкам.
  r = ev((c) => { c.tasks = c.tasks.map((x) => ({ name: x.name, exists: true })); });
  assert.equal(r.trusted, true, msg(r.problem));
  r = ev((c) => { c.tasks = c.tasks.map((x) => ({ name: x.name, exists: null, error: 'Отказано в доступе' })); });
  assert.equal(r.trusted, true, msg(r.problem));
});

test('помощник: устаревший комплект - предлагаем переустановить', () => {
  const e = env('C:\\t');
  const bundled = H.bundledHashes(ps.PS_DIR);
  const c = goodCheck(e);
  c.manifest.version = H.HELPER_VERSION - 1;
  let r = H.evaluate(c, { env: e, bundled });
  assert.equal(r.outdated, true);
  // Программа обновилась: другой collect.ps1 - помощник устарел, но установленным файлам доверять можно.
  const newer = new Map(bundled);
  newer.set('ps/collect.ps1', 'f'.repeat(64));
  r = H.evaluate(goodCheck(e), { env: e, bundled: newer });
  assert.equal(r.outdated, true);
  assert.equal(r.trusted, true, msg(r.problem));
  // Новый раздел появился в программе.
  const more = new Map(bundled);
  more.set('ps/sections/zzz.ps1', 'a'.repeat(64));
  assert.equal(H.evaluate(goodCheck(e), { env: e, bundled: more }).outdated, true);
});

// ---------------------------------------------------------------- ответы

function fullJson(at = NOW - 3600_000, facts = {}) {
  return { format: 'adamant-helper-full', version: H.HELPER_VERSION, at: new Date(at).toISOString(), facts: { format: 'adamant-facts', isAdmin: true, ...facts } };
}
function securityJson(at = NOW - 60_000, extra = {}) {
  return {
    format: 'adamant-helper-security', version: H.HELPER_VERSION, at: new Date(at).toISOString(), days: 14,
    failed: [], failedTotal: 0, failedTruncated: false, logons: [], locks: [], created: [], adminAdds: [], ...extra,
  };
}

test('помощник: full.json - свежесть и формат', () => {
  assert.ok(H.parseFull(fullJson(), { now: NOW }));
  assert.equal(H.parseFull(fullJson(NOW - 27 * 3600_000), { now: NOW }), null, 'старше суток с запасом');
  assert.ok(H.parseFull(fullJson(NOW - 27 * 3600_000), { now: NOW, maxAgeMs: Infinity }));
  assert.equal(H.parseFull(fullJson(NOW + 3600_000), { now: NOW }), null, 'из будущего');
  assert.equal(H.parseFull({ ...fullJson(), at: 'вчера' }, { now: NOW }), null);
  assert.equal(H.parseFull({ ...fullJson(), version: H.HELPER_VERSION + 1 }, { now: NOW }), null, 'неизвестная новая версия');
  assert.equal(H.parseFull({ ...fullJson(), format: 'x' }, { now: NOW }), null);
  assert.equal(H.parseFull(fullJson(NOW - 60_000, { isAdmin: false }), { now: NOW }), null, 'собрано без прав администратора');
  assert.equal(H.parseFull(null, { now: NOW }), null);
  assert.equal(H.parseFull([], { now: NOW }), null);
});

test('помощник: security.json - проверка и обрезка', () => {
  const long = 'x'.repeat(5000);
  const s = H.parseSecurity(securityJson(NOW - 60_000, {
    failed: [
      { at: new Date(NOW - 1000).toISOString(), user: long, logonType: '3', ip: '10.0.0.5', workstation: 'W\nX' },
      { at: 'не дата', user: 'a' }, 'мусор', null,
      ...Array.from({ length: 400 }, (_, i) => ({ at: new Date(NOW - i * 1000).toISOString(), user: 'u', logonType: 3 })),
    ],
    locks: [{ at: new Date(NOW).toISOString(), user: 'PC\\me', kind: 'evil' }],
  }), { now: NOW });
  assert.ok(s);
  assert.ok(s.failed.length <= 300);
  assert.equal(s.failed[0].user.length, 256);
  assert.equal(s.failed[0].logonType, 3);
  assert.equal(s.failed[0].workstation, 'W X');
  assert.equal(s.locks[0].kind, 'unlock');
  assert.equal(H.parseSecurity(securityJson(NOW - 30 * 3600_000), { now: NOW }), null);
  assert.equal(H.parseSecurity({ ...securityJson(), format: 'adamant-helper-full' }, { now: NOW }), null);
});

// ---------------------------------------------------------------- перенос в обычную проверку

function userFacts() {
  return {
    format: 'adamant-facts', isAdmin: false,
    smb: { server1: false, feature: undefined },
    encryption: { drives: [{ drive: 'C:' }] },
    boot: { secureBoot: 1 },
    firmware: { vendor: null, manufacturer: 'X' },
    events: { admin: false, security: null, system: { servicesInstalled: [] } },
    physical: {
      admin: false,
      bitlocker: { protectors: [], preboot: null, policy: { useTpmPin: 1 } },
      winre: { enabled: true, source: 'reagent.xml' },
      presence: {
        days: 14, security: false, events: [
          { at: new Date(NOW - 7200_000).toISOString(), kind: 'boot', source: 'system' },
          { at: new Date(NOW - 7000_000).toISOString(), kind: 'logon', source: 'system', user: 'PC\\me' },
        ],
      },
    },
    readiness: { restore: { rpSessionInterval: 1, points: null, lastPoint: null, protectedDrives: null } },
    persistence: { admin: false, exclusions: { visible: false, paths: [], processes: [], extensions: [] }, wmi: { visible: false } },
  };
}
function helperFacts() {
  return fullJson(NOW - 3600_000, {
    smb: { feature: 'Disabled' },
    encryption: { volumes: [{ drive: 'C:', protection: 'On' }] },
    boot: { tpm: { present: true }, tpmSpec: '2.0', bcdFirmware: 'text' },
    firmware: { vendor: { source: 'Lenovo', admin: true } },
    events: { security: { failedTotal: 3 } },
    physical: {
      bitlocker: { protection: 'On', protectors: ['Tpm', 'RecoveryPassword'], preboot: 'tpm-only', policy: { useTpmPin: 0 } },
      winre: { enabled: false, source: 'reagentc' },
      presence: { days: 14, security: true, events: [
        { at: new Date(NOW - 7000_000).toISOString(), kind: 'logon', source: 'security', user: 'PC\\me', logonType: 2 },
        { at: new Date(NOW - 9000_000).toISOString(), kind: 'boot', source: 'system' },
      ] },
    },
    readiness: { restore: { points: 4, lastPoint: '2026-11-10T00:00:00Z', protectedDrives: ['C:'] } },
    persistence: { exclusions: { visible: true, paths: ['C:\\Games'], processes: [], extensions: [] }, wmi: { visible: true, filters: [], consumers: [], bindings: [] } },
  });
}

test('помощник: перенос - только невидимое без прав администратора, видимое не заменяется', () => {
  const f = userFacts();
  const full = H.parseFull(helperFacts(), { now: NOW });
  const r = H.mergeHelper(f, { full });
  assert.equal(r.fullAt, full.at);
  assert.equal(f.smb.feature, 'Disabled');
  assert.deepEqual(f.encryption.volumes, [{ drive: 'C:', protection: 'On' }]);
  assert.equal(f.boot.tpmSpec, '2.0');
  assert.equal(f.boot.secureBoot, 1, 'своё не трогаем');
  assert.equal(f.firmware.manufacturer, 'X');
  assert.equal(f.firmware.vendor.source, 'Lenovo');
  assert.equal(f.events.security.failedTotal, 3);
  assert.equal(f.physical.bitlocker.preboot, 'tpm-only');
  assert.deepEqual(f.physical.bitlocker.protectors, ['Tpm', 'RecoveryPassword']);
  assert.equal(f.physical.bitlocker.policy.useTpmPin, 1, 'политика своя (одна на компьютер, свежее)');
  assert.equal(f.physical.winre.enabled, true, 'видимое без прав не заменяется');
  assert.equal(f.readiness.restore.points, 4);
  assert.equal(f.readiness.restore.rpSessionInterval, 1);
  assert.deepEqual(f.persistence.exclusions.paths, ['C:\\Games']);
  assert.equal(f.persistence.wmi.visible, true);
  assert.equal(f.helper.fullAt, full.at);
  // Входы: из «Безопасности» вместо системного журнала, включения - свои (свежие).
  const pr = f.physical.presence;
  assert.equal(pr.security, true);
  assert.deepEqual(pr.events.map((e) => `${e.kind}/${e.source}`), ['logon/security', 'boot/system']);
});

test('помощник: перенос - свежие входы из security.json, неверный пароль только с клавиатуры', () => {
  const f = userFacts();
  const sec = H.parseSecurity(securityJson(NOW - 60_000, {
    logons: [
      { at: new Date(NOW - 600_000).toISOString(), user: 'PC\\me', logonType: 2 },
      { at: new Date(NOW - 500_000).toISOString(), user: 'PC\\me', logonType: 7 },
      { at: new Date(NOW - 400_000).toISOString(), user: 'PC\\admin', logonType: 10 },
    ],
    locks: [{ at: new Date(NOW - 550_000).toISOString(), user: 'PC\\me', kind: 'lock' }],
    failed: [
      { at: new Date(NOW - 300_000).toISOString(), user: 'PC\\me', logonType: 2, status: '0xc000006a' },
      { at: new Date(NOW - 200_000).toISOString(), user: '', unknownUser: true, logonType: 7, status: '0xc0000064' },
      { at: new Date(NOW - 100_000).toISOString(), user: 'admin', logonType: 3, ip: '203.0.113.9' },
    ],
  }), { now: NOW });
  const r = H.mergeHelper(f, { full: H.parseFull(helperFacts(), { now: NOW }), security: sec });
  assert.equal(r.securityAt, sec.at);
  const kinds = f.physical.presence.events.map((e) => e.kind);
  assert.deepEqual(kinds, ['failed-local', 'failed-local', 'unlock', 'lock', 'logon', 'boot']);
  assert.ok(!f.physical.presence.events.some((e) => e.kind === 'failed-local' && e.logonType === 3), 'попытки по сети - не «за этим компьютером»');
  assert.ok(!f.physical.presence.events.some((e) => e.logonType === 10), 'удалённый рабочий стол - не вход с клавиатуры');
  assert.equal(f.physical.presence.events[0].user, undefined, 'скрытое имя не появляется');
  // Только security.json, без полной проверки - тоже работает.
  const g = userFacts();
  H.mergeHelper(g, { security: sec });
  assert.equal(g.physical.presence.security, true);
  assert.equal(g.events.security, null);
});

test('помощник: перенос не трогает полную проверку и пустые ответы', () => {
  const f = { ...userFacts(), isAdmin: true };
  assert.equal(H.mergeHelper(f, { full: H.parseFull(helperFacts(), { now: NOW }) }), null);
  assert.equal(f.smb.feature, undefined);
  assert.equal(H.mergeHelper(userFacts(), {}), null);
  // Раздел, который у пользователя не собрался (ошибка), помощник не создаёт: правила ждут полный раздел.
  const g = userFacts();
  delete g.boot;
  H.mergeHelper(g, { full: H.parseFull(helperFacts(), { now: NOW }) });
  assert.equal(g.boot, undefined);
});

// ---------------------------------------------------------------- createHelper: файлы, кэш, установка

function rig({ check, files = {}, elevated } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-helper-'));
  const e = env(dir);
  const P = H.paths(e);
  fs.mkdirSync(P.out, { recursive: true });
  for (const [n, v] of Object.entries(files)) fs.writeFileSync(path.join(P.out, n), typeof v === 'string' ? v : JSON.stringify(v));
  const calls = { runJson: 0, elevated: [], tasks: [] };
  let clock = NOW;
  const fakePs = {
    PS_DIR: ps.PS_DIR,
    runJson: async (name, args) => {
      calls.runJson++;
      assert.equal(name, 'helper-install.ps1');
      assert.deepEqual(args, ['-Check']);
      return typeof check === 'function' ? check(e) : (check || goodCheck(e));
    },
    runElevated: async (name, args) => {
      calls.elevated.push([name, args]);
      return elevated ? elevated(name, args) : { ok: true };
    },
  };
  const helper = H.createHelper({
    ps: fakePs, env: e, now: () => clock, tmpDir: dir,
    runTask: async (n) => { calls.tasks.push(n); }, sleep: () => new Promise((r) => setImmediate(() => { clock += 2000; r(); })), whoami: async () => `"pc\\me","${ME}"`,
  });
  return { helper, calls, P, dir, tick: (ms) => { clock += ms; } };
}

test('помощник: чтение ответов - только при доверии и свежести, битый JSON - null', async () => {
  let { helper } = rig({ files: { 'full.json': fullJson(), 'security.json': securityJson() } });
  const f = await helper.readFull();
  assert.ok(f && f.facts.isAdmin);
  assert.ok(await helper.readSecurity());

  ({ helper } = rig({ files: { 'full.json': '{не json', 'security.json': '' } }));
  assert.equal(await helper.readFull(), null);
  assert.equal(await helper.readSecurity(), null);

  // Папку ответов создал пользователь - даже свежим файлам не верим.
  ({ helper } = rig({ files: { 'full.json': fullJson() }, check: (e) => { const c = goodCheck(e); c.out.dir.owner = ME; return c; } }));
  assert.equal(await helper.readFull(), null);
  const s = await helper.status();
  assert.equal(s.trusted, false);
  assert.match(msg(s.problem), /владелец/);

  ({ helper } = rig({ files: { 'full.json': fullJson(NOW - 30 * 3600_000) } }));
  assert.equal(await helper.readFull(), null, 'устаревший ответ');
  assert.ok(await helper.readFull({ maxAgeMs: Infinity }));
});

test('помощник: проверка доверия кэшируется и повторяется, если папку пересоздали', async () => {
  const { helper, calls, P, tick } = rig({ files: { 'full.json': fullJson() } });
  await helper.readFull();
  await helper.readSecurity();
  await helper.status();
  assert.equal(calls.runJson, 1);
  tick(6 * 60_000);
  await helper.readFull();
  assert.equal(calls.runJson, 2, 'кэш истёк');
  fs.rmSync(P.out, { recursive: true });
  fs.mkdirSync(P.out, { recursive: true });
  await helper.readFull();
  assert.equal(calls.runJson, 3, 'папку пересоздали - проверяем заново');
});

test('помощник: состояние - время запусков и ошибка помощника', async () => {
  let { helper } = rig({ files: { 'full.json': fullJson(NOW - 3600_000), 'security.json': securityJson(NOW - 60_000) } });
  let s = await helper.status();
  assert.equal(s.installed, true);
  assert.equal(s.trusted, true);
  assert.equal(s.lastFull, new Date(NOW - 3600_000).toISOString());
  assert.equal(s.lastSecurity, new Date(NOW - 60_000).toISOString());
  assert.equal(s.lastError, null);
  assert.equal(s.problem, null);

  ({ helper } = rig({ files: { 'error.json': { format: 'adamant-helper-error', version: 1, at: new Date(NOW - 1000).toISOString(), mode: 'full', error: 'Файлы помощника изменены' } } }));
  s = await helper.status();
  assert.equal(s.lastError.error, 'Файлы помощника изменены');
  assert.match(msg(s.problem), /не смог проверить/);

  ({ helper } = rig({ files: { 'full.json': fullJson(NOW - 40 * 3600_000) } }));
  s = await helper.status();
  assert.match(msg(s.problem), /давно не проверял/);
});

test('помощник: установка и удаление через UAC, отказ - CANCELLED', async () => {
  const bundled = H.bundledHashes(ps.PS_DIR);
  let { helper, calls } = rig({ elevated: () => ({ ok: true, files: [...bundled].map(([name, sha256]) => ({ name, sha256 })) }) });
  const r = await helper.install({ userSid: ME });
  assert.equal(r.ok, true);
  assert.equal(r.warning, undefined);
  assert.deepEqual(calls.elevated[0], ['helper-install.ps1', ['-ReaderSid', ME]]);

  // SID не передан или испорчен - берём свой из whoami.
  ({ helper, calls } = rig({ elevated: () => ({ ok: true, files: [] }) }));
  const r2 = await helper.install({ userSid: 'S-1-5-21-1"; calc' });
  assert.deepEqual(calls.elevated[0], ['helper-install.ps1', ['-ReaderSid', ME]]);
  assert.ok(r2.warning, 'в Program Files легло не то, что в программе');

  ({ helper } = rig({ elevated: () => { throw Object.assign(new Error('Запрос прав администратора отклонён'), { code: 'CANCELLED' }); } }));
  await assert.rejects(helper.install({ userSid: ME }), (e) => e.code === 'CANCELLED');
  await assert.rejects(helper.uninstall(), (e) => e.code === 'CANCELLED');

  ({ helper } = rig({ elevated: () => ({ ok: false, error: 'Нужны права администратора' }) }));
  await assert.rejects(helper.install({ userSid: ME }), /Нужны права администратора/);

  ({ helper, calls } = rig({ elevated: () => ({ ok: true, removed: ['x'] }) }));
  assert.equal((await helper.uninstall()).ok, true);
  assert.deepEqual(calls.elevated[0], ['helper-uninstall.ps1', []]);
});

test('помощник: «Проверить полностью» без UAC - запуск задания и ожидание ответа', async () => {
  // Ответ моложе 20 минут: задание не запускаем (helper-run.ps1 всё равно бы пропустил).
  let { helper, calls } = rig({ files: { 'full.json': fullJson(NOW - 60_000) } });
  assert.ok(await helper.refresh());
  assert.deepEqual(calls.tasks, []);

  const x = rig({ files: { 'full.json': fullJson(NOW - 3 * 3600_000) } });
  const waiting = x.helper.refresh({ timeoutMs: 60_000 });
  setImmediate(() => fs.writeFileSync(path.join(x.P.out, 'full.json'), JSON.stringify(fullJson(NOW + 1000))));
  const got = await waiting;
  assert.equal(got.at, new Date(NOW + 1000).toISOString());
  assert.deepEqual(x.calls.tasks, ['Adamant Helper']);

  ({ helper } = rig({ files: { 'full.json': fullJson(NOW - 3 * 3600_000) } }));
  await assert.rejects(helper.refresh({ timeoutMs: 10_000 }), (e) => e.code === 'HELPER_TIMEOUT');

  ({ helper } = rig({ check: (e) => { const c = goodCheck(e); c.manifest.version = 0; return c; } }));
  await assert.rejects(helper.refresh(), (e) => e.code === 'HELPER_UNAVAILABLE', 'устаревшего помощника не запускаем');
});

// ---------------------------------------------------------------- согласованность с PowerShell

test('помощник: версия, список переносимых сведений и маска прав совпадают в JS и PowerShell', () => {
  const run = fs.readFileSync(path.join(ROOT, 'server/ps/helper/helper-run.ps1'), 'utf8');
  const inst = fs.readFileSync(path.join(ROOT, 'server/ps/helper-install.ps1'), 'utf8');
  assert.equal(Number(/\$H_Version = (\d+)/.exec(run)[1]), H.HELPER_VERSION);
  assert.equal(Number(/\$HelperVersion = (\d+)/.exec(inst)[1]), H.HELPER_VERSION);
  const keep = /\$H_Keep = '([^']+)'/.exec(run)[1].split(' ').sort();
  assert.deepEqual(keep, H.ADMIN_KEYS.map((k) => k.join('.')).sort());
  assert.match(run, /\$H_WriteMask = 0x500D0156/);
  assert.match(inst, /\$WriteMask = 0x500D0156/);
  // Команда задания: та же строка, что сравнивает helper.js.
  assert.match(inst, /'-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' \+ \(Join-Path \$Prog 'helper-run\.ps1'\) \+ '" -Mode ' \+ \$mode/);
  assert.equal(H.paths({ ProgramW6432: 'C:\\Program Files', SystemRoot: 'C:\\Windows' }).taskArgs('full'), '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\\Program Files\\Adamant\\Helper\\helper-run.ps1" -Mode full');
  for (const x of H.TASKS) assert.ok(inst.includes(`'${x.name}' = '${x.mode}'`), x.name);
  // Комплект: те же файлы, что копирует установщик.
  const names = H.payloadFiles(ps.PS_DIR).map((p) => p.name);
  assert.ok(names.includes('helper-run.ps1') && names.includes('helper-uninstall.ps1') && names.includes('ps/collect.ps1'));
  assert.ok(names.some((n) => n.startsWith('ps/sections/')));
  for (const p of H.payloadFiles(ps.PS_DIR)) assert.ok(fs.existsSync(p.file), p.file);
});
