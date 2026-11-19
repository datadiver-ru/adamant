'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createAway, validateEvent, parseTasklist, decodeOem, normalizeLogons, ignoredFile, isNoise, TAIL_MS } = require('../server/away');
const { createStore } = require('../server/store');
const { render } = require('../server/i18n');

const T0 = Date.parse('2026-11-18T10:00:00Z');
const iso = (ms) => new Date(ms).toISOString();
const MIN = 60_000;

const BASE_PROCS = [
  { name: 'System', pid: 4, session: 0 }, { name: 'explorer.exe', pid: 100, session: 1 }, { name: 'node.exe', pid: 200, session: 1 },
];

function setup(opts = {}) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-away-')));
  const dataDir = path.join(root, 'data');
  const store = createStore(dataDir);
  store.write('settings.json', { lang: 'ru', background: true, away: true, awayPhoto: false, ...(opts.settings || {}) });
  const clock = { t: T0 };
  const st = { procs: BASE_PROCS.slice(), logons: { visible: true, items: [] }, procCalls: 0, logonCalls: 0 };
  const deps = {
    store, dataDir, now: () => clock.t, owner: 'Хозяин',
    settings: () => ({ ...store.read('settings.json', {}) }),
    listProcesses: async () => { st.procCalls += 1; return st.procs.slice(); },
    readLogons: async () => { st.logonCalls += 1; return st.logons; },
    watchDirs: opts.watchDirs || [],
    ...(opts.deps || {}),
  };
  let away = createAway(deps);
  const ev = (kind, extra = {}) => away.event({ kind, at: iso(clock.t), ...extra });
  return {
    root, dataDir, store, clock, st, deps,
    get away() { return away; },
    restart() { away.stop(); away = createAway(deps); return away; },
    ev,
    adv: (ms) => { clock.t += ms; },
    cleanup() { try { away.stop(); } catch { /* ignore */ } fs.rmSync(root, { recursive: true, force: true }); },
  };
}

const waitFor = async (cond, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return cond();
};
const ru = (m) => render('ru', m);
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200, 7), Buffer.from([0xff, 0xd9])]);

test('событие от значка: строгая проверка ввода', () => {
  const now = T0;
  const ok = validateEvent({ kind: 'lock', at: '2026-11-18T09:59:00.123Z' }, now);
  assert.deepEqual(ok, { kind: 'lock', at: '2026-11-18T09:59:00.123Z' });
  // Семь знаков после точки (так пишет .NET) и смещение пояса принимаются, время приводится к UTC.
  assert.equal(validateEvent({ kind: 'unlock', at: '2026-11-18T12:59:00.1234567+03:00' }, now).at, '2026-11-18T09:59:00.123Z');
  assert.deepEqual(validateEvent({ kind: 'usb', at: iso(now), drive: 'e:', type: 'Removable', label: ' KINGSTON\u0007 ' }, now),
    { kind: 'usb', at: iso(now), drive: 'E:', type: 'Removable', label: 'KINGSTON' });
  assert.equal(validateEvent({ kind: 'remote', at: iso(now), how: 'remote-connect' }, now).how, 'remote-connect');
  const bad = [
    null, [], 'lock', {}, { kind: 'LOCK', at: iso(now) }, { kind: 'reboot', at: iso(now) }, { kind: 'lock' },
    { kind: 'lock', at: 'вчера' }, { kind: 'lock', at: '2026-11-18 10:00:00' }, { kind: 'lock', at: 12345 },
    { kind: 'lock', at: iso(now - 25 * 3600_000) }, { kind: 'lock', at: iso(now + 5 * MIN) },
    { kind: 'lock', at: '2026-13-45T99:99:99Z' }, { kind: 'lock', at: iso(now), extra: 1 }, { kind: 'lock', at: iso(now), how: 'remote-connect' },
    { kind: 'remote', at: iso(now) }, { kind: 'remote', at: iso(now), how: 'rdp' }, { kind: 'usb', at: iso(now), drive: 'C:\\Windows' },
    { kind: 'usb', at: iso(now), drive: 'E:', type: 'Floppy' }, { kind: 'usb', at: iso(now), label: 'x'.repeat(200) },
    { kind: 'usb', at: iso(now), label: { a: 1 } }, { kind: 'lock', at: `${iso(now)}${' '.repeat(50)}` },
  ];
  for (const b of bad) {
    assert.throws(() => validateEvent(b, now), (e) => e.status === 400, JSON.stringify(b));
  }
});

test('выключено - события не записываются и ничего не опрашивается', async () => {
  const s = setup({ settings: { away: false } });
  try {
    assert.deepEqual(s.ev('lock'), { ok: true, recorded: false });
    await s.away.tick();
    assert.equal(s.st.procCalls, 0);
    assert.equal(s.st.logonCalls, 0);
    assert.equal(s.away.report().spans.length, 0);
    assert.equal(s.away.photoRequest(), null);
    assert.throws(() => s.away.event({ kind: 'nope', at: iso(T0) }), (e) => e.status === 400);
    // Включили, заблокировали, выключили - отрезок закрывается, опрос прекращается.
    s.store.write('settings.json', { ...s.store.read('settings.json', {}), away: true });
    s.ev('lock'); await s.away.tick();
    assert.equal(s.away.status().active, true);
    s.store.write('settings.json', { ...s.store.read('settings.json', {}), away: false });
    const calls = s.st.procCalls;
    s.adv(15_000); await s.away.tick(); await s.away.tick();
    assert.equal(s.st.procCalls, calls);
    assert.equal(s.away.status().active, false);
    assert.equal(s.away.report().spans[0].endKind, 'off');
  } finally { s.cleanup(); }
});

test('обычная работа без блокировки ничего не стоит', async () => {
  const s = setup();
  try {
    for (let i = 0; i < 10; i += 1) { s.adv(15_000); await s.away.tick(); }
    assert.equal(s.st.procCalls, 0);
    assert.equal(s.st.logonCalls, 0);
    // usb без отрезка не записывается
    assert.equal(s.ev('usb', { drive: 'E:' }).recorded, false);
  } finally { s.cleanup(); }
});

test('отрезок: блокировка → новые программы (без служебных) → разблокировка; спокойная сводка', async () => {
  const s = setup();
  try {
    assert.equal(s.ev('lock').recorded, true);
    await s.away.tick(); // слепок процессов
    s.adv(15_000);
    s.st.procs.push({ name: 'svchost.exe', pid: 301, session: 0 }, { name: 'RuntimeBroker.exe', pid: 302, session: 1 },
      { name: 'notepad.exe', pid: 303, session: 1 }, { name: 'conhost.exe', pid: 304, session: 1 }, { name: 'tasklist.exe', pid: 305, session: 1 });
    await s.away.tick();
    s.adv(15_000);
    s.st.procs.push({ name: 'notepad.exe', pid: 306, session: 1 }, { name: 'AnyDesk.exe', pid: 307, session: 1 });
    await s.away.tick();
    const st = s.away.status();
    assert.equal(st.active, true);
    let r = s.away.report();
    assert.equal(r.active.id, r.spans[0].id);
    assert.match(ru(r.active.headline), /Компьютер заблокирован с \d\d:\d\d/);
    s.adv(40 * MIN);
    s.ev('unlock');
    await s.away.tick();
    r = s.away.report();
    assert.equal(r.spans.length, 1);
    const sp = r.spans[0];
    assert.equal(sp.kind, 'lock');
    assert.equal(sp.endKind, 'unlock');
    assert.equal(sp.active, false);
    assert.deepEqual(sp.processes.map((p) => p.name), ['notepad.exe', 'AnyDesk.exe']);
    assert.ok(sp.processes.every((p) => !p.after));
    assert.equal(sp.calm, true, 'запуск программ сам по себе не тревога');
    assert.equal(sp.logonsVisible, true);
    assert.match(ru(sp.headline), /^Пока вас не было \(\d\d:\d\d-\d\d:\d\d\): никто не входил и не пытался войти$/);
    assert.equal(r.last.id, sp.id);
    assert.equal(r.last.calm, true);
    assert.deepEqual(sp.events.map((e) => e.kind), ['lock', 'unlock']);
    assert.ok(sp.events.every((e) => ru(e.text)));
  } finally { s.cleanup(); }
});

test('сон: блокировка + сон + пробуждение - один отрезок до разблокировки; сон без блокировки закрывает пробуждение', async () => {
  const s = setup();
  try {
    s.ev('lock'); s.adv(MIN); s.ev('suspend'); s.adv(60 * MIN); s.ev('resume');
    assert.equal(s.away.status().active, true, 'после пробуждения ещё заблокирован');
    s.adv(MIN); s.ev('unlock');
    let r = s.away.report();
    assert.equal(r.spans.length, 1);
    assert.deepEqual(r.spans[0].events.map((e) => e.kind), ['lock', 'suspend', 'resume', 'unlock']);
    s.away.acknowledge([r.spans[0].id]);
    s.adv(MIN); s.ev('suspend'); s.adv(30 * MIN); s.ev('resume');
    r = s.away.report();
    assert.equal(r.spans.length, 2);
    assert.equal(r.spans[0].kind, 'suspend');
    assert.equal(r.spans[0].endKind, 'resume');
    assert.equal(s.away.status().active, false);
  } finally { s.cleanup(); }
});

test('после разблокировки: час «хвоста», «Это был я» и конец опроса', async () => {
  const s = setup();
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(10 * MIN); s.ev('unlock'); await s.away.tick();
    s.adv(15_000);
    s.st.procs.push({ name: 'chrome.exe', pid: 401, session: 1 });
    await s.away.tick();
    s.ev('usb', { drive: 'F:', type: 'Removable', label: 'Флешка' });
    let sp = s.away.report().spans[0];
    assert.deepEqual(sp.processes.map((p) => [p.name, p.after]), [['chrome.exe', true]]);
    assert.equal(sp.usb[0].after, true);
    assert.equal(sp.calm, true, 'после возвращения - не тревога');
    // Через час опрос прекращается.
    s.adv(TAIL_MS);
    const calls = s.st.procCalls;
    await s.away.tick(); await s.away.tick();
    assert.equal(s.st.procCalls, calls);
    assert.equal(s.away.status().tail, false);
    // Новый отрезок; «Это был я» сразу прекращает хвост.
    s.ev('lock'); await s.away.tick(); s.adv(MIN); s.ev('unlock'); await s.away.tick();
    assert.equal(s.away.status().tail, true);
    sp = s.away.report().spans[0];
    assert.deepEqual(s.away.acknowledge([sp.id]), { ok: true, confirmed: 1 });
    assert.equal(s.away.status().tail, false);
    const c2 = s.st.procCalls;
    s.adv(15_000); await s.away.tick();
    assert.equal(s.st.procCalls, c2);
    const r = s.away.report();
    assert.equal(r.spans[0].confirmed, true);
    assert.match(ru(r.spans[0].headline), /вы отметили, что это были вы/);
    assert.throws(() => s.away.acknowledge('x'), (e) => e.status === 400);
    assert.throws(() => s.away.acknowledge(['../../etc']), (e) => e.status === 400);
    assert.throws(() => s.away.acknowledge([1]), (e) => e.status === 400);
  } finally { s.cleanup(); }
});

test('помощник: ждём его ответ после разблокировки, разблокировка Windows 11 (вход типа 2), его powershell.exe не чужой', async () => {
  const s = setup({ deps: { helperSecurity: async () => null } });
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(5 * MIN);
    // Ответ помощника после первой неверной попытки: второй попытки в нём ещё нет.
    const fail1 = iso(s.clock.t - 3000);
    s.st.logons = { at: iso(s.clock.t - 1000), failed: [{ at: fail1, user: 'PC\\Хозяин', logonType: 2 }], logons: [] };
    s.adv(2000);
    const fail2 = iso(s.clock.t);
    s.adv(3000);
    s.ev('unlock');
    const unlockAt = s.clock.t;
    s.st.procs.push({ name: 'powershell.exe', pid: 601, session: 0 }, { name: 'powershell.exe', pid: 602, session: 1 });
    await s.away.tick();
    assert.equal(s.away.report().spans[0].failed, 1);
    // Через 15 секунд помощник отработал по событию входа: обе попытки и вход владельца (Windows 11 пишет тип 2, дважды).
    s.adv(15_000);
    s.st.logons = { at: iso(s.clock.t - 2000), failed: [{ at: fail1, user: 'PC\\Хозяин', logonType: 2 }, { at: fail2, user: 'PC\\Хозяин', logonType: 2 }],
      logons: [{ at: iso(unlockAt - 20), user: 'PC\\Хозяин', logonType: 2 }, { at: iso(unlockAt - 10), user: 'PC\\Хозяин', logonType: 2 }] };
    await s.away.tick();
    const sp = s.away.report().spans[0];
    assert.equal(sp.failed, 2, 'вторая попытка из свежего ответа помощника');
    assert.equal(sp.unlocks, 1, 'две записи одного входа - одна разблокировка');
    assert.ok(!sp.reasons.includes('unlocks'));
    assert.deepEqual(sp.processes.map((p) => p.name), ['powershell.exe'], 'powershell.exe помощника (сеанс 0) не считается');
    // Свежий ответ получен - больше не перечитываем.
    const calls = s.st.logonCalls;
    s.adv(15_000); await s.away.tick();
    assert.equal(s.st.logonCalls, calls);
  } finally { s.cleanup(); }
});

test('помощник не ответил после разблокировки - ждём не дольше двух минут', async () => {
  const s = setup();
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(5 * MIN);
    s.st.logons = { at: iso(s.clock.t - 60_000), failed: [], logons: [] };
    s.ev('unlock');
    await s.away.tick();
    for (let i = 0; i < 12; i += 1) { s.adv(15_000); await s.away.tick(); }
    const calls = s.st.logonCalls;
    s.adv(15_000); await s.away.tick();
    s.adv(15_000); await s.away.tick();
    assert.equal(s.st.logonCalls, calls);
  } finally { s.cleanup(); }
});

test('тревога: неверный пароль, чужая учётная запись, флешка, удалённое подключение', async () => {
  const s = setup();
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(5 * MIN);
    s.st.logons = { visible: true, items: [
      { at: iso(s.clock.t - MIN), kind: 'failed', user: 'Хозяин', logonType: 7 },
      { at: iso(s.clock.t - 30_000), kind: 'failed', user: 'admin', logonType: 2 },
      { at: iso(s.clock.t - 20_000), kind: 'logon', user: 'PC\\Гость', logonType: 2 },
      { at: iso(s.clock.t - 10_000), kind: 'logon', user: 'DWM-1', logonType: 2 },
      { at: iso(T0 - 3600_000), kind: 'failed', user: 'давно', logonType: 2 },
    ] };
    await s.away.tick();
    s.ev('usb', { drive: 'E:', type: 'Removable' });
    s.ev('remote', { how: 'remote-connect' });
    s.adv(MIN);
    s.ev('unlock');
    s.st.logons.items.push({ at: iso(s.clock.t), kind: 'unlock', user: 'Хозяин', logonType: 7 });
    await s.away.tick();
    const r = s.away.report();
    const sp = r.spans[0];
    assert.equal(sp.failed, 2, 'старые попытки до блокировки не считаются');
    assert.deepEqual(sp.otherLogons, ['PC\\Гость']);
    assert.equal(sp.unlocks, 1);
    assert.equal(sp.calm, false);
    assert.equal(sp.level, 'alarm');
    assert.deepEqual(sp.reasons.sort(), ['failed', 'logon', 'remote', 'usb'].sort());
    const h = ru(sp.headline);
    assert.match(h, /неверный пароль: 2/);
    assert.match(h, /вход под другой учётной записью: PC\\Гость/);
    assert.match(h, /подключали диск или флешку: 1/);
    assert.match(h, /к сеансу подключались удалённо/);
    assert.ok(sp.events.some((e) => e.kind === 'failed' && ru(e.text) === 'Неверный пароль для «admin»'));
    assert.equal(r.last.calm, false);
    assert.equal(r.last.level, 'alarm');
    // «Это был я» - сводка спокойная.
    s.away.acknowledge(r.last.ids);
    assert.equal(s.away.report().last.calm, true);
  } finally { s.cleanup(); }
});

test('журнал входов не виден: честная формулировка и редкие попытки', async () => {
  const s = setup();
  try {
    s.st.logons = { visible: false };
    s.ev('lock');
    for (let i = 0; i < 20; i += 1) { await s.away.tick(); s.adv(15_000); }
    assert.equal(s.st.logonCalls, 1, 'не видно - повтор не раньше чем через 10 минут');
    s.ev('unlock');
    await s.away.tick();
    assert.equal(s.st.logonCalls, 1, 'после разблокировки тоже не дёргаем журнал зря');
    const sp = s.away.report().spans[0];
    assert.equal(sp.calm, true);
    assert.equal(sp.logonsVisible, false);
    assert.match(ru(sp.headline), /ничего необычного$/);
    assert.match(ru(sp.note), /правами администратора/);
  } finally { s.cleanup(); }
});

test('короткая разблокировка, пока вас не было, попадает в сводку', async () => {
  const s = setup();
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(20 * MIN); s.ev('unlock'); await s.away.tick();
    s.adv(15_000); s.st.procs.push({ name: 'cmd.exe', pid: 501, session: 1 }); await s.away.tick();
    s.adv(4 * MIN); s.ev('lock'); await s.away.tick();
    s.adv(60 * MIN); s.ev('unlock'); await s.away.tick();
    const r = s.away.report();
    assert.equal(r.spans.length, 2);
    const [later, earlier] = r.spans;
    assert.equal(later.calm, true);
    assert.ok(earlier.reasons.includes('brief'));
    assert.equal(earlier.calm, false);
    assert.deepEqual(earlier.processes.map((p) => [p.name, p.after]), [['cmd.exe', true]]);
    assert.deepEqual(r.last.ids, [later.id, earlier.id]);
    assert.equal(r.last.from, earlier.from);
    assert.equal(r.last.calm, false);
    assert.match(ru(r.last.headline), /компьютер разблокировали в \d\d:\d\d на 4 мин/);
  } finally { s.cleanup(); }
});

test('снимки: запрос после неверного пароля, не чаще раза в минуту, не больше трёх за отрезок', async () => {
  const s = setup({ settings: { awayPhoto: true } });
  try {
    s.ev('lock'); await s.away.tick();
    assert.equal(s.away.photoRequest(), null);
    const fail = (n) => { for (let i = 0; i < n; i += 1) s.st.logons.items.push({ at: iso(s.clock.t - i * 1000), kind: 'failed', user: 'x', logonType: 7 }); };
    s.adv(30_000); fail(1); await s.away.tick();
    const p1 = s.away.photoRequest();
    assert.match(p1.id, /^[a-f0-9]{32}$/);
    assert.deepEqual(s.away.photoRequest(), p1, 'тот же запрос, пока значок не ответил');
    assert.ok(fs.statSync(path.join(s.dataDir, 'away', 'photos')).isDirectory());
    // Ответ значка - строгая проверка.
    assert.throws(() => s.away.photoDone({ id: 'x', ok: true }), (e) => e.status === 400);
    assert.throws(() => s.away.photoDone({ id: p1.id, ok: 'yes' }), (e) => e.status === 400);
    assert.throws(() => s.away.photoDone({ id: p1.id, ok: true, path: 'C:\\x.jpg' }), (e) => e.status === 400);
    assert.throws(() => s.away.photoDone({ id: 'a'.repeat(32), ok: true }), (e) => e.status === 400);
    fs.writeFileSync(path.join(s.dataDir, 'away', 'photos', `${p1.id}.jpg`), JPEG);
    assert.deepEqual(s.away.photoDone({ id: p1.id, ok: true }), { ok: true, saved: true });
    assert.equal(s.away.photoRequest(), null);
    // Новая попытка через 30 секунд - рано; через минуту - можно.
    s.adv(30_000); fail(1); await s.away.tick();
    assert.equal(s.away.photoRequest(), null);
    s.adv(31_000); await s.away.tick();
    const p2 = s.away.photoRequest();
    assert.ok(p2 && p2.id !== p1.id);
    // Значок сообщил: камеры нет. Файл, которого не должно быть, удаляется.
    assert.deepEqual(s.away.photoDone({ id: p2.id, ok: false, error: 'no-camera' }), { ok: true, saved: false });
    s.adv(61_000); fail(1); await s.away.tick();
    const p3 = s.away.photoRequest();
    assert.ok(p3);
    fs.writeFileSync(path.join(s.dataDir, 'away', 'photos', `${p3.id}.jpg`), 'не картинка, а текст достаточной длины'.repeat(10));
    assert.deepEqual(s.away.photoDone({ id: p3.id, ok: true }), { ok: true, saved: false });
    assert.equal(fs.existsSync(path.join(s.dataDir, 'away', 'photos', `${p3.id}.jpg`)), false);
    // Четвёртого снимка за отрезок нет.
    s.adv(61_000); fail(1); await s.away.tick();
    s.adv(61_000); await s.away.tick();
    assert.equal(s.away.photoRequest(), null);
    s.ev('unlock'); await s.away.tick();
    const sp = s.away.report().spans[0];
    assert.deepEqual(sp.photos.map((p) => p.id), [p1.id]);
    assert.ok(sp.events.some((e) => e.kind === 'photo' && /камеры нет/.test(ru(e.text))));
    assert.ok(sp.events.some((e) => e.kind === 'photo' && /не сохранился/.test(ru(e.text))));
    // Снимок для окна.
    const data = s.away.photoData(p1.id);
    assert.ok(data.startsWith('data:image/jpeg;base64,'));
    assert.deepEqual(Buffer.from(data.split(',')[1], 'base64'), JPEG);
    assert.equal(s.away.photoData(p2.id), null);
    assert.throws(() => s.away.photoData('../../server.json'), (e) => e.status === 400);
    assert.throws(() => s.away.photoData(p1.id.toUpperCase()), (e) => e.status === 400);
  } finally { s.cleanup(); }
});

test('снимки: значок не ответил вовремя; снимок после разблокировки, если были неверные пароли; выключено - нет запросов', async () => {
  const s = setup({ settings: { awayPhoto: true } });
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(30_000);
    s.st.logons.items.push({ at: iso(s.clock.t), kind: 'failed', user: 'x', logonType: 7 });
    await s.away.tick();
    const p = s.away.photoRequest();
    assert.ok(p);
    s.adv(3 * MIN);
    assert.equal(s.away.photoRequest(), null, 'запрос устарел');
    s.ev('unlock');
    await s.away.tick();
    const p2 = s.away.photoRequest();
    assert.ok(p2, 'кто-то вошёл после неверных паролей - снимок того, кто сел за компьютер');
    assert.throws(() => s.away.photoDone({ id: p.id, ok: true }), (e) => e.status === 400, 'старый номер не принимается');
    s.away.photoDone({ id: p2.id, ok: false, error: 'blocked' });
    const sp = s.away.report().spans[0];
    assert.ok(sp.events.some((e) => /не ответил/.test(ru(e.text))));
    assert.ok(sp.events.some((e) => /конфиденциальности/.test(ru(e.text))));
    // Снимки выключены - запросов нет.
    s.store.write('settings.json', { ...s.store.read('settings.json', {}), awayPhoto: false });
    s.adv(5 * MIN); s.ev('lock'); await s.away.tick();
    s.adv(MIN); s.st.logons.items.push({ at: iso(s.clock.t), kind: 'failed', user: 'x', logonType: 7 });
    await s.away.tick();
    assert.equal(s.away.photoRequest(), null);
  } finally { s.cleanup(); }
});

test('журнал переживает перезапуск сервера; запуск значка после перезагрузки закрывает отрезок', async () => {
  const s = setup();
  try {
    s.ev('lock'); await s.away.tick();
    s.adv(MIN); s.ev('usb', { drive: 'G:' });
    const a2 = s.restart();
    assert.equal(a2.status().active, true);
    s.adv(30 * MIN);
    a2.event({ kind: 'start', at: iso(s.clock.t) });
    const r = a2.report();
    assert.equal(r.spans.length, 1);
    assert.equal(r.spans[0].endKind, 'start');
    assert.equal(r.spans[0].usb.length, 1);
    assert.ok(r.spans[0].events.some((e) => e.kind === 'start' && /перезагружали/.test(ru(e.text))));
    // start без открытого отрезка ничего не делает.
    assert.equal(a2.event({ kind: 'start', at: iso(s.clock.t) }).recorded, false);
    const a3 = s.restart();
    assert.equal(a3.report().spans[0].id, r.spans[0].id);
    // Испорченный файл журнала - начинаем с чистого листа.
    fs.writeFileSync(path.join(s.dataDir, 'away.json'), '{ сломано');
    assert.equal(s.restart().report().spans.length, 0);
  } finally { s.cleanup(); }
});

test('ограничения: 14 дней, снимки старых отрезков удаляются, события и программы с потолком, отрезок не длиннее суток', async () => {
  const s = setup({ settings: { awayPhoto: true } });
  try {
    s.ev('lock'); await s.away.tick();
    for (let i = 0; i < 300; i += 1) s.ev('usb', { drive: 'E:' });
    for (let i = 0; i < 200; i += 1) s.st.procs.push({ name: `app${i}.exe`, pid: 10_000 + i, session: 1 });
    s.adv(15_000); await s.away.tick();
    s.adv(30_000); s.st.logons.items.push({ at: iso(s.clock.t), kind: 'failed', user: 'x', logonType: 7 }); await s.away.tick();
    const p = s.away.photoRequest();
    const photo = path.join(s.dataDir, 'away', 'photos', `${p.id}.jpg`);
    fs.writeFileSync(photo, JPEG);
    s.away.photoDone({ id: p.id, ok: true });
    s.ev('unlock');
    const sp = s.away.report().spans[0];
    assert.ok(sp.events.length <= 150);
    assert.ok(sp.usb.length <= 20);
    assert.ok(sp.processes.length <= 60);
    // Сутки без разблокировки - отрезок закрывается сам.
    s.ev('lock');
    s.adv(25 * 3600_000);
    await s.away.tick();
    assert.equal(s.away.status().active, false);
    assert.equal(s.away.report().spans[0].endKind, 'lost');
    // Через 15 дней всё старое убрано вместе со снимком.
    s.adv(15 * 24 * 3600_000);
    const a2 = s.restart();
    assert.equal(a2.report().spans.length, 0);
    assert.equal(fs.existsSync(photo), false);
    assert.ok(fs.statSync(path.join(s.dataDir, 'away.json')).size < 1_600_000);
  } finally { s.cleanup(); }
});

test('файлы: изменения в папках только во время отрезка, без временных файлов и приманок', async (t) => {
  const s0 = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'adamant-away-dirs-')));
  const docs = path.join(s0, 'Documents');
  const down = path.join(s0, 'Downloads');
  fs.mkdirSync(path.join(docs, 'Отчёты'), { recursive: true });
  fs.mkdirSync(down);
  const s = setup({ watchDirs: () => Promise.resolve([docs, down, path.join(docs, 'Отчёты'), path.join(s0, 'нет такой')]) });
  t.after(() => fs.rmSync(s0, { recursive: true, force: true }));
  try {
    fs.writeFileSync(path.join(docs, 'до.txt'), 'до блокировки');
    s.ev('lock');
    assert.ok(await waitFor(() => s.away.status().watching === 2), 'вложенная папка не смотрится дважды, несуществующая пропущена');
    fs.writeFileSync(path.join(docs, 'Отчёты', 'отчёт.docx'), 'x');
    fs.writeFileSync(path.join(docs, '~$отчёт.docx'), 'x');
    fs.writeFileSync(path.join(docs, 'a.tmp'), 'x');
    fs.writeFileSync(path.join(docs, '!_Адамант_контроль.docx'), 'x');
    fs.writeFileSync(path.join(down, 'setup.exe'), 'x');
    assert.ok(await waitFor(() => { const r = s.away.report().spans[0]; return r.files.count >= 2; }));
    await new Promise((r) => setTimeout(r, 200));
    let sp = s.away.report().spans[0];
    assert.equal(sp.files.count, 2);
    const names = sp.files.sample.map((f) => path.basename(f.path)).sort();
    assert.deepEqual(names, ['setup.exe', 'отчёт.docx']);
    assert.equal(sp.calm, false);
    s.ev('unlock');
    assert.match(ru(s.away.report().spans[0].headline), /: изменились файлы: 2$/);
    s.away.acknowledge([sp.id]);
    await s.away.tick();
    assert.equal(s.away.status().watching, 0, 'после «Это был я» папки не отслеживаются');
    fs.writeFileSync(path.join(docs, 'после.txt'), 'x');
    await new Promise((r) => setTimeout(r, 300));
    sp = s.away.report().spans[0];
    assert.equal(sp.files.count + sp.files.afterCount, 2);
  } finally { s.cleanup(); }
});

test('разбор tasklist, кодировка OEM, служебные процессы и имена файлов', () => {
  const csv = '"System Idle Process","0","Services","0","8 K"\r\n"notepad.exe","1234","Console","1","12 345 K"\r\n"bad","x","","",""\r\nINFO: нет\r\n"a ""b"".exe","5","Console","1","1 K"\r\n';
  assert.deepEqual(parseTasklist(csv), [
    { name: 'System Idle Process', pid: 0, session: 0 }, { name: 'notepad.exe', pid: 1234, session: 1 }, { name: 'a "b".exe', pid: 5, session: 1 },
  ]);
  // «КБ» в cp866 - 0x8A 0x81.
  const ruBuf = Buffer.concat([Buffer.from('"Программа.exe","7","Console","1","8 ', 'latin1'), Buffer.from([0x8a, 0x81]), Buffer.from('"\r\n')]);
  const ruName = Buffer.from([0x8f, 0xe0, 0xae, 0xa3, 0xe0, 0xa0, 0xac, 0xac, 0xa0]); // «Программа» в cp866
  const buf = Buffer.concat([Buffer.from('"'), ruName, Buffer.from('.exe","7","Console","1","8 '), Buffer.from([0x8a, 0x81]), Buffer.from('"\r\n')]);
  assert.ok(ruBuf.length > 0);
  assert.equal(parseTasklist(decodeOem(buf))[0].name, 'Программа.exe');
  assert.equal(parseTasklist(decodeOem(Buffer.from(csv, 'latin1')))[1].name, 'notepad.exe');
  for (const n of ['svchost.exe', 'SVCHOST.EXE', 'conhost.exe', 'RuntimeBroker.exe', 'backgroundTaskHost.exe', 'dllhost.exe', 'SearchProtocolHost.exe', 'ngentask.exe', '']) assert.ok(isNoise(n), n);
  for (const n of ['notepad.exe', 'powershell.exe', 'cmd.exe', 'AnyDesk.exe', 'msiexec.exe']) assert.ok(!isNoise(n), n);
  for (const n of ['~$Отчёт.docx', 'x.tmp', 'X.TMP', 'file.crdownload', '!_Адамант_контроль.docx', 'desktop.ini', 'Thumbs.db', '.~lock.a.odt#', '']) assert.ok(ignoredFile(n), n);
  for (const n of ['Отчёт.docx', 'photo.jpg', 'tmp.txt']) assert.ok(!ignoredFile(n), n);
});

test('входы: массив, {visible:false}, файл помощника и мусор', () => {
  assert.deepEqual(normalizeLogons({ visible: false }), { visible: false, items: [] });
  assert.deepEqual(normalizeLogons(null), { visible: false, items: [] });
  assert.deepEqual(normalizeLogons('строка'), { visible: false, items: [] });
  assert.deepEqual(normalizeLogons({ something: [] }), { visible: false, items: [] });
  const helper = normalizeLogons({
    at: '2026-11-18T10:00:00Z',
    failed: [{ at: '2026-11-18T09:00:00Z', user: 'Вася', logonType: 2, ip: '-' }, { at: 'плохо' }, null, 5, { user: 'без времени' }],
    logons: [{ at: '2026-11-18T09:05:00Z', user: 'Хозяин', logonType: 7 }, { at: '2026-11-18T09:05:01Z', user: 'Хозяин', logonType: 7 },
      { at: '2026-11-18T09:06:00Z', user: 'SYSTEM', logonType: 2 }, { at: '2026-11-18T09:07:00Z', user: 'PC$', logonType: 2 },
      { at: '2026-11-18T09:08:00Z', user: 'Гость', logonType: 'x' }],
    unknown: 'поле',
  });
  assert.equal(helper.visible, true);
  assert.deepEqual(helper.items, [
    { at: '2026-11-18T09:00:00.000Z', kind: 'failed', user: 'Вася', logonType: 2 },
    { at: '2026-11-18T09:05:00.000Z', kind: 'unlock', user: 'Хозяин', logonType: 7 },
    { at: '2026-11-18T09:08:00.000Z', kind: 'logon', user: 'Гость', logonType: null },
  ]);
  const arr = normalizeLogons([{ at: '2026-11-18T09:00:00Z', kind: 'hack', user: 'x' }, { at: '2026-11-18T09:00:00Z', kind: 'failed', user: 'a\u0000b'.repeat(100) }]);
  assert.equal(arr.items.length, 1);
  assert.ok(arr.items[0].user.length <= 128 && !arr.items[0].user.includes('\u0000'));
});

test('logons.ps1 только читает', () => {
  const WRITE = /\b(Set-\w+|New-ItemProperty|New-Item\b|Remove-\w+|Disable-\w+|Enable-\w+|Stop-\w+|Start-Service|Restart-\w+|Add-MpPreference|Rename-\w+|Clear-\w+|Invoke-Expression|Out-File|Add-Content|reg(\.exe)?\s+(add|delete)|wevtutil\s+(cl|sl)|auditpol\s+\/set)\b/i;
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'logons.ps1'), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.equal(WRITE.exec(src), null);
  assert.doesNotMatch(src, /WriteAll|\.Delete\(|\.Move\(/);
});

test('camera.ps1 пишет только в away\\photos\\<номер>.jpg', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'windows', 'camera.ps1'), 'utf8');
  assert.match(src, /\^\[a-f0-9\]\{32\}\\\.jpg\$/);
  assert.match(src, /-eq 'photos'/);
  assert.match(src, /-eq 'away'/);
  assert.doesNotMatch(src, /Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Set-ItemProperty|New-ItemProperty/i);
});
