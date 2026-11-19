'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const checklist = require('../server/checklist');
const bluetooth = require('../server/bluetooth');
const { OPEN_TARGETS } = require('../server/guides');

// ---- Чек-лист

test('чек-лист: у пунктов уникальные id, известные группы и настройки', () => {
  const groups = new Set(checklist.GROUPS.map((g) => g.id));
  const ids = new Set();
  for (const i of checklist.ITEMS) {
    assert.ok(!ids.has(i.id), `повтор id ${i.id}`);
    ids.add(i.id);
    assert.ok(groups.has(i.group), `${i.id}: неизвестная группа ${i.group}`);
    assert.ok(i.title && i.why && i.how, `${i.id}: нет текста`);
    if (i.open) assert.ok(OPEN_TARGETS[i.open], `${i.id}: неизвестная настройка ${i.open}`);
  }
  for (const g of groups) assert.ok(checklist.ITEMS.some((i) => i.group === g), `пустая группа ${g}`);
  // Пояснения про сетевой экран и раздельную сеть.
  const net = checklist.GROUPS.find((g) => g.id === 'network');
  assert.equal(net.intro.length, 2);
});

test('чек-лист: шаблоны находок', () => {
  assert.ok(checklist.matches('firewall-*', 'firewall-off-public'));
  assert.ok(!checklist.matches('firewall-*', 'port-smb-nofw'));
  assert.ok(checklist.matches('smb1*', 'smb1'));
  assert.ok(checklist.matches('guest-on', 'guest-on'));
  assert.ok(!checklist.matches('guest-on', 'guest-on-2'));
});

test('чек-лист: состояние пункта по находкам', () => {
  const item = checklist.ITEMS.find((i) => i.id === 'firewall');
  assert.deepEqual(checklist.itemState(item, []), { state: null, fix: null, findings: [] });
  assert.equal(checklist.itemState(item, [{ id: 'firewall-ok', sev: 'ok' }]).state, 'ok');
  const fix = { action: 'firewall-on' };
  const st = checklist.itemState(item, [
    { id: 'firewall-ok', sev: 'ok' },
    { id: 'firewall-off-public', sev: 'high' },
    { id: 'firewall-off-private', sev: 'critical', fix },
    { id: 'defender-off', sev: 'critical', fix: { action: 'x' } },
  ]);
  assert.equal(st.state, 'todo');
  assert.deepEqual(st.fix, fix, 'исправление - первой проблемной находки этого пункта, у которой оно есть');
  assert.deepEqual(st.findings, ['firewall-off-public', 'firewall-off-private']);
  // Мусор в находках не ломает разбор.
  assert.equal(checklist.itemState(item, [null, { id: 5 }, { sev: 'high' }]).state, null);
  // Пункт без проверок программа не отмечает.
  const manual = checklist.ITEMS.find((i) => !i.checks);
  assert.ok(manual, 'есть пункты, которые отмечает только пользователь');
  assert.equal(checklist.itemState(manual, [{ id: 'firewall-off-public', sev: 'high' }]).state, null);
});

test('чек-лист: отметки пользователя - только известные пункты и строки', () => {
  assert.deepEqual(checklist.cleanMarks(null), {});
  assert.deepEqual(checklist.cleanMarks({ done: 'x' }), {});
  const m = checklist.cleanMarks({ done: { firewall: '2026-11-18T12:00:00.000Z', nope: '2026', backup: 5, wifi: 'x'.repeat(100) } });
  assert.deepEqual(Object.keys(m).sort(), ['firewall', 'wifi']);
  assert.equal(m.wifi.length, 40);
});

// ---- Bluetooth

const RAW = (over = {}) => ({
  format: 'adamant-bluetooth', at: '2026-11-18T12:00:00.000Z', seconds: 10,
  radio: { present: true, on: true, name: 'Bluetooth' },
  adapter: { name: 'TP-Link Bluetooth USB Adapter', status: 'OK' },
  paired: [], nearby: [], errors: {}, ...over,
});

test('Bluetooth: неверный ответ сценария - ошибка', () => {
  assert.throws(() => bluetooth.analyse(null));
  assert.throws(() => bluetooth.analyse({ format: 'other' }));
});

test('Bluetooth: нет адаптера - одна спокойная находка', () => {
  const r = bluetooth.analyse(RAW({ radio: { present: false, on: false }, adapter: null }));
  assert.deepEqual(r.findings.map((f) => f.id), ['bt-none']);
});

test('Bluetooth: выключен - спокойно, совет не нужен', () => {
  const r = bluetooth.analyse(RAW({ radio: { present: true, on: false } }));
  assert.deepEqual(r.findings.map((f) => f.id), ['bt-off']);
});

test('Bluetooth: включён без сопряжённых устройств - совет выключить', () => {
  const r = bluetooth.analyse(RAW());
  assert.deepEqual(r.findings.map((f) => f.id), ['bt-on-unused']);
  assert.equal(r.findings[0].sev, 'advice');
});

test('Bluetooth: сопряжённое устройство для атак - критично', () => {
  const r = bluetooth.analyse(RAW({
    paired: [
      { name: 'BadUSB Demo', mac: 'a1b2c3d4e5f6', le: true, hid: true, status: 'OK' },
      { name: 'MX Keys', mac: '001122334455', hid: true, status: 'OK' },
      { name: 'AirPods Pro', mac: '665544332211', audio: true, status: 'OK' },
    ],
  }));
  const bad = r.findings.find((f) => f.id === 'bt-attack-paired');
  assert.equal(bad.sev, 'critical');
  assert.match(JSON.stringify(bad.title), /BadUSB Demo/);
  assert.equal(r.paired[0].mac, 'A1:B2:C3:D4:E5:F6');
  assert.equal(r.paired[0].kind, 'attack');
  assert.equal(r.paired[1].kind, 'hid');
  assert.equal(r.paired[2].kind, 'audio');
  const hid = r.findings.find((f) => f.id === 'bt-hid-paired');
  assert.equal(hid.evidence.length, 1, 'устройство для атак не считается обычной клавиатурой');
  assert.ok(!r.findings.some((f) => f.id === 'bt-ok'));
});

test('Bluetooth: кто рядом - метки, устройства для атак, рассылка', () => {
  const apple = (i, type) => ({ addr: 'AABBCCDDEE' + String(i).padStart(2, '0'), rssi: -80, n: 3, mf: ['004C:' + type + '0511'], random: true });
  const r = bluetooth.analyse(RAW({
    paired: [{ name: 'Keyboard', mac: '001122334455', hid: true, status: 'OK' }],
    nearby: [
      { addr: '112233445566', rssi: -50, n: 9, mf: ['004C:1219AB'], random: true },
      { addr: '112233445577', rssi: -90, n: 2, svc: ['FD5A'] },
      { addr: '112233445588', rssi: -70, n: 5, name: 'Flipper Zero', connectable: true },
      { addr: '001122334455', rssi: -40, n: 5, name: 'Keyboard', svc: ['1812'] },
      { addr: 'zz', rssi: -40 },
      'мусор',
      ...[1, 2, 3, 4, 5].map((i) => apple(i, '0F')),
    ],
  }));
  assert.equal(r.nearby.length, 9, 'неверные адреса отброшены');
  assert.equal(r.nearby[0].addr, '00:11:22:33:44:55', 'ближние - первыми');
  assert.equal(r.nearby[0].paired, true);
  const tag = r.nearby.find((d) => d.addr === '11:22:33:44:55:66');
  assert.equal(tag.kind, 'tracker');
  assert.equal(tag.vendor, 'Apple');
  assert.equal(r.nearby.find((d) => d.addr === '11:22:33:44:55:77').tracker, 'Samsung SmartTag');
  assert.equal(r.counts.trackers, 2);
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('bt-attack-nearby'));
  assert.ok(ids.includes('bt-spam'));
  assert.ok(ids.includes('bt-tracker-close'));
  assert.equal(r.findings.find((f) => f.id === 'bt-tracker-close').evidence.length, 1, 'дальняя метка - без тревоги');
});

test('Bluetooth: имена и данные чистятся', () => {
  const r = bluetooth.analyse(RAW({
    paired: [{ name: 'x\u0007y'.repeat(50), mac: '001122334455' }],
    nearby: [{ addr: '112233445566', rssi: 999, n: 1e9, name: 'a\nb', mf: ['zz', '0075:01', 5], svc: 'FEED' }],
  }));
  assert.ok(!/[\u0000-\u001f]/.test(r.paired[0].name));
  assert.ok(r.paired[0].name.length <= 80);
  const d = r.nearby[0];
  assert.equal(d.rssi, 20);
  assert.equal(d.seen, 100000);
  assert.equal(d.name, 'ab');
  assert.deepEqual(d.mf, ['0075:01']);
  assert.equal(d.kind, 'tracker');
  assert.equal(d.vendor, 'Samsung', 'производитель по коду в объявлении');
});
