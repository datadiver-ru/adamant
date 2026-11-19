'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const deep = require('../server/rules-deep');
const rules = require('../server/rules');
const fixes = require('../server/fixes');
const { guide, GUIDES, OPEN_TARGETS } = require('../server/guides');
const { GUIDES: DEEP_GUIDES } = require('../server/guides-deep');
const { render } = require('../server/i18n');
const { strong, weak, NOW } = require('./fixtures/deep');
const { good } = require('./fixtures/facts');

const ROOT = path.join(__dirname, '..');
const FIX_PS = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'fix.ps1'), 'utf8');
const SECTION = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'sections', 'hardening.ps1'), 'utf8');
const byId = (list) => new Map(list.map((f) => [f.id, f]));

test('глубокие проверки: крепкий компьютер - только «в порядке»', () => {
  const list = deep.evaluate(strong(), { now: NOW });
  assert.deepEqual(list.filter((f) => f.sev !== 'ok').map((f) => f.id), []);
  const ids = byId(list);
  for (const id of ['hard-lsa-ppl-ok', 'hard-ntlm-ok', 'hard-hvci-ok', 'hard-defender-extra-ok', 'hard-smartscreen-ok', 'hard-driver-blocklist-ok', 'hard-name-spoofing-ok', 'hard-office-macros-ok']) {
    assert.ok(ids.has(id), `нет находки ${id}`);
  }
});

test('глубокие проверки: слабый компьютер - правильные находки и важность', () => {
  const ids = byId(deep.evaluate(weak(), { now: NOW }));
  const expect = {
    'hard-lsa-ppl-off': 'advice', 'hard-wdigest-on': 'high', 'hard-ntlmv1': 'high', 'hard-lm-hash': 'high', 'hard-cached-logons': 'advice',
    'hard-hvci-off': 'advice', 'hard-credguard-off': 'advice', 'hard-cfa-off': 'advice', 'hard-asr': 'advice', 'hard-pua-off': 'advice',
    'hard-cloud-off': 'high', 'hard-smartscreen-off': 'high', 'hard-driver-blocklist-off': 'advice', 'hard-llmnr-on': 'advice',
    'hard-netbios-on': 'advice', 'hard-wpad': 'advice', 'hard-smb-signing': 'advice', 'hard-winrm-on': 'advice',
    'hard-remote-assistance-on': 'advice', 'hard-remote-registry-on': 'advice', 'hard-spooler-idle': 'advice', 'hard-ps2': 'advice',
    'hard-execpolicy': 'advice', 'hard-autorun': 'advice', 'hard-office-macros-all': 'high', 'hard-office-macros-internet': 'advice',
  };
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
  // Никаких «критично»: это слабые настройки, а не активная опасность.
  assert.equal([...ids.values()].filter((f) => f.sev === 'critical').length, 0);
  // Сетевые адаптеры: VPN с выключенным NetBIOS в список не попадает.
  assert.equal(ids.get('hard-netbios-on').evidence.length, 2);
  // Правило ASR, которое уже блокирует, не перечисляется; правило в режиме журнала - перечисляется.
  assert.equal(ids.get('hard-asr').evidence.length, 5);
});

test('глубокие проверки: находки ссылаются на исправления и инструкции, которые есть', () => {
  for (const f of deep.evaluate(weak(), { now: NOW })) {
    assert.equal(f.cat, 'hardening');
    assert.match(f.id, /^hard-[a-z0-9-]+$/);
    assert.ok(render('ru', f.title) && render('ru', f.text), f.id);
    assert.ok(Array.isArray(f.evidence), f.id);
    if (f.fix) {
      assert.ok(fixes.FIXES[f.fix.id], `нет исправления ${f.fix.id}`);
      assert.ok(FIX_PS.includes(`'${f.fix.id}' = `), `fix.ps1 не знает ${f.fix.id}`);
    }
    if (f.guide) {
      const g = guide(f.guide, weak());
      assert.ok(g, `нет инструкции ${f.guide}`);
      assert.ok(g.steps.length >= 2, f.guide);
      for (const o of g.open) assert.ok(OPEN_TARGETS[o.id], o.id);
    }
    if (f.sev !== 'ok' && f.sev !== 'unknown') assert.ok(f.fix || f.guide || f.id === 'hard-cached-logons', `${f.id}: нет ни исправления, ни инструкции`);
  }
  for (const id of Object.keys(DEEP_GUIDES)) {
    assert.ok(GUIDES[id], id);
    assert.ok(guide(id, {}).steps.length >= 2, id);
  }
});

test('глубокие проверки: старый отчёт без раздела - ничего; ошибка раздела - одна находка «не видно»', () => {
  assert.deepEqual(deep.evaluate(good(), { now: NOW }), []);
  assert.deepEqual(deep.evaluate({}, { now: NOW }), []);
  const f = good();
  f.errors = { hardening: 'Отказано в доступе' };
  const list = deep.evaluate(f, { now: NOW });
  assert.equal(list.length, 1);
  assert.equal(list[0].sev, 'unknown');
  assert.equal(list[0].cat, 'hardening');
});

test('другой антивирус: настройки Defender не считаются проблемами', () => {
  const f = weak();
  f.defender = { status: { serviceEnabled: true, antivirusEnabled: false, realTime: false, mode: 'Passive Mode' }, products: [{ name: 'Kaspersky', state: 266240 }, { name: 'Windows Defender', state: 393472 }] };
  const ids = byId(deep.evaluate(f, { now: NOW }));
  assert.equal(ids.get('hard-defender-other').sev, 'ok');
  for (const id of ['hard-cfa-off', 'hard-asr', 'hard-pua-off', 'hard-cloud-off', 'hard-samples-never']) assert.ok(!ids.has(id), id);
  // Нет сведений о Defender - «не видно», а не проблема.
  const g = weak();
  g.hardening.mp = { available: false, error: 'Служба не запущена' };
  const u = byId(deep.evaluate(g, { now: NOW }));
  assert.equal(u.get('hard-defender-unknown').sev, 'unknown');
  assert.ok(!u.has('hard-cfa-off'));
});

test('глубокие проверки: тонкие случаи', () => {
  // Защита LSA на Windows 10: кнопки нет (откат там сложнее), только инструкция.
  let f = weak();
  f.hardening.build = 19045;
  let ids = byId(deep.evaluate(f, { now: NOW }));
  assert.equal(ids.get('hard-lsa-ppl-off').fix, undefined);
  assert.equal(ids.get('hard-lsa-ppl-off').guide, 'hard-lsa');
  // Защита LSA подтверждена событием этой загрузки, даже если в реестре пусто.
  f = weak();
  f.hardening.lsa.pplEvent = { at: new Date(NOW - 1_000_000).toISOString(), level: 4 };
  assert.ok(byId(deep.evaluate(f, { now: NOW })).has('hard-lsa-ppl-ok'));
  // Событие прошлой загрузки не считается.
  f.hardening.lsa.pplEvent.at = new Date(NOW - 10 * 86_400_000).toISOString();
  assert.ok(byId(deep.evaluate(f, { now: NOW })).has('hard-lsa-ppl-off'));
  // Удалённый помощник разрешён политикой - кнопка не поможет.
  f = weak();
  f.hardening.remoteAssistance.policy = 1;
  assert.equal(byId(deep.evaluate(f, { now: NOW })).get('hard-remote-assistance-on').fix, undefined);
  // Настоящий принтер - службу печати не трогаем.
  f = weak();
  f.hardening.printers.push({ name: 'Canon MF3010', port: 'USB001' });
  assert.ok(!byId(deep.evaluate(f, { now: NOW })).has('hard-spooler-idle'));
  // Не в домене - число запомненных входов не важно; Credential Guard только для корпоративных выпусков.
  f = strong();
  f.hardening.cachedLogons = '50';
  f.meta.edition = 'Core';
  ids = byId(deep.evaluate(f, { now: NOW }));
  assert.ok(!ids.has('hard-cached-logons'));
  assert.ok(!ids.has('hard-credguard-off'));
  // Список уязвимых драйверов не задан: на Windows 11 22H2+ он включён по умолчанию, на Windows 10 - нет.
  f = strong();
  f.hardening.driverBlocklist = null;
  f.hardening.deviceGuard.running = [];
  assert.ok(byId(deep.evaluate(f, { now: NOW })).has('hard-driver-blocklist-ok'));
  f.hardening.build = 19045;
  assert.ok(byId(deep.evaluate(f, { now: NOW })).has('hard-driver-blocklist-off'));
  // Изоляция ядра не прочиталась - «не видно».
  f = strong();
  f.hardening.deviceGuard = { vbs: null, running: [], error: 'Недопустимое пространство имён' };
  assert.equal(byId(deep.evaluate(f, { now: NOW })).get('hard-hvci-unknown').sev, 'unknown');
  // Без Office - без находок про макросы.
  f = weak();
  f.hardening.office = [];
  assert.ok(![...byId(deep.evaluate(f, { now: NOW })).keys()].some((id) => id.startsWith('hard-office')));
});

test('глубокие проверки входят в общий список находок', () => {
  const ids = byId(rules.evaluate(weak(), { now: NOW }));
  assert.equal(ids.get('hard-wdigest-on').sev, 'high');
  assert.equal(rules.CATEGORIES.hardening, 'Защита от взлома');
  // «Хороший» компьютер из общих тестов по-прежнему без критичных и важных находок.
  const s = rules.summarize(rules.evaluate(strong(), { now: NOW }));
  assert.equal(s.critical + s.high, 0);
});

test('раздел hardening: обёрнут в Section, только чтение, без медленных и меняющих команд', () => {
  assert.match(SECTION, /^﻿?#/);
  assert.match(SECTION, /Section 'hardening' \{/);
  assert.doesNotMatch(SECTION, /Get-WindowsOptionalFeature|Get-WmiObject|Win32_Product|Invoke-|Start-Process/i);
  // Списки правил ASR и программ специальных возможностей одинаковые в JS и fix.ps1.
  for (const id of Object.keys(deep.SAFE_ASR)) assert.ok(FIX_PS.includes(`'${id}'`), id);
  for (const exe of ['sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe']) assert.ok(FIX_PS.includes(`'${exe}'`), exe);
});
