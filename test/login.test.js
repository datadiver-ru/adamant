'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const login = require('../server/rules-login');
const rules = require('../server/rules');
const fixes = require('../server/fixes');
const { plan } = require('../server/bitlocker-plan');
const { guide, GUIDES, OPEN_TARGETS } = require('../server/guides');
const { GUIDES: LOGIN_GUIDES } = require('../server/guides-login');
const { render } = require('../server/i18n');
const { good, bad } = require('./fixtures/facts');
const { strongFacts, weakFacts, NOW } = require('./fixtures/login');

const ROOT = path.join(__dirname, '..');
const FIX_PS = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'fix.ps1'), 'utf8');
const SECTION = fs.readFileSync(path.join(ROOT, 'server', 'ps', 'sections', 'login.ps1'), 'utf8');
const byId = (list) => new Map(list.map((f) => [f.id, f]));
const flat = (m) => render('ru', m);
const STATES = ['done', 'todo', 'blocked', 'unknown'];

// ---------------------------------------------------------------- Находки

test('вход в Windows: крепкий компьютер - только «в порядке»', () => {
  const list = login.evaluate(strongFacts(), { now: NOW });
  assert.deepEqual(list.filter((f) => f.sev !== 'ok').map((f) => f.id), []);
  const ids = byId(list);
  for (const id of ['login-lockout-ok', 'login-cad-ok', 'login-hello-pin-ok', 'phys-dynamic-lock-ok']) assert.ok(ids.has(id), `нет находки ${id}`);
  assert.match(flat(ids.get('login-lockout-ok').title), /10 неверных/);
});

test('вход в Windows: слабый компьютер - правильные находки, важность, исправления и инструкции', () => {
  const ids = byId(login.evaluate(weakFacts(), { now: NOW }));
  const expect = { 'login-lockout-off': 'high', 'login-cad-off': 'advice', 'login-hello-pin-none': 'advice', 'phys-dynamic-lock-off': 'advice' };
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
  assert.deepEqual(ids.get('login-lockout-off').fix, { id: 'lockout-policy' });
  assert.equal(ids.get('login-lockout-off').guide, 'lockout');
  assert.deepEqual(ids.get('login-cad-off').fix, { id: 'require-cad' });
  assert.equal(ids.get('login-hello-pin-none').guide, 'hello-pin');
  assert.equal(ids.get('phys-dynamic-lock-off').guide, 'dynamic-lock');
  assert.equal(ids.get('phys-dynamic-lock-off').cat, 'physical');
  assert.ok(ids.get('login-hello-pin-none').evidence.map(flat).some((e) => /Goodix/.test(e)), 'сканер отпечатков упомянут');
  assert.ok(ids.get('login-lockout-off').evidence.map(flat).some((e) => /не задан \(0\)/.test(e)));
});

test('блокировка входа: много попыток - совет; в домене - без кнопки; «навсегда» - понятным словом', () => {
  const f = weakFacts();
  f.login.lockout = { threshold: 50, windowSec: 1800, durationSec: 4294967295 };
  let x = byId(login.evaluate(f)).get('login-lockout-high');
  assert.equal(x.sev, 'advice');
  assert.deepEqual(x.fix, { id: 'lockout-policy' });
  assert.ok(x.evidence.map(flat).some((e) => /до разблокировки администратором/.test(e)));
  f.login.partOfDomain = true;
  x = byId(login.evaluate(f)).get('login-lockout-high');
  assert.equal(x.fix, undefined, 'в домене правила задаёт администратор - кнопки нет');
  assert.equal(x.guide, 'lockout');
  f.login.lockout.threshold = 3;
  assert.equal(byId(login.evaluate(f)).get('login-lockout-ok').sev, 'ok');
  // Не удалось прочитать - «не видно», без ложной тревоги.
  f.login.lockout = null;
  f.login.errors = { lockout: 'NetUserModalsGet: 5' };
  assert.equal(byId(login.evaluate(f)).get('login-lockout-unknown').sev, 'unknown');
});

test('ПИН-код Hello: о нём говорим, только если это точно известно', () => {
  const f = weakFacts();
  f.login.hello.pin = null;
  assert.ok(![...byId(login.evaluate(f)).keys()].some((id) => id.startsWith('login-hello')));
  f.login.cad.required = null;
  assert.ok(![...byId(login.evaluate(f)).keys()].some((id) => id.startsWith('login-cad')));
  delete f.physical;
  assert.ok(![...byId(login.evaluate(f)).keys()].some((id) => id.startsWith('phys-dynamic')), 'нет раздела physical - о динамической блокировке молчим');
});

test('вход в Windows: старый отчёт без раздела - ничего; ошибка раздела - одна находка «не видно»', () => {
  assert.deepEqual(login.evaluate(good(), { now: NOW }), []);
  assert.deepEqual(login.evaluate(bad(), { now: NOW }), []);
  assert.deepEqual(login.evaluate({}, { now: NOW }), []);
  assert.deepEqual(login.evaluate(undefined), []);
  const f = good();
  f.errors = { login: 'Access denied' };
  const list = login.evaluate(f);
  assert.equal(list.length, 1);
  assert.equal(list[0].sev, 'unknown');
  assert.doesNotThrow(() => login.evaluate({ login: {} }));
  assert.doesNotThrow(() => login.evaluate({ login: { lockout: {}, cad: {}, hello: {} }, physical: { lock: {} } }));
});

test('вход в Windows входит в общий список: ссылки на исправления и инструкции есть, id не повторяются', () => {
  for (const facts of [strongFacts(), weakFacts()]) {
    const all = rules.evaluate(facts, { now: NOW });
    const mine = all.filter((f) => /^login-|^phys-dynamic-lock/.test(f.id));
    assert.ok(mine.length >= 4);
    assert.equal(new Set(all.map((f) => f.id)).size, all.length, 'id находок не повторяются');
    for (const f of mine) {
      assert.ok(rules.SEVERITIES.includes(f.sev), f.id);
      assert.ok(rules.CATEGORIES[f.cat], f.id);
      assert.ok(flat(f.title) && flat(f.text) && Array.isArray(f.evidence), f.id);
      if (f.fix) {
        assert.ok(fixes.FIXES[f.fix.id], `нет исправления ${f.fix.id}`);
        assert.ok(FIX_PS.includes(`'${f.fix.id}' = `), `fix.ps1 не знает ${f.fix.id}`);
      }
      if (f.guide) {
        const g = guide(f.guide, facts);
        assert.ok(g && g.steps.length >= 2, f.guide);
        for (const o of g.open) assert.ok(OPEN_TARGETS[o.id], o.id);
      }
      if (f.sev !== 'ok' && f.sev !== 'unknown') assert.ok(f.fix || f.guide, `${f.id}: нет ни исправления, ни инструкции`);
    }
  }
  // «Хороший» компьютер из общих тестов (без раздела login) не меняется.
  const s = rules.summarize(rules.evaluate(good(), { now: NOW }));
  assert.equal(s.critical + s.high, 0);
});

// ---------------------------------------------------------------- Инструкции

test('инструкции входа: есть, работают без сведений, кнопки только из списка', () => {
  for (const id of ['lockout', 'dynamic-lock', 'hello-pin', 'bios-lock', 'bitlocker-pin-add']) {
    assert.ok(LOGIN_GUIDES[id] && GUIDES[id], id);
    const g = guide(id, {});
    assert.ok(g.steps.length >= 3, id);
    for (const o of g.open) assert.ok(OPEN_TARGETS[o.id], o.id);
  }
  const b = guide('bios-lock', bad()).steps.map(flat).join('\n');
  assert.match(b, /особые варианты загрузки/, 'вход в UEFI - общими шагами enterFirmware');
  assert.match(b, /F2/, 'клавиша производителя (Dell)');
  assert.match(b, /Secure Boot/);
  assert.match(b, /USB/);
  assert.match(b, /Boot Menu/);
  assert.match(flat(guide('bios-lock', {}).intro), /CMOS/, 'честно: пароль BIOS можно сбросить');
  assert.match(flat(guide('bios-lock', {}).intro), /BitLocker с ПИН-кодом/);
  const add = guide('bitlocker-pin-add', good()).steps.map(flat).join('\n');
  assert.match(add, /Изменить способ разблокировки диска при запуске/);
  assert.match(add, /manage-bde -protectors -add C: -TPMAndPIN/);
  assert.match(guide('lockout', {}).steps.map(flat).join('\n'), /net accounts \/lockoutthreshold:10/);
});

// ---------------------------------------------------------------- Сбор сведений

test('login.ps1: раздел login, только чтение, без подсказки к паролю и без запуска программ', () => {
  assert.match(SECTION, /^﻿/);
  assert.match(SECTION, /Section 'login' \{/);
  assert.match(SECTION, /admin = \$isAdmin/);
  assert.match(SECTION, /NetUserModalsGet/);
  assert.doesNotMatch(SECTION, /NetUserModalsSet|UserPasswordHint|Invoke-|Start-Process|Get-WmiObject|Win32_Product/i);
  assert.match(SECTION, /'DisableCAD'/);
  assert.match(SECTION, /Policies\\Microsoft\\FVE/);
  assert.match(SECTION, /'Adamant\.Login' -as \[type\]/, 'тип C# добавляется один раз');
});

// ---------------------------------------------------------------- Мастер «Закрыть вход в обход Windows»

function checkPlan(p, facts) {
  assert.ok(flat(p.headline), 'есть заголовок');
  assert.ok(['pro', 'home', 'unknown'].includes(p.edition));
  assert.ok(p.steps.length >= 3);
  assert.equal(new Set(p.steps.map((s) => s.id)).size, p.steps.length, 'id шагов не повторяются');
  for (const s of p.steps) {
    assert.ok(STATES.includes(s.state), s.id);
    assert.ok(flat(s.title) && flat(s.text), s.id);
    assert.doesNotMatch(flat(s.text), /\{\d\}|undefined|\[object/, s.id);
    if (s.fix) assert.ok(fixes.FIXES[s.fix.id] && FIX_PS.includes(`'${s.fix.id}' = `), s.fix.id);
    if (s.guide) assert.ok(guide(s.guide, facts), s.guide);
    for (const o of s.open || []) assert.ok(OPEN_TARGETS[o.id] && o.label, o.id);
  }
  return new Map(p.steps.map((s) => [s.id, s]));
}

test('мастер: диск не зашифрован, политика не задана - сначала разрешить ПИН-код, потом мастер Windows', () => {
  const f = weakFacts();
  f.boot.tpmDevices = [{ name: 'Trusted Platform Module 2.0', status: 'OK' }];
  const p = plan(f);
  assert.equal(p.available, true);
  assert.equal(p.edition, 'pro');
  const s = checkPlan(p, f);
  assert.deepEqual([...s.keys()], ['recovery-key', 'pin-policy', 'turn-on', 'firmware']);
  assert.equal(s.get('recovery-key').state, 'todo');
  assert.match(flat(s.get('recovery-key').text), /мастер BitLocker/);
  assert.equal(s.get('pin-policy').state, 'todo');
  assert.deepEqual(s.get('pin-policy').fix, { id: 'bitlocker-pin-policy' });
  assert.equal(s.get('turn-on').state, 'blocked', 'пока политика не разрешает ПИН-код, мастер его не предложит');
  assert.equal(s.get('firmware').state, 'todo', 'нет пароля BIOS, Secure Boot выключен');
  assert.equal(s.get('firmware').guide, 'bios-lock');
  assert.match(flat(p.headline), /можно обойти/);
  // Политика разрешает - можно открывать мастер BitLocker.
  f.login.bitlocker.policy = { useAdvancedStartup: 1, useTpmPin: 2, useTpm: 2, useTpmKey: 2, useTpmKeyPin: 2 };
  const q = checkPlan(plan(f), f);
  assert.equal(q.get('pin-policy').state, 'done');
  assert.equal(q.get('turn-on').state, 'todo');
  assert.deepEqual(q.get('turn-on').open.map((o) => o.id), ['bitlocker']);
  assert.match(flat(q.get('turn-on').text), /Ввести ПИН-код/);
  // Без TPM - честно «нельзя», с инструкцией про TPM.
  f.boot.tpmDevices = [];
  const r = checkPlan(plan(f), f);
  assert.equal(r.get('turn-on').state, 'blocked');
  assert.equal(r.get('turn-on').guide, 'tpm');
});

test('мастер: диск зашифрован только с TPM - добавить ПИН-код; ключ восстановления виден с правами администратора', () => {
  const f = strongFacts();
  f.physical.bitlocker = { protectors: ['Tpm', 'RecoveryPassword'], preboot: 'tpm-only', protection: 'On', policy: {} };
  f.login.bitlocker.policy = { useAdvancedStartup: null, useTpmPin: null };
  let s = checkPlan(plan(f), f);
  assert.equal(s.get('recovery-key').state, 'done');
  assert.equal(s.get('pin-policy').state, 'todo');
  assert.equal(s.get('add-pin').state, 'blocked');
  f.login.bitlocker.policy = { useAdvancedStartup: 1, useTpmPin: 2 };
  s = checkPlan(plan(f), f);
  assert.equal(s.get('add-pin').state, 'todo');
  assert.equal(s.get('add-pin').guide, 'bitlocker-pin-add');
  assert.match(flat(s.get('add-pin').text), /Изменить способ разблокировки диска при запуске/);
  // Нет ключа восстановления - сказать прямо.
  f.physical.bitlocker.protectors = ['Tpm'];
  s = checkPlan(plan(f), f);
  assert.equal(s.get('recovery-key').state, 'todo');
  assert.match(flat(s.get('recovery-key').text), /-RecoveryPassword/);
});

test('мастер: без прав администратора - «видно после полной проверки», а не выдуманное «сделано»', () => {
  const f = strongFacts();
  f.isAdmin = false;
  f.physical.admin = false;
  f.physical.bitlocker = { protectors: [], preboot: null, policy: {} };
  const p = plan(f);
  const s = checkPlan(p, f);
  assert.equal(s.get('recovery-key').state, 'unknown');
  assert.match(flat(s.get('recovery-key').text), /Видно после полной проверки/);
  assert.equal(s.get('add-pin').state, 'unknown');
  assert.equal(p.needsFullCheck, true);
  // Способы открыть диск перенесены из полной проверки (encryption.volumes) - тогда видно.
  f.encryption.volumes = [{ drive: 'C:', protection: 'On', status: 'FullyEncrypted', percent: 100, protectors: ['TpmPin', 'RecoveryPassword'] }];
  const q = checkPlan(plan(f), f);
  assert.equal(q.get('recovery-key').state, 'done');
  assert.equal(q.get('pin-on').state, 'done');
});

test('мастер: всё сделано - заголовок не обещает лишнего', () => {
  const f = strongFacts();
  let p = plan(f);
  let s = checkPlan(p, f);
  assert.equal(s.get('pin-on').state, 'done');
  assert.equal(s.get('pin-policy').state, 'done');
  assert.equal(s.get('firmware').state, 'unknown', 'порядок загрузки не виден - не «сделано»');
  assert.match(flat(p.headline), /Осталось проверить BIOS/);
  f.boot.bcdFirmware = 'Диспетчер загрузки встроенного ПО\n---\nидентификатор {fwbootmgr}\ndisplayorder {bootmgr}\n\nДиспетчер загрузки Windows\n---\nидентификатор {bootmgr}\ndescription Windows Boot Manager\n';
  p = plan(f);
  s = checkPlan(p, f);
  assert.equal(s.get('firmware').state, 'done');
  assert.match(flat(s.get('firmware').text), /из Windows не проверить/, 'честно: запрет USB из Windows не виден');
  assert.match(flat(p.headline), /Главное сделано/);
});

test('мастер: Windows Домашняя - шифрование устройства и честный отказ в ПИН-коде', () => {
  const f = weakFacts();
  f.login.edition.id = 'CoreSingleLanguage';
  f.boot.tpmDevices = [{ name: 'Trusted Platform Module 2.0', status: 'OK' }];
  const p = plan(f);
  assert.equal(p.available, false);
  assert.equal(p.edition, 'home');
  const s = checkPlan(p, f);
  assert.deepEqual([...s.keys()], ['device-encryption', 'pin-home', 'firmware']);
  assert.equal(s.get('device-encryption').state, 'todo');
  assert.deepEqual(s.get('device-encryption').open.map((o) => o.id), ['deviceencryption']);
  assert.equal(s.get('pin-home').state, 'blocked');
  assert.match(flat(s.get('pin-home').text), /Windows Pro/);
  assert.doesNotMatch(flat(s.get('pin-home').text), /https?:|www\./, 'без ссылок на скачивание');
  assert.ok(!p.steps.some((x) => x.fix), 'на Домашней кнопки политики нет');
  // Выпуск по названию, если EditionID нет.
  const g = { meta: { osCaption: 'Майкрософт Windows 11 Домашняя' } };
  assert.equal(plan(g).edition, 'home');
  // Зашифровано - сделано.
  f.encryption.drives[0].shellState = 1;
  assert.equal(checkPlan(plan(f), f).get('device-encryption').state, 'done');
});

test('мастер: пустые и странные сведения не ломают', () => {
  for (const f of [{}, undefined, { login: {} }, { encryption: {}, boot: {}, physical: {} }, good(), bad()]) {
    const p = plan(f);
    checkPlan(p, f || {});
  }
  const p = plan({});
  assert.equal(p.available, null);
  assert.ok(p.steps.every((s) => s.state !== 'done'), 'без сведений ничего не «сделано»');
});

test('мастер: старый отчёт без политики - шаг с ПИН-кодом не заблокирован, но с подсказкой', () => {
  const f = weakFacts();
  delete f.login;
  f.physical.bitlocker = { protectors: [], preboot: 'none', protection: 'Off' };
  f.boot.tpmDevices = [{ name: 'Trusted Platform Module 2.0', status: 'OK' }];
  const s = checkPlan(plan(f), f);
  assert.equal(s.get('pin-policy').state, 'unknown');
  assert.equal(s.get('turn-on').state, 'todo');
  assert.match(flat(s.get('turn-on').text), /Если Windows не предложит ПИН-код/);
});
