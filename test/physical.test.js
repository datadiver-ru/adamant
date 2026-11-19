'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const physical = require('../server/rules-physical');
const { evaluate, SEVERITIES } = require('../server/rules');
const { guide, OPEN_TARGETS } = require('../server/guides');
const { good, bad } = require('./fixtures/facts');
const { protectedFacts, exposedFacts, NOW } = require('./fixtures/physical');

const byId = (list) => new Map(list.map((f) => [f.id, f]));
const phys = (facts) => byId(physical.evaluate(facts, { now: NOW }));
const { render } = require('../server/i18n');
const flat = (m) => render('ru', m);

test('физический доступ: защищённый компьютер - ни одной критичной или важной находки', () => {
  const list = physical.evaluate(protectedFacts(), { now: NOW });
  assert.deepEqual(list.filter((f) => f.sev === 'critical' || f.sev === 'high'), []);
  const ids = byId(list);
  for (const id of ['phys-accessibility-ok', 'phys-usb-boot-ok', 'phys-bitlocker-pin-ok', 'phys-autolock-ok', 'phys-presence', 'phys-usb-history', 'phys-dma-ok']) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, 'ok', id);
  }
  assert.match(flat(ids.get('phys-presence').title), /ничего подозрительного/);
  assert.match(flat(ids.get('phys-autolock-ok').title), /10 мин/);
});

test('физический доступ: открытый компьютер - правильные находки и важность', () => {
  const ids = phys(exposedFacts());
  const expect = {
    'phys-accessibility-backdoor': 'critical', 'phys-open-to-usb-boot': 'high', 'phys-no-autolock': 'advice',
    'phys-no-signin-after-sleep': 'high', 'phys-failed-local': 'high', 'phys-usb-history': 'advice', 'phys-dma': 'advice', 'phys-presence': 'ok',
  };
  for (const [id, sev] of Object.entries(expect)) {
    assert.ok(ids.has(id), `нет находки ${id}`);
    assert.equal(ids.get(id).sev, sev, id);
  }
  assert.ok(!ids.has('phys-bitlocker-pin'), 'диск не зашифрован - совет про ПИН-код не нужен');
  assert.doesNotMatch(flat(ids.get('phys-presence').title), /ничего подозрительного/);
});

test('подмена специальных возможностей: отладчик убирается кнопкой, подменённый файл - по инструкции', () => {
  const b = phys(exposedFacts()).get('phys-accessibility-backdoor');
  assert.deepEqual(b.fix, { id: 'ifeo-clean', arg: { exes: ['sethc.exe'] } });
  assert.equal(b.guide, 'accessibility-restore');
  const ev = b.evidence.map(flat).join('\n');
  assert.match(ev, /sethc\.exe.*cmd\.exe/);
  assert.match(ev, /utilman\.exe.*Cmd\.Exe/);

  // Только подменённый файл, без отладчика: критично, но кнопки нет.
  const f = protectedFacts();
  f.physical.accessibility[0].originalName = 'powershell.exe';
  const x = phys(f).get('phys-accessibility-backdoor');
  assert.equal(x.sev, 'critical');
  assert.equal(x.fix, undefined);

  // Незнакомое имя, не командная строка, - важно, но не тревога.
  const g = protectedFacts();
  g.physical.accessibility[2].originalName = 'SomethingElse.exe';
  assert.equal(phys(g).get('phys-accessibility-backdoor').sev, 'high');

  // Настоящие имена Windows (с суффиксом .mui, как отдаёт VersionInfo) - в порядке.
  const h = protectedFacts();
  h.physical.accessibility[1].originalName = 'utilman2.exe.mui';
  h.physical.accessibility[3].originalName = 'ScreenMagnifier.exe.mui';
  assert.ok(phys(h).has('phys-accessibility-ok'));

  // Средство специальных возможностей запускает командную строку.
  const k = protectedFacts();
  k.physical.ats.push({ name: 'evil', startExe: '"C:\\Windows\\System32\\cmd.exe" /k', atExe: '' });
  assert.equal(phys(k).get('phys-accessibility-backdoor').sev, 'critical');
});

test('флешка и незашифрованный диск: с паролем BIOS и Secure Boot - только совет', () => {
  const f = exposedFacts();
  f.firmware.adminPasswordStatus = 1;
  f.boot.secureBoot = 1;
  const c = phys(f).get('phys-open-to-usb-boot');
  assert.equal(c.sev, 'advice');
  assert.equal(c.guide, 'physical');
  // Защита BitLocker приостановлена - для вора это то же, что без шифрования.
  const g = exposedFacts();
  g.encryption.drives[0].shellState = 5;
  assert.equal(phys(g).get('phys-open-to-usb-boot').sev, 'high');
  // Состояние шифрования не видно - о составной находке молчим (скажет находка BitLocker).
  const h = exposedFacts();
  h.encryption.drives[0].shellState = null;
  assert.ok(!phys(h).has('phys-open-to-usb-boot'));
  assert.ok(!phys(h).has('phys-usb-boot-ok'));
});

test('ПИН-код BitLocker: только TPM - совет; без прав администратора - «не видно»', () => {
  const f = protectedFacts();
  f.physical.bitlocker = { protectors: ['Tpm', 'RecoveryPassword'], preboot: 'tpm-only', policy: {} };
  const pin = phys(f).get('phys-bitlocker-pin');
  assert.equal(pin.sev, 'advice');
  assert.equal(pin.guide, 'bitlocker-pin');
  const g = protectedFacts();
  g.physical.admin = false;
  g.physical.bitlocker = { protectors: [], preboot: null, policy: {} };
  const u = phys(g).get('phys-bitlocker-pin-unknown');
  assert.equal(u.sev, 'unknown');
  assert.match(flat(u.text), /Проверить полностью/);
});

test('неверный пароль за компьютером: 1-2 раза - совет, от 3 - важно; без прав - «не видно»', () => {
  const f = exposedFacts();
  f.physical.presence.events = f.physical.presence.events.filter((e) => e.kind !== 'failed-local').concat([{ at: new Date(NOW - 3600_000).toISOString(), kind: 'failed-local', user: 'TEST-PC\\user' }]);
  assert.equal(phys(f).get('phys-failed-local').sev, 'advice');
  const ids = phys(exposedFacts());
  assert.equal(ids.get('phys-failed-local').evidence.length, 3, 'попытка старше 14 дней не считается');
  const g = protectedFacts();
  g.physical.admin = false;
  g.physical.presence.security = false;
  const u = phys(g);
  assert.equal(u.get('phys-failed-local-unknown').sev, 'unknown');
  assert.match(flat(u.get('phys-failed-local-unknown').text), /Проверить полностью/);
  assert.equal(u.get('phys-presence').sev, 'ok');
});

test('неожиданные выключения - только для сведения, без тревоги', () => {
  const ids = phys(protectedFacts());
  assert.equal(ids.get('phys-presence').sev, 'ok');
  assert.match(ids.get('phys-presence').evidence.map(flat).join('\n'), /Неожиданных выключений: 1/);
});

test('автоблокировка: сон с паролем считается, вход после сна без пароля - важно', () => {
  const f = protectedFacts();
  f.physical.lock.inactivityTimeout = null;
  f.physical.lock.sleepAc = 900; f.physical.lock.sleepDc = 300;
  assert.ok(phys(f).has('phys-autolock-ok'));
  const g = protectedFacts();
  g.physical.lock.inactivityTimeout = null;
  g.physical.lock.sleepAc = 0;
  const n = phys(g).get('phys-no-autolock');
  assert.equal(n.sev, 'advice');
  assert.deepEqual(n.fix, { id: 'lock-timeout' });
  const h = protectedFacts();
  h.physical.lock.delayLock = 4294967295;
  assert.equal(phys(h).get('phys-no-signin-after-sleep').sev, 'high');
  // powercfg ничего не сказал - не считаем это отсутствием пароля.
  const k = protectedFacts();
  k.physical.lock.consoleLockAc = null; k.physical.lock.consoleLockDc = null;
  assert.ok(!phys(k).has('phys-no-signin-after-sleep'));
  // У настольного компьютера настройка «от батареи» не важна.
  const d = protectedFacts();
  d.physical.lock.battery = false; d.physical.lock.consoleLockDc = 0;
  assert.ok(!phys(d).has('phys-no-signin-after-sleep'));
});

test('флешки: список не длиннее 8 строк и не тревожит сам по себе', () => {
  const f = protectedFacts();
  f.physical.usb = Array.from({ length: 12 }, (_, i) => ({ name: `Disk ${i}`, serial: String(i), first: null, last: null, present: i === 0 }));
  const u = phys(f).get('phys-usb-history');
  assert.equal(u.sev, 'ok');
  assert.equal(u.evidence.length, 9);
  assert.match(flat(u.evidence[0]), /подключён сейчас/);
  f.physical.usb = [];
  assert.equal(phys(f).get('phys-usb-history').sev, 'ok');
});

test('Thunderbolt без защиты DMA - совет; без Thunderbolt - ничего', () => {
  assert.equal(phys(exposedFacts()).get('phys-dma').guide, 'dma-protection');
  const f = exposedFacts();
  f.physical.dma.thunderbolt = false;
  assert.ok(!phys(f).has('phys-dma') && !phys(f).has('phys-dma-ok'));
});

test('старые отчёты без раздела physical: ничего или одна находка «не видно»', () => {
  assert.deepEqual(physical.evaluate(good(), { now: NOW }), []);
  assert.deepEqual(physical.evaluate({}, { now: NOW }), []);
  assert.deepEqual(physical.evaluate(undefined, { now: NOW }), []);
  const f = good();
  f.errors = { physical: 'Access denied' };
  const list = physical.evaluate(f, { now: NOW });
  assert.equal(list.length, 1);
  assert.equal(list[0].sev, 'unknown');
  // Пустой раздел и одиночные объекты вместо массивов - без падения.
  assert.doesNotThrow(() => physical.evaluate({ physical: {} }, { now: NOW }));
  const g = protectedFacts();
  g.physical.accessibility = g.physical.accessibility[0];
  g.physical.usb = g.physical.usb[0];
  g.physical.presence.events = g.physical.presence.events[0];
  assert.doesNotThrow(() => physical.evaluate(g, { now: NOW }));
});

test('находки физического доступа: правильный вид, категория и инструкции', () => {
  for (const facts of [protectedFacts(), exposedFacts()]) {
    const all = evaluate(facts, { now: NOW });
    const list = all.filter((f) => f.cat === 'physical');
    assert.ok(list.length >= 5);
    for (const f of list) {
      assert.match(f.id, /^phys-/);
      assert.ok(SEVERITIES.includes(f.sev), f.id);
      assert.ok(f.title && f.text && Array.isArray(f.evidence), f.id);
      if (f.guide) {
        const g = guide(f.guide, facts);
        assert.ok(g, `нет инструкции ${f.guide}`);
        assert.ok(g.steps.length >= 2, f.guide);
        for (const o of g.open) assert.ok(OPEN_TARGETS[o.id], o.id);
      }
    }
    assert.equal(new Set(list.map((f) => f.id)).size, list.length, 'id находок не повторяются');
  }
});

test('инструкции физического доступа есть и работают без сведений', () => {
  for (const id of ['physical', 'bitlocker-pin', 'usb-boot-off', 'accessibility-restore', 'wake-signin', 'dma-protection']) {
    const g = guide(id, {});
    assert.ok(g, id);
    assert.ok(g.steps.length >= 3, id);
    for (const o of g.open) assert.ok(OPEN_TARGETS[o.id], o.id);
  }
  const g = guide('usb-boot-off', bad());
  assert.ok(g.steps.some((s) => /особые варианты загрузки/.test(flat(s))), 'вход в UEFI - общими шагами enterFirmware');
  assert.ok(guide('bitlocker-pin', good()).steps.some((s) => /manage-bde -protectors -add C: -TPMAndPIN/.test(flat(s))));
});

test('physical.ps1: раздел physical, только чтение, админские части под $isAdmin', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'sections', 'physical.ps1'), 'utf8');
  assert.match(src, /^\uFEFF/);
  assert.match(src, /Section 'physical' \{/);
  assert.match(src, /admin = \$isAdmin/);
  for (const re of [/Get-BitLockerVolume/, /reagentc\.exe/, /LogName Security/]) {
    const i = src.search(re);
    assert.ok(i > 0, String(re));
    assert.ok(src.lastIndexOf('if ($isAdmin)', i) > 0, `${re} - только с правами администратора`);
  }
  assert.match(src, /-MaxEvents/);
});
