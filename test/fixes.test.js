'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const fixes = require('../server/fixes');
const { evaluate } = require('../server/rules');
const { guide, GUIDES, OPEN_TARGETS } = require('../server/guides');
const { bad, NOW } = require('./fixtures/facts');

const FIX_PS = fs.readFileSync(path.join(__dirname, '..', 'server', 'ps', 'fix.ps1'), 'utf8');

test('каждое исправление из находок есть в каталоге и в fix.ps1', () => {
  const ids = new Set();
  for (const f of evaluate(bad(), { now: NOW })) {
    if (f.fix) ids.add(f.fix.id);
    for (const a of f.alt || []) ids.add(a.id);
  }
  for (const id of Object.keys(fixes.FIXES)) ids.add(id);
  for (const id of ids) {
    assert.ok(fixes.FIXES[id], `нет описания ${id}`);
    assert.ok(FIX_PS.includes(`'${id}' = `), `fix.ps1 не знает ${id}`);
  }
});

test('у каждой инструкции из находок есть текст и кнопки только из списка', () => {
  for (const f of evaluate(bad(), { now: NOW })) {
    if (!f.guide) continue;
    const g = guide(f.guide, bad());
    assert.ok(g, `нет инструкции ${f.guide}`);
    assert.ok(g.steps.length >= 2);
    for (const o of g.open) assert.ok(OPEN_TARGETS[o.id]);
  }
  for (const id of Object.keys(GUIDES)) assert.ok(guide(id, {}));
});

test('план показывает, что изменится', () => {
  const f = bad();
  const p = fixes.plan('firewall-on', f);
  assert.equal(p.changes.length, 3);
  assert.deepEqual(p.changes[0], { what: { k: "Брандмауэр: профиль {0}", a: ["доменная сеть"] }, from: 'выключен', to: 'включён' });
  assert.ok(p.commands.length);
  const u = fixes.plan('uac-on', f);
  assert.equal(u.changes.length, 3);
});

test('аргументы автозагрузки берутся из сведений, а не из запроса', () => {
  const f = bad();
  const a = fixes.validate('autostart-off', f, { loc: 'HKCU-Run', name: 'Updater', userSid: 'S-1-5-21-9-9-9-9', extra: 'x' });
  assert.deepEqual(a, { loc: 'HKCU-Run', name: 'Updater', userSid: f.autostart.userSid });
  assert.throws(() => fixes.validate('autostart-off', f, { loc: 'HKCU-Run', name: 'НетТакой' }));
  assert.throws(() => fixes.validate('autostart-off', f, { loc: 'HKLM-RunOnce', name: 'Updater' }));
  assert.throws(() => fixes.validate('autostart-off', f, null));
  assert.throws(() => fixes.validate('rm-rf', f));
});

test('аргументы для fix.ps1: только проверенные значения', () => {
  assert.deepEqual(fixes.scriptArgs('apply', { id: 'firewall-on' }), ['-Action', 'apply', '-Id', 'firewall-on']);
  const a = fixes.scriptArgs('apply', { id: 'autostart-off', arg: { loc: 'HKCU-Run', name: 'Имя "с" кавычками; & | $x', userSid: 'S-1-5-21-1-2-3-4' } });
  assert.equal(a[4], '-Arg');
  assert.match(a[5], /^[A-Za-z0-9+/=]+$/, 'значение передаётся в Base64 - без кавычек и спецсимволов');
  assert.equal(JSON.parse(Buffer.from(a[5], 'base64').toString('utf8')).name, 'Имя "с" кавычками; & | $x');
  assert.throws(() => fixes.scriptArgs('apply', { id: 'evil; Remove-Item' }));
  assert.throws(() => fixes.scriptArgs('undo', { record: '../../x' }));
  assert.deepEqual(fixes.scriptArgs('undo', { record: '0f8fad5b-d9cb-469f-a165-70867728950e' }), ['-Action', 'undo', '-Record', '0f8fad5b-d9cb-469f-a165-70867728950e']);
});

test('fix.ps1 сам проверяет параметры и хранит откат в защищённой папке', () => {
  assert.match(FIX_PS, /ValidatePattern\('\^\[a-z0-9-\]\{1,40\}\$'\)\]\[string\]\$Id/);
  assert.match(FIX_PS, /ValidatePattern\('\^\[A-Za-z0-9\+\/=\]\{0,8000\}\$'\)\]\[string\]\$Arg/);
  assert.match(FIX_PS, /\$env:ProgramData 'Adamant'/);
  assert.match(FIX_PS, /inheritance:r/);
  assert.match(FIX_PS, /создана не администратором/);
  // Никаких Invoke-Expression и запуска строк из аргументов.
  assert.doesNotMatch(FIX_PS, /Invoke-Expression|\biex\b|ScriptBlock\]::Create\(\$Arg|Start-Process/i);
});

// ---------------------------------------------------------------- Защита от взлома и физический доступ

const DEEP_FIXES = ['llmnr-off', 'wdigest-off', 'lsa-ppl-on', 'autorun-off', 'remote-assistance-off', 'ps2-off', 'pua-on', 'cloud-on', 'cfa-on', 'asr-safe', 'driver-blocklist-on', 'ifeo-clean', 'lock-timeout'];

test('глубокие исправления: план показывает, что было и что станет', () => {
  const { weak } = require('./fixtures/deep');
  const f = weak();
  for (const id of DEEP_FIXES) {
    const arg = id === 'ifeo-clean' ? { exes: ['sethc.exe'] } : undefined;
    const p = fixes.plan(id, f, arg);
    assert.ok(p.changes.length >= 1, id);
    for (const c of p.changes) assert.ok(c.what && c.from != null && c.to != null, id);
    assert.ok(p.commands.length && p.notes.length, id);
    assert.ok(FIX_PS.includes(`'${id}' = `), `fix.ps1 не знает ${id}`);
    assert.deepEqual(fixes.scriptArgs('apply', { id, arg: p.arg }).slice(0, 4), ['-Action', 'apply', '-Id', id]);
  }
  assert.deepEqual(fixes.plan('cloud-on', f).changes[0], { what: 'Облачная защита (MAPS)', from: 'выключена', to: 'расширенная' });
  assert.deepEqual(fixes.plan('lock-timeout', f).changes[0].to, { k: 'через {0} с', a: [600] });
  // ASR: правило, которое уже блокирует, не меняется; правило в режиме журнала - меняется.
  const asr = fixes.plan('asr-safe', f).changes;
  assert.equal(asr.length, 5);
  assert.equal(asr[0].from, 'только запись в журнал');
  // Исправления с перезагрузкой честно об этом говорят.
  for (const id of ['lsa-ppl-on', 'driver-blocklist-on']) {
    assert.equal(fixes.FIXES[id].reboot, true, id);
    assert.ok(fixes.plan(id, f).notes.includes('Начнёт действовать после перезагрузки.'), id);
  }
  // Рискованные исправления предупреждают о риске и об откате.
  for (const id of ['cfa-on', 'asr-safe', 'driver-blocklist-on', 'lsa-ppl-on']) {
    assert.ok(fixes.FIXES[id].notes.some((n) => /откат|вернуть|Исправления/i.test(n)), id);
  }
});

test('защита LSA кнопкой - только на Windows 11 22H2 и новее', () => {
  const { weak } = require('./fixtures/deep');
  const f = weak();
  assert.equal(fixes.validate('lsa-ppl-on', f), null);
  f.hardening.build = 19045;
  f.meta.osBuild = '19045';
  assert.throws(() => fixes.validate('lsa-ppl-on', f), /22H2/);
  assert.match(FIX_PS, /Build -lt 22621/);
  assert.match(FIX_PS, /name = 'RunAsPPL'; value = 2/);
});

test('ifeo-clean: убирает перехват только у специальных возможностей, найденных проверкой', () => {
  const { weak } = require('./fixtures/deep');
  const f = weak();
  // Имя приводится к списку, повторы убираются, лишние поля отбрасываются.
  assert.deepEqual(fixes.validate('ifeo-clean', f, { exes: ['SETHC.EXE', 'sethc.exe'], cmd: 'x' }), { exes: ['sethc.exe'] });
  // Повторная проверка уже проверенного аргумента (так делает app.js) даёт то же.
  assert.deepEqual(fixes.validate('ifeo-clean', f, fixes.validate('ifeo-clean', f, { exes: ['sethc.exe'] })), { exes: ['sethc.exe'] });
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['utilman.exe'] }), /уже нет/, 'пустой Debugger - перехвата нет');
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['osk.exe'] }), /уже нет/);
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['cmd.exe'] }), /не из списка/);
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['..\\..\\Run'] }), /не из списка/);
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: [] }));
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: [{ toLowerCase: 1 }] }));
  assert.throws(() => fixes.validate('ifeo-clean', f, null));
  f.physical.accessibility.push({ exe: 'cmd.exe', path: 'C:\\Windows\\System32\\cmd.exe', exists: true, originalName: 'cmd.exe', debugger: 'x' });
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['cmd.exe'] }), /не из списка/, 'чужая программа не проходит, даже если она есть в сведениях');
  delete f.physical;
  assert.throws(() => fixes.validate('ifeo-clean', f, { exes: ['sethc.exe'] }), /уже нет/);
  // План показывает, какой перехват убирается.
  const p = fixes.plan('ifeo-clean', require('./fixtures/deep').weak(), { exes: ['sethc.exe'] });
  assert.deepEqual(p.changes, [{ what: { k: 'Перехват запуска {0}', a: ['sethc.exe'] }, from: 'C:\\Windows\\System32\\cmd.exe', to: 'удалён' }]);
  // Аргумент уходит в fix.ps1 только в Base64 JSON.
  const a = fixes.scriptArgs('apply', { id: 'ifeo-clean', arg: p.arg });
  assert.equal(a[4], '-Arg');
  assert.match(a[5], /^[A-Za-z0-9+/=]+$/);
  assert.deepEqual(JSON.parse(Buffer.from(a[5], 'base64').toString('utf8')), { exes: ['sethc.exe'] });
  // fix.ps1 сверяет имя со своим списком и не подставляет путь из аргумента.
  assert.match(FIX_PS, /\$IfeoExes \| Where-Object \{ \$_ -ieq \[string\]\$x \}/);
  assert.match(FIX_PS, /path = "\$IFEO\\\$exe"/);
});

// ---------------------------------------------------------------- Вход в Windows и ПИН-код BitLocker

const LOGIN_FIXES = ['lockout-policy', 'require-cad', 'bitlocker-pin-policy'];

test('исправления входа: план показывает, что было и что станет', () => {
  const { weakFacts } = require('./fixtures/login');
  const { render } = require('../server/i18n');
  const f = weakFacts();
  for (const id of LOGIN_FIXES) {
    assert.equal(fixes.validate(id, f), null, id);
    const p = fixes.plan(id, f);
    assert.ok(p.changes.length >= 1, id);
    for (const c of p.changes) assert.ok(c.what && c.from != null && c.to != null, id);
    assert.ok(p.commands.length && p.notes.length, id);
    assert.ok(p.notes.some((n) => /откат|Исправления|вернуть/i.test(render('ru', n))), `${id}: как вернуть`);
    assert.ok(FIX_PS.includes(`'${id}' = `), `fix.ps1 не знает ${id}`);
    assert.deepEqual(fixes.scriptArgs('apply', { id, arg: p.arg }), ['-Action', 'apply', '-Id', id]);
  }
  const lo = fixes.plan('lockout-policy', f);
  assert.deepEqual(lo.changes.map((c) => [render('ru', c.from), render('ru', c.to)]), [['не задан (0)', '10'], ['30 мин', '10 мин'], ['30 мин', '10 мин']]);
  const notes = lo.notes.map((n) => render('ru', n)).join('\n');
  assert.match(notes, /всех локальных учётных записей/);
  assert.match(notes, /net accounts \/lockoutthreshold:0/, 'как вернуть вручную - прежнее значение');
  f.login.lockout = { threshold: 50, windowSec: 1800, durationSec: 4294967295 };
  assert.match(fixes.plan('lockout-policy', f).notes.map((n) => render('ru', n)).join('\n'), /\/lockoutthreshold:50 \/lockoutwindow:30 \/lockoutduration:0/);
  assert.equal(render('ru', fixes.plan('lockout-policy', f).changes[2].from), 'до разблокировки администратором');
  assert.deepEqual(fixes.plan('require-cad', f).changes, [{ what: 'Ctrl+Alt+Del перед входом (DisableCAD)', from: 'не требуется', to: 'требуется' }]);
  // Политика не задана: включается проверка при запуске, ПИН-код и остальные способы «разрешать».
  const bl = fixes.plan('bitlocker-pin-policy', weakFacts()).changes;
  assert.equal(bl.length, 5);
  assert.deepEqual(bl.map((c) => [c.from, c.to]), [['не задана', 'включена'], ['не задано', 'разрешать'], ['не задано', 'разрешать'], ['не задано', 'разрешать'], ['не задано', 'разрешать']]);
  // Старый отчёт без раздела login - план всё равно строится.
  for (const id of LOGIN_FIXES) assert.ok(fixes.plan(id, bad()).changes.length >= 1, id);
});

test('исправления входа: отказ, если менять нечего или нельзя', () => {
  const { weakFacts, strongFacts } = require('./fixtures/login');
  let f = weakFacts();
  f.login.lockout.threshold = 5;
  assert.throws(() => fixes.validate('lockout-policy', f), /уже включена/);
  f.login.lockout.threshold = 10;
  assert.throws(() => fixes.validate('lockout-policy', f), /уже включена/);
  f.login.lockout.threshold = 11;
  assert.equal(fixes.validate('lockout-policy', f), null);
  f.login.partOfDomain = true;
  assert.throws(() => fixes.validate('lockout-policy', f), /домен/);
  assert.throws(() => fixes.validate('require-cad', strongFacts()), /уже требуется/);
  assert.throws(() => fixes.validate('bitlocker-pin-policy', strongFacts()), /уже разрешён/);
  f = weakFacts();
  f.login.edition.id = 'Core';
  assert.throws(() => fixes.validate('bitlocker-pin-policy', f), /Домашняя/);
  f = weakFacts();
  delete f.login.edition;
  f.meta.edition = 'CoreSingleLanguage';
  assert.throws(() => fixes.validate('bitlocker-pin-policy', f), /Домашняя/);
  // ПИН-код уже «требуется» (1): трогаем только UseAdvancedStartup, остальное как было.
  f = weakFacts();
  f.login.bitlocker.policy = { useAdvancedStartup: null, useTpmPin: 1, useTpm: 0, useTpmKey: 0, useTpmKeyPin: 0 };
  assert.deepEqual(fixes.plan('bitlocker-pin-policy', f).changes.map((c) => c.what), ['Политика BitLocker: дополнительная проверка при запуске']);
  f.login.bitlocker.policy.useAdvancedStartup = 1;
  assert.throws(() => fixes.validate('bitlocker-pin-policy', f), /уже разрешён/);
  // «Не разрешать» (0) остаётся, «требовать» (1) у другого способа → «разрешать», иначе ПИН-код с ним в конфликте.
  f.login.bitlocker.policy = { useAdvancedStartup: 1, useTpmPin: 0, useTpm: 0, useTpmKey: 1, useTpmKeyPin: 2 };
  const ch = fixes.plan('bitlocker-pin-policy', f).changes;
  assert.deepEqual(ch.map((c) => [c.what, c.from, c.to]), [
    ['Политика BitLocker: ПИН-код вместе с TPM', 'не разрешать', 'разрешать'],
    ['Политика BitLocker: TPM и флешка-ключ', 'требовать', 'разрешать'],
  ]);
  // То же правило - в fix.ps1.
  assert.equal(fixes.LOGIN.pinAllowed({ useAdvancedStartup: 1, useTpmPin: 2, useTpm: 1 }), false, '«требовать только TPM» мешает ПИН-коду');
  assert.equal(fixes.LOGIN.pinAllowed({ useAdvancedStartup: 1, useTpmPin: 1, useTpm: 0 }), true);
  assert.equal(fixes.LOGIN.pinAllowed(null), null);
});

test('fix.ps1: исправления входа сохраняют прежние значения, проверяют результат и сами отказываются', () => {
  // Блокировка: читается и пишется одним вызовом, откат пишет сохранённые значения, результат проверяется.
  assert.match(FIX_PS, /NetUserModalsGet\(null, 3/);
  assert.match(FIX_PS, /NetUserModalsSet\(null, 3/);
  assert.match(FIX_PS, /'lockout-policy' = @\{[\s\S]*?threshold -ge 1 -and \$v\.threshold -le 10[\s\S]*?undo = \{ param\(\$b\)\s+Lockout-Write \$b/);
  assert.match(FIX_PS, /Windows не приняла новые значения блокировки входа/);
  assert.match(FIX_PS, /if \(Part-Of-Domain\) \{ throw 'Компьютер в домене/);
  // Ctrl+Alt+Del: только политика DisableCAD = 0, через общий захват/откат реестра.
  assert.match(FIX_PS, /'require-cad' = @\{[\s\S]*?name = 'DisableCAD'; value = 0; kind = 'DWord'[\s\S]*?undo = \{ param\(\$b\) Deep-Undo \$b \}/);
  assert.match(FIX_PS, /if \(\$eff -eq 0\) \{ throw 'Ctrl\+Alt\+Del перед входом уже требуется/);
  // BitLocker: отказ на Домашней, «разрешать» = 2, отсутствующие значения при откате удаляются (Get-RegState → existed = $false).
  assert.match(FIX_PS, /'bitlocker-pin-policy' = @\{[\s\S]*?-match '\^Core'\) \{ throw 'В Windows Домашняя/);
  assert.match(FIX_PS, /name = 'UseTPMPIN'; value = 2/);
  assert.match(FIX_PS, /name = 'UseAdvancedStartup'; value = 1/);
  assert.match(FIX_PS, /throw 'ПИН-код BitLocker уже разрешён политикой/);
  // Программа не шифрует диск и не ставит ПИН-код сама.
  assert.doesNotMatch(FIX_PS, /Enable-BitLocker|Add-BitLockerKeyProtector|manage-bde(\.exe)?\s+-(on|protectors)/i);
});
