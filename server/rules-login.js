'use strict';
/**
 * Вход в Windows: блокировка после неверных паролей, Ctrl+Alt+Del, ПИН-код Windows Hello, динамическая блокировка.
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Нет раздела login (старый отчёт) - ничего;
 * раздел не собрался из-за ошибки - одна находка «Не видно».
 *
 * facts.login (server/ps/sections/login.ps1):
 *   admin, partOfDomain (bool | null)
 *   lockout { threshold, windowSec, durationSec } | null - durationSec 4294967295 = «до разблокировки администратором»
 *   cad { policy, winlogon, source: 'policy'|'winlogon'|'default'|null, required: bool | null }
 *   hello { pin: bool | null, pinSource, biometricDevices: [имя] | null, biometrics: null }
 *   edition { id, composition }
 *   bitlocker { controlKey, autoDE, preventDeviceEncryption, tools { wizard, manageBde },
 *               policy { useAdvancedStartup, enableBdeWithNoTpm, useTpm, useTpmPin, useTpmKey, useTpmKeyPin, minimumPin, useEnhancedPin } }
 *   errors { … }
 * Динамическая блокировка берётся из facts.physical.lock.dynamicLock.
 */
const { tx, t } = require('./i18n');

const FOREVER = 4294967295;
const LOCKOUT = { threshold: 10, windowSec: 600, durationSec: 600 };

const num = (v) => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
const mins = (sec) => Math.max(1, Math.round(sec / 60));
/** Длительность блокировки для людей. */
const lockFor = (sec) => (num(sec) === FOREVER ? t('до разблокировки администратором') : num(sec) ? tx('{0} мин', mins(num(sec))) : t('не задано'));

function ok(id, cat, title, text, evidence = []) {
  return { id, cat, sev: 'ok', title, text, evidence };
}

function lockoutRules(l, out) {
  const lo = l.lockout;
  if (!lo) {
    if (l.errors && l.errors.lockout) out.push({ id: 'login-lockout-unknown', cat: 'hardening', sev: 'unknown', title: t('Блокировка входа после неверных паролей'), text: tx('Не удалось проверить: {0}', l.errors.lockout), evidence: [] });
    return;
  }
  const thr = num(lo.threshold);
  if (thr == null) return;
  const evidence = [
    thr ? tx('Вход закрывается после {0} неверных паролей подряд', thr) : t('Порог блокировки: не задан (0) - попыток сколько угодно'),
    ...(thr ? [tx('Неверные пароли считаются за {0} мин', mins(num(lo.windowSec) || 0)), tx('Вход закрыт на: {0}', lockFor(lo.durationSec))] : []),
  ];
  const domain = l.partOfDomain === true;
  if (domain) evidence.push(t('Компьютер в домене: правила входа обычно задаёт администратор домена'));
  if (thr >= 1 && thr <= LOCKOUT.threshold) {
    out.push(ok('login-lockout-ok', 'hardening', tx('Вход закрывается после {0} неверных паролей', thr), tx('Подбирать пароль за этим компьютером или по сети придётся очень долго: после ошибок вход закрывается ({0}).', lockFor(lo.durationSec)), evidence));
    return;
  }
  const off = thr === 0;
  out.push({
    id: off ? 'login-lockout-off' : 'login-lockout-high', cat: 'hardening', sev: off ? 'high' : 'advice',
    title: off ? t('Пароль Windows можно подбирать сколько угодно раз') : tx('Вход закрывается только после {0} неверных паролей', thr),
    text: off
      ? t('Windows не закрывает вход после неверных паролей. Тот, кто сидит за компьютером или подключается к нему по сети, может перебирать пароли без ограничений - короткий или простой пароль так рано или поздно подберут. Пусть после 10 неверных попыток подряд вход закрывается на 10 минут: вам это не помешает, а подбор станет очень долгим.')
      : t('Попыток слишком много: подбирать пароль можно долго. Обычно хватает 10 попыток подряд, после них вход закрывается на 10 минут.'),
    evidence,
    fix: domain ? undefined : { id: 'lockout-policy' },
    guide: 'lockout',
  });
}

function cadRules(l, out) {
  const c = l.cad;
  if (!c || c.required == null) return;
  if (c.required) {
    out.push(ok('login-cad-ok', 'hardening', t('Перед входом нужно нажать Ctrl+Alt+Del'), t('Это сочетание перехватывает только Windows, поэтому поддельный экран входа не выманит пароль.')));
    return;
  }
  const evidence = [];
  if (c.policy != null) evidence.push(tx('Политика DisableCAD: {0}', c.policy));
  if (c.winlogon != null) evidence.push(tx('Winlogon DisableCAD: {0}', c.winlogon));
  if (c.source === 'default') evidence.push(t('Ничего не задано - так Windows ведёт себя по умолчанию вне домена'));
  out.push({
    id: 'login-cad-off', cat: 'hardening', sev: 'advice',
    title: t('Перед входом не нужно нажимать Ctrl+Alt+Del'),
    text: t('Сочетание Ctrl+Alt+Del перехватывает только сама Windows. Если требовать его перед вводом пароля, программа, которая рисует поддельный экран входа, не сможет выманить пароль. Это небольшое, но бесплатное улучшение: перед входом нужно будет нажать три клавиши.'),
    evidence,
    fix: { id: 'require-cad' },
  });
}

function helloRules(f, l, out) {
  const h = l.hello;
  if (!h) return;
  const user = (f.meta && f.meta.user) || '';
  if (h.pin === true) {
    out.push(ok('login-hello-pin-ok', 'hardening', t('Для входа настроен ПИН-код Windows Hello'), t('ПИН-код работает только на этом компьютере: с ним нельзя войти с другого устройства или по сети.')));
  } else if (h.pin === false) {
    const bio = Array.isArray(h.biometricDevices) ? h.biometricDevices.filter(Boolean) : [];
    out.push({
      id: 'login-hello-pin-none', cat: 'hardening', sev: 'advice',
      title: t('ПИН-код Windows Hello не настроен'),
      text: t('Сейчас вы входите паролем учётной записи. ПИН-код Windows Hello привязан к этому компьютеру: даже если его подсмотрят, войти с ним с другого устройства или по сети не получится, а пароль не придётся вводить при каждом входе. Если в компьютере есть чип TPM, после нескольких неверных попыток Windows замедляет подбор ПИН-кода.'),
      evidence: [user ? tx('У учётной записи {0} ПИН-код не найден', user) : t('У этой учётной записи ПИН-код не найден'), ...bio.map((n) => tx('Есть сканер для Windows Hello: {0}', n))],
      guide: 'hello-pin',
    });
  }
}

function dynamicLockRules(f, out) {
  const lock = f.physical && typeof f.physical === 'object' ? f.physical.lock : null;
  if (!lock || typeof lock.dynamicLock !== 'boolean') return;
  if (lock.dynamicLock) {
    out.push(ok('phys-dynamic-lock-ok', 'physical', t('Динамическая блокировка по телефону включена'), t('Когда телефон, связанный с компьютером по Bluetooth, уходит из зоны связи, Windows сама блокирует экран.')));
    return;
  }
  out.push({
    id: 'phys-dynamic-lock-off', cat: 'physical', sev: 'advice',
    title: t('Динамическая блокировка по телефону выключена'),
    text: t('Windows умеет сама блокировать экран, когда вы уходите с телефоном: телефон связывают с компьютером по Bluetooth, и примерно через минуту после того, как он пропал из зоны связи, экран блокируется. Это подстраховка на случай, если вы забыли нажать Win+L. Нужен телефон с Bluetooth.'),
    evidence: [t('«Динамическая блокировка» в параметрах входа выключена')],
    guide: 'dynamic-lock',
  });
}

function evaluate(facts) {
  const f = facts || {};
  const l = f.login;
  if (!l || typeof l !== 'object') {
    const err = f.errors && f.errors.login;
    return err ? [{ id: 'login-unknown', cat: 'hardening', sev: 'unknown', title: t('Вход в Windows'), text: tx('Не удалось проверить: {0}', err), evidence: [] }] : [];
  }
  const out = [];
  lockoutRules(l, out);
  cadRules(l, out);
  helloRules(f, l, out);
  dynamicLockRules(f, out);
  return out;
}

module.exports = { evaluate, LOCKOUT, FOREVER };
