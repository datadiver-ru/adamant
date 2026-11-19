'use strict';
/**
 * Мастер «Закрыть вход в обход Windows»: по сведениям проверки - что уже сделано и что осталось.
 * plan(facts) → { available, edition, editionId, needsFullCheck, headline, steps[] }
 *   available - есть ли на этом выпуске BitLocker с ПИН-кодом при включении (true / false / null - не видно);
 *   edition - 'pro' | 'home' | 'unknown';
 *   step: { id, title, text, state: 'done'|'todo'|'blocked'|'unknown', fix?: { id }, guide?: id, open?: [{ id, label }] }.
 * Программа сама диск не шифрует и ПИН-код не ставит: шаг «ПИН-код» открывает мастер BitLocker самой Windows,
 * который заставляет сохранить ключ восстановления. Кнопкой меняется только политика (исправление bitlocker-pin-policy).
 * Сведения: encryption, boot, firmware (collect.ps1), physical (physical.ps1), login (login.ps1). Чего нет - 'unknown'.
 */
const { tx, t } = require('./i18n');
const { diskState, secondLayer } = require('./rules-physical');
const { LOGIN } = require('./fixes');
const { OPEN_TARGETS, firmwareKey } = require('./guides');

const NEED_ADMIN = t('Видно после полной проверки (кнопка «Проверить полностью»)');
/** Что сказать о сведениях, которые Windows показывает только администратору. */
const fullCheck = (f) => (f.isAdmin ? t('Даже полная проверка этого не показала.') : NEED_ADMIN);
const arr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
const ENCRYPTED = ['on', 'encrypting'];
const PIN_PROTECTORS = ['TpmPin', 'TpmPinStartupKey'];
/** Несколько сообщений подряд - тоже сообщение (каждая часть переводится отдельно); пустые части пропускаются. */
const join = (sep, ...parts) => parts.flat().filter((m) => m != null && m !== '').reduce((acc, m) => (acc == null ? m : tx('{0}' + sep + '{1}', acc, m)), null) || '';

/** Кнопки «Открыть …» - только те, что есть в OPEN_TARGETS (новые появятся, когда их добавят в guides.js). */
const open = (...ids) => ids.filter((id) => OPEN_TARGETS[id]).map((id) => ({ id, label: OPEN_TARGETS[id].label }));
const step = (s) => {
  const out = { id: s.id, title: s.title, text: s.text, state: s.state };
  if (s.fix) out.fix = s.fix;
  if (s.guide) out.guide = s.guide;
  if (s.open && s.open.length) out.open = s.open;
  return out;
};

/** Способы открыть системный диск (видно только с правами администратора) или null. */
function protectorsOf(f, drive) {
  const vol = arr(f.encryption && f.encryption.volumes).find((v) => v && String(v.drive).toUpperCase() === String(drive).toUpperCase());
  if (vol && Array.isArray(vol.protectors)) return vol.protectors.map(String);
  const p = f.physical;
  const b = p && p.bitlocker;
  if (p && p.admin && b && b.preboot != null && Array.isArray(b.protectors)) return b.protectors.map(String);
  return null;
}
/** 'pin' | 'tpm-only' | null - как диск открывается при включении. */
function prebootOf(f, protectors) {
  const b = f.physical && f.physical.bitlocker;
  if (b && (b.preboot === 'pin' || b.preboot === 'tpm-only')) return b.preboot;
  if (!protectors) return null;
  if (protectors.some((x) => PIN_PROTECTORS.includes(x))) return 'pin';
  if (protectors.includes('Tpm')) return 'tpm-only';
  return null;
}
/** Модуль TPM: true / false / null (та же логика, что в rules.js bootRules). */
function tpmOf(f) {
  const b = f.boot;
  if (!b) return null;
  if (b.tpm && typeof b.tpm.present === 'boolean') return b.tpm.present && b.tpm.ready !== false;
  const list = arr(b.tpmDevices);
  if (list.some((d) => d && /tpm|доверенный платформенный|trusted platform/i.test(d.name))) return true;
  return Array.isArray(b.tpmDevices) ? false : null;
}

function recoveryStep(f, disk, protectors) {
  const base = { id: 'recovery-key', title: t('Ключ восстановления') };
  if (ENCRYPTED.includes(disk.state) || ['suspended', 'waiting'].includes(disk.state)) {
    if (!protectors) return step({ ...base, state: 'unknown', text: join(' ', t('Есть ли у диска ключ восстановления, Windows показывает только администратору.'), fullCheck(f)), open: open('bitlocker') });
    if (protectors.includes('RecoveryPassword')) {
      return step({ ...base, title: t('Ключ восстановления создан'), state: 'done', open: open('bitlocker'),
        text: tx('У диска {0} есть ключ восстановления. Программа не видит, где он хранится. Убедитесь, что он сохранён не только на этом компьютере: в учётной записи Microsoft, на флешке или на бумаге. Сохранить ещё раз: «Шифрование диска BitLocker» → «Создать резервную копию ключа восстановления».', disk.drive) });
    }
    return step({ ...base, title: t('У диска нет ключа восстановления'), state: 'todo', open: open('bitlocker'),
      text: tx('Если забыть ПИН-код или поменять настройки прошивки, диск {0} без ключа восстановления не открыть. Добавьте ключ: откройте командную строку от имени администратора и введите manage-bde -protectors -add {0} -RecoveryPassword. Потом сохраните его: «Шифрование диска BitLocker» → «Создать резервную копию ключа восстановления».', disk.drive) });
  }
  if (['off', 'none', 'decrypting'].includes(disk.state)) {
    return step({ ...base, state: 'todo',
      text: t('Ключ восстановления создаёт сам мастер BitLocker на шаге «Включить BitLocker с ПИН-кодом»: он не даст продолжить, пока вы его не сохраните. Сохраните ключ в учётной записи Microsoft, на флешке или распечатайте - и не храните его только на этом же диске. Без ключа забытый ПИН-код означает потерю всех файлов.') });
  }
  return step({ ...base, state: 'unknown', text: t('Состояние шифрования диска не видно. Запустите проверку ещё раз.') });
}

function policyStep(f, preboot) {
  const base = { id: 'pin-policy', title: t('Разрешить ПИН-код при включении') };
  const p = LOGIN.fvePolicy(f);
  const domain = f.login && f.login.partOfDomain === true ? t('Компьютер в домене: эту политику может задавать администратор организации.') : '';
  if (preboot === 'pin') return step({ ...base, title: t('ПИН-код при включении разрешён'), state: 'done', text: t('Диск уже открывается с ПИН-кодом - значит, политика его разрешает.') });
  if (!p) return step({ ...base, state: 'unknown', text: t('Политика BitLocker не видна в этой проверке. Запустите проверку ещё раз.') });
  if (LOGIN.pinAllowed(p)) return step({ ...base, title: t('ПИН-код при включении разрешён'), state: 'done', text: t('Политика Windows разрешает ПИН-код: мастер BitLocker предложит «Ввести ПИН-код».') });
  return step({ ...base, state: 'todo', fix: { id: 'bitlocker-pin-policy' },
    text: join(' ', t('Сейчас политика Windows не разрешает ПИН-код при включении, поэтому мастер BitLocker его не предложит. Кнопка ниже только разрешает ПИН-код: диск она не шифрует и ПИН-код не ставит. Откатить можно в разделе «Исправления».'), domain) });
}

function pinStep(f, disk, preboot, policyState, tpm) {
  const later = policyState === 'todo' ? t('Сначала выполните шаг «Разрешить ПИН-код при включении».') : null;
  const maybe = policyState === 'unknown' ? t('Если Windows не предложит ПИН-код, сначала выполните шаг «Разрешить ПИН-код при включении».') : '';
  if (ENCRYPTED.includes(disk.state)) {
    if (preboot === 'pin') {
      return step({ id: 'pin-on', title: t('ПИН-код при включении спрашивается'), state: 'done',
        text: t('Диск зашифрован и без ПИН-кода не открывается: загрузиться с флешки или вынуть диск бесполезно. Не записывайте ПИН-код на самом компьютере.') });
    }
    const base = { id: 'add-pin', title: t('Добавить ПИН-код к BitLocker'), guide: 'bitlocker-pin-add', open: open('bitlocker') };
    if (preboot == null) return step({ ...base, state: 'unknown', text: join(' ', tx('Диск {0} зашифрован. Спрашивает ли он ПИН-код при включении, Windows показывает только администратору.', disk.drive), fullCheck(f)) });
    return step({ ...base, state: later ? 'blocked' : 'todo',
      text: later || join(' ', tx('Диск {0} зашифрован, но открывается сам, без ПИН-кода. Нажмите «Открыть: шифрование диска BitLocker» → «Изменить способ разблокировки диска при запуске» → «Ввести ПИН-код». ПИН-код - не короче 6 цифр. После перезагрузки компьютер спросит его до запуска Windows.', disk.drive), maybe) });
  }
  if (disk.state === 'suspended' || disk.state === 'waiting') {
    return step({ id: 'resume', title: t('Возобновить защиту BitLocker'), state: 'todo', guide: 'bitlocker-pin-add', open: open('bitlocker'),
      text: tx('Диск {0} зашифрован, но защита приостановлена: ключ сейчас лежит открыто. Нажмите «Открыть: шифрование диска BitLocker» → «Возобновить защиту». Потом добавьте ПИН-код: «Изменить способ разблокировки диска при запуске».', disk.drive) });
  }
  if (['off', 'none', 'decrypting'].includes(disk.state)) {
    const base = { id: 'turn-on', title: t('Включить BitLocker с ПИН-кодом'), guide: 'bitlocker', open: open('bitlocker') };
    if (tpm === false) return step({ ...base, state: 'blocked', guide: 'tpm', open: open('tpm'), text: t('Модуль TPM не найден или не готов. BitLocker с ПИН-кодом при включении работает вместе с TPM: сначала включите его в настройках UEFI по инструкции.') });
    if (later) return step({ ...base, state: 'blocked', text: later });
    const wait = disk.state === 'decrypting' ? t('Сейчас диск расшифровывается - дождитесь конца.') : '';
    return step({ ...base, state: 'todo',
      text: join(' ', wait, tx('Нажмите «Открыть: шифрование диска BitLocker» → «Включить BitLocker» у диска {0}. Мастер Windows спросит, как открывать диск при запуске, - выберите «Ввести ПИН-код» (не короче 6 цифр). Потом он попросит сохранить ключ восстановления и предложит проверку с перезагрузкой - не пропускайте её. Шифрование идёт в фоне, работать можно.', disk.drive), maybe) });
  }
  return step({ id: 'turn-on', title: t('Включить BitLocker с ПИН-кодом'), state: 'unknown', guide: 'bitlocker', open: open('bitlocker'), text: t('Состояние шифрования диска не видно. Запустите проверку ещё раз.') });
}

function firmwareStep(f) {
  const l = secondLayer(f);
  const fw = f.firmware || {};
  const issues = [];
  const unseen = [];
  if (l.biosPw === 'none') issues.push(t('пароль BIOS/UEFI не установлен'));
  else if (l.biosPw === 'unknown') unseen.push(t('Прошивка не сообщает Windows, установлен ли пароль BIOS/UEFI, - проверьте сами по инструкции.'));
  if (l.secureBoot === 'off') issues.push(t('безопасная загрузка (Secure Boot) выключена'));
  else if (l.secureBoot === 'legacy') issues.push(t('компьютер загружается в старом режиме BIOS, без Secure Boot'));
  else if (l.secureBoot === 'unknown') unseen.push(t('Состояние Secure Boot Windows не сообщает.'));
  if (l.bootOrder === 'external-first') issues.push(t('первой в порядке загрузки стоит флешка или сеть'));
  else if (l.bootOrder === 'external-listed') issues.push(t('в порядке загрузки есть флешка или сеть'));
  else if (l.bootOrder === 'unknown') unseen.push(join(' ', t('Порядок загрузки Windows показывает только администратору.'), fullCheck(f)));
  const who = fw.manufacturer ? tx('Компьютер: {0} {1}. Войти в настройки прошивки: {2}.', fw.manufacturer, fw.model || '', firmwareKey(fw.manufacturer)) : '';
  const base = { id: 'firmware', title: t('Закрыть BIOS/UEFI: пароль, Secure Boot, загрузка только с диска'), guide: 'bios-lock', open: open('recovery') };
  const cant = t('Выключена ли загрузка с флешки и меню выбора загрузки, из Windows не проверить - загляните в настройки прошивки сами.');
  if (issues.length) return step({ ...base, state: 'todo', text: join(' ', tx('Сейчас: {0}.', join('; ', issues)), t('Поставьте пароль администратора BIOS/UEFI, включите Secure Boot, первым поставьте диск Windows и выключите загрузку с USB и по сети.'), unseen, who) });
  if (unseen.length) return step({ ...base, state: 'unknown', text: join(' ', unseen, cant, who) });
  return step({ ...base, state: 'done', text: join(' ', t('Пароль BIOS/UEFI установлен, Secure Boot включён, первым загружается диск Windows.'), cant, who) });
}

function homeSteps(f, disk, tpm) {
  const steps = [];
  const prevent = f.login && f.login.bitlocker && Number(f.login.bitlocker.preventDeviceEncryption) === 1 ? t('Автоматическое шифрование устройства выключено настройкой (PreventDeviceEncryption) - включите его вручную.') : '';
  const base = { id: 'device-encryption', title: t('Зашифровать диск (шифрование устройства)'), open: open('deviceencryption'), guide: 'bitlocker' };
  if (ENCRYPTED.includes(disk.state)) {
    steps.push(step({ ...base, title: t('Диск зашифрован'), state: 'done',
      text: tx('Диск {0} зашифрован. Ключ восстановления обычно хранится в вашей учётной записи Microsoft: «Учётная запись Microsoft» → «Устройства» → «Ключи восстановления BitLocker». Проверьте, что он там есть.', disk.drive) }));
  } else if (disk.state === 'waiting' || disk.state === 'suspended') {
    steps.push(step({ ...base, state: 'todo', text: join(' ', tx('Диск {0} подготовлен к шифрованию, но защита не включена. Войдите в Windows с учётной записью Microsoft или включите «Шифрование устройства» в параметрах - тогда ключ восстановления сохранится в учётной записи.', disk.drive), prevent) }));
  } else if (tpm === false) {
    steps.push(step({ ...base, state: 'blocked', guide: 'tpm', open: open('tpm'), text: t('Шифрованию устройства нужен модуль TPM, а он не найден или не готов. Иногда его можно включить в настройках UEFI по инструкции.') }));
  } else if (['off', 'none', 'decrypting'].includes(disk.state)) {
    steps.push(step({ ...base, state: 'todo',
      text: join(' ', t('Нажмите «Открыть: шифрование устройства» и включите переключатель. Нужна учётная запись Microsoft: туда Windows сохранит ключ восстановления. Если такого пункта в параметрах нет, этот компьютер шифрование устройства не поддерживает.'), prevent) }));
  } else {
    steps.push(step({ ...base, state: 'unknown', text: t('Состояние шифрования диска не видно. Запустите проверку ещё раз.') }));
  }
  steps.push(step({
    id: 'pin-home', title: t('ПИН-код при включении в Windows Домашняя недоступен'), state: 'blocked', open: open('activation'),
    text: t('В Windows Домашняя зашифрованный диск открывается чипом TPM сам, без ПИН-кода. Обычному вору этого хватает, чтобы ничего не прочитать, но со специальными инструментами ключ можно достать из включённого или спящего компьютера. ПИН-код при включении есть в Windows Pro: перейти можно в «Параметры» → «Система» → «Активация», это платно. Есть и сторонние программы полного шифрования диска с паролем при включении: выбирайте известную, с открытым кодом, и обязательно сохраните её ключ или диск восстановления. А пока в дороге выключайте компьютер полностью, а не усыпляйте.'),
  }));
  steps.push(firmwareStep(f));
  return steps;
}

function plan(facts) {
  const f = facts || {};
  const edition = LOGIN.edition(f);
  const editionId = String((f.login && f.login.edition && f.login.edition.id) || (f.meta && f.meta.edition) || '') || null;
  const disk = diskState(f);
  const tpm = tpmOf(f);
  let steps;
  if (edition === 'home') {
    steps = homeSteps(f, disk, tpm);
  } else {
    const protectors = ENCRYPTED.includes(disk.state) || ['suspended', 'waiting'].includes(disk.state) ? protectorsOf(f, disk.drive) : null;
    const preboot = ENCRYPTED.includes(disk.state) ? prebootOf(f, protectors) : null;
    const policy = policyStep(f, preboot);
    steps = [recoveryStep(f, disk, protectors), policy, pinStep(f, disk, preboot, policy.state, tpm), firmwareStep(f)];
  }
  const count = (s) => steps.filter((x) => x.state === s).length;
  const needsFullCheck = !f.isAdmin && steps.some((x) => x.state === 'unknown');
  const done = count('done');
  let headline;
  const pinOn = steps.some((x) => x.id === 'pin-on' && x.state === 'done');
  const fwDone = steps.some((x) => x.id === 'firmware' && x.state === 'done');
  if (edition === 'home') {
    headline = ENCRYPTED.includes(disk.state)
      ? t('Диск зашифрован. ПИН-код при включении в Windows Домашняя недоступен - осталось закрыть BIOS/UEFI.')
      : t('Диск не зашифрован: если загрузить компьютер с флешки или вынуть диск, ваши файлы можно прочитать. В Windows Домашняя есть шифрование устройства, но без ПИН-кода при включении.');
  } else if (pinOn && fwDone) {
    headline = t('Главное сделано: диск зашифрован и без ПИН-кода не откроется, BIOS/UEFI под паролем.');
  } else if (pinOn) {
    headline = t('Главное сделано: диск зашифрован и без ПИН-кода не откроется. Осталось проверить BIOS/UEFI.');
  } else if (ENCRYPTED.includes(disk.state)) {
    headline = tx('Диск зашифрован, но ПИН-кода при включении пока нет. Сделано шагов: {0} из {1}.', done, steps.length);
  } else if (['off', 'none', 'decrypting', 'suspended', 'waiting'].includes(disk.state)) {
    headline = tx('Сейчас Windows можно обойти: если загрузить компьютер с флешки или вынуть диск, ваши файлы можно прочитать. Сделано шагов: {0} из {1}.', done, steps.length);
  } else {
    headline = tx('Сделано шагов: {0} из {1}. Часть сведений не видна - запустите проверку ещё раз.', done, steps.length);
  }
  return { available: edition === 'pro' ? true : edition === 'home' ? false : null, edition, editionId, needsFullCheck, headline, steps };
}

module.exports = { plan, tpmOf, protectorsOf, prebootOf };
