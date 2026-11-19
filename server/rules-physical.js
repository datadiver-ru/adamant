'use strict';
/**
 * Физический доступ: обход входа в Windows через загрузку с флешки, подмену специальных возможностей, BIOS и т. п.
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Если нужного раздела в facts нет
 * (старый отчёт), - не больше одной находки «Не видно» или ничего.
 * Сведения: facts.physical (server/ps/sections/physical.ps1) + общие encryption, boot, firmware из collect.ps1.
 */
const { tx, t } = require('./i18n');
const { arr, ok, DAY } = require('./rules');
const { parseBcdFirmware } = require('./bcd');

const CAT = 'physical';
const NEED_ADMIN = t('Видно после полной проверки (кнопка «Проверить полностью»)');

/** Какое «настоящее» имя (OriginalFilename) у файлов специальных возможностей Windows. */
const EXPECTED_NAMES = {
  'sethc.exe': ['sethc.exe'],
  'utilman.exe': ['utilman2.exe', 'utilman.exe'],
  'osk.exe': ['osk.exe'],
  'magnify.exe': ['screenmagnifier.exe', 'magnify.exe'],
  'narrator.exe': ['sr.exe', 'narrator.exe'],
  'displayswitch.exe': ['displayswitch.exe', 'displayswitch'],
  'atbroker.exe': ['atbroker.exe'],
};
/** Программы, которыми обычно подменяют специальные возможности: командная строка, PowerShell, проводник… */
const SHELL_RE = /^(cmd|powershell|powershell_ise|pwsh|explorer|taskmgr|regedit|regedt32|mmc|conhost|openconsole|wt|windowsterminal|wscript|cscript|mshta|rundll32|notepad|net1?|whoami|bash|wsl|compmgmt|lusrmgr|control)(\.exe)?$/i;

/** Имя файла из команды: «"C:\Windows\System32\cmd.exe" /k» → cmd.exe. */
function baseName(cmd) {
  const s = String(cmd || '').trim();
  const m = /^"([^"]*)"/.exec(s);
  return (m ? m[1] : s.split(/\s+/)[0]).split(/[\\/]/).pop();
}
const normName = (s) => String(s || '').trim().toLowerCase().replace(/\.mui$/, '');
/** Время события для людей: «2026-11-10 23:14» (в часовом поясе компьютера, как записала Windows). */
const when = (iso) => String(iso || '').slice(0, 16).replace('T', ' ');
const mins = (sec) => Math.max(1, Math.round(sec / 60));

// ---------------------------------------------------------------- Специальные возможности

function accessibilityRules(p, out) {
  const items = arr(p.accessibility);
  if (!items.length) return;
  const debuggers = items.filter((a) => a.debugger && String(a.debugger).trim());
  const replaced = [];
  const odd = [];
  for (const a of items) {
    if (!a.exists || a.originalName == null) continue;
    const name = normName(a.originalName);
    const expected = EXPECTED_NAMES[normName(a.exe)];
    if (!expected || expected.includes(name)) continue;
    if (!name || SHELL_RE.test(name)) replaced.push(a);
    else odd.push(a);
  }
  const ats = arr(p.ats).filter((x) => SHELL_RE.test(baseName(x.startExe)) || SHELL_RE.test(baseName(x.atExe)));
  if (!debuggers.length && !replaced.length && !odd.length && !ats.length) {
    out.push(ok('phys-accessibility-ok', CAT, t('Специальные возможности на экране входа не подменены'), t('Залипание клавиш, экранная клавиатура и другие кнопки экрана входа запускают настоящие программы Windows.')));
    return;
  }
  const evidence = [
    ...debuggers.map((a) => tx('{0}: вместо него запускается {1}', a.exe, a.debugger)),
    ...replaced.map((a) => (normName(a.originalName) ? tx('{0}: на его месте лежит {1}', a.exe, a.originalName) : tx('{0}: файл без сведений о версии, это не программа Windows', a.exe))),
    ...odd.map((a) => tx('{0}: внутри файл {1}, а должен быть {2}', a.exe, a.originalName, EXPECTED_NAMES[normName(a.exe)][0])),
    ...ats.map((x) => tx('Средство специальных возможностей «{0}» запускает {1}', x.name, x.startExe || x.atExe)),
  ];
  for (const a of [...replaced, ...odd]) if (a.modified) evidence.push(tx('{0} изменён {1}', a.exe, when(a.modified)));
  const critical = debuggers.length || replaced.length || ats.length;
  out.push({
    id: 'phys-accessibility-backdoor', cat: CAT, sev: critical ? 'critical' : 'high',
    title: critical ? t('На экране входа спрятан вход без пароля') : t('Файл специальных возможностей отличается от обычного'),
    text: critical
      ? t('Кнопки специальных возможностей на экране входа (залипание клавиш - 5 раз Shift, экранная клавиатура, Win+U) подменены. Так любой, кто сядет за компьютер, открывает командную строку с полными правами без пароля и может сменить пароль, создать учётную запись или забрать файлы. Это известный приём взлома. Если вы сами этого не делали, считайте, что к компьютеру имел доступ посторонний.')
      : t('Программа специальных возможностей на экране входа - не та, что ставит Windows. Это может быть подмена. Проверьте системные файлы по инструкции.'),
    evidence,
    fix: debuggers.length ? { id: 'ifeo-clean', arg: { exes: debuggers.map((a) => a.exe) } } : undefined,
    guide: 'accessibility-restore',
  });
}

// ---------------------------------------------------------------- Флешка и чужая система

/** Состояние шифрования системного диска - та же логика, что в rules.js (bitlockerRules). */
const BL_SHELL = { 1: 'on', 2: 'off', 3: 'encrypting', 4: 'decrypting', 5: 'suspended', 6: 'on', 7: 'suspended', 8: 'waiting' };
function diskState(f) {
  const e = f.encryption;
  if (!e) return { state: null, drive: 'C:' };
  const sys = arr(e.drives).find((d) => d.system) || arr(e.drives)[0];
  const vol = sys && arr(e.volumes).find((v) => String(v.drive).toUpperCase() === String(sys.drive).toUpperCase());
  let state = sys ? BL_SHELL[sys.shellState] || (sys.shellState === 0 ? 'none' : null) : null;
  if (vol) state = vol.protection === 'On' ? 'on' : vol.status === 'EncryptionInProgress' ? 'encrypting' : vol.status === 'FullyEncrypted' ? 'suspended' : 'off';
  return { state, drive: sys ? sys.drive : 'C:' };
}

/** Второй слой защиты: пароль прошивки, Secure Boot, порядок загрузки. */
function secondLayer(f) {
  const fw = f.firmware || {};
  const v = fw.vendor;
  const biosPw = v && v.admin === true ? 'set' : v && v.admin === false ? 'none'
    : Number(fw.adminPasswordStatus) === 1 ? 'set' : Number(fw.adminPasswordStatus) === 0 ? 'none' : 'unknown';
  const b = f.boot || {};
  const secureBoot = b.firmware === 'bios' ? 'legacy' : b.secureBoot === 1 ? 'on' : b.secureBoot === 0 ? 'off' : 'unknown';
  let bootOrder = 'unknown';
  if (b.bcdFirmware) {
    const order = parseBcdFirmware(b.bcdFirmware);
    const ext = (o) => /usb|pxe|ipv4|ipv6|network|lan|сеть|cd|dvd|removable|флеш/i.test(o.description) && !/windows boot manager|диспетчер загрузки windows/i.test(o.description);
    if (order.length) bootOrder = ext(order[0]) ? 'external-first' : order.some(ext) ? 'external-listed' : 'windows-only';
  }
  return { biosPw, secureBoot, bootOrder };
}

function usbBootRules(f, p, out) {
  const { state, drive } = diskState(f);
  if (state === 'on' || state === 'encrypting') {
    out.push(ok('phys-usb-boot-ok', CAT, tx('Диск {0} зашифрован: с флешки файлы не прочитать', drive), t('Даже если загрузить компьютер с флешки или вынуть диск, без ключа BitLocker файлы не открыть. Это главная защита от того, у кого компьютер окажется в руках.')));
    return;
  }
  if (!['off', 'none', 'suspended', 'waiting', 'decrypting'].includes(state)) return; // не видно - об этом скажет находка BitLocker
  const l = secondLayer(f);
  const ev = [state === 'suspended' || state === 'waiting' ? tx('Диск {0}: защита BitLocker приостановлена', drive) : tx('Диск {0} не зашифрован', drive)];
  ev.push({ set: t('Пароль BIOS/UEFI: установлен'), none: t('Пароль BIOS/UEFI: нет'), unknown: t('Пароль BIOS/UEFI: из Windows не видно') }[l.biosPw]);
  ev.push({ on: t('Secure Boot: включён'), off: t('Secure Boot: выключен'), legacy: t('Secure Boot: нет, старый режим BIOS'), unknown: t('Secure Boot: не видно') }[l.secureBoot]);
  ev.push({ 'external-first': t('Порядок загрузки: первой стоит флешка или сеть'), 'external-listed': t('Порядок загрузки: загрузка с флешки или по сети разрешена'), 'windows-only': t('Порядок загрузки: только диск Windows'), unknown: t('Порядок загрузки: видно после полной проверки') }[l.bootOrder]);
  if (p.winre && p.winre.enabled === true) ev.push(t('Среда восстановления Windows включена: через неё тоже можно добраться до файлов'));
  const strong = l.biosPw === 'set' && l.secureBoot === 'on' && l.bootOrder !== 'external-first';
  out.push({
    id: 'phys-open-to-usb-boot', cat: CAT, sev: strong ? 'advice' : 'high',
    title: strong ? t('Диск не зашифрован: его можно вынуть и прочитать') : t('Любой, у кого компьютер в руках, может обойти пароль Windows'),
    text: strong
      ? t('Пароль BIOS и безопасная загрузка мешают загрузиться с чужой флешки. Но диск не зашифрован: его можно вынуть и подключить к другому компьютеру, и все файлы будут видны. Настоящая защита - шифрование диска (BitLocker).')
      : t('Пароль Windows действует, только пока работает сама Windows. Диск не зашифрован, поэтому посторонний может загрузить компьютер с флешки, прочитать и скопировать ваши файлы, а потом сбросить пароль Windows. Хватит нескольких минут без присмотра. Главная защита - шифрование диска (BitLocker). Второй слой - пароль на BIOS/UEFI и запрет загрузки с флешки.'),
    evidence: ev,
    guide: 'physical',
  });
}

function bitlockerPinRules(f, p, out) {
  const { state, drive } = diskState(f);
  if (state !== 'on') return;
  const b = p.bitlocker || {};
  if (b.preboot === 'pin') {
    out.push(ok('phys-bitlocker-pin-ok', CAT, t('При включении компьютер спрашивает ПИН-код BitLocker'), t('Без ПИН-кода ключ шифрования не выдаётся, даже если у вора будет сам компьютер.')));
  } else if (b.preboot === 'tpm-only') {
    out.push({
      id: 'phys-bitlocker-pin', cat: CAT, sev: 'advice',
      title: t('BitLocker открывает диск сам, без ПИН-кода при включении'),
      text: t('Сейчас ключ шифрования выдаёт чип TPM, как только компьютер включают. Обычному вору этого достаточно, чтобы ничего не прочитать. Но со специальными инструментами ключ можно достать из включённого или спящего компьютера. ПИН-код при запуске закрывает эту дыру: без него Windows даже не начнёт загружаться.'),
      evidence: [tx('Диск {0}: способы открыть - {1}', drive, arr(b.protectors).join(', ') || 'Tpm')],
      guide: 'bitlocker-pin',
    });
  } else if (b.preboot == null) {
    out.push({ id: 'phys-bitlocker-pin-unknown', cat: CAT, sev: 'unknown', title: t('Спрашивает ли BitLocker ПИН-код при включении'), text: p.admin ? t('Не удалось узнать, как BitLocker открывает диск при включении.') : NEED_ADMIN, evidence: [], guide: 'bitlocker-pin' });
  }
}

// ---------------------------------------------------------------- Экран без присмотра

function lockRules(p, out) {
  const l = p.lock;
  if (!l) return;
  const never = Number(l.delayLock) === 4294967295;
  const noAc = l.consoleLockAc != null && Number(l.consoleLockAc) === 0;
  const noDc = !!l.battery && l.consoleLockDc != null && Number(l.consoleLockDc) === 0;
  const ways = [];
  if (Number(l.inactivityTimeout) > 0) ways.push({ sec: Number(l.inactivityTimeout), what: t('блокировка при бездействии') });
  if (l.screenSaverActive && l.screenSaverSecure && l.screenSaverExe && Number(l.screenSaverTimeout) > 0) ways.push({ sec: Number(l.screenSaverTimeout), what: t('заставка с паролем') });
  const sleeps = [l.sleepAc, ...(l.battery ? [l.sleepDc] : [])].map(Number);
  if (!noAc && !noDc && !never && sleeps.every((s) => s > 0)) ways.push({ sec: Math.max(...sleeps), what: t('спящий режим') });
  const best = ways.sort((a, b) => a.sec - b.sec)[0];
  if (!best || best.sec > 30 * 60) {
    out.push({
      id: 'phys-no-autolock', cat: CAT, sev: 'advice',
      title: best ? tx('Компьютер блокируется сам только через {0} мин', mins(best.sec)) : t('Компьютер не блокируется сам, когда вы отходите'),
      text: t('Если вы отошли и забыли нажать Win+L, любой может сесть за компьютер и работать от вашего имени: читать почту, переписку, файлы. Пусть Windows сама блокирует экран, если с ним никто не работает 10 минут.'),
      evidence: [
        best ? tx('Быстрее всего срабатывает: {0}, {1} мин', best.what, mins(best.sec)) : t('Нет ни заставки с паролем, ни блокировки при бездействии, ни спящего режима'),
        ...(l.dynamicLock ? [t('Динамическая блокировка по телефону включена')] : []),
      ],
      fix: { id: 'lock-timeout' },
    });
  } else {
    out.push(ok('phys-autolock-ok', CAT, tx('Экран блокируется сам через {0} мин', mins(best.sec)), tx('Срабатывает {0}. Уходя, всё равно нажимайте Win+L.', best.what)));
  }
  if (noAc || noDc || never) {
    out.push({
      id: 'phys-no-signin-after-sleep', cat: CAT, sev: 'high',
      title: t('После сна компьютер открывается без пароля'),
      text: t('Когда компьютер просыпается, Windows не спрашивает пароль или ПИН-код. Достаточно открыть крышку ноутбука или пошевелить мышью - и всё ваше доступно тому, кто рядом.'),
      evidence: [
        noAc ? t('От сети: вход после сна не требуется') : null,
        noDc ? t('От батареи: вход после сна не требуется') : null,
        never ? t('«Требовать вход после отсутствия»: никогда') : null,
      ].filter(Boolean),
      guide: 'wake-signin',
    });
  }
}

// ---------------------------------------------------------------- Кто садился за компьютер

function presenceRules(p, out, now) {
  const pr = p.presence;
  if (!pr) return;
  const days = Number(pr.days) || 14;
  const since = now - days * DAY;
  const ev = arr(pr.events).filter((e) => {
    const at = Date.parse(e.at);
    return Number.isFinite(at) && at >= since && at <= now + DAY;
  });
  const count = (k) => ev.filter((e) => e.kind === k).length;
  const failed = ev.filter((e) => e.kind === 'failed-local').sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  if (pr.security) {
    if (failed.length) {
      const many = failed.length >= 3;
      out.push({
        id: 'phys-failed-local', cat: CAT, sev: many ? 'high' : 'advice',
        title: many ? tx('За этим компьютером {0} раз ввели неверный пароль', failed.length) : tx('Неверный пароль на этом компьютере: {0} раз за {1} дн.', failed.length, days),
        text: many
          ? t('Неверный пароль вводили с клавиатуры именно этого компьютера, а не по сети. Если это были не вы, кто-то пытался войти, пока вас не было рядом. Посмотрите время попыток. Поставьте сложный пароль и не оставляйте компьютер без присмотра.')
          : t('Скорее всего, это вы сами ошиблись при вводе. Если время попытки вам незнакомо, значит, кто-то пробовал войти без вас.'),
        evidence: failed.slice(0, 10).map((e) => (e.user ? tx('{0} - учётная запись {1}', when(e.at), e.user) : when(e.at))),
        guide: 'physical',
      });
    }
  } else {
    out.push({ id: 'phys-failed-local-unknown', cat: CAT, sev: 'unknown', title: t('Пытался ли кто-то войти за этим компьютером'), text: p.admin ? t('Не удалось прочитать журнал безопасности Windows.') : NEED_ADMIN, evidence: [] });
  }
  // Один сбой Windows записывает дважды (Kernel-Power 41 и EventLog 6008) - считаем случаи, а не записи.
  const unexpected = ev.filter((e) => e.kind === 'unexpected').map((e) => Date.parse(e.at)).sort((a, b) => a - b)
    .filter((at, i, all) => i === 0 || at - all[i - 1] > 10 * 60_000).length;
  const evidence = [
    tx('Включений: {0}, выходов из сна: {1}', count('boot'), count('wake')),
    tx('Входов в Windows: {0}', count('logon') + count('unlock')),
  ];
  if (unexpected) evidence.push(tx('Неожиданных выключений: {0} - обычно это пропавшее питание или зависание, само по себе не опасно', unexpected));
  const lastBoot = ev.filter((e) => e.kind === 'boot').sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0];
  if (lastBoot) evidence.push(tx('Последнее включение: {0}', when(lastBoot.at)));
  if (pr.security && !failed.length) evidence.push(t('Неверных паролей за этим компьютером не было'));
  const clean = pr.security && !failed.length && !out.some((x) => x.id === 'phys-accessibility-backdoor');
  out.push({
    id: 'phys-presence', cat: CAT, sev: 'ok',
    title: clean ? tx('За {0} дн. ничего подозрительного', days) : tx('Включения и входы за {0} дн.', days),
    text: clean
      ? t('Попыток подобрать пароль за этим компьютером не было. Если какое-то время включения или входа вам незнакомо, значит, компьютером пользовался кто-то другой.')
      : t('Когда компьютер включали, усыпляли и входили в Windows. Если какое-то время вам незнакомо, значит, компьютером пользовался кто-то другой.'),
    evidence,
  });
}

// ---------------------------------------------------------------- Флешки

/** Промежутки, когда компьютер был заблокирован (журнал безопасности: блокировка → разблокировка). */
function lockedIntervals(p) {
  const ev = arr(p.presence && p.presence.events)
    .filter((e) => e.kind === 'lock' || e.kind === 'unlock')
    .map((e) => ({ kind: e.kind, at: Date.parse(e.at) }))
    .filter((e) => Number.isFinite(e.at))
    .sort((a, b) => a.at - b.at);
  const out = [];
  let start = null;
  for (const e of ev) {
    if (e.kind === 'lock') start = e.at;
    else if (start != null) { out.push([start, e.at]); start = null; }
  }
  return out;
}

function usbRules(p, out) {
  if (p.usb == null) return;
  const list = arr(p.usb);
  if (!list.length) {
    out.push(ok('phys-usb-history', CAT, t('Флешки и внешние диски к компьютеру не подключали'), t('Windows не помнит ни одной флешки или внешнего диска.')));
    return;
  }
  const locked = lockedIntervals(p);
  const whileLocked = list.filter((d) => {
    const at = Date.parse(d.last);
    return Number.isFinite(at) && locked.some(([a, b]) => at > a && at < b);
  });
  const evidence = list.slice(0, 8).map((d) => {
    const name = d.name || d.serial || '-';
    if (d.present) return tx('{0} - подключён сейчас', name);
    if (d.last) return tx('{0} - последний раз {1}', name, when(d.last));
    return name;
  });
  if (list.length > 8) evidence.push(tx('и ещё {0}', list.length - 8));
  if (whileLocked.length) {
    out.push({
      id: 'phys-usb-history', cat: CAT, sev: 'advice',
      title: t('Флешку подключали, когда компьютер был заблокирован'),
      text: t('Пока экран был заблокирован, к компьютеру подключали флешку или внешний диск. Если это были не вы, кто-то был у компьютера без вас. Список всех флешек - ниже.'),
      evidence: [...whileLocked.map((d) => tx('{0} - {1}, экран был заблокирован', d.name || d.serial, when(d.last))), ...evidence],
      guide: 'physical',
    });
    return;
  }
  out.push({
    id: 'phys-usb-history', cat: CAT, sev: 'ok',
    title: tx('Флешки и внешние диски, которые подключали: {0}', list.length),
    text: t('Windows помнит флешки и внешние диски, которые к ней подключали. Если какой-то вам незнаком, значит, его подключал кто-то другой.'),
    evidence,
  });
}

// ---------------------------------------------------------------- Порты Thunderbolt/USB4

function dmaRules(p, out) {
  const d = p.dma;
  if (!d || !d.thunderbolt) return;
  if (d.protection === true) {
    out.push(ok('phys-dma-ok', CAT, t('Защита памяти от устройств Thunderbolt включена'), t('Устройство, подключённое к порту Thunderbolt или USB4, не может само читать память компьютера.')));
  } else if (d.protection === false) {
    out.push({
      id: 'phys-dma', cat: CAT, sev: 'advice',
      title: t('Порт Thunderbolt/USB4 без защиты памяти'),
      text: t('Через порт Thunderbolt или USB4 специальное устройство может напрямую читать память компьютера - даже заблокированного, вместе с ключами шифрования. Windows умеет это запрещать (защита DMA ядра), но на этом компьютере она выключена. Обычно её включают в настройках UEFI.'),
      evidence: [t('Защита DMA ядра: выключена'), t('Есть контроллер Thunderbolt/USB4')],
      guide: 'dma-protection',
    });
  }
}

function evaluate(facts, { now = Date.now() } = {}) {
  const f = facts || {};
  const p = f.physical;
  if (!p || typeof p !== 'object') {
    const err = f.errors && f.errors.physical;
    return err ? [{ id: 'phys-unknown', cat: CAT, sev: 'unknown', title: t('Защита от физического доступа'), text: tx('Не удалось проверить: {0}', err), evidence: [] }] : [];
  }
  const out = [];
  accessibilityRules(p, out);
  usbBootRules(f, p, out);
  bitlockerPinRules(f, p, out);
  lockRules(p, out);
  presenceRules(p, out, now);
  usbRules(p, out);
  dmaRules(p, out);
  return out;
}

module.exports = { evaluate, EXPECTED_NAMES, diskState, secondLayer };
