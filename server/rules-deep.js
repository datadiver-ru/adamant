'use strict';
/**
 * Глубокие проверки защиты от взлома (раздел hardening, server/ps/sections/hardening.ps1).
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Если раздела hardening в facts нет
 * (старый отчёт), - ничего; если раздел не собрался из-за ошибки - одна находка «Не видно».
 *
 * facts.hardening:
 *   admin, build, partOfDomain
 *   lsa { runAsPPL, runAsPPLBoot, lmCompat, noLmHash, lsaCfgFlags, lsaCfgFlagsPolicy, pplEvent: { at, level } | null }
 *   wdigest { useLogonCredential }, cachedLogons
 *   deviceGuard { vbs, running[], configured[], available[], hvciEnabled, vbsEnabled, error? }
 *   mp { available, cfa, pua, maps, samples, asr: [{ id, action }], error? }
 *   smartScreen { explorer, policy, policyLevel, smartAppControl }, driverBlocklist
 *   llmnr, netbiosNodeType, netbios: [{ name, option, index }], wpad { autoDetect, serviceStart }
 *   smbSigning { server, client, serverReg, clientReg }
 *   services { WinRM, RemoteRegistry, Spooler: { status, start } | null }, winrmListeners
 *   remoteAssistance { allow, policy }, printers: [{ name, port }]
 *   ps2 { engine }, execPolicy { machinePolicy, userPolicy, machine, user }
 *   autorun { machineDriveTypes, userDriveTypes, machineNoAutorun, userNoAutorun, disableAutoplay }
 *   office: [{ app, vbaWarnings, policyVbaWarnings, blockInternet }], lock { inactivityTimeoutSecs }
 */
const { tx, t } = require('./i18n');

const CAT = 'hardening';
const FULL = t('Видно после полной проверки (кнопка «Проверить полностью»)');

/** Безопасный набор правил ASR (режим «Блокировать»). Тот же список - в fix.ps1 ($AsrSafe). */
const SAFE_ASR = {
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2': t('Кража паролей из процесса lsass'),
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550': t('Запуск программ из вложений почты'),
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a': t('Запуск программ из Office'),
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc': t('Запуск запутанных сценариев'),
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4': t('Неподписанные программы с флешек'),
  '56a863a9-875e-4185-98a7-b882c64b5ce5': t('Уязвимые подписанные драйверы'),
};
const ASR_ACTIONS = { 0: t('выключено'), 1: t('блокировать'), 2: t('только запись в журнал'), 6: t('предупреждать') };

const arr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
const num = (v) => (v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v));
const shown = (v) => (v == null ? t('не задано') : String(v));

function ok(id, title, text) {
  return { id, cat: CAT, sev: 'ok', title, text, evidence: [] };
}
function unknown(id, title, reason) {
  return { id: `${id}-unknown`, cat: CAT, sev: 'unknown', title, text: reason ? tx('Не удалось проверить: {0}', reason) : t('Не удалось проверить'), evidence: [] };
}

/** productState центра безопасности: биты 12-15 - включён ли антивирус (как в rules.js). */
const avOn = (state) => ((Number(state) >> 12) & 0xf) === 1;

/**
 * Защищает ли компьютер именно Microsoft Defender: { active: true } - да, { active: false, others } - работает
 * другой антивирус, null - не видно. Тот же принцип, что в rules.js.
 */
function defenderIsActive(f) {
  const d = f.defender;
  if (!d) return null;
  const others = arr(d.products).filter((p) => p && !/defender/i.test(String(p.name)) && avOn(p.state));
  const s = d.status;
  if (others.length && (!s || /passive|edr|sidebyside/i.test(String(s.mode || '')) || !s.realTime)) return { active: false, others };
  if (!s) return null;
  return { active: true, others };
}

// ---------------------------------------------------------------- Кража паролей

function credentialRules(f, h, out) {
  const lsa = h.lsa || {};
  const ppl = num(lsa.runAsPPL);
  const ev = lsa.pplEvent;
  const boot = Date.parse((f.meta && f.meta.lastBoot) || '');
  const evFresh = !!ev && num(ev.level) === 4 && (!Number.isFinite(boot) || Date.parse(ev.at || '') >= boot - 60_000);
  const build = num(h.build) || num(f.meta && f.meta.osBuild) || 0;
  if (ppl === 1 || ppl === 2 || evFresh) {
    out.push(ok('hard-lsa-ppl-ok', t('Защита паролей в памяти (LSA) включена'), evFresh ? t('Windows подтвердила: процесс входа защищён с последней загрузки.') : t('Включится полностью после перезагрузки, если вы ещё не перезагружались.')));
  } else {
    out.push({
      id: 'hard-lsa-ppl-off', cat: CAT, sev: 'advice',
      title: t('Защита паролей в памяти (LSA) выключена'),
      text: t('Windows держит данные для входа в памяти особого процесса. Если вирус получит права администратора, он может вытащить их оттуда и войти в другие ваши компьютеры и почту. Защита LSA не даёт чужим программам читать эту память.'),
      evidence: [tx('RunAsPPL: {0}', shown(lsa.runAsPPL))],
      ...(build >= 22621 ? { fix: { id: 'lsa-ppl-on' } } : { guide: 'hard-lsa' }),
    });
  }

  const wd = num(h.wdigest && h.wdigest.useLogonCredential);
  if (wd === 1) {
    out.push({
      id: 'hard-wdigest-on', cat: CAT, sev: 'high',
      title: t('Windows хранит ваш пароль в памяти открытым текстом'),
      text: t('Включена старая настройка WDigest. С ней пароль лежит в памяти без шифрования, и любой вирус с правами администратора его прочитает. Сама Windows её давно не включает: часто это делают взломщики, чтобы собрать пароли.'),
      evidence: [t('WDigest UseLogonCredential = 1')],
      fix: { id: 'wdigest-off' },
    });
  }

  const lm = num(lsa.lmCompat);
  if (lm != null && lm < 3) {
    out.push({
      id: 'hard-ntlmv1', cat: CAT, sev: 'high',
      title: t('Разрешён устаревший вход по сети (LM и NTLMv1)'),
      text: t('Когда компьютер входит на другой компьютер или в сетевую папку, он отправляет ответ, из которого пароль легко подобрать. Современный способ - NTLMv2 - так не взломать.'),
      evidence: [tx('LmCompatibilityLevel = {0} (нужно 3 или больше)', lm)],
      guide: 'hard-ntlm',
    });
  }
  if (num(lsa.noLmHash) === 0) {
    out.push({
      id: 'hard-lm-hash', cat: CAT, sev: 'high',
      title: t('Windows хранит пароли в очень слабом виде (LM)'),
      text: t('Пароли учётных записей хранятся ещё и в старом формате LM. Его подбирают за минуты, если получат копию базы паролей.'),
      evidence: [t('NoLMHash = 0')],
      guide: 'hard-ntlm',
    });
  }
  if (wd !== 1 && (lm == null || lm >= 3) && num(lsa.noLmHash) !== 0) {
    out.push(ok('hard-ntlm-ok', t('Пароли не хранятся и не передаются в слабом виде'), t('WDigest выключен, вход по сети - только NTLMv2.')));
  }

  const cached = num(h.cachedLogons);
  if (h.partOfDomain === true && cached != null && cached > 4) {
    out.push({
      id: 'hard-cached-logons', cat: CAT, sev: 'advice',
      title: t('Компьютер помнит много входов в домен'),
      text: t('Чтобы вы могли войти без связи с офисом, Windows запоминает данные последних входов. Чем их больше, тем больше паролей может достаться вору вместе с компьютером. Обычно хватает 1-4. Решает это администратор домена.'),
      evidence: [tx('CachedLogonsCount = {0}', cached)],
    });
  }
}

// ---------------------------------------------------------------- Изоляция ядра

function coreIsolationRules(f, h, out) {
  const dg = h.deviceGuard;
  if (!dg || (dg.error && dg.vbs == null)) {
    out.push(unknown('hard-hvci', t('Целостность памяти (изоляция ядра)'), (dg && dg.error) || (!h.admin ? FULL : null)));
    return;
  }
  const running = arr(dg.running).map(Number);
  const vbsText = { 0: t('выключена'), 1: t('включена, но не работает'), 2: t('работает') };
  if (running.includes(2)) {
    out.push(ok('hard-hvci-ok', t('Целостность памяти включена'), t('Вредоносный драйвер не сможет незаметно изменить ядро Windows.')));
  } else {
    out.push({
      id: 'hard-hvci-off', cat: CAT, sev: 'advice',
      title: t('Целостность памяти (изоляция ядра) выключена'),
      text: t('Эта защита Windows не даёт вирусам и вредоносным драйверам встроиться в самое сердце системы. Включается одним переключателем, но старые драйверы могут ей мешать - Windows сама подскажет, какие.'),
      evidence: [tx('Безопасность на основе виртуализации: {0}', vbsText[num(dg.vbs)] || shown(dg.vbs))],
      guide: 'hard-memory-integrity',
    });
  }
  const edition = String((f.meta && f.meta.edition) || '');
  if (/enterprise|education/i.test(edition)) {
    if (running.includes(1)) {
      out.push(ok('hard-credguard-ok', t('Credential Guard работает'), t('Данные для входа хранятся в изолированной памяти.')));
    } else {
      out.push({
        id: 'hard-credguard-off', cat: CAT, sev: 'advice',
        title: t('Credential Guard не работает'),
        text: t('В вашей версии Windows есть Credential Guard: он прячет данные для входа в отдельную защищённую память. Тогда их не украсть даже с правами администратора.'),
        evidence: [tx('Выпуск Windows: {0}', edition)],
        guide: 'hard-credguard',
      });
    }
  }
}

// ---------------------------------------------------------------- Вирусы и шантажисты

function defenderExtraRules(f, h, out) {
  const who = defenderIsActive(f);
  if (who && !who.active) {
    out.push(ok('hard-defender-other', tx('Дополнительные настройки Defender не нужны: работает {0}', who.others.map((p) => p.name).join(', ')),
      t('Защиту от шантажистов и опасных программ даёт ваш антивирус, у него свои настройки.')));
    return;
  }
  const mp = h.mp || {};
  if (!who || !mp.available) {
    out.push(unknown('hard-defender', t('Дополнительная защита Microsoft Defender'), mp.error || (!h.admin ? FULL : null)));
    return;
  }
  let problems = 0;
  if (num(mp.cfa) !== 1) {
    problems++;
    out.push({
      id: 'hard-cfa-off', cat: CAT, sev: 'advice',
      title: t('Защита папок от программ-шантажистов выключена'),
      text: t('Программа-шантажист шифрует документы и фото и просит выкуп. «Контролируемый доступ к папкам» не даёт незнакомым программам менять файлы в «Документах», «Изображениях» и на рабочем столе.'),
      evidence: [tx('Контролируемый доступ к папкам: {0}', { 0: t('выключен'), 2: t('только запись в журнал'), 3: t('только защита дисков'), 4: t('только запись в журнал') }[num(mp.cfa)] || shown(mp.cfa))],
      fix: { id: 'cfa-on' },
    });
  }
  const rules = new Map(arr(mp.asr).filter((r) => r && r.id).map((r) => [String(r.id).toLowerCase(), num(r.action)]));
  const missing = Object.keys(SAFE_ASR).filter((id) => rules.get(id) !== 1);
  if (missing.length) {
    problems++;
    out.push({
      id: 'hard-asr', cat: CAT, sev: 'advice',
      title: t('Не включены правила, которые блокируют приёмы вирусов'),
      text: t('В Defender есть правила «Сокращение направлений атак». Они не дают, например, документу Word запустить программу или вирусу украсть пароли из памяти. Обычной работе почти не мешают.'),
      evidence: missing.map((id) => tx('{0}: {1}', SAFE_ASR[id], rules.has(id) ? ASR_ACTIONS[rules.get(id)] || shown(rules.get(id)) : t('не задано'))),
      fix: { id: 'asr-safe' },
    });
  }
  if (num(mp.pua) !== 1) {
    problems++;
    out.push({
      id: 'hard-pua-off', cat: CAT, sev: 'advice',
      title: t('Не блокируются нежелательные программы'),
      text: t('Defender может не пускать программы с навязчивой рекламой, «ускорители» и установщики, которые тайком ставят что-то ещё. Сейчас это выключено.'),
      evidence: [tx('Блокировка нежелательных программ: {0}', { 0: t('выключена'), 2: t('только запись в журнал') }[num(mp.pua)] || shown(mp.pua))],
      fix: { id: 'pua-on' },
    });
  }
  if (num(mp.maps) === 0) {
    problems++;
    out.push({
      id: 'hard-cloud-off', cat: CAT, sev: 'high',
      title: t('Облачная защита Defender выключена'),
      text: t('Без облака Defender узнаёт о новом вирусе только с обновлением баз, а это часы или дни. С облаком незнакомый файл проверяется сразу.'),
      evidence: [t('Облачная защита (MAPS): выключена')],
      fix: { id: 'cloud-on' },
    });
  } else if (num(mp.samples) === 2) {
    problems++;
    out.push({
      id: 'hard-samples-never', cat: CAT, sev: 'advice',
      title: t('Defender не отправляет подозрительные файлы на проверку'),
      text: t('Если Defender не уверен в файле, он может отправить его в Microsoft и через секунды получить ответ. Сейчас это запрещено, поэтому новые вирусы ловятся хуже. Документы с личными данными без спроса не отправляются.'),
      evidence: [t('Автоматическая отправка образцов: никогда')],
      guide: 'hard-samples',
    });
  }
  if (!problems) out.push(ok('hard-defender-extra-ok', t('Дополнительная защита Defender включена'), t('Защита папок, правила против приёмов вирусов, облако и блокировка нежелательных программ.')));
}

function smartScreenRules(f, h, out) {
  const s = h.smartScreen;
  if (!s) return;
  const policyOff = num(s.policy) === 0;
  if (policyOff || /^off$/i.test(String(s.explorer || ''))) {
    out.push({
      id: 'hard-smartscreen-off', cat: CAT, sev: 'high',
      title: t('SmartScreen не проверяет скачанные программы'),
      text: t('SmartScreen предупреждает, когда вы запускаете незнакомую программу из интернета. Так чаще всего и заражают компьютеры. Сейчас предупреждений не будет.'),
      evidence: [policyOff ? t('Выключено групповой политикой') : t('Проверка приложений и файлов: выключена')],
      guide: 'hard-smartscreen',
    });
  } else {
    out.push(ok('hard-smartscreen-ok', t('SmartScreen проверяет скачанные программы'), t('Windows предупредит перед запуском незнакомой программы из интернета.')));
  }
}

function driverBlocklistRules(f, h, out) {
  const v = num(h.driverBlocklist);
  const hvci = arr(h.deviceGuard && h.deviceGuard.running).map(Number).includes(2);
  const build = num(h.build) || 0;
  if (v === 1 || hvci || (v == null && build >= 22621)) {
    out.push(ok('hard-driver-blocklist-ok', t('Уязвимые драйверы блокируются'), t('Windows не загрузит драйверы, через которые вирусы отключают защиту.')));
    return;
  }
  out.push({
    id: 'hard-driver-blocklist-off', cat: CAT, sev: 'advice',
    title: t('Не блокируются известные уязвимые драйверы'),
    text: t('Вирусы иногда ставят старый драйвер с известной дырой и через него выключают антивирус. У Microsoft есть список таких драйверов, но он сейчас не применяется.'),
    evidence: [tx('VulnerableDriverBlocklistEnable = {0}', shown(h.driverBlocklist))],
    fix: { id: 'driver-blocklist-on' },
  });
}

// ---------------------------------------------------------------- Сеть

/** Виртуальный принтер (PDF, OneNote, факс) - не повод держать службу печати. */
const isVirtualPrinter = (p) => /^(PORTPROMPT:|nul:?|XPSPort:|SHRFAX:|FILE:|FOXIT_|Microsoft\.Office|OneNote|PDF)/i.test(String(p.port || '')) ||
  /pdf|xps|onenote|fax|факс|evernote|send to|snagit/i.test(String(p.name || ''));

function networkRules(f, h, out) {
  const llmnrOn = num(h.llmnr) !== 0;
  if (llmnrOn) {
    out.push({
      id: 'hard-llmnr-on', cat: CAT, sev: 'advice',
      title: t('Включён старый поиск имён в сети (LLMNR)'),
      text: t('Если компьютер не нашёл имя через обычный DNS, он спрашивает всю сеть. В кафе или гостинице чужой ноутбук может ответить «это я» и получить ваш пароль в зашифрованном виде для подбора.'),
      evidence: [tx('EnableMulticast: {0}', shown(h.llmnr))],
      fix: { id: 'llmnr-off' },
    });
  }
  const nodeP = num(h.netbiosNodeType) === 2;
  const nb = nodeP ? [] : arr(h.netbios).filter((a) => a && num(a.option) != null && num(a.option) !== 2);
  if (nb.length) {
    out.push({
      id: 'hard-netbios-on', cat: CAT, sev: 'advice',
      title: t('Включён NetBIOS - ещё один старый поиск имён'),
      text: t('NetBIOS работает так же, как LLMNR: компьютер спрашивает имена у всей сети, и ответить может кто угодно. Дома он почти никогда не нужен.'),
      evidence: nb.map((a) => tx('{0}: {1}', a.name, num(a.option) === 1 ? t('включён') : t('по настройке роутера (обычно включён)'))),
      guide: 'hard-netbios',
    });
  }
  const w = h.wpad || {};
  if (w.autoDetect === true && num(w.serviceStart) !== 4 && (llmnrOn || nb.length)) {
    out.push({
      id: 'hard-wpad', cat: CAT, sev: 'advice',
      title: t('Компьютер сам ищет прокси-сервер в сети (WPAD)'),
      text: t('Включено «Определять параметры автоматически». Вместе с LLMNR и NetBIOS это позволяет чужому устройству в сети назваться прокси и видеть, куда вы ходите. Если на работе прокси не нужен, это можно выключить.'),
      evidence: [t('Прокси: определять параметры автоматически - включено')],
      guide: 'hard-wpad',
    });
  }
  if (!llmnrOn && !nb.length) out.push(ok('hard-name-spoofing-ok', t('Старые способы поиска имён в сети выключены'), t('LLMNR и NetBIOS выключены - чужое устройство не сможет выдать себя за другой компьютер.')));

  const sg = h.smbSigning || {};
  const eff = (v, reg) => (typeof v === 'boolean' ? v : num(reg) === 1 ? true : num(reg) === 0 ? false : null);
  const server = eff(sg.server, sg.serverReg);
  const client = eff(sg.client, sg.clientReg);
  if (server === false || client === false) {
    out.push({
      id: 'hard-smb-signing', cat: CAT, sev: 'advice',
      title: t('Обмен файлами по сети не требует подписи'),
      text: t('Подпись SMB не даёт чужому устройству в сети незаметно подменить файлы или перехватить вход в сетевую папку. Старые сетевые хранилища и принтеры могут её не поддерживать, поэтому программа меняет это только по инструкции.'),
      evidence: [
        ...(client === false ? [t('Подключение к чужим папкам: подпись не обязательна')] : []),
        ...(server === false ? [t('Общие папки этого компьютера: подпись не обязательна')] : []),
      ],
      guide: 'hard-smb-signing',
    });
  }

  const svc = h.services || {};
  const winrm = svc.WinRM;
  if (winrm && winrm.status === 'Running' && num(h.winrmListeners) > 0) {
    out.push({
      id: 'hard-winrm-on', cat: CAT, sev: 'advice',
      title: t('Включено удалённое управление Windows (WinRM)'),
      text: t('Через WinRM можно выполнять команды на этом компьютере по сети, зная пароль администратора. Дома это почти никогда не нужно. Если компьютер рабочий, его могли включить специально - спросите администратора.'),
      evidence: [tx('Служба WinRM работает, точек подключения: {0}', num(h.winrmListeners))],
      guide: 'hard-winrm',
    });
  }
  const ra = h.remoteAssistance || {};
  const raPolicy = num(ra.policy);
  if (raPolicy === 1 || (raPolicy == null && num(ra.allow) === 1)) {
    out.push({
      id: 'hard-remote-assistance-on', cat: CAT, sev: 'advice',
      title: t('Разрешён «Удалённый помощник» Windows'),
      text: t('По приглашению с этого компьютера другой человек может увидеть ваш экран и управлять им. Мошенники «из службы поддержки» часто просят именно это. Если вы им не пользуетесь, лучше выключить.'),
      evidence: [raPolicy === 1 ? t('Разрешено групповой политикой') : t('Приглашения удалённому помощнику: разрешены')],
      ...(raPolicy === 1 ? {} : { fix: { id: 'remote-assistance-off' } }),
    });
  }
  const rr = svc.RemoteRegistry;
  if (rr && (rr.status === 'Running' || rr.start === 'Automatic')) {
    out.push({
      id: 'hard-remote-registry-on', cat: CAT, sev: 'advice',
      title: t('Работает служба «Удалённый реестр»'),
      text: t('Она позволяет читать и менять настройки этого компьютера по сети. В Windows она обычно выключена. Если её не включал администратор, лучше выключить.'),
      evidence: [tx('Служба RemoteRegistry: {0}, запуск: {1}', rr.status, rr.start)],
      guide: 'hard-remote-registry',
    });
  }
  const sp = svc.Spooler;
  const realPrinters = arr(h.printers).filter((p) => p && !isVirtualPrinter(p));
  if (sp && sp.status === 'Running' && !realPrinters.length) {
    out.push({
      id: 'hard-spooler-idle', cat: CAT, sev: 'advice',
      title: t('Служба печати работает, а принтера нет'),
      text: t('Через службу печати не раз заражали компьютеры (например, уязвимость PrintNightmare). Если вы не печатаете, её можно выключить. Тогда перестанет работать и «Печать в PDF».'),
      evidence: [tx('Принтеры: {0}', arr(h.printers).map((p) => p.name).join(', ') || t('нет'))],
      guide: 'hard-spooler',
    });
  }
}

// ---------------------------------------------------------------- Устаревшие лазейки

function legacyRules(f, h, out) {
  const ps2 = h.ps2 && h.ps2.engine;
  if (ps2 && /^2\./.test(String(ps2))) {
    out.push({
      id: 'hard-ps2', cat: CAT, sev: 'advice',
      title: t('Установлен старый PowerShell 2.0'),
      text: t('Взломщики запускают свои команды через старый PowerShell 2.0: он не умеет показывать их антивирусу. Нужен он только очень старым сценариям.'),
      evidence: [tx('Версия движка: {0}', ps2)],
      fix: { id: 'ps2-off' },
    });
  }
  const ep = h.execPolicy || {};
  const machine = ep.machinePolicy || ep.machine;
  if (/^(unrestricted|bypass)$/i.test(String(machine || ''))) {
    out.push({
      id: 'hard-execpolicy', cat: CAT, sev: 'advice',
      title: t('PowerShell запускает любые сценарии без проверки'),
      text: t('Политика выполнения PowerShell для всего компьютера разрешает всё. Это не главная защита, но с ней случайно открытый вредоносный сценарий запустится без вопросов.'),
      evidence: [ep.machinePolicy ? tx('Политика выполнения: {0} (групповая политика)', machine) : tx('Политика выполнения: {0}', machine)],
      guide: 'hard-execpolicy',
    });
  }
  const a = h.autorun || {};
  const autorunOff = [a.machineDriveTypes, a.userDriveTypes].some((v) => num(v) === 255) || [a.machineNoAutorun, a.userNoAutorun].some((v) => num(v) === 1);
  if (!autorunOff) {
    out.push({
      id: 'hard-autorun', cat: CAT, sev: 'advice',
      title: t('Автозапуск с флешек и дисков не выключен полностью'),
      text: t('Когда вы вставляете флешку или диск, Windows может предложить запустить с него программу. Так распространяются вирусы с чужих флешек. Безопаснее открывать диски самому в Проводнике.'),
      evidence: [tx('NoDriveTypeAutoRun: {0}', shown(a.machineDriveTypes ?? a.userDriveTypes))],
      fix: { id: 'autorun-off' },
    });
  }
  const office = arr(h.office).filter(Boolean);
  if (office.length) {
    const allMacros = office.filter((o) => num(o.policyVbaWarnings ?? o.vbaWarnings) === 1);
    const internet = office.filter((o) => num(o.blockInternet) === 0);
    if (allMacros.length) {
      out.push({
        id: 'hard-office-macros-all', cat: CAT, sev: 'high',
        title: t('Office запускает все макросы без спроса'),
        text: t('Макрос - это программа внутри документа. Вирусы часто приходят в письмах как «счёт» или «договор» с макросом. Сейчас Office запустит такой макрос сразу при открытии файла.'),
        evidence: allMacros.map((o) => tx('{0}: включить все макросы', o.app)),
        guide: 'hard-office-macros',
      });
    }
    if (internet.length) {
      out.push({
        id: 'hard-office-macros-internet', cat: CAT, sev: 'advice',
        title: t('Office не блокирует макросы в файлах из интернета'),
        text: t('Обычно Office сам блокирует макросы в документах, скачанных из интернета или полученных по почте. Здесь эта защита выключена настройкой.'),
        evidence: internet.map((o) => tx('{0}: макросы из интернета не блокируются', o.app)),
        guide: 'hard-office-macros',
      });
    }
    if (!allMacros.length && !internet.length) out.push(ok('hard-office-macros-ok', t('Макросы Office под контролем'), t('Макросы в файлах из интернета блокируются, остальные - только с вашего согласия.')));
  }
}

function evaluate(facts, { now = Date.now() } = {}) { // eslint-disable-line no-unused-vars
  const f = facts || {};
  const h = f.hardening;
  if (!h || typeof h !== 'object') {
    return f.errors && f.errors.hardening ? [unknown('hard', t('Защита от взлома'), f.errors.hardening)] : [];
  }
  const out = [];
  credentialRules(f, h, out);
  coreIsolationRules(f, h, out);
  defenderExtraRules(f, h, out);
  smartScreenRules(f, h, out);
  driverBlocklistRules(f, h, out);
  networkRules(f, h, out);
  legacyRules(f, h, out);
  return out;
}

module.exports = { evaluate, SAFE_ASR, defenderIsActive, isVirtualPrinter };
