'use strict';
/**
 * Страж: следы атак и закрепления вредоносных программ по журналам Windows и «слепку» системы.
 * evaluate(facts, { now }) → находки того же вида, что в rules.js. Если нужного раздела в facts нет
 * (старый отчёт), - не больше одной находки «Не видно» или ничего.
 *
 * Сведения: facts.events (server/ps/sections/events.ps1) и facts.persistence (persistence.ps1).
 * «Критично» - только явные признаки взлома. Там, где бывает и законная причина (антивирус, VPN,
 * программа для разработки), - «Важно» или «Совет» со словом «проверьте».
 */
const { tx, t } = require('./i18n');
const { suspiciousReason, arr } = require('./rules');

const CAT = 'guard';
const NEED_ADMIN = t('Видно после полной проверки (кнопка «Проверить полностью»)');

// ---------------------------------------------------------------- Адреса

/** Адрес этого компьютера или «нет адреса» в журнале. */
function isLocalIp(ip) {
  const s = String(ip || '').trim();
  return !s || s === '-' || /^127\./.test(s) || s === '::1' || /^::ffff:127\./i.test(s);
}
/** Частная (домашняя, офисная) сеть, в том числе адреса VPN и CGNAT. */
function isPrivateIp(ip) {
  const s = String(ip || '').trim().replace(/^::ffff:/i, '').replace(/%.*$/, '');
  return isLocalIp(s)
    || /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(s)
    || /^(fe80:|fc|fd|fec0:)/i.test(s);
}

const when = (iso) => (iso ? String(iso).slice(0, 16).replace('T', ' ') : '');

// ---------------------------------------------------------------- Команды служб и заданий

const SCRIPT_HOST = /\b(mshta|wscript|cscript)(\.exe)?\b/i;
const SCROBJ = /\bregsvr32(\.exe)?["']?\s.*(scrobj|\/i:\s*["']?https?:)/i;
const HIDDEN_PS = /\b(powershell|pwsh)(\.exe)?["']?\s.*[-/](w|wi|win|window|windowstyle)\s+h(idden)?\b/i;
const ENC_PS = /\b(powershell|pwsh)(\.exe)?["']?\s.*[-/](e|ec|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{12,}/i;
const USER_DIR = /\\(Users|ProgramData)\\(?!Microsoft\\)/i;
const TEMP_DIR = /\\(AppData\\Local\\Temp|Windows\\Temp|Temp)\\/i;
const signedOk = (s) => !!s && s.status === 'Valid';
const msSigned = (s) => signedOk(s) && /Microsoft/i.test(s.subject || '');

/**
 * Чем подозрительна команда службы или задания: { sev: 'high'|'advice', why } или null.
 * file - путь к программе (после разбора), signer - подпись { status, subject }, если PowerShell её проверял.
 */
function commandRisk(cmd, file, signer) {
  const c = String(cmd || '');
  const p = String(file || '');
  if (msSigned(signer)) return null;
  const strong = suspiciousReason(c)
    || (ENC_PS.test(c) && t('PowerShell со скрытой (закодированной) командой'))
    || (HIDDEN_PS.test(c) && t('PowerShell запускается в скрытом окне'))
    || (SCROBJ.test(c) && t('regsvr32 загружает сценарий - так обходят защиту'))
    || (SCRIPT_HOST.test(c) && (USER_DIR.test(c) || /https?:/i.test(c)) && t('сценарий Windows запускается из папки пользователя или из интернета'));
  if (strong) {
    // Подписанный установщик во временной папке бывает и у честных программ.
    const onlyPlace = TEMP_DIR.test(c) && !/powershell|pwsh|mshta|regsvr32|wscript|cscript|https?:/i.test(c);
    return { sev: onlyPlace && signedOk(signer) ? 'advice' : 'high', why: strong };
  }
  if (SCRIPT_HOST.test(c)) return { sev: 'advice', why: t('запускает сценарий Windows (VBS или JS) - так часто прячутся вредоносные программы') };
  if (p && USER_DIR.test(p) && !signedOk(signer) && !(signer && signer.status === 'Missing')) {
    return { sev: 'advice', why: t('программа лежит в папке, куда может писать любая программа, и не подписана издателем') };
  }
  return null;
}

// ---------------------------------------------------------------- Журналы

const HANDLED_ACTIONS = new Set(['1', '2', '3', '10']); // очищено, карантин, удалено, заблокировано

/** Defender обезвредил угрозу (1117 - меры приняты; 1118/1119 - не удалось). */
function detectionHandled(d) {
  const ev = arr(d && d.events).map(Number);
  if (ev.includes(1118) || ev.includes(1119)) return false;
  return HANDLED_ACTIONS.has(String((d && d.actionId) || '')) || ev.includes(1117);
}

function rdpEnabled(f) {
  const r = f.rdp;
  if (!r || r.policyDeny === 1) return false;
  return r.deny === 0 || r.policyDeny === 0;
}

/** Неудачные входы по сети, сведённые по адресам (без входов с самого компьютера). */
function attackers(sec) {
  const by = new Map();
  for (const a of arr(sec && sec.failed)) {
    if (isLocalIp(a.ip)) continue;
    const x = by.get(a.ip) || { ip: a.ip, count: 0, users: new Set(), first: a.first, last: a.last };
    x.count += Number(a.count) || 0;
    if (a.user) x.users.add(a.user);
    if (a.first && (!x.first || a.first < x.first)) x.first = a.first;
    if (a.last && (!x.last || a.last > x.last)) x.last = a.last;
    by.set(a.ip, x);
  }
  return [...by.values()].sort((a, b) => b.count - a.count);
}

function securityRules(f, sec, out) {
  const hot = attackers(sec).filter((a) => a.count >= 10);
  if (hot.length) {
    const total = hot.reduce((s, a) => s + a.count, 0);
    const rdp = rdpEnabled(f);
    out.push({
      id: 'guard-bruteforce', cat: CAT, sev: hot[0].count >= 50 && rdp ? 'critical' : 'high',
      title: tx('Кто-то подбирает пароль: {0} неудачных входов по сети', total),
      text: rdp
        ? t('За 14 дней с этих адресов много раз пытались войти в компьютер, перебирая пароли. Удалённый рабочий стол включён - если он вам не нужен, выключите его. Если нужен: длинный пароль, вход только через VPN, не открывайте порт 3389 в роутере.')
        : t('За 14 дней с этих адресов много раз пытались войти в компьютер по сети, перебирая пароли. Проверьте, что у всех учётных записей длинные пароли, а общие папки и удалённый доступ открыты только тем, кому нужно. Если адрес из вашей сети - проверьте это устройство антивирусом.'),
      evidence: hot.slice(0, 10).map((a) => `${a.ip} - ${a.count} (${[...a.users].slice(0, 3).join(', ') || '?'}), ${when(a.first)} … ${when(a.last)}`)
        .concat(sec.failedTruncated ? [t('Попыток больше 5000 - показаны последние.')] : []),
      guide: 'password',
    });
  }

  const remote = arr(sec.remoteLogons);
  const outside = remote.filter((l) => !isPrivateIp(l.ip));
  const rdpLan = remote.filter((l) => isPrivateIp(l.ip) && !isLocalIp(l.ip) && Number(l.type) === 10);
  if (outside.length) {
    out.push({
      id: 'guard-logon-internet', cat: CAT, sev: 'high',
      title: tx('Входы в компьютер из интернета: {0}', outside.length),
      text: t('В компьютер успешно входили с адресов вне вашей сети. Если это были не вы (например, с работы через удалённый рабочий стол), срочно смените пароль этой учётной записи и выключите удалённый доступ.'),
      evidence: outside.slice(0, 10).map((l) => `${when(l.at)} ${l.user} ← ${l.ip}${Number(l.type) === 10 ? ' (RDP)' : ''}`),
      guide: 'password',
    });
  }
  if (rdpLan.length) {
    out.push({
      id: 'guard-logon-rdp', cat: CAT, sev: 'advice',
      title: tx('Входы через удалённый рабочий стол: {0}', rdpLan.length),
      text: t('В компьютер входили через удалённый рабочий стол из вашей сети. Если это были вы - всё в порядке.'),
      evidence: rdpLan.slice(0, 10).map((l) => `${when(l.at)} ${l.user} ← ${l.ip}`),
    });
  }

  if (arr(sec.usersCreated).length) {
    out.push({
      id: 'guard-user-created', cat: CAT, sev: 'high',
      title: t('Появилась новая учётная запись'),
      text: t('За 14 дней на компьютере создали пользователя. Если вы этого не делали, удалите эту учётную запись и смените пароль своей: так взломщики оставляют себе вход.'),
      evidence: arr(sec.usersCreated).slice(0, 10).map((u) => tx('{0}: «{1}», создал {2}', when(u.at), u.user, u.by || '?')),
      guide: 'admins',
    });
  }
  if (arr(sec.adminAdds).length) {
    out.push({
      id: 'guard-admin-added', cat: CAT, sev: 'high',
      title: t('Кому-то дали права администратора'),
      text: t('За 14 дней учётную запись добавили в администраторы. Если вы этого не делали, уберите её из администраторов и проверьте компьютер антивирусом.'),
      evidence: arr(sec.adminAdds).slice(0, 10).map((a) => tx('{0}: «{1}» → {2}, добавил {3}', when(a.at), a.member || a.sid, a.group, a.by || '?')),
      guide: 'admins',
    });
  }
}

function defenderRules(df, out) {
  const dets = arr(df.detections);
  const open = dets.filter((d) => !detectionHandled(d));
  const done = dets.filter(detectionHandled);
  const line = (d) => `${when(d.at)} ${d.threat || '?'} - ${d.path || ''}${d.action ? ` (${d.action})` : ''}`;
  if (open.length) {
    out.push({
      id: 'guard-threat-active', cat: CAT, sev: 'high',
      title: tx('Антивирус нашёл угрозы и не смог их обезвредить: {0}', open.length),
      text: t('Microsoft Defender нашёл вредоносные программы, но не удалил их. Откройте «Безопасность Windows» → «Журнал защиты», выберите угрозу и нажмите «Удалить» или «Карантин», затем запустите полную проверку.'),
      evidence: open.slice(0, 10).map(line),
    });
  }
  if (done.length) {
    out.push({
      id: 'guard-threat-handled', cat: CAT, sev: 'advice',
      title: tx('Антивирус обезвредил угроз: {0}', done.length),
      text: t('Microsoft Defender нашёл и обезвредил вредоносные программы - делать ничего не нужно. Если угрозы появляются снова, запустите полную проверку и подумайте, откуда они приходят (флешки, скачанные программы).'),
      evidence: done.slice(0, 10).map(line),
    });
  }
  if (arr(df.rtpDisabled).length) {
    out.push({
      id: 'guard-rtp-disabled', cat: CAT, sev: 'advice',
      title: t('Защиту в реальном времени выключали'),
      text: t('За 14 дней защиту Microsoft Defender в реальном времени выключали. Если это делали вы или вы ставили другой антивирус - всё в порядке. Иначе так поступают вредоносные программы: проверьте, что защита сейчас включена.'),
      evidence: arr(df.rtpDisabled).slice(0, 10).map((x) => when(x.at)),
    });
  }
}

function eventRules(f, out, hidden) {
  const ev = f.events;
  const sys = ev.system || {};
  const start = out.length;

  if (ev.security) securityRules(f, ev.security, out);
  else hidden.push(t('журнал безопасности: попытки входа, очистка журнала, новые пользователи и администраторы'));

  const cleared = arr(ev.security && ev.security.cleared).map((c) => ({ ...c, channel: 'Security' })).concat(arr(sys.cleared));
  if (cleared.length) {
    out.push({
      id: 'guard-log-cleared', cat: CAT, sev: 'high',
      title: t('Журналы Windows очищали'),
      text: t('Журнал событий очистили - так взломщики заметают следы. Если вы сами чистили журналы (например, программой очистки), всё в порядке. Иначе проверьте компьютер антивирусом и смените пароли.'),
      evidence: cleared.slice(0, 10).map((c) => `${when(c.at)} ${c.channel || ''} - ${c.user || '?'}`),
    });
  }

  // Службы, установленные за 14 дней: подозрительные - сразу, остальные видны в изменениях «слепка».
  let n = 0;
  for (const s of arr(sys.servicesInstalled)) {
    const risk = commandRisk(s.path, '', null);
    if (!risk || risk.sev !== 'high' || n++ >= 5) continue;
    out.push({
      id: `guard-service-installed-${s.name}`, cat: CAT, sev: 'high',
      title: tx('Установлена подозрительная служба: {0}', s.name),
      text: tx('За 14 дней в системе появилась служба: {0}. Если вы её не узнаёте, проверьте компьютер антивирусом.', s.why || risk.why),
      evidence: [s.path, when(s.at)].filter(Boolean),
    });
  }

  if (ev.defender) defenderRules(ev.defender, out);

  const psr = ev.powershell;
  if (psr && Number(psr.strong) > 0) {
    out.push({
      id: 'guard-powershell', cat: CAT, sev: 'advice',
      title: tx('Подозрительные команды PowerShell: {0}', psr.strong),
      text: t('Windows заметил команды PowerShell, которые скачивают и сразу запускают код из интернета. Так работают и вредоносные программы, и некоторые установщики. Если вы не запускали ничего такого, проверьте компьютер антивирусом.'),
      evidence: arr(psr.samples).slice(0, 5).map((s) => `${when(s.at)} ${s.path || ''} ${s.text || ''}`.trim()),
    });
  }

  if (!out.slice(start).some((x) => x.sev === 'critical' || x.sev === 'high')) {
    const errs = ev.errors || {};
    out.push({
      id: 'guard-events-ok', cat: CAT, sev: 'ok',
      title: tx('Следов взлома за {0} дней не найдено', ev.days || 14),
      text: ev.security
        ? t('Подбора паролей, входов из интернета, очистки журналов, новых пользователей и администраторов не было. Антивирус не нашёл необезвреженных угроз.')
        : t('В системном журнале и журнале антивируса тревожного нет. Попытки входа по сети и новые учётные записи записаны в журнале безопасности - он виден после полной проверки (кнопка «Проверить полностью»).'),
      evidence: Object.keys(errs).map((k) => `${k}: ${errs[k]}`),
    });
  }
}

// ---------------------------------------------------------------- Закрепление и перехват

/** Сертификаты программ для перехвата HTTPS (отладчики и известное рекламное ПО). */
const INTERCEPT_CERT = /fiddler|superfish|edellroot|privdog|komodia|mitmproxy|charles proxy|portswigger|burp|do_not_trust|httpdebugger|proxyman/i;
/** Антивирусы, которые проверяют HTTPS, сертификаты для разработки и госсертификат Минцифры - это нормально. */
const KNOWN_LOCAL_CERT = /kaspersky|eset|avast|\bavg\b|bitdefender|dr\.?web|norton|mcafee|sophos|trend micro|f-secure|malwarebytes|adguard|zscaler|netskope|CN=localhost\b|mkcert|IIS Express|ASP\.NET Core|Russian Trusted (Root|Sub) CA|Минцифр/i;

const cn = (subject) => {
  const m = /(?:^|,\s*)CN=("?)([^,"]+)\1/.exec(String(subject || ''));
  return m ? m[2] : String(subject || '');
};

/** Известные сайты: их подмена в hosts - признак фишинга. */
const KNOWN_SITES = ['google.com', 'google.ru', 'gstatic.com', 'googleapis.com', 'youtube.com', 'gmail.com', 'microsoft.com', 'microsoftonline.com', 'windowsupdate.com', 'windows.com', 'live.com', 'office.com', 'outlook.com', 'apple.com', 'icloud.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'telegram.org', 't.me', 'twitter.com', 'x.com', 'yandex.ru', 'yandex.com', 'ya.ru', 'vk.com', 'mail.ru', 'ok.ru', 'gosuslugi.ru', 'nalog.ru', 'nalog.gov.ru', 'mos.ru', 'sberbank.ru', 'sber.ru', 'tinkoff.ru', 'tbank.ru', 'vtb.ru', 'alfabank.ru', 'raiffeisen.ru', 'gazprombank.ru', 'pochtabank.ru', 'qiwi.com', 'paypal.com', 'amazon.com', 'github.com', 'steamcommunity.com', 'steampowered.com', 'avito.ru', 'ozon.ru', 'wildberries.ru', 'binance.com'];
/** Сайты антивирусов: их блокировка - признак вредоносной программы. */
const SECURITY_SITES = ['kaspersky.com', 'kaspersky.ru', 'drweb.com', 'drweb.ru', 'eset.com', 'esetnod32.ru', 'avast.com', 'avg.com', 'bitdefender.com', 'malwarebytes.com', 'virustotal.com', 'norton.com', 'mcafee.com', 'sophos.com', 'wdcp.microsoft.com', 'definitionupdates.microsoft.com'];
/** Адреса обновлений Windows: их блокируют «твикеры». */
const UPDATE_SITES = ['windowsupdate.com', 'update.microsoft.com', 'wustat.windows.com'];
const siteOf = (name, list) => list.find((d) => name === d || String(name).endsWith('.' + d));
const isBlockIp = (ip) => /^(0\.0\.0\.0|127\.|::1?$)/.test(String(ip || ''));

const RISKY_EXCL_PATH = /^[a-z]:\\?$|^%?(temp|tmp|appdata|localappdata|userprofile|public|programdata)%?(\\|$)|\\(temp|tmp)\\?$|\\appdata(\\(local|roaming|locallow))?\\?$|\\appdata\\local\\temp|\\(downloads|загрузки|desktop|рабочий стол)\\?$|\\users\\public|^[a-z]:\\users(\\[^\\]+)?\\?$|^[a-z]:\\programdata\\?$|^[a-z]:\\windows(\\system32)?\\?$/i;
const RISKY_EXCL_PROC = /(^|\\)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|explorer|svchost|msiexec|conhost)(\.exe)?$/i;
const RISKY_EXCL_EXT = /^\.?(exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|scr|com|msi|lnk|pif|jar|cpl)$/i;

/** Опасные исключения антивируса (строки для показа). */
function riskyExclusions(ex) {
  if (!ex) return [];
  return [
    ...arr(ex.paths).filter((x) => RISKY_EXCL_PATH.test(String(x).trim())).map((x) => tx('папка: {0}', x)),
    ...arr(ex.processes).filter((x) => RISKY_EXCL_PROC.test(String(x).trim())).map((x) => tx('программа: {0}', x)),
    ...arr(ex.extensions).filter((x) => RISKY_EXCL_EXT.test(String(x).trim())).map((x) => tx('тип файлов: {0}', x)),
  ];
}

function serviceTaskRules(p, out) {
  let n = 0;
  for (const s of arr(p.services)) {
    const risk = commandRisk(s.path, s.file, s.signer);
    if (!risk || n++ >= 10) continue;
    out.push({
      id: `guard-service-${s.name}`, cat: CAT, sev: risk.sev,
      title: tx('Подозрительная служба: {0}', s.displayName || s.name),
      text: risk.sev === 'high'
        ? tx('Служба: {0}. Службы работают с правами системы - вредоносные программы любят так закрепляться. Если вы её не узнаёте, проверьте компьютер антивирусом.', risk.why)
        : tx('Служба: {0}. Скорее всего, это программа, которую вы ставили сами, - тогда всё в порядке. Если не узнаёте её, проверьте файл антивирусом.', risk.why),
      evidence: [s.path || s.file, s.company ? tx('Издатель по файлу: {0}', s.company) : t('Издатель не указан')].filter(Boolean),
    });
  }

  n = 0;
  for (const tk of arr(p.tasks)) {
    if (msSigned(tk.signer)) continue;
    const acts = arr(tk.actions).filter((a) => a && !/^COM /.test(a.exe || ''));
    let risk = null;
    acts.some((a, i) => (risk = commandRisk(`${a.exe} ${a.args || ''}`, i === 0 ? String(a.exe || '').replace(/^"|"$/g, '') : '', i === 0 ? tk.signer : null)));
    if (!risk || n++ >= 10) continue;
    out.push({
      id: `guard-task-${tk.path}`, cat: CAT, sev: risk.sev,
      title: tx('Подозрительное задание планировщика: {0}', tk.name),
      text: risk.sev === 'high'
        ? tx('Задание: {0}. Задания планировщика запускают программы сами, без вашего ведома, - так часто закрепляются вредоносные программы. Если вы его не узнаёте, отключите его в «Планировщике заданий» и проверьте компьютер антивирусом.', risk.why)
        : tx('Задание: {0}. Скорее всего, это программа, которую вы ставили сами, - тогда всё в порядке. Если не узнаёте его, проверьте файл антивирусом.', risk.why),
      evidence: [tk.path, ...acts.slice(0, 2).map((a) => `${a.exe} ${a.args || ''}`.trim()), tk.author ? tx('Автор: {0}', tk.author) : ''].filter(Boolean),
    });
  }
}

function trafficRules(p, out) {
  const certs = arr(p.rootCerts);
  const flagged = certs.filter((c) => {
    const s = `${c.subject} ${c.issuer || ''}`;
    return INTERCEPT_CERT.test(s) || (c.store === 'CurrentUser' && !KNOWN_LOCAL_CERT.test(s));
  });
  if (flagged.length) {
    out.push({
      id: 'guard-rootcert', cat: CAT, sev: 'high',
      title: tx('Необычные корневые сертификаты: {0}', flagged.length),
      text: t('Корневой сертификат позволяет его владельцу читать ваш зашифрованный трафик (сайты банков, почту). Такие ставят программы-отладчики, рекламное ПО и вредоносные программы, иногда - антивирус или прокси на работе. Проверьте: если вы не ставили такую программу, удалите сертификат (Win+R → certmgr.msc → «Доверенные корневые центры сертификации»).'),
      evidence: flagged.slice(0, 10).map((c) => tx('{0} ({1}), {2}', cn(c.subject), c.store === 'CurrentUser' ? t('только для вашей учётной записи') : t('для всего компьютера'), c.thumbprint)),
    });
  }

  const entries = arr(p.hosts && p.hosts.entries);
  const redirect = entries.filter((e) => !isBlockIp(e.ip) && siteOf(e.name, KNOWN_SITES.concat(SECURITY_SITES)));
  const blockedSec = entries.filter((e) => isBlockIp(e.ip) && siteOf(e.name, SECURITY_SITES));
  const blockedUpd = entries.filter((e) => isBlockIp(e.ip) && siteOf(e.name, UPDATE_SITES));
  if (redirect.length || blockedSec.length) {
    out.push({
      id: 'guard-hosts-redirect', cat: CAT, sev: 'high',
      title: t('Файл hosts подменяет известные сайты'),
      text: redirect.length
        ? t('В файле hosts известный сайт направлен на чужой адрес: вы можете попасть на поддельную страницу банка или почты. Если вы не вносили эту запись сами, удалите её из файла C:\\Windows\\System32\\drivers\\etc\\hosts и проверьте компьютер антивирусом.')
        : t('В файле hosts заблокированы сайты антивирусов - так поступают вредоносные программы, чтобы антивирус не обновлялся. Если вы не вносили эти записи сами, удалите их и проверьте компьютер антивирусом.'),
      evidence: redirect.concat(blockedSec).slice(0, 10).map((e) => `${e.ip} ${e.name}`),
    });
  }
  if (blockedUpd.length) {
    out.push({
      id: 'guard-hosts-updates', cat: CAT, sev: 'advice',
      title: t('Файл hosts блокирует обновления Windows'),
      text: t('В файле hosts заблокированы адреса обновлений Windows - так делают «твикеры» и некоторые сборки Windows. Без обновлений компьютер уязвим. Если вы не делали этого нарочно, удалите эти строки.'),
      evidence: blockedUpd.slice(0, 10).map((e) => `${e.ip} ${e.name}`),
    });
  }

  const px = p.proxy;
  const ev = [];
  if (px && px.enabled && px.server) ev.push(tx('Прокси для браузеров: {0}', px.server));
  if (px && px.pac) ev.push(tx('Сценарий настройки прокси: {0}', px.pac));
  if (px && px.winhttp) ev.push(tx('Прокси для служб Windows: {0}', px.winhttp));
  if (ev.length) {
    const local = /(^|[\s=;/])(127\.|localhost|\[?::1\]?)/i.test(` ${px.enabled ? px.server : ''} ${px.winhttp || ''}`);
    out.push({
      id: 'guard-proxy', cat: CAT, sev: 'advice',
      title: t('Интернет идёт через прокси'),
      text: local
        ? t('Трафик направлен через программу на этом компьютере. Так работают VPN-клиенты, программы обхода блокировок, некоторые антивирусы и отладчики - тогда всё в порядке. Если вы ничего такого не ставили, выключите прокси: «Параметры» → «Сеть и Интернет» → «Прокси-сервер».')
        : t('Трафик направлен через посредника - он видит, какие сайты вы открываете. На работе так бывает нужно. Если вы прокси не настраивали, выключите его: «Параметры» → «Сеть и Интернет» → «Прокси-сервер».'),
      evidence: ev,
    });
  }
}

function persistenceRules(f, out, hidden) {
  const p = f.persistence;
  const start = out.length;
  serviceTaskRules(p, out);

  const w = p.wmi;
  if (!w || !w.visible) hidden.push(t('подписки WMI (скрытый автозапуск)'));
  else {
    const bad = arr(w.consumers).filter((c) => /^(CommandLineEventConsumer|ActiveScriptEventConsumer)$/.test(c.type));
    if (bad.length) {
      out.push({
        id: 'guard-wmi-consumer', cat: CAT, sev: 'high',
        title: tx('Скрытый автозапуск через WMI: {0}', bad.length),
        text: t('В Windows настроена подписка WMI, которая сама запускает команду или сценарий. Обычные программы так почти не делают, а вредоносные - часто: этого не видно в автозагрузке. Проверьте, что это за команда. Если не знаете - покажите специалисту и проверьте компьютер антивирусом.'),
        evidence: bad.slice(0, 5).map((c) => `${c.name}: ${c.command || c.type}`),
      });
    }
  }

  trafficRules(p, out);

  const ex = p.exclusions;
  if (!ex || !ex.visible) hidden.push(t('исключения антивируса Microsoft Defender'));
  const exList = riskyExclusions(ex);
  if (exList.length) {
    out.push({
      id: 'guard-exclusion-risky', cat: CAT, sev: 'high',
      title: t('Антивирус не проверяет опасные места'),
      text: t('В исключениях Microsoft Defender - целый диск, временные или пользовательские папки, системные программы или исполняемые файлы. Вредоносные программы добавляют такие исключения, чтобы антивирус их не видел. Если вы не добавляли их сами, удалите: «Безопасность Windows» → «Защита от вирусов и угроз» → «Управление настройками» → «Исключения».'),
      evidence: exList.slice(0, 10),
    });
  }

  if (!out.slice(start).some((x) => x.sev === 'critical' || x.sev === 'high')) {
    out.push({
      id: 'guard-persistence-ok', cat: CAT, sev: 'ok',
      title: t('Скрытого автозапуска и перехвата трафика не найдено'),
      text: tx('Проверено служб не от Microsoft: {0}, заданий планировщика: {1}, корневых сертификатов: {2}, а также файл hosts и подписки WMI.', arr(p.services).length, arr(p.tasks).length, arr(p.rootCerts).length),
      evidence: [],
    });
  }
}

// ---------------------------------------------------------------- Вместе

function evaluate(facts, { now = Date.now() } = {}) { // eslint-disable-line no-unused-vars
  const f = facts || {};
  const out = [];
  if (!f.events && !f.persistence) {
    const errors = f.errors || {};
    const why = errors.events || errors.persistence;
    if (why) out.push({ id: 'guard-unknown', cat: CAT, sev: 'unknown', title: t('Страж: журналы и скрытый автозапуск'), text: tx('Не удалось проверить: {0}', why), evidence: [] });
    return out;
  }
  const hidden = [];
  if (f.events) eventRules(f, out, hidden);
  if (f.persistence) persistenceRules(f, out, hidden);
  if (hidden.length && !f.isAdmin) {
    out.push({ id: 'guard-admin-unknown', cat: CAT, sev: 'unknown', title: t('Страж: часть сведений видна только администратору'), text: NEED_ADMIN, evidence: hidden });
  }
  return out;
}

module.exports = { evaluate, commandRisk, isLocalIp, isPrivateIp, attackers, detectionHandled, riskyExclusions, KNOWN_SITES };
