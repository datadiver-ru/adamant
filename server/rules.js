'use strict';
/**
 * Правила: сведения о компьютере (collect.ps1) → находки.
 * Находка: { id, cat, sev, title, text, evidence[], fix?, alt?, guide? }
 *   sev: critical - «Критично», high - «Важно», advice - «Совет», unknown - «Не видно», ok - «В порядке».
 *   fix - исправление кнопкой ({ id, arg? }), guide - пошаговая инструкция (guides.js).
 * Тексты - на русском, через tx() (перевод - public/i18n-en.js).
 */
const { tx, t } = require('./i18n');
const { parseBcdFirmware } = require('./bcd');

const SEVERITIES = ['critical', 'high', 'advice', 'unknown', 'ok'];
const CATEGORIES = {
  windows: t('Защита Windows'),
  ports: t('Порты и службы'),
  accounts: t('Учётные записи'),
  autostart: t('Автозагрузка'),
  updates: t('Обновления'),
  boot: t('Шифрование и загрузка'),
  hardening: t('Защита от взлома'),
  physical: t('Физический доступ'),
  readiness: t('Готовность к беде'),
  privacy: t('Приватность'),
  guard: t('Страж'),
  network: t('Своя сеть'),
  browser: t('Браузеры'),
  downloads: t('Скачанные файлы'),
};

const arr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);
const DAY = 86_400_000;

/** Адрес слушает только этот компьютер? */
function isLoopback(addr) {
  return /^127\./.test(addr) || addr === '::1';
}
function isAnyAddr(addr) {
  return addr === '0.0.0.0' || addr === '::';
}

/** Опасные службы на этом компьютере, если они доступны из сети. */
const RISKY_LOCAL = {
  21: { name: 'FTP', sev: 'high', why: t('FTP передаёт пароли и файлы без шифрования.') },
  23: { name: 'Telnet', sev: 'critical', why: t('Telnet передаёт пароли открытым текстом и давно считается небезопасным.') },
  5900: { name: 'VNC', sev: 'high', why: t('VNC даёт управление экраном. Часто его защищает только короткий пароль.') },
  5901: { name: 'VNC', sev: 'high', why: t('VNC даёт управление экраном. Часто его защищает только короткий пароль.') },
  1433: { name: 'SQL Server', sev: 'high', why: t('База данных принимает подключения из сети.') },
  3306: { name: 'MySQL', sev: 'high', why: t('База данных принимает подключения из сети.') },
  5432: { name: 'PostgreSQL', sev: 'high', why: t('База данных принимает подключения из сети.') },
  6379: { name: 'Redis', sev: 'high', why: t('Redis по умолчанию работает без пароля.') },
  27017: { name: 'MongoDB', sev: 'high', why: t('MongoDB в старых настройках работает без пароля.') },
  9200: { name: 'Elasticsearch', sev: 'high', why: t('Elasticsearch по умолчанию отдаёт данные без пароля.') },
  11211: { name: 'Memcached', sev: 'high', why: t('Memcached работает без пароля.') },
  5985: { name: 'WinRM', sev: 'advice', why: t('Удалённое управление Windows (WinRM) включено.') },
  5986: { name: 'WinRM', sev: 'advice', why: t('Удалённое управление Windows (WinRM) включено.') },
};

/** Системные процессы Windows, которые обычно слушают порты. */
const SYSTEM_PROCS = new Set(['system', 'svchost', 'lsass', 'wininit', 'services', 'spoolsv', 'idle', 'searchindexer']);

function firewallState(f) {
  const profiles = arr(f.firewall && f.firewall.profiles);
  const nets = arr(f.firewall && f.firewall.networks);
  const catToProfile = { Public: 'Public', Private: 'Private', DomainAuthenticated: 'Domain' };
  const active = new Set(nets.map((n) => catToProfile[n.category]).filter(Boolean));
  const off = profiles.filter((p) => String(p.enabled) === 'False');
  return { profiles, nets, active, off, offActive: off.filter((p) => active.has(p.name)) };
}

// ---------------------------------------------------------------- Защита Windows

function firewallRules(f, out) {
  if (!f.firewall) return out.push(unknown('firewall', 'windows', t('Брандмауэр'), f.errors && f.errors.firewall));
  const fw = firewallState(f);
  const names = { Domain: t('доменная сеть'), Private: t('частная сеть'), Public: t('общедоступная сеть') };
  if (fw.off.length) {
    out.push({
      id: 'firewall-off', cat: 'windows', sev: fw.offActive.length ? 'critical' : 'high',
      title: t('Брандмауэр Windows выключен'),
      text: t('Брандмауэр не пускает к компьютеру чужие подключения из сети. Без него любая программа, которая слушает порт, доступна всем в сети: в кафе, в гостинице, у соседей по Wi-Fi.'),
      evidence: fw.off.map((p) => tx('Профиль «{0}» выключен', names[p.name] || p.name)),
      fix: { id: 'firewall-on' },
    });
  }
  const allowIn = fw.profiles.filter((p) => String(p.enabled) !== 'False' && p.inbound === 'Allow');
  if (allowIn.length) {
    out.push({
      id: 'firewall-allow-inbound', cat: 'windows', sev: 'high',
      title: t('Брандмауэр пропускает все входящие подключения'),
      text: t('Брандмауэр включён, но по умолчанию разрешает входящие подключения. Обычно они запрещены.'),
      evidence: allowIn.map((p) => tx('Профиль «{0}»: входящие разрешены', names[p.name] || p.name)),
      guide: 'firewall-inbound',
    });
  }
  if (!fw.off.length && !allowIn.length) {
    out.push(ok('firewall-ok', 'windows', t('Брандмауэр Windows включён'), t('Все профили сети защищены.')));
  }
  const publicHome = fw.nets.filter((n) => n.category === 'Private');
  if (publicHome.length) {
    out.push({
      id: 'network-private', cat: 'windows', sev: 'ok',
      title: t('Есть сеть с типом «Частная»'),
      text: t('В частной сети компьютер виден другим устройствам. Это нормально дома и в офисе, но не в общественном Wi-Fi.'),
      evidence: publicHome.map((n) => tx('{0} ({1})', n.name, n.alias)),
    });
  }
}

/** productState центра безопасности: биты 12-15 - включён ли антивирус. */
function avEnabled(state) {
  return ((Number(state) >> 12) & 0xf) === 1;
}

function defenderRules(f, out) {
  const d = f.defender;
  if (!d) return out.push(unknown('defender', 'windows', t('Антивирус'), f.errors && f.errors.defender));
  const others = arr(d.products).filter((p) => !/defender/i.test(p.name) && avEnabled(p.state));
  const s = d.status;
  if (!s) {
    if (others.length) return out.push(ok('av-other', 'windows', tx('Работает антивирус {0}', others.map((p) => p.name).join(', ')), t('Microsoft Defender уступил место другому антивирусу.')));
    return out.push(unknown('defender', 'windows', t('Антивирус'), d.statusError));
  }
  const passive = /passive|edr/i.test(s.mode || '');
  if ((!s.realTime || !s.antivirusEnabled) && !others.length) {
    out.push({
      id: 'defender-off', cat: 'windows', sev: 'critical',
      title: t('Защита от вирусов в реальном времени выключена'),
      text: t('Microsoft Defender сейчас не проверяет файлы при открытии и загрузке. Другого антивируса на компьютере не найдено.'),
      evidence: [tx('Защита в реальном времени: {0}', s.realTime ? t('включена') : t('выключена'))],
      fix: { id: 'defender-realtime' },
    });
  } else if (others.length && (passive || !s.realTime)) {
    out.push(ok('av-other', 'windows', tx('Работает антивирус {0}', others.map((p) => p.name).join(', ')), t('Microsoft Defender уступил место другому антивирусу.')));
  } else {
    out.push(ok('defender-ok', 'windows', t('Microsoft Defender работает'), t('Защита в реальном времени включена.')));
  }
  if (s.realTime && s.signatureAge > 7) {
    out.push({
      id: 'defender-signatures', cat: 'windows', sev: 'high',
      title: t('Базы антивируса устарели'),
      text: t('Антивирус не знает о новых вирусах, пока не обновит базы.'),
      evidence: [tx('Возраст баз: {0} дн.', s.signatureAge)],
      guide: 'defender-update',
    });
  }
  if (s.tamper === false && !others.length) {
    out.push({
      id: 'defender-tamper', cat: 'windows', sev: 'advice',
      title: t('Защита от подделки выключена'),
      text: t('Эта настройка не даёт вредоносным программам тихо выключить антивирус.'),
      evidence: [t('Защита от подделки: выключена')],
      guide: 'tamper',
    });
  }
}

function smbRules(f, out) {
  const s = f.smb;
  if (!s) return;
  const ev = [];
  if (s.server1 === true) ev.push(t('Сервер SMBv1 включён'));
  if (s.feature === 'Enabled') ev.push(t('Компонент «Поддержка SMB 1.0» установлен'));
  if (s.clientDriver && Number(s.clientStart) !== 4) ev.push(t('Клиент SMBv1 установлен'));
  if (ev.length) {
    out.push({
      id: 'smb1', cat: 'windows', sev: s.server1 === true ? 'high' : 'advice',
      title: t('Включён устаревший протокол SMBv1'),
      text: t('Через уязвимости SMBv1 распространялись вирусы-шифровальщики WannaCry и NotPetya. Современным устройствам он не нужен.'),
      evidence: ev,
      fix: { id: 'smb1-off' },
    });
  } else if (s.server1 === false) {
    out.push(ok('smb1-ok', 'windows', t('SMBv1 выключен'), t('Устаревший протокол общих папок не используется.')));
  }
  const shares = arr(s.shares);
  if (shares.length) {
    out.push({
      id: 'smb-shares', cat: 'windows', sev: 'advice',
      title: tx('Открыты общие папки: {0}', shares.length),
      text: t('Эти папки видны по сети. Проверьте, что доступ к ним есть только у тех, кому он нужен.'),
      evidence: shares.map((x) => tx('{0} → {1}', x.name, x.path)),
      guide: 'shares',
    });
  }
}

function rdpRules(f, out) {
  const r = f.rdp;
  if (!r) return;
  const deny = r.policyDeny != null ? Number(r.policyDeny) : Number(r.deny);
  const nla = r.policyNla != null ? Number(r.policyNla) : Number(r.nla);
  if (deny === 0) {
    const listening = arr(f.ports && f.ports.tcp).some((p) => p.port === Number(r.port || 3389) && !isLoopback(p.addr));
    const ev = [tx('Порт: {0}', r.port || 3389), listening ? t('Служба принимает подключения') : t('Служба сейчас не слушает порт')];
    if (nla === 0) {
      out.push({
        id: 'rdp-no-nla', cat: 'windows', sev: 'critical',
        title: t('Удалённый рабочий стол включён без проверки подлинности на уровне сети'),
        text: t('Без NLA экран входа Windows доступен любому по сети ещё до ввода пароля. Через такие подключения подбирают пароли и используют уязвимости.'),
        evidence: [...ev, t('NLA выключена')],
        fix: { id: 'rdp-nla' }, alt: [{ id: 'rdp-off', label: t('Или выключить удалённый рабочий стол') }],
      });
    } else {
      out.push({
        id: 'rdp-on', cat: 'windows', sev: 'advice',
        title: t('Удалённый рабочий стол включён'),
        text: t('К компьютеру можно подключиться по сети и управлять им. Если вы этим не пользуетесь, лучше выключить.'),
        evidence: [...ev, t('NLA включена')],
        fix: { id: 'rdp-off' },
      });
    }
  } else if (deny === 1) {
    out.push(ok('rdp-off', 'windows', t('Удалённый рабочий стол выключен'), t('Подключиться к компьютеру по RDP нельзя.')));
  }
}

function uacRules(f, out) {
  const u = f.uac;
  if (!u) return;
  const lua = u.enableLua == null ? 1 : Number(u.enableLua);
  if (lua === 0) {
    out.push({
      id: 'uac-off', cat: 'windows', sev: 'critical',
      title: t('Контроль учётных записей (UAC) выключен'),
      text: t('Любая программа сразу получает полные права администратора без вашего ведома.'),
      evidence: [t('EnableLUA = 0')],
      fix: { id: 'uac-on' },
    });
  } else if (Number(u.consentAdmin) === 0) {
    out.push({
      id: 'uac-silent', cat: 'windows', sev: 'high',
      title: t('UAC не спрашивает подтверждения у администратора'),
      text: t('Программы повышают свои права молча. Вы не увидите, что что-то получило права администратора.'),
      evidence: [t('ConsentPromptBehaviorAdmin = 0')],
      fix: { id: 'uac-on' },
    });
  } else if (u.secureDesktop != null && Number(u.secureDesktop) === 0) {
    out.push({
      id: 'uac-desktop', cat: 'windows', sev: 'advice',
      title: t('Запрос UAC показывается на обычном рабочем столе'),
      text: t('На защищённом рабочем столе другие программы не могут нажать «Да» за вас.'),
      evidence: [t('PromptOnSecureDesktop = 0')],
      fix: { id: 'uac-on' },
    });
  } else {
    out.push(ok('uac-ok', 'windows', t('Контроль учётных записей включён'), t('Windows спрашивает разрешение, прежде чем дать программе права администратора.')));
  }
}

// ---------------------------------------------------------------- Порты

function portRules(f, out) {
  const tcp = arr(f.ports && f.ports.tcp);
  if (!f.ports) return out.push(unknown('ports', 'ports', t('Открытые порты'), f.errors && f.errors.ports));
  const fw = firewallState(f);
  const exposed = tcp.filter((p) => !isLoopback(p.addr));
  const seen = new Set();
  for (const p of exposed) {
    const r = RISKY_LOCAL[p.port];
    if (!r || seen.has(p.port)) continue;
    seen.add(p.port);
    out.push({
      id: `port-${p.port}`, cat: 'ports', sev: r.sev,
      title: tx('Открыт порт {0} ({1})', p.port, r.name),
      text: r.why,
      evidence: [tx('Слушает {0}, адрес {1}', p.proc || tx('процесс {0}', p.pid), p.addr)],
      guide: 'local-service',
    });
  }
  if (fw.offActive.length || fw.off.length === fw.profiles.length) {
    const smb = exposed.filter((p) => p.port === 445 || p.port === 139);
    if (smb.length && fw.off.length) {
      out.push({
        id: 'port-smb-nofw', cat: 'ports', sev: 'high',
        title: t('Общие папки Windows доступны из сети без брандмауэра'),
        text: t('Порт 445 (SMB) принимает подключения со всех адресов, а брандмауэр выключен.'),
        evidence: [...new Set(smb.map((p) => p.port))].sort((a, b) => b - a).map((port) => tx('Порт {0}, адрес {1}', port, [...new Set(smb.filter((p) => p.port === port).map((p) => p.addr))].join(', '))),
        fix: { id: 'firewall-on' },
      });
    }
  }
  const apps = new Map();
  for (const p of exposed) {
    const name = (p.proc || '').toLowerCase();
    if (!name || SYSTEM_PROCS.has(name) || RISKY_LOCAL[p.port]) continue;
    if (!apps.has(p.proc)) apps.set(p.proc, []);
    apps.get(p.proc).push(p.port);
  }
  if (apps.size) {
    out.push({
      id: 'ports-apps', cat: 'ports', sev: fw.off.length ? 'advice' : 'ok',
      title: tx('Программы, которые принимают подключения из сети: {0}', apps.size),
      text: fw.off.length
        ? t('Брандмауэр выключен, поэтому эти программы доступны всем в сети. Проверьте, что вы их знаете.')
        : t('Кто может к ним подключиться, решает брандмауэр. Проверьте, что вы знаете эти программы.'),
      evidence: [...apps].map(([n, ports]) => tx('{0}: {1}', n, [...new Set(ports)].sort((a, b) => a - b).join(', '))),
    });
  }
  if (!seen.size) out.push(ok('ports-ok', 'ports', t('Опасных служб, открытых в сеть, нет'), tx('Портов, которые слушают подключения: {0}.', tcp.length)));
}

// ---------------------------------------------------------------- Учётные записи

function accountRules(f, out) {
  const a = f.accounts;
  if (!a) return out.push(unknown('accounts', 'accounts', t('Учётные записи'), f.errors && f.errors.accounts));
  const users = arr(a.users);
  const me = f.meta && f.meta.userSid;
  const guest = users.find((u) => /-501$/.test(u.sid));
  if (guest && guest.enabled) {
    out.push({
      id: 'guest-on', cat: 'accounts', sev: 'high',
      title: t('Включена гостевая учётная запись'),
      text: t('Под гостем можно войти без пароля, в том числе по сети.'),
      evidence: [tx('Учётная запись «{0}» включена', guest.name)],
      fix: { id: 'guest-off' },
    });
  }
  const builtin = users.find((u) => /-500$/.test(u.sid));
  if (builtin && builtin.enabled && builtin.sid !== me) {
    out.push({
      id: 'admin-builtin-on', cat: 'accounts', sev: 'advice',
      title: t('Включена встроенная учётная запись «Администратор»'),
      text: t('Её имя одинаково на всех компьютерах, а UAC для неё по умолчанию не спрашивает подтверждения. Обычно её держат выключенной.'),
      evidence: [tx('Учётная запись «{0}» включена', builtin.name)],
      fix: { id: 'admin-off', arg: { userSid: me } },
    });
  }
  const noPass = users.filter((u) => u.enabled && u.passwordRequired === false && !/-50[01]$/.test(u.sid) && !/^(WDAGUtility|DefaultAccount)/i.test(u.name));
  if (noPass.length) {
    out.push({
      id: 'password-not-required', cat: 'accounts', sev: 'high',
      title: t('Учётным записям разрешён пустой пароль'),
      text: t('Для этих учётных записей Windows не требует пароль. Если пароль пустой, войти может любой, кто сядет за компьютер.'),
      evidence: noPass.map((u) => tx('«{0}»', u.name)),
      guide: 'password',
    });
  }
  if (String(a.autoLogon) === '1' && a.autoLogonPasswordStored) {
    out.push({
      id: 'autologon-password', cat: 'accounts', sev: 'high',
      title: t('Пароль автоматического входа хранится в реестре открытым текстом'),
      text: t('Компьютер входит в Windows сам, а пароль записан в реестре так, что его может прочитать любая программа.'),
      evidence: [t('AutoAdminLogon = 1, DefaultPassword записан')],
      fix: { id: 'autologon-off' },
    });
  }
  const admins = arr(a.admins);
  const enabledLocal = new Map(users.map((u) => [u.sid, u.enabled]));
  const activeAdmins = admins.filter((m) => !enabledLocal.has(m.sid) || enabledLocal.get(m.sid));
  if (activeAdmins.length > 2) {
    out.push({
      id: 'admins-many', cat: 'accounts', sev: 'advice',
      title: tx('Администраторов на компьютере: {0}', activeAdmins.length),
      text: t('Каждая учётная запись администратора - ещё одна возможность получить полный доступ. Для повседневной работы лучше обычная учётная запись.'),
      evidence: activeAdmins.map((m) => m.name),
      guide: 'admins',
    });
  }
  if (!out.some((x) => x.cat === 'accounts' && x.sev !== 'ok')) {
    out.push(ok('accounts-ok', 'accounts', t('С учётными записями всё в порядке'), tx('Учётных записей: {0}, администраторов: {1}.', users.filter((u) => u.enabled).length, activeAdmins.length)));
  }
}

// ---------------------------------------------------------------- Автозагрузка

/** Признаки, по которым запись автозагрузки стоит проверить в первую очередь. */
function suspiciousReason(cmd) {
  const c = String(cmd || '');
  if (/\\(AppData\\Local\\Temp|Windows\\Temp)\\/i.test(c)) return t('запускается из временной папки');
  if (/\\Users\\Public\\/i.test(c)) return t('запускается из общей папки пользователей');
  if (/powershell(\.exe)?["']?\s.*-(e|en|enc|encodedcommand)\s/i.test(c)) return t('PowerShell со скрытой (закодированной) командой');
  if (/\b(mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?["']?\s.*(https?:|javascript:|vbscript:)/i.test(c)) return t('системная программа загружает код из интернета');
  if (/(https?:)\/\//i.test(c) && /\b(mshta|powershell|cmd)\b/i.test(c)) return t('команда обращается к адресу в интернете');
  return null;
}

function autostartRules(f, out) {
  const a = f.autostart;
  if (!a) return out.push(unknown('autostart', 'autostart', t('Автозагрузка'), f.errors && f.errors.autostart));
  const items = arr(a.items);
  const on = items.filter((i) => i.state !== 'off');
  for (const i of on) {
    const why = suspiciousReason(i.command);
    if (!why) continue;
    out.push({
      id: `autostart-suspicious-${i.loc}-${i.name}`, cat: 'autostart', sev: 'high',
      title: tx('Подозрительная запись автозагрузки: {0}', i.name),
      text: tx('Запись {0}. Так часто прописываются вредоносные программы. Если вы её не узнаёте, отключите и проверьте компьютер антивирусом.', why),
      evidence: [i.command],
      fix: canDisable(i) ? { id: 'autostart-off', arg: { loc: i.loc, name: i.name, userSid: a.userSid } } : undefined,
      guide: canDisable(i) ? undefined : 'autostart',
    });
  }
  out.push({
    id: 'autostart-list', cat: 'autostart', sev: on.length > 15 ? 'advice' : 'ok',
    title: tx('Программ в автозагрузке: {0}', on.length),
    text: on.length > 15
      ? t('Программ много: они замедляют запуск и каждая работает постоянно. Отключите те, что не нужны сразу после входа.')
      : t('Список программ, которые запускаются при входе в Windows. Отключить можно на вкладке «Автозагрузка».'),
    evidence: on.slice(0, 30).map((i) => i.name),
  });
}
/** Отключить через StartupApproved можно всё, кроме RunOnce. */
function canDisable(i) {
  return ['HKLM-Run', 'HKLM-Run32', 'HKCU-Run', 'Startup-User', 'Startup-Common'].includes(i.loc);
}

// ---------------------------------------------------------------- Обновления

function updateRules(f, out, now) {
  const u = f.updates;
  if (!u) return out.push(unknown('updates', 'updates', t('Обновления Windows'), f.errors && f.errors.updates));
  const dates = [u.lastUpdate, u.lastHotfix].map((d) => (d ? Date.parse(d) : NaN)).filter(Number.isFinite);
  const last = dates.length ? Math.max(...dates) : null;
  if (u.service === 'Disabled' || Number(u.noAutoUpdate) === 1) {
    out.push({
      id: 'updates-disabled', cat: 'updates', sev: 'critical',
      title: t('Обновления Windows отключены'),
      text: t('Без обновлений Windows не получает исправления уязвимостей. Через них заражают компьютеры автоматически.'),
      evidence: [u.service === 'Disabled' ? t('Служба «Центр обновления Windows» отключена') : null, Number(u.noAutoUpdate) === 1 ? t('Политика «Не обновлять автоматически» включена') : null].filter(Boolean),
      fix: { id: 'updates-on' },
    });
  }
  if (last == null) {
    out.push(unknown('updates-date', 'updates', t('Дата последнего обновления'), u.historyError || u.hotfixError));
  } else {
    const days = Math.floor((now - last) / DAY);
    const when = tx('Последнее обновление: {0} дн. назад', days);
    if (days > 90) out.push({ id: 'updates-old', cat: 'updates', sev: 'critical', title: t('Windows давно не обновлялась'), text: t('Больше трёх месяцев без исправлений безопасности.'), evidence: [when], guide: 'update' });
    else if (days > 40) out.push({ id: 'updates-old', cat: 'updates', sev: 'high', title: t('Windows давно не обновлялась'), text: t('Исправления безопасности выходят каждый месяц. Последние на компьютер не установлены.'), evidence: [when], guide: 'update' });
    else out.push(ok('updates-ok', 'updates', t('Windows обновляется'), when));
  }
  if (u.rebootRequired) {
    out.push({ id: 'updates-reboot', cat: 'updates', sev: 'advice', title: t('Обновления ждут перезагрузки'), text: t('Исправления скачаны, но заработают только после перезагрузки.'), evidence: [t('Windows ждёт перезагрузки')], guide: 'update' });
  }
}

// ---------------------------------------------------------------- Шифрование и загрузка

/** System.Volume.BitLockerProtection из проводника. */
const BL_SHELL = { 1: 'on', 2: 'off', 3: 'encrypting', 4: 'decrypting', 5: 'suspended', 6: 'on', 7: 'suspended', 8: 'waiting' };

function bitlockerRules(f, out) {
  const e = f.encryption;
  if (!e) return out.push(unknown('bitlocker', 'boot', t('Шифрование диска'), f.errors && f.errors.encryption));
  const sys = arr(e.drives).find((d) => d.system) || arr(e.drives)[0];
  const vol = sys && arr(e.volumes).find((v) => String(v.drive).toUpperCase() === String(sys.drive).toUpperCase());
  let state = sys ? BL_SHELL[sys.shellState] || (sys.shellState === 0 ? 'none' : null) : null;
  if (vol) state = vol.protection === 'On' ? 'on' : vol.status === 'EncryptionInProgress' ? 'encrypting' : vol.status === 'FullyEncrypted' ? 'suspended' : 'off';
  const drive = sys ? sys.drive : 'C:';
  if (state === 'on') return out.push(ok('bitlocker-ok', 'boot', tx('Диск {0} зашифрован BitLocker', drive), t('Если компьютер или диск украдут, данные не прочитать.')));
  if (state === 'encrypting') return out.push(ok('bitlocker-progress', 'boot', tx('Диск {0} шифруется', drive), t('BitLocker сейчас шифрует диск. Работать при этом можно.')));
  if (state === 'suspended' || state === 'waiting') {
    return out.push({ id: 'bitlocker-suspended', cat: 'boot', sev: 'high', title: tx('Защита BitLocker на диске {0} приостановлена', drive), text: t('Диск зашифрован, но ключ сейчас лежит открыто. Обычно защиту приостанавливают на время обновления BIOS - потом её нужно вернуть.'), evidence: [t('Защита приостановлена')], guide: 'bitlocker' });
  }
  if (state === 'off' || state === 'none') {
    return out.push({ id: 'bitlocker-off', cat: 'boot', sev: 'high', title: tx('Диск {0} не зашифрован', drive), text: t('Если компьютер украдут или вынут из него диск, все файлы, пароли браузера и почту можно прочитать без пароля Windows.'), evidence: [t('BitLocker выключен')], guide: 'bitlocker' });
  }
  out.push(unknown('bitlocker', 'boot', t('Шифрование диска'), t('Состояние BitLocker видно после полной проверки')));
}

function bootRules(f, out) {
  const b = f.boot;
  if (!b) return out.push(unknown('secureboot', 'boot', t('Безопасная загрузка'), f.errors && f.errors.boot));
  if (b.firmware === 'bios') {
    out.push({ id: 'legacy-bios', cat: 'boot', sev: 'high', title: t('Компьютер загружается в старом режиме BIOS'), text: t('В старом режиме нет безопасной загрузки (Secure Boot): вредоносная программа может встроиться в загрузку Windows до запуска антивируса.'), evidence: [t('Режим загрузки: BIOS (Legacy/CSM)')], guide: 'secureboot' });
  } else if (b.secureBoot === 1) {
    out.push(ok('secureboot-ok', 'boot', t('Безопасная загрузка (Secure Boot) включена'), t('Компьютер запускает только подписанный загрузчик.')));
  } else if (b.secureBoot === 0) {
    out.push({ id: 'secureboot-off', cat: 'boot', sev: 'high', title: t('Безопасная загрузка (Secure Boot) выключена'), text: t('Без неё вредоносная программа может подменить загрузчик и запускаться раньше Windows и антивируса.'), evidence: [t('Режим загрузки: UEFI'), t('Secure Boot: выключен')], guide: 'secureboot' });
  } else {
    out.push(unknown('secureboot', 'boot', t('Безопасная загрузка'), t('Windows не сообщает состояние Secure Boot')));
  }
  const tpmDev = arr(b.tpmDevices).find((d) => /tpm|доверенный платформенный|trusted platform/i.test(d.name));
  if (b.tpm && b.tpm.present === false) {
    out.push({ id: 'tpm-missing', cat: 'boot', sev: 'advice', title: t('Модуль TPM не найден'), text: t('TPM хранит ключи шифрования и нужен для BitLocker и Windows 11. Часто он есть, но выключен в настройках UEFI.'), evidence: [t('TPM не обнаружен')], guide: 'tpm' });
  } else if (b.tpm && b.tpm.ready === false) {
    out.push({ id: 'tpm-not-ready', cat: 'boot', sev: 'advice', title: t('Модуль TPM не готов к работе'), text: t('TPM есть, но Windows ещё не может им пользоваться.'), evidence: [t('TPM: не готов')], guide: 'tpm' });
  } else if (tpmDev || (b.tpm && b.tpm.present)) {
    const v = /2\.0/.test((tpmDev && tpmDev.name) || '') || /^2\.0/.test(b.tpmSpec || '') ? '2.0' : /1\.2/.test((tpmDev && tpmDev.name) || '') || /^1\.2/.test(b.tpmSpec || '') ? '1.2' : '';
    if (v === '1.2') out.push({ id: 'tpm-old', cat: 'boot', sev: 'advice', title: t('Модуль TPM старой версии 1.2'), text: t('Он работает, но для Windows 11 нужна версия 2.0. Иногда её можно включить в настройках UEFI.'), evidence: [tpmDev ? tpmDev.name : 'TPM 1.2'], guide: 'tpm' });
    else out.push(ok('tpm-ok', 'boot', tx('Модуль TPM {0} работает', v || ''), t('Ключи шифрования хранятся в отдельном защищённом чипе.')));
  } else {
    out.push({ id: 'tpm-missing', cat: 'boot', sev: 'advice', title: t('Модуль TPM не найден'), text: t('TPM хранит ключи шифрования и нужен для BitLocker и Windows 11. Часто он есть, но выключен в настройках UEFI.'), evidence: [t('Устройство TPM не найдено')], guide: 'tpm' });
  }
}

function firmwareRules(f, out, now) {
  const fw = f.firmware;
  if (!fw) return out.push(unknown('bios-password', 'boot', t('Пароль BIOS/UEFI'), f.errors && f.errors.firmware));
  const v = fw.vendor;
  if (v && v.admin === true) {
    out.push(ok('bios-password-ok', 'boot', t('Пароль администратора BIOS/UEFI установлен'), tx('Сведения производителя ({0}).', v.source)));
  } else if (v && v.admin === false) {
    out.push({ id: 'bios-password-none', cat: 'boot', sev: 'high', title: t('Пароль BIOS/UEFI не установлен'), text: t('Без пароля любой, кто сядет за компьютер, может выключить безопасную загрузку или загрузиться с флешки и обойти защиту Windows.'), evidence: [tx('Сведения производителя ({0}): пароль администратора не задан', v.source)], guide: 'bios-password' });
  } else if (Number(fw.adminPasswordStatus) === 1) {
    out.push(ok('bios-password-ok', 'boot', t('Пароль администратора BIOS/UEFI установлен'), t('Так сообщает прошивка компьютера.')));
  } else if (Number(fw.adminPasswordStatus) === 0) {
    out.push({ id: 'bios-password-none', cat: 'boot', sev: 'high', title: t('Пароль BIOS/UEFI не установлен'), text: t('Без пароля любой, кто сядет за компьютер, может выключить безопасную загрузку или загрузиться с флешки и обойти защиту Windows.'), evidence: [t('Прошивка сообщает: пароль администратора выключен')], guide: 'bios-password' });
  } else {
    out.push({ id: 'bios-password-unknown', cat: 'boot', sev: 'unknown', title: t('Установлен ли пароль BIOS/UEFI - из Windows не видно'), text: t('Прошивка этого компьютера не сообщает Windows о пароле. Проверьте сами по инструкции: это займёт пару минут.'), evidence: [tx('{0} {1}, BIOS {2}', fw.manufacturer, fw.model, fw.biosVersion)], guide: 'bios-password' });
  }
  const biosDate = fw.biosDate ? Date.parse(fw.biosDate) : NaN;
  if (Number.isFinite(biosDate)) {
    const years = (now - biosDate) / (365.25 * DAY);
    if (years > 3) {
      out.push({ id: 'bios-old', cat: 'boot', sev: 'advice', title: tx('Прошивке BIOS/UEFI больше {0} лет', Math.floor(years)), text: t('Производители исправляют в прошивках уязвимости процессора и загрузки. Проверьте, нет ли новой версии на сайте производителя.'), evidence: [tx('{0}, версия {1}, от {2}', fw.biosVendor, fw.biosVersion, new Date(biosDate).toISOString().slice(0, 10))], guide: 'bios-update' });
    }
  }
  bootOrderRules(f, out);
}

function bootOrderRules(f, out) {
  const raw = f.boot && f.boot.bcdFirmware;
  if (!raw) {
    out.push({ id: 'boot-order-unknown', cat: 'boot', sev: 'unknown', title: t('Порядок загрузки'), text: t('Windows показывает порядок загрузки только администратору. Нажмите «Проверить полностью».'), evidence: [], guide: 'boot-order' });
    return;
  }
  const order = parseBcdFirmware(raw);
  if (!order.length) return;
  const first = order[0];
  const ext = /usb|pxe|ipv4|ipv6|network|lan|сеть|cd|dvd|removable|флеш/i;
  if (ext.test(first.description) && !/windows boot manager|диспетчер загрузки windows/i.test(first.description)) {
    out.push({ id: 'boot-order-external', cat: 'boot', sev: 'advice', title: t('Первой в порядке загрузки стоит флешка или сеть'), text: t('Компьютер сначала пробует загрузиться с внешнего носителя или по сети. Так легче обойти защиту Windows. Поставьте первым диспетчер загрузки Windows.'), evidence: order.slice(0, 5).map((o, i) => tx('{0}. {1}', i + 1, o.description)), guide: 'boot-order' });
  } else {
    out.push(ok('boot-order-ok', 'boot', t('Порядок загрузки в порядке'), tx('Первым загружается: {0}', first.description)));
  }
}

// ---------------------------------------------------------------- Вспомогательные

function ok(id, cat, title, text) {
  return { id, cat, sev: 'ok', title, text, evidence: [] };
}
function unknown(id, cat, title, reason) {
  return { id: `${id}-unknown`, cat, sev: 'unknown', title, text: reason ? tx('Не удалось проверить: {0}', reason) : t('Не удалось проверить'), evidence: [] };
}

function sortFindings(list) {
  return list.slice().sort((a, b) => SEVERITIES.indexOf(a.sev) - SEVERITIES.indexOf(b.sev));
}

function summarize(list) {
  const s = Object.fromEntries(SEVERITIES.map((k) => [k, 0]));
  for (const f of list) s[f.sev]++;
  return s;
}

/** Все находки по компьютеру. */
function evaluate(facts, { now = Date.now() } = {}) {
  const f = facts || {};
  const out = [];
  firewallRules(f, out);
  defenderRules(f, out);
  smbRules(f, out);
  rdpRules(f, out);
  uacRules(f, out);
  portRules(f, out);
  accountRules(f, out);
  autostartRules(f, out);
  updateRules(f, out, now);
  bitlockerRules(f, out);
  bootRules(f, out);
  firmwareRules(f, out, now);
  // Дополнительные модули правил подключаются здесь (лениво - они сами берут ok/unknown из этого файла).
  for (const m of ['./rules-deep', './rules-ready', './rules-physical', './rules-guard', './rules-login', './rules-browser', './rules-downloads']) out.push(...require(m).evaluate(f, { now }));
  return sortFindings(out);
}

module.exports = { evaluate, summarize, sortFindings, SEVERITIES, CATEGORIES, suspiciousReason, avEnabled, isLoopback, isAnyAddr, arr, ok, unknown, DAY };
