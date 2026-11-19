'use strict';
/**
 * Страж: «слепок» системы и что изменилось без вашего ведома.
 *
 *   snapshot(facts) → { at, admin, kinds: { [kind]: { [key]: label } | null }, hidden: [kind] }
 *     kind = null - в этой проверке не видно (нужны права администратора, раздел не собрался):
 *     diff такие виды пропускает, а update сохраняет для них прежний слепок.
 *   diff(prev, cur) → [{ kind, change: 'added'|'removed'|'changed', key, label, from, to, sev: 'high'|'advice'|'info' }]
 *   createGuard(store, { now }) → { update(facts), log({ days }), acknowledge(ids), weekly({ days }) }
 *
 * Файлы в папке данных: guard-baseline.json (слепок + последние сводки журналов), guard-log.json (изменения,
 * не больше 1000, новые первыми). Работает только во время проверки - фоновой нагрузки нет.
 */
const crypto = require('node:crypto');
const { tx, t } = require('./i18n');
const { parseBcdFirmware } = require('./bcd');
const { arr, isLoopback, DAY } = require('./rules');
const { isLocalIp, isPrivateIp, detectionHandled } = require('./rules-guard');

const BASELINE = 'guard-baseline.json';
const LOG = 'guard-log.json';
const LOG_MAX = 1000;

const KINDS = ['autostart', 'services', 'tasks', 'wmi', 'rootCerts', 'hosts', 'dns', 'proxy', 'exclusions', 'admins', 'ports', 'usb', 'bootOrder', 'secureBoot', 'firewall'];

const cut = (s, n = 200) => {
  const v = String(s == null ? '' : s).replace(/\s+/g, ' ').trim();
  return v.length > n ? v.slice(0, n) + '…' : v;
};
const cn = (subject) => {
  const m = /(?:^|,\s*)CN=("?)([^,"]+)\1/.exec(String(subject || ''));
  return m ? m[2] : String(subject || '');
};

// ---------------------------------------------------------------- Слепок

/** Раздел собрался без ошибки? */
const seen = (f, sec) => !!f[sec] && !(f.errors && f.errors[sec]);
const subOk = (p, part) => !!p && !(p.errors && p.errors[part]);

function build(f) {
  const p = seen(f, 'persistence') ? f.persistence : null;
  const k = {};

  k.autostart = seen(f, 'autostart') ? Object.fromEntries(arr(f.autostart.items).map((i) => [`${i.loc}|${i.name}`, cut(`${i.name}: ${i.command}`)])) : null;

  k.services = p && subOk(p, 'services') && p.services ? Object.fromEntries(arr(p.services).map((s) => [s.name, cut(`${s.displayName || s.name}: ${s.file || s.path || ''}`)])) : null;

  k.tasks = p && subOk(p, 'tasks') && p.tasks ? Object.fromEntries(arr(p.tasks).map((x) => {
    const a = arr(x.actions)[0];
    return [x.path, cut(`${x.name}: ${a ? `${a.exe} ${a.args || ''}` : ''}`)];
  })) : null;

  k.wmi = p && p.wmi && p.wmi.visible ? Object.fromEntries([
    ...arr(p.wmi.filters).map((x) => [`filter:${x.name}`, cut(`${x.name}: ${x.query}`)]),
    ...arr(p.wmi.consumers).map((x) => [`consumer:${x.type}:${x.name}`, cut(`${x.name} (${x.type})${x.command ? `: ${x.command}` : ''}`)]),
    ...arr(p.wmi.bindings).map((x) => [`binding:${x.filter}>${x.consumer}`, cut(`${x.filter} → ${x.consumer}`)]),
  ]) : null;

  k.rootCerts = p && subOk(p, 'rootCerts') && p.rootCerts ? Object.fromEntries(arr(p.rootCerts).map((c) => [`${c.store}:${c.thumbprint}`, cut(cn(c.subject))])) : null;

  k.hosts = p && subOk(p, 'hosts') && p.hosts ? Object.fromEntries(arr(p.hosts.entries).map((e) => [e.name, `${e.ip} ${e.name}`])) : null;

  k.dns = p && subOk(p, 'dns') && p.dns ? Object.fromEntries(arr(p.dns).map((d) => [d.name, `${d.name}: ${arr(d.servers).join(', ')}`])) : null;

  if (p && subOk(p, 'proxy') && p.proxy) {
    const x = p.proxy;
    k.proxy = {};
    if (x.enabled && x.server) k.proxy.ie = x.server;
    if (x.pac) k.proxy.pac = x.pac;
    if (x.winhttp) k.proxy.winhttp = x.winhttp;
  } else k.proxy = null;

  k.exclusions = p && p.exclusions && p.exclusions.visible ? Object.fromEntries([
    ...arr(p.exclusions.paths).map((v) => [`path:${String(v).toLowerCase()}`, String(v)]),
    ...arr(p.exclusions.processes).map((v) => [`process:${String(v).toLowerCase()}`, String(v)]),
    ...arr(p.exclusions.extensions).map((v) => [`ext:${String(v).toLowerCase()}`, String(v)]),
  ]) : null;

  k.admins = seen(f, 'accounts') && f.accounts.admins ? Object.fromEntries(arr(f.accounts.admins).map((a) => [a.sid || a.name, a.name || a.sid])) : null;

  if (seen(f, 'ports')) {
    // Только TCP и не динамические порты (до 49152): иначе каждый запуск программ даёт «новые» порты.
    k.ports = {};
    for (const x of arr(f.ports.tcp)) {
      if (isLoopback(String(x.addr || '')) || Number(x.port) >= 49152) continue;
      k.ports[`tcp:${x.port}`] = `${x.proc || '?'} (TCP ${x.port})`;
    }
  } else k.ports = null;

  const usb = f.physical && Array.isArray(f.physical.usb) ? f.physical.usb : null;
  k.usb = usb ? Object.fromEntries(usb.filter((u) => u && (u.serial || u.name)).map((u) => [String(u.serial || u.name), cut(u.name || u.serial)])) : null;

  const order = f.boot && f.boot.bcdFirmware ? parseBcdFirmware(f.boot.bcdFirmware) : [];
  k.bootOrder = order.length ? { order: cut(order.map((o) => o.description).join(' → '), 400) } : null;

  const sb = f.boot ? f.boot.secureBoot : null;
  k.secureBoot = sb == null ? null : { state: Number(sb) === 1 ? t('включена') : t('выключена') };

  k.firewall = seen(f, 'firewall') ? Object.fromEntries(arr(f.firewall.profiles).map((x) => [x.name, String(x.enabled) === 'True' ? t('включён') : t('выключен')])) : null;

  return k;
}

function snapshot(facts) {
  const f = facts || {};
  const kinds = build(f);
  return {
    at: f.collectedAt || new Date().toISOString(),
    admin: !!f.isAdmin,
    kinds,
    hidden: KINDS.filter((x) => kinds[x] == null),
  };
}

// ---------------------------------------------------------------- Сравнение

/** Известные удостоверяющие центры: их Windows добавляет сама при обновлении корневых сертификатов. */
const KNOWN_CA = /digicert|globalsign|sectigo|comodo|usertrust|isrg|let's encrypt|entrust|godaddy|go daddy|starfield|baltimore|verisign|thawte|geotrust|quovadis|microsoft|amazon|google trust|\bgts\b|certum|buypass|swisssign|actalis|identrust|aaa certificate|t-telesec|d-trust|telia|harica|ssl\.com|emsign|secom|security communication|xramp|trustwave|securetrust|affirmtrust|cybertrust|certigna|camerfirma|accv|izenpe|netlock|microsec|e-szigno|hongkong post|twca|chunghwa|globaltrust|atos|cfca|uca |tunrootca|naver|autoridad|firmaprofesional|ac raiz|symantec|network solutions|wosign|startcom|apple root|post\.ch|e-tugra|tubitak|sk id|ee certification|oiste|wisekey|trustcor|asseco|unizeto|kisa|gdca|vtrus|bjca|certainly|anf |hellenic|staat der nederlanden|government|minist|Russian Trusted/i;

/** Публичные DNS, которые выбирают сами (Google, Cloudflare, Quad9, Яндекс, OpenDNS, AdGuard…). */
const KNOWN_DNS = new Set(['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3', '9.9.9.9', '149.112.112.112', '9.9.9.10', '208.67.222.222', '208.67.220.220', '77.88.8.8', '77.88.8.1', '77.88.8.88', '77.88.8.2', '77.88.8.7', '77.88.8.3', '94.140.14.14', '94.140.15.15', '94.140.14.15', '94.140.15.16', '76.76.2.0', '76.76.10.0', '185.228.168.9', '185.228.169.9', '64.6.64.6', '64.6.65.6']);
const KNOWN_DNS6 = /^(2001:4860:4860::|2606:4700:4700::|2620:fe::|2620:119:|2a02:6b8::feed|2a10:50c0::)/i;

function dnsSev(label) {
  const servers = String(label || '').split(': ').slice(1).join(': ').split(',').map((s) => s.trim()).filter(Boolean);
  if (!servers.length || servers.every((s) => isPrivateIp(s))) return 'info';
  if (servers.every((s) => isPrivateIp(s) || KNOWN_DNS.has(s) || KNOWN_DNS6.test(s))) return 'advice';
  return 'high';
}

function sevFor(kind, change, key, from, to) {
  if (change === 'removed') return 'info';
  switch (kind) {
    case 'admins': case 'proxy': case 'wmi': case 'exclusions':
      return 'high';
    case 'bootOrder': return change === 'changed' ? 'high' : 'info';
    case 'rootCerts':
      if (String(key).startsWith('CurrentUser:')) return 'high';
      return KNOWN_CA.test(String(to || '')) ? 'info' : 'high';
    case 'hosts': {
      const ip = String(to || '').split(/\s+/)[0];
      return /^(0\.0\.0\.0|127\.|::1?$)/.test(ip) ? 'advice' : 'high';
    }
    case 'dns': return dnsSev(to);
    case 'secureBoot': return to === t('выключена') ? 'high' : 'info';
    case 'firewall': return to === t('выключен') ? 'high' : 'info';
    case 'usb': return 'info';
    case 'ports': return change === 'added' ? 'advice' : 'info';
    default: return 'advice'; // autostart, services, tasks
  }
}

function diff(prev, cur) {
  const out = [];
  const a = (prev && prev.kinds) || {};
  const b = (cur && cur.kinds) || {};
  for (const kind of KINDS) {
    const x = a[kind];
    const y = b[kind];
    if (x == null || y == null) continue; // в одной из проверок этого не видно - не «исчезло» и не «появилось»
    for (const key of Object.keys(y)) {
      if (!Object.hasOwn(x, key)) out.push({ kind, change: 'added', key, label: y[key], from: null, to: y[key], sev: sevFor(kind, 'added', key, null, y[key]) });
      else if (x[key] !== y[key]) out.push({ kind, change: 'changed', key, label: y[key], from: x[key], to: y[key], sev: sevFor(kind, 'changed', key, x[key], y[key]) });
    }
    for (const key of Object.keys(x)) {
      if (!Object.hasOwn(y, key)) out.push({ kind, change: 'removed', key, label: x[key], from: x[key], to: null, sev: sevFor(kind, 'removed', key, x[key], null) });
    }
  }
  return out;
}

/**
 * Свои задания «Адаманта»: задания помощника администратора с ровно той командой, которую ставит установщик.
 * Вызывающий передаёт это только при проверенном помощнике (владелец, права, SHA-256, команда задания - helper.trust()).
 * Подменённое задание с тем же именем, но другой командой, сюда не подходит и остаётся обычным изменением.
 */
function ownTaskMatcher(paths, tasks) {
  const want = new Map(arr(tasks).map((x) => [`\\Adamant\\${x.name}`.toLowerCase(), cut(`${x.name}: ${paths.powershell} ${paths.taskArgs(x.mode)}`).toLowerCase()]));
  return (c) => !!c && c.kind === 'tasks' && c.change !== 'removed' && typeof c.to === 'string'
    && want.get(String(c.key).toLowerCase()) === c.to.toLowerCase();
}

/** Свой автозапуск: значение в HKCU\...\Run ровно с той командой, которую пишет «Работа в фоне». */
function ownAutorunMatcher(name, command) {
  const want = cut(`${name}: ${command}`).toLowerCase();
  return (c) => !!c && c.kind === 'autostart' && c.change !== 'removed' && String(c.key) === `HKCU-Run|${name}`
    && typeof c.to === 'string' && c.to.toLowerCase() === want;
}

/** Новый слепок; для видов, которых сейчас не видно, - прежний (чтобы не потерять базу). */
function carryForward(prev, cur) {
  const kinds = { ...cur.kinds };
  for (const kind of KINDS) if (kinds[kind] == null && prev && prev.kinds && prev.kinds[kind] != null) kinds[kind] = prev.kinds[kind];
  return { ...cur, kinds, hidden: KINDS.filter((x) => kinds[x] == null) };
}

// ---------------------------------------------------------------- Хранилище и неделя

function createGuard(store, { now = () => Date.now() } = {}) {
  const readBase = () => store.read(BASELINE, null);
  const readLog = () => {
    const l = store.read(LOG, []);
    return Array.isArray(l) ? l : [];
  };

  /** isOwn(change) - изменение сделал сам «Адамант» (задания проверенного помощника): сразу отмечено «это я». */
  function update(facts, { isOwn = null } = {}) {
    if (!facts || typeof facts !== 'object') return { first: false, changes: [] };
    const at = new Date(now()).toISOString();
    const cur = snapshot(facts);
    const base = readBase();
    const ev = facts.events && typeof facts.events === 'object' ? facts.events : null;
    // Журнал безопасности виден только при полной проверке - держим последнюю такую сводку (не старше 14 дней).
    let security = base && base.security;
    if (ev && ev.security) security = { at, data: ev.security };
    else if (security && now() - Date.parse(security.at) > 14 * DAY) security = null;
    const events = ev ? { at, data: { ...ev, security: undefined } } : (base && base.events) || null;

    if (!base || !base.snapshot) {
      store.write(BASELINE, { version: 1, created: at, updated: at, snapshot: cur, events, security });
      return { first: true, changes: [] };
    }
    const own = typeof isOwn === 'function' ? isOwn : () => false;
    const all = diff(base.snapshot, cur).map((c) => (own(c)
      ? { id: crypto.randomBytes(6).toString('hex'), at, ...c, sev: 'info', ack: true, ackAt: at, own: true }
      : { id: crypto.randomBytes(6).toString('hex'), at, ...c, ack: false }));
    // Записанные раньше (до установки помощника или в прежней версии) - тоже отмечаем.
    const old = readLog();
    let fixed = 0;
    for (const e of old) if (!e.ack && own(e)) { e.ack = true; e.ackAt = at; e.own = true; e.sev = 'info'; fixed += 1; }
    if (all.length || fixed) store.write(LOG, [...all, ...old].slice(0, LOG_MAX));
    const changes = all.filter((c) => !c.own);
    store.write(BASELINE, { ...base, version: 1, updated: at, snapshot: carryForward(base.snapshot, cur), events, security });
    return { first: false, changes };
  }

  function log({ days } = {}) {
    const from = days ? now() - days * DAY : -Infinity;
    return readLog().filter((e) => Date.parse(e.at) >= from).sort((x, y) => Date.parse(y.at) - Date.parse(x.at));
  }

  function acknowledge(ids) {
    const want = new Set(arr(ids).map(String));
    const l = readLog();
    let n = 0;
    const at = new Date(now()).toISOString();
    for (const e of l) if (want.has(e.id) && !e.ack) { e.ack = true; e.ackAt = at; n++; }
    if (n) store.write(LOG, l);
    return n;
  }

  function weekly({ days = 7 } = {}) {
    const to = now();
    const from = to - days * DAY;
    const base = readBase() || {};
    const sec = base.security && base.security.data;
    const ev = (base.events && base.events.data) || {};

    // Попытки входа по сети за период: по дням из сводки (дни - местные, как в журнале Windows).
    let attempts = null;
    let attackers = null;
    if (sec) {
      const fromDay = new Date(from).toISOString().slice(0, 10);
      attempts = 0;
      for (const [d, c] of Object.entries(sec.failedByDay || {})) if (d >= fromDay) attempts += Number(c) || 0;
      const ips = new Map();
      for (const a of arr(sec.failed)) {
        if (isLocalIp(a.ip) || !a.last || Date.parse(a.last) < from) continue;
        ips.set(a.ip, (ips.get(a.ip) || 0) + (Number(a.count) || 0));
      }
      attackers = [...ips.values()].filter((c) => c >= 10).length;
    }
    const dets = arr(ev.defender && ev.defender.detections).filter((d) => d.at && Date.parse(d.at) >= from);
    const detections = dets.length;
    const detectionsActive = dets.filter((d) => !detectionHandled(d)).length;
    const entries = log().filter((e) => Date.parse(e.at) >= from);
    const changes = entries.length;
    const unacknowledged = entries.filter((e) => !e.ack && e.sev !== 'info').length;
    // Угроза, которую антивирус уже обезвредил, не повод для тревоги: спокойствие нарушают только действующие.
    const calm = !attackers && (attempts == null || attempts < 10) && detectionsActive === 0 && unacknowledged === 0;

    let headline;
    if (calm && detections) {
      headline = tx('Неделя прошла спокойно: антивирус сам обезвредил угроз - {0}, тревожных изменений нет', detections);
    } else if (calm) {
      if (attempts == null) headline = changes ? t('Неделя прошла спокойно: угроз не было, тревожных изменений нет') : t('Неделя прошла спокойно: угроз не было, ничего не менялось');
      else if (attempts > 0) headline = tx('Неделя прошла спокойно: взлома не было (неудачных входов по сети: {0}), тревожных изменений нет', attempts);
      else headline = changes ? t('Неделя прошла спокойно: попыток взлома не было, тревожных изменений нет') : t('Неделя прошла спокойно: попыток взлома не было, ничего не менялось');
    } else if (attempts == null) {
      headline = tx('За неделю: угроз - {0}, незнакомых изменений - {1}. Посмотрите подробности.', detections, unacknowledged);
    } else {
      headline = tx('За неделю: неудачных входов по сети - {0}, угроз - {1}, незнакомых изменений - {2}. Посмотрите подробности.', attempts, detections, unacknowledged);
    }

    return {
      from: new Date(from).toISOString(), to: new Date(to).toISOString(),
      attempts, attackers, detections, detectionsActive, changes, unacknowledged, calm, headline,
      securityVisible: !!sec, lastCheck: base.updated || null,
    };
  }

  return { update, log, acknowledge, weekly };
}

module.exports = { snapshot, diff, createGuard, KINDS, sevFor, ownTaskMatcher, ownAutorunMatcher };
