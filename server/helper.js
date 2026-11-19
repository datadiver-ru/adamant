'use strict';
/**
 * Помощник администратора («Адамант Helper»): по желанию пользователя один раз ставится с разрешением UAC.
 * Дальше планировщик Windows от имени SYSTEM запускает защищённую копию сценариев из %ProgramFiles%\Adamant\Helper:
 *   - full     - раз в сутки и после включения: то, что видно только администратору → %ProgramData%\Adamant\helper\out\full.json;
 *   - security - сразу после неудачного входа, входа с клавиатуры или разблокировки → ...\out\security.json.
 * Сама программа прав администратора не получает: она только читает эти файлы.
 *
 * Доверие к ответам: папку ответов и файлы помощника проверяет helper-install.ps1 -Check (только чтение).
 * Владелец - администраторы или SYSTEM, писать не может никто другой, нет ссылок, задания запускают ровно то,
 * что ставили, файлы в Program Files совпадают со списком SHA-256. Иначе ответы не используются.
 */
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { t, tx } = require('./i18n');

/** Версия комплекта. Та же, что $H_Version в ps/helper/helper-run.ps1 и $HelperVersion в ps/helper-install.ps1. */
const HELPER_VERSION = 1;
/** Полная проверка помощника идёт раз в сутки: сведения старше 26 часов не используем. */
const FULL_MAX_AGE = 26 * 3600_000;
const SECURITY_MAX_AGE = 26 * 3600_000;
/** Как helper-run.ps1: полную проверку моложе 20 минут он не повторяет. */
const FRESH_SKIP_MS = 20 * 60_000;
const TRUST_CACHE_MS = 5 * 60_000;
const FUTURE_SLACK_MS = 5 * 60_000;
const MAX_FULL_BYTES = 16 * 1024 * 1024;
const MAX_SECURITY_BYTES = 4 * 1024 * 1024;

const ADMINS = 'S-1-5-32-544';
const SYSTEM = 'S-1-5-18';
const TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
const TRUSTED = new Set([ADMINS, SYSTEM, TRUSTED_INSTALLER]);
/** Права на изменение: запись, дозапись, атрибуты, удаление, смена прав и владельца, GENERIC_WRITE/GENERIC_ALL. Как $H_WriteMask. */
const WRITE_MASK = 0x500D0156;
const SID_RE = /^S-1-(5-21|12-1)(-\d{1,10}){4}$/;
const TASKS = [{ name: 'Adamant Helper', mode: 'full' }, { name: 'Adamant Helper Security', mode: 'security' }];
/** Задание должно идти от имени SYSTEM. Имя SYSTEM на разных языках Windows своё, поэтому ловим только обычные учётные записи (SID S-1-5-21-…, S-1-12-1-…). */
const USER_ACCOUNT_RE = /^S-1-(5-21|12-1)-/;

/**
 * Что помощник переносит в проверку без прав администратора: [раздел, ключ]. Тот же список - $H_Keep в helper-run.ps1.
 * Остальное у SYSTEM своё (HKCU, автозагрузка, Wi-Fi) и программе не подходит.
 */
const ADMIN_KEYS = [
  ['smb', 'feature'], ['encryption', 'volumes'], ['boot', 'tpm'], ['boot', 'tpmSpec'], ['boot', 'bcdFirmware'], ['firmware', 'vendor'],
  ['events', 'security'], ['physical', 'bitlocker'], ['physical', 'winre'], ['physical', 'presence'],
  ['readiness', 'restore'], ['persistence', 'exclusions'], ['persistence', 'wmi'],
];

const arr = (x) => (Array.isArray(x) ? x : []);
const isObj = (x) => x != null && typeof x === 'object' && !Array.isArray(x);
const toMs = (s) => {
  const v = typeof s === 'string' ? Date.parse(s) : NaN;
  return Number.isFinite(v) ? v : null;
};

function paths(env = process.env) {
  const pf = env.ProgramW6432 || env.ProgramFiles || 'C:\\Program Files';
  const pd = env.ProgramData || 'C:\\ProgramData';
  const root = env.SystemRoot || 'C:\\Windows';
  const programParent = path.win32.join(pf, 'Adamant');
  const program = path.win32.join(programParent, 'Helper');
  return {
    programParent, program,
    out: path.win32.join(pd, 'Adamant', 'helper', 'out'),
    powershell: path.win32.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    schtasks: path.win32.join(root, 'System32', 'schtasks.exe'),
    whoami: path.win32.join(root, 'System32', 'whoami.exe'),
    taskArgs: (mode) => `-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${path.win32.join(program, 'helper-run.ps1')}" -Mode ${mode}`,
  };
}

/** Состав комплекта - тот же, что копирует helper-install.ps1: имя в Program Files → файл программы. */
function payloadFiles(psDir, fs = nodeFs) {
  const list = [
    { name: 'helper-run.ps1', file: path.join(psDir, 'helper', 'helper-run.ps1') },
    { name: 'helper-uninstall.ps1', file: path.join(psDir, 'helper-uninstall.ps1') },
    { name: 'ps/collect.ps1', file: path.join(psDir, 'collect.ps1') },
  ];
  let sections = [];
  try { sections = fs.readdirSync(path.join(psDir, 'sections')).filter((n) => /^[a-z0-9-]+\.ps1$/i.test(n)); } catch { sections = []; }
  for (const n of sections.sort()) list.push({ name: `ps/sections/${n}`, file: path.join(psDir, 'sections', n) });
  return list;
}

function bundledHashes(psDir, fs = nodeFs) {
  const m = new Map();
  for (const p of payloadFiles(psDir, fs)) {
    try { m.set(p.name, crypto.createHash('sha256').update(fs.readFileSync(p.file)).digest('hex')); } catch { m.set(p.name, null); }
  }
  return m;
}

// ---------------------------------------------------------------- доверие

/** Что не так с файлом или папкой из отчёта -Check (или null). */
function aclProblem(d, what) {
  if (!d || !d.exists) return tx('{0}: нет', what);
  if (d.error) return tx('{0}: не удалось прочитать права ({1})', what, String(d.error).slice(0, 200));
  if (d.reparse) return tx('{0}: вместо папки или файла - ссылка', what);
  if (!TRUSTED.has(d.owner)) return tx('{0}: владелец - не администратор', what);
  for (const a of arr(d.acl)) {
    if (!a || !a.allow || TRUSTED.has(a.sid)) continue;
    if (((Number(a.rights) >>> 0) & WRITE_MASK) !== 0) return tx('{0}: менять может не только администратор ({1})', what, String(a.sid));
  }
  return null;
}

function sameText(a, b) {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

/**
 * Разбор ответа helper-install.ps1 -Check.
 * → { installed, version, outdated, trusted, problem, tasks, readerSid, filesChanged }
 */
function evaluate(check, { env = process.env, bundled = new Map() } = {}) {
  const P = paths(env);
  const res = { installed: false, version: null, bundledVersion: HELPER_VERSION, outdated: false, trusted: false, problem: null, tasks: [], readerSid: null };
  if (!isObj(check) || check.format !== 'adamant-helper-check') {
    res.problem = tx('Не удалось проверить помощника: {0}', (check && check.error) || t('неожиданный ответ'));
    return res;
  }
  const prog = check.program || {};
  const manifest = isObj(check.manifest) && check.manifest.format === 'adamant-helper' ? check.manifest : null;
  const tasks = arr(check.tasks);
  res.tasks = TASKS.map((x) => {
    const tk = tasks.find((y) => y && y.name === x.name) || { exists: null };
    return { name: x.name, mode: x.mode, exists: tk.exists ?? null, enabled: tk.enabled ?? null, lastRun: tk.lastRun || null, lastResult: tk.lastResult ?? null, nextRun: tk.nextRun || null };
  });
  res.installed = !!(manifest || (prog.dir && prog.dir.exists) || tasks.some((x) => x && x.exists === true));
  if (!res.installed) {
    res.problem = t('Помощник не установлен');
    return res;
  }
  res.version = manifest && Number.isInteger(manifest.version) ? manifest.version : null;
  res.readerSid = manifest && SID_RE.test(String(manifest.readerSid || '')) ? manifest.readerSid : null;

  // Устарел: другая версия или сценарии программы с тех пор изменились (обновление программы).
  const mfiles = new Map(arr(manifest && manifest.files).filter((f) => f && typeof f.name === 'string').map((f) => [f.name, String(f.sha256 || '').toLowerCase()]));
  if (res.version !== HELPER_VERSION) res.outdated = true;
  if (bundled.size) {
    if (mfiles.size !== bundled.size) res.outdated = true;
    for (const [n, h] of bundled) if (mfiles.get(n) !== h) res.outdated = true;
  }

  const problems = [];
  const add = (p) => { if (p) problems.push(p); };
  if (!manifest) add(check.manifestError ? tx('Описание помощника не читается: {0}', String(check.manifestError).slice(0, 200)) : t('Нет описания помощника (helper.json)'));
  add(aclProblem(prog.parent, P.programParent));
  add(aclProblem(prog.dir, P.program));
  // Каждый файл в Program Files: надёжные права и SHA-256 как при установке; лишних файлов нет.
  for (const f of arr(prog.files)) {
    add(aclProblem(f, f && f.path ? f.path : P.program));
    if (!f || f.dir) continue;
    if (f.name === 'helper.json') continue;
    if (!mfiles.has(f.name)) add(tx('Лишний файл в папке помощника: {0}', String(f.name)));
    else if (String(f.sha256 || '').toLowerCase() !== mfiles.get(f.name)) add(tx('Файл помощника изменён после установки: {0}', String(f.name)));
  }
  for (const n of mfiles.keys()) if (!arr(prog.files).some((f) => f && f.name === n)) add(tx('Нет файла помощника: {0}', n));

  const out = check.out || {};
  add(aclProblem(out.dir, P.out));
  for (const f of arr(out.files)) if (f && f.exists) add(aclProblem(f, f.path || f.name));

  // Задания запускают ровно powershell.exe из System32 и сценарий из Program Files, от имени SYSTEM.
  for (const x of TASKS) {
    const tk = tasks.find((y) => y && y.name === x.name);
    if (!tk || tk.exists === false) { add(tx('Нет задания «{0}» в планировщике', x.name)); continue; }
    if (tk.exists !== true || tk.command == null) continue; // задание не видно этой учётной записи - судим по файлам
    const okCmd = Number(tk.actions) === 1 && sameText(tk.command, P.powershell) && sameText(tk.arguments, P.taskArgs(x.mode));
    if (!okCmd || USER_ACCOUNT_RE.test(String(tk.userId || ''))) add(tx('Задание «{0}» изменено после установки', x.name));
  }
  res.problem = problems[0] || null;
  res.problems = problems.slice(0, 10);
  res.trusted = !problems.length;
  return res;
}

// ---------------------------------------------------------------- ответы помощника

function freshAt(obj, now, maxAgeMs) {
  const at = toMs(obj && obj.at);
  if (at == null || at > now + FUTURE_SLACK_MS || now - at > maxAgeMs) return null;
  return at;
}

/** full.json → { at, version, facts } или null. */
function parseFull(obj, { now = Date.now(), maxAgeMs = FULL_MAX_AGE } = {}) {
  if (!isObj(obj) || obj.format !== 'adamant-helper-full') return null;
  if (!Number.isInteger(obj.version) || obj.version < 1 || obj.version > HELPER_VERSION) return null;
  if (freshAt(obj, now, maxAgeMs) == null) return null;
  const f = obj.facts;
  if (!isObj(f) || f.format !== 'adamant-facts' || f.isAdmin !== true) return null;
  return { at: obj.at, version: obj.version, facts: f };
}

const str = (v, n = 256) => (v == null ? '' : String(v).replace(/[\r\n\t]/g, ' ').slice(0, n));
const int = (v) => (Number.isFinite(Number(v)) ? Math.trunc(Number(v)) : null);
function list(a, max, map) {
  return arr(a).slice(0, max).filter((x) => isObj(x) && toMs(x.at) != null).map(map);
}

/** security.json → проверенный и обрезанный объект или null. */
function parseSecurity(obj, { now = Date.now(), maxAgeMs = SECURITY_MAX_AGE } = {}) {
  if (!isObj(obj) || obj.format !== 'adamant-helper-security') return null;
  if (!Number.isInteger(obj.version) || obj.version < 1 || obj.version > HELPER_VERSION) return null;
  if (freshAt(obj, now, maxAgeMs) == null) return null;
  return {
    at: obj.at, version: obj.version, days: int(obj.days) || 14,
    failedTotal: int(obj.failedTotal) || 0, failedTruncated: !!obj.failedTruncated,
    failed: list(obj.failed, 300, (x) => ({ at: x.at, user: str(x.user), logonType: int(x.logonType), ip: str(x.ip, 64), workstation: str(x.workstation, 64), status: str(x.status, 16), ...(x.unknownUser ? { unknownUser: true } : {}) })),
    logons: list(obj.logons, 300, (x) => ({ at: x.at, user: str(x.user), logonType: int(x.logonType), ip: str(x.ip, 64), workstation: str(x.workstation, 64) })),
    locks: list(obj.locks, 200, (x) => ({ at: x.at, user: str(x.user), kind: x.kind === 'lock' ? 'lock' : 'unlock' })),
    created: list(obj.created, 50, (x) => ({ at: x.at, user: str(x.user), sid: str(x.sid, 80), by: str(x.by) })),
    adminAdds: list(obj.adminAdds, 50, (x) => ({ at: x.at, member: str(x.member), sid: str(x.sid, 80), group: str(x.group), by: str(x.by) })),
  };
}

// ---------------------------------------------------------------- перенос в проверку без прав администратора

/** События «Безопасности» в формате physical.presence.events (как их собирает physical.ps1 с правами администратора). */
function presenceFromSecurity(sec) {
  const ev = [];
  for (const l of arr(sec && sec.logons)) {
    if (l.logonType === 2 || l.logonType === 11) ev.push({ at: l.at, kind: 'logon', source: 'security', user: l.user, logonType: l.logonType });
    else if (l.logonType === 7) ev.push({ at: l.at, kind: 'unlock', source: 'security', user: l.user, logonType: 7 });
  }
  for (const l of arr(sec && sec.locks)) ev.push({ at: l.at, kind: l.kind === 'lock' ? 'lock' : 'unlock', source: 'security', user: l.user });
  // Неверный пароль именно за этим компьютером (не по сети) - как в physical.ps1: типы 2 и 7.
  for (const f of arr(sec && sec.failed)) {
    if (f.logonType !== 2 && f.logonType !== 7) continue;
    const e = { at: f.at, kind: 'failed-local', source: 'security', logonType: f.logonType };
    if (f.user) e.user = f.user;
    if (f.status) e.status = f.status;
    ev.push(e);
  }
  return ev;
}

function mergeEvents(own, secEvents) {
  // Как physical.ps1 с правами администратора: входы берём из «Безопасности», а не из системного журнала (там беднее).
  const sys = arr(own).filter((e) => isObj(e) && e.source !== 'security' && e.kind !== 'logon');
  const seen = new Set();
  const out = [];
  for (const e of [...sys, ...secEvents]) {
    if (!isObj(e) || toMs(e.at) == null) continue;
    const k = `${e.kind}|${e.user || ''}|${String(e.at).slice(0, 19)}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(e);
  }
  return out.sort((a, b) => toMs(b.at) - toMs(a.at)).slice(0, 300);
}

/**
 * Дополняет сведения обычной проверки (без прав администратора) ответами помощника. Меняет facts.
 * Берётся только то, чего обычная проверка не видит; видимое пользователю не заменяется.
 *   full     - результат parseFull/readFull или null;
 *   security - результат parseSecurity/readSecurity или null (свежие входы и блокировки для physical.presence).
 * → { fullAt, securityAt } или null, если переносить нечего.
 */
function mergeHelper(facts, { full = null, security = null } = {}) {
  if (!isObj(facts) || facts.isAdmin) return null;
  const h = full && isObj(full.facts) ? full.facts : null;
  if (!h && !security) return null;
  const sec = (name) => (isObj(facts[name]) ? facts[name] : null);
  const hs = (name) => (h && isObj(h[name]) ? h[name] : null);
  const fill = (name, key) => {
    const u = sec(name);
    const v = hs(name);
    if (u && v && u[key] == null && v[key] != null) u[key] = v[key];
  };
  if (h) {
    fill('smb', 'feature');
    fill('encryption', 'volumes');
    fill('boot', 'tpm');
    fill('boot', 'tpmSpec');
    fill('boot', 'bcdFirmware');
    fill('firmware', 'vendor');
    fill('events', 'security');
    const up = sec('physical');
    const hp = hs('physical');
    if (up && hp) {
      if (isObj(up.bitlocker) && up.bitlocker.preboot == null && isObj(hp.bitlocker) && hp.bitlocker.preboot != null) {
        up.bitlocker = { ...up.bitlocker, protection: hp.bitlocker.protection, protectors: arr(hp.bitlocker.protectors), preboot: hp.bitlocker.preboot };
      }
      if (isObj(up.winre) && up.winre.enabled == null && isObj(hp.winre) && hp.winre.enabled != null) up.winre = { ...hp.winre };
    }
    const ur = sec('readiness');
    const hr = hs('readiness');
    if (ur && hr && isObj(ur.restore) && isObj(hr.restore)) {
      for (const k of ['points', 'lastPoint', 'protectedDrives']) if (ur.restore[k] == null && hr.restore[k] != null) ur.restore[k] = hr.restore[k];
    }
    const ue = sec('persistence');
    const he = hs('persistence');
    if (ue && he) {
      if (isObj(ue.exclusions) && !ue.exclusions.visible && isObj(he.exclusions) && he.exclusions.visible === true) ue.exclusions = he.exclusions;
      if ((!isObj(ue.wmi) || ue.wmi.visible === false) && isObj(he.wmi) && he.wmi.visible === true) ue.wmi = he.wmi;
    }
  }
  // Кто садился за компьютер: свежие события из security.json, иначе - из полной проверки помощника.
  const pr = sec('physical') && isObj(facts.physical.presence) ? facts.physical.presence : null;
  if (pr && !pr.security) {
    let secEvents = null;
    if (security) secEvents = presenceFromSecurity(security);
    else if (h && isObj(h.physical) && isObj(h.physical.presence) && h.physical.presence.security) secEvents = arr(h.physical.presence.events).filter((e) => isObj(e) && e.source === 'security');
    if (secEvents) {
      pr.events = mergeEvents(pr.events, secEvents);
      pr.security = true;
    }
  }
  const res = { fullAt: full && h ? full.at : null, securityAt: security ? security.at : null };
  facts.helper = { ...res, version: (full && full.version) || (security && security.version) || null };
  return res;
}

// ---------------------------------------------------------------- работа с Windows

function readJsonFile(fs, file, maxBytes) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > maxBytes) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
  } catch {
    return null;
  }
}

function execText(file, args, timeout = 30_000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout, encoding: 'utf8' }, (err, stdout, stderr) => (err ? reject(Object.assign(new Error(String(stderr || err.message).trim().slice(0, 300)), { exitCode: err.code })) : resolve(String(stdout || ''))));
  });
}

/**
 * createHelper({ ps, fs, env, now, tmpDir }) - всё внешнее подменяется в тестах.
 *   status()                 → { installed, version, bundledVersion, outdated, trusted, problem, lastFull, lastSecurity, lastError, tasks, readerSid }
 *   readFull({ maxAgeMs })   → { at, version, facts } | null   (только если помощнику можно доверять и ответ свежий)
 *   readSecurity({ maxAgeMs }) → объект security.json | null
 *   install({ userSid })     → ответ helper-install.ps1 (UAC; отказ → ошибка с code = 'CANCELLED')
 *   uninstall()              → ответ helper-uninstall.ps1 (UAC; отказ → 'CANCELLED')
 *   refresh({ timeoutMs })   → свежий { at, version, facts }: запуск задания полной проверки без UAC
 */
function createHelper({
  ps = require('./ps'), fs = nodeFs, env = process.env, now = () => Date.now(), tmpDir,
  runTask = null, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), whoami = null,
} = {}) {
  const P = paths(env);
  let cache = null;
  let pending = null;

  const dirId = () => {
    try {
      const st = fs.statSync(P.out, { bigint: true });
      return `${st.ino}:${st.birthtimeNs}`;
    } catch {
      return null;
    }
  };

  async function trust({ force = false } = {}) {
    const id = dirId();
    if (!force && cache && now() - cache.at < TRUST_CACHE_MS && cache.id === id) return cache.res;
    if (pending) return pending;
    pending = (async () => {
      let res;
      try {
        const check = await ps.runJson('helper-install.ps1', ['-Check'], { timeout: 60_000 });
        res = evaluate(check, { env, bundled: bundledHashes(ps.PS_DIR, fs) });
      } catch (e) {
        const installed = fs.existsSync(path.win32.join(P.program, 'helper.json'));
        res = { installed, version: null, bundledVersion: HELPER_VERSION, outdated: false, trusted: false, tasks: [], readerSid: null, problem: installed ? tx('Не удалось проверить помощника: {0}', e.message) : t('Помощник не установлен') };
      }
      cache = { at: now(), id: dirId(), res };
      return res;
    })();
    try {
      return await pending;
    } finally {
      pending = null;
    }
  }
  const forget = () => { cache = null; };
  const outFile = (n) => path.win32.join(P.out, n);

  async function readFull({ maxAgeMs = FULL_MAX_AGE } = {}) {
    const tr = await trust();
    if (!tr.trusted) return null;
    return parseFull(readJsonFile(fs, outFile('full.json'), MAX_FULL_BYTES), { now: now(), maxAgeMs });
  }

  async function readSecurity({ maxAgeMs = SECURITY_MAX_AGE } = {}) {
    const tr = await trust();
    if (!tr.trusted) return null;
    return parseSecurity(readJsonFile(fs, outFile('security.json'), MAX_SECURITY_BYTES), { now: now(), maxAgeMs });
  }

  function lastError() {
    const e = readJsonFile(fs, outFile('error.json'), 65536);
    if (!isObj(e) || e.format !== 'adamant-helper-error' || toMs(e.at) == null) return null;
    return { at: e.at, mode: e.mode === 'full' ? 'full' : 'security', error: str(e.error, 500) };
  }

  async function status({ force = false } = {}) {
    const tr = await trust({ force });
    const s = { ...tr, lastFull: null, lastSecurity: null, lastError: null };
    if (tr.trusted) {
      const f = parseFull(readJsonFile(fs, outFile('full.json'), MAX_FULL_BYTES), { now: now(), maxAgeMs: Infinity });
      const q = parseSecurity(readJsonFile(fs, outFile('security.json'), MAX_SECURITY_BYTES), { now: now(), maxAgeMs: Infinity });
      s.lastFull = f ? f.at : null;
      s.lastSecurity = q ? q.at : null;
      const e = lastError();
      // Ошибка важна, только если после неё не было удачного запуска того же вида.
      const okAt = e && toMs(e.mode === 'full' ? s.lastFull : s.lastSecurity);
      if (e && !(okAt != null && okAt > toMs(e.at))) s.lastError = e;
      if (!s.lastFull && !s.problem) s.problem = s.lastError ? tx('Помощник не смог проверить компьютер: {0}', s.lastError.error) : t('Помощник ещё ни разу не проверял компьютер');
      else if (s.lastFull && now() - toMs(s.lastFull) > FULL_MAX_AGE && !s.problem) s.problem = t('Помощник давно не проверял компьютер');
    }
    delete s.problems;
    return s;
  }

  async function currentUserSid() {
    try {
      const out = whoami ? await whoami() : await execText(P.whoami, ['/user', '/fo', 'csv', '/nh']);
      const m = String(out).match(/S-1-(5-21|12-1)(-\d{1,10}){4}/);
      return m ? m[0] : null;
    } catch {
      return null;
    }
  }

  async function install({ userSid } = {}) {
    const sid = userSid && SID_RE.test(String(userSid)) ? String(userSid) : await currentUserSid();
    forget();
    let res;
    try {
      res = await ps.runElevated('helper-install.ps1', sid ? ['-ReaderSid', sid] : [], { tmpDir, timeout: 300_000 });
    } finally {
      forget();
    }
    if (!res || !res.ok) throw new Error((res && res.error) || t('Помощник не установился'));
    // Установщик читал файлы из папки программы: сверяем, что в Program Files легло то же, что видим мы.
    const mine = bundledHashes(ps.PS_DIR, fs);
    const got = new Map(arr(res.files).map((f) => [f && f.name, String((f && f.sha256) || '').toLowerCase()]));
    if (got.size !== mine.size || [...mine].some(([n, h]) => got.get(n) !== h)) res.warning = t('Файлы помощника отличаются от файлов программы. Удалите помощника и установите заново.');
    return res;
  }

  async function uninstall() {
    forget();
    let res;
    try {
      res = await ps.runElevated('helper-uninstall.ps1', [], { tmpDir, timeout: 300_000 });
    } finally {
      forget();
    }
    if (!res || !res.ok) throw new Error((res && res.error) || t('Помощник не удалился'));
    return res;
  }

  /** «Проверить полностью» без окна UAC: запускаем задание помощника и ждём новый full.json. */
  async function refresh({ timeoutMs = 240_000, pollMs = 2000 } = {}) {
    const tr = await trust();
    if (!tr.trusted || tr.outdated) throw Object.assign(new Error(t('Помощник недоступен')), { code: 'HELPER_UNAVAILABLE', problem: tr.problem });
    const read = () => parseFull(readJsonFile(fs, outFile('full.json'), MAX_FULL_BYTES), { now: now(), maxAgeMs: Infinity });
    const before = read();
    if (before && now() - toMs(before.at) < FRESH_SKIP_MS) return before;
    const started = now();
    try {
      await (runTask ? runTask(TASKS[0].name) : execText(P.schtasks, ['/Run', '/TN', `\\Adamant\\${TASKS[0].name}`]));
    } catch (e) {
      // Например, задание не разрешено запускать этой учётной записи: тогда - обычная проверка через UAC.
      throw Object.assign(new Error(e.message), { code: 'HELPER_UNAVAILABLE' });
    }
    while (now() - started < timeoutMs) {
      await sleep(pollMs);
      const cur = read();
      if (cur && (!before || cur.at !== before.at) && toMs(cur.at) >= started - FUTURE_SLACK_MS) return cur;
      const e = lastError();
      if (e && e.mode === 'full' && toMs(e.at) >= started) throw Object.assign(new Error(e.error), { code: 'HELPER_FAILED' });
    }
    throw Object.assign(new Error(t('Помощник не успел проверить компьютер')), { code: 'HELPER_TIMEOUT' });
  }

  return { status, readFull, readSecurity, install, uninstall, refresh, trust, forget, paths: P };
}

module.exports = {
  createHelper, evaluate, aclProblem, parseFull, parseSecurity, mergeHelper, presenceFromSecurity, mergeEvents,
  payloadFiles, bundledHashes, paths, HELPER_VERSION, ADMIN_KEYS, WRITE_MASK, TASKS, FULL_MAX_AGE, SECURITY_MAX_AGE, FRESH_SKIP_MS, SID_RE,
};
