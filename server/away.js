'use strict';
/**
 * «Пока вас не было»: что происходило с компьютером, пока он был заблокирован или спал.
 *
 * Источники (всё только читается, ничего не уходит с компьютера):
 *  - значок в трее (windows/tray.ps1) присылает события сеанса: блокировка, разблокировка, сон, пробуждение,
 *    удалённое подключение, подключение диска или флешки, запуск значка после входа в Windows;
 *  - список процессов (tasklist.exe, без PowerShell) - какие программы запускались;
 *  - fs.watch по «Документам», «Рабочему столу» и «Загрузкам» - какие файлы менялись;
 *  - журнал безопасности Windows (server/ps/logons.ps1 или файл помощника с правами администратора) -
 *    неверные пароли и входы других учётных записей.
 *
 * Отрезок («span») - от блокировки или сна до разблокировки или пробуждения. После разблокировки ещё час
 * («хвост») записывается, что запускали и меняли, пока владелец не нажмёт «Это был я» или не заблокирует снова.
 * В остальное время модуль ничего не опрашивает и не следит за папками: обычная работа ничего не стоит.
 *
 * Журнал - away.json в папке данных: 14 дней, размер ограничен. Снимки - away/photos/<id>.jpg.
 */
const nodeFs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { t, tx } = require('./i18n');
const { defaultDirs, PREFIX: CANARY_PREFIX } = require('./canary');

const FILE = 'away.json';
const DAY = 24 * 3600_000;
const KEEP_DAYS = 14;
const TAIL_MS = 60 * 60_000; // сколько следить после неподтверждённой разблокировки
const BRIEF_MS = 15 * 60_000; // разблокировали и снова заблокировали быстрее - «ненадолго»
const MAX_OPEN_MS = DAY; // дольше отрезок не бывает: значок мог пропустить разблокировку
const SLOW_AFTER_MS = 60 * 60_000; // после часа блокировки процессы смотрим реже
const PROC_SLOW_MS = 60_000;
const LOGON_EVERY_MS = 30_000;
const LOGON_BACKOFF_MS = 10 * 60_000; // журнал не виден - пробуем снова не чаще
const FINAL_WAIT_MS = 2 * 60_000; // сколько после разблокировки ждать свежего ответа помощника
const PHOTO_MAX = 3;
const PHOTO_GAP_MS = 60_000;
const PHOTO_TTL_MS = 2 * 60_000; // значок должен ответить за это время
const PHOTO_WANT_MS = 5 * 60_000; // сколько ждать возможности сделать отложенный снимок
const PHOTO_MAX_BYTES = 8 * 1024 * 1024;
const MAX_SPANS = 300;
const MAX_BYTES = 1_500_000;
const PRUNE_EVERY_MS = 3600_000;
const CAP = { events: 100, processes: 60, files: 50, usb: 20, logons: 50, photos: 6, seen: 5000 };

const KINDS = new Set(['lock', 'unlock', 'suspend', 'resume', 'remote', 'usb', 'start']);
const REMOTE_HOW = new Set(['remote-connect', 'remote-disconnect', 'console-connect', 'console-disconnect', 'remote-control']);
const ALARM_HOW = new Set(['remote-connect', 'console-disconnect', 'remote-control']);
const DRIVE_TYPES = new Set(['Removable', 'Fixed', 'CDRom', 'Network', 'Ram', 'NoRootDirectory', 'Unknown', '']);
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?(Z|[+-]\d\d:\d\d)$/;
const SPAN_ID = /^[a-f0-9]{16}$/;
const PHOTO_ID = /^[a-f0-9]{32}$/;
const ERR_CODE = /^[a-z][a-z0-9-]{0,31}$/;
const LOGON_KINDS = new Set(['failed', 'logon', 'unlock', 'lock']);

/** Служебные процессы Windows: появляются сами, пока компьютер стоит. Имена в нижнем регистре. */
const NOISE = new Set([
  'system idle process', 'system', 'secure system', 'registry', 'memory compression', 'smss.exe', 'csrss.exe', 'wininit.exe',
  'winlogon.exe', 'services.exe', 'lsass.exe', 'lsaiso.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'conhost.exe',
  'runtimebroker.exe', 'backgroundtaskhost.exe', 'dllhost.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
  'searchindexer.exe', 'searchhost.exe', 'searchapp.exe', 'sihost.exe', 'taskhostw.exe', 'ctfmon.exe', 'wmiprvse.exe',
  'wmiapsrv.exe', 'unsecapp.exe', 'audiodg.exe', 'spoolsv.exe', 'msmpeng.exe', 'mpcmdrun.exe', 'nissrv.exe',
  'mpdefendercoreservice.exe', 'mpsigstub.exe', 'mrt.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe',
  'securityhealthhost.exe', 'smartscreen.exe', 'sgrmbroker.exe', 'sppsvc.exe', 'sppextcomobj.exe', 'tiworker.exe',
  'trustedinstaller.exe', 'mousocoreworker.exe', 'usoclient.exe', 'wuauclt.exe', 'compattelrunner.exe', 'devicecensus.exe',
  'werfault.exe', 'wermgr.exe', 'wudfhost.exe', 'lockapp.exe', 'logonui.exe', 'shellexperiencehost.exe',
  'startmenuexperiencehost.exe', 'textinputhost.exe', 'applicationframehost.exe', 'systemsettingsbroker.exe',
  'useroobebroker.exe', 'credentialuibroker.exe', 'musnotification.exe', 'musnotifyicon.exe', 'monotificationux.exe',
  'dashost.exe', 'dismhost.exe', 'comppkgsrv.exe', 'aggregatorhost.exe', 'wlanext.exe', 'ngen.exe', 'ngentask.exe',
  'mscorsvw.exe', 'tasklist.exe', 'msedgewebview2.exe', 'microsoftedgeupdate.exe', 'googleupdate.exe', 'officeclicktorun.exe',
  'sdxhelper.exe', 'filecoauth.exe', 'onedrivestandaloneupdater.exe', 'gamebarpresencewriter.exe', 'widgets.exe',
  'widgetservice.exe', 'phoneexperiencehost.exe', 'crossdeviceresume.exe', 'appactions.exe', 'ai.exe', 'smss',
  'uhssvc.exe', 'upfc.exe', 'sihclient.exe', 'wsqmcons.exe', 'msiexec.exe.mui',
]);
/** Свои дочерние процессы «Адаманта» в момент проверки (сам сервер, сценарии PowerShell). */
const SELF_NAMES = new Set(['powershell.exe', 'conhost.exe', 'node.exe']);
const SYSTEM_USERS = /^(system|local service|network service|anonymous logon|-|umfd-\d+|dwm-\d+|font driver host|window manager)$/i;

const TASKLIST = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tasklist.exe');
const HELPER_FILE = path.join(process.env.ProgramData || 'C:\\ProgramData', 'Adamant', 'helper', 'out', 'security.json');
const HELPER_FRESH_MS = 10 * 60_000;

function bad(message) {
  const e = new Error(message);
  e.status = 400;
  e.code = 'BAD_INPUT';
  return e;
}
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const clean = (s, max) => String(s).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
const iso = (ms) => new Date(ms).toISOString();
const ms = (s) => Date.parse(s);

/**
 * Событие от значка в трее - это ввод по HTTP: проверяется строго.
 * {kind, at, how?(remote), drive?, type?, label?(usb)}. Лишние поля - ошибка.
 */
function validateEvent(evt, nowMs) {
  if (!isObj(evt)) throw bad('event');
  const allowed = { remote: ['how'], usb: ['drive', 'type', 'label'] };
  if (typeof evt.kind !== 'string' || !KINDS.has(evt.kind)) throw bad('kind');
  for (const k of Object.keys(evt)) if (k !== 'kind' && k !== 'at' && !(allowed[evt.kind] || []).includes(k)) throw bad(`field ${k.slice(0, 20)}`);
  if (typeof evt.at !== 'string' || evt.at.length > 40 || !ISO.test(evt.at)) throw bad('at');
  const at = ms(evt.at);
  if (!Number.isFinite(at) || at < nowMs - DAY || at > nowMs + 2 * 60_000) throw bad('at');
  const out = { kind: evt.kind, at: iso(at) };
  if (evt.kind === 'remote') {
    if (typeof evt.how !== 'string' || !REMOTE_HOW.has(evt.how)) throw bad('how');
    out.how = evt.how;
  }
  if (evt.kind === 'usb') {
    if (evt.drive != null) {
      if (typeof evt.drive !== 'string' || !/^[A-Za-z]:$/.test(evt.drive)) throw bad('drive');
      out.drive = evt.drive.toUpperCase();
    }
    if (evt.type != null) {
      if (typeof evt.type !== 'string' || !DRIVE_TYPES.has(evt.type)) throw bad('type');
      if (evt.type) out.type = evt.type;
    }
    if (evt.label != null) {
      if (typeof evt.label !== 'string' || evt.label.length > 128) throw bad('label');
      const l = clean(evt.label, 64);
      if (l) out.label = l;
    }
  }
  return out;
}

/** tasklist /fo csv /nh → [{name, pid, session}] */
function parseTasklist(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    if (!line.startsWith('"')) continue;
    const f = [...line.matchAll(/"((?:[^"]|"")*)"/g)].map((m) => m[1].replace(/""/g, '"'));
    const pid = Number(f[1]);
    if (!f[0] || !Number.isInteger(pid)) continue;
    out.push({ name: f[0], pid, session: Number(f[3]) });
  }
  return out;
}

/** Вывод tasklist - в кодировке OEM. Русская Windows: cp866 («КБ» в колонке памяти). */
function decodeOem(buf) {
  try {
    const s = new TextDecoder('ibm866').decode(buf);
    if (/\d\s?К[БB]"/.test(s)) return s;
  } catch { /* нет такой кодировки в сборке Node */ }
  return Buffer.from(buf).toString('latin1');
}

const isNoise = (name) => {
  const n = String(name || '').toLowerCase();
  return !n || NOISE.has(n) || /^(ngen|mscorsvw)/.test(n);
};

/** Файлы, которые меняются сами: временные файлы Office и программ, служебные файлы Проводника, приманки «Адаманта». */
function ignoredFile(base) {
  const b = String(base || '');
  const l = b.toLowerCase();
  return !b || b.startsWith('~$') || b.startsWith('.~lock.') || b.startsWith(CANARY_PREFIX)
    || l === 'desktop.ini' || l === 'thumbs.db' || /\.(tmp|crdownload|partial|part|download|temp)$/.test(l) || /^~.*\.tmp$/.test(l);
}

const normUser = (u) => String(u || '').split('\\').pop().trim().toLowerCase();

/**
 * Ответ readLogons (сценарий, файл помощника или тестовая подделка) → {visible, items:[{at, kind, user, logonType}]}.
 * Принимает массив, {visible:false}, {visible, items} и форму помощника {at, failed:[], logons:[], unlocks?:[]}.
 * Незнакомая форма - «не видно».
 */
function normalizeLogons(res) {
  const item = (x, forceKind) => {
    if (!isObj(x) || typeof x.at !== 'string') return null;
    const at = ms(x.at);
    if (!Number.isFinite(at)) return null;
    let lt = x.logonType == null ? null : Number(x.logonType);
    if (!Number.isInteger(lt) || lt < 0 || lt > 20) lt = null;
    let kind = forceKind || (typeof x.kind === 'string' ? x.kind : null);
    if (forceKind === 'logon' && (x.kind === 'unlock' || lt === 7)) kind = 'unlock';
    if (!LOGON_KINDS.has(kind)) return null;
    const user = clean(x.user == null ? '' : x.user, 128);
    if (kind !== 'failed' && (SYSTEM_USERS.test(user) || user.endsWith('$'))) return null;
    return { at: iso(at), kind, user, logonType: lt };
  };
  let visible = false;
  let items = [];
  if (Array.isArray(res)) {
    visible = true;
    items = res.map((x) => item(x));
  } else if (isObj(res)) {
    if (Array.isArray(res.items)) {
      visible = res.visible !== false;
      items = res.items.map((x) => item(x));
    } else if (Array.isArray(res.failed) || Array.isArray(res.logons) || Array.isArray(res.unlocks)) {
      visible = res.visible !== false;
      items = [
        ...(Array.isArray(res.failed) ? res.failed.map((x) => item(x, 'failed')) : []),
        ...(Array.isArray(res.logons) ? res.logons.map((x) => item(x, 'logon')) : []),
        ...(Array.isArray(res.unlocks) ? res.unlocks.map((x) => item(x, 'unlock')) : []),
        // 4801 «рабочая станция разблокирована» (если аудит включён); блокировки 4800 знает сам значок в трее.
        ...(Array.isArray(res.locks) ? res.locks.filter((x) => isObj(x) && x.kind === 'unlock').map((x) => item(x, 'unlock')) : []),
      ];
    }
  }
  items = items.filter(Boolean).sort((a, b) => ms(a.at) - ms(b.at));
  // Один вход Windows пишет дважды (два маркера доступа у администратора, 4624 и 4801 при разблокировке): склеиваем за 5 секунд.
  const out = [];
  for (const x of items) {
    const dup = out.find((y) => y.kind === x.kind && normUser(y.user) === normUser(x.user) && Math.abs(ms(y.at) - ms(x.at)) <= 5000
      && (x.kind === 'failed' ? y.logonType === x.logonType && y.at === x.at : true));
    if (!dup) out.push(x);
  }
  return { visible, items: out.slice(-400) };
}

/** Время для заголовка: «14:02» сегодня, «17.11 14:02» в другой день. */
function hm(isoStr, nowMs) {
  const d = new Date(ms(isoStr));
  const n = new Date(nowMs);
  const p = (x) => String(x).padStart(2, '0');
  const time = `${p(d.getHours())}:${p(d.getMinutes())}`;
  return d.toDateString() === n.toDateString() ? time : `${p(d.getDate())}.${p(d.getMonth() + 1)} ${time}`;
}
function range(fromIso, toIso, nowMs) {
  const a = hm(fromIso, nowMs);
  if (!toIso) return a;
  const sameDay = new Date(ms(fromIso)).toDateString() === new Date(ms(toIso)).toDateString();
  const b = sameDay && a.length > 5 ? hm(toIso, nowMs).slice(-5) : hm(toIso, nowMs);
  return `${a}-${b}`;
}
/** Список сообщений через «; » (строка без русских букв - переводить не нужно). */
const joinMsgs = (parts) => parts.reduce((acc, p) => (acc == null ? p : tx('{0}; {1}', acc, p)), null);

const PHOTO_ERRORS = {
  'no-camera': t('камеры нет или она выключена'),
  blocked: t('камера запрещена в параметрах конфиденциальности или недоступна на экране блокировки'),
  busy: t('камера занята другой программой'),
  timeout: t('камера не ответила'),
  'no-answer': t('значок в трее не ответил'),
  'bad-file': t('снимок не сохранился'),
};

// ---------------------------------------------------------------- настоящие источники

/** Процессы через tasklist.exe (без PowerShell): дёшево, окно не появляется. */
function tasklist({ ownPids, timeout = 15_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(TASKLIST, ['/fo', 'csv', '/nh'], { windowsHide: true, timeout, encoding: 'buffer', maxBuffer: 16 * 1024 * 1024 }, (err, out) => {
      if (child && child.pid && ownPids) setTimeout(() => ownPids.delete(child.pid), 60_000).unref();
      if (err) return reject(err);
      resolve(parseTasklist(decodeOem(out)));
    });
    if (child && child.pid && ownPids) ownPids.add(child.pid);
    try { if (child && child.pid) os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL); } catch { /* не страшно */ }
  });
}

/** Файл помощника с правами администратора, если он свежий. */
function readHelperFile(file = HELPER_FILE, nowMs = Date.now(), fs = nodeFs) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > 4 * 1024 * 1024) return null;
    const j = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
    if (!isObj(j)) return null;
    const at = typeof j.at === 'string' ? ms(j.at) : st.mtimeMs;
    if (!Number.isFinite(at) || nowMs - at > HELPER_FRESH_MS) return null;
    return j;
  } catch {
    return null;
  }
}

/** Неверные пароли и входы: сначала файл помощника, иначе server/ps/logons.ps1 (только чтение). */
function logonReader({ ownPids, helperSecurity = null }) {
  const ps = require('./ps');
  return async (sinceIso) => {
    // С помощником файл читает helper.js: он проверяет владельца и права папки, подделку не примет.
    if (helperSecurity) {
      let h = null;
      try { h = await helperSecurity(); } catch { h = null; }
      if (h) return h;
    } else {
      const h = readHelperFile();
      if (h) return h;
    }
    const extra = helperSecurity ? ['-NoHelper'] : [];
    return new Promise((resolve) => {
      const child = execFile(ps.POWERSHELL, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(ps.PS_DIR, 'logons.ps1'), '-Since', sinceIso, ...extra],
        { windowsHide: true, timeout: 30_000, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' }, (err, stdout) => {
          if (child && child.pid) setTimeout(() => ownPids.delete(child.pid), 60_000).unref();
          try { resolve(ps.parseJsonOutput(stdout)); } catch { resolve({ visible: false }); }
        });
      if (child && child.pid) ownPids.add(child.pid);
      try { if (child && child.pid) os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL); } catch { /* не страшно */ }
    });
  };
}

/** «Документы» и «Рабочий стол» (как у приманок) и «Загрузки». */
function defaultWatchDirs() {
  const home = process.env.USERPROFILE || os.homedir();
  return [...defaultDirs(), path.join(home, 'Downloads')];
}

// ---------------------------------------------------------------- модуль

function createAway({
  store = null, dataDir, now = () => Date.now(), listProcesses = null, watchDirs = defaultWatchDirs, readLogons = null,
  settings = null, fs = nodeFs, owner = (() => { try { return os.userInfo().username; } catch { return ''; } })(),
  selfBusy = () => false, ignoreDirs = [], watchFs = null, helperSecurity = null,
} = {}) {
  if (!dataDir) throw new Error('dataDir required');
  const ownPids = new Set([process.pid]);
  const list = listProcesses || (() => tasklist({ ownPids }));
  const logons = readLogons || logonReader({ ownPids, helperSecurity });
  const getSettings = () => {
    try {
      const s = settings ? settings() : store && store.settings ? store.settings() : {};
      return { away: !!(s && s.away), photo: !!(s && s.away && s.awayPhoto) };
    } catch {
      return { away: false, photo: false };
    }
  };
  const photosDir = path.join(dataDir, 'away', 'photos');
  const ownerName = normUser(owner);
  const realDir = (d) => { try { return (fs.realpathSync.native || fs.realpathSync)(d); } catch { return path.resolve(d); } };
  const skipRoots = [dataDir, path.resolve(__dirname, '..'), ...ignoreDirs].map((d) => realDir(d).toLowerCase());

  // ---- журнал
  function load() {
    let j = null;
    try {
      j = store && store.read ? store.read(FILE, null) : JSON.parse(fs.readFileSync(path.join(dataDir, FILE), 'utf8'));
    } catch { j = null; }
    if (!isObj(j) || !Array.isArray(j.spans)) j = { v: 1, spans: [], meta: {} };
    j.spans = j.spans.filter((s) => isObj(s) && typeof s.id === 'string' && SPAN_ID.test(s.id) && Number.isFinite(ms(s.from)));
    for (const s of j.spans) fillSpan(s);
    if (!isObj(j.meta)) j.meta = {};
    return j;
  }
  function save() {
    dirty = false;
    try {
      if (store && store.write) store.write(FILE, J);
      else {
        fs.mkdirSync(dataDir, { recursive: true });
        const tmp = path.join(dataDir, `${FILE}.${process.pid}.tmp`);
        fs.writeFileSync(tmp, JSON.stringify(J), { mode: 0o600 });
        fs.renameSync(tmp, path.join(dataDir, FILE));
      }
    } catch (e) {
      console.error('Пока вас не было:', e.message);
    }
  }
  function fillSpan(s) {
    s.events = Array.isArray(s.events) ? s.events : [];
    s.processes = Array.isArray(s.processes) ? s.processes : [];
    s.files = isObj(s.files) ? s.files : {};
    s.files.count = Number(s.files.count) || 0;
    s.files.afterCount = Number(s.files.afterCount) || 0;
    s.files.sample = Array.isArray(s.files.sample) ? s.files.sample : [];
    s.usb = Array.isArray(s.usb) ? s.usb : [];
    s.photos = Array.isArray(s.photos) ? s.photos : [];
    s.logons = isObj(s.logons) ? s.logons : { visible: null, items: [] };
    if (!Array.isArray(s.logons.items)) s.logons.items = [];
    return s;
  }

  let J = load();
  let dirty = false;
  let watchers = [];
  let watching = false;
  let watchStarting = false;
  let baseline = null; // PID на начало отрезка
  let baselineSpan = null;
  let lastProcPoll = 0;
  let lastLogonPoll = 0;
  let lastVisible = null;
  let lastPrune = 0;
  let ticking = null;
  let procBusy = false;
  const seenFiles = new Map(); // id отрезка → Set путей (только в памяти)

  const nowIso = () => iso(now());
  const openSpan = () => J.spans.find((s) => !s.to) || null;
  /** Отрезок, который сейчас пополняется: открытый или «хвост» после неподтверждённой разблокировки. */
  function current() {
    const o = openSpan();
    if (o) return o;
    const s = J.spans[0];
    if (s && s.to && !s.confirmed && now() - ms(s.to) < TAIL_MS) return s;
    return null;
  }
  const push = (arr, x, cap) => { if (arr.length < cap) arr.push(x); };

  function newSpan(at, kind) {
    const s = fillSpan({ id: crypto.randomBytes(8).toString('hex'), from: at, to: null, kind, endKind: null, locked: kind === 'lock', confirmed: false });
    J.spans.unshift(s);
    baseline = null;
    baselineSpan = s.id;
    lastLogonPoll = 0;
    return s;
  }
  function close(s, at, endKind) {
    s.to = iso(Math.max(ms(at), ms(s.from)));
    s.endKind = endKind;
    s.needFinalLogons = true;
    if (s.logons.items.some((x) => x.kind === 'failed')) want(s, 'unlock');
  }
  function want(s, reason) {
    if (!getSettings().photo) return;
    s.wantPhoto = { reason, at: nowIso() };
  }

  // ---- события от значка
  function event(evt) {
    const e = validateEvent(evt, now());
    if (!getSettings().away) return { ok: true, recorded: false };
    let s = openSpan();
    let recorded = true;
    if (s && now() - ms(s.from) > MAX_OPEN_MS) { close(s, iso(ms(s.from) + MAX_OPEN_MS), 'lost'); s = null; }
    switch (e.kind) {
      case 'lock':
      case 'suspend':
        if (s) {
          push(s.events, { at: e.at, kind: e.kind }, CAP.events);
          if (e.kind === 'lock') s.locked = true;
        } else {
          s = newSpan(e.at, e.kind);
          push(s.events, { at: e.at, kind: e.kind }, CAP.events);
          pollProcesses(s).catch(() => {}); // слепок процессов сразу, а не через 15 секунд
          ensureWatch();
        }
        break;
      case 'unlock':
      case 'start':
        if (s) {
          push(s.events, { at: e.at, kind: e.kind }, CAP.events);
          close(s, e.at, e.kind);
        } else recorded = false;
        break;
      case 'resume':
        if (s) {
          push(s.events, { at: e.at, kind: e.kind }, CAP.events);
          // После сна с блокировкой компьютер всё ещё заблокирован - отрезок закроет разблокировка.
          if (!s.locked) close(s, e.at, 'resume');
        } else recorded = false;
        break;
      default: { // remote, usb
        const c = s || current();
        if (!c) { recorded = false; break; }
        const after = !!c.to;
        const rec = { ...e, after };
        push(c.events, rec, CAP.events);
        if (e.kind === 'usb') push(c.usb, { at: e.at, drive: e.drive || '', type: e.type || '', label: e.label || '', after }, CAP.usb);
      }
    }
    if (recorded) save();
    return { ok: true, recorded };
  }

  // ---- процессы
  async function pollProcesses(s) {
    if (procBusy) return;
    procBusy = true;
    try {
      const procs = await list();
      if (!Array.isArray(procs)) return;
      lastProcPoll = now();
      if (!baseline || baselineSpan !== s.id) {
        baseline = new Set(procs.map((p) => p.pid));
        baselineSpan = s.id;
        return;
      }
      // Своя проверка «Адаманта» или снимок с камеры (значок запускает PowerShell) - не считать их чужими программами.
      const busy = !!selfBusy() || !!(J.meta.lastPhotoAt && now() - ms(J.meta.lastPhotoAt) < PHOTO_TTL_MS + 30_000);
      const at = nowIso();
      for (const p of procs) {
        if (baseline.has(p.pid)) continue;
        baseline.add(p.pid);
        const name = clean(p.name, 80);
        if (ownPids.has(p.pid) || isNoise(name)) continue;
        if (busy && SELF_NAMES.has(name.toLowerCase())) continue; // идёт своя проверка «Адаманта»
        // Помощник администратора: Windows запускает его powershell.exe от имени SYSTEM (сеанс 0) сразу после входа и неверного пароля.
        if (helperSecurity && p.session === 0 && SELF_NAMES.has(name.toLowerCase())) continue;
        if (s.processes.some((x) => x.name.toLowerCase() === name.toLowerCase())) continue;
        push(s.processes, { name, at, after: !!s.to, pid: p.pid }, CAP.processes);
        dirty = true;
      }
    } finally {
      procBusy = false;
    }
  }

  // ---- файлы
  function onFile(root, filename) {
    const s = current();
    if (!s || !filename) return;
    const rel = String(filename);
    if (ignoredFile(path.basename(rel))) return;
    const full = path.join(root, rel);
    const key = full.toLowerCase();
    if (skipRoots.some((d) => key === d || key.startsWith(d + path.sep))) return;
    let seen = seenFiles.get(s.id);
    if (!seen) { seen = new Set(); seenFiles.clear(); seenFiles.set(s.id, seen); }
    if (seen.has(key)) return;
    if (seen.size < CAP.seen) seen.add(key);
    const after = !!s.to;
    if (after) s.files.afterCount += 1;
    else s.files.count += 1;
    push(s.files.sample, { path: full, at: nowIso(), after }, CAP.files);
    dirty = true;
  }
  function ensureWatch() {
    if (watching || watchStarting) return;
    watchStarting = true;
    Promise.resolve().then(() => (typeof watchDirs === 'function' ? watchDirs() : watchDirs)).then((dirs) => {
      watchStarting = false;
      if (watching || !current()) return;
      const roots = [...new Set((Array.isArray(dirs) ? dirs : []).filter((d) => typeof d === 'string' && d).map(realDir))];
      // Вложенные папки (рабочий стол внутри OneDrive и т. п.) не смотрим дважды.
      const top = roots.filter((d) => !roots.some((o) => o !== d && d.toLowerCase().startsWith(o.toLowerCase() + path.sep)));
      const w = watchFs || fs.watch;
      for (const d of top) {
        try {
          const h = w.call(fs, d, { recursive: true, persistent: false }, (ev, name) => { try { onFile(d, name); } catch { /* не мешаем */ } });
          h.on('error', () => {
            try { h.close(); } catch { /* уже закрыт */ }
            watchers = watchers.filter((x) => x !== h);
          });
          watchers.push(h);
        } catch { /* папки нет или нет доступа */ }
      }
      watching = true;
    }).catch(() => { watchStarting = false; });
  }
  function unwatch() {
    for (const w of watchers) { try { w.close(); } catch { /* уже закрыт */ } }
    watchers = [];
    watching = false;
  }

  // ---- входы
  async function pollLogons(s) {
    const open = !s.to;
    const every = lastVisible === false ? LOGON_BACKOFF_MS : LOGON_EVERY_MS;
    if (open && now() - lastLogonPoll < every) return;
    if (!open && !s.needFinalLogons) return;
    if (!open && lastVisible === false && now() - lastLogonPoll < LOGON_BACKOFF_MS) { s.needFinalLogons = false; return; }
    lastLogonPoll = now();
    s.needFinalLogons = false;
    let res;
    let srcAt = null;
    try {
      const raw = await logons(iso(ms(s.from) - 2000));
      if (isObj(raw) && typeof raw.at === 'string' && Number.isFinite(ms(raw.at))) srcAt = ms(raw.at);
      res = normalizeLogons(raw);
    } catch {
      res = { visible: false, items: [] };
    }
    // Помощник обновляет ответ через несколько секунд после разблокировки (задание по событию входа).
    // Пока его ответ старше разблокировки, последние неверные пароли в нём могут отсутствовать - перечитаем на следующем такте.
    if (!open && res.visible && srcAt != null && srcAt < ms(s.to) + 2000 && now() - ms(s.to) < FINAL_WAIT_MS) s.needFinalLogons = true;
    lastVisible = res.visible;
    s.logons.visible = res.visible || s.logons.visible === true;
    s.logons.at = nowIso();
    dirty = true;
    if (!res.visible) return;
    const from = ms(s.from) - 2000;
    const end = s.to ? ms(s.to) + 60_000 : Infinity;
    const inSpan = res.items.filter((x) => ms(x.at) >= from && ms(x.at) <= end && x.kind !== 'lock');
    const before = s.logons.items.filter((x) => x.kind === 'failed').length;
    s.logons.items = inSpan.slice(-CAP.logons);
    const failed = s.logons.items.filter((x) => x.kind === 'failed').length;
    if (failed > before) {
      if (!s.to) want(s, 'failed');
      else if (now() - ms(s.to) < PHOTO_WANT_MS) want(s, 'unlock');
    }
  }

  // ---- снимки
  function pendingValid() {
    const p = J.meta.pending;
    if (!p) return null;
    if (now() - ms(p.at) > PHOTO_TTL_MS) {
      const s = J.spans.find((x) => x.id === p.span);
      if (s) push(s.photos, { id: p.id, at: p.at, ok: false, error: 'no-answer', reason: p.reason }, CAP.photos);
      J.meta.pending = null;
      dirty = true;
      return null;
    }
    return p;
  }
  function maybePhoto(s) {
    const w = s.wantPhoto;
    if (!w) return;
    if (!getSettings().photo || now() - ms(w.at) > PHOTO_WANT_MS || s.photos.length >= PHOTO_MAX) { s.wantPhoto = null; dirty = true; return; }
    if (pendingValid()) return;
    if (J.meta.lastPhotoAt && now() - ms(J.meta.lastPhotoAt) < PHOTO_GAP_MS) return;
    const attempts = s.photos.length + (J.meta.pending && J.meta.pending.span === s.id ? 1 : 0);
    if (attempts >= PHOTO_MAX) { s.wantPhoto = null; return; }
    try { fs.mkdirSync(photosDir, { recursive: true }); } catch { return; }
    J.meta.pending = { id: crypto.randomBytes(16).toString('hex'), span: s.id, at: nowIso(), reason: w.reason };
    J.meta.lastPhotoAt = J.meta.pending.at;
    s.wantPhoto = null;
    save();
  }
  /** Для GET /api/tray: номер снимка, который должен сделать значок, или null. */
  function photoRequest() {
    if (!getSettings().photo) return null;
    const p = pendingValid();
    if (dirty) save();
    return p ? { id: p.id } : null;
  }
  const photoFile = (id) => path.join(photosDir, `${id}.jpg`);
  /** Ответ значка: {id, ok, error?}. Файл значок кладёт только в away/photos/<id>.jpg - сервер проверяет, что это JPEG. */
  function photoDone(body) {
    if (!isObj(body) || typeof body.id !== 'string' || !PHOTO_ID.test(body.id) || typeof body.ok !== 'boolean') throw bad('photo');
    if (body.error != null && (typeof body.error !== 'string' || body.error.length > 32)) throw bad('error');
    for (const k of Object.keys(body)) if (!['id', 'ok', 'error'].includes(k)) throw bad(`field ${k.slice(0, 20)}`);
    const p = J.meta.pending;
    if (!p || p.id !== body.id) throw bad('unknown photo');
    J.meta.pending = null;
    const s = J.spans.find((x) => x.id === p.span);
    let ok = body.ok;
    let error = ok ? null : (ERR_CODE.test(body.error || '') ? body.error : 'error');
    if (ok) {
      try {
        const st = fs.statSync(photoFile(p.id));
        const head = Buffer.alloc(3);
        const fd = fs.openSync(photoFile(p.id), 'r');
        try { fs.readSync(fd, head, 0, 3, 0); } finally { fs.closeSync(fd); }
        if (!st.isFile() || st.size < 100 || st.size > PHOTO_MAX_BYTES || head[0] !== 0xff || head[1] !== 0xd8 || head[2] !== 0xff) throw new Error('not jpeg');
      } catch {
        ok = false;
        error = 'bad-file';
      }
    }
    if (!ok) { try { fs.unlinkSync(photoFile(p.id)); } catch { /* нет файла */ } }
    if (s) push(s.photos, ok ? { id: p.id, at: nowIso(), ok: true, reason: p.reason } : { id: p.id, at: nowIso(), ok: false, error, reason: p.reason }, CAP.photos);
    else if (ok) { try { fs.unlinkSync(photoFile(p.id)); } catch { /* нет */ } }
    save();
    return { ok: true, saved: ok && !!s };
  }
  /** Снимок для окна: data:-адрес (CSP разрешает data: для картинок). */
  function photoData(id) {
    if (typeof id !== 'string' || !PHOTO_ID.test(id)) throw bad('id');
    if (!J.spans.some((s) => s.photos.some((p) => p.id === id && p.ok))) return null;
    try {
      const buf = fs.readFileSync(photoFile(id));
      if (buf.length > PHOTO_MAX_BYTES || buf[0] !== 0xff || buf[1] !== 0xd8) return null;
      return `data:image/jpeg;base64,${buf.toString('base64')}`;
    } catch {
      return null;
    }
  }

  // ---- уборка
  function dropSpan(s) {
    for (const p of s.photos) if (p.id && PHOTO_ID.test(p.id)) { try { fs.unlinkSync(photoFile(p.id)); } catch { /* нет */ } }
    seenFiles.delete(s.id);
  }
  function prune(force = false) {
    if (!force && now() - lastPrune < PRUNE_EVERY_MS) return;
    lastPrune = now();
    const limit = now() - KEEP_DAYS * DAY;
    const keep = [];
    for (const s of J.spans) {
      const end = s.to ? ms(s.to) : ms(s.from);
      if (end < limit || keep.length >= MAX_SPANS) { dropSpan(s); dirty = true; } else keep.push(s);
    }
    J.spans = keep;
    while (J.spans.length > 1 && JSON.stringify(J).length > MAX_BYTES) { dropSpan(J.spans.pop()); dirty = true; }
    // Снимки без записи в журнале (сорванные, недописанные .part) старше часа.
    try {
      const known = new Set(J.spans.flatMap((s) => s.photos.map((p) => p.id)));
      if (J.meta.pending) known.add(J.meta.pending.id);
      for (const n of fs.readdirSync(photosDir)) {
        const m = /^([a-f0-9]{32})\.jpg(\.part)?$/.exec(n);
        if (!m || (known.has(m[1]) && !m[2])) continue;
        const p = path.join(photosDir, n);
        try { if (now() - fs.statSync(p).mtimeMs > 3600_000) fs.unlinkSync(p); } catch { /* занят */ }
      }
    } catch { /* папки нет */ }
  }

  // ---- раз в 15 секунд
  async function tickOnce() {
    prune();
    if (!getSettings().away) {
      // Выключили, пока компьютер был заблокирован, - отрезок не должен висеть до следующего включения.
      const o = openSpan();
      if (o) { close(o, nowIso(), 'off'); o.needFinalLogons = false; o.wantPhoto = null; dirty = true; }
      unwatch();
      if (dirty) save();
      return;
    }
    let s = openSpan();
    if (s && now() - ms(s.from) > MAX_OPEN_MS) { close(s, iso(ms(s.from) + MAX_OPEN_MS), 'lost'); dirty = true; }
    s = current();
    // Отрезок закрыт, но последние входы ещё не прочитаны (неверный пароль прямо перед разблокировкой).
    const last = J.spans[0];
    if (last && last.to && last.needFinalLogons && last !== s) { try { await pollLogons(last); } catch { /* ignore */ } }
    if (!s) {
      unwatch();
      baseline = null;
      if (dirty) save();
      return;
    }
    ensureWatch();
    const slow = !s.to && now() - ms(s.from) > SLOW_AFTER_MS;
    if (!slow || now() - lastProcPoll >= PROC_SLOW_MS - 1000) {
      try { await pollProcesses(s); } catch { /* tasklist не ответил */ }
    }
    try { await pollLogons(s); } catch { /* ignore */ }
    maybePhoto(s);
    if (dirty) save();
  }
  function tick() {
    if (ticking) return ticking;
    ticking = tickOnce().catch((e) => console.error('Пока вас не было:', e.message)).finally(() => { ticking = null; });
    return ticking;
  }

  // ---- «Это был я»
  function acknowledge(ids) {
    if (!Array.isArray(ids) || ids.length > MAX_SPANS || ids.some((x) => typeof x !== 'string' || !SPAN_ID.test(x))) throw bad('ids');
    const set = new Set(ids);
    let n = 0;
    for (const s of J.spans) {
      if (set.has(s.id) && !s.confirmed) {
        s.confirmed = true;
        s.confirmedAt = nowIso();
        s.wantPhoto = null;
        n += 1;
      }
    }
    if (n) save();
    if (!current()) unwatch();
    return { ok: true, confirmed: n };
  }

  // ---- для окна
  function analyse(s, next, nowMs) {
    const inSpan = (x) => !x.after;
    const failed = s.logons.items.filter((x) => x.kind === 'failed');
    // Разблокировка: событие 4624 тип 7 или 4801, а в Windows 11 - обычный вход владельца с клавиатуры (тип 2 или 11).
    // Один раз разблокировали - несколько записей за пару секунд, склеиваем их за 5 секунд.
    const unlockEnd = s.to ? ms(s.to) + 10_000 : Infinity;
    const unlockLogons = [];
    for (const x of s.logons.items) {
      const own = x.kind === 'logon' && (x.logonType === 2 || x.logonType === 11) && ownerName && normUser(x.user) === ownerName;
      if ((x.kind !== 'unlock' && !own) || ms(x.at) > unlockEnd) continue;
      if (!unlockLogons.some((y) => Math.abs(ms(y.at) - ms(x.at)) <= 5000)) unlockLogons.push(x);
    }
    const others = s.logons.items.filter((x) => (x.kind === 'logon' || x.kind === 'unlock') && ownerName && normUser(x.user) && normUser(x.user) !== ownerName);
    const remote = s.events.filter((e) => e.kind === 'remote' && inSpan(e) && ALARM_HOW.has(e.how));
    const usb = s.usb.filter(inSpan);
    const reasons = [];
    const parts = [];
    let level = 'calm';
    const alarm = (r, m) => { reasons.push(r); parts.push(m); level = 'alarm'; };
    const attention = (r, m) => { reasons.push(r); parts.push(m); if (level === 'calm') level = 'attention'; };
    if (failed.length) alarm('failed', tx('неверный пароль: {0}', failed.length));
    if (others.length) alarm('logon', tx('вход под другой учётной записью: {0}', [...new Set(others.map((x) => x.user))].join(', ')));
    if (remote.some((e) => e.how === 'console-disconnect')) alarm('switch', t('на компьютер входил другой пользователь'));
    if (remote.some((e) => e.how !== 'console-disconnect')) alarm('remote', t('к сеансу подключались удалённо'));
    if (s.to && unlockLogons.length > 1) alarm('unlocks', tx('компьютер разблокировали ещё раз: {0}', unlockLogons.length - 1));
    let brief = null;
    if (next && s.to && !s.confirmed && (s.endKind === 'unlock' || s.endKind === 'resume')) {
      const gap = ms(next.from) - ms(s.to);
      if (gap >= 0 && gap < BRIEF_MS) {
        brief = Math.max(1, Math.round(gap / 60_000));
        attention('brief', tx('компьютер разблокировали в {0} на {1} мин', hm(s.to, nowMs), brief));
      }
    }
    if (usb.length) attention('usb', tx('подключали диск или флешку: {0}', usb.length));
    if (s.files.count) attention('files', tx('изменились файлы: {0}', s.files.count));
    const calm = s.confirmed || level === 'calm';
    return { failed, unlockLogons, others, reasons, parts, level: s.confirmed ? 'calm' : level, calm, brief };
  }

  function headlineFor(s, a, nowMs) {
    if (!s.to) return s.kind === 'suspend' && !s.locked ? tx('Компьютер спит с {0}', hm(s.from, nowMs)) : tx('Компьютер заблокирован с {0}', hm(s.from, nowMs));
    const r = range(s.from, s.to, nowMs);
    if (s.confirmed) return tx('{0}: вы отметили, что это были вы', r);
    if (!a.calm) return tx('Пока вас не было ({0}): {1}', r, joinMsgs(a.parts));
    return s.logons.visible ? tx('Пока вас не было ({0}): никто не входил и не пытался войти', r) : tx('Пока вас не было ({0}): ничего необычного', r);
  }

  function eventText(e) {
    switch (e.kind) {
      case 'lock': return t('Компьютер заблокировали');
      case 'unlock': return t('Компьютер разблокировали');
      case 'suspend': return t('Компьютер уснул');
      case 'resume': return t('Компьютер проснулся');
      case 'start': return t('Вход в Windows: компьютер перезагружали или выключали');
      case 'remote': return {
        'remote-connect': t('Удалённое подключение к сеансу'),
        'remote-disconnect': t('Удалённое подключение завершено'),
        'console-connect': t('Сеанс снова на этом экране'),
        'console-disconnect': t('Сеанс отключён от экрана: возможно, вошёл другой пользователь'),
        'remote-control': t('Сеансом управляют удалённо'),
      }[e.how] || t('Удалённое подключение');
      case 'usb': return e.label ? tx('Подключён диск {0} «{1}»', e.drive || '?', e.label) : tx('Подключён диск {0}', e.drive || '?');
      default: return null;
    }
  }

  function spanOut(s, next, nowMs) {
    const a = analyse(s, next, nowMs);
    const events = [
      ...s.events.map((e) => ({ at: e.at, kind: e.kind, how: e.how, drive: e.drive, label: e.label, after: !!e.after, text: eventText(e) })),
      ...a.failed.map((x) => ({ at: x.at, kind: 'failed', user: x.user, logonType: x.logonType, after: !!(s.to && ms(x.at) > ms(s.to)), text: x.user ? tx('Неверный пароль для «{0}»', x.user) : t('Неверный пароль') })),
      ...a.others.map((x) => ({ at: x.at, kind: 'logon', user: x.user, logonType: x.logonType, after: !!(s.to && ms(x.at) > ms(s.to)), text: tx('Вход учётной записи «{0}»', x.user) })),
      ...s.photos.map((p) => ({ at: p.at, kind: 'photo', id: p.ok ? p.id : undefined, after: !!(s.to && ms(p.at) > ms(s.to)), text: p.ok ? t('Снимок с камеры') : tx('Снимок не получился: {0}', PHOTO_ERRORS[p.error] || t('ошибка')) })),
    ].sort((x, y) => ms(x.at) - ms(y.at)).slice(-150);
    return {
      id: s.id, from: s.from, to: s.to, kind: s.kind, endKind: s.endKind, active: !s.to, confirmed: !!s.confirmed,
      events,
      failed: a.failed.length,
      unlocks: a.unlockLogons.length,
      otherLogons: [...new Set(a.others.map((x) => x.user))],
      logonsVisible: s.logons.visible === true,
      processes: s.processes.map((p) => ({ name: p.name, at: p.at, after: !!p.after })),
      files: { count: s.files.count, afterCount: s.files.afterCount, sample: s.files.sample.map((f) => ({ path: f.path, at: f.at, after: !!f.after })) },
      usb: s.usb.map((u) => ({ at: u.at, drive: u.drive, type: u.type, label: u.label, after: !!u.after })),
      photos: s.photos.filter((p) => p.ok).map((p) => ({ id: p.id, at: p.at })),
      calm: a.calm, level: a.level, reasons: a.reasons,
      headline: headlineFor(s, a, nowMs),
      note: !s.to || s.logons.visible === true ? null : t('Неверные пароли видны только с правами администратора или в группе «Читатели журнала событий»'),
      _a: a,
    };
  }

  /** Отчёт для окна: отрезки (новые сначала) и сводка last - последний законченный отрезок вместе с короткими разблокировками перед ним. */
  function report({ days = KEEP_DAYS } = {}) {
    const d = Math.min(KEEP_DAYS, Math.max(1, Math.floor(Number(days)) || KEEP_DAYS));
    const nowMs = now();
    const limit = nowMs - d * DAY;
    const src = J.spans.filter((s) => (s.to ? ms(s.to) : ms(s.from)) >= limit);
    const spans = src.map((s, i) => spanOut(s, i > 0 ? src[i - 1] : null, nowMs));
    let last = null;
    const li = spans.findIndex((s) => !s.active);
    if (li >= 0) {
      const chain = [spans[li]];
      for (let j = li + 1; j < spans.length; j += 1) {
        if (spans[j].reasons.includes('brief') && !spans[j].confirmed) chain.push(spans[j]);
        else break;
      }
      const L = spans[li];
      const from = chain[chain.length - 1].from;
      const calm = chain.every((s) => s.calm);
      let headline = L.headline;
      if (chain.length > 1) {
        const parts = chain.slice().reverse().flatMap((s) => s._a.parts);
        headline = tx('Пока вас не было ({0}): {1}', range(from, L.to, nowMs), joinMsgs(parts));
      }
      last = { id: L.id, ids: chain.map((s) => s.id), from, to: L.to, calm, confirmed: chain.every((s) => s.confirmed), level: calm ? 'calm' : chain.some((s) => s.level === 'alarm') ? 'alarm' : 'attention', headline, note: L.note };
    }
    for (const s of spans) delete s._a;
    const st = getSettings();
    return { enabled: st.away, photo: st.photo, active: spans.find((s) => s.active) || null, last, spans, logonsVisible: lastVisible };
  }

  function status() {
    const o = openSpan();
    const c = current();
    const st = getSettings();
    return {
      enabled: st.away, photo: st.photo, active: !!o, since: o ? o.from : null, tail: !!(c && c.to),
      watching: watchers.length, logonsVisible: lastVisible, pendingPhoto: !!(J.meta.pending && now() - ms(J.meta.pending.at) <= PHOTO_TTL_MS),
      spans: J.spans.length,
    };
  }

  function stop() {
    unwatch();
    if (dirty) save();
  }

  prune(true);
  if (dirty) save();
  return { event, tick, report, acknowledge, photoRequest, photoDone, photoData, status, stop };
}

module.exports = {
  createAway, validateEvent, parseTasklist, decodeOem, normalizeLogons, ignoredFile, isNoise, readHelperFile, tasklist,
  HELPER_FILE, TAIL_MS, BRIEF_MS, PHOTO_MAX, PHOTO_GAP_MS, PHOTO_TTL_MS, KEEP_DAYS,
};
