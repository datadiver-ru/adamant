'use strict';
/**
 * Внутренний сервер окна программы. Слушает только 127.0.0.1.
 * Защита:
 *  - каждый запрос к /api (кроме /api/status) несёт ключ X-Adamant-Key - случайный, новый при каждом запуске;
 *    ключ знают только ярлык (из server.json в папке данных) и окно программы;
 *  - заголовок Host должен быть 127.0.0.1:порт или localhost:порт (защита от подмены DNS);
 *  - POST - только application/json и только со своего Origin;
 *  - строгая политика CSP: никаких внешних скриптов, стилей и запросов.
 */
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const { evaluate, summarize } = require('./rules');
const fixes = require('./fixes');
const { guide, OPEN_TARGETS } = require('./guides');
const netscan = require('./netscan');
const traffic = require('./traffic');
const bluetooth = require('./bluetooth');
const checklist = require('./checklist');
const license = require('./license');
const { reportHtml } = require('./report');
const { render, t, tx } = require('./i18n');
const upnp = require('./upnp');
const rulesDownloads = require('./rules-downloads');
const { score, pushHistory } = require('./score');
const { createGuard, ownTaskMatcher, ownAutorunMatcher } = require('./guard');
const { mergeHelper, TASKS: HELPER_TASKS } = require('./helper');
const { digestFacts } = require('./psblocks');

const PUBLIC = path.join(__dirname, '..', 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.webp': 'image/webp', '.jpg': 'image/jpeg' };
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'";
const FULL_TTL = 12 * 3600_000;

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function safe(fn, fallback) {
  try { return fn(); } catch (e) { console.error(e.message); return fallback; }
}

function sameKey(a, b) {
  const x = Buffer.from(String(a || ''));
  const y = Buffer.from(String(b || ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/** Сведения, которые видны только администратору, переносим из недавней полной проверки. */
function carryOverAdmin(facts, prev, nowMs = Date.now()) {
  if (!prev || !prev.facts || !prev.fullAt || nowMs - Date.parse(prev.fullAt) > FULL_TTL || facts.isAdmin) return null;
  const p = prev.facts;
  const pick = (sec, key) => {
    if (p[sec] && p[sec][key] != null && facts[sec] && facts[sec][key] == null) facts[sec][key] = p[sec][key];
  };
  pick('encryption', 'volumes');
  pick('boot', 'tpm');
  pick('boot', 'tpmSpec');
  pick('boot', 'bcdFirmware');
  pick('smb', 'feature');
  pick('firmware', 'vendor');
  // Новые разделы: всё, чего не видно без прав администратора (значение null), берём из полной проверки.
  for (const sec of ['hardening', 'physical', 'persistence', 'events', 'readiness', 'privacy', 'software']) {
    if (!p[sec] || !facts[sec] || typeof p[sec] !== 'object' || typeof facts[sec] !== 'object') continue;
    for (const k of Object.keys(p[sec])) if (k !== 'admin' && facts[sec][k] == null && p[sec][k] != null) facts[sec][k] = p[sec][k];
  }
  return prev.fullAt;
}

function createApp({ store, key, version, runner, autorun = { set: async () => {} }, openTarget = () => {}, now = () => Date.now(), guard = null, drills = null, canary = null, away = null, helper = null, licensePublicKey, realtime = null, notify = null, telegram = null, updateFetch = undefined, vault = null, wiper = null }) {
  const state = { busy: null, lastSeen: now(), progress: null, port: 0, alerts: [], quietUntil: 0 };
  // Свои изменения системы (исправление, откат, автозапуск, обновление программ) Страж в реальном времени не считает чужими.
  const QUIET_MS = 2 * 60_000;
  const hush = () => { state.quietUntil = Math.max(state.quietUntil, now() + QUIET_MS); };
  const watch = guard || createGuard(store, { now });

  function report() {
    return store.read('report.json', null);
  }

  async function runCheck(full = false) {
    if (state.busy) throw new HttpError(409, t('Уже идёт проверка'));
    state.busy = full ? 'full' : 'check';
    try {
      // С помощником администратора полная проверка идёт без окна UAC: её делает он сам.
      let viaHelper = false;
      if (full && helper) {
        try { await helper.refresh(); viaHelper = true; } catch (e) { if (e.code !== 'HELPER_UNAVAILABLE') console.error('Помощник:', e.message); }
      }
      const facts = await runner.collect(full && !viaHelper);
      if (!facts || facts.format !== 'adamant-facts') throw new Error(t('Сценарий проверки вернул неожиданный ответ'));
      digestFacts(facts);
      const prev = report();
      let helperAt = null;
      if (helper && !facts.isAdmin) {
        try {
          const [hf, hs] = await Promise.all([helper.readFull(), helper.readSecurity()]);
          const m = mergeHelper(facts, { full: hf, security: hs });
          helperAt = m && m.fullAt;
        } catch (e) { console.error('Помощник:', e.message); }
      }
      const carried = facts.isAdmin ? null : carryOverAdmin(facts, prev, now());
      const fullAt = facts.isAdmin ? new Date(now()).toISOString() : [helperAt, carried].filter(Boolean).sort().pop() || null;
      const findings = evaluate(facts, { now: now() });
      const before = new Set(((prev && prev.findings) || []).filter((f) => f.sev === 'critical' || f.sev === 'high').map((f) => f.id));
      // Страж: сравнение со «слепком» системы. Сбой Стража не должен ломать проверку.
      let guardRes = { first: false, changes: [] };
      // Свои изменения «Адаманта» - «Это я» для них не нужно: задания проверенного помощника
      // и автозапуск значка, пока включена работа в фоне (оба - только с точной командой).
      const own = [];
      if (helper && typeof helper.trust === 'function' && helper.paths) {
        try { if ((await helper.trust()).trusted) own.push(ownTaskMatcher(helper.paths, HELPER_TASKS)); } catch { /* помощник не проверился - как чужие */ }
      }
      if (autorun.name && autorun.command && store.read('settings.json', {}).background === true) {
        own.push(ownAutorunMatcher(autorun.name, autorun.command));
        if (autorun.legacyCommand) own.push(ownAutorunMatcher(autorun.name, autorun.legacyCommand));
      }
      const isOwn = own.length ? (c) => own.some((m) => m(c)) : null;
      try { guardRes = watch.update(facts, { isOwn }) || guardRes; } catch (e) { console.error('Страж:', e.message); }
      const at = new Date(now()).toISOString();
      const summary = summarize(findings);
      const sc = score(findings);
      const r = {
        at, full: !!facts.isAdmin, fullAt, helper: facts.helper || null, facts, findings, summary, score: sc,
        guard: { first: !!guardRes.first, changes: (guardRes.changes || []).length, important: (guardRes.changes || []).filter((c) => c.sev === 'high').length },
        newAlerts: [
          ...findings.filter((f) => (f.sev === 'critical' || f.sev === 'high') && !before.has(f.id)).map((f) => f.id),
          ...(guardRes.changes || []).filter((c) => c.sev === 'high').map((c) => `guard:${c.kind}:${c.key}`),
        ],
      };
      store.write('report.json', r);
      store.write('history.json', pushHistory(store.read('history.json', []), { at, value: sc.value, critical: summary.critical, high: summary.high }));
      return r;
    } catch (e) {
      if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
      throw e;
    } finally {
      state.busy = null;
      hush();
    }
  }

  function currentFacts() {
    const r = report();
    if (!r) throw new HttpError(409, t('Сначала проведите проверку'));
    return r.facts;
  }

  async function applyFix({ id, arg }) {
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    const facts = currentFacts();
    bulkPorts(id, arg);
    let a;
    try {
      a = fixes.validate(id, facts, arg);
    } catch (e) {
      throw new HttpError(400, e.message);
    }
    const p = fixes.plan(id, facts, a);
    state.busy = 'fix';
    try {
      const res = await runner.fix(fixes.scriptArgs('apply', { id, arg: a }));
      if (res && res.ok && res.record) {
        store.addJournal({ record: res.record, id, title: p.title, arg: a, at: new Date(now()).toISOString(), changes: res.changes || [], reboot: !!res.reboot });
      }
      return res;
    } catch (e) {
      if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
      throw e;
    } finally {
      state.busy = null;
      hush();
    }
  }

  async function undoFix({ record }) {
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    const entry = store.journal().find((e) => e.record === record);
    if (!entry) throw new HttpError(404, t('Запись не найдена в журнале'));
    if (entry.undoneAt) throw new HttpError(409, t('Это исправление уже откачено'));
    state.busy = 'undo';
    try {
      const res = await runner.fix(fixes.scriptArgs('undo', { record }));
      if (res && res.ok) store.updateJournal(record, { undoneAt: new Date(now()).toISOString(), undoChanges: res.changes || [] });
      return res;
    } catch (e) {
      if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
      throw e;
    } finally {
      state.busy = null;
      hush();
    }
  }

  async function subnets() {
    let adapters = null;
    try { adapters = await runner.adapters(); } catch { adapters = null; }
    return netscan.subnets(adapters);
  }

  async function runScan({ selected }) {
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    if (!Array.isArray(selected) || !selected.length || selected.some((s) => typeof s !== 'string')) throw new HttpError(400, t('Не выбрана ни одна подсеть'));
    const subs = await subnets();
    state.busy = 'scan';
    state.progress = { done: 0, total: 1 };
    try {
      const result = await netscan.scan({
        subnets: subs, selected, neighbors: () => runner.neighbors(),
        probe: runner.probe, httpInfo: runner.httpInfo, names: runner.deviceNames,
        onProgress: (done, total) => { state.progress = { done, total }; },
      });
      const s = { at: new Date(now()).toISOString(), result, findings: netscan.networkFindings(result) };
      store.write('scan.json', s);
      // Имена, которые назвали сами устройства, - в список знакомых устройств (по MAC).
      updateDevices((devices) => {
        for (const h of result.hosts || []) {
          const mac = normMac(h.mac);
          if (!mac || !h.name) continue;
          devices[mac] = { ...(devices[mac] || { first: s.at }), last: s.at, ip: h.ip, name: h.name, nameSource: h.nameSource || null };
        }
      });
      return s;
    } catch (e) {
      throw new HttpError(400, e.message);
    } finally {
      state.busy = null;
      state.progress = null;
    }
  }

  // ---- Знакомые устройства своей сети: net-devices.json, ключ - MAC. { first, last, ip, name?, nameSource?, label? }
  // label - подпись, которую дал пользователь; name - имя, которое назвало само устройство или кэш DNS.
  const MAC_RE = /^[0-9A-F]{2}(-[0-9A-F]{2}){5}$/;
  function normMac(m) {
    const v = String(m || '').trim().toUpperCase().replace(/:/g, '-');
    return MAC_RE.test(v) && v !== 'FF-FF-FF-FF-FF-FF' && v !== '00-00-00-00-00-00' ? v : null;
  }
  function readDevices() {
    const prev = store.read('net-devices.json', null);
    return { exists: !!prev, devices: prev && prev.devices && typeof prev.devices === 'object' ? prev.devices : {} };
  }
  function updateDevices(fn) {
    const { devices } = readDevices();
    fn(devices);
    // Подписанные пользователем не вытесняются, остальные - самые свежие, всего до 500.
    const all = Object.entries(devices).sort((a, b) => (!!b[1].label - !!a[1].label) || String(b[1].last).localeCompare(String(a[1].last))).slice(0, 500);
    store.write('net-devices.json', { version: 1, devices: Object.fromEntries(all) });
    return devices;
  }
  function deviceLabel({ mac, label }) {
    const m = normMac(mac);
    if (!m) throw new HttpError(400, 'mac');
    if (label != null && typeof label !== 'string') throw new HttpError(400, 'label');
    const text = String(label || '').replace(/[\u0000-\u001f\u007f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 40);
    updateDevices((devices) => {
      const d = { ...(devices[m] || { first: new Date(now()).toISOString(), last: new Date(now()).toISOString() }) };
      if (text) d.label = text; else delete d.label;
      devices[m] = d;
    });
    if (lastTraffic && Array.isArray(lastTraffic.devices)) {
      for (const d of lastTraffic.devices) if (d.mac === m) d.label = text || null;
    }
    return { mac: m, label: text || null };
  }

  // ---- Сеть и трафик: по кнопке и при открытии раздела. В памяти: адреса сайтов - личное, на диск не пишем.
  let lastTraffic = null;
  let trafficRun = null;
  function runTraffic() {
    if (!runner.traffic) throw new HttpError(501, t('Проверка трафика недоступна'));
    if (trafficRun) return trafficRun;
    trafficRun = (async () => {
      const [raw, nb] = await Promise.all([runner.traffic(), runner.neighbors ? runner.neighbors().catch(() => null) : null]);
      const prev = readDevices();
      const res = traffic.analyse(raw, { neighbors: Array.isArray(nb) ? nb : null, known: prev.exists ? new Set(Object.keys(prev.devices)) : null, saved: prev.devices });
      // Знакомые устройства своей сети (MAC, последний адрес, имя) - чтобы отмечать новые и помнить имена.
      updateDevices((devices) => {
        for (const d of res.devices || []) {
          if (!d.mac) continue;
          const o = { ...(devices[d.mac] || { first: res.at }), last: res.at, ip: d.ip };
          if (d.nameSource === 'dns' && d.name) { o.name = d.name; o.nameSource = 'dns'; }
          devices[d.mac] = o;
        }
      });
      lastTraffic = res;
      return res;
    })().catch((e) => { throw new HttpError(500, e.message); }).finally(() => { trafficRun = null; });
    return trafficRun;
  }

  // ---- Роутер: пробросы портов по UPnP. По кнопке; результат - router.json.
  let routerRun = null;
  function runRouter() {
    if (!runner.router) throw new HttpError(501, t('Проверка роутера недоступна'));
    if (routerRun) return routerRun;
    routerRun = (async () => {
      const result = await runner.router();
      const facts = (report() && report().facts) || {};
      const listen = [...((facts.ports && facts.ports.tcp) || []), ...((facts.ports && facts.ports.udp) || [])];
      const r = { at: new Date(now()).toISOString(), result, findings: upnp.findings(result, { own: upnp.localAddresses(), listen }) };
      store.write('router.json', r);
      return r;
    })().catch((e) => { throw new HttpError(500, e.message); }).finally(() => { routerRun = null; });
    return routerRun;
  }

  // ---- Скачанные файлы: проверить антивирусом, показать в папке, в корзину. Только файлы из находок последней проверки.
  function downloadFile(p) {
    const r = report();
    const x = rulesDownloads.allowedPath(r && r.findings, p);
    if (!x) throw new HttpError(400, t('Этого файла нет в находках последней проверки'));
    return x;
  }
  async function scanDownload({ path: p }) {
    const x = downloadFile(p);
    if (!runner.avScan) throw new HttpError(501, t('Проверка антивирусом недоступна'));
    let res;
    try { res = await runner.avScan(x.path); } catch (e) { throw new HttpError(500, e.message); }
    if (res.failed) throw new HttpError(500, t('Антивирус Microsoft Defender не смог проверить файл. Если у вас другой антивирус, проверьте файл им.'));
    return { name: x.name, threats: res.threats, clean: res.clean };
  }
  async function trashDownload({ path: p }) {
    const x = downloadFile(p);
    const res = await runner.trash(x.path);
    if (!res || !res.ok) throw new HttpError(500, t('Не удалось переместить файл в корзину'));
    return { ok: true, name: x.name };
  }

  // ---- Обновление программ (winget). Список - upgrades.json; обновление идёт в фоне по одной программе.
  const upgrade = { running: false, total: 0, done: 0, current: null, results: [] };
  let listRun = null;
  function wingetError(e) {
    if (e && e.code === 'NO_WINGET') return new HttpError(501, t('На компьютере нет winget. Установите «Установщик приложений» (App Installer) из Microsoft Store.'), 'NO_WINGET');
    return new HttpError(500, e && e.message ? e.message : 'winget');
  }
  function listUpgrades() {
    if (!runner.wingetList) throw new HttpError(501, t('Обновление программ недоступно'));
    if (upgrade.running) throw new HttpError(409, t('Подождите: идёт обновление программ'));
    if (listRun) return listRun;
    listRun = (async () => {
      let items;
      try { items = await runner.wingetList(); } catch (e) { throw wingetError(e); }
      const r = { at: new Date(now()).toISOString(), items };
      store.write('upgrades.json', r);
      return r;
    })().finally(() => { listRun = null; });
    return listRun;
  }
  function startUpgrade({ ids }) {
    if (!runner.wingetUpgrade) throw new HttpError(501, t('Обновление программ недоступно'));
    if (upgrade.running || listRun) throw new HttpError(409, t('Подождите: идёт обновление программ'));
    const saved = store.read('upgrades.json', null);
    const known = new Map(((saved && saved.items) || []).map((x) => [x.id, x]));
    if (!Array.isArray(ids) || !ids.length || ids.length > 100 || ids.some((x) => typeof x !== 'string' || !known.has(x))) throw new HttpError(400, t('Сначала найдите обновления'));
    const queue = [...new Set(ids)];
    Object.assign(upgrade, { running: true, total: queue.length, done: 0, current: null, results: [], at: new Date(now()).toISOString() });
    (async () => {
      for (const id of queue) {
        upgrade.current = known.get(id).name;
        let res;
        try { res = await runner.wingetUpgrade(id); } catch (e) { res = { id, ok: false, reason: e.code === 'NO_WINGET' ? 'no-winget' : 'error', hex: null }; }
        upgrade.results.push({ ...res, name: known.get(id).name, available: known.get(id).available });
        upgrade.done += 1;
        if (res.ok) {
          const cur = store.read('upgrades.json', null);
          if (cur && Array.isArray(cur.items)) store.write('upgrades.json', { ...cur, items: cur.items.filter((x) => x.id !== id) });
        }
      }
    })().catch((e) => console.error('winget:', e.message)).finally(() => { upgrade.running = false; upgrade.current = null; hush(); });
    return upgradeStatus();
  }
  const upgradeStatus = () => ({ running: upgrade.running, total: upgrade.total, done: upgrade.done, current: upgrade.current, results: upgrade.results, at: upgrade.at || null });

  // ---- Полная версия: ключ в license.json, подпись проверяется на этом компьютере, без интернета.
  const licPub = license.publicKey(licensePublicKey);
  function currentLicense() {
    const saved = store.read('license.json', null);
    if (!saved || typeof saved.key !== 'string') return null;
    try { return license.parse(saved.key, { pub: licPub, now: now() }); } catch { return null; }
  }
  const licenseStatus = () => license.status(currentLicense());
  const paid = (f) => !!licenseStatus().features[f];
  /** «Закрыть лишнее» (несколько портов сразу) - в полной версии; по одному порту - во всех. */
  function bulkPorts(id, arg) {
    if (id === 'port-block' && arg && Array.isArray(arg.items) && arg.items.length > 1) needPaid('ports');
  }
  function needPaid(f) {
    if (!paid(f)) throw new HttpError(402, t('Это доступно в полной версии'), 'PAID');
  }
  function setLicense({ key }) {
    if (key === null) {
      store.write('license.json', { key: null });
      lastBluetooth = null;
      return licenseStatus();
    }
    if (typeof key !== 'string' || key.length > 4000) throw new HttpError(400, t('Это не ключ Адаманта: скопируйте его целиком, начиная с ADAMANT1.'));
    let lic;
    try { lic = license.parse(key, { pub: licPub, now: now() }); } catch (e) { throw new HttpError(400, e.message); }
    if (lic.expired) throw new HttpError(400, t('Срок действия ключа закончился'));
    store.write('license.json', { key: key.replace(/\s+/g, '') });
    lastBluetooth = null; // урезанный результат бесплатной версии больше не нужен
    return licenseStatus();
  }

  // ---- Bluetooth: по кнопке и при открытии раздела. Адреса чужих устройств рядом - только в памяти.
  // В бесплатной версии - только сопряжённые устройства и только тревога об устройстве для атак (угрозы не прячем).
  let lastBluetooth = null;
  let bluetoothRun = null;
  function runBluetooth() {
    if (!runner.bluetooth) throw new HttpError(501, t('Проверка Bluetooth недоступна'));
    if (bluetoothRun) return bluetoothRun;
    bluetoothRun = (async () => {
      const full = paid('bluetooth');
      let res = bluetooth.analyse(await runner.bluetooth(full ? 10 : 0));
      if (!full) {
        res = {
          at: res.at, limited: true, seconds: 0, radio: res.radio, adapter: res.adapter, paired: [], nearby: [],
          counts: { paired: res.counts.paired, nearby: 0, named: 0, trackers: 0, close: 0 }, errors: res.errors,
          findings: res.findings.filter((f) => f.id === 'bt-attack-paired'),
        };
      }
      lastBluetooth = res;
      return res;
    })().catch((e) => { throw new HttpError(500, e.message); }).finally(() => { bluetoothRun = null; });
    return bluetoothRun;
  }

  // ---- Чек-лист: пункты, состояние по находкам всех проверок и отметки пользователя (checklist.json).
  function allFindings() {
    const r = report();
    const sc = store.read('scan.json', null);
    return [
      ...((r && r.findings) || []),
      ...((sc && sc.findings) || []),
      ...((store.read('router.json', null) || {}).findings || []),
      ...((lastTraffic && lastTraffic.findings) || []),
      ...((lastBluetooth && lastBluetooth.findings) || []),
    ];
  }
  function checklistView() {
    const marks = checklist.cleanMarks(store.read('checklist.json', null));
    const found = allFindings();
    const items = checklist.ITEMS.map((i) => {
      const st = checklist.itemState(i, found);
      return { id: i.id, group: i.group, title: i.title, why: i.why, how: i.how, open: i.open || null, auto: !!(i.checks && i.checks.length), ...st, marked: marks[i.id] || null };
    });
    return { groups: checklist.GROUPS, items, checked: !!report() };
  }
  function markChecklist({ id, done }) {
    if (typeof id !== 'string' || !checklist.IDS.has(id)) throw new HttpError(400, 'id');
    if (typeof done !== 'boolean') throw new HttpError(400, 'done');
    const marks = checklist.cleanMarks(store.read('checklist.json', null));
    if (done) marks[id] = new Date(now()).toISOString();
    else delete marks[id];
    store.write('checklist.json', { version: 1, done: marks });
    return checklistView();
  }

  async function runDrills({ ids }) {
    if (!drills) throw new HttpError(501, t('Учения недоступны'));
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    if (ids != null && (!Array.isArray(ids) || ids.some((x) => typeof x !== 'string'))) throw new HttpError(400, 'ids');
    state.busy = 'drills';
    try {
      return await drills.run(ids || undefined);
    } finally {
      state.busy = null;
    }
  }

  /** Приманки для шифровальщиков: включить/выключить. Следят, пока работает программа (окно или значок в трее). */
  async function setCanary(on) {
    if (!canary) throw new HttpError(501, t('Приманки недоступны'));
    if (on) {
      await canary.arm();
      canary.watch();
    } else {
      canary.stop();
      await canary.disarm();
    }
    store.saveSettings({ canary: !!on });
    return canary.status();
  }

  /** Тревога (приманки, Страж в реальном времени, «Тревога»): окно, значок в трее и, если включено, Telegram. */
  function raiseAlert(alert) {
    const a = { id: crypto.randomUUID(), at: new Date(now()).toISOString(), ...alert };
    state.alerts.unshift(a);
    state.alerts = state.alerts.slice(0, 20);
    if (a.kind === 'guard' && Array.isArray(a.items)) {
      const log = store.read('realtime-log.json', []);
      store.write('realtime-log.json', [...a.items.map((x) => ({ at: a.at, kind: x.kind, change: x.change, text: x.text, detail: x.detail || null })), ...log].slice(0, 200));
    }
    if (notify) Promise.resolve().then(() => notify(a)).catch((e) => console.error('Уведомление:', e.message));
    return a;
  }
  /** Короткий текст тревоги на языке пользователя (значок в трее, Telegram). */
  function alertText(lang, a) {
    if (a.kind === 'guard') {
      const items = a.items || [];
      const first = items[0] ? render(lang, items[0].text) : '';
      return render(lang, items.length > 1 ? tx('Страж: {0} (и ещё {1})', first, items.length - 1) : tx('Страж: {0}', first));
    }
    if (a.kind === 'panic') return render(lang, t('Нажата «Тревога»: компьютер отключён от сети.'));
    return render(lang, t('Тревога: кто-то изменил файлы-приманки. Так ведут себя программы-шифровальщики.'));
  }
  // ---- «Тревога»: отключить компьютер от сети одной кнопкой (с правами администратора) и вернуть сеть.
  async function panic({ mode }) {
    // Вернуть сеть можно всегда (даже если ключ закончился), отключить - только в полной версии.
    if (mode !== 'restore') needPaid('panic');
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    if (!runner.panic) throw new HttpError(501, t('«Тревога» недоступна'));
    const prev = store.read('panic.json', null);
    if (mode === 'restore') {
      if (!prev || !prev.active) throw new HttpError(409, t('Сеть не отключалась «Тревогой»'));
      state.busy = 'panic';
      try {
        const res = await runner.panic('restore', (prev.adapters || []).map((a) => a.name).filter(Boolean));
        const failed = (res && res.failed) || [];
        // Не включился ни один адаптер - оставляем «отключено», чтобы кнопка «Вернуть сеть» не пропала.
        const back = (res && res.adapters) || [];
        if (back.length || !failed.length) store.write('panic.json', { ...prev, active: false, restoredAt: new Date(now()).toISOString(), restoreFailed: failed });
        else store.write('panic.json', { ...prev, restoreFailed: failed });
        return { ok: !!(res && res.ok), failed, panic: store.read('panic.json', null) };
      } catch (e) {
        if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
        throw e;
      } finally {
        state.busy = null;
        hush();
      }
    }
    if (prev && prev.active) throw new HttpError(409, t('Компьютер уже отключён от сети'));
    // Сообщение в Telegram (если включено) - до отключения, пока связь ещё есть.
    if (notify) Promise.resolve().then(() => notify({ kind: 'panic', at: new Date(now()).toISOString() })).catch(() => {});
    state.busy = 'panic';
    try {
      const res = await runner.panic('isolate');
      const adapters = (res && res.adapters) || [];
      const rec = { active: adapters.length > 0, at: new Date(now()).toISOString(), adapters, failed: (res && res.failed) || [], none: !!(res && res.none), processes: ((res && res.processes) || []).slice(0, 40) };
      store.write('panic.json', rec);
      return { ok: !!(res && res.ok), panic: rec };
    } catch (e) {
      if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
      throw e;
    } finally {
      state.busy = null;
      hush();
    }
  }

  // ---- Telegram (полная версия, выключено по умолчанию).
  function tgCall(fn) {
    if (!telegram) throw new HttpError(501, t('Уведомления в Telegram недоступны'));
    return Promise.resolve().then(fn).catch((e) => {
      if (e && e.code && telegram.REASON && telegram.REASON[e.code]) throw new HttpError(400, telegram.REASON[e.code], 'TG_' + e.code);
      if (e && (e.code === 'FORMAT' || e.code === 'SETUP')) throw new HttpError(400, e.message, 'TG_' + e.code);
      throw e;
    });
  }

  /** Для Стража в реальном времени: идёт своё изменение? и что считать своим. */
  const isQuiet = () => state.busy === 'fix' || state.busy === 'undo' || upgrade.running || now() < state.quietUntil;
  function ownChanges() {
    const bg = store.read('settings.json', {}).background === true;
    return {
      autorun: bg && autorun.name && autorun.command ? { name: autorun.name, command: autorun.command } : null,
      helperDir: helper && helper.paths ? helper.paths.program : null,
    };
  }

  // ------------------------------------------------------------ HTTP

  // Список файлов окна составляется один раз при запуске: отдаются только они (public/ и public/img/).
  const files = new Map();
  for (const dir of ['', 'img']) {
    const abs = path.join(PUBLIC, dir);
    if (!fs.existsSync(abs)) continue;
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      const ext = path.extname(e.name);
      if (e.isFile() && TYPES[ext]) files.set('/' + (dir ? dir + '/' : '') + e.name, { file: path.join(abs, e.name), type: TYPES[ext] });
    }
  }

  function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    res.writeHead(status, {
      'Content-Type': type, 'Content-Length': buf.length, 'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
      'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin', ...extra,
    });
    res.end(buf);
  }

  function readJson(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > 65536) {
          reject(new HttpError(413, 'too large'));
          req.destroy();
        } else chunks.push(c);
      });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(new HttpError(400, 'bad json'));
        }
      });
      req.on('error', reject);
    });
  }

  async function helperOp(fn) {
    if (!helper) throw new HttpError(501, t('Помощник администратора недоступен'));
    if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
    state.busy = 'helper';
    try {
      const result = await fn();
      return { result, status: await helper.status({ force: true }) };
    } catch (e) {
      if (e.code === 'CANCELLED') throw new HttpError(400, t('Запрос прав администратора отклонён'), 'CANCELLED');
      throw e;
    } finally {
      state.busy = null;
      hush();
    }
  }

  const awayCall = (fn) => {
    if (!away) throw new HttpError(501, t('Раздел «Пока вас не было» недоступен'));
    try { return fn(); } catch (e) { if (e && e.status === 400) throw new HttpError(400, e.message); throw e; }
  };

  const routes = {
    'GET /api/state': () => ({
      version, settings: store.settings(), report: report(), scan: store.read('scan.json', null), router: store.read('router.json', null),
      journal: store.journal(), busy: state.busy, openTargets: Object.keys(OPEN_TARGETS),
      history: store.read('history.json', []),
      guard: safe(() => ({ weekly: watch.weekly(), log: watch.log({ days: 60 }) }), null),
      drills: drills ? safe(() => drills.last(), null) : null,
      canary: canary ? safe(() => canary.status(), null) : null,
      drillList: safe(() => require('./drills').DRILLS || [], []),
      license: licenseStatus(),
      bitlockerPlan: !paid('entry') ? null : safe(() => require('./bitlocker-plan').plan((report() && report().facts) || {}), null),
      alerts: state.alerts,
      realtime: realtime ? { ...safe(() => realtime.status(), {}), log: store.read('realtime-log.json', []).slice(0, 50) } : null,
      away: away && paid('away') ? safe(() => away.report({ days: 14 }), null) : null,
      panic: store.read('panic.json', null),
      ports: safe(() => (report() ? require('./ports').annotate(report().facts, store.journal()) : null), null),
      telegram: telegram ? safe(() => telegram.status(), null) : null,
      vault: vault ? safe(() => vault.state(), null) : null,
    }),
    // Ключ данных пропал или не открылся: старые файлы - в unreadable-<время>, новый ключ, данные из памяти сохраняются.
    'POST /api/vault/reset': async () => {
      if (!vault) throw new HttpError(400, t('Шифрование данных выключено'));
      const st = await vault.reset();
      return { vault: st };
    },
    // «Уничтожить данные»: только со словом из окна. После этого программа закрывается и удаляет папку данных.
    'POST /api/wipe': async (b) => {
      if (!wiper) throw new HttpError(501, t('Уничтожение данных недоступно'));
      if (!require('./wipe').wordOk(b && b.word)) throw new HttpError(400, t('Введите слово УНИЧТОЖИТЬ, чтобы подтвердить'));
      if (state.busy) throw new HttpError(409, t('Подождите: идёт другая операция'));
      state.busy = 'wipe';
      try {
        const r = await wiper.run({ admin: !!(b && b.admin === true) });
        // Данных больше нет: проверки и исправления до закрытия программы не запускаются.
        state.busy = 'wiped';
        return r;
      } catch (e) {
        state.busy = null;
        throw e instanceof HttpError ? e : new HttpError(500, e.message);
      }
    },
    'POST /api/panic': (b) => panic({ mode: (b && b.mode) === 'restore' ? 'restore' : 'isolate' }),
    'GET /api/telegram': () => tgCall(() => telegram.status()),
    'POST /api/telegram': (b) => {
      const p = b || {};
      if ((typeof p.token === 'string' && p.token.trim()) || p.enabled === true) needPaid('telegram');
      return tgCall(() => {
      return telegram.save({ token: typeof p.token === 'string' ? p.token : undefined, enabled: typeof p.enabled === 'boolean' ? p.enabled : undefined, events: p.events && typeof p.events === 'object' ? p.events : undefined, forget: p.forget === true });
      });
    },
    'POST /api/telegram/find-chat': () => { needPaid('telegram'); return tgCall(() => telegram.findChat()); },
    'POST /api/telegram/test': () => { needPaid('telegram'); return tgCall(async () => { await telegram.test(); return telegram.status(); }); },
    'GET /api/license': () => licenseStatus(),
    'POST /api/license': (b) => setLicense(b || {}),
    'GET /api/helper': () => (helper ? helper.status() : null),
    'POST /api/helper/install': () => helperOp(() => helper.install({ userSid: report() && report().facts && report().facts.meta ? report().facts.meta.userSid : undefined })),
    'POST /api/helper/uninstall': () => helperOp(() => helper.uninstall()),
    'POST /api/away/event': (b) => { needPaid('away'); return awayCall(() => away.event(b)); },
    'POST /api/away/photo': (b) => { needPaid('away'); return awayCall(() => away.photoDone(b)); },
    'POST /api/away/ack': (b) => awayCall(() => away.acknowledge(b.ids)),
    'POST /api/away/photo-data': (b) => awayCall(() => ({ data: away.photoData(String(b.id || '')) })),
    'POST /api/guard/ack': (b) => {
      if (!Array.isArray(b.ids) || b.ids.some((x) => typeof x !== 'string')) throw new HttpError(400, 'ids');
      watch.acknowledge(b.ids);
      return { ok: true };
    },
    'POST /api/drills/run': (b) => { needPaid('drills'); return runDrills({ ids: b.ids }); },
    'POST /api/canary': (b) => { if (b.on) needPaid('drills'); return setCanary(!!b.on); },
    'POST /api/alerts/ack': () => {
      state.alerts = [];
      return { ok: true };
    },
    'POST /api/check': (b) => runCheck(!!b.full),
    'POST /api/fix/plan': (b) => {
      bulkPorts(String(b.id || ''), b.arg);
      try {
        return fixes.plan(String(b.id || ''), currentFacts(), b.arg);
      } catch (e) {
        if (e instanceof HttpError) throw e;
        throw new HttpError(400, e.message);
      }
    },
    'POST /api/fix/apply': (b) => applyFix({ id: String(b.id || ''), arg: b.arg }),
    'POST /api/fix/undo': (b) => undoFix({ record: String(b.record || '') }),
    'POST /api/guide': (b) => {
      const g = guide(String(b.id || ''), report() && report().facts);
      if (!g) throw new HttpError(404, t('Инструкция не найдена'));
      return g;
    },
    // Только по кнопке «Проверить обновления»: один запрос списка выпусков на GitHub, ничего не скачивается.
    'POST /api/update/check': async () => {
      try {
        return await require('./update').check({ version, fetch: updateFetch });
      } catch (e) {
        throw new HttpError(502, e.message);
      }
    },
    'POST /api/open': (b) => {
      if (!Object.hasOwn(OPEN_TARGETS, String(b.target))) throw new HttpError(400, t('Неизвестное окно'));
      openTarget(String(b.target));
      return { ok: true };
    },
    'GET /api/net/subnets': () => subnets(),
    'POST /api/net/scan': (b) => runScan({ selected: b.selected }),
    'GET /api/net/progress': () => ({ busy: state.busy, progress: state.progress }),
    'GET /api/net/traffic': () => ({ traffic: lastTraffic }),
    'POST /api/net/traffic': () => runTraffic(),
    'POST /api/net/device-label': (b) => deviceLabel(b || {}),
    'POST /api/net/router': () => runRouter(),
    'GET /api/apps': () => ({ list: store.read('upgrades.json', null), progress: upgradeStatus() }),
    'POST /api/apps/list': () => listUpgrades(),
    'POST /api/apps/upgrade': (b) => startUpgrade(b || {}),
    'POST /api/downloads/scan': (b) => scanDownload(b || {}),
    'POST /api/downloads/reveal': (b) => { const x = downloadFile((b || {}).path); runner.reveal(x.path); return { ok: true }; },
    'POST /api/downloads/trash': (b) => trashDownload(b || {}),
    'GET /api/bluetooth': () => ({ bluetooth: lastBluetooth }),
    'POST /api/bluetooth': () => runBluetooth(),
    'GET /api/checklist': () => checklistView(),
    'POST /api/checklist': (b) => markChecklist(b || {}),
    'POST /api/settings': async (b) => {
      if (b && (b.away === true || b.awayPhoto === true)) needPaid('away');
      if (b && b.realtime === true) needPaid('realtime');
      const before = store.settings();
      const s = store.saveSettings(b || {});
      if (realtime && realtime.sync) safe(() => realtime.sync(), null);
      if (s.background !== before.background) {
        hush();
        try {
          await autorun.set(s.background);
        } catch (e) {
          store.saveSettings({ background: before.background });
          throw new HttpError(500, e.message);
        }
      }
      return s;
    },
    'POST /api/heartbeat': () => ({ ok: true, busy: state.busy, alerts: state.alerts.length }),
    'GET /api/tray': () => {
      const r = report();
      const s = store.settings();
      return { lang: s.lang, exit: !s.background, busy: state.busy, at: r ? r.at : null, summary: r ? r.summary : null, newAlerts: r ? r.newAlerts || [] : [], alerts: state.alerts.map((x) => x.id),
        alertInfo: state.alerts.map((x) => ({ id: x.id, kind: x.kind || 'canary', text: alertText(s.lang, x) })),
        away: !!(away && s.away && paid('away')),
        photo: away ? safe(() => { const p = away.photoRequest(); return p ? p.id : null; }, null) : null,
      };
    },
    'POST /api/tray/check': () => {
      runCheck(false).catch(() => {});
      return { ok: true };
    },
    'POST /api/shutdown': () => {
      setTimeout(() => process.emit('adamant-shutdown'), 50);
      return { ok: true };
    },
  };

  async function handle(req, res) {
    const url = new URL(req.url, 'http://127.0.0.1');
    const host = String(req.headers.host || '');
    if (state.port && host !== `127.0.0.1:${state.port}` && host !== `localhost:${state.port}`) return send(res, 421, { error: 'host' });
    if (req.method === 'GET' && url.pathname === '/api/status') return send(res, 200, { app: 'adamant', version });
    if (!url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'method' });
      const f = files.get(url.pathname === '/' ? '/index.html' : url.pathname);
      if (!f) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
      return send(res, 200, fs.readFileSync(f.file), f.type);
    }
    if (!sameKey(req.headers['x-adamant-key'], key)) return send(res, 401, { error: 'key' });
    if (req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && state.port && origin !== `http://127.0.0.1:${state.port}` && origin !== `http://localhost:${state.port}`) return send(res, 403, { error: 'origin' });
      if (!/^application\/json\b/.test(String(req.headers['content-type'] || ''))) return send(res, 415, { error: 'type' });
    }
    state.lastSeen = now();
    if (req.method === 'GET' && url.pathname === '/api/report.html') {
      const lang = store.settings().lang;
      const r = report();
      const html = reportHtml({ report: r, scan: store.read('scan.json', null), lang, version });
      const name = `adamant-report-${(r && r.facts && r.facts.meta && r.facts.meta.computer) || 'pc'}-${new Date(now()).toISOString().slice(0, 10)}.html`.replace(/[^A-Za-z0-9._-]/g, '_');
      return send(res, 200, html, 'text/html; charset=utf-8', { 'Content-Disposition': `attachment; filename="${name}"` });
    }
    const fn = routes[`${req.method} ${url.pathname}`];
    if (!fn) return send(res, 404, { error: 'not found' });
    try {
      const body = req.method === 'POST' ? await readJson(req) : {};
      send(res, 200, (await fn(body || {})) ?? null);
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      send(res, status, { error: render('ru', e.message), code: e.code || null });
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      try { send(res, 500, { error: e.message }); } catch { /* ответ уже ушёл */ }
    });
  });
  server.on('listening', () => {
    state.port = server.address().port;
  });
  return { server, state, runCheck, applyFix, undoFix, runScan, runDrills, setCanary, raiseAlert, alertText, isQuiet, ownChanges, paid, licenseStatus, report, guard: watch };
}

module.exports = { createApp, carryOverAdmin, sameKey, CSP };
