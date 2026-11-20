'use strict';
/**
 * «Учения»: безопасные пробные атаки, которые показывают, что защита действительно срабатывает.
 *   eicar    - учебный «вирус» EICAR во временной папке (server/ps/drill.ps1);
 *   amsi     - учебный «вредный» сценарий PowerShell (drill.ps1);
 *   cfa      - попытка записать файл в «Документы», как это делает шантажист (drill.ps1);
 *   exposure - «взгляд соседа»: какие порты этот компьютер принимает на своём адресе в домашней сети.
 * Ни одна проверка не меняет настройки и не обращается к другим компьютерам.
 * Последний результат - в папке данных, файл drills.json.
 */
const { tx, t } = require('./i18n');
const { isPrivate } = require('./netscan');
const { isLoopback, isAnyAddr } = require('./rules');

const DRILLS = [
  {
    id: 'eicar',
    title: t('Учебный вирус'),
    what: t('«Адамант» кладёт в свою временную папку стандартный учебный файл EICAR и смотрит, как быстро антивирус его уберёт.'),
    why: t('EICAR - это не вирус, а короткая строка текста, которую все антивирусы договорились считать «вирусом» для проверки. Файл ничего не умеет делать, а папку «Адамант» удаляет сам. Антивирус может показать уведомление об угрозе - так и должно быть.'),
  },
  {
    id: 'amsi',
    title: t('Учебный вредный сценарий'),
    what: t('«Адамант» запускает PowerShell с учебной строкой AMSI. Антивирус должен остановить такой сценарий ещё до запуска.'),
    why: t('Строка ничего не делает: это общепринятая метка для проверки антивирусов. Так проверяется защита от вредных сценариев, которые не оставляют файлов на диске.'),
  },
  {
    id: 'cfa',
    title: t('Шантажист в «Документах»'),
    what: t('«Адамант» пробует записать маленький текстовый файл в «Документы» так, как это сделала бы незнакомая программа.'),
    why: t('Если включён контролируемый доступ к папкам, Windows не даст записать файл. Если файл всё же записался, «Адамант» сразу его удаляет. Если защита выключена, файл не создаётся.'),
  },
  {
    id: 'exposure',
    title: t('Взгляд соседа по сети'),
    what: t('«Адамант» подключается к своему же адресу в домашней сети и смотрит, какие службы принимают подключения.'),
    why: t('Подключения идут только к этому компьютеру, к другим устройствам - нет. Ничего не меняется.'),
  },
];
const IDS = DRILLS.map((d) => d.id);
const STATUSES = ['passed', 'failed', 'skipped', 'error'];

// ---------------------------------------------------------------- Взгляд соседа

/** Службы, которые соседу по сети лучше не видеть. always - опасно всегда, sharing - опасно без брандмауэра. */
const RISKY = {
  21: { name: 'FTP', kind: 'always' },
  23: { name: 'Telnet', kind: 'always' },
  135: { name: 'RPC', kind: 'sharing' },
  139: { name: 'NetBIOS', kind: 'sharing' },
  445: { name: 'SMB', kind: 'sharing' },
  1433: { name: 'SQL Server', kind: 'always' },
  3306: { name: 'MySQL', kind: 'always' },
  3389: { name: 'RDP', kind: 'always', fix: 'rdp-off' },
  5432: { name: 'PostgreSQL', kind: 'always' },
  5900: { name: 'VNC', kind: 'always' },
  5901: { name: 'VNC', kind: 'always' },
  5938: { name: 'TeamViewer', kind: 'always' },
  5985: { name: 'WinRM', kind: 'always' },
  5986: { name: 'WinRM', kind: 'always' },
  6379: { name: 'Redis', kind: 'always' },
  7070: { name: 'AnyDesk', kind: 'always' },
  9200: { name: 'Elasticsearch', kind: 'always' },
  11211: { name: 'Memcached', kind: 'always' },
  21118: { name: 'RustDesk', kind: 'always' },
  27017: { name: 'MongoDB', kind: 'always' },
};

/** Несколько сообщений через пробел (каждое переводится отдельно). */
const joinMsgs = (msgs) => msgs.reduce((a, m) => (a == null ? m : tx('{0} {1}', a, m)), null);
const arr = (x) => (x == null ? [] : Array.isArray(x) ? x : [x]);

/** Свои частные IPv4-адреса (только из списка адаптеров этого компьютера). */
function ownPrivateIps(adapters) {
  const up = arr(adapters).filter((a) => a && isPrivate(String(a.address)) && (a.status == null || a.status === '' || a.status === 'Up'));
  const physical = up.filter((a) => !a.virtual && a.hardware !== false);
  return [...new Set((physical.length ? physical : up).map((a) => String(a.address)))];
}

/** Брандмауэр включён во всех профилях? null - неизвестно. */
function firewallOn(facts) {
  const profiles = arr(facts && facts.firewall && facts.firewall.profiles);
  if (!profiles.length) return null;
  return profiles.every((p) => String(p.enabled) === 'True');
}

/**
 * Как этот компьютер видит сосед по сети. Подключается ТОЛЬКО к своим частным адресам
 * из adapters и только к портам, которые слушает этот компьютер (facts.ports.tcp).
 * Подключение к своему адресу изнутри брандмауэр Windows не фильтрует, поэтому
 * результат - «что принимает подключения на сетевом адресе», а с брандмауэром соседу может быть видно меньше.
 */
async function exposure({ facts, adapters, probe, timeout = 800, now = () => Date.now() } = {}) {
  const started = now();
  const done = (status, detail, extra = {}) => ({ drill: 'exposure', status, ms: Math.max(0, now() - started), detail, ...extra });
  if (typeof probe !== 'function') throw new Error('probe required');
  const tcp = arr(facts && facts.ports && facts.ports.tcp);
  if (!facts || !facts.ports) return done('skipped', t('Нет сведений об открытых портах: сначала запустите проверку компьютера.'));
  const own = ownPrivateIps(adapters);
  if (!own.length) return done('skipped', t('У компьютера нет адреса в домашней или офисной сети - соседям по сети он не виден.'));
  const ownSet = new Set(own);
  // Порт → адреса, на которые его проверять, и программы, которые его слушают.
  const byPort = new Map();
  for (const p of tcp) {
    const port = Number(p && p.port);
    const addr = String((p && p.addr) || '');
    if (!Number.isInteger(port) || port < 1 || port > 65535 || isLoopback(addr)) continue;
    let ips;
    if (isAnyAddr(addr)) ips = own;
    else if (ownSet.has(addr)) ips = [addr];
    else continue; // слушает другой адрес (виртуальный адаптер, IPv6) - с домашней сети его не видно
    if (!byPort.has(port)) byPort.set(port, { port, ips: new Set(), procs: new Set() });
    const e = byPort.get(port);
    ips.forEach((ip) => e.ips.add(ip));
    if (p.proc) e.procs.add(String(p.proc));
  }
  const jobs = [...byPort.values()].flatMap((e) => [...e.ips].map((ip) => ({ e, ip })));
  const open = new Map();
  let i = 0;
  const workers = Array.from({ length: Math.min(16, jobs.length) }, async () => {
    while (i < jobs.length) {
      const { e, ip } = jobs[i++];
      if (!ownSet.has(ip) || !isPrivate(ip)) continue; // только свои частные адреса
      let r = 'filtered';
      try { r = await probe(ip, e.port, timeout); } catch { r = 'filtered'; }
      if (r === 'open') {
        if (!open.has(e.port)) open.set(e.port, { port: e.port, ips: [], procs: [...e.procs].sort() });
        open.get(e.port).ips.push(ip);
      }
    }
  });
  await Promise.all(workers);
  const fw = firewallOn(facts);
  const reachable = [...open.values()].sort((a, b) => a.port - b.port).map((x) => {
    const r = RISKY[x.port];
    const risky = !!r && (r.kind === 'always' || fw !== true);
    return { port: x.port, name: r ? r.name : '', ips: x.ips.sort(), procs: x.procs, risky };
  });
  const risky = reachable.filter((x) => x.risky);
  const list = (xs) => xs.map((x) => `${x.port}${x.name ? ` (${x.name})` : ''}${x.procs.length ? ` - ${x.procs.join(', ')}` : ''}`).join('; ');
  const extra = { reachable, checked: jobs.length, addresses: own, firewall: fw };
  if (!risky.length) {
    const detail = reachable.length
      ? tx('Опасных служб на сетевом адресе нет. Принимают подключения: {0}.', list(reachable))
      : t('На сетевом адресе компьютера ни одна служба не принимает подключения.');
    return done('passed', detail, extra);
  }
  const fwNote = fw === true
    ? t('Брандмауэр включён и может закрывать часть этих портов для соседей, но изнутри компьютера это не проверить.')
    : t('Брандмауэр выключен или его состояние неизвестно - эти службы, скорее всего, видны всем в сети.');
  const advice = [];
  let fix = null;
  if (fw !== true) {
    advice.push(t('Включите брандмауэр Windows (кнопка «Исправить…» у находки о брандмауэре).'));
    fix = 'firewall-on';
  }
  if (risky.some((x) => x.port === 3389)) {
    advice.push(t('Если удалённый рабочий стол не нужен, выключите его (кнопка «Исправить…» у находки о RDP).'));
    fix = fix || 'rdp-off';
  }
  advice.push(t('Закройте программы из списка, которые вам не нужны, или запретите им входящие подключения в брандмауэре.'));
  return done('failed', tx('Компьютер принимает подключения к опасным службам: {0}. {1}', list(risky), fwNote), {
    ...extra, advice: joinMsgs(advice), fix, guide: 'local-service',
  });
}

// ---------------------------------------------------------------- Результаты drill.ps1 → понятный текст

const sec = (ms) => (Math.max(0, Number(ms) || 0) / 1000).toFixed(1);

function errorText(detail) {
  const d = String(detail || '');
  if (d === 'timeout') return t('Проверка не уложилась во время и остановлена.');
  if (d === 'no-documents') return t('Не найдена папка «Документы».');
  return tx('Учения не удалось провести: {0}', d.replace(/^no-result:\s*/, '') || t('нет ответа'));
}

/** Сырой ответ учения → { status, detail, advice, fix?, open? }. */
function describe(id, raw) {
  const st = raw && STATUSES.includes(raw.status) ? raw.status : 'error';
  const d = raw ? String(raw.detail || '') : '';
  const out = { status: st, detail: null, advice: null };
  if (st === 'error') {
    out.detail = errorText(raw ? raw.detail : '');
    return out;
  }
  if (id === 'eicar') {
    if (st === 'passed') {
      out.detail = d === 'blocked-write'
        ? t('Антивирус не дал даже записать учебный файл.')
        : tx('Антивирус убрал учебный файл через {0} с.', sec(raw.ms));
      if (raw.threat) out.detail = tx('{0} Название угрозы: {1}.', out.detail, String(raw.threat).slice(0, 120));
    } else if (st === 'failed') {
      out.detail = t('Учебный файл пролежал 15 секунд, и антивирус его не тронул: защита в реальном времени не следит за файлами.');
      out.advice = t('Включите защиту в реальном времени (кнопка «Исправить…» у находки о Microsoft Defender) и повторите учения. Если стоит другой антивирус, проверьте, что он включён и его лицензия не истекла.');
      out.fix = 'defender-realtime';
    } else {
      out.detail = t('Учения пропущены.');
    }
    if (raw.cleaned === false) out.detail = tx('{0} Временную папку удалить не удалось - она в %TEMP%, папка Adamant-drill-….', out.detail);
  } else if (id === 'amsi') {
    if (st === 'passed') out.detail = t('Антивирус остановил сценарий PowerShell до запуска.');
    else if (st === 'failed') {
      out.detail = t('Сценарий с учебной строкой выполнился: антивирус не проверяет сценарии PowerShell перед запуском.');
      out.advice = t('Включите защиту в реальном времени в Microsoft Defender. Если стоит другой антивирус, узнайте у его производителя, поддерживает ли он проверку сценариев (AMSI).');
      out.fix = 'defender-realtime';
    } else out.detail = t('Учения пропущены.');
  } else if (id === 'cfa') {
    if (st === 'passed') out.detail = t('Windows не дала незнакомой программе записать файл в «Документы».');
    else if (st === 'failed') {
      out.detail = t('Файл записался в «Документы», хотя контролируемый доступ к папкам включён. Скорее всего, PowerShell добавлен в разрешённые программы. Файл уже удалён.');
      if (raw.cleaned === false) out.detail = t('Файл записался в «Документы», хотя контролируемый доступ к папкам включён. Удалить его не удалось: это файл Adamant-check-….txt, его можно удалить вручную.');
      out.advice = t('Откройте «Безопасность Windows» → «Защита от программ-шантажистов» → «Разрешить работу приложения через контролируемый доступ к папкам» и уберите из списка лишнее.');
      out.open = 'ransomware';
    } else if (d === 'audit') {
      out.detail = t('Контролируемый доступ к папкам работает в режиме аудита: он только записывает попытки, но не мешает им.');
      out.advice = t('Переключите контролируемый доступ к папкам в режим блокировки (кнопка «Исправить…» или «Безопасность Windows» → «Защита от программ-шантажистов»).');
      out.fix = 'cfa-on';
      out.open = 'ransomware';
    } else if (d === 'off') {
      out.detail = t('Контролируемый доступ к папкам выключен: программа-шантажист сможет зашифровать «Документы». Поэтому файл не записывался.');
      out.advice = t('Включите контролируемый доступ к папкам (кнопка «Исправить…» или «Безопасность Windows» → «Защита от программ-шантажистов»).');
      out.fix = 'cfa-on';
      out.open = 'ransomware';
    } else {
      out.detail = t('Не удалось узнать, включён ли контролируемый доступ к папкам. Возможно, стоит другой антивирус.');
    }
  } else if (id === 'exposure') {
    out.detail = raw.detail || null;
    out.advice = raw.advice || null;
    if (raw.fix) out.fix = raw.fix;
    if (raw.guide) out.guide = raw.guide;
    if (raw.reachable) out.reachable = raw.reachable;
  }
  return out;
}

// ---------------------------------------------------------------- Учения целиком

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'TIMEOUT' })), ms); }),
  ]).finally(() => clearTimeout(timer));
}

function headline(passed, total, results) {
  if (!total) return results.length ? t('Учения не прошли: ни одна проверка не дала ответа') : t('Учения не проводились');
  if (passed === total) return tx('Учения пройдены: отражено атак - {0} из {1}', passed, total);
  return tx('Учения: отражено атак - {0} из {1}, есть что исправить', passed, total);
}

/**
 * runDrill(id) → Promise ответа drill.ps1; exposure() → Promise ответа exposure().
 * run(ids) - учения по очереди; сбой одного не останавливает остальные. Общий лимит времени - totalMs.
 */
function createDrills({ store, runDrill, exposure: runExposure, now = () => Date.now(), drillMs = 60_000, totalMs = 180_000 } = {}) {
  let running = null;

  async function runOne(id, deadline) {
    const meta = DRILLS.find((d) => d.id === id);
    const base = { id, title: meta.title };
    const left = deadline - now();
    if (left <= 0) return { ...base, status: 'skipped', detail: t('Не хватило времени: учения остановлены по общему лимиту.'), advice: null, ms: 0 };
    const started = now();
    let raw;
    try {
      const p = id === 'exposure' ? runExposure() : runDrill(id);
      raw = await withTimeout(Promise.resolve(p), Math.min(drillMs, left));
    } catch (e) {
      raw = { status: 'error', detail: e && e.code === 'TIMEOUT' ? 'timeout' : String((e && e.message) || e).slice(0, 300) };
    }
    const d = describe(id, raw);
    const ms = raw && Number.isFinite(Number(raw.ms)) && raw.status !== 'error' ? Number(raw.ms) : Math.max(0, now() - started);
    return { ...base, ...d, ms };
  }

  async function run(ids) {
    if (running) return running;
    const list = (Array.isArray(ids) && ids.length ? ids : IDS).filter((x, i, a) => IDS.includes(x) && a.indexOf(x) === i);
    if (!list.length) throw new Error(t('Не выбрано ни одного учения'));
    running = (async () => {
      const at = new Date(now()).toISOString();
      const deadline = now() + totalMs;
      const results = [];
      for (const id of list) results.push(await runOne(id, deadline));
      const passed = results.filter((r) => r.status === 'passed').length;
      const total = results.filter((r) => r.status === 'passed' || r.status === 'failed').length;
      const res = { at, results, passed, total, headline: headline(passed, total, results) };
      try { store.write('drills.json', res); } catch { /* результат всё равно вернём */ }
      return res;
    })();
    try {
      return await running;
    } finally {
      running = null;
    }
  }

  return {
    run,
    last: () => store.read('drills.json', null),
    running: () => !!running,
  };
}

/**
 * Учебные строки для drill.ps1: стандартный файл EICAR (68 символов) и учебная строка AMSI (54).
 * Хранятся кодами символов, чтобы антивирус не принял за угрозу сами файлы программы, и уходят
 * в сценарий через стандартный ввод - не в командной строке и не внутри сценария PowerShell.
 */
const SAMPLE_CODES = {
  eicar: [88,53,79,33,80,37,64,65,80,91,52,92,80,90,88,53,52,40,80,94,41,55,67,67,41,55,125,36,69,73,67,65,82,45,83,84,65,78,68,65,82,68,45,65,78,84,73,86,73,82,85,83,45,84,69,83,84,45,70,73,76,69,33,36,72,43,72,42],
  amsi: [65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,55,101,55,50,99,51,99,101,45,56,54,49,98,45,52,51,51,57,45,56,55,52,48,45,48,97,99,49,52,56,52,99,49,51,56,54],
};
/** Что передать drill.ps1 на стандартный ввод (null - учению ничего не нужно). */
function drillInput(id) {
  const c = SAMPLE_CODES[id];
  return c ? JSON.stringify({ sample: String.fromCharCode(...c) }) : null;
}

module.exports = { DRILLS, createDrills, exposure, describe, ownPrivateIps, RISKY, drillInput, SAMPLE_CODES };
