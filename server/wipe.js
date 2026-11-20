'use strict';
/**
 * «Уничтожить данные» («Камни: защита данных», этап 2).
 *
 * Данные Адаманта хранятся зашифрованными (server/vault.js), поэтому уничтожить - значит уничтожить ключ:
 * data.key перезаписывается случайными байтами и удаляется. На SSD удаление файла не гарантирует, что байты
 * исчезли, а без ключа зашифрованные файлы прочитать нельзя. Файлы потом удаляются уже для порядка.
 *
 * Порядок:
 *   1. приманки из «Учений» - их список лежит в зашифрованном canary.json, поэтому пока ключ ещё есть;
 *   2. все ключи данных (и старые, отодвинутые «Начать заново» в unreadable-*);
 *   3. закрыть программу: значок в трее (иначе он перезапустит сервер), сервер, окно;
 *   4. удалить папку данных; открытые файлы (профиль окна, settings.json, server.log) перед удалением затираются;
 *   5. по желанию (--admin, разрешение UAC) - записи для отката и ответы помощника в %ProgramData%\Adamant.
 * Программа остаётся установленной и при следующем запуске начинает с чистого листа.
 *
 * Командная строка (договор камней, её вызовет «Тревога» в этапе 3):
 *   node server/wipe.js --wipe-all --yes [--admin] [--data=<папка>] [--wait=<секунды>]
 * Без окна и без вопросов. Печатает одну строку JSON {"ok":true,"keysDestroyed":true,"filesLeft":[...]},
 * код выхода 0 - ключи уничтожены, 1 - нет, 2 - неверный вызов.
 */
const nodeFs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { unseal, isSealed, MAGIC, KEY_FILE } = require('./vault');
const { NAMES: DECOY_NAMES } = require('./canary');

const WORDS = ['УНИЧТОЖИТЬ', 'DESTROY'];
/** Файлы, по которым видно, что это папка данных Адаманта. */
const MARKERS = [KEY_FILE, 'settings.json', 'server.json', 'server.lock', 'server.log', 'report.json', 'journal.json', 'history.json'];
const MAX_LEFT = 50;
const MAX_OVERWRITE = 256 * 1024 * 1024;
const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));
const lower = (p) => path.resolve(p).replace(/[\\/]+$/, '').toLowerCase();
const isKeyName = (n) => { const l = n.toLowerCase(); return l === KEY_FILE || (l.startsWith(`${KEY_FILE}.`) && l.endsWith('.tmp')); };

/** Слово подтверждения из окна. */
const wordOk = (w) => WORDS.includes(String(w || '').trim().toUpperCase());

/**
 * Папку удаляем целиком, поэтому сначала убеждаемся, что это действительно папка данных Адаманта,
 * а не профиль пользователя, корень диска или папка программы (ошибка в config.json не должна стоить документов).
 */
function checkDataDir(dir, { fs = nodeFs, env = process.env, root = path.resolve(__dirname, '..') } = {}) {
  if (!dir || !path.isAbsolute(dir)) throw new Error('папка данных не указана');
  const d = lower(dir);
  const parsed = path.parse(path.resolve(dir));
  if (path.resolve(dir) === parsed.root || d.split(/[\\/]/).filter(Boolean).length < 3) throw new Error(`слишком общая папка: ${dir}`);
  const home = env.USERPROFILE || os.homedir();
  const forbidden = [home, env.LOCALAPPDATA, env.APPDATA, env.ProgramData, env.ProgramFiles, env['ProgramFiles(x86)'], env.SystemRoot, env.PUBLIC,
    home && path.join(home, 'Desktop'), home && path.join(home, 'Documents'), home && path.join(home, 'Downloads'), root].filter(Boolean).map(lower);
  for (const f of forbidden) {
    if (d === f || f.startsWith(`${d}\\`) || f.startsWith(`${d}/`)) throw new Error(`эту папку удалять нельзя: ${dir}`);
  }
  let names = [];
  try { names = fs.readdirSync(dir).map((n) => n.toLowerCase()); } catch (e) { if (e && e.code === 'ENOENT') return; throw e; }
  if (names.length && !names.some((n) => MARKERS.includes(n))) throw new Error(`не похоже на папку данных Адаманта: ${dir}`);
}

/** Перезаписать файл случайными байтами (лучшее, что можно сделать; на SSD - без гарантий). */
function overwrite(fs, abs) {
  try {
    const size = fs.statSync(abs).size;
    if (size <= 0 || size > MAX_OVERWRITE) return false;
    const fd = fs.openSync(abs, 'r+');
    try {
      for (let off = 0; off < size; off += 1 << 20) {
        const n = Math.min(1 << 20, size - off);
        fs.writeSync(fd, crypto.randomBytes(n), 0, n, off);
      }
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    return true;
  } catch { return false; }
}

/** Обход без перехода по ссылкам: { files, dirs, links } (пути абсолютные, папки - от верхних к нижним). */
function walk(fs, dir, depth = 0, out = { files: [], dirs: [], links: [] }) {
  let list = [];
  try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of list) {
    const abs = path.join(dir, e.name);
    if (e.isSymbolicLink()) out.links.push(abs);
    else if (e.isDirectory()) { out.dirs.push(abs); if (depth < 12) walk(fs, abs, depth + 1, out); }
    else out.files.push(abs);
  }
  return out;
}

/** Все ключи данных в папке (data.key, его временные копии, старые ключи в unreadable-*). */
function destroyKeys({ dataDir, fs = nodeFs }) {
  const keys = walk(fs, dataDir).files.filter((f) => isKeyName(path.basename(f)));
  const left = [];
  for (const f of keys) {
    overwrite(fs, f);
    try { fs.unlinkSync(f); } catch (e) { if (!e || e.code !== 'ENOENT') left.push(f); }
  }
  return { found: keys.length, left };
}

/** Список приманок из canary.json: зашифрованный открываем ключом (DPAPI), пока ключ ещё есть. */
async function readDecoys({ dataDir, fs = nodeFs, unprotect }) {
  let buf;
  try { buf = fs.readFileSync(path.join(dataDir, 'canary.json')); } catch { return null; }
  try {
    if (isSealed(buf)) {
      const j = JSON.parse(fs.readFileSync(path.join(dataDir, KEY_FILE), 'utf8'));
      const k = await unprotect(Buffer.from(j.key, 'base64'));
      try { buf = unseal(k, 'canary.json', buf); } finally { if (Buffer.isBuffer(k)) k.fill(0); }
    }
    const m = JSON.parse(buf.toString('utf8'));
    return m && Array.isArray(m.files) ? m : null;
  } catch { return null; }
}

/** Удалить приманки - по тем же правилам, что canary.disarm(): только из своего списка, со своим именем, в своей папке. */
function removeDecoys({ manifest, fs = nodeFs }) {
  const removed = [];
  const kept = [];
  if (!manifest) return { removed, kept };
  const dirs = (manifest.dirs || []).map((d) => lower(String(d)));
  for (const f of manifest.files || []) {
    const p = String((f && f.path) || '');
    if (!p || !path.isAbsolute(p) || !DECOY_NAMES.includes(path.basename(p)) || !dirs.includes(lower(path.dirname(p)))) { if (p) kept.push(p); continue; }
    try { fs.unlinkSync(p); removed.push(p); } catch (e) { if (!e || e.code !== 'ENOENT') kept.push(p); }
  }
  return { removed, kept };
}

/** Удалить папку данных целиком. Занятые файлы (окно ещё закрывается) - несколько попыток. */
async function deleteAll({ dataDir, fs = nodeFs, sleep = sleepMs, tries = 6 }) {
  if (!fs.existsSync(dataDir)) return [];
  let left = [];
  for (let i = 0; i < tries; i++) {
    const w = walk(fs, dataDir);
    left = [];
    for (const l of w.links) {
      try { fs.unlinkSync(l); } catch { try { fs.rmdirSync(l); } catch { left.push(l); } }
    }
    for (const f of w.files) {
      // Зашифрованные без ключа уже не прочитать; открытые (профиль окна, журнал сервера) затираем.
      let sealed = false;
      try {
        const fd = fs.openSync(f, 'r');
        try { const b = Buffer.alloc(MAGIC.length); sealed = fs.readSync(fd, b, 0, b.length, 0) === b.length && b.equals(MAGIC); } finally { fs.closeSync(fd); }
      } catch { /* занят - попробуем удалить как есть */ }
      if (!sealed) overwrite(fs, f);
      try { fs.unlinkSync(f); } catch (e) { if (!e || e.code !== 'ENOENT') left.push(f); }
    }
    for (const d of w.dirs.slice().reverse()) { try { fs.rmdirSync(d); } catch { /* не пустая - останется в left через файлы */ } }
    if (!left.length) break;
    await sleep(500);
  }
  try { fs.rmdirSync(dataDir); } catch (e) { if (!left.length && e && e.code !== 'ENOENT') left.push(dataDir); }
  return left;
}

/** Что лежит в %ProgramData%\Adamant и удаляется только с правами администратора. */
function adminTargets({ fs = nodeFs, env = process.env } = {}) {
  const base = path.join(env.ProgramData || 'C:\\ProgramData', 'Adamant');
  const out = [];
  const undo = path.join(base, 'undo');
  if (fs.existsSync(undo)) out.push(undo);
  const helperOut = path.join(base, 'helper', 'out');
  try { if (fs.readdirSync(helperOut).length) out.push(helperOut); } catch { /* нет или нет доступа */ }
  return out;
}

/** Попросить работающий сервер завершиться (он сам уберёт server.json и server.lock). */
async function askServerStop({ dataDir, fs = nodeFs }) {
  let s;
  try { s = JSON.parse(fs.readFileSync(path.join(dataDir, 'server.json'), 'utf8')); } catch { return false; }
  if (!Number.isInteger(s.port) || typeof s.key !== 'string') return false;
  try {
    await fetch(`http://127.0.0.1:${s.port}/api/shutdown`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Adamant-Key': s.key }, body: '{}', signal: AbortSignal.timeout(2000) });
    return true;
  } catch { return false; }
}

/**
 * Полное уничтожение (командная строка). Всё внешнее подменяется в тестах:
 * unprotect - DPAPI, stopServer/stopProcs - закрыть программу, runAdmin - часть с UAC.
 */
async function wipeAll({ dataDir, admin = false, wait = 0, fs = nodeFs, env = process.env, root, unprotect, stopServer, stopProcs, runAdmin, sleep = sleepMs }) {
  checkDataDir(dataDir, { fs, env, root });
  const manifest = unprotect ? await readDecoys({ dataDir, fs, unprotect }) : null;
  const decoys = removeDecoys({ manifest, fs });
  const keys = destroyKeys({ dataDir, fs });
  if (wait > 0) await sleep(wait * 1000);
  // Сначала процессы (значок первым: увидев, что сервер не отвечает, он запустил бы его снова), потом -
  // вежливая просьба серверу, если он запущен как-то иначе и по командной строке не нашёлся.
  if (stopProcs) { try { await stopProcs(); } catch { /* закроем, что получится */ } }
  if (stopServer) { try { await stopServer(); } catch { /* не запущен */ } }
  await sleep(700);
  const filesLeft = await deleteAll({ dataDir, fs, sleep });
  let adminLeft = [];
  let adminError;
  if (admin && runAdmin) {
    try {
      const r = await runAdmin();
      adminLeft = Array.isArray(r && r.left) ? r.left.map(String) : [];
    } catch (e) {
      adminError = e && e.code === 'CANCELLED' ? 'cancelled' : 'error';
      adminLeft = adminTargets({ fs, env });
    }
  } else {
    adminLeft = adminTargets({ fs, env });
  }
  const left = [...keys.left, ...filesLeft, ...decoys.kept, ...adminLeft];
  const out = { ok: keys.left.length === 0, keysDestroyed: keys.left.length === 0, filesLeft: left.slice(0, MAX_LEFT) };
  if (left.length > MAX_LEFT) out.more = left.length - MAX_LEFT;
  if (decoys.removed.length) out.decoysRemoved = decoys.removed.length;
  if (adminError) out.admin = adminError;
  return out;
}

/**
 * Для сервера (кнопка «Уничтожить данные»). Сначала то, что видно в окне: приманки, ключ, часть с UAC.
 * Остальное - отдельный процесс wipe.js через несколько секунд: он закроет окно, значок и сам сервер
 * и удалит папку. Вызывающий сервер к этому моменту уже ответил окну.
 */
function createWiper({ dataDir, vault = null, canary = null, stopWatchers = () => {}, runAdmin = null, spawnCli = null, fs = nodeFs, env = process.env, root, delayMs = 300 }) {
  return {
    async run({ admin = false } = {}) {
      checkDataDir(dataDir, { fs, env, root });
      let decoys = { removed: [], kept: [] };
      if (canary) { try { decoys = await canary.disarm(); } catch { /* список приманок не открылся */ } }
      try { stopWatchers(); } catch { /* ignore */ }
      const keys = destroyKeys({ dataDir, fs });
      if (vault && vault.forget) vault.forget();
      let adminLeft = [];
      let adminError;
      if (admin && runAdmin) {
        try {
          const r = await runAdmin();
          adminLeft = Array.isArray(r && r.left) ? r.left.map(String) : [];
        } catch (e) {
          adminError = e && e.code === 'CANCELLED' ? 'cancelled' : 'error';
          adminLeft = adminTargets({ fs, env });
        }
      }
      if (spawnCli) setTimeout(() => { try { spawnCli(); } catch (e) { console.error('Уничтожение данных:', e.message); } }, delayMs);
      const out = { ok: keys.left.length === 0, keysDestroyed: keys.left.length === 0, decoysRemoved: decoys.removed.length, decoysKept: decoys.kept.length, adminLeft };
      if (adminError) out.admin = adminError;
      return out;
    },
  };
}

/** Отдельный процесс wipe.js для сервера: без окна, переживает сам сервер. */
function spawnWipeCli({ dataDir, wait = 6, node = process.execPath }) {
  spawn(node, [path.join(__dirname, 'wipe.js'), '--wipe-all', '--yes', `--data=${dataDir}`, `--wait=${wait}`],
    { cwd: path.resolve(__dirname, '..'), detached: true, windowsHide: true, stdio: 'ignore' }).unref();
}

async function cli(argv = process.argv.slice(2)) {
  if (!argv.includes('--wipe-all') || !argv.includes('--yes')) {
    console.log(JSON.stringify({ ok: false, error: 'usage: wipe.js --wipe-all --yes [--admin] [--data=<папка>] [--wait=<секунды>]' }));
    return 2;
  }
  const { loadConfig } = require('./config');
  const cfg = loadConfig(argv);
  const ps = require('./ps');
  const { dpapi } = require('./vault');
  const waitArg = argv.find((a) => a.startsWith('--wait='));
  const wait = Math.min(Math.max(Number(waitArg ? waitArg.slice(7) : 0) || 0, 0), 60);
  try {
    const r = await wipeAll({
      dataDir: cfg.dataDir,
      root: cfg.root,
      admin: argv.includes('--admin'),
      wait,
      unprotect: (b) => dpapi('unprotect', b),
      stopServer: () => askServerStop({ dataDir: cfg.dataDir }),
      stopProcs: () => ps.runJson('wipe-procs.ps1', [], { timeout: 60_000, input: JSON.stringify({ data: cfg.dataDir, self: process.pid }) }),
      runAdmin: () => ps.runElevated('wipe-admin.ps1', [], { tmpDir: os.tmpdir() }),
    });
    console.log(JSON.stringify(r));
    return r.ok ? 0 : 1;
  } catch (e) {
    console.log(JSON.stringify({ ok: false, keysDestroyed: false, error: String(e && e.message || e).slice(0, 300), filesLeft: [] }));
    return 1;
  }
}

if (require.main === module) cli().then((code) => { process.exitCode = code; });

module.exports = { wipeAll, createWiper, spawnWipeCli, checkDataDir, destroyKeys, readDecoys, removeDecoys, deleteAll, adminTargets, wordOk, WORDS, cli };
