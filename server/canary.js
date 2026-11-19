'use strict';
/**
 * «Приманки»: контрольные файлы против программ-шантажистов.
 * В каждую папку (по умолчанию «Документы» и «Рабочий стол») кладутся два скрытых файла с именами,
 * которые стоят первыми по алфавиту: шантажист обычно обходит папку по порядку и зашифрует их раньше
 * настоящих документов. Если файл изменился, исчез или переименован - onAlert.
 *  - Файлы создаются только заново (флаг wx): чужой файл с таким же именем не перезаписывается.
 *  - disarm() удаляет только файлы из своего списка (canary.json) и только с именем-приманкой.
 *  - Слежение - fs.watch по папке (без обхода подпапок) и редкая сверка раз в 10 минут.
 */
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

const PREFIX = '!_Адамант_контроль';
const NAMES = [`${PREFIX}.docx`, `${PREFIX}.xlsx`];
const MANIFEST = 'canary.json';
const VERIFY_MS = 10 * 60_000;
const DEBOUNCE_MS = 400;
const MARK = 'Это контрольный файл программы «Адамант».';
const CONTENT = `${MARK}\r\n\r\n`
  + 'Не удаляйте, не открывайте и не меняйте его. Он нужен, чтобы вовремя заметить программу-шантажиста: '
  + 'такие программы шифруют файлы по порядку, и этот файл стоит первым. Если он изменится, «Адамант» сразу предупредит.\r\n\r\n'
  + 'Файл не является документом Word или Excel и ничего не делает. Убрать контрольные файлы можно в «Адаманте» в разделе «Приманки».\r\n';

const ATTRIB = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'attrib.exe');

/** Скрыть файл (attrib +h, без командной оболочки). Ошибка не мешает работе приманки. */
function defaultHide(p) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve(false);
    execFile(ATTRIB, ['+h', p], { windowsHide: true, timeout: 10_000 }, (err) => resolve(!err));
  });
}

/**
 * «Документы» и «Рабочий стол» по профилю пользователя (быстро, без внешних программ).
 * Если папки профиля нет - та же папка в OneDrive. Точные пути с учётом переноса - knownDirs().
 */
function defaultDirs({ env = process.env, fs = nodeFs } = {}) {
  const home = env.USERPROFILE || require('node:os').homedir();
  const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
  const pick = (names) => {
    const cands = [path.join(home, names[0])];
    for (const base of [env.OneDrive, env.OneDriveConsumer, env.OneDriveCommercial].filter(Boolean)) for (const n of names) cands.push(path.join(base, n));
    return cands.find(isDir) || cands[0];
  };
  return [...new Set([pick(['Documents', 'Документы']), pick(['Desktop', 'Рабочий стол'])])];
}

/**
 * Точные пути «Документов» и «Рабочего стола» из Windows (с учётом переноса в OneDrive).
 * Только чтение: [Environment]::GetFolderPath. При ошибке - defaultDirs().
 */
function knownDirs({ timeout = 15_000 } = {}) {
  const ps = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const cmd = "[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; [Console]::Out.Write([Environment]::GetFolderPath('MyDocuments') + \"`n\" + [Environment]::GetFolderPath('Desktop'))";
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve(defaultDirs());
    execFile(ps, ['-NoProfile', '-NonInteractive', '-Command', cmd], { windowsHide: true, timeout, encoding: 'utf8' }, (err, stdout) => {
      const dirs = String(stdout || '').split(/\r?\n/).map((s) => s.trim()).filter((s) => s && path.isAbsolute(s));
      resolve(!err && dirs.length ? [...new Set(dirs)] : defaultDirs());
    });
  });
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const samePath = (a, b) => path.resolve(a).toLowerCase() === path.resolve(b).toLowerCase();
const isOurName = (p) => NAMES.includes(path.basename(p));

function createCanary({ dataDir, dirs, fs = nodeFs, onAlert = () => {}, now = () => Date.now(), hide = defaultHide, verifyMs = VERIFY_MS, debounceMs = DEBOUNCE_MS } = {}) {
  if (!dataDir) throw new Error('dataDir required');
  const manifestPath = path.join(dataDir, MANIFEST);
  let watchers = [];
  let debounce = null;
  let verifyTimer = null;
  let lastCheck = null;
  let checking = null;
  let alerted = new Set(); // файлы, о которых уже предупредили (одно предупреждение на случай)
  const alerts = [];

  function readManifest() {
    try {
      const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      return m && Array.isArray(m.files) ? m : null;
    } catch {
      return null;
    }
  }
  function writeManifest(m) {
    fs.mkdirSync(dataDir, { recursive: true });
    const tmp = `${manifestPath}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(m, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, manifestPath);
  }
  /** Полный путь без коротких имён (C:\Users\ABCD~1): с ними fs.watch в Windows падает. */
  const realDir = (d) => {
    try { return (fs.realpathSync.native || fs.realpathSync)(d); } catch { return path.resolve(d); }
  };
  const targetDirs = () => [...new Set((dirs && dirs.length ? dirs : defaultDirs()).map(realDir))];

  async function arm() {
    const wasWatching = watchers.length > 0;
    stop();
    const old = readManifest();
    const files = [];
    const skipped = [];
    const armedDirs = [];
    for (const dir of targetDirs()) {
      try {
        if (!fs.statSync(dir).isDirectory()) throw new Error('not a directory');
      } catch {
        skipped.push({ dir, reason: 'missing' });
        continue;
      }
      armedDirs.push(dir);
      for (const name of NAMES) {
        const p = path.join(dir, name);
        const known = old && old.files.find((f) => samePath(f.path, p));
        let buf = null;
        try { buf = fs.readFileSync(p); } catch { buf = null; }
        if (buf) {
          // Уже есть: своя целая приманка (по списку или по тексту) - оставляем; чужой файл не трогаем.
          const ours = (known && sha256(buf) === known.sha256) || buf.toString('utf8').startsWith(MARK);
          if (ours) files.push({ path: p, sha256: sha256(buf), size: buf.length });
          else skipped.push({ dir, name, reason: known ? 'changed' : 'foreign' });
          continue;
        }
        try {
          const data = Buffer.from(CONTENT, 'utf8');
          fs.writeFileSync(p, data, { flag: 'wx' });
          files.push({ path: p, sha256: sha256(data), size: data.length });
          try { await hide(p); } catch { /* видимый файл тоже работает */ }
        } catch (e) {
          // Например, контролируемый доступ к папкам не пустил «Адамант» в «Документы».
          skipped.push({ dir, name, reason: e && e.code === 'EEXIST' ? 'foreign' : e && (e.code === 'EPERM' || e.code === 'EACCES') ? 'denied' : 'error' });
        }
      }
    }
    // Приманки из прежнего списка в папках, которых больше нет среди целевых, остаются в списке, чтобы disarm() их убрал.
    for (const f of (old ? old.files : [])) {
      if (files.some((x) => samePath(x.path, f.path)) || !isOurName(f.path)) continue;
      try {
        const buf = fs.readFileSync(f.path);
        if (sha256(buf) !== f.sha256) continue;
        files.push({ path: f.path, sha256: f.sha256, size: buf.length });
        const d = path.dirname(f.path);
        if (!armedDirs.some((x) => samePath(x, d))) armedDirs.push(d);
      } catch { /* файла уже нет */ }
    }
    const m = { armedAt: new Date(now()).toISOString(), dirs: armedDirs, files };
    if (files.length) writeManifest(m);
    else { try { fs.unlinkSync(manifestPath); } catch { /* нет */ } }
    alerted = new Set();
    lastCheck = null;
    if (wasWatching && files.length) watch();
    return { ...status(), skipped };
  }

  async function disarm() {
    stop();
    const m = readManifest();
    const removed = [];
    const kept = [];
    for (const f of (m ? m.files : [])) {
      const p = String(f.path || '');
      const inDir = (m.dirs || []).some((d) => samePath(path.dirname(p), d));
      if (!p || !path.isAbsolute(p) || !isOurName(p) || !inDir) { kept.push(p); continue; }
      try {
        fs.unlinkSync(p);
        removed.push(p);
      } catch (e) {
        if (e && e.code === 'ENOENT') continue;
        kept.push(p);
      }
    }
    try { fs.unlinkSync(manifestPath); } catch { /* нет */ }
    alerted = new Set();
    return { removed, kept };
  }

  /** Что случилось с приманками: modified - содержимое другое, renamed - рядом файл с её именем и приставкой, deleted - пропала. */
  function checkSync() {
    const m = readManifest();
    const at = new Date(now()).toISOString();
    const tampered = [];
    for (const f of (m ? m.files : [])) {
      let buf = null;
      let missing = false;
      try { buf = fs.readFileSync(f.path); } catch (e) { missing = !e || e.code === 'ENOENT' || e.code === 'ENOTDIR'; if (!missing) buf = null; }
      if (buf) {
        if (buf.length !== f.size || sha256(buf) !== f.sha256) tampered.push({ path: f.path, change: 'modified', at });
        continue;
      }
      if (!missing) {
        // Файл есть, но не читается (занят другой программой) - для шантажиста это обычно «зашифрован».
        let exists = false;
        try { fs.statSync(f.path); exists = true; } catch { exists = false; }
        if (exists) { tampered.push({ path: f.path, change: 'modified', at }); continue; }
      }
      const base = path.basename(f.path);
      let renamed = false;
      try {
        renamed = fs.readdirSync(path.dirname(f.path)).some((n) => n !== base && n.includes(base));
      } catch { renamed = false; }
      tampered.push({ path: f.path, change: renamed ? 'renamed' : 'deleted', at });
    }
    lastCheck = at;
    return tampered;
  }

  function check() {
    return checkSync();
  }

  function verify() {
    if (checking) return;
    checking = true;
    try {
      const tampered = checkSync();
      const fresh = tampered.filter((x) => !alerted.has(x.path.toLowerCase()));
      // Файл вернули на место - следующее изменение снова считается новым случаем.
      for (const p of [...alerted]) if (!tampered.some((x) => x.path.toLowerCase() === p)) alerted.delete(p);
      if (fresh.length) {
        fresh.forEach((x) => alerted.add(x.path.toLowerCase()));
        const incident = { files: fresh, at: fresh[0].at };
        alerts.unshift(incident);
        alerts.length = Math.min(alerts.length, 20);
        try { onAlert(incident); } catch { /* ошибка получателя не ломает слежение */ }
      }
    } finally {
      checking = false;
    }
  }

  function schedule() {
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => { debounce = null; verify(); }, debounceMs);
    if (debounce.unref) debounce.unref();
  }

  /** Слежение за папками с приманками. Возвращает число папок под наблюдением. */
  function watch() {
    stop();
    const m = readManifest();
    if (!m || !m.files.length) return 0;
    const ours = new Set(m.files.map((f) => path.basename(f.path)));
    const dirsToWatch = [...new Set(m.files.map((f) => path.dirname(f.path)))];
    for (const dir of dirsToWatch) {
      try {
        const w = fs.watch(realDir(dir), { persistent: false }, (event, filename) => {
          const n = filename ? String(filename) : '';
          if (!n || ours.has(n) || n.startsWith(PREFIX)) schedule();
        });
        w.on('error', () => {
          // Папку удалили или переименовали - сверить приманки.
          try { w.close(); } catch { /* уже закрыт */ }
          watchers = watchers.filter((x) => x !== w);
          schedule();
        });
        watchers.push(w);
      } catch { /* папка недоступна - поможет редкая сверка */ }
    }
    if (verifyMs > 0) {
      verifyTimer = setInterval(verify, verifyMs);
      if (verifyTimer.unref) verifyTimer.unref();
    }
    verify();
    return watchers.length;
  }

  function stop() {
    for (const w of watchers) { try { w.close(); } catch { /* уже закрыт */ } }
    watchers = [];
    if (debounce) { clearTimeout(debounce); debounce = null; }
    if (verifyTimer) { clearInterval(verifyTimer); verifyTimer = null; }
  }

  function status() {
    const m = readManifest();
    return {
      armed: !!(m && m.files.length),
      armedAt: m ? m.armedAt : null,
      files: m ? m.files.map((f) => ({ path: f.path, size: f.size })) : [],
      lastCheck,
      alerts: alerts.slice(),
      watching: watchers.length,
    };
  }

  return { arm, disarm, check, watch, stop, status };
}

module.exports = { createCanary, defaultDirs, knownDirs, defaultHide, NAMES, PREFIX };
