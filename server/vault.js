'use strict';
/**
 * Шифрование папки данных («Камни: защита данных», этап 1).
 *
 * Ключ данных (DEK) - 32 случайных байта. На диске он лежит только обёрнутым через DPAPI текущего
 * пользователя Windows (data.key): открыть его может только эта учётная запись на этом компьютере.
 * Пароль не нужен - работа в фоне, автозапуск и «Пока вас не было» работают как раньше.
 *
 * Каждый файл: ADMENC1\0 | iv (12) | tag (16) | шифротекст AES-256-GCM. В AAD - имя файла
 * относительно папки данных, поэтому файлы нельзя незаметно поменять местами.
 *
 * Открытыми остаются только файлы без личных сведений, нужные до открытия ключа:
 * settings.json (язык, переключатели), server.json/server.lock (порт и разовый ключ работающего
 * сервера), server.log, сам data.key и профиль окна Edge (window/).
 *
 * Защищает от кражи диска или ноутбука без входа в Windows и от копирования папки на другой компьютер.
 * Не защищает от программы, запущенной под той же учётной записью: ей DPAPI откроет ключ так же, как Адаманту.
 */
const nodeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAGIC = Buffer.from('ADMENC1\0', 'latin1');
const IV_LEN = 12;
const TAG_LEN = 16;
const HEAD = MAGIC.length + IV_LEN + TAG_LEN;
const KEY_FILE = 'data.key';
/** Остаются открытыми (см. выше). Имена - в нижнем регистре. */
const PLAIN = new Set([KEY_FILE, 'settings.json', 'server.json', 'server.lock', 'server.log']);
const SKIP_DIR = (n) => n === 'window' || n.startsWith('unreadable-');
/** Временные файлы: запись в процессе (.tmp, .part) и ответы сценариев с правами администратора. */
const TRANSIENT = /(\.tmp|\.part)$|^adamant-\d+-[0-9a-f]{12}\.json$/i;

const norm = (name) => String(name).replace(/\\/g, '/').replace(/^\/+/, '').toLowerCase();
const aad = (name) => Buffer.from(`adamant-data-v1:${norm(name)}`, 'utf8');
const isSealed = (buf) => Buffer.isBuffer(buf) && buf.length >= HEAD && buf.subarray(0, MAGIC.length).equals(MAGIC);
/** Должен ли файл с таким именем (относительно папки данных) храниться открытым. */
const isPlainName = (name) => {
  const n = norm(name);
  return PLAIN.has(n) || TRANSIENT.test(path.posix.basename(n)) || n.split('/').slice(0, -1).some(SKIP_DIR);
};

function seal(dek, name, plain) {
  const iv = crypto.randomBytes(IV_LEN);
  const c = crypto.createCipheriv('aes-256-gcm', dek, iv);
  c.setAAD(aad(name));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), ct]);
}

function unseal(dek, name, buf) {
  if (!isSealed(buf)) throw new Error('not sealed');
  const iv = buf.subarray(MAGIC.length, MAGIC.length + IV_LEN);
  const tag = buf.subarray(MAGIC.length + IV_LEN, HEAD);
  const d = crypto.createDecipheriv('aes-256-gcm', dek, iv);
  d.setAAD(aad(name));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(buf.subarray(HEAD)), d.final()]);
}

/** DPAPI текущего пользователя через server/ps/dpapi.ps1 (в Node его нет, а внешних модулей у нас нет). */
async function dpapi(op, buf) {
  const ps = require('./ps');
  const j = await ps.runJson('dpapi.ps1', ['-Op', op], { timeout: 60_000, input: JSON.stringify({ data: buf.toString('base64') }) });
  if (!j || j.ok !== true || typeof j.data !== 'string') throw new Error((j && j.error) || 'DPAPI не ответил');
  return Buffer.from(j.data, 'base64');
}

/**
 * createVault({ dataDir, fs, protect, unprotect, now }) - всё внешнее подменяется в тестах.
 * open() - открыть или создать ключ и перешифровать открытые файлы; state() - что получилось;
 * reset() - «Начать заново», если ключ пропал или не открывается.
 */
function createVault({ dataDir, fs = nodeFs, protect = (b) => dpapi('protect', b), unprotect = (b) => dpapi('unprotect', b), now = () => new Date() } = {}) {
  if (!dataDir) throw new Error('dataDir required');
  const keyFile = path.join(dataDir, KEY_FILE);
  let dek = null;
  let st = { state: 'closed' };
  const readyHooks = [];

  const relOf = (abs) => path.relative(dataDir, abs).split(path.sep).join('/');

  /** Файлы, которые должны быть зашифрованы (без открытых, временных, window/ и unreadable-*). */
  function candidates() {
    const out = [];
    (function walk(dir, depth) {
      let list = [];
      try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of list) {
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) {
          if (depth < 4 && !SKIP_DIR(e.name.toLowerCase())) walk(abs, depth + 1);
        } else if (e.isFile() && !isPlainName(relOf(abs))) out.push(abs);
      }
    })(dataDir, 0);
    return out;
  }
  function head(abs) {
    try {
      const fd = fs.openSync(abs, 'r');
      try {
        const b = Buffer.alloc(MAGIC.length);
        const n = fs.readSync(fd, b, 0, b.length, 0);
        return b.subarray(0, n);
      } finally { fs.closeSync(fd); }
    } catch { return Buffer.alloc(0); }
  }
  const sealedOnDisk = (abs) => head(abs).equals(MAGIC);

  async function writeKey(k) {
    const wrapped = await protect(k);
    const check = seal(k, KEY_FILE, Buffer.from('adamant-key-check'));
    const j = { v: 1, kind: 'dpapi-user', key: wrapped.toString('base64'), check: check.toString('base64'), created: now().toISOString() };
    const tmp = `${keyFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(j, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, keyFile);
  }

  /** Атомарная запись с затиранием прежнего содержимого (на SSD - без гарантий, поэтому главное - шифрование). */
  function replaceFile(abs, data) {
    const tmp = `${abs}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, data, { mode: 0o600 });
    try {
      const size = fs.statSync(abs).size;
      if (size > 0) {
        const fd = fs.openSync(abs, 'r+');
        try {
          for (let off = 0; off < size; off += 1 << 20) {
            const n = Math.min(1 << 20, size - off);
            fs.writeSync(fd, crypto.randomBytes(n), 0, n, off);
          }
          fs.fsyncSync(fd);
        } finally { fs.closeSync(fd); }
      }
    } catch { /* файла ещё нет или занят - просто заменим */ }
    fs.renameSync(tmp, abs);
  }

  /** Зашифровать один открытый файл на месте. true - зашифрован сейчас. */
  function sealFile(abs) {
    if (!dek) throw new Error('vault closed');
    const plain = fs.readFileSync(abs);
    if (isSealed(plain)) return false;
    const name = relOf(abs);
    const sealed = seal(dek, name, plain);
    // Проверка до замены: открытый файл удаляем, только если зашифрованный точно читается.
    if (!unseal(dek, name, sealed).equals(plain)) throw new Error(`проверка шифрования не прошла: ${name}`);
    replaceFile(abs, sealed);
    return true;
  }

  /** Перешифровать все открытые файлы. Возвращает число зашифрованных; ошибки - в st.migrateErrors. */
  function migrate() {
    let n = 0;
    const errors = [];
    for (const abs of candidates()) {
      try { if (sealFile(abs)) n++; } catch (e) { errors.push(`${relOf(abs)}: ${e.message}`); }
    }
    if (errors.length) st.migrateErrors = errors.slice(0, 20);
    return n;
  }

  function becomeReady() {
    st = { state: 'ok' };
    const migrated = migrate();
    if (migrated) st.migrated = migrated;
    for (const f of readyHooks) { try { f(); } catch (e) { console.error('Хранилище:', e.message); } }
  }

  async function open() {
    try { fs.mkdirSync(dataDir, { recursive: true }); } catch { /* ниже станет видно */ }
    let raw = null;
    try {
      raw = fs.readFileSync(keyFile, 'utf8');
    } catch (e) {
      if (!e || e.code !== 'ENOENT') { st = { state: 'broken', reason: 'key-unreadable' }; return st; }
    }
    if (raw != null) {
      let k = null;
      try {
        const j = JSON.parse(raw);
        if (!j || j.v !== 1 || j.kind !== 'dpapi-user' || typeof j.key !== 'string') throw new Error('format');
        k = await unprotect(Buffer.from(j.key, 'base64'));
        if (!Buffer.isBuffer(k) || k.length !== 32) throw new Error('length');
        if (typeof j.check === 'string' && unseal(k, KEY_FILE, Buffer.from(j.check, 'base64')).toString() !== 'adamant-key-check') throw new Error('check');
      } catch {
        st = { state: 'broken', reason: 'key-unreadable' };
        return st;
      }
      // Ключ мог прийти из другой папки данных: сверяемся с одним зашифрованным файлом.
      const probe = candidates().find(sealedOnDisk);
      if (probe) {
        try { unseal(k, relOf(probe), fs.readFileSync(probe)); } catch { st = { state: 'broken', reason: 'key-mismatch' }; return st; }
      }
      dek = k;
    } else {
      // Ключа нет. Если зашифрованные файлы есть - открыть их нечем, новый ключ молча не создаём.
      if (candidates().some(sealedOnDisk)) { st = { state: 'broken', reason: 'key-missing' }; return st; }
      const k = crypto.randomBytes(32);
      try { await writeKey(k); } catch (e) { st = { state: 'broken', reason: 'dpapi', detail: String(e && e.message || e).slice(0, 200) }; return st; }
      dek = k;
    }
    becomeReady();
    return st;
  }

  /** «Начать заново»: старые зашифрованные файлы и ключ - в папку unreadable-<время>, новый ключ. */
  async function reset() {
    if (st.state === 'ok') return st;
    // Местное время: имя папки видит человек.
    const t = now();
    const p2 = (n) => String(n).padStart(2, '0');
    const stamp = `${t.getFullYear()}${p2(t.getMonth() + 1)}${p2(t.getDate())}-${p2(t.getHours())}${p2(t.getMinutes())}${p2(t.getSeconds())}`;
    const dir = path.join(dataDir, `unreadable-${stamp}`);
    const move = (abs) => {
      const to = path.join(dir, path.relative(dataDir, abs));
      fs.mkdirSync(path.dirname(to), { recursive: true });
      fs.renameSync(abs, to);
    };
    const k = crypto.randomBytes(32);
    const wrapped = await protect(k); // сначала убедимся, что DPAPI работает, потом трогаем файлы
    const sealed = candidates().filter(sealedOnDisk);
    if (fs.existsSync(keyFile)) move(keyFile);
    for (const abs of sealed) move(abs);
    dek = k;
    const check = seal(k, KEY_FILE, Buffer.from('adamant-key-check'));
    const tmp = `${keyFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ v: 1, kind: 'dpapi-user', key: wrapped.toString('base64'), check: check.toString('base64'), created: now().toISOString() }, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, keyFile);
    becomeReady();
    st.movedTo = sealed.length || fs.existsSync(dir) ? path.basename(dir) : null;
    return st;
  }

  return {
    open,
    reset,
    migrate,
    sealFile,
    /** «Уничтожить данные» (server/wipe.js): ключ уже стёрт на диске - забыть его и в памяти. Дальше запись только в память. */
    forget() {
      if (dek) dek.fill(0);
      dek = null;
      st = { state: 'wiped' };
    },
    state: () => ({ ...st }),
    ready: () => st.state === 'ok' && !!dek,
    onReady: (f) => { readyHooks.push(f); },
    isPlainName,
    isSealed,
    /** Байты файла → открытые байты. Открытый файл (старый или из списка открытых) возвращается как есть. */
    decode(name, buf) {
      if (!isSealed(buf)) return buf;
      if (!dek) throw new Error('vault closed');
      return unseal(dek, name, buf);
    },
    /** Открытые байты → то, что пишем на диск. */
    encode(name, plain) {
      if (isPlainName(name)) return plain;
      if (!dek) throw new Error('vault closed');
      return seal(dek, name, Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), 'utf8'));
    },
    relOf,
  };
}

module.exports = { createVault, seal, unseal, isSealed, isPlainName, dpapi, MAGIC, KEY_FILE };
