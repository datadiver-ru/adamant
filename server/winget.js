'use strict';
/**
 * Обновление программ через winget (встроен в Windows 10/11 как «Установщик приложений»).
 *  - list()     - `winget upgrade`: какие программы можно обновить. winget спрашивает свой каталог у Microsoft -
 *                 это единственный запрос в интернет, и только по кнопке «Найти обновления»;
 *  - upgrade(id) - `winget upgrade --id <id> --exact --silent`: скачивает и ставит новую версию. Только по кнопке.
 * Источник - только каталог winget (--source winget). Условия каталога и пакета принимаются флагами
 * --accept-source-agreements и --accept-package-agreements: об этом сказано у кнопки в окне.
 * Таблицу winget разбираем по позициям столбцов строки заголовка (над строкой из дефисов): подписи бывают
 * на любом языке, а в именах программ есть пробелы.
 */
const { execFile } = require('node:child_process');

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/;
const FLAGS = ['--source', 'winget', '--accept-source-agreements', '--disable-interactivity'];

/** Последний кусок строки после возврата каретки: winget рисует «крутилку» символом \r. */
const clean = (line) => String(line).replace(/\r+$/, '').split('\r').pop().replace(/[\u0008]/g, '').replace(/\s+$/, '');

/** Начала столбцов: позиции, где после пробела начинается слово. */
function columns(header) {
  const starts = [];
  for (let i = 0; i < header.length; i += 1) if (header[i] !== ' ' && (i === 0 || header[i - 1] === ' ')) starts.push(i);
  return starts;
}

/** Таблицы из вывода `winget upgrade` → [{ name, id, version, available }]. */
function parseUpgrade(text) {
  const lines = String(text || '').split('\n').map(clean);
  const out = [];
  const seen = new Set();
  for (let i = 1; i < lines.length; i += 1) {
    if (!/^-{10,}$/.test(lines[i].trim())) continue;
    const header = lines[i - 1];
    const cols = columns(header);
    if (cols.length < 4) continue;
    for (let j = i + 1; j < lines.length; j += 1) {
      const l = lines[j];
      if (!l.trim() || /^-{10,}$/.test(l.trim())) break;
      if (l.length < cols[2]) break; // строка итога («21 upgrades available.»)
      const cut = (k) => l.slice(cols[k], k + 1 < cols.length ? cols[k + 1] : undefined).trim();
      let name = cut(0); let id = cut(1); let version = cut(2); let available = cut(3);
      if (!ID_RE.test(id)) {
        // Выравнивание сбилось (широкие символы в имени) - разбираем справа по двойным пробелам.
        const parts = l.trim().split(/\s{2,}|\s(?=\S+\s+\S+\s+\S+$)/);
        if (parts.length < 4) continue;
        const tail = cols.length > 4 ? 1 : 0;
        available = parts[parts.length - 1 - tail]; version = parts[parts.length - 2 - tail]; id = parts[parts.length - 3 - tail];
        name = parts.slice(0, parts.length - 3 - tail).join(' ');
        if (!ID_RE.test(id)) continue;
      }
      if (!available || seen.has(id.toLowerCase())) continue;
      seen.add(id.toLowerCase());
      out.push({ name: name.replace(/…$/, '').trim() || id, id, version, available });
    }
  }
  return out;
}

function run(args, { timeout, exec = execFile } = {}) {
  return new Promise((resolve, reject) => {
    exec('winget', args, { encoding: 'buffer', windowsHide: true, timeout, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      const text = Buffer.isBuffer(stdout) ? stdout.toString('utf8') : String(stdout || '');
      if (err && (err.code === 'ENOENT' || err.errno === -4058)) {
        const e = new Error('winget не найден');
        e.code = 'NO_WINGET';
        return reject(e);
      }
      if (err && err.killed) return reject(new Error('timeout'));
      // У winget свои коды выхода (0x8A15xxxx); как беззнаковое число - для показа.
      const code = err ? (typeof err.code === 'number' ? err.code >>> 0 : -1) : 0;
      resolve({ code, text, err: Buffer.isBuffer(stderr) ? stderr.toString('utf8') : String(stderr || '') });
    });
  });
}

async function list(opts = {}) {
  const r = await run(['upgrade', ...FLAGS], { timeout: 180_000, ...opts });
  return parseUpgrade(r.text);
}

/** Известные коды winget → понятная причина. */
const CODES = {
  0x8a15002b: 'no-upgrade', // нет обновления для этой версии
  0x8a150011: 'no-installer', // нет установщика для этой системы
  0x8a150010: 'not-found',
  0x8a150056: 'pinned',
  0x8a150109: 'reboot', // нужна перезагрузка
  0x8a15010c: 'running', // программа запущена
  0x8a150116: 'cancelled',
};

async function upgrade(id, opts = {}) {
  if (!ID_RE.test(String(id))) throw new Error('bad id');
  const r = await run(['upgrade', '--id', id, '--exact', '--silent', '--accept-package-agreements', ...FLAGS], { timeout: 30 * 60_000, ...opts });
  const reason = r.code === 0 ? null : CODES[r.code] || 'error';
  return { id, ok: r.code === 0 || reason === 'reboot', code: r.code, reason, hex: r.code ? '0x' + r.code.toString(16).toUpperCase() : null };
}

module.exports = { parseUpgrade, columns, list, upgrade, ID_RE, CODES };
