'use strict';
/**
 * Запуск с ярлыка.
 *   node server/launch.js               - запустить сервер (если нужно) и открыть окно программы
 *   node server/launch.js --background  - только сервер
 *   node server/launch.js --tray        - сервер и значок в трее (автозапуск при входе в Windows)
 *   node server/launch.js --stop        - остановить сервер
 * Окно - Microsoft Edge (или Chrome) в режиме приложения: без адресной строки и вкладок, со своим профилем
 * в папке данных. Ключ доступа передаётся в части адреса после «#»: она не уходит на сервер и не пишется в журналы.
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { loadConfig } = require('./config');
const { startTray } = require('./runner');

const cfg = loadConfig();
const args = process.argv.slice(2);
const SERVER_FILE = path.join(cfg.dataDir, 'server.json');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function readServer() {
  try {
    const s = JSON.parse(fs.readFileSync(SERVER_FILE, 'utf8'));
    return Number.isInteger(s.port) && typeof s.key === 'string' ? s : null;
  } catch {
    return null;
  }
}

async function call(s, route, body = {}) {
  const r = await fetch(`http://127.0.0.1:${s.port}${route}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Adamant-Key': s.key }, body: JSON.stringify(body), signal: AbortSignal.timeout(2000),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function alive() {
  const s = readServer();
  if (!s) return null;
  try {
    await call(s, '/api/heartbeat');
    return s;
  } catch {
    return null;
  }
}

async function ensureServer() {
  let s = await alive();
  if (s) return s;
  fs.mkdirSync(cfg.dataDir, { recursive: true });
  const log = fs.openSync(path.join(cfg.dataDir, 'server.log'), 'a');
  spawn(process.execPath, [path.join(__dirname, 'index.js'), `--data=${cfg.dataDir}`], { cwd: cfg.root, detached: true, windowsHide: true, stdio: ['ignore', log, log] }).unref();
  for (let i = 0; i < 80; i++) {
    await sleep(150);
    if ((s = await alive())) return s;
  }
  throw new Error('Сервер не запустился. Подробности - в server.log в папке данных.');
}

/** Edge есть в каждой Windows 10/11; если его удалили - Chrome; иначе обычный браузер. */
function findAppBrowser() {
  const pf = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean);
  const candidates = [
    ...pf.map((p) => path.join(p, 'Microsoft', 'Edge', 'Application', 'msedge.exe')),
    ...pf.map((p) => path.join(p, 'Google', 'Chrome', 'Application', 'chrome.exe')),
  ];
  return candidates.find((c) => fs.existsSync(c)) || null;
}

function openWindow(s) {
  const url = `http://127.0.0.1:${s.port}/#key=${encodeURIComponent(s.key)}`;
  const browser = findAppBrowser();
  if (browser) {
    spawn(browser, [
      `--app=${url}`, `--user-data-dir=${path.join(cfg.dataDir, 'window')}`, '--no-first-run', '--no-default-browser-check',
      '--disable-sync', '--disable-features=Translate,msEdgeSidebarV2,msUndersideButton', '--window-size=1240,860', '--lang=' + (readLang() === 'en' ? 'en-US' : 'ru'),
    ], { detached: true, stdio: 'ignore' }).unref();
  } else {
    spawn('cmd.exe', [`/c start "" "${url}"`], { detached: true, stdio: 'ignore', windowsVerbatimArguments: true, windowsHide: true }).unref();
  }
}

function readLang() {
  try {
    return JSON.parse(fs.readFileSync(path.join(cfg.dataDir, 'settings.json'), 'utf8')).lang;
  } catch {
    return 'ru';
  }
}

async function main() {
  if (args.includes('--stop')) {
    const s = await alive();
    if (!s) return console.log('Адамант не запущен.');
    await call(s, '/api/shutdown').catch(() => {});
    return console.log('Адамант остановлен.');
  }
  const s = await ensureServer();
  if (args.includes('--background')) return;
  if (args.includes('--tray')) return startTray(cfg.dataDir);
  openWindow(s);
}

main().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
