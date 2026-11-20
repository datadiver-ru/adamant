'use strict';
/**
 * Сервер «Адаманта». Обычно его запускает ярлык (launch.js), а не человек.
 *  - слушает 127.0.0.1 на случайном свободном порту;
 *  - порт и новый случайный ключ пишет в server.json в папке данных;
 *  - сам завершается, когда окно закрыто и значка в трее нет (3 минуты без обращений);
 *  - если включена работа в фоне - раз в сутки проверяет компьютер (только чтение).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadConfig } = require('./config');
const { createStore } = require('./store');
const { createVault } = require('./vault');
const { createApp } = require('./app');
const { createRunner, createAutorun } = require('./runner');
const { openTarget } = require('./guides');
const { createGuard } = require('./guard');
const { createDrills, exposure } = require('./drills');
const { createCanary, defaultDirs, knownDirs } = require('./canary');
const { createAway } = require('./away');
const { createHelper } = require('./helper');
const { createRealtime } = require('./realtime');
const { createTelegram } = require('./telegram');
const { createWiper, spawnWipeCli } = require('./wipe');
const { register } = require('./stones');
const ps = require('./ps');
const os = require('node:os');

const IDLE_MS = 3 * 60_000;
const BACKGROUND_EVERY = 24 * 3600_000;

async function main() {
  const cfg = loadConfig();
  // Данные хранятся зашифрованными (server/vault.js); ключ открываем после захвата server.lock.
  const vault = createVault({ dataDir: cfg.dataDir });
  const store = createStore(cfg.dataDir, { vault });
  const lockFile = path.join(cfg.dataDir, 'server.lock');
  // Один сервер на папку данных.
  try {
    const fd = fs.openSync(lockFile, 'wx');
    fs.writeSync(fd, String(process.pid));
    fs.closeSync(fd);
  } catch {
    let pid = 0;
    try { pid = Number(fs.readFileSync(lockFile, 'utf8')); } catch { /* ignore */ }
    let alive = false;
    try { process.kill(pid, 0); alive = pid > 0; } catch { alive = false; }
    if (alive) {
      console.error(`Сервер уже запущен (PID ${pid}).`);
      process.exit(0);
    }
    fs.writeFileSync(lockFile, String(process.pid));
  }
  // Первый запуск после обновления: создать ключ и перешифровать открытые файлы. Ключ не открылся -
  // программа работает дальше, окно объясняет, что случилось, и предлагает «Начать заново».
  try {
    const vs = await vault.open();
    if (vs.migrated) console.log(`Данные зашифрованы: файлов ${vs.migrated}`);
    if (vs.migrateErrors) console.error('Шифрование данных:', vs.migrateErrors.join('; '));
    if (vs.state !== 'ok') console.error(`Ключ данных не открылся: ${vs.reason}`);
  } catch (e) {
    console.error('Ключ данных:', e.message);
  }

  // Регистрация камня: по ней «Тревога» найдёт команду уничтожения данных (server/stones.js).
  try { register({ dataDir: cfg.dataDir, version: cfg.version, root: cfg.root }); } catch (e) { console.error('Регистрация камня:', e.message); }

  const key = crypto.randomBytes(24).toString('base64url');
  const runner = createRunner(cfg.dataDir);
  const guard = createGuard(store);
  const drills = createDrills({
    store,
    runDrill: (id) => runner.drill(id),
    exposure: async () => {
      const r = store.read('report.json', null);
      let adapters = [];
      try { adapters = await runner.adapters(); } catch { adapters = []; }
      return exposure({ facts: r ? r.facts : {}, adapters, probe: runner.probe });
    },
  });
  let app = null;
  // Папки для приманок: сразу - по профилю, затем точные пути Windows (с учётом переноса в OneDrive).
  const canaryDirs = defaultDirs();
  knownDirs().then((d) => { if (d && d.length) canaryDirs.splice(0, canaryDirs.length, ...d); }).catch(() => {});
  const canary = createCanary({ dataDir: cfg.dataDir, store, dirs: canaryDirs, onAlert: (a) => app && app.raiseAlert({ kind: 'canary', ...a }) });
  // «Пока вас не было»: работает, пока запущен значок в трее (он сообщает о блокировке и сне).
  const helper = createHelper({ tmpDir: cfg.dataDir });
  const away = createAway({
    store, vault, dataDir: cfg.dataDir,
    helperSecurity: () => helper.readSecurity(),
    watchDirs: () => [...canaryDirs, path.join(process.env.USERPROFILE || os.homedir(), 'Downloads')],
    selfBusy: () => !!(app && app.state.busy), // своя проверка (powershell) не считается чужой программой
  });
  // Telegram (полная версия): выключено, пока человек сам не включит; отправляет только короткие тревоги.
  const telegram = createTelegram({ dataDir: cfg.dataDir, store, lang: () => store.settings().lang });
  const tgOn = () => !!(app && app.paid('telegram'));
  const notify = (a) => (tgOn() ? telegram.notifyAlert(a.kind, app.alertText(store.settings().lang, a)) : null);
  // Страж в реальном времени (полная версия): работает, пока работает программа, и если не выключен в настройках.
  const live = createRealtime({
    onAlert: (items) => app && app.raiseAlert({ kind: 'guard', items }),
    own: () => (app ? app.ownChanges() : {}),
    quiet: () => !!(app && app.isQuiet()),
  });
  const realtime = {
    status: live.status,
    sync() {
      const want = !!(app && app.paid('realtime') && store.settings().realtime !== false);
      if (want) live.start(); else live.stop();
    },
  };
  // «Уничтожить данные»: приманки, ключ и часть с UAC - сразу; закрыть программу и удалить папку - отдельным процессом.
  const wiper = createWiper({
    dataDir: cfg.dataDir, root: cfg.root, vault, canary,
    stopWatchers: () => { away.stop(); live.stop(); },
    runAdmin: () => ps.runElevated('wipe-admin.ps1', [], { tmpDir: os.tmpdir() }),
    spawnCli: () => spawnWipeCli({ dataDir: cfg.dataDir }),
  });
  app = createApp({ store, key, version: cfg.version, runner, autorun: createAutorun(cfg.dataDir), openTarget, guard, drills, canary, away, helper, realtime, notify, telegram, vault, wiper });
  realtime.sync();
  // После обновления: автозапуск через adamant.vbs → через Adamant.exe (только своё значение и только при работе в фоне).
  if (store.settings().background) {
    const ar = createAutorun(cfg.dataDir);
    ar.migrate().then((done) => { if (done) console.log('Автозапуск: теперь через Adamant.exe'); }).catch((e) => console.error('Автозапуск:', e.message));
  }
  // Лицензию могут ввести или она может закончиться - сверяемся раз в 30 секунд. Там же - «Пока вас не было» для Telegram.
  setInterval(() => {
    try { realtime.sync(); } catch (e) { console.error('Страж:', e.message); }
    if (tgOn() && store.settings().away) {
      try { telegram.notifyAway(away.report({ days: 1 })); } catch (e) { console.error('Telegram:', e.message); }
    }
  }, 30_000).unref();
  setInterval(() => { Promise.resolve().then(() => away.tick()).catch(() => {}); }, 15_000).unref();
  // Приманки следят, пока работает программа (окно открыто или включена работа в фоне).
  if (store.settings().canary) {
    try { canary.watch(); } catch (e) { console.error('Приманки:', e.message); }
  }
  const serverFile = path.join(cfg.dataDir, 'server.json');

  function shutdown() {
    try { away.stop(); } catch { /* ignore */ }
    try { live.stop(); } catch { /* ignore */ }
    try {
      const cur = JSON.parse(fs.readFileSync(serverFile, 'utf8'));
      if (cur.pid === process.pid) fs.unlinkSync(serverFile);
    } catch { /* ignore */ }
    try { if (Number(fs.readFileSync(lockFile, 'utf8')) === process.pid) fs.unlinkSync(lockFile); } catch { /* ignore */ }
    process.exit(0);
  }
  process.on('adamant-shutdown', shutdown);
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  // --port=N - только для разработки; обычно порт случайный.
  const portArg = process.argv.find((a) => a.startsWith('--port='));
  const listenPort = portArg ? Number(portArg.slice(7)) || 0 : 0;
  app.server.listen(listenPort, '127.0.0.1', () => {
    const port = app.server.address().port;
    fs.writeFileSync(serverFile, JSON.stringify({ port, key, pid: process.pid, started: new Date().toISOString() }), { mode: 0o600 });
    console.log(`Адамант ${cfg.version}: http://127.0.0.1:${port}/ (данные: ${cfg.dataDir})`);
  });

  setInterval(() => {
    if (!app.state.busy && Date.now() - app.state.lastSeen > IDLE_MS) shutdown();
  }, 30_000).unref();

  // Фоновая проверка: раз в сутки, только чтение.
  setInterval(() => {
    if (!store.settings().background || app.state.busy) return;
    const r = app.report();
    if (!r || Date.now() - Date.parse(r.at) > BACKGROUND_EVERY) app.runCheck(false).catch((e) => console.error('Фоновая проверка:', e.message));
  }, 30 * 60_000);
}

main().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
