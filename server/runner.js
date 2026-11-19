'use strict';
/**
 * Связь с Windows: сценарии PowerShell (только чтение - collect, network; исправления - fix с правами администратора),
 * автозапуск значка в трее (HKCU\...\Run - только для текущего пользователя, без прав администратора).
 */
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');
const ps = require('./ps');
const netscan = require('./netscan');
const devnames = require('./devnames');
const upnp = require('./upnp');
const winget = require('./winget');

const ROOT = path.resolve(__dirname, '..');
const WSCRIPT = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wscript.exe');
const REG = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe');
const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const EXPLORER = path.join(process.env.SystemRoot || 'C:\\Windows', 'explorer.exe');
const MPCMDRUN = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Windows Defender', 'MpCmdRun.exe');

/** Проверка одного файла антивирусом Microsoft Defender (найденное он сам уберёт в карантин). Код 2 - найдены угрозы. */
function avScan(file) {
  return new Promise((resolve, reject) => {
    execFile(MPCMDRUN, ['-Scan', '-ScanType', '3', '-File', file], { windowsHide: true, timeout: 10 * 60_000, encoding: 'utf8' }, (err, stdout) => {
      const code = err ? (typeof err.code === 'number' ? err.code : -1) : 0;
      if (err && code === -1) return reject(new Error(err.message));
      const m = /found (\d+) threats?/i.exec(String(stdout));
      const threats = m ? Number(m[1]) : code === 2 ? 1 : 0;
      resolve({ code, threats, clean: code === 0 && threats === 0, failed: code !== 0 && code !== 2 });
    });
  });
}

function createRunner(dataDir) {
  return {
    collect: (full) => (full ? ps.runElevated('collect.ps1', [], { tmpDir: dataDir }) : ps.runJson('collect.ps1')),
    adapters: () => ps.runJson('network.ps1', ['-Mode', 'adapters'], { timeout: 60_000 }),
    neighbors: () => ps.runJson('network.ps1', ['-Mode', 'neighbors'], { timeout: 60_000 }),
    // Сеть и трафик: соединения, скорость, Wi-Fi, общий доступ (traffic.ps1), только чтение.
    traffic: () => ps.runJson('traffic.ps1', [], { timeout: 90_000 }),
    // Bluetooth: сопряжённые устройства и seconds секунд прослушивания эфира (bluetooth.ps1), только чтение. 0 - без эфира.
    bluetooth: (seconds = 10) => ps.runJson('bluetooth.ps1', ['-Seconds', String(Math.max(0, Math.min(20, Number(seconds) || 0)))], { timeout: 90_000 }),
    fix: (args) => ps.runElevated('fix.ps1', args, { tmpDir: dataDir }),
    // Учения: безвредные тесты защиты (drill.ps1), без прав администратора.
    drill: (id) => ps.runJson('drill.ps1', ['-Drill', id], { timeout: 90_000 }),
    probe: netscan.probe,
    // Имена устройств своей сети (mDNS, NetBIOS, роутер) - только при «Найти устройства».
    deviceNames: (ips, opts) => devnames.lookup(ips, opts),
    httpInfo: undefined,
    // Роутер: пробросы портов по UPnP (только чтение, только своя сеть).
    router: () => upnp.inspect(),
    // Скачанные файлы - только по кнопке пользователя (путь проверяет сервер).
    avScan,
    // Обновление программ через winget - только по кнопке (список спрашивает каталог Microsoft).
    wingetList: () => winget.list(),
    wingetUpgrade: (id) => winget.upgrade(id),
    // Кавычек в именах файлов Windows не бывает, поэтому путь можно передать как есть.
    reveal: (file) => { spawn(EXPLORER, [`/select,"${String(file).replace(/"/g, '')}"`], { detached: true, stdio: 'ignore', windowsVerbatimArguments: true }).unref(); },
    trash: (file) => ps.runJson('files.ps1', ['-Action', 'trash', '-Path', file], { timeout: 60_000 }),
    // «Тревога»: отключить от сети / вернуть сеть - только по кнопке, с правами администратора.
    panic: (mode, names = []) => ps.runElevated('panic.ps1', ['-Mode', mode === 'restore' ? 'restore' : 'isolate', ...(names.length ? ['-Names', Buffer.from(JSON.stringify(names), 'utf8').toString('base64')] : [])], { tmpDir: dataDir, timeout: 180_000 }),
  };
}

/**
 * Значок в трее: сценарий windows/tray.ps1 (один экземпляр на пользователя).
 * Запускаем через windows/tray.vbs (WScript.Shell.Run), а не напрямую:
 *  - powershell.exe с detached (DETACHED_PROCESS) остаётся без консоли и молча завершается, не начав работу;
 *  - без detached он погибает вместе с запустившим его Node (launch.js --tray сразу завершается).
 * wscript.exe - оконная программа, ей консоль не нужна, а PowerShell от неё получает свою скрытую консоль и живёт сам по себе.
 */
function startTray(dataDir) {
  const child = spawn(WSCRIPT, [path.join(ROOT, 'windows', 'tray.vbs'), dataDir], { detached: true, stdio: 'ignore', windowsHide: true });
  child.unref();
}

function execReg(args) {
  return new Promise((resolve, reject) => {
    execFile(REG, args, { windowsHide: true, timeout: 15_000 }, (err, stdout, stderr) => (err ? reject(new Error(String(stderr || err.message).trim())) : resolve()));
  });
}

/** Команда автозапуска, которую пишет «Работа в фоне» (Страж узнаёт её как свою). */
const autorunCommand = () => `"${WSCRIPT}" "${path.join(ROOT, 'windows', 'adamant.vbs')}" --tray`;

/** Работа в фоне: значок в трее при входе в Windows. */
function createAutorun(dataDir) {
  return {
    name: 'Adamant',
    command: autorunCommand(),
    async set(on) {
      if (on) {
        const cmd = autorunCommand();
        await execReg(['add', RUN_KEY, '/v', 'Adamant', '/t', 'REG_SZ', '/d', cmd, '/f']);
        startTray(dataDir);
      } else {
        await execReg(['delete', RUN_KEY, '/v', 'Adamant', '/f']).catch(() => {});
      }
    },
  };
}

module.exports = { createRunner, createAutorun, startTray, ROOT };
