'use strict';
/**
 * Страж в реальном времени (полная версия): server/ps/watch.ps1 работает, пока работает программа, и раз в минуту
 * сравнивает быстрый слепок автозагрузки, служб, задач, администраторов, Defender, hosts и прокси с прошлым.
 * Важные изменения сразу поднимают тревогу (окно, значок в трее, по желанию - Telegram).
 *
 * Шум отсеиваем: обновление программы, которое меняет только папку с номером версии, удаления, службы пользователя,
 * свои изменения «Адаманта» (автозапуск значка с точной командой, задачи помощника из защищённой папки)
 * и всё, что меняется, пока сама программа применяет исправление.
 */
const path = require('node:path');
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const os = require('node:os');
const { tx, t } = require('./i18n');
const ps = require('./ps');

const SECURITY_SERVICES = { WinDefend: 'Microsoft Defender', mpssvc: t('Брандмауэр Windows'), wscsvc: t('Центр безопасности'), BFE: t('Служба базовой фильтрации'), SecurityHealthService: t('Служба «Безопасность Windows»'), Sense: 'Defender for Endpoint' };

/** Имя программы из команды: «"C:\...\app-1.2\Foo.exe" --x» → foo.exe. */
function exeOf(cmd) {
  const s = String(cmd || '').trim();
  const m = /^"([^"]+)"/.exec(s) || /^(\S+\.(?:exe|cmd|bat|vbs|js|ps1|lnk|com|scr))/i.exec(s) || /^(\S+)/.exec(s);
  return m ? path.win32.basename(m[1]).toLowerCase() : '';
}

/**
 * Изменение из watch.ps1 → сообщение для тревоги или null (шум).
 * own: { autorun: { name, command }, helperDir }.
 */
function classify(c, own = {}) {
  if (!c || typeof c.kind !== 'string') return null;
  const key = String(c.key || '');
  switch (c.kind) {
    case 'autostart': {
      const [loc, ...rest] = key.split('|');
      const name = rest.join('|');
      if (c.change === 'removed') return null;
      if (own.autorun && loc === 'HKCU-Run' && name === own.autorun.name && String(c.to || '').toLowerCase() === String(own.autorun.command || '').toLowerCase()) return null;
      if (c.change === 'changed' && exeOf(c.from) && exeOf(c.from) === exeOf(c.to)) return null;
      return { sev: 'high', text: c.change === 'added' ? tx('Новая программа в автозагрузке: {0}', name) : tx('Автозагрузка «{0}» теперь запускает другое', name), detail: c.to };
    }
    case 'services':
      if (c.change === 'removed') return null;
      if (c.change === 'changed' && exeOf(c.from) === exeOf(c.to)) return null;
      return { sev: 'high', text: c.change === 'added' ? tx('Новая служба Windows: {0}', key) : tx('Служба {0} теперь запускает другую программу', key), detail: c.to };
    case 'svcstart':
      if (c.change !== 'changed' || String(c.to) !== '4') return null;
      return { sev: 'high', text: tx('Отключена служба защиты: {0}', SECURITY_SERVICES[key] || key) };
    case 'tasks':
      if (c.change !== 'added') return null;
      if (own.helperDir && key.toLowerCase().startsWith('\\adamant\\') && String(c.to || '').toLowerCase().includes(String(own.helperDir).toLowerCase())) return null;
      return { sev: 'high', text: tx('Новая задача планировщика: {0}', key), detail: c.to };
    case 'admins':
      return c.change === 'added' ? { sev: 'high', text: tx('Новый администратор компьютера: {0}', key) } : null;
    case 'defender':
      return c.change === 'changed' && c.to === 'off' ? { sev: 'high', text: t('Защита Microsoft Defender в реальном времени выключена') } : null;
    case 'hosts':
      return c.change === 'removed' ? null : { sev: 'high', text: t('Изменён файл hosts: так подменяют адреса сайтов') };
    case 'proxy':
      return c.change === 'removed' ? null : { sev: 'high', text: tx('Включён прокси: весь трафик идёт через {0}', c.to) };
    default:
      return null;
  }
}

/**
 * Наблюдатель. onAlert(items[]) - пачка важных изменений (собираются 3 секунды).
 * own() - свои изменения (см. classify), quiet() - true, пока программа сама что-то меняет.
 */
function createRealtime({ onAlert, own = () => ({}), quiet = () => false, interval = 60, spawnFn = spawn, script = path.join(ps.PS_DIR, 'watch.ps1') } = {}) {
  let child = null;
  let stopped = true;
  let ready = false;
  let restartTimer = null;
  let fails = 0;
  let batch = [];
  let batchTimer = null;
  let started = null;

  function flush() {
    batchTimer = null;
    const items = batch;
    batch = [];
    if (items.length) {
      try { onAlert(items); } catch (e) { console.error('Страж:', e.message); }
    }
  }

  function onLine(line) {
    let c;
    try { c = JSON.parse(line); } catch { return; }
    if (c && c.ready) { ready = true; fails = 0; return; }
    if (quiet()) return;
    const m = classify(c, own());
    if (!m) return;
    batch.push({ ...m, kind: c.kind, change: c.change, key: c.key });
    if (!batchTimer) batchTimer = setTimeout(flush, 3000);
  }

  function launch() {
    if (stopped || child) return;
    ready = false;
    started = Date.now();
    child = spawnFn(ps.POWERSHELL, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, '-Interval', String(interval), '-ParentPid', String(process.pid)], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    try { if (child.pid) os.setPriority(child.pid, os.constants.priority.PRIORITY_LOW); } catch { /* не страшно */ }
    const rl = readline.createInterface({ input: child.stdout });
    rl.on('line', onLine);
    child.on('error', () => {});
    child.on('exit', () => {
      child = null;
      ready = false;
      if (stopped) return;
      // Упал - перезапуск с паузой (до 10 минут), чтобы не крутиться впустую.
      fails = Date.now() - started > 10 * 60_000 ? 1 : fails + 1;
      restartTimer = setTimeout(launch, Math.min(10 * 60_000, 15_000 * 2 ** Math.min(fails, 6)));
      if (restartTimer.unref) restartTimer.unref();
    });
  }

  return {
    start() { if (!stopped) return; stopped = false; launch(); },
    stop() {
      stopped = true;
      if (restartTimer) clearTimeout(restartTimer);
      restartTimer = null;
      if (child) { try { child.kill(); } catch { /* ignore */ } }
      child = null;
      ready = false;
    },
    status: () => ({ running: !stopped, ready }),
    _line: onLine,
  };
}

module.exports = { createRealtime, classify, exeOf };
