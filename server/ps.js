'use strict';
/**
 * Запуск сценариев PowerShell из server/ps.
 *  - runJson: обычный запуск с правами пользователя, ответ - JSON в stdout.
 *  - runElevated: запуск с правами администратора через запрос UAC (Start-Process -Verb RunAs).
 *    Ответ сценарий пишет в файл -Out, потому что вывод повышенного процесса недоступен.
 * Сценарии принимают только проверенные значения (см. fixes.js): имена из списка, GUID, Base64.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

const PS_DIR = path.join(__dirname, 'ps');
const POWERSHELL = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const BASE = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass'];

/** Разбор вывода: BOM, лишние строки до JSON. */
function parseJsonOutput(text) {
  const s = String(text || '').replace(/^\uFEFF/, '').trim();
  if (!s) throw new Error('пустой ответ');
  try {
    return JSON.parse(s);
  } catch {
    const i = Math.min(...['{', '['].map((c) => (s.indexOf(c) < 0 ? Infinity : s.indexOf(c))));
    if (!Number.isFinite(i)) throw new Error('ответ не похож на JSON');
    return JSON.parse(s.slice(i));
  }
}

function scriptPath(name) {
  if (!/^[a-z-]+\.ps1$/.test(name)) throw new Error('недопустимое имя сценария');
  return path.join(PS_DIR, name);
}

/** Проверки идут с пониженным приоритетом: компьютер не должен тормозить, пока «Адамант» смотрит настройки. */
function lowerPriority(child) {
  try { if (child && child.pid) os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL); } catch { /* не страшно */ }
}

function runJson(name, args = [], { timeout = 180_000, input = null } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(POWERSHELL, [...BASE, '-File', scriptPath(name), ...args],
      { windowsHide: true, timeout, maxBuffer: 64 * 1024 * 1024, encoding: 'utf8' },
      (err, stdout, stderr) => {
        if (err && !stdout) return reject(new Error((stderr || err.message).trim().slice(0, 500)));
        try {
          resolve(parseJsonOutput(stdout));
        } catch (e) {
          reject(new Error(`${name}: ${e.message}. ${String(stderr || '').trim().slice(0, 300)}`));
        }
      });
    // Данные для сценария (например, учебная строка учений) - через стандартный ввод, не в командной строке.
    if (input != null && child.stdin) child.stdin.end(String(input));
    lowerPriority(child);
  });
}

/** Строка в одинарных кавычках PowerShell. */
const psQuote = (s) => "'" + String(s).replace(/'/g, "''") + "'";
/** Аргумент командной строки Windows в двойных кавычках (значения уже проверены: без кавычек). */
function winArg(s) {
  s = String(s);
  if (/["\r\n\0]/.test(s)) throw new Error('недопустимый символ в аргументе');
  return /[\s]/.test(s) || s === '' ? `"${s.replace(/(\\+)$/, '$1$1')}"` : s;
}

/** Команда для powershell -Command, которая запрашивает права и ждёт завершения. */
function elevatedCommand(file, args) {
  const inner = [...BASE, '-WindowStyle', 'Hidden', '-File', winArg(file), ...args.map(winArg)].join(' ');
  return `$ErrorActionPreference='Stop'; try { $p = Start-Process -FilePath ${psQuote(POWERSHELL)} -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList ${psQuote(inner)}; exit $p.ExitCode } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1223 }`;
}

/**
 * Запуск с правами администратора. Возвращает JSON из файла ответа.
 * Отказ в окне UAC → ошибка с code = 'CANCELLED'.
 */
function runElevated(name, args = [], { timeout = 600_000, tmpDir = os.tmpdir() } = {}) {
  const out = path.join(tmpDir, `adamant-${process.pid}-${crypto.randomBytes(6).toString('hex')}.json`);
  return new Promise((resolve, reject) => {
    execFile(POWERSHELL, [...BASE, '-Command', elevatedCommand(scriptPath(name), [...args, '-Out', out])],
      { windowsHide: true, timeout, encoding: 'utf8' },
      (err, stdout, stderr) => {
        let data = null;
        try {
          data = parseJsonOutput(fs.readFileSync(out, 'utf8'));
        } catch { /* файла нет */ }
        try { fs.unlinkSync(out); } catch { /* ignore */ }
        if (data) return resolve(data);
        const e = new Error(err && err.code === 1223 ? 'Запрос прав администратора отклонён' : (String(stderr || '').trim() || 'Сценарий не вернул ответ').slice(0, 500));
        if (err && err.code === 1223) e.code = 'CANCELLED';
        reject(e);
      });
  });
}

module.exports = { runJson, runElevated, parseJsonOutput, elevatedCommand, winArg, psQuote, PS_DIR, POWERSHELL };
