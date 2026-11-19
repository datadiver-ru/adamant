'use strict';
/**
 * Где лежат программа и данные.
 *  - Программа: папка на уровень выше server/.
 *  - Данные (отчёты, журнал исправлений, настройки, профиль окна): config.json → dataDir,
 *    иначе переменная ADAMANT_DATA, иначе папка data рядом с программой (запуск из исходников).
 *    Установщик пишет config.json с dataDir = %LOCALAPPDATA%\Adamant.
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function loadConfig(argv = process.argv.slice(2)) {
  let file = {};
  try {
    file = JSON.parse(fs.readFileSync(path.join(ROOT, 'config.json'), 'utf8').replace(/^﻿/, ''));
  } catch { /* нет файла - значения по умолчанию */ }
  const arg = argv.find((a) => a.startsWith('--data='));
  const dataDir = path.resolve(arg ? arg.slice(7) : process.env.ADAMANT_DATA || file.dataDir || path.join(ROOT, 'data'));
  return { root: ROOT, dataDir, version: pkg.version };
}

module.exports = { ROOT, pkg, loadConfig };
