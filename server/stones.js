'use strict';
/**
 * Регистрация камня («Камни: защита данных», этап 2): файл %LOCALAPPDATA%\DataDiver\stones\adamant.json.
 * По нему «Тревога» (этап 3) найдёт команду уничтожения данных Адаманта, как и у других камней:
 *   { "id": "adamant", "name": "Адамант", "version": "…", "wipe": [node, wipe.js, "--wipe-all", "--yes", "--data=…"], "dataDirs": ["…"] }
 * Пишется при запуске сервера (только если что-то изменилось), удаляется при удалении программы
 * (windows/uninstall-app.ps1). В файле нет личных сведений: только пути программы и папки данных.
 */
const nodeFs = require('node:fs');
const path = require('node:path');

const ID = 'adamant';

function stoneFile(env = process.env) {
  const base = env.LOCALAPPDATA;
  return base ? path.join(base, 'DataDiver', 'stones', `${ID}.json`) : null;
}

function describe({ dataDir, version, root, node = process.execPath }) {
  return {
    id: ID,
    name: 'Адамант',
    version,
    wipe: [node, path.join(root, 'server', 'wipe.js'), '--wipe-all', '--yes', `--data=${dataDir}`],
    dataDirs: [dataDir],
  };
}

/** Записать регистрацию. true - файл изменился. */
function register({ dataDir, version, root, node, env = process.env, fs = nodeFs }) {
  const file = stoneFile(env);
  if (!file) return false;
  const text = JSON.stringify(describe({ dataDir, version, root, node }), null, 1);
  try { if (fs.readFileSync(file, 'utf8') === text) return false; } catch { /* ещё нет */ }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text);
  fs.renameSync(tmp, file);
  return true;
}

module.exports = { register, describe, stoneFile, ID };
