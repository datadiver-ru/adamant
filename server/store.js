'use strict';
/**
 * Файлы в папке данных:
 *   report.json   - последняя проверка (сведения + находки)
 *   scan.json     - последняя проверка сети
 *   journal.json  - журнал исправлений (что применено, когда, номер записи для отката)
 *   settings.json - язык, работа в фоне
 *   server.json   - порт и ключ работающего сервера (только для ярлыка и значка в трее)
 * Запись атомарная: во временный файл, затем переименование.
 */
const fs = require('node:fs');
const path = require('node:path');

function createStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = (n) => path.join(dataDir, n);
  function read(name, fallback) {
    try {
      return JSON.parse(fs.readFileSync(file(name), 'utf8'));
    } catch {
      return fallback;
    }
  }
  function write(name, value) {
    const tmp = file(`${name}.${process.pid}.tmp`);
    fs.writeFileSync(tmp, JSON.stringify(value, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, file(name));
  }
  const DEFAULT_SETTINGS = { lang: 'ru', background: false, canary: false, away: false, awayPhoto: false, realtime: true };
  return {
    dataDir,
    read,
    write,
    settings: () => ({ ...DEFAULT_SETTINGS, ...read('settings.json', {}) }),
    saveSettings(patch) {
      const s = { ...this.settings() };
      if (patch.lang === 'ru' || patch.lang === 'en') s.lang = patch.lang;
      if (typeof patch.background === 'boolean') s.background = patch.background;
      if (typeof patch.canary === 'boolean') s.canary = patch.canary;
      if (typeof patch.away === 'boolean') s.away = patch.away;
      if (typeof patch.awayPhoto === 'boolean') s.awayPhoto = patch.awayPhoto;
      if (typeof patch.realtime === 'boolean') s.realtime = patch.realtime;
      write('settings.json', s);
      return s;
    },
    journal: () => read('journal.json', []),
    addJournal(entry) {
      const j = read('journal.json', []);
      j.unshift(entry);
      write('journal.json', j.slice(0, 500));
    },
    updateJournal(record, patch) {
      const j = read('journal.json', []);
      const e = j.find((x) => x.record === record);
      if (e) Object.assign(e, patch);
      write('journal.json', j);
      return e;
    },
  };
}

module.exports = { createStore };
