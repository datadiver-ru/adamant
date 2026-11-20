'use strict';
/**
 * Файлы в папке данных:
 *   report.json   - последняя проверка (сведения + находки)
 *   scan.json     - последняя проверка сети
 *   journal.json  - журнал исправлений (что применено, когда, номер записи для отката)
 *   settings.json - язык, работа в фоне
 *   server.json   - порт и ключ работающего сервера (только для ярлыка и значка в трее)
 * Запись атомарная: во временный файл, затем переименование.
 *
 * С vault (server/vault.js) файлы хранятся зашифрованными, кроме settings.json и server.*.
 * Если ключ данных не открылся, новые записи держатся только в памяти (на диск открытым текстом
 * ничего не пишется), а после «Начать заново» сохраняются уже с новым ключом.
 */
const fs = require('node:fs');
const path = require('node:path');

function createStore(dataDir, { vault = null } = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const file = (n) => path.join(dataDir, n);
  const mem = new Map();
  const locked = (name) => !!vault && !vault.ready() && !vault.isPlainName(name);
  function read(name, fallback) {
    if (mem.has(name)) return JSON.parse(mem.get(name));
    try {
      const buf = fs.readFileSync(file(name));
      return JSON.parse((vault ? vault.decode(name, buf) : buf).toString('utf8'));
    } catch {
      return fallback;
    }
  }
  function write(name, value) {
    const text = JSON.stringify(value, null, 1);
    if (locked(name)) { mem.set(name, text); return; }
    const tmp = file(`${name}.${process.pid}.tmp`);
    fs.writeFileSync(tmp, vault ? vault.encode(name, Buffer.from(text, 'utf8')) : text, { mode: 0o600 });
    fs.renameSync(tmp, file(name));
    mem.delete(name);
  }
  // После «Начать заново» - сохранить то, что набралось в памяти.
  if (vault) vault.onReady(() => { for (const [n, text] of [...mem]) write(n, JSON.parse(text)); });
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
      if (typeof patch.introDone === 'boolean') s.introDone = patch.introDone;
      if (typeof patch.stepsHidden === 'boolean') s.stepsHidden = patch.stepsHidden;
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
