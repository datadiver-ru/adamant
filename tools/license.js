'use strict';
/**
 * Инструмент автора: выпуск ключей полной версии Адаманта. Запускается только у автора -
 * закрытый ключ (adamant-license-private.pem) не передаётся покупателю и не кладётся в дистрибутив.
 *
 *   node tools/license.js issue --key C:\Users\...\Adamant-vendor\adamant-license-private.pem --licensee "Иван П." [--expires 2027-12-31]
 *   node tools/license.js verify ADAMANT1....
 *
 * Без --expires ключ бессрочный. С --expires удобно выдавать пробный ключ на несколько дней.
 */
const fs = require('node:fs');
const lic = require('../server/license');

const [cmd, ...rest] = process.argv.slice(2);
const opt = (name) => {
  const i = rest.indexOf('--' + name);
  return i >= 0 ? rest[i + 1] : undefined;
};

try {
  if (cmd === 'issue') {
    const keyPath = opt('key');
    if (!keyPath) throw new Error('Укажите --key: путь к закрытому ключу автора');
    const licensee = opt('licensee');
    if (!licensee) throw new Error('Укажите --licensee: кому выдан ключ (имя или название)');
    const expires = opt('expires') || null;
    if (expires && !/^\d{4}-\d{2}-\d{2}$/.test(expires)) throw new Error('--expires в формате ГГГГ-ММ-ДД');
    const key = lic.issue({ licensee, expires }, fs.readFileSync(keyPath, 'utf8'));
    const p = lic.parse(key);
    console.log(`Полная версия для «${p.licensee}», ${p.expires ? 'до ' + p.expires : 'бессрочно'}.`);
    console.log('');
    console.log(key);
  } else if (cmd === 'verify') {
    console.log(JSON.stringify(lic.parse(rest.join('')), null, 2));
  } else {
    console.log('Команды: issue, verify. Подробности - в начале файла tools/license.js.');
  }
} catch (e) {
  console.error('Ошибка: ' + e.message);
  process.exitCode = 1;
}
