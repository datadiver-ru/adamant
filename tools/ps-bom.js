'use strict';
/**
 * Windows PowerShell 5.1 читает .ps1 без BOM в кодировке ANSI - русский текст ломается.
 * Сценарий добавляет BOM UTF-8 всем .ps1 программы. Запуск: node tools/ps-bom.js
 * (тест test/ps.test.js проверяет, что BOM на месте).
 */
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
for (const dir of ['server/ps', 'server/ps/sections', 'server/ps/helper', 'windows']) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) continue;
  for (const f of fs.readdirSync(abs).filter((n) => n.endsWith('.ps1'))) {
    const p = path.join(abs, f);
    const buf = fs.readFileSync(p);
    if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) continue;
    fs.writeFileSync(p, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), buf]));
    console.log('BOM:', path.join(dir, f));
  }
}
