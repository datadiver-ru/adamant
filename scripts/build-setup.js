'use strict';
/**
 * Установщик для сайта: dist/Adamant-Setup-<версия>.exe (один файл).
 * Внутри - архив dist/Adamant-<версия>-win-x64.zip и его SHA-256; окно установки - windows/setup/Setup.cs.
 * Собирается компилятором C#, который входит в Windows (.NET Framework 4), - ничего ставить не нужно.
 * Рядом кладётся .sha256. Запуск: npm run setup (сначала соберёт архив).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const DIST = path.join(ROOT, 'dist');
const zip = path.join(DIST, `Adamant-${pkg.version}-win-x64.zip`);
const out = path.join(DIST, `Adamant-Setup-${pkg.version}.exe`);

function findCsc() {
  const win = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  for (const fw of ['Framework64', 'Framework']) {
    const p = path.join(win, 'Microsoft.NET', fw, 'v4.0.30319', 'csc.exe');
    if (fs.existsSync(p)) return p;
  }
  throw new Error('Не найден компилятор C# из .NET Framework 4 (csc.exe)');
}

const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

if (!fs.existsSync(zip)) throw new Error(`Нет архива ${zip}: сначала npm run dist`);
const tmp = fs.mkdtempSync(path.join(DIST, '.setup-'));
try {
  fs.writeFileSync(path.join(tmp, 'version.txt'), pkg.version);
  fs.writeFileSync(path.join(tmp, 'Adamant.sha256'), sha256(zip));
  execFileSync(findCsc(), [
    '/nologo', '/target:winexe', '/optimize+', '/codepage:65001', `/out:${out}`,
    `/win32icon:${path.join(ROOT, 'windows', 'adamant.ico')}`,
    '/reference:System.IO.Compression.dll', '/reference:System.IO.Compression.FileSystem.dll',
    '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll',
    `/resource:${zip},Adamant.zip`, `/resource:${path.join(tmp, 'Adamant.sha256')},Adamant.sha256`, `/resource:${path.join(tmp, 'version.txt')},version.txt`, `/resource:${path.join(ROOT, 'LICENSE')},LICENSE.txt`,
    `/resource:${path.join(ROOT, 'public', 'img', 'diamond.png')},diamond.png`, `/resource:${path.join(ROOT, 'windows', 'setup', 'banner.jpg')},banner.jpg`,
    path.join(ROOT, 'windows', 'setup', 'Setup.cs'),
  ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
} catch (e) {
  const msg = e.stdout ? e.stdout.toString() : '';
  console.error(msg || e.message);
  process.exitCode = 1;
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
if (!process.exitCode) {
  const hash = sha256(out);
  fs.writeFileSync(out + '.sha256', `${hash}  ${path.basename(out)}\n`);
  console.log(`Готово: ${out}`);
  console.log(`Размер: ${(fs.statSync(out).size / 1048576).toFixed(1)} МБ`);
  console.log(`SHA-256: ${hash}`);
}
