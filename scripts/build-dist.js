'use strict';
/**
 * Сборка дистрибутива: dist/Adamant-<версия>-win-x64.zip
 *   Adamant-<версия>/
 *     Установить Адамант.cmd    - установка в один щелчок (без прав администратора)
 *     Adamant.exe - запуск прямо из папки (windows/launcher/Launcher.cs, собирается здесь же)
 *     Прочитайте.txt
 *     server/ public/ windows/   - программа
 *     runtime/node.exe           - Node.js, на котором прошли тесты: ставить его отдельно не нужно
 *     manifest.json              - SHA-256 каждого файла
 * Рядом с архивом - .sha256. Тесты, инструменты и данные в архив не входят.
 * Запуск: npm run dist
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { zip } = require('./zip');

const ROOT = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const base = `Adamant-${pkg.version}`;

function walk(rel) {
  const out = [];
  for (const e of fs.readdirSync(path.join(ROOT, rel), { withFileTypes: true })) {
    const r = `${rel}/${e.name}`;
    if (e.isDirectory()) out.push(...walk(r));
    else out.push(r);
  }
  return out;
}
const crlf = (s) => Buffer.from(s.replace(/\r?\n/g, '\r\n'), 'utf8');

/** Состав программы (общий для сборки и тестов). */
function appFiles() {
  const files = [];
  for (const d of ['server', 'public', 'windows']) for (const f of walk(d)) if (!f.startsWith('windows/setup/') && !f.startsWith('windows/launcher/')) files.push({ name: f, data: fs.readFileSync(path.join(ROOT, f)) });
  for (const f of ['package.json', 'LICENSE', 'README.md', 'SECURITY.md', 'CHANGELOG.md']) {
    if (fs.existsSync(path.join(ROOT, f))) files.push({ name: f, data: fs.readFileSync(path.join(ROOT, f)) });
  }
  return files;
}

/** Adamant.exe: запуск без окна консоли вместо скриптов VBS (компилятор C# из .NET Framework 4, как у установщика). */
function buildLauncher() {
  const win = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
  const csc = ['Framework64', 'Framework'].map((fw) => path.join(win, 'Microsoft.NET', fw, 'v4.0.30319', 'csc.exe')).find((p) => fs.existsSync(p));
  if (!csc) throw new Error('Не найден компилятор C# из .NET Framework 4 (csc.exe)');
  const tmp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'adamant-launcher-'));
  try {
    const out = path.join(tmp, 'Adamant.exe');
    require('node:child_process').execFileSync(csc, ['/nologo', '/target:winexe', '/optimize+', '/codepage:65001', `/out:${out}`,
      `/win32icon:${path.join(ROOT, 'windows', 'adamant.ico')}`, path.join(ROOT, 'windows', 'launcher', 'Launcher.cs')], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    return fs.readFileSync(out);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

function launchers() {
  return [
    { name: 'Установить Адамант.cmd', data: crlf('@echo off\nrem Адамант: установка на этот компьютер для текущего пользователя (без прав администратора).\nchcp 65001 >nul\npowershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\\install-app.ps1" %*\npause\n') },
    { name: 'Adamant.exe', data: buildLauncher() },
    { name: 'Прочитайте.txt', data: crlf(`Адамант ${pkg.version} - проверка защиты компьютера с Windows и своей сети

УСТАНОВКА
  Дважды щёлкните «Установить Адамант.cmd». Права администратора не нужны.
  Программа появится на рабочем столе и в меню «Пуск», удаляется через «Параметры» → «Приложения».
  Без установки: дважды щёлкните Adamant.exe (отчёты сохраняются в папке data рядом).

ЧТО ДЕЛАЕТ
  - Проверяет брандмауэр, антивирус, SMBv1, удалённый рабочий стол, UAC, учётные записи, автозагрузку,
    обновления, BitLocker, Secure Boot, TPM, пароль BIOS/UEFI и порядок загрузки, открытые порты.
  - Находит устройства и опасные службы в вашей домашней или офисной сети (только частные адреса).
  - Исправляет найденное по кнопке «Применить» с разрешения администратора; любое исправление можно откатить.

ПРИВАТНОСТЬ
  Программа сама ничего не отправляет в интернет. Исключения - только если вы сами их включили:
  «Проверить обновления» (один запрос на GitHub по кнопке) и уведомления в Telegram.
  Проверки только читают настройки.
  Изменения - только по вашей кнопке, прежние значения сохраняются для отката.

БРАУЗЕР ИЛИ WINDOWS ПРЕДУПРЕЖДАЮТ - ЭТО ОЖИДАЕМО
  Адамант пока не подписан сертификатом разработчика, а Windows и браузеры
  предупреждают о любой новой программе, которую скачало мало людей.
  Само предупреждение не значит, что в файле вирус.
  - Браузер не даёт скачать: откройте список загрузок (стрелка справа вверху), нажмите на файл
    или на «...» рядом с ним и выберите «Сохранить» / «Всё равно сохранить» / «Скачать».
  - Синее окно «Система Windows защитила ваш компьютер»: нажмите «Подробнее»,
    затем «Выполнить в любом случае».
  Так поступайте только с файлом с сайта datadiver-ru.github.io или со страницы
  github.com/datadiver-ru/adamant. Если Адамант прислали в чате или он лежит на другом сайте -
  не запускайте.
Целостность архива: сравните SHA-256 архива с файлом .sha256, который выдал автор.

Вопросы: data.diver.ru@gmail.com
`) },
    { name: 'runtime/node.exe', data: fs.readFileSync(process.execPath) },
    { name: 'runtime/NOTICE.txt', data: crlf(`Node.js ${process.version} (${process.platform}-${process.arch})\nCopyright Node.js contributors. MIT License; bundled libraries (V8, OpenSSL, ICU, libuv and others) under their own licenses.\nFull text: https://github.com/nodejs/node/blob/${process.version}/LICENSE\n`) },
  ];
}

function build() {
  if (process.platform !== 'win32') throw new Error('Дистрибутив собирается на Windows: в него кладётся node.exe, на котором прошли тесты.');
  const files = [...appFiles(), ...launchers()];
  const manifest = { app: 'adamant', version: pkg.version, node: process.version, createdAt: new Date().toISOString(), files: files.map((f) => ({ name: f.name, size: f.data.length, sha256: crypto.createHash('sha256').update(f.data).digest('hex') })) };
  files.push({ name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 1)) });
  const out = path.join(ROOT, 'dist');
  fs.mkdirSync(out, { recursive: true });
  const zipPath = path.join(out, `${base}-win-x64.zip`);
  const buf = zip(files.map((f) => ({ name: `${base}/${f.name}`, data: f.data })));
  fs.writeFileSync(zipPath + '.tmp', buf);
  fs.renameSync(zipPath + '.tmp', zipPath);
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  fs.writeFileSync(zipPath + '.sha256', `${sha}  ${path.basename(zipPath)}\n`);
  return { zipPath, sha, size: buf.length, count: files.length };
}

if (require.main === module) {
  try {
    const r = build();
    console.log(`Готово: ${r.zipPath}`);
    console.log(`Размер: ${(r.size / 1048576).toFixed(1)} МБ, файлов: ${r.count}`);
    console.log(`SHA-256: ${r.sha}`);
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}

module.exports = { appFiles, launchers, build, base };
