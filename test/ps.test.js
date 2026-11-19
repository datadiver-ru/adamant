'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ps = require('../server/ps');
const { parseBcdFirmware } = require('../server/bcd');

const ROOT = path.join(__dirname, '..');
const psFiles = () => ['server/ps', 'server/ps/sections', 'server/ps/helper', 'windows'].filter((d) => fs.existsSync(path.join(ROOT, d))).flatMap((d) => fs.readdirSync(path.join(ROOT, d)).filter((f) => f.endsWith('.ps1')).map((f) => path.join(d, f)));

test('все сценарии PowerShell сохранены с BOM (иначе PowerShell 5.1 ломает русский текст)', () => {
  for (const f of psFiles()) {
    const b = fs.readFileSync(path.join(ROOT, f));
    assert.ok(b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf, `${f}: нет BOM - запустите node tools/ps-bom.js`);
  }
});

test('сценарии проверки только читают: в них нет команд, которые что-то меняют', () => {
  const WRITE = /\b(Set-\w+|New-ItemProperty|New-Item\b|Remove-\w+|Disable-\w+|Enable-\w+|Stop-\w+|Start-Service|Restart-\w+|Add-MpPreference|Rename-\w+|Clear-\w+|Invoke-Expression|reg(\.exe)?\s+(add|delete)|netsh\s+\S+\s+set|bcdedit(\.exe)?["']?\s+\/(set|delete|create))\b/i;
  const sections = fs.existsSync(path.join(ROOT, 'server/ps/sections')) ? fs.readdirSync(path.join(ROOT, 'server/ps/sections')).filter((f) => f.endsWith('.ps1')).map((f) => 'server/ps/sections/' + f) : [];
  for (const f of ['server/ps/collect.ps1', 'server/ps/network.ps1', 'server/ps/traffic.ps1', 'server/ps/bluetooth.ps1', ...sections]) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    const m = WRITE.exec(src);
    assert.equal(m, null, `${f}: ${m && m[0]}`);
  }
});

// Помощник администратора работает от имени SYSTEM, поэтому к нему правило строже, чем к collect.ps1:
// вне участка «запись ответов» нет ни команд, которые что-то меняют, ни записи файлов через .NET и внешние программы.
// Сам участок пишет только в свои папки ($H_Out, $H_Tmp) и только файлы с фиксированными именами.
test('помощник администратора только читает: пишет лишь свои ответы в %ProgramData%\\Adamant\\helper', () => {
  const src = fs.readFileSync(path.join(ROOT, 'server/ps/helper/helper-run.ps1'), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*#(?! (region|endregion))/.test(l)).join('\n');
  const m = /^# region: запись ответов[^\n]*\n([\s\S]*?)^# endregion\s*$/m.exec(code);
  assert.ok(m, 'нет участка «# region: запись ответов … # endregion»');
  const region = m[1];
  const rest = code.replace(m[0], '');
  const WRITE = /\b(Set-\w+|New-ItemProperty|New-Item\b|Remove-\w+|Disable-\w+|Enable-\w+|Stop-\w+|Start-Service|Restart-\w+|Add-MpPreference|Rename-\w+|Clear-\w+|Invoke-Expression|Register-\w+|Unregister-\w+|Copy-Item|Move-Item|Out-File|Add-Content|Export-\w+|reg(\.exe)?\s+(add|delete)|netsh\s+\S+\s+set|bcdedit(\.exe)?["']?\s+\/(set|delete|create)|icacls|takeown|schtasks|cmd(\.exe)?\s|Start-Process)\b/i;
  const NET_WRITE = /\[(System\.)?IO\.(File|Directory|FileInfo|DirectoryInfo)\]::(Write\w*|Append\w*|Create\w*|Delete|Move|Replace|Copy|Set\w+|Open(?!Read|Text))/i;
  for (const [what, re] of [['команда', WRITE], ['запись .NET', NET_WRITE]]) {
    const x = re.exec(rest);
    assert.equal(x, null, `вне участка записи: ${what} ${x && x[0]}`);
  }
  assert.equal(WRITE.exec(region), null, 'в участке записи - только [IO.File]');
  // Каждый путь в участке записи строится от $H_Out или $H_Tmp, имена - по фиксированному шаблону.
  assert.match(region, /-notmatch '\^\(full\|security\|error\)\\\.json\$'/);
  for (const j of region.matchAll(/Join-Path\s+(\$\w+)/g)) assert.ok(['$H_Out', '$H_Tmp'].includes(j[1]), `путь от ${j[1]}`);
  for (const w of region.matchAll(/\[IO\.File\]::(Write\w*|Delete|Move|Replace|SetAccessControl)\(\s*(\$[\w.]+)/g)) assert.ok(['$tmp', '$p', '$f.FullName'].includes(w[2]), `${w[1]}(${w[2]})`);
  // Права ответов: только администраторы, SYSTEM и читатель; наследование выключено.
  assert.match(region, /SetAccessRuleProtection\(\$true, \$false\)/);
  // Своих аргументов - только -Mode из списка; модули - только системные.
  assert.match(src, /param\(\[ValidateSet\('full', 'security'\)\]\[string\]\$Mode = 'security'\)/);
  assert.match(src, /\$env:PSModulePath = "\$H_Sys32\\WindowsPowerShell\\v1\.0\\Modules"/);
});

test('разбор ответа PowerShell: BOM и лишний текст до JSON', () => {
  assert.deepEqual(ps.parseJsonOutput('\uFEFF{"a":1}'), { a: 1 });
  assert.deepEqual(ps.parseJsonOutput('WARNING: x\r\n[1,2]'), [1, 2]);
  assert.throws(() => ps.parseJsonOutput(''));
  assert.throws(() => ps.parseJsonOutput('нет json'));
});

test('команда запроса прав: сценарий только из папки ps, аргументы без кавычек', () => {
  const cmd = ps.elevatedCommand(path.join(ps.PS_DIR, 'fix.ps1'), ['-Action', 'apply', '-Id', 'firewall-on', '-Out', 'C:\\Users\\Пользователь\\x y.json']);
  assert.match(cmd, /-Verb RunAs/);
  assert.match(cmd, /"C:\\Users\\Пользователь\\x y.json"/);
  assert.throws(() => ps.winArg('a"b'));
  assert.throws(() => ps.winArg('a\nb'));
  assert.equal(ps.psQuote("it's"), "'it''s'");
});

test('bcdedit: порядок загрузки с русскими заголовками', () => {
  const ru = `Диспетчер загрузки встроенного ПО
---------------------------------
идентификатор           {fwbootmgr}
displayorder            {bootmgr}
                        {b1}
                        {b2}
timeout                 0

Диспетчер загрузки Windows
--------------------------
идентификатор           {bootmgr}
device                  partition=\\Device\\HarddiskVolume1
description             Windows Boot Manager

Приложение встроенного ПО (101fffff)
------------------------------------
идентификатор           {b1}
description             UEFI: PXE IPv4 Intel(R) Ethernet

Приложение встроенного ПО (101fffff)
------------------------------------
идентификатор           {b2}
description             UEFI: Generic USB
`;
  assert.deepEqual(parseBcdFirmware(ru).map((x) => x.description), ['Windows Boot Manager', 'UEFI: PXE IPv4 Intel(R) Ethernet', 'UEFI: Generic USB']);
  assert.deepEqual(parseBcdFirmware(''), []);
  assert.deepEqual(parseBcdFirmware('The boot configuration data store could not be opened.'), []);
});

test('значок в трее запускается через tray.vbs, а не напрямую powershell.exe', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'server', 'runner.js'), 'utf8');
  const body = src.slice(src.indexOf('function startTray'), src.indexOf('function execReg'));
  // powershell.exe с detached остаётся без консоли и завершается; без detached - гибнет вместе с Node.
  assert.ok(body.includes('tray.vbs') && body.includes('WSCRIPT'));
  assert.ok(!body.includes('ps.POWERSHELL'), 'startTray не должен запускать powershell.exe напрямую');
  const vbs = fs.readFileSync(path.join(__dirname, '..', 'windows', 'tray.vbs'), 'utf8');
  assert.ok(vbs.includes('tray.ps1') && /,\s*0\s*,\s*False/.test(vbs), 'tray.vbs: скрытое окно и без ожидания');
  assert.ok(/InStr\(data, """"\) > 0/.test(vbs), 'tray.vbs отклоняет кавычки в пути к данным');
});
