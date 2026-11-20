# Адамант: установка на этот компьютер для текущего пользователя Windows. Права администратора не нужны.
#
#   powershell -ExecutionPolicy Bypass -File windows\install-app.ps1
#
# Что делает:
#  1. Копирует программу в InstallDir (по умолчанию %LOCALAPPDATA%\Programs\Adamant).
#     Данные (отчёты, журнал исправлений, настройки) живут отдельно - в %LOCALAPPDATA%\Adamant,
#     поэтому обновление их не трогает.
#  2. Кладёт ярлык «Адамант» на рабочий стол и в меню «Пуск», добавляет программу в «Установленные приложения»
#     (там же - удаление).
#  3. Запускает программу.
# Ничего не скачивает, брандмауэр, службы и настройки Windows не меняет.
param(
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Adamant'),
  [string]$DataDir = (Join-Path $env:LOCALAPPDATA 'Adamant'),
  [switch]$NoShortcuts,
  [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
trap {
  Write-Host ''
  Write-Host ('Установка не завершена: ' + $_.Exception.Message) -ForegroundColor Red
  exit 1
}

$src = Split-Path -Parent $PSScriptRoot
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$DataDir = [IO.Path]::GetFullPath($DataDir)
if ([IO.Path]::GetFullPath($src).TrimEnd('\') -ieq $InstallDir.TrimEnd('\')) { throw "Программа уже установлена в $InstallDir. Запустите установщик из распакованного архива." }
if (-not (Test-Path (Join-Path $src 'runtime\node.exe')) -and -not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw 'В комплекте нет runtime\node.exe, а Node.js на компьютере не найден.'
}

# Работающая копия держит файлы: останавливаем сервер и значок в трее.
if (Test-Path (Join-Path $InstallDir 'server\launch.js')) {
  Write-Host 'Остановка запущенной программы ...'
  $n = Join-Path $InstallDir 'runtime\node.exe'
  if (-not (Test-Path $n)) { $n = 'node' }
  & $n (Join-Path $InstallDir 'server\launch.js') --stop 2>$null | Out-Null
  $tray = (Join-Path $InstallDir 'windows\tray.ps1')
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($tray) } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }
  Start-Sleep -Seconds 1
}

Write-Host "1. Копирование программы в $InstallDir ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($d in @('server', 'public', 'windows', 'runtime') | Where-Object { Test-Path (Join-Path $src $_) }) {
  robocopy (Join-Path $src $d) (Join-Path $InstallDir $d) /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "Не удалось скопировать $d (код robocopy $LASTEXITCODE)" }
}
foreach ($f in @('package.json', 'LICENSE', 'README.md', 'SECURITY.md', 'CHANGELOG.md')) {
  $p = Join-Path $src $f
  if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
}
# Без BOM: так его читает программа.
$cfg = [ordered]@{ dataDir = $DataDir }
[IO.File]::WriteAllText((Join-Path $InstallDir 'config.json'), ($cfg | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))

Write-Host "2. Папка данных $DataDir ..."
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$vbs = Join-Path $InstallDir 'windows\adamant.vbs'
# Adamant.exe - запуск без окна консоли; adamant.vbs остаётся только для старых ярлыков и автозапуска.
$exe = Join-Path $InstallDir 'Adamant.exe'
$useExe = Test-Path -LiteralPath $exe
$ico = Join-Path $InstallDir 'windows\adamant.ico'
$wscript = Join-Path $env:WINDIR 'System32\wscript.exe'
if (-not $NoShortcuts) {
  Write-Host '3. Ярлыки и «Установленные приложения» ...'
  $shell = New-Object -ComObject WScript.Shell
  function New-Link($path, $description) {
    $l = $shell.CreateShortcut($path)
    if ($useExe) { $l.TargetPath = $exe; $l.Arguments = '' } else { $l.TargetPath = $wscript; $l.Arguments = '"' + $vbs + '"' }
    $l.WorkingDirectory = $InstallDir
    $l.IconLocation = $ico + ',0'
    $l.Description = $description
    $l.Save()
  }
  $desktop = [Environment]::GetFolderPath('Desktop')
  $menu = [Environment]::GetFolderPath('Programs')
  New-Link (Join-Path $desktop 'Адамант.lnk') 'Адамант - проверка защиты компьютера'
  New-Link (Join-Path $menu 'Адамант.lnk') 'Адамант - проверка защиты компьютера'

  $pkg = Get-Content (Join-Path $InstallDir 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $un = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $InstallDir 'windows\uninstall-app.ps1') + '"'
  $size = [int]((Get-ChildItem $InstallDir -Recurse -File | Measure-Object Length -Sum).Sum / 1KB)
  $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Adamant'
  New-Item -Path $key -Force | Out-Null
  $vals = @{ DisplayName = 'Адамант'; DisplayVersion = [string]$pkg.version; Publisher = 'Adamant'; DisplayIcon = $ico; InstallLocation = $InstallDir; UninstallString = $un; HelpLink = 'mailto:data.diver.ru@gmail.com' }
  foreach ($k in $vals.Keys) { New-ItemProperty -Path $key -Name $k -Value $vals[$k] -PropertyType String -Force | Out-Null }
  foreach ($k in @('NoModify', 'NoRepair')) { New-ItemProperty -Path $key -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }
  New-ItemProperty -Path $key -Name EstimatedSize -Value $size -PropertyType DWord -Force | Out-Null
}

Write-Host ''
Write-Host "Готово. Программа: $InstallDir"
Write-Host "        Данные:    $DataDir"
if (-not $NoLaunch) {
  if ($useExe) { Start-Process -FilePath $exe -WorkingDirectory $InstallDir } else { Start-Process -FilePath $wscript -ArgumentList ('"' + $vbs + '"') }
  Write-Host 'Адамант откроется в своём окне и сразу проверит компьютер.'
}
# Явный код выхода: иначе установщик .exe увидел бы код последней внешней программы (robocopy возвращает 1 при успехе).
exit 0
