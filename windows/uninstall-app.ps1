# Адамант: удаление с компьютера (установка для текущего пользователя).
# Запускается из «Параметры» → «Приложения» или вручную:
#   powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Programs\Adamant\windows\uninstall-app.ps1"
# Отчёты и журнал исправлений (папка данных) остаются: удалите их сами, если они не нужны.
param([string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Adamant'))
$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:LOCALAPPDATA 'Adamant'
try { $cur = Get-Content (Join-Path $InstallDir 'config.json') -Raw -Encoding UTF8 | ConvertFrom-Json; if ($cur.dataDir) { $dataDir = $cur.dataDir } } catch {}

# Значок в трее при входе в Windows.
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Adamant' -ErrorAction SilentlyContinue
$tray = Join-Path $InstallDir 'windows\tray.ps1'
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($tray) } | ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName Terminate | Out-Null }

$node = Join-Path $InstallDir 'runtime\node.exe'
if (Test-Path (Join-Path $InstallDir 'server\launch.js')) {
  $n = if (Test-Path $node) { $node } else { 'node' }
  & $n (Join-Path $InstallDir 'server\launch.js') --stop 2>$null | Out-Null
  Start-Sleep -Seconds 1
}

# Помощник администратора (если ставили): спрашиваем и удаляем с разрешением UAC. Без помощника окна UAC нет.
# Запускаем защищённую копию из Program Files (её не может подменить обычная программа), иначе - копию программы.
$pf = [Environment]::GetEnvironmentVariable('ProgramW6432')
if (-not $pf) { $pf = $env:ProgramFiles }
$helperDir = Join-Path $pf 'Adamant\Helper'
if (Test-Path -LiteralPath (Join-Path $helperDir 'helper.json')) {
  Write-Host ''
  Write-Host 'На компьютере установлен помощник администратора Адаманта (задание в планировщике от имени SYSTEM).'
  $a = Read-Host 'Удалить и его? Windows попросит разрешение администратора. [Д/н]'
  if ($a -notmatch '^\s*(н|n|нет|no)\s*$') {
    $un = Join-Path $helperDir 'helper-uninstall.ps1'
    if (-not (Test-Path -LiteralPath $un)) { $un = Join-Path $InstallDir 'server\ps\helper-uninstall.ps1' }
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
      $p = Start-Process -FilePath $psExe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $un + '"')
      if ($p.ExitCode -eq 0) { Write-Host 'Помощник администратора удалён.' } else { Write-Host "Помощник удалён не полностью (код $($p.ExitCode)). Задания - в «Планировщике заданий», папка Adamant." -ForegroundColor Yellow }
    } catch {
      Write-Host 'Помощник оставлен: разрешение администратора не получено.' -ForegroundColor Yellow
      Write-Host "Удалить его позже: запустите от имени администратора $un"
    }
  } else {
    Write-Host "Помощник оставлен. Удалить его позже: запустите от имени администратора $(Join-Path $helperDir 'helper-uninstall.ps1')"
  }
}

$desktop = [Environment]::GetFolderPath('Desktop')
$menu = [Environment]::GetFolderPath('Programs')
foreach ($l in @((Join-Path $desktop 'Адамант.lnk'), (Join-Path $menu 'Адамант.lnk'))) { if (Test-Path $l) { Remove-Item -Force $l -Confirm:$false } }
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Adamant' -Recurse -Force -ErrorAction SilentlyContinue

# Сам сценарий лежит в удаляемой папке: PowerShell уже прочитал его целиком, удалять можно.
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir -Confirm:$false }
Write-Host 'Адамант удалён.'
Write-Host "Отчёты и журнал исправлений сохранены: $dataDir"
Write-Host 'Прежние значения для отката исправлений лежат в %ProgramData%\Adamant (доступ только администраторам).'
Write-Host 'Если вы что-то исправляли и хотите вернуть, установите Адамант снова и нажмите «Откатить» в разделе «Исправления».'
Read-Host 'Нажмите Enter, чтобы закрыть окно' | Out-Null
