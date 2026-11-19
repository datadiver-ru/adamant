# Адамант: значок в трее. Запускается, только если в настройках включена «Работа в фоне».
#  - держит сервер программы запущенным (раз в минуту спрашивает его о состоянии);
#  - показывает уведомление, если фоновая проверка нашла новое «Критично» или «Важно»;
#  - сразу предупреждает, если тронуты файлы-приманки (похоже на программу-шифровальщика);
#  - меню: открыть программу, проверить сейчас, убрать значок;
#  - «Пока вас не было» (если включено в настройках): сообщает серверу о блокировке и разблокировке, сне,
#    удалённом подключении и подключённых дисках; по просьбе сервера делает снимок камерой (windows\camera.ps1,
#    отдельная настройка, по умолчанию выключена) - только в папку данных программы away\photos.
# Сам ничего не проверяет и не меняет: всё делает сервер программы.
param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$Data)
$ErrorActionPreference = 'Stop'

$created = $false
$mutex = New-Object Threading.Mutex($true, 'Local\AdamantTray', [ref]$created)
if (-not $created) { exit 0 }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
# Обращения только к 127.0.0.1 - системный прокси не нужен.
[Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy

$wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
$vbs = Join-Path $Root 'windows\adamant.vbs'
$serverFile = Join-Path $Data 'server.json'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$cameraPs1 = Join-Path $Root 'windows\camera.ps1'
$T = @{
  ru = @{ open = 'Открыть Адамант'; check = 'Проверить сейчас'; quit = 'Убрать значок'; started = 'Проверка запущена.'; alert = 'Новые находки: {0}. Откройте Адамант, чтобы посмотреть.'; done = 'Проверка закончена. Критично: {0}, важно: {1}.'; canary = 'Тревога: кто-то изменил файлы-приманки. Так ведут себя программы-шифровальщики. Отключите интернет и откройте Адамант.' }
  en = @{ open = 'Open Adamant'; check = 'Check now'; quit = 'Remove icon'; started = 'Check started.'; alert = 'New findings: {0}. Open Adamant to see them.'; done = 'Check finished. Critical: {0}, important: {1}.'; canary = 'Alert: someone changed the decoy files. Ransomware behaves like this. Disconnect from the internet and open Adamant.' }
}
$script:lang = 'ru'
$script:lastAt = $null
$script:manual = $false
$script:first = $true
$script:seenAlerts = @{}
$script:away = $false        # сервер сказал, что «Пока вас не было» включено
$script:startSent = $false
$script:outbox = New-Object System.Collections.ArrayList
$script:cam = $null          # идущий снимок: @{ id; proc; started; out }
$script:lastPhoto = ''

function Api([string]$route, [string]$method = 'GET', $body = $null) {
  $s = Get-Content -LiteralPath $serverFile -Raw -Encoding UTF8 | ConvertFrom-Json
  $p = @{ Uri = "http://127.0.0.1:$($s.port)$route"; Headers = @{ 'X-Adamant-Key' = [string]$s.key }; TimeoutSec = 5; Method = $method }
  if ($method -eq 'POST') {
    # Тело - байты UTF-8: строку PowerShell 5.1 отправил бы в ISO-8859-1 и испортил бы русские буквы.
    $json = if ($null -ne $body) { ConvertTo-Json -InputObject $body -Compress -Depth 4 } else { '{}' }
    $p.ContentType = 'application/json; charset=utf-8'
    $p.Body = [Text.Encoding]::UTF8.GetBytes($json)
  }
  Invoke-RestMethod @p
}
function Say([string]$text, [string]$icon = 'Info') {
  $tray.BalloonTipTitle = 'Адамант'
  $tray.BalloonTipText = $text
  $tray.BalloonTipIcon = $icon
  $tray.ShowBalloonTip(8000)
}
function Open-App { Start-Process -FilePath $wscript -ArgumentList ('"' + $vbs + '"') }
function Quit {
  $timer.Stop(); $eventTimer.Stop(); $camTimer.Stop()
  try { Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like 'Adamant.*' } | Unregister-Event } catch { }
  $tray.Visible = $false; $tray.Dispose(); [Windows.Forms.Application]::Exit()
}

# ------------------------------------------------------------ «Пока вас не было»
# События Windows копятся в очереди PowerShell (Register-ObjectEvent без -Action) и разбираются таймером
# в потоке окна: обработчики не выполняются в чужом потоке и не могут уронить значок.
function IsoUtc([datetime]$d) { $d.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture) }
function Queue-Away([hashtable]$evt) {
  if (-not $script:away) { return }
  if ($script:outbox.Count -ge 30) { $script:outbox.RemoveAt(0) }
  [void]$script:outbox.Add($evt)
}
function Flush-Away {
  while ($script:outbox.Count -gt 0) {
    try {
      Api '/api/away/event' 'POST' $script:outbox[0] | Out-Null
    } catch {
      # Сервер отклонил событие (4xx) - не повторять; сервер недоступен - повторить на следующем шаге.
      $code = 0
      try { $code = [int]$_.Exception.Response.StatusCode } catch { }
      if ($code -lt 400 -or $code -ge 500) { return }
    }
    $script:outbox.RemoveAt(0)
  }
}
$sessionKinds = @{
  SessionLock = @{ kind = 'lock' }; SessionUnlock = @{ kind = 'unlock' }
  RemoteConnect = @{ kind = 'remote'; how = 'remote-connect' }; RemoteDisconnect = @{ kind = 'remote'; how = 'remote-disconnect' }
  ConsoleConnect = @{ kind = 'remote'; how = 'console-connect' }; ConsoleDisconnect = @{ kind = 'remote'; how = 'console-disconnect' }
  SessionRemoteControl = @{ kind = 'remote'; how = 'remote-control' }
}
function Drain-Events {
  foreach ($ev in @(Get-Event -ErrorAction SilentlyContinue)) {
    try {
      $at = IsoUtc $ev.TimeGenerated
      switch ([string]$ev.SourceIdentifier) {
        'Adamant.Session' {
          $reason = [string]$ev.SourceEventArgs.Reason
          if ($sessionKinds.ContainsKey($reason)) { $e = $sessionKinds[$reason].Clone(); $e.at = $at; Queue-Away $e }
        }
        'Adamant.Power' {
          $mode = [string]$ev.SourceEventArgs.Mode
          if ($mode -eq 'Suspend') { Queue-Away @{ kind = 'suspend'; at = $at } }
          elseif ($mode -eq 'Resume') { Queue-Away @{ kind = 'resume'; at = $at } }
        }
        'Adamant.Volume' {
          $drive = [string]$ev.SourceEventArgs.NewEvent.DriveName
          if ($drive -match '^[A-Za-z]:$') {
            $e = @{ kind = 'usb'; at = $at; drive = $drive.ToUpper() }
            try {
              $di = New-Object IO.DriveInfo($drive)
              $e.type = [string]$di.DriveType
              if ($di.IsReady -and $di.VolumeLabel) { $l = [string]$di.VolumeLabel; $e.label = $l.Substring(0, [Math]::Min(64, $l.Length)) }
            } catch { }
            if ($e.type -ne 'Network') { Queue-Away $e }
          }
        }
      }
    } catch { }
    try { Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue } catch { }
  }
  if ($script:away -and $script:outbox.Count -gt 0) { Flush-Away }
}
# Снимок: номер выбирает сервер, файл - только <данные>\away\photos\<номер>.jpg (camera.ps1 проверяет это ещё раз).
function Start-Camera([string]$id) {
  $script:lastPhoto = $id
  $out = Join-Path $Data ('away\photos\' + $id + '.jpg')
  try {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $powershell
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -MTA -WindowStyle Hidden -File "' + $cameraPs1 + '" -Out "' + $out + '"'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($psi)
    $script:cam = @{ id = $id; proc = $p; started = Get-Date; out = $p.StandardOutput.ReadToEndAsync() }
    $camTimer.Start()
  } catch {
    Finish-Camera @{ id = $id; proc = $null } $false 'error'
  }
}
function Finish-Camera($c, [bool]$ok, [string]$err) {
  $script:cam = $null
  $camTimer.Stop()
  if ($c.proc) { try { $c.proc.Dispose() } catch { } }
  $b = @{ id = $c.id; ok = $ok }
  if (-not $ok) { $b.error = $err }
  try { Api '/api/away/photo' 'POST' $b | Out-Null } catch { }
}
function Check-Camera {
  $c = $script:cam
  if (-not $c) { $camTimer.Stop(); return }
  try {
    if ($c.proc.HasExited) {
      $ok = $false; $err = 'error'
      try {
        if ($c.out.Wait(1000)) {
          $j = $c.out.Result | ConvertFrom-Json
          $ok = [bool]$j.ok
          if (-not $ok -and ([string]$j.error) -match '^[a-z][a-z0-9-]{0,31}$') { $err = [string]$j.error }
        }
      } catch { }
      Finish-Camera $c $ok $err
    } elseif (((Get-Date) - $c.started).TotalSeconds -gt 30) {
      try { $c.proc.Kill() } catch { }
      Finish-Camera $c $false 'timeout'
    }
  } catch {
    Finish-Camera $c $false 'error'
  }
}

$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = New-Object Drawing.Icon (Join-Path $Root 'windows\adamant.ico')
$tray.Text = 'Адамант'
$menu = New-Object Windows.Forms.ContextMenuStrip
$miOpen = $menu.Items.Add($T.ru.open)
$miCheck = $menu.Items.Add($T.ru.check)
[void]$menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
$miQuit = $menu.Items.Add($T.ru.quit)
$miOpen.add_Click({ Open-App })
$miCheck.add_Click({ try { Api '/api/tray/check' 'POST' | Out-Null; $script:manual = $true; Say $T[$script:lang].started } catch {} })
$miQuit.add_Click({ Quit })
$tray.ContextMenuStrip = $menu
$tray.add_DoubleClick({ Open-App })
$tray.add_BalloonTipClicked({ Open-App })
$tray.Visible = $true

function Poll {
  try {
    $r = Api '/api/tray'
  } catch {
    # Сервер завершился - запускаем снова (только сервер, без окна).
    Start-Process -FilePath $wscript -ArgumentList ('"' + $vbs + '" --background')
    return
  }
  if ($r.exit) { Quit; return }
  $script:away = [bool]$r.away
  if ($script:away -and -not $script:startSent) {
    # Значок запускается при входе в Windows: если сервер ждал разблокировки (компьютер перезагрузили), отрезок закроется.
    $script:startSent = $true
    Queue-Away @{ kind = 'start'; at = (IsoUtc ([Diagnostics.Process]::GetCurrentProcess().StartTime)) }
  }
  if ($r.photo -and ([string]$r.photo) -cmatch '^[a-f0-9]{32}$' -and -not $script:cam -and [string]$r.photo -ne $script:lastPhoto) { Start-Camera ([string]$r.photo) }
  if ($r.lang -in @('ru', 'en') -and $r.lang -ne $script:lang) {
    $script:lang = $r.lang
    $miOpen.Text = $T[$script:lang].open; $miCheck.Text = $T[$script:lang].check; $miQuit.Text = $T[$script:lang].quit
  }
  if ($r.at -and $r.at -ne $script:lastAt) {
    $isNew = -not $script:first
    $script:lastAt = $r.at
    $n = @($r.newAlerts).Count
    if ($isNew -and $n -gt 0) { Say ($T[$script:lang].alert -f $n) 'Warning' }
    elseif ($script:manual -and $r.summary) { Say ($T[$script:lang].done -f $r.summary.critical, $r.summary.high) }
    $script:manual = $false
  }
  # Тревоги: приманки - свой текст; Страж в реальном времени и другие - короткий текст от сервера на языке пользователя.
  foreach ($a in @($r.alertInfo)) {
    $id = [string]$a.id
    if (-not $id -or $script:seenAlerts.ContainsKey($id)) { continue }
    $script:seenAlerts[$id] = $true
    $msg = [string]$a.text
    if ($a.kind -eq 'canary' -or -not $msg) { $msg = $T[$script:lang].canary }
    if ($msg.Length -gt 250) { $msg = $msg.Substring(0, 249) + '…' }
    Say $msg 'Error'
  }
  $script:first = $false
}

$timer = New-Object Windows.Forms.Timer
# Раз в 15 секунд: обращение к своему серверу почти ничего не стоит, а тревогу от приманок важно показать сразу.
$timer.Interval = 15000
$timer.add_Tick({ Poll })
$timer.Start()

# События сеанса, сна и дисков. Если подписаться не вышло - значок работает как раньше.
try { Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName SessionSwitch -SourceIdentifier 'Adamant.Session' | Out-Null } catch { }
try { Register-ObjectEvent -InputObject ([Microsoft.Win32.SystemEvents]) -EventName PowerModeChanged -SourceIdentifier 'Adamant.Power' | Out-Null } catch { }
try { Register-WmiEvent -Query 'SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2' -SourceIdentifier 'Adamant.Volume' | Out-Null } catch { }
$eventTimer = New-Object Windows.Forms.Timer
# Раз в 2 секунды разбирать очередь событий: только память процесса, к серверу - только если событие есть.
$eventTimer.Interval = 2000
$eventTimer.add_Tick({ try { Drain-Events } catch { } })
$eventTimer.Start()
$camTimer = New-Object Windows.Forms.Timer
$camTimer.Interval = 1000
$camTimer.add_Tick({ try { Check-Camera } catch { } })

Poll
[Windows.Forms.Application]::Run()
$mutex.ReleaseMutex()
