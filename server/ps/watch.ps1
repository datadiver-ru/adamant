# Адамант: Страж в реальном времени (ТОЛЬКО ЧТЕНИЕ). Работает, пока работает программа (окно или значок в трее).
# Раз в -Interval секунд делает быстрый слепок мест, где закрепляются вредоносные программы, и сравнивает с прошлым:
#   autostart - реестр Run/RunOnce и папки «Автозагрузка»;  services - службы Windows (новые и подменённые);
#   tasks     - задачи планировщика (новые);                admins   - группа «Администраторы»;
#   defender  - защита в реальном времени выключена;        hosts    - файл hosts;  proxy - прокси Windows.
# В stdout - по строке JSON на каждое изменение: { kind, change ('added'|'removed'|'changed'), key, label, from, to }.
# Первая строка - { ready: true } (слепок снят). Сам ничего не меняет; низкий приоритет задаёт сервер.
param([int]$Interval = 60, [int]$ParentPid = 0)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

function Out-Line($o) { [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress -Depth 4)); [Console]::Out.Flush() }
function Cut([string]$s, [int]$n = 300) { if ($null -eq $s) { return '' }; if ($s.Length -gt $n) { return $s.Substring(0, $n) }; return $s }

$runKeys = [ordered]@{
  'HKLM-Run' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  'HKLM-Run32' = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
  'HKCU-Run' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
  'HKLM-RunOnce' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
  'HKCU-RunOnce' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
}
$startup = [ordered]@{ 'Startup-User' = [Environment]::GetFolderPath('Startup'); 'Startup-Common' = [Environment]::GetFolderPath('CommonStartup') }
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$sched = $null
try { $sched = New-Object -ComObject Schedule.Service; $sched.Connect() } catch { $sched = $null }

function Tasks($folder, $map, [int]$depth) {
  if ($depth -gt 8) { return }
  try {
    foreach ($t in @($folder.GetTasks(1))) {
      $cmd = ''
      try { foreach ($a in @($t.Definition.Actions)) { if ($a.Type -eq 0) { $cmd = (([string]$a.Path) + ' ' + ([string]$a.Arguments)).Trim(); break } } } catch { }
      $map['tasks|' + [string]$t.Path] = Cut $cmd
    }
    foreach ($sub in @($folder.GetFolders(0))) { Tasks $sub $map ($depth + 1) }
  } catch { }
}

function Snap {
  $s = @{}
  foreach ($loc in $runKeys.Keys) {
    try {
      $k = Get-Item -LiteralPath $runKeys[$loc] -ErrorAction Stop
      foreach ($n in $k.GetValueNames()) { if ($n) { $s["autostart|$loc|$n"] = Cut ([string]$k.GetValue($n, '', 'DoNotExpandEnvironmentNames')) } }
    } catch { }
  }
  foreach ($loc in $startup.Keys) {
    $d = $startup[$loc]
    if ($d -and (Test-Path -LiteralPath $d)) { foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue)) { if ($f.Name -ine 'desktop.ini') { $s["autostart|$loc|$($f.Name)"] = Cut $f.FullName } } }
  }
  try {
    $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services')
    foreach ($n in $root.GetSubKeyNames()) {
      # Службы пользователя (имя_1a2b3c) создаются заново при каждом входе - их не считаем.
      if ($n -match '_[0-9a-f]{4,8}$') { continue }
      $k = $null
      try {
        $k = $root.OpenSubKey($n)
        $type = [int]("0" + $k.GetValue('Type'))
        $img = [string]$k.GetValue('ImagePath', '', 'DoNotExpandEnvironmentNames')
        if (($type -band 0x30) -eq 0 -or -not $img) { continue }
        $s["services|$n"] = Cut $img
        if (@('WinDefend', 'mpssvc', 'wscsvc', 'BFE', 'SecurityHealthService', 'Sense') -contains $n) { $s["svcstart|$n"] = [string]$k.GetValue('Start') }
      } catch { } finally { if ($k) { $k.Close() } }
    }
    $root.Close()
  } catch { }
  if ($sched) { try { Tasks ($sched.GetFolder('\')) $s 0 } catch { } }
  try {
    $g = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    foreach ($m in @(([ADSI]"WinNT://$env:COMPUTERNAME/$g,group").psbase.Invoke('Members'))) {
      $n = [string]$m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
      if ($n) { $s["admins|$n"] = $n }
    }
  } catch { }
  try { $mp = Get-MpComputerStatus -ErrorAction Stop; $s['defender|realtime'] = $(if ($mp.RealTimeProtectionEnabled) { 'on' } else { 'off' }) } catch { }
  try { if (Test-Path -LiteralPath $hostsFile) { $s['hosts|file'] = (Get-FileHash -LiteralPath $hostsFile -Algorithm SHA256).Hash } } catch { }
  try {
    $is = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if ([int]$is.ProxyEnable -eq 1 -and $is.ProxyServer) { $s['proxy|server'] = Cut ([string]$is.ProxyServer) 120 }
    if ($is.AutoConfigURL) { $s['proxy|pac'] = Cut ([string]$is.AutoConfigURL) 200 }
  } catch { }
  return $s
}

$prev = Snap
Out-Line ([ordered]@{ ready = $true; count = $prev.Count })
while ($true) {
  Start-Sleep -Seconds ([Math]::Max(10, $Interval))
  # Сервер завершился (даже аварийно) - уходим и мы, чтобы не остаться висеть без хозяина.
  if ($ParentPid -gt 0 -and -not (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue)) { exit 0 }
  $cur = Snap
  # Слепок не снялся целиком (например, реестр служб не прочитался) - не сравниваем, чтобы не поднять ложную тревогу.
  if ($cur.Count -lt [Math]::Floor($prev.Count / 2)) { continue }
  foreach ($k in $cur.Keys) {
    $kind, $rest = $k.Split('|', 2)
    if (-not $prev.ContainsKey($k)) { Out-Line ([ordered]@{ kind = $kind; change = 'added'; key = $rest; to = $cur[$k] }) }
    elseif ($prev[$k] -ne $cur[$k]) { Out-Line ([ordered]@{ kind = $kind; change = 'changed'; key = $rest; from = $prev[$k]; to = $cur[$k] }) }
  }
  foreach ($k in $prev.Keys) {
    if (-not $cur.ContainsKey($k)) { $kind, $rest = $k.Split('|', 2); Out-Line ([ordered]@{ kind = $kind; change = 'removed'; key = $rest; from = $prev[$k] }) }
  }
  $prev = $cur
}
