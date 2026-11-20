# Страж: следы атак в журналах Windows за 14 дней. ТОЛЬКО ЧТЕНИЕ.
# Журнал безопасности (попытки входа, очистка журнала, новые пользователи и администраторы) виден только
# администратору. Системный журнал, журнал Defender и PowerShell обычно видны всем.
# Читаем через EventLogReader с XPath - без оформления текста событий, это в разы быстрее Get-WinEvent.
# Результат сразу сводим (по адресам, по дням), чтобы JSON оставался маленьким.

$guardDays = 14
$guardSince = (Get-Date).AddDays(-$guardDays)
# Папка самой программы (sections → ps → server → корень): её сценарии в журнале PowerShell не считаем.
$guardOwn = '(?i)^' + [regex]::Escape((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))) + '\\'
$guardTw = 'TimeCreated[timediff(@SystemTime) <= ' + ([int64]$guardDays * 86400000) + ']'

function GuardEvents([string]$log, [string]$xpath, [int]$max) {
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
  $q.ReverseDirection = $true
  $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
  $list = New-Object System.Collections.ArrayList
  try {
    while ($list.Count -lt $max) { $e = $rd.ReadEvent(); if ($null -eq $e) { break }; [void]$list.Add($e) }
  } finally { $rd.Dispose() }
  return , $list
}
function GuardProp($e, [int]$i) { try { if ($e.Properties.Count -gt $i) { return [string]$e.Properties[$i].Value } } catch {}; return '' }
function GuardData($e) {
  # Именованные поля события (EventData/Data Name=…) - для журнала Defender, где номера полей меняются.
  $d = @{}
  try { foreach ($x in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$x.Name] = [string]$x.'#text' } } catch {}
  return $d
}
# Командные строки бывают с секретами (ключ VPN, пароль в аргументах): берём только первую строку и прячем значения.
function GuardCut2([string]$s, [int]$n) {
  if ($null -eq $s) { return '' }
  $s = ([string]($s -split '[\r\n]')[0]).Trim()
  $s = $s -replace '(?i)((private|preshared|secret|passw|pwd|token|apikey|api_key|auth)\w*\s*[=:]\s*)\S+', '$1***' -replace '(?i)(--?(password|pass|pwd|token|key|secret)[\s=]+)\S+', '$1***'
  if ($s.Length -gt $n) { return $s.Substring(0, $n) + '…' }
  return $s
}
function GuardSidName([string]$sid) {
  if (-not $sid -or $sid -notmatch '^S-1-') { return '' }
  try { return (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { return '' }
}

Section 'events' {
  $r = [ordered]@{ days = $guardDays; since = IsoDate $guardSince; admin = $isAdmin; errors = [ordered]@{}; security = $null; system = $null; defender = $null; powershell = $null }

  # ---------- Журнал безопасности (только администратор) ----------
  if ($isAdmin) {
    try {
      $s = [ordered]@{}
      # 4625 - неудачный вход. Типы 3 (по сети, в том числе RDP с NLA) и 10 (удалённый рабочий стол).
      $max = 5000
      $ev = GuardEvents 'Security' "*[System[(EventID=4625) and $guardTw] and EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]" $max
      $agg = @{}; $byDay = [ordered]@{}
      foreach ($e in $ev) {
        $ip = GuardProp $e 19; $user = GuardProp $e 5; $type = GuardProp $e 10
        if (-not $ip) { $ip = '-' }
        $key = "$ip|$user"
        $t = $e.TimeCreated
        if (-not $agg.ContainsKey($key)) { $agg[$key] = [ordered]@{ ip = $ip; user = $user; workstation = (GuardProp $e 13); types = @(); count = 0; first = $t; last = $t } }
        $a = $agg[$key]
        $a.count++
        if ($t -lt $a.first) { $a.first = $t }
        if ($t -gt $a.last) { $a.last = $t }
        if ($a.types -notcontains $type) { $a.types += $type }
        # По дням - только попытки с других адресов (не с самого компьютера): для недельной сводки.
        if ($ip -eq '-' -or $ip -eq '::1' -or $ip.StartsWith('127.')) { continue }
        $day = $t.ToString('yyyy-MM-dd')
        if ($byDay.Contains($day)) { $byDay[$day]++ } else { $byDay[$day] = 1 }
      }
      $s.failedTotal = $ev.Count
      $s.failedTruncated = ($ev.Count -ge $max)
      $s.failedByDay = $byDay
      $s.failed = @($agg.Values | Sort-Object { $_.count } -Descending | Select-Object -First 30 | ForEach-Object {
        [ordered]@{ ip = $_.ip; user = $_.user; workstation = $_.workstation; types = @($_.types); count = $_.count; first = IsoDate $_.first; last = IsoDate $_.last }
      })

      # 4624 - успешный вход: удалённый рабочий стол (10) и по сети (3) не с этого компьютера.
      $ev = GuardEvents 'Security' "*[System[(EventID=4624) and $guardTw] and EventData[Data[@Name='LogonType']='10' or (Data[@Name='LogonType']='3' and Data[@Name='IpAddress']!='-' and Data[@Name='IpAddress']!='127.0.0.1' and Data[@Name='IpAddress']!='::1')]]" 3000
      $s.remoteLogons = @($ev | Where-Object { (GuardProp $_ 18) -notmatch '^(-|127\.|::1$|$)' -or (GuardProp $_ 8) -eq '10' } | Select-Object -First 20 | ForEach-Object {
        [ordered]@{ at = IsoDate $_.TimeCreated; user = (GuardProp $_ 5); domain = (GuardProp $_ 6); ip = (GuardProp $_ 18); type = [int](GuardProp $_ 8); workstation = (GuardProp $_ 11) }
      })

      # 1102 - журнал безопасности очищен; 4720 - создан пользователь; 4732/4728 - добавлен в группу администраторов.
      $ev = GuardEvents 'Security' "*[System[(EventID=1102 or EventID=4720 or EventID=4732 or EventID=4728) and $guardTw]]" 500
      $s.cleared = @(); $s.usersCreated = @(); $s.adminAdds = @()
      foreach ($e in $ev) {
        switch ($e.Id) {
          1102 { $s.cleared += [ordered]@{ at = IsoDate $e.TimeCreated; user = (GuardProp $e 1) } }
          4720 { $s.usersCreated += [ordered]@{ at = IsoDate $e.TimeCreated; user = (GuardProp $e 0); sid = (GuardProp $e 2); by = (GuardProp $e 4) } }
          default {
            # Только группы администраторов: локальная S-1-5-32-544 и доменные (…-512, -518, -519).
            $gsid = GuardProp $e 4
            if ($gsid -ne 'S-1-5-32-544' -and $gsid -notmatch '-(512|518|519)$') { break }
            $msid = GuardProp $e 1
            $member = GuardProp $e 0
            if (-not $member -or $member -eq '-') { $member = GuardSidName $msid }
            $s.adminAdds += [ordered]@{ at = IsoDate $e.TimeCreated; member = $member; sid = $msid; group = (GuardProp $e 2); by = (GuardProp $e 6) }
          }
        }
      }
      $r.security = $s
    } catch { $r.errors.security = $_.Exception.Message }
  }

  # ---------- Системный журнал ----------
  try {
    $sy = [ordered]@{ servicesInstalled = @(); servicesTotal = 0; cleared = @() }
    $ev = GuardEvents 'System' "*[System[Provider[@Name='Service Control Manager'] and (EventID=7045) and $guardTw]]" 300
    $sy.servicesTotal = $ev.Count
    $seen = @{}
    foreach ($e in $ev) {
      # Одну и ту же службу программы переустанавливают десятки раз - оставляем последнюю установку.
      $key = (GuardProp $e 0) + '|' + (GuardProp $e 1)
      if ($seen.ContainsKey($key)) { continue }
      $seen[$key] = 1
      if ($sy.servicesInstalled.Count -ge 20) { continue }
      $sy.servicesInstalled += [ordered]@{ at = IsoDate $e.TimeCreated; name = (GuardProp $e 0); path = (GuardCut2 (GuardProp $e 1) 300); type = (GuardProp $e 2); start = (GuardProp $e 3); account = (GuardProp $e 4) }
    }
    $ev = GuardEvents 'System' "*[System[Provider[@Name='Microsoft-Windows-Eventlog'] and (EventID=104) and $guardTw]]" 50
    $sy.cleared = @($ev | ForEach-Object { [ordered]@{ at = IsoDate $_.TimeCreated; user = (GuardProp $_ 0); channel = (GuardProp $_ 2) } })
    $r.system = $sy
  } catch { $r.errors.system = $_.Exception.Message }

  # ---------- Microsoft Defender ----------
  try {
    $df = [ordered]@{ detections = @(); rtpDisabled = @(); configChanges = 0 }
    # 1116 - найдена угроза, 1117 - меры приняты, 1118/1119 - меры не удались.
    $ev = GuardEvents 'Microsoft-Windows-Windows Defender/Operational' "*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119) and $guardTw]]" 300
    $det = [ordered]@{}
    foreach ($e in $ev) {
      $d = GuardData $e
      $id = $d['Detection ID']
      if (-not $id) { $id = [string]$e.RecordId }
      if (-not $det.Contains($id)) {
        $det[$id] = [ordered]@{ at = IsoDate $e.TimeCreated; threat = $d['Threat Name']; severity = $d['Severity Name']; category = $d['Category Name']; path = (GuardCut2 $d['Path'] 300); process = (GuardCut2 $d['Process Name'] 200); user = $d['Detection User']; events = @(); actionId = ''; action = ''; error = '' }
      }
      $x = $det[$id]
      $x.events += [int]$e.Id
      # События идут от новых к старым: первое встреченное действие - последнее по времени.
      if ($e.Id -ne 1116 -and -not $x.actionId) { $x.actionId = [string]$d['Action ID']; $x.action = [string]$d['Action Name']; if ($e.Id -ne 1117) { $x.error = GuardCut2 $d['Error Description'] 200 } }
    }
    $df.detections = @($det.Values | Select-Object -First 30)
    # 5001 - защита в реальном времени выключена; 5007 - изменены настройки (только число).
    $ev = GuardEvents 'Microsoft-Windows-Windows Defender/Operational' "*[System[(EventID=5001) and $guardTw]]" 50
    $df.rtpDisabled = @($ev | ForEach-Object { [ordered]@{ at = IsoDate $_.TimeCreated } })
    $df.configChanges = (GuardEvents 'Microsoft-Windows-Windows Defender/Operational' "*[System[(EventID=5007) and $guardTw]]" 2000).Count
    $r.defender = $df
  } catch { $r.errors.defender = $_.Exception.Message }

  # ---------- PowerShell: блоки сценариев, которые Windows сама пометила подозрительными ----------
  # Windows помечает по ключевым словам, поэтому много шума: модули Windows (cmdletization), сам Адамант.
  # Здесь только отбор и счёт: тексты свежих блоков уходят в программу, а «сильный» признак (код
  # скачивается и сразу запускается) ищет server/psblocks.js. Образцов атак в сценарии PowerShell нет:
  # их антивирус принимает за инструмент атаки (так было с PSAttackTool в ноябре 2026).
  try {
    $psr = [ordered]@{ suspicious = 0; blocks = @() }
    $ev = GuardEvents 'Microsoft-Windows-PowerShell/Operational' "*[System[(EventID=4104) and (Level=3) and $guardTw]]" 1000
    $blocks = New-Object System.Collections.ArrayList
    foreach ($e in $ev) {
      if ((GuardProp $e 0) -ne '1') { continue }
      $path = GuardProp $e 4
      if ($path -and ($path -match $guardOwn -or $path -match '(?i)\\Adamant\\')) { continue }
      $text = GuardProp $e 2
      if ($text -match '__cmdletization|PowerShell\.Core\\.et-StrictMode -Off') { continue }
      $psr.suspicious++
      if ($blocks.Count -lt 60) { [void]$blocks.Add([ordered]@{ at = IsoDate $e.TimeCreated; path = $path; text = (GuardCut2 ($text -replace '\s+', ' ') 400) }) }
    }
    $psr.blocks = @($blocks)
    $r.powershell = $psr
  } catch { $r.errors.powershell = $_.Exception.Message }

  $r
}
