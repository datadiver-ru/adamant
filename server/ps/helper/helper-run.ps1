# Адамант: помощник администратора. Запускается ТОЛЬКО планировщиком заданий от имени SYSTEM
# и ТОЛЬКО из защищённой копии %ProgramFiles%\Adamant\Helper (её кладёт helper-install.ps1).
# Систему только ЧИТАЕТ. Пишет одно: ответы в %ProgramData%\Adamant\helper\out (и временные файлы в ...\helper\tmp).
#
#   helper-run.ps1 -Mode full      - те же проверки, что collect.ps1, но с правами администратора → out\full.json
#                                    (в файл идут только сведения, которые без прав администратора не видны)
#   helper-run.ps1 -Mode security  - быстро (1-2 с): журнал «Безопасность» за 14 дней → out\security.json
#
# Защита:
#  - сценарий проверяет, что сам лежит в %ProgramFiles%\Adamant\Helper, а у этой папки и папок ответа
#    владелец - администраторы или SYSTEM и писать туда не может никто другой. Иначе отказывается работать;
#  - аргументов, кроме фиксированного -Mode, нет; пути к модулям и программам - только системные;
#  - временные файлы (в том числе Add-Type) - в своей папке, куда обычный пользователь не пишет;
#  - в ответе нет секретов: пароли Wi-Fi не читаются, командные строки обрезаются (как в collect.ps1),
#    имена из неудачных входов с клавиатуры, которых нет на компьютере, скрываются (часто это пароль, набранный не в то поле).
param([ValidateSet('full', 'security')][string]$Mode = 'security')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Версия комплекта помощника. Меняется вместе с helper-install.ps1 и server/helper.js (HELPER_VERSION).
$H_Version = 1

# Компьютер не должен тормозить: пониженный приоритет процесса.
try { [Diagnostics.Process]::GetCurrentProcess().PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal } catch {}

# Только системные пути: никакой подмены модулей и программ через переменные окружения.
$H_Sys32 = Join-Path $env:SystemRoot 'System32'
$env:PATH = "$H_Sys32;$env:SystemRoot;$H_Sys32\Wbem;$H_Sys32\WindowsPowerShell\v1.0"
$env:PSModulePath = "$H_Sys32\WindowsPowerShell\v1.0\Modules"

$H_ADMINS = 'S-1-5-32-544'
$H_SYSTEM = 'S-1-5-18'
$H_Trusted = @($H_ADMINS, $H_SYSTEM, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# Права, которые позволяют что-то изменить: запись, дозапись, атрибуты, удаление, смена прав и владельца, GENERIC_WRITE/ALL.
$H_WriteMask = 0x500D0156

$H_PF = [Environment]::GetEnvironmentVariable('ProgramW6432')
if (-not $H_PF) { $H_PF = $env:ProgramFiles }
$H_ProgParent = Join-Path $H_PF 'Adamant'
$H_Prog = Join-Path $H_ProgParent 'Helper'
$H_Base = Join-Path $env:ProgramData 'Adamant'
$H_Data = Join-Path $H_Base 'helper'
$H_Out = Join-Path $H_Data 'out'
$H_Tmp = Join-Path $H_Data 'tmp'

function H-Item([string]$p) {
  $d = New-Object IO.DirectoryInfo $p
  if ($d.Exists) { return $d }
  $f = New-Object IO.FileInfo $p
  if ($f.Exists) { return $f }
  return $null
}
# Что не так с папкой или файлом (или $null, если всё в порядке).
function H-Problem([string]$p) {
  $it = H-Item $p
  if (-not $it) { return "нет $p" }
  if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "ссылка вместо файла или папки: $p" }
  $acl = $it.GetAccessControl([Security.AccessControl.AccessControlSections]'Owner, Access')
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($H_Trusted -notcontains $owner) { return "владелец $owner, а не администраторы: $p" }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
    if ($H_Trusted -contains $r.IdentityReference.Value) { continue }
    if (([int64][int]$r.FileSystemRights -band $H_WriteMask) -ne 0) { return "право записи у $($r.IdentityReference.Value): $p" }
  }
  return $null
}
# Папка и всё внутри (ссылки внутрь не считаются: это уже ошибка).
function H-TreeProblem([string]$p) {
  $x = H-Problem $p
  if ($x) { return $x }
  foreach ($c in (New-Object IO.DirectoryInfo $p).GetFileSystemInfos()) {
    if ($c -is [IO.DirectoryInfo] -and -not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $x = H-TreeProblem $c.FullName }
    else { $x = H-Problem $c.FullName }
    if ($x) { return $x }
  }
  return $null
}

# Чтение журнала через EventLogReader и XPath - без оформления текста событий (быстро).
function H-Events([string]$xpath, [int]$max) {
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
  $q.ReverseDirection = $true
  $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
  $list = New-Object System.Collections.ArrayList
  try {
    while ($list.Count -lt $max) { $e = $rd.ReadEvent(); if ($null -eq $e) { break }; [void]$list.Add($e) }
  } finally { $rd.Dispose() }
  return , $list
}
function H-Prop($e, [int]$i, [int]$n = 128) {
  $s = ''
  try { if ($e.Properties.Count -gt $i) { $s = [string]$e.Properties[$i].Value } } catch {}
  $s = ($s -replace '[\r\n\t]', ' ').Trim()
  if ($s.Length -gt $n) { $s = $s.Substring(0, $n) }
  return $s
}
function H-Iso($d) { try { return ([datetime]$d).ToString('o') } catch { return $null } }
function H-User($e, [int]$user, [int]$domain) {
  $u = H-Prop $e $user; $d = H-Prop $e $domain
  if ($d -and $d -ne '-') { return "$d\$u" }
  return $u
}

# ---------- Журнал «Безопасность»: входы, блокировки, новые пользователи и администраторы ----------
function H-Security {
  $days = 14
  $tw = 'TimeCreated[timediff(@SystemTime) <= ' + ([int64]$days * 86400000) + ']'
  $lt = { param($types) ($types | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or ' }
  $r = [ordered]@{ format = 'adamant-helper-security'; version = $H_Version; at = $null; days = $days
    failed = @(); failedTotal = 0; failedTruncated = $false; logons = @(); locks = @(); created = @(); adminAdds = @() }

  # 4625 - неудачный вход: 2 - с клавиатуры, 3 - по сети, 7 - разблокировка, 10 - удалённый рабочий стол, 11 - сохранённый пароль.
  $max = 300
  $ev = H-Events "*[System[(EventID=4625) and $tw] and EventData[$(& $lt @(2, 3, 7, 10, 11))]]" $max
  $r.failedTotal = $ev.Count
  $r.failedTruncated = ($ev.Count -ge $max)
  $r.failed = @(foreach ($e in $ev) {
    $type = [int](H-Prop $e 10)
    $sub = (H-Prop $e 9).ToLowerInvariant()
    $x = [ordered]@{ at = H-Iso $e.TimeCreated; user = (H-User $e 5 6); logonType = $type; ip = (H-Prop $e 19 64); workstation = (H-Prop $e 13 64); status = $sub }
    # 0xc0000064 - такого имени нет. С клавиатуры этого компьютера это чаще всего пароль, набранный в поле имени: не сохраняем.
    if ($sub -eq '0xc0000064' -and $type -in @(2, 7, 11)) { $x.user = ''; $x.unknownUser = $true }
    $x
    $e.Dispose()
  })

  # 4624 - успешный вход: 2 - с клавиатуры, 7 - разблокировка, 10 - удалённый рабочий стол, 11 - сохранённый пароль.
  $ev = H-Events "*[System[(EventID=4624) and $tw] and EventData[$(& $lt @(2, 7, 10, 11))]]" 600
  $logons = New-Object System.Collections.ArrayList
  foreach ($e in $ev) {
    if ($logons.Count -lt 300) {
      # Служебные входы Windows (диспетчер окон, драйвер шрифтов, службы) пропускаем, как в physical.ps1.
      $sid = H-Prop $e 4
      $dom = H-Prop $e 6
      if (-not ($sid -match '^S-1-5-(90|96|18|19|20)(-|$)' -or $dom -in @('Window Manager', 'Font Driver Host'))) {
        [void]$logons.Add([ordered]@{ at = H-Iso $e.TimeCreated; user = (H-User $e 5 6); logonType = [int](H-Prop $e 8); ip = (H-Prop $e 18 64); workstation = (H-Prop $e 11 64) })
      }
    }
    $e.Dispose()
  }
  $r.logons = @($logons)

  # 4800 - компьютер заблокирован, 4801 - разблокирован.
  $ev = H-Events "*[System[(EventID=4800 or EventID=4801) and $tw]]" 200
  $r.locks = @(foreach ($e in $ev) {
    [ordered]@{ at = H-Iso $e.TimeCreated; user = (H-User $e 1 2); kind = $(if ($e.Id -eq 4800) { 'lock' } else { 'unlock' }) }
    $e.Dispose()
  })

  # 4720 - создан пользователь; 4732 - добавлен в локальную группу (берём только «Администраторы»).
  $ev = H-Events "*[System[(EventID=4720 or EventID=4732) and $tw]]" 200
  $created = New-Object System.Collections.ArrayList
  $adds = New-Object System.Collections.ArrayList
  foreach ($e in $ev) {
    if ($e.Id -eq 4720) {
      if ($created.Count -lt 50) { [void]$created.Add([ordered]@{ at = H-Iso $e.TimeCreated; user = (H-User $e 0 1); sid = (H-Prop $e 2 80); by = (H-Prop $e 4) }) }
    } elseif ((H-Prop $e 4 80) -eq $H_ADMINS -and $adds.Count -lt 50) {
      $member = H-Prop $e 0
      $msid = H-Prop $e 1 80
      if ((-not $member -or $member -eq '-') -and $msid -match '^S-1-') { try { $member = (New-Object Security.Principal.SecurityIdentifier $msid).Translate([Security.Principal.NTAccount]).Value } catch {} }
      [void]$adds.Add([ordered]@{ at = H-Iso $e.TimeCreated; member = $member; sid = $msid; group = (H-Prop $e 2); by = (H-Prop $e 6) })
    }
    $e.Dispose()
  }
  $r.created = @($created)
  $r.adminAdds = @($adds)
  $r.at = (Get-Date).ToString('o')
  return $r
}

# ---------- Полная проверка: collect.ps1 и разделы с правами администратора ----------
# Только сведения, которые без прав администратора не видны (их и переносит server/helper.js).
# Остальное (HKCU, автозагрузка, Wi-Fi) у SYSTEM своё и программе не нужно - в ответ не идёт.
$H_Keep = 'smb.feature encryption.volumes boot.tpm boot.tpmSpec boot.bcdFirmware firmware.vendor events.security physical.bitlocker physical.winre physical.presence readiness.restore persistence.exclusions persistence.wmi'
$H_KeepErrors = @('bitlocker', 'restorePoints', 'encryption', 'boot', 'firmware', 'events', 'physical', 'readiness', 'persistence', 'smb')

function H-Pick($all) {
  $f = [ordered]@{ format = 'adamant-facts'; version = $all.version; collectedAt = $all.collectedAt; isAdmin = [bool]$all.isAdmin; errors = [ordered]@{} }
  if ($all.meta) { $f.meta = [ordered]@{ computer = $all.meta.computer; osBuild = $all.meta.osBuild } }
  foreach ($k in $H_KeepErrors) { if ($all.errors -and $all.errors.Contains($k)) { $f.errors[$k] = [string]$all.errors[$k] } }
  foreach ($k in $H_Keep.Split(' ')) {
    $s, $n = $k.Split('.')
    $sec = $all[$s]
    if ($null -eq $sec -or -not ($sec -is [Collections.IDictionary])) { continue }
    if (-not $f.Contains($s)) { $f[$s] = [ordered]@{} }
    $f[$s][$n] = $(if ($sec.Contains($n)) { $sec[$n] } else { $null })
  }
  return $f
}

# region: запись ответов - единственное место, где сценарий что-то пишет (только в $H_Out и $H_Tmp)
function H-OutSecurity {
  $fs = New-Object Security.AccessControl.FileSecurity
  $fs.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($H_ADMINS, $H_SYSTEM)) { $fs.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'Allow'))) }
  if ($H_Reader) { $fs.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $H_Reader), 'Read', 'Allow'))) }
  return $fs
}
# Атомарная запись: временный файл рядом → права → подмена одним действием (читатель видит или старый, или новый файл).
function H-WriteOut([string]$name, [string]$json) {
  if ($name -notmatch '^(full|security|error)\.json$') { throw "недопустимое имя ответа: $name" }
  $dest = Join-Path $H_Out $name
  $tmp = Join-Path $H_Out ($name + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
  [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding $false))
  [IO.File]::SetAccessControl($tmp, (H-OutSecurity))
  # Программа может как раз читать прежний файл - тогда пробуем ещё раз чуть позже.
  for ($i = 1; ; $i++) {
    try {
      if ([IO.File]::Exists($dest)) { [IO.File]::Replace($tmp, $dest, [NullString]::Value) } else { [IO.File]::Move($tmp, $dest) }
      break
    } catch {
      if ($i -ge 5) { try { [IO.File]::Delete($tmp) } catch {}; throw }
      Start-Sleep -Milliseconds 200
    }
  }
}
# Остатки прерванных запусков: только свои временные файлы и только в своих папках.
function H-CleanTemp {
  foreach ($d in @($H_Out, $H_Tmp)) {
    foreach ($f in (New-Object IO.DirectoryInfo $d).GetFiles()) {
      if ($f.Name -match '^((full|security|error)\.json\.[0-9a-f]{32}\.tmp|collect-[0-9a-f]{32}\.json)$' -and $f.LastWriteTime -lt (Get-Date).AddMinutes(-30)) { [IO.File]::Delete($f.FullName) }
    }
  }
}
function H-DropCollect([string]$p) {
  if ((Split-Path -Parent $p) -ne $H_Tmp -or (Split-Path -Leaf $p) -notmatch '^collect-[0-9a-f]{32}\.json$') { return }
  if ([IO.File]::Exists($p)) { [IO.File]::Delete($p) }
}
# endregion

# ---------- Запуск ----------
$H_Started = Get-Date
$H_OutOk = $false
$H_Reader = ''
try {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  if ($me.User.Value -ne $H_SYSTEM) { throw 'Помощник работает только от имени SYSTEM (из планировщика заданий)' }
  if ($PSScriptRoot.TrimEnd('\') -ne $H_Prog) { throw "Помощник запущен не из $H_Prog" }
  $p = H-Problem $H_Base
  if (-not $p) { $p = H-Problem $H_Data }
  if (-not $p) { $p = H-Problem $H_Out }
  if ($p) { throw "Папка ответов помощника ненадёжна ($p)" }
  $H_OutOk = $true
  $p = H-Problem $H_Tmp
  if (-not $p) { $p = H-Problem $H_ProgParent }
  if (-not $p) { $p = H-TreeProblem $H_Prog }
  if ($p) { throw "Файлы помощника изменены - работа остановлена ($p)" }

  # Кто читает ответы: учётная запись, которая ставила помощника (записана в защищённой папке).
  try {
    $m = [IO.File]::ReadAllText((Join-Path $H_Prog 'helper.json')) | ConvertFrom-Json
    if ([string]$m.readerSid -match '^S-1-(5-21|12-1)(-\d{1,10}){4}$') { $H_Reader = [string]$m.readerSid }
  } catch {}
  # Временные файлы (и компиляция Add-Type) - только в своей папке.
  $env:TEMP = $H_Tmp
  $env:TMP = $H_Tmp
  H-CleanTemp

  if ($Mode -eq 'security') {
    # Пачку событий (подбор пароля) обрабатываем один раз: не чаще, чем раз в 15 секунд.
    $age = ((Get-Date) - [IO.File]::GetLastWriteTime((Join-Path $H_Out 'security.json'))).TotalSeconds
    if ($age -ge 0 -and $age -lt 15) { Start-Sleep -Milliseconds ([int]((15 - $age) * 1000)) }
    H-WriteOut 'security.json' (H-Security | ConvertTo-Json -Depth 6 -Compress)
  } else {
    # После включения компьютера задание может прийти дважды (пропущенный запуск и запуск при старте).
    $age = ((Get-Date) - [IO.File]::GetLastWriteTime((Join-Path $H_Out 'full.json'))).TotalMinutes
    if ($age -ge 0 -and $age -lt 20) { exit 0 }
    $H_CollectOut = Join-Path $H_Tmp ('collect-' + [guid]::NewGuid().ToString('N') + '.json')
    try {
      # Тот же сценарий проверки, что и в программе, в этом же процессе: после него в $R - все сведения.
      . (Join-Path $H_Prog 'ps\collect.ps1') -Out $H_CollectOut
    } finally { H-DropCollect $H_CollectOut }
    $ErrorActionPreference = 'Stop'
    if (-not $R -or $R.format -ne 'adamant-facts') { throw 'Сценарий проверки не вернул сведения' }
    $full = [ordered]@{ format = 'adamant-helper-full'; version = $H_Version; at = (Get-Date).ToString('o'); durationMs = [int]((Get-Date) - $H_Started).TotalMilliseconds; facts = (H-Pick $R) }
    H-WriteOut 'full.json' ($full | ConvertTo-Json -Depth 10 -Compress)
    H-WriteOut 'security.json' (H-Security | ConvertTo-Json -Depth 6 -Compress)
  }
  exit 0
} catch {
  $msg = [string]$_.Exception.Message
  if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
  if ($H_OutOk) {
    try { H-WriteOut 'error.json' ([ordered]@{ format = 'adamant-helper-error'; version = $H_Version; at = (Get-Date).ToString('o'); mode = $Mode; error = $msg } | ConvertTo-Json -Compress) } catch {}
  }
  exit 1
}
