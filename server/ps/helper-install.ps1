# Адамант: установка помощника администратора и проверка его состояния.
#
#   helper-install.ps1 -Check                              - ТОЛЬКО ЧТЕНИЕ, права администратора не нужны: JSON в stdout
#   helper-install.ps1 -ReaderSid <SID> -Out <файл.json>   - установка или обновление (с правами администратора)
#
# Что делает установка:
#  1. Копирует фиксированный набор сценариев (helper-run.ps1, helper-uninstall.ps1, collect.ps1, sections\*.ps1)
#     в %ProgramFiles%\Adamant\Helper. Владелец - «Администраторы», полный доступ - администраторы и SYSTEM,
#     пользователи - только чтение и запуск, наследование прав выключено. Копия сверяется по SHA-256.
#  2. Создаёт %ProgramData%\Adamant\helper\out (ответы; читать может только учётная запись ReaderSid)
#     и ...\helper\tmp (временные файлы; только администраторы и SYSTEM). Папку, созданную не администратором,
#     не удаляет (удаление чужого содержимого с правами администратора опасно: ссылки), а отодвигает в сторону.
#  3. Регистрирует два задания в папке \Adamant\ планировщика от имени SYSTEM:
#     «Adamant Helper»          - -Mode full: раз в сутки в 03:30 (или как только компьютер включён) и через 15 минут после включения;
#     «Adamant Helper Security» - -Mode security: при неудачном входе (4625) и при входе с клавиатуры или разблокировке (4624, типы 2/7/11).
#     Компьютер не будит, на батарее работает, не дольше 10 минут (security - 2 минут), один экземпляр, низкий приоритет.
#  4. Запоминает прежнее состояние (была ли папка в Program Files, её права, папка заданий) для чистого удаления.
# Команда задания фиксирована: powershell.exe из System32 и сценарий из Program Files. Аргументов от пользователя нет.
param(
  [switch]$Check,
  [ValidatePattern('^(S-1-(5-21|12-1)(-\d{1,10}){4})?$')][string]$ReaderSid = '',
  [ValidatePattern('^$|\.json$')][string]$Out = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}

# Версия комплекта помощника: та же, что $H_Version в helper\helper-run.ps1 и HELPER_VERSION в server/helper.js.
$HelperVersion = 1

$ADMINS = 'S-1-5-32-544'
$SYSTEM = 'S-1-5-18'
$USERS = 'S-1-5-32-545'
$Trusted = @($ADMINS, $SYSTEM, 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$WriteMask = 0x500D0156

$PF = [Environment]::GetEnvironmentVariable('ProgramW6432')
if (-not $PF) { $PF = $env:ProgramFiles }
$ProgParent = Join-Path $PF 'Adamant'
$Prog = Join-Path $ProgParent 'Helper'
$Base = Join-Path $env:ProgramData 'Adamant'
$Data = Join-Path $Base 'helper'
$OutDir = Join-Path $Data 'out'
$TmpDir = Join-Path $Data 'tmp'
$Sys32 = Join-Path $env:SystemRoot 'System32'
$PsExe = Join-Path $Sys32 'WindowsPowerShell\v1.0\powershell.exe'
$Icacls = Join-Path $Sys32 'icacls.exe'
$TaskFolder = '\Adamant'
$Tasks = [ordered]@{ 'Adamant Helper' = 'full'; 'Adamant Helper Security' = 'security' }

function Sid([string]$s) { New-Object Security.Principal.SecurityIdentifier $s }
function Iso($d) { try { $x = [datetime]$d; if ($x.Year -lt 2000) { return $null }; return $x.ToString('o') } catch { return $null } }
function Sha256([byte[]]$b) {
  $h = [Security.Cryptography.SHA256]::Create()
  try { return (($h.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $h.Dispose() }
}
function TaskArgs([string]$mode) { '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $Prog 'helper-run.ps1') + '" -Mode ' + $mode }
function Info([string]$p) {
  $d = New-Object IO.DirectoryInfo $p
  if ($d.Exists) { return $d }
  $f = New-Object IO.FileInfo $p
  if ($f.Exists) { return $f }
  return $null
}
function HResult($ex) { while ($ex.InnerException) { $ex = $ex.InnerException }; return $ex.HResult }

# Описание файла или папки: владелец, права (как есть, решает server/helper.js), ссылка ли это.
function Describe([string]$p, [switch]$Hash) {
  $o = [ordered]@{ path = $p; exists = $false }
  try {
    $it = Info $p
    if (-not $it) { return $o }
    $o.exists = $true
    $o.dir = $it -is [IO.DirectoryInfo]
    $o.reparse = [bool]($it.Attributes -band [IO.FileAttributes]::ReparsePoint)
    $o.mtime = $it.LastWriteTimeUtc.ToString('o')
    if (-not $o.dir) { $o.size = [int64]$it.Length }
    $acl = $it.GetAccessControl([Security.AccessControl.AccessControlSections]'Owner, Access')
    $o.owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $o.protected = [bool]$acl.AreAccessRulesProtected
    $o.acl = @(foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      [ordered]@{
        sid = $r.IdentityReference.Value; allow = ($r.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
        rights = [int64][int]$r.FileSystemRights; inherited = [bool]$r.IsInherited
        inheritOnly = [bool]($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)
      }
    })
    if ($Hash -and -not $o.dir) { $o.sha256 = Sha256 ([IO.File]::ReadAllBytes($p)) }
  } catch { $o.error = $_.Exception.Message }
  return $o
}
# Все файлы и папки внутри (в ссылки не заходим).
function Tree([string]$root) {
  $list = New-Object Collections.ArrayList
  $stack = New-Object Collections.Stack
  $stack.Push($root)
  while ($stack.Count) {
    foreach ($c in (New-Object IO.DirectoryInfo ($stack.Pop())).GetFileSystemInfos()) {
      [void]$list.Add($c.FullName)
      if ($c -is [IO.DirectoryInfo] -and -not ($c.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($c.FullName) }
    }
  }
  return , $list
}
function Problem([string]$p) {
  $it = Info $p
  if (-not $it) { return "нет $p" }
  if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { return "ссылка: $p" }
  $acl = $it.GetAccessControl([Security.AccessControl.AccessControlSections]'Owner, Access')
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($Trusted -notcontains $owner) { return "владелец ${owner}: $p" }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $Trusted -contains $r.IdentityReference.Value) { continue }
    if (([int64][int]$r.FileSystemRights -band $WriteMask) -ne 0) { return "право записи у $($r.IdentityReference.Value): $p" }
  }
  return $null
}

# Задания планировщика: есть ли, что запускают, когда запускались.
function TaskInfo {
  $svc = $null; $folder = $null; $ferr = $null
  try { $svc = New-Object -ComObject Schedule.Service; $svc.Connect(); $folder = $svc.GetFolder($TaskFolder) } catch { $ferr = $_.Exception }
  return @(foreach ($n in $Tasks.Keys) {
    $o = [ordered]@{ name = $n; mode = $Tasks[$n]; exists = $false }
    if (-not $folder) {
      $h = if ($ferr) { HResult $ferr } else { 0 }
      if ($h -ne -2147024894 -and $h -ne -2147024893) { $o.exists = $null; $o.error = $(if ($ferr) { $ferr.Message } else { 'нет планировщика' }) }
    } else {
      try {
        $t = $folder.GetTask($n)
        $o.exists = $true
        $o.enabled = [bool]$t.Enabled
        $o.state = [int]$t.State
        $o.lastRun = Iso $t.LastRunTime
        $o.lastResult = [int64]$t.LastTaskResult
        $o.nextRun = Iso $t.NextRunTime
        try {
          $def = $t.Definition
          $o.actions = [int]$def.Actions.Count
          $a = $def.Actions.Item(1)
          $o.command = [string]$a.Path
          $o.arguments = [string]$a.Arguments
          $o.userId = [string]$def.Principal.UserId
          $o.runLevel = [int]$def.Principal.RunLevel
        } catch { $o.definitionError = $_.Exception.Message }
      } catch {
        $h = HResult $_.Exception
        if ($h -ne -2147024894 -and $h -ne -2147024893) { $o.exists = $null; $o.error = $_.Exception.Message }
      }
    }
    $o
  })
}

function CheckState {
  $files = @()
  if ((Info $Prog) -is [IO.DirectoryInfo]) {
    try {
      $files = @(foreach ($f in (Tree $Prog)) {
        $d = Describe $f -Hash
        $d.name = $f.Substring($Prog.Length + 1).Replace('\', '/')
        $d
      })
    } catch { $files = @([ordered]@{ name = ''; path = $Prog; exists = $true; error = $_.Exception.Message }) }
  }
  $manifest = $null; $manifestError = $null
  try { $mf = Join-Path $Prog 'helper.json'; if ([IO.File]::Exists($mf)) { $manifest = [IO.File]::ReadAllText($mf) | ConvertFrom-Json } } catch { $manifestError = $_.Exception.Message }
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  return [ordered]@{
    format = 'adamant-helper-check'; version = $HelperVersion; at = (Get-Date).ToString('o')
    user = $me.User.Value; isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    paths = [ordered]@{ programParent = $ProgParent; program = $Prog; out = $OutDir; powershell = $PsExe }
    program = [ordered]@{ parent = (Describe $ProgParent); dir = (Describe $Prog); files = $files }
    manifest = $manifest; manifestError = $manifestError
    out = [ordered]@{ dir = (Describe $OutDir); files = @(foreach ($n in @('full.json', 'security.json', 'error.json')) { $d = Describe (Join-Path $OutDir $n); $d.name = $n; $d }) }
    tasks = @(TaskInfo)
  }
}

function Emit($obj, [int]$depth = 8) {
  $json = $obj | ConvertTo-Json -Depth $depth -Compress
  if ($Out) { [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false)) } else { [Console]::Out.Write($json) }
}

if ($Check) {
  try { Emit (CheckState) 8 } catch { Emit ([ordered]@{ format = 'adamant-helper-check'; version = $HelperVersion; error = $_.Exception.Message }) }
  exit 0
}

# ======================================================================== установка (права администратора)

# Права папки целиком: владелец «Администраторы», наследование выключено, только перечисленные записи.
function Set-Secure([string]$p, [string]$readerSid, [string]$readRights) {
  $s = New-Object Security.AccessControl.DirectorySecurity
  $s.SetOwner((Sid $ADMINS))
  $s.SetAccessRuleProtection($true, $false)
  $inh = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $none = [Security.AccessControl.PropagationFlags]::None
  foreach ($x in @($ADMINS, $SYSTEM)) { $s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((Sid $x), 'FullControl', $inh, $none, 'Allow'))) }
  if ($readerSid) { $s.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((Sid $readerSid), $readRights, $inh, $none, 'Allow'))) }
  [IO.Directory]::SetAccessControl($p, $s)
}
function New-Dir([string]$p) { [void][IO.Directory]::CreateDirectory($p) }
# Удаление своей папки: ссылки удаляются как ссылки, внутрь них не заходим.
function Remove-Tree([string]$p) {
  $it = Info $p
  if (-not $it) { return }
  if ($it -is [IO.FileInfo]) { $it.Attributes = [IO.FileAttributes]::Normal; $it.Delete(); return }
  if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { [IO.Directory]::Delete($p, $false); return }
  foreach ($c in $it.GetFileSystemInfos()) {
    if ($c -is [IO.DirectoryInfo]) { Remove-Tree $c.FullName } else { $c.Attributes = [IO.FileAttributes]::Normal; $c.Delete() }
  }
  [IO.Directory]::Delete($p, $false)
}
# Папку, созданную не администратором, не удаляем (её содержимое мог подготовить кто угодно), а переименовываем.
function Move-Aside([string]$p) {
  $dst = $p + '.untrusted-' + (Get-Date).ToString('yyyyMMddHHmmss')
  $it = Info $p
  try {
    if ($it -is [IO.DirectoryInfo]) { [IO.Directory]::Move($p, $dst) } else { [IO.File]::Move($p, $dst) }
  } catch { throw "Папку $p создал не администратор, и её не удалось убрать. Удалите её вручную и повторите установку." }
  return $dst
}
function Is-Empty([string]$p) { $d = New-Object IO.DirectoryInfo $p; return ($d.Exists -and -not @($d.GetFileSystemInfos()).Count) }
function Owner-Ok([string]$p) {
  try { $it = Info $p; return ($it -and -not ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $Trusted -contains $it.GetAccessControl([Security.AccessControl.AccessControlSections]::Owner).GetOwner([Security.Principal.SecurityIdentifier]).Value) } catch { return $false }
}
function Load-State {
  $f = Join-Path $Data 'state.json'
  if (-not (Owner-Ok $Data) -or -not (Owner-Ok $f)) { return $null }
  try { $s = [IO.File]::ReadAllText($f) | ConvertFrom-Json; if ($s.format -eq 'adamant-helper-state') { return $s } } catch {}
  return $null
}
function Esc([string]$s) { [Security.SecurityElement]::Escape($s) }

function TaskXml([string]$mode) {
  $desc = 'Адамант: помощник администратора. Только читает настройки защиты и журнал «Безопасность» и пишет ответ в %ProgramData%\Adamant\helper\out. Удаление - в настройках Адаманта.'
  if ($mode -eq 'full') {
    $triggers = '<CalendarTrigger><StartBoundary>2026-01-01T03:30:00</StartBoundary><RandomDelay>PT30M</RandomDelay><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay><Enabled>true</Enabled></CalendarTrigger>' +
      '<BootTrigger><Delay>PT15M</Delay><Enabled>true</Enabled></BootTrigger>'
    $limit = 'PT10M'
  } else {
    $q1 = '<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4625)]]</Select></Query></QueryList>'
    $q2 = "<QueryList><Query Id=`"0`" Path=`"Security`"><Select Path=`"Security`">*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='11']]</Select></Query></QueryList>"
    $triggers = '<EventTrigger><Enabled>true</Enabled><Subscription>' + (Esc $q1) + '</Subscription></EventTrigger>' +
      '<EventTrigger><Enabled>true</Enabled><Subscription>' + (Esc $q2) + '</Subscription></EventTrigger>'
    $limit = 'PT2M'
  }
  return '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' +
    '<RegistrationInfo><Author>Adamant</Author><Description>' + (Esc $desc) + '</Description></RegistrationInfo>' +
    '<Triggers>' + $triggers + '</Triggers>' +
    '<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>' +
    '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>' +
    '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable>' +
    '<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>' +
    '<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle>' +
    '<WakeToRun>false</WakeToRun><ExecutionTimeLimit>' + $limit + '</ExecutionTimeLimit><Priority>7</Priority></Settings>' +
    '<Actions Context="Author"><Exec><Command>' + (Esc $PsExe) + '</Command><Arguments>' + (Esc (TaskArgs $mode)) + '</Arguments></Exec></Actions>' +
    '</Task>'
}
function Remove-Tasks($folder) {
  foreach ($n in $Tasks.Keys) {
    try { $t = $folder.GetTask($n); try { [void]$t.Stop(0) } catch {}; $folder.DeleteTask($n, 0) } catch {}
  }
}

$result = [ordered]@{ ok = $false; version = $HelperVersion; moved = @(); warnings = @() }
$did = [ordered]@{ tasks = $false; prog = $false; parentCreated = $false; parentSddl = $null; data = $false; baseCreated = $false; taskFolderCreated = $false }
$folder = $null
try {
  $me = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Нужны права администратора' }
  if (-not $Out) { throw 'Не указан файл ответа -Out' }
  # Кто будет читать ответы помощника. Обычно его SID передаёт программа (тот, кто нажал «Установить»).
  if (-not $ReaderSid) { $ReaderSid = $me.User.Value }
  if ($ReaderSid -notmatch '^S-1-(5-21|12-1)(-\d{1,10}){4}$') { throw 'Недопустимая учётная запись для чтения ответов' }
  $result.readerSid = $ReaderSid

  # ---------- 1. Что копируем: только фиксированный список, байты читаются один раз ----------
  $src = $PSScriptRoot
  $payload = New-Object Collections.ArrayList
  [void]$payload.Add(@{ name = 'helper-run.ps1'; from = (Join-Path $src 'helper\helper-run.ps1') })
  [void]$payload.Add(@{ name = 'helper-uninstall.ps1'; from = (Join-Path $src 'helper-uninstall.ps1') })
  [void]$payload.Add(@{ name = 'ps/collect.ps1'; from = (Join-Path $src 'collect.ps1') })
  foreach ($f in (New-Object IO.DirectoryInfo (Join-Path $src 'sections')).GetFiles('*.ps1')) {
    if ($f.Name -notmatch '^[a-z0-9-]+\.ps1$') { continue }
    [void]$payload.Add(@{ name = 'ps/sections/' + $f.Name; from = $f.FullName })
  }
  foreach ($p in $payload) {
    $p.bytes = [IO.File]::ReadAllBytes($p.from)
    $p.sha256 = Sha256 $p.bytes
  }

  # Прежнее состояние (при переустановке - из первой установки).
  $old = Load-State
  $before = if ($old -and $old.before) { $old.before } else {
    [ordered]@{
      programParentExisted = [bool](Info $ProgParent); programParentSddl = $null
      baseExisted = [bool](Info $Base); taskFolderExisted = $null
    }
  }

  # ---------- 2. Задания: сначала убираем старые, чтобы не запустились посреди копирования ----------
  $svc = New-Object -ComObject Schedule.Service
  $svc.Connect()
  try { $folder = $svc.GetFolder($TaskFolder) } catch {
    $folder = $svc.GetFolder('\').CreateFolder('Adamant')
    $did.taskFolderCreated = $true
  }
  if ($null -eq $before.taskFolderExisted) { $before.taskFolderExisted = -not $did.taskFolderCreated }
  Remove-Tasks $folder

  # ---------- 3. %ProgramFiles%\Adamant\Helper ----------
  $pi = Info $ProgParent
  if ($pi -and (($pi -isnot [IO.DirectoryInfo]) -or ($pi.Attributes -band [IO.FileAttributes]::ReparsePoint))) { throw "$ProgParent - не обычная папка. Установка отменена." }
  if (-not $pi) {
    New-Dir $ProgParent
    $did.parentCreated = $true
    Set-Secure $ProgParent $USERS 'ReadAndExecute'
  } elseif (Problem $ProgParent) {
    # Папка была, но писать в неё мог не только администратор: запоминаем прежние права и закрываем.
    $did.parentSddl = $pi.GetAccessControl().GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Owner, Group, Access')
    if (-not $before.programParentSddl) { $before.programParentSddl = $did.parentSddl }
    Set-Secure $ProgParent $USERS 'ReadAndExecute'
  }
  if (Info $Prog) { Remove-Tree $Prog }
  New-Dir $Prog
  $did.prog = $true
  Set-Secure $Prog $USERS 'ReadAndExecute'
  foreach ($p in $payload) {
    $dest = Join-Path $Prog ($p.name.Replace('/', '\'))
    New-Dir (Split-Path -Parent $dest)
    [IO.File]::WriteAllBytes($dest, $p.bytes)
  }
  $manifest = [ordered]@{
    format = 'adamant-helper'; version = $HelperVersion; installedAt = (Get-Date).ToString('o'); readerSid = $ReaderSid
    files = @($payload | ForEach-Object { [ordered]@{ name = $_.name; sha256 = $_.sha256; size = $_.bytes.Length } })
  }
  [IO.File]::WriteAllText((Join-Path $Prog 'helper.json'), ($manifest | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
  & $Icacls $Prog /setowner "*$ADMINS" /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Не удалось назначить владельца файлов помощника (icacls $LASTEXITCODE)" }

  # Сверка копии: те же байты и надёжные права у каждого файла.
  foreach ($p in $payload) {
    $dest = Join-Path $Prog ($p.name.Replace('/', '\'))
    if ((Sha256 ([IO.File]::ReadAllBytes($dest))) -ne $p.sha256) { throw "Копия $($p.name) не совпадает с исходным файлом" }
  }
  foreach ($x in @($ProgParent, $Prog)) { $why = Problem $x; if ($why) { throw "Права папки помощника не установились ($why)" } }
  foreach ($x in (Tree $Prog)) { $why = Problem $x; if ($why) { throw "Права файла помощника не установились ($why)" } }

  # ---------- 4. %ProgramData%\Adamant\helper\{out,tmp} ----------
  $bi = Info $Base
  if ($bi -and -not (Owner-Ok $Base)) { $result.moved += (Move-Aside $Base); $bi = $null }
  if (-not $bi) {
    New-Dir $Base
    $did.baseCreated = $true
    Set-Secure $Base '' ''
  } elseif (Problem $Base) {
    Set-Secure $Base '' ''
  }
  $di = Info $Data
  if ($di) {
    if (Owner-Ok $Data) { Remove-Tree $Data } else { $result.moved += (Move-Aside $Data) }
  }
  New-Dir $Data
  $did.data = $true
  Set-Secure $Data '' ''
  New-Dir $TmpDir
  Set-Secure $TmpDir '' ''
  New-Dir $OutDir
  Set-Secure $OutDir $ReaderSid 'ReadAndExecute'
  foreach ($x in @($Base, $Data, $TmpDir, $OutDir)) { $why = Problem $x; if ($why) { throw "Права папки ответов не установились ($why)" } }
  $state = [ordered]@{ format = 'adamant-helper-state'; version = $HelperVersion; installedAt = $manifest.installedAt; readerSid = $ReaderSid; before = $before }
  [IO.File]::WriteAllText((Join-Path $Data 'state.json'), ($state | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding $false))
  & $Icacls $Data /setowner "*$ADMINS" /T /C /Q | Out-Null

  # ---------- 5. Задания ----------
  # Права на задания: администраторы и SYSTEM - всё; читатель - смотреть состояние, полную проверку - ещё и запускать.
  foreach ($n in $Tasks.Keys) {
    $mode = $Tasks[$n]
    $sddl = 'D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;' + $(if ($mode -eq 'full') { 'GRGX' } else { 'GR' }) + ";;;$ReaderSid)"
    $xml = TaskXml $mode
    try { [void]$folder.RegisterTask($n, $xml, 6, $null, $null, 5, $sddl) }
    catch { [void]$folder.RegisterTask($n, $xml, 6, 'SYSTEM', $null, 5, $sddl) }
    $did.tasks = $true
    $t = $folder.GetTask($n)
    $a = $t.Definition.Actions.Item(1)
    if ($t.Definition.Actions.Count -ne 1 -or [string]$a.Path -ne $PsExe -or [string]$a.Arguments -ne (TaskArgs $mode)) { throw "Задание «$n» зарегистрировано не так, как нужно" }
  }
  $result.tasks = @($Tasks.Keys)

  # Первая полная проверка - сразу, чтобы сведения появились без ожидания до ночи.
  $result.started = $false
  try { [void]$folder.GetTask('Adamant Helper').Run($null); $result.started = $true } catch { $result.warnings += ('Первый запуск не удался: ' + $_.Exception.Message) }

  $result.program = $Prog
  $result.out = $OutDir
  $result.files = @($manifest.files)
  $result.ok = $true
} catch {
  $result.error = $_.Exception.Message
  # Откат: убираем то, что успели сделать.
  try { if ($folder -and $did.tasks) { Remove-Tasks $folder } } catch {}
  try { if ($did.prog) { Remove-Tree $Prog } } catch {}
  try { if ($did.parentSddl) { $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm($did.parentSddl); [IO.Directory]::SetAccessControl($ProgParent, $s) } } catch {}
  try { if ($did.parentCreated -and (Is-Empty $ProgParent)) { [IO.Directory]::Delete($ProgParent, $false) } } catch {}
  try { if ($did.data) { Remove-Tree $Data } } catch {}
  try { if ($did.baseCreated -and (Is-Empty $Base)) { [IO.Directory]::Delete($Base, $false) } } catch {}
  try { if ($did.taskFolderCreated) { $svc.GetFolder('\').DeleteFolder('Adamant', 0) } } catch {}
}
if ($Out) { Emit $result 6 }
