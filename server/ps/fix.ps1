# Адамант: исправления с откатом. Запускается ТОЛЬКО с правами администратора и только по кнопке «Применить».
#
#   fix.ps1 -Action apply -Id <исправление> [-Arg <Base64 JSON>] -Out <файл.json>
#   fix.ps1 -Action undo  -Record <GUID> -Out <файл.json>
#
# Безопасность:
#  - выполняется только исправление из списка $Fixes ниже, своих команд сценарий не принимает;
#  - аргументы проверяются здесь же (тип расположения автозагрузки, SID, имя);
#  - прежние значения сохраняются в %ProgramData%\Adamant\undo - доступ только у администраторов и SYSTEM.
#    Откат берёт значения оттуда, а не из папки пользователя, поэтому подменить их без прав администратора нельзя;
#  - если исправление сорвалось на середине, прежние значения сразу возвращаются.
param(
  [ValidateSet('apply', 'undo')][string]$Action = 'apply',
  [ValidatePattern('^[a-z0-9-]{1,40}$')][string]$Id = 'none',
  [ValidatePattern('^[A-Za-z0-9+/=]{0,8000}$')][string]$Arg = '',
  [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')][string]$Record = '00000000-0000-0000-0000-000000000000',
  [Parameter(Mandatory = $true)][ValidatePattern('\.json$')][string]$Out
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ADMINS = 'S-1-5-32-544'
$SYSTEM = 'S-1-5-18'
$Base = Join-Path $env:ProgramData 'Adamant'
$Store = Join-Path $Base 'undo'

function Msg([string]$k) { $a = @($args); if ($a.Count) { return [ordered]@{ k = $k; a = $a } } else { return $k } }
function ProfileName([string]$n) { $m = @{ Domain = 'доменная сеть'; Private = 'частная сеть'; Public = 'общедоступная сеть' }; if ($m.ContainsKey($n)) { return $m[$n] } else { return $n } }
function Change($what, $from, $to) { [ordered]@{ what = $what; from = $from; to = $to } }

# ---------- Хранилище прежних значений ----------
function Get-OwnerSid([string]$p) { (Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value }
function Set-Aside([string]$p) {
  # Папку, созданную не администратором, не удаляем: внутри может быть ссылка на чужую папку,
  # и удаление с правами администратора стёрло бы чужие файлы. Просто отодвигаем её в сторону.
  $leaf = Split-Path -Leaf $p
  Rename-Item -LiteralPath $p -NewName ("$leaf.untrusted-" + (Get-Date -Format 'yyyyMMddHHmmss'))
}
function Ensure-Store {
  if ((Test-Path -LiteralPath $Base) -and ((Get-OwnerSid $Base) -notin @($ADMINS, $SYSTEM))) { Set-Aside $Base }
  if ((Test-Path -LiteralPath $Store) -and ((Get-OwnerSid $Store) -notin @($ADMINS, $SYSTEM))) { Set-Aside $Store }
  New-Item -ItemType Directory -Force -Path $Store | Out-Null
  # Сама папка Adamant - только владелец и права для новых вложенных; у помощника (helper) свои защищённые права, их не трогаем.
  & icacls.exe $Base /setowner "*$ADMINS" /Q | Out-Null
  & icacls.exe $Base /inheritance:r /grant:r "*${ADMINS}:(OI)(CI)F" "*${SYSTEM}:(OI)(CI)F" /Q | Out-Null
  & icacls.exe $Store /setowner "*$ADMINS" /T /Q | Out-Null
  & icacls.exe $Store /inheritance:r /grant:r "*${ADMINS}:(OI)(CI)F" "*${SYSTEM}:(OI)(CI)F" /T /Q | Out-Null
}
function Save-Record([string]$rec, $data) {
  $f = Join-Path $Store "$rec.json"
  [IO.File]::WriteAllText($f, ($data | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
  & icacls.exe $f /setowner "*$ADMINS" /Q | Out-Null
}
function Load-Record([string]$rec) {
  $f = Join-Path $Store "$rec.json"
  if (-not (Test-Path -LiteralPath $f)) { throw 'Запись для отката не найдена' }
  if ((Get-OwnerSid $f) -notin @($ADMINS, $SYSTEM)) { throw 'Запись для отката создана не администратором - откат отменён' }
  return (Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# ---------- Реестр ----------
function Get-RegState([string]$path, [string]$name) {
  $k = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
  if (-not $k -or ($k.GetValueNames() -notcontains $name)) { return [ordered]@{ path = $path; name = $name; existed = $false } }
  $kind = [string]$k.GetValueKind($name)
  $v = $k.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
  if ($kind -eq 'Binary') { $v = [Convert]::ToBase64String([byte[]]$v) }
  return [ordered]@{ path = $path; name = $name; existed = $true; kind = $kind; value = $v }
}
function Set-Reg([string]$path, [string]$name, $value, [string]$kind) {
  if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
  if ($kind -eq 'Binary' -and $value -is [string]) { $value = [Convert]::FromBase64String($value) }
  if ($kind -eq 'DWord') { $value = [int]$value }
  New-ItemProperty -LiteralPath $path -Name $name -Value $value -PropertyType $kind -Force | Out-Null
}
function Restore-Reg($st) {
  if ($st.existed) { Set-Reg $st.path $st.name $st.value $st.kind }
  else { Remove-ItemProperty -LiteralPath $st.path -Name $st.name -ErrorAction SilentlyContinue }
}
function Shown($st, [bool]$secret) {
  if (-not $st.existed) { return (Msg 'нет значения') }
  if ($secret) { return (Msg 'записан') }
  return $st.value
}
# Набор значений реестра: capture → change → undo.
function Reg-Capture($specs) { return @($specs | ForEach-Object { Get-RegState $_.path $_.name }) }
function Reg-Change($specs, $backup) {
  $changes = @()
  for ($i = 0; $i -lt $specs.Count; $i++) {
    $s = $specs[$i]; $st = $backup[$i]
    if ($s.remove) {
      if ($st.existed) { Remove-ItemProperty -LiteralPath $s.path -Name $s.name; $changes += Change $s.what (Shown $st $s.secret) (Msg 'удалено') }
    } elseif (-not $st.existed -or "$($st.value)" -ne "$($s.value)") {
      Set-Reg $s.path $s.name $s.value $s.kind
      $changes += Change $s.what (Shown $st $false) $s.value
    }
  }
  return $changes
}
function Reg-Undo($backup) {
  $changes = @()
  foreach ($st in @($backup)) { Restore-Reg $st; $changes += Change $st.name (Msg 'восстановлено') (Shown $st ($st.name -eq 'DefaultPassword')) }
  return $changes
}

# ---------- Список исправлений ----------
$TS = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$UACKEY = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$WINLOGON = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

$RegFixes = @{
  'rdp-nla' = @(@{ path = "$TS\WinStations\RDP-Tcp"; name = 'UserAuthentication'; value = 1; kind = 'DWord'; what = (Msg 'Проверка подлинности на уровне сети (NLA)') })
  'rdp-off' = @(@{ path = $TS; name = 'fDenyTSConnections'; value = 1; kind = 'DWord'; what = (Msg 'Запрет подключений к удалённому рабочему столу') })
  'autologon-off' = @(
    @{ path = $WINLOGON; name = 'AutoAdminLogon'; value = '0'; kind = 'String'; what = (Msg 'Автоматический вход') },
    @{ path = $WINLOGON; name = 'DefaultPassword'; remove = $true; secret = $true; what = (Msg 'Пароль автоматического входа в реестре') }
  )
}
function Uac-Specs {
  $s = @(@{ path = $UACKEY; name = 'EnableLUA'; value = 1; kind = 'DWord'; what = (Msg 'Контроль учётных записей (UAC)') })
  $c = (Get-RegState $UACKEY 'ConsentPromptBehaviorAdmin')
  if ($c.existed -and [int]$c.value -eq 0) { $s += @{ path = $UACKEY; name = 'ConsentPromptBehaviorAdmin'; value = 5; kind = 'DWord'; what = (Msg 'Запрос подтверждения для администраторов') } }
  $s += @{ path = $UACKEY; name = 'PromptOnSecureDesktop'; value = 1; kind = 'DWord'; what = (Msg 'Запрос на защищённом рабочем столе') }
  return $s
}

function Local-User([string]$suffix) { Get-LocalUser | Where-Object { $_.SID.Value -match "-$suffix$" } | Select-Object -First 1 }

$ApprovedKeys = @{
  'HKLM-Run' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
  'HKLM-Run32' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
  'HKCU-Run' = 'Registry::HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
  'Startup-User' = 'Registry::HKEY_USERS\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
  'Startup-Common' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
}
function Autostart-Spec($a) {
  if (-not $a -or -not $ApprovedKeys.ContainsKey([string]$a.loc)) { throw 'Неизвестное место автозагрузки' }
  $name = [string]$a.name
  if ($name.Length -lt 1 -or $name.Length -gt 260 -or $name -match '[\x00-\x1f]') { throw 'Недопустимое имя записи автозагрузки' }
  if ($a.loc -like 'Startup-*' -and $name -match '[\\/]') { throw 'Недопустимое имя файла автозагрузки' }
  $path = $ApprovedKeys[[string]$a.loc]
  if ($path -like '*{SID}*') {
    $sid = [string]$a.userSid
    if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Недопустимый SID пользователя' }
    $path = $path.Replace('{SID}', $sid)
  }
  # Так же отключает «Диспетчер задач»: запись остаётся, Windows её не запускает. Первый байт 03 - «отключено».
  $bytes = [byte[]](@(3, 0, 0, 0) + [BitConverter]::GetBytes([DateTime]::Now.ToFileTimeUtc()))
  return @(@{ path = $path; name = $name; value = [Convert]::ToBase64String($bytes); kind = 'Binary'; what = (Msg 'Автозагрузка: {0}' $name) })
}

# ---------- Закрыть порт: правило брандмауэра «не пускать из сети» ----------
# Тот же список - в server/ports.js (NEVER): без этих портов пропадёт сеть или сломается Windows.
$NeverPorts = @('udp:67', 'udp:68', 'udp:546', 'udp:547', 'tcp:135', 'udp:123')
function PortBlock-Specs($a) {
  $items = @($a.items)
  if ($items.Count -lt 1 -or $items.Count -gt 40) { throw 'Неверный список портов' }
  $cat = @{ Public = 'Public'; Private = 'Private'; DomainAuthenticated = 'Domain' }
  $active = @{}
  foreach ($n in @(Get-NetConnectionProfile)) { $p = $cat[[string]$n.NetworkCategory]; if ($p) { $active[$p] = $true } }
  $off = @(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -ne 'True' -and ($active.Count -eq 0 -or $active.ContainsKey([string]$_.Name)) })
  if ($off.Count) { throw 'Брандмауэр выключен, и правило не сработает. Сначала включите брандмауэр.' }
  $win = [IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\') + '\'
  $specs = @()
  foreach ($i in $items) {
    $rule = [ordered]@{ name = 'Adamant-Block-' + [guid]::NewGuid().ToString('N').Substring(0, 12) }
    if ([string]$i.kind -eq 'program') {
      $path = [string]$i.path
      if ($path.Length -lt 4 -or $path.Length -gt 260 -or $path -match '[\x00-\x1f"*?<>|]' -or $path -notmatch '^[A-Za-z]:\\') { throw 'Недопустимый путь программы' }
      $full = [IO.Path]::GetFullPath($path)
      if ($full.StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) { throw 'Программы Windows так закрывать нельзя' }
      if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'Программа не найдена - обновите проверку' }
      $rule.kind = 'program'; $rule.path = $full
      $rule.display = 'Адамант: не пускать из сети - ' + (Split-Path -Leaf $full)
    } else {
      $proto = [string]$i.proto; $port = 0
      if ($proto -notin @('tcp', 'udp') -or -not [int]::TryParse([string]$i.port, [ref]$port) -or $port -lt 1 -or $port -gt 49151) { throw 'Недопустимый порт' }
      if ($NeverPorts -contains ($proto + ':' + $port)) { throw 'Этот порт закрывать нельзя: без него сломается сеть или Windows' }
      $rule.kind = 'port'; $rule.proto = $proto; $rule.port = $port
      $rule.display = 'Адамант: закрыт порт ' + $proto.ToUpper() + ' ' + $port
    }
    $specs += $rule
  }
  return $specs
}
function PortBlock-What($r) { if ([string]$r.kind -eq 'program') { return (Msg 'Программа «{0}»' (Split-Path -Leaf ([string]$r.path))) } else { return (Msg 'Порт {0} {1}' ([string]$r.proto).ToUpper() ([int]$r.port)) } }

$Fixes = @{
  'firewall-on' = @{
    capture = { param($a) @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } }) }
    change = { param($a, $b)
      Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
      $bad = @(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -ne 'True' })
      if ($bad.Count) { throw 'Брандмауэр не включился. Возможно, им управляет групповая политика или другая программа.' }
      @{ changes = @($b | Where-Object { $_.enabled -ne 'True' } | ForEach-Object { Change (Msg 'Брандмауэр: профиль {0}' (ProfileName $_.name)) (Msg 'выключен') (Msg 'включён') }) }
    }
    undo = { param($b) @($b | ForEach-Object { Set-NetFirewallProfile -Profile $_.name -Enabled $_.enabled; Change (Msg 'Брандмауэр: профиль {0}' (ProfileName $_.name)) (Msg 'восстановлено') $_.enabled }) }
  }
  'defender-realtime' = @{
    capture = { param($a) [ordered]@{ disabled = [bool](Get-MpPreference).DisableRealtimeMonitoring } }
    change = { param($a, $b)
      Set-MpPreference -DisableRealtimeMonitoring $false
      Start-Sleep -Seconds 2
      if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled) { throw 'Защита в реальном времени не включилась. Возможно, её держит политика или другой антивирус.' }
      @{ changes = @(Change (Msg 'Защита Microsoft Defender в реальном времени') (Msg 'выключена') (Msg 'включена')) }
    }
    undo = { param($b) Set-MpPreference -DisableRealtimeMonitoring ([bool]$b.disabled); @(Change (Msg 'Защита Microsoft Defender в реальном времени') (Msg 'восстановлено') $(if ($b.disabled) { Msg 'выключена' } else { Msg 'включена' })) }
  }
  'smb1-off' = @{
    capture = { param($a) [ordered]@{ server = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol; feature = [string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State } }
    change = { param($a, $b)
      $ch = @(); $reboot = $false
      if ($b.server) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false; $ch += Change (Msg 'Сервер SMBv1') (Msg 'включён') (Msg 'выключен') }
      if ($b.feature -eq 'Enabled') {
        $res = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        $reboot = [bool]$res.RestartNeeded
        $ch += Change (Msg 'Компонент Windows «Поддержка SMB 1.0»') (Msg 'установлен') (Msg 'удалён')
      }
      @{ changes = $ch; reboot = $reboot }
    }
    undo = { param($b)
      $ch = @()
      if ($b.feature -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart | Out-Null; $ch += Change (Msg 'Компонент Windows «Поддержка SMB 1.0»') (Msg 'восстановлено') (Msg 'установлен') }
      if ($b.server) { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false; $ch += Change (Msg 'Сервер SMBv1') (Msg 'восстановлено') (Msg 'включён') }
      $ch
    }
  }
  'uac-on' = @{
    capture = { param($a) $s = Uac-Specs; [ordered]@{ specs = $s; regs = (Reg-Capture $s) } }
    change = { param($a, $b) $ch = @(Reg-Change $b.specs $b.regs); @{ changes = $ch; reboot = [bool]($ch | Where-Object { $_.what -eq 'Контроль учётных записей (UAC)' }) } }
    undo = { param($b) Reg-Undo $b.regs }
  }
  'updates-on' = @{
    capture = { param($a) [ordered]@{ service = [string](Get-CimInstance Win32_Service -Filter "Name='wuauserv'").StartMode; regs = (Reg-Capture @(@{ path = $AU; name = 'NoAutoUpdate' })) } }
    change = { param($a, $b)
      $ch = @()
      if ($b.service -eq 'Disabled') { Set-Service -Name wuauserv -StartupType Manual; $ch += Change (Msg 'Служба «Центр обновления Windows»') (Msg 'отключена') (Msg 'вручную (как в Windows по умолчанию)') }
      $ch += @(Reg-Change @(@{ path = $AU; name = 'NoAutoUpdate'; remove = $true; what = (Msg 'Политика «Не обновлять автоматически»') }) $b.regs)
      @{ changes = $ch }
    }
    undo = { param($b)
      $mode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[[string]$b.service]
      if ($mode) { Set-Service -Name wuauserv -StartupType $mode }
      @(Change (Msg 'Служба «Центр обновления Windows»') (Msg 'восстановлено') $b.service) + @(Reg-Undo $b.regs)
    }
  }
  'guest-off' = @{
    capture = { param($a) $u = Local-User '501'; if (-not $u) { throw 'Гостевая учётная запись не найдена' }; [ordered]@{ sid = [string]$u.SID.Value; name = [string]$u.Name; enabled = [bool]$u.Enabled } }
    change = { param($a, $b) Disable-LocalUser -SID $b.sid; @{ changes = @(Change (Msg 'Учётная запись «{0}»' $b.name) (Msg 'включена') (Msg 'отключена')) } }
    undo = { param($b) if ($b.enabled) { Enable-LocalUser -SID $b.sid }; @(Change (Msg 'Учётная запись «{0}»' $b.name) (Msg 'восстановлено') $(if ($b.enabled) { Msg 'включена' } else { Msg 'отключена' })) }
  }
  'admin-off' = @{
    capture = { param($a)
      $u = Local-User '500'
      if (-not $u) { throw 'Встроенная учётная запись администратора не найдена' }
      $sid = [string]$u.SID.Value
      if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq $sid -or ($a -and [string]$a.userSid -eq $sid)) { throw 'Вы работаете под этой учётной записью - отключать её нельзя' }
      $others = @(Get-LocalGroupMember -SID $ADMINS | Where-Object { $_.SID.Value -ne $sid } | Where-Object {
        if ([string]$_.PrincipalSource -eq 'Local' -and [string]$_.ObjectClass -eq 'User') { [bool](Get-LocalUser -SID $_.SID).Enabled } else { $true } })
      if (-not $others.Count) { throw 'Других администраторов нет - отключение заблокировало бы управление компьютером' }
      [ordered]@{ sid = $sid; name = [string]$u.Name; enabled = [bool]$u.Enabled }
    }
    change = { param($a, $b) Disable-LocalUser -SID $b.sid; @{ changes = @(Change (Msg 'Учётная запись «{0}»' $b.name) (Msg 'включена') (Msg 'отключена')) } }
    undo = { param($b) if ($b.enabled) { Enable-LocalUser -SID $b.sid }; @(Change (Msg 'Учётная запись «{0}»' $b.name) (Msg 'восстановлено') $(if ($b.enabled) { Msg 'включена' } else { Msg 'отключена' })) }
  }
  'autostart-off' = @{
    capture = { param($a) $s = Autostart-Spec $a; [ordered]@{ specs = $s; regs = (Reg-Capture $s) } }
    change = { param($a, $b) Reg-Change $b.specs $b.regs | Out-Null; @{ changes = @(Change $b.specs[0].what (Msg 'запускается') (Msg 'отключена')) } }
    undo = { param($b) Reg-Undo $b.regs | Out-Null; @(Change $b.specs[0].what (Msg 'восстановлено') (Msg 'запускается')) }
  }
  # Программа не останавливается: брандмауэр просто не пускает к ней подключения с других устройств.
  # Откат удаляет только свои правила - по имени Adamant-Block-…, записанному до изменения.
  'port-block' = @{
    capture = { param($a) [ordered]@{ rules = @(PortBlock-Specs $a) } }
    change = { param($a, $b)
      $ch = @()
      foreach ($r in @($b.rules)) {
        $p = @{ Name = [string]$r.name; DisplayName = [string]$r.display; Group = 'Адамант'; Direction = 'Inbound'; Action = 'Block'; Profile = 'Any'; Enabled = 'True' }
        if ([string]$r.kind -eq 'program') { $p.Program = [string]$r.path } else { $p.Protocol = ([string]$r.proto).ToUpper(); $p.LocalPort = [string]$r.port }
        New-NetFirewallRule @p | Out-Null
        if (-not (Get-NetFirewallRule -Name ([string]$r.name) -ErrorAction SilentlyContinue)) { throw 'Правило брандмауэра не появилось' }
        $ch += Change (PortBlock-What $r) (Msg 'открыт для сети') (Msg 'закрыт брандмауэром')
      }
      @{ changes = $ch }
    }
    undo = { param($b) @(@($b.rules) | ForEach-Object { Remove-NetFirewallRule -Name ([string]$_.name) -ErrorAction SilentlyContinue; Change (PortBlock-What $_) (Msg 'восстановлено') (Msg 'открыт для сети') }) }
  }
}
foreach ($k in $RegFixes.Keys) {
  $Fixes[$k] = @{
    capture = [scriptblock]::Create("param(`$a) `$s = `$RegFixes['$k']; [ordered]@{ specs = `$s; regs = (Reg-Capture `$s) }")
    change = { param($a, $b) @{ changes = @(Reg-Change $b.specs $b.regs) } }
    undo = { param($b) Reg-Undo $b.regs }
  }
}

# ---------- Защита от взлома (rules-deep.js) и физический доступ ----------
$LSA = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$EXPLPOL = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
# Простые исправления реестра. reboot - изменение начнёт действовать после перезагрузки.
$DeepRegFixes = @{
  'llmnr-off' = @{ reboot = $false; specs = @(@{ path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; name = 'EnableMulticast'; value = 0; kind = 'DWord'; what = (Msg 'Многоадресное разрешение имён (LLMNR)') }) }
  'wdigest-off' = @{ reboot = $false; specs = @(@{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; name = 'UseLogonCredential'; value = 0; kind = 'DWord'; what = (Msg 'Хранение пароля для WDigest') }) }
  'autorun-off' = @{ reboot = $false; specs = @(
    @{ path = $EXPLPOL; name = 'NoDriveTypeAutoRun'; value = 255; kind = 'DWord'; what = (Msg 'Автозапуск для всех типов дисков (NoDriveTypeAutoRun)') },
    @{ path = $EXPLPOL; name = 'NoAutorun'; value = 1; kind = 'DWord'; what = (Msg 'Запуск autorun.inf (NoAutorun)') }
  ) }
  'remote-assistance-off' = @{ reboot = $false; specs = @(@{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; name = 'fAllowToGetHelp'; value = 0; kind = 'DWord'; what = (Msg 'Приглашения удалённому помощнику') }) }
  'driver-blocklist-on' = @{ reboot = $true; specs = @(@{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'; name = 'VulnerableDriverBlocklistEnable'; value = 1; kind = 'DWord'; what = (Msg 'Список уязвимых драйверов Microsoft') }) }
}
function Deep-Capture($specs) { return [ordered]@{ specs = @($specs); regs = @(Reg-Capture @($specs)) } }
function Deep-Undo($b) { $regs = @($b.regs | Where-Object { $_ }); if ($regs.Count) { return @(Reg-Undo $regs) } else { return @() } }
foreach ($k in $DeepRegFixes.Keys) {
  $Fixes[$k] = @{
    capture = [scriptblock]::Create("param(`$a) Deep-Capture `$DeepRegFixes['$k'].specs")
    change = [scriptblock]::Create("param(`$a, `$b) `$ch = @(Reg-Change @(`$b.specs) @(`$b.regs)); @{ changes = `$ch; reboot = (`$ch.Count -gt 0 -and [bool]`$DeepRegFixes['$k'].reboot) }")
    undo = { param($b) Deep-Undo $b }
  }
}

# Специальные возможности на экране входа: только этот список (тот же - в fixes.js).
$IfeoExes = @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')
function Ifeo-Specs($a) {
  $list = @($a.exes | Where-Object { $_ })
  if (-not $list.Count -or $list.Count -gt $IfeoExes.Count) { throw 'Не указаны программы специальных возможностей' }
  $s = @(); $seen = @{}
  foreach ($x in $list) {
    $exe = $IfeoExes | Where-Object { $_ -ieq [string]$x } | Select-Object -First 1
    if (-not $exe) { throw 'Программа не из списка специальных возможностей' }
    if ($seen.ContainsKey($exe)) { continue }
    $seen[$exe] = $true
    $s += @{ path = "$IFEO\$exe"; name = 'Debugger'; remove = $true; what = (Msg 'Перехват запуска {0}' $exe) }
  }
  return ,$s
}

# Microsoft Defender: настройки через Get-/Set-MpPreference с проверкой, что изменение применилось.
function Mp-Name($map, $v) { if ($null -ne $v -and $map.ContainsKey([int]$v)) { return $map[[int]$v] } else { return 'Disabled' } }
$PuaNames = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode' }
$MapsNames = @{ 0 = 'Disabled'; 1 = 'Basic'; 2 = 'Advanced' }
$CfaNames = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 3 = 'BlockDiskModificationOnly'; 4 = 'AuditDiskModificationOnly' }
$MpBlocked = 'Настройка не изменилась. Возможно, её держит защита от подделки, групповая политика или другой антивирус - включите её вручную в «Безопасность Windows».'
$MpShownNames = @{
  Disabled = (Msg 'выключено'); Enabled = (Msg 'включено'); AuditMode = (Msg 'только запись в журнал'); Basic = (Msg 'базовая'); Advanced = (Msg 'расширенная')
  BlockDiskModificationOnly = (Msg 'только защита дисков'); AuditDiskModificationOnly = (Msg 'только запись в журнал'); Warn = (Msg 'предупреждать')
}
function Mp-Shown($map, $v) { if ($null -eq $v) { return (Msg 'не задано') }; return $MpShownNames[(Mp-Name $map $v)] }
# Осторожный набор правил ASR (тот же - в rules-deep.js, SAFE_ASR).
$AsrSafe = [ordered]@{
  '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = (Msg 'Кража паролей из процесса lsass')
  'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = (Msg 'Запуск программ из вложений почты')
  'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = (Msg 'Запуск программ из Office')
  '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = (Msg 'Запуск запутанных сценариев')
  'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = (Msg 'Неподписанные программы с флешек')
  '56a863a9-875e-4185-98a7-b882c64b5ce5' = (Msg 'Уязвимые подписанные драйверы')
}
$AsrActions = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }
function Asr-State {
  $p = Get-MpPreference
  $ids = @($p.AttackSurfaceReductionRules_Ids); $acts = @($p.AttackSurfaceReductionRules_Actions)
  $m = @{}
  for ($i = 0; $i -lt $ids.Count; $i++) {
    if (-not $ids[$i]) { continue }
    $m[([string]$ids[$i]).ToLower()] = $(if ($i -lt $acts.Count -and $null -ne $acts[$i]) { [int]$acts[$i] } else { $null })
  }
  return $m
}
function Asr-Shown($r) { if (-not $r.existed) { return (Msg 'не задано') }; if ($null -ne $r.action -and $AsrActions.ContainsKey([int]$r.action)) { return $MpShownNames[$AsrActions[[int]$r.action]] }; return "$($r.action)" }

$DeepFixes = @{
  'lsa-ppl-on' = @{
    capture = { param($a)
      if ([Environment]::OSVersion.Version.Build -lt 22621) { throw 'Нужна Windows 11 версии 22H2 или новее' }
      $st = Get-RegState $LSA 'RunAsPPL'
      if ($st.existed -and @(1, 2) -contains [int]$st.value) { throw 'Защита LSA уже включена' }
      # 2 - включено без записи в UEFI: откат (удаление значения) работает полностью.
      Deep-Capture @(@{ path = $LSA; name = 'RunAsPPL'; value = 2; kind = 'DWord'; what = (Msg 'Защита LSA (RunAsPPL)') })
    }
    change = { param($a, $b) $ch = @(Reg-Change @($b.specs) @($b.regs)); @{ changes = $ch; reboot = ($ch.Count -gt 0) } }
    undo = { param($b) Deep-Undo $b }
  }
  'lock-timeout' = @{
    capture = { param($a)
      $st = Get-RegState $UACKEY 'InactivityTimeoutSecs'
      if ($st.existed -and [int]$st.value -ge 1 -and [int]$st.value -le 600) { throw 'Автоблокировка уже включена на 10 минут или меньше - менять нечего' }
      Deep-Capture @(@{ path = $UACKEY; name = 'InactivityTimeoutSecs'; value = 600; kind = 'DWord'; what = (Msg 'Автоблокировка при бездействии, секунд') })
    }
    change = { param($a, $b) @{ changes = @(Reg-Change @($b.specs) @($b.regs)) } }
    undo = { param($b) Deep-Undo $b }
  }
  'ifeo-clean' = @{
    capture = { param($a)
      $c = Deep-Capture (Ifeo-Specs $a)
      if (-not @($c.regs | Where-Object { $_.existed }).Count) { throw 'Перехвата уже нет - обновите проверку' }
      $c
    }
    change = { param($a, $b) @{ changes = @(Reg-Change @($b.specs) @($b.regs)) } }
    undo = { param($b) Deep-Undo $b }
  }
  'ps2-off' = @{
    capture = { param($a)
      $st = [ordered]@{}
      foreach ($n in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $f = Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction SilentlyContinue
        $st[$n] = $(if ($f) { [string]$f.State } else { '' })
      }
      if ($st['MicrosoftWindowsPowerShellV2Root'] -ne 'Enabled' -and $st['MicrosoftWindowsPowerShellV2'] -ne 'Enabled') { throw 'PowerShell 2.0 уже удалён или его нет в этой версии Windows' }
      $st
    }
    change = { param($a, $b)
      $res = Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
      @{ changes = @(Change (Msg 'Компонент Windows «PowerShell 2.0»') (Msg 'установлен') (Msg 'удалён')); reboot = [bool]$res.RestartNeeded }
    }
    undo = { param($b)
      # MicrosoftWindowsPowerShellV2 с -All включает и родительский компонент.
      if ($b.MicrosoftWindowsPowerShellV2 -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -All -NoRestart | Out-Null }
      elseif ($b.MicrosoftWindowsPowerShellV2Root -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null }
      @(Change (Msg 'Компонент Windows «PowerShell 2.0»') (Msg 'восстановлено') (Msg 'установлен'))
    }
  }
  'pua-on' = @{
    capture = { param($a) [ordered]@{ value = [int](Get-MpPreference).PUAProtection } }
    change = { param($a, $b)
      Set-MpPreference -PUAProtection Enabled
      if ([int](Get-MpPreference).PUAProtection -ne 1) { throw $MpBlocked }
      @{ changes = @(Change (Msg 'Блокировка нежелательных программ') (Mp-Shown $PuaNames $b.value) (Msg 'включена')) }
    }
    undo = { param($b) Set-MpPreference -PUAProtection (Mp-Name $PuaNames $b.value); @(Change (Msg 'Блокировка нежелательных программ') (Msg 'восстановлено') (Mp-Shown $PuaNames $b.value)) }
  }
  'cloud-on' = @{
    capture = { param($a) [ordered]@{ value = [int](Get-MpPreference).MAPSReporting } }
    change = { param($a, $b)
      Set-MpPreference -MAPSReporting Advanced
      if ([int](Get-MpPreference).MAPSReporting -eq 0) { throw $MpBlocked }
      @{ changes = @(Change (Msg 'Облачная защита (MAPS)') (Mp-Shown $MapsNames $b.value) (Msg 'расширенная')) }
    }
    undo = { param($b) Set-MpPreference -MAPSReporting (Mp-Name $MapsNames $b.value); @(Change (Msg 'Облачная защита (MAPS)') (Msg 'восстановлено') (Mp-Shown $MapsNames $b.value)) }
  }
  'cfa-on' = @{
    capture = { param($a) [ordered]@{ value = [int](Get-MpPreference).EnableControlledFolderAccess } }
    change = { param($a, $b)
      Set-MpPreference -EnableControlledFolderAccess Enabled
      if ([int](Get-MpPreference).EnableControlledFolderAccess -ne 1) { throw $MpBlocked }
      @{ changes = @(Change (Msg 'Контролируемый доступ к папкам') (Mp-Shown $CfaNames $b.value) (Msg 'включён')) }
    }
    undo = { param($b) Set-MpPreference -EnableControlledFolderAccess (Mp-Name $CfaNames $b.value); @(Change (Msg 'Контролируемый доступ к папкам') (Msg 'восстановлено') (Mp-Shown $CfaNames $b.value)) }
  }
  'asr-safe' = @{
    capture = { param($a)
      $m = Asr-State
      [ordered]@{ rules = @($AsrSafe.Keys | ForEach-Object { [ordered]@{ id = $_; existed = $m.ContainsKey($_); action = $(if ($m.ContainsKey($_)) { $m[$_] } else { $null }) } }) }
    }
    change = { param($a, $b)
      $ch = @()
      foreach ($r in @($b.rules)) {
        if ($r.existed -and $null -ne $r.action -and [int]$r.action -eq 1) { continue }
        # Remove + Add - так правило точно получает режим «Блокировать», даже если уже было в другом режиме.
        if ($r.existed) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $r.id }
        Add-MpPreference -AttackSurfaceReductionRules_Ids $r.id -AttackSurfaceReductionRules_Actions Enabled
        $ch += Change (Msg 'Правило защиты: {0}' $AsrSafe[$r.id]) (Asr-Shown $r) (Msg 'блокировать')
      }
      $m = Asr-State
      foreach ($id in $AsrSafe.Keys) { if ($m[$id] -ne 1) { throw $MpBlocked } }
      @{ changes = $ch }
    }
    undo = { param($b)
      $ch = @()
      foreach ($r in @($b.rules)) {
        if ($r.existed -and $null -ne $r.action -and [int]$r.action -eq 1) { continue }
        if ((Asr-State).ContainsKey([string]$r.id)) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $r.id }
        if ($r.existed -and $null -ne $r.action -and $AsrActions.ContainsKey([int]$r.action)) { Add-MpPreference -AttackSurfaceReductionRules_Ids $r.id -AttackSurfaceReductionRules_Actions $AsrActions[[int]$r.action] }
        $ch += Change (Msg 'Правило защиты: {0}' $AsrSafe[$r.id]) (Msg 'восстановлено') (Asr-Shown $r)
      }
      $ch
    }
  }
}
foreach ($k in $DeepFixes.Keys) { $Fixes[$k] = $DeepFixes[$k] }

# ---------- Вход в Windows (rules-login.js) и ПИН-код BitLocker (bitlocker-plan.js) ----------
$FVE = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$CV = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$LockoutForever = [uint32]4294967295
# Блокировка после неверных паролей: USER_MODALS_INFO_3 читается и пишется одним вызовом -
# порог, окно и длительность меняются вместе (net accounts меняет их по одному).
function Lockout-Api {
  if (-not ('Adamant.FixLockout' -as [type])) {
    Add-Type -Namespace Adamant -Name FixLockout -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct INFO3 { public uint duration; public uint window; public uint threshold; }
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserModalsGet(string server, int level, out IntPtr buf);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserModalsSet(string server, int level, ref INFO3 buf, out uint parmErr);
[DllImport("netapi32.dll")] static extern int NetApiBufferFree(IntPtr buf);
// [порог, окно (с), длительность (с)]
public static uint[] Read() {
  IntPtr p;
  int rc = NetUserModalsGet(null, 3, out p);
  if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
  try { INFO3 i = (INFO3)Marshal.PtrToStructure(p, typeof(INFO3)); return new uint[] { i.threshold, i.window, i.duration }; }
  finally { NetApiBufferFree(p); }
}
public static void Write(uint threshold, uint window, uint duration) {
  INFO3 i = new INFO3(); i.threshold = threshold; i.window = window; i.duration = duration;
  uint e;
  int rc = NetUserModalsSet(null, 3, ref i, out e);
  if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
}
'@
  }
}
function Lockout-Read { Lockout-Api; $v = [Adamant.FixLockout]::Read(); return [ordered]@{ threshold = [long]$v[0]; window = [long]$v[1]; duration = [long]$v[2] } }
function Lockout-Write($v) {
  Lockout-Api
  [Adamant.FixLockout]::Write([uint32]$v.threshold, [uint32]$v.window, [uint32]$v.duration)
  $n = Lockout-Read
  if ($n.threshold -ne [long]$v.threshold -or $n.window -ne [long]$v.window -or $n.duration -ne [long]$v.duration) { throw 'Windows не приняла новые значения блокировки входа' }
}
function Lockout-Changes($from, $to, $restored) {
  $minutes = { param($s) if ([long]$s -eq [long]$LockoutForever) { Msg 'до разблокировки администратором' } else { Msg '{0} мин' ([Math]::Max(1, [Math]::Round([long]$s / 60))) } }
  $thr = { param($n) if ([long]$n -eq 0) { Msg 'не задан (0)' } else { "$n" } }
  $f = $(if ($restored) { Msg 'восстановлено' } else { $null })
  @(
    (Change (Msg 'Порог блокировки: неверных паролей подряд') $(if ($restored) { $f } else { & $thr $from.threshold }) (& $thr $to.threshold)),
    (Change (Msg 'За сколько времени считаются ошибки') $(if ($restored) { $f } else { & $minutes $from.window }) (& $minutes $to.window)),
    (Change (Msg 'На сколько закрывается вход') $(if ($restored) { $f } else { & $minutes $from.duration }) (& $minutes $to.duration))
  )
}
function Part-Of-Domain { try { return [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { return $false } }

# Политика BitLocker «ПИН-код при запуске разрешён». Та же логика - в fixes.js (fveSpecs):
# UseAdvancedStartup = 1; если ПИН-код уже «требуется» (1) - больше ничего; иначе UseTPMPIN = 2,
# а UseTPM, UseTPMKey, UseTPMKeyPIN без значения или «требовать» (1) → 2 «разрешать»; «не разрешать» (0) не трогаем.
function Fve-Int($st) { if (-not $st.existed) { return $null }; try { return [int]$st.value } catch { return -1 } }
function Fve-Specs {
  $what = @{
    UseAdvancedStartup = (Msg 'Политика BitLocker: дополнительная проверка при запуске')
    UseTPMPIN = (Msg 'Политика BitLocker: ПИН-код вместе с TPM')
    UseTPM = (Msg 'Политика BitLocker: только TPM, без ПИН-кода')
    UseTPMKey = (Msg 'Политика BitLocker: TPM и флешка-ключ')
    UseTPMKeyPIN = (Msg 'Политика BitLocker: TPM, флешка-ключ и ПИН-код')
  }
  $s = @(@{ path = $FVE; name = 'UseAdvancedStartup'; value = 1; kind = 'DWord'; what = $what.UseAdvancedStartup })
  if ((Fve-Int (Get-RegState $FVE 'UseTPMPIN')) -ne 1) {
    $s += @{ path = $FVE; name = 'UseTPMPIN'; value = 2; kind = 'DWord'; what = $what.UseTPMPIN }
    foreach ($n in @('UseTPM', 'UseTPMKey', 'UseTPMKeyPIN')) {
      $v = Fve-Int (Get-RegState $FVE $n)
      if ($null -eq $v -or $v -eq 1) { $s += @{ path = $FVE; name = $n; value = 2; kind = 'DWord'; what = $what[$n] } }
    }
  }
  return ,$s
}

$LoginFixes = @{
  'lockout-policy' = @{
    capture = { param($a)
      if (Part-Of-Domain) { throw 'Компьютер в домене: правила входа задаёт администратор домена - программа их не меняет' }
      $v = Lockout-Read
      if ($v.threshold -ge 1 -and $v.threshold -le 10) { throw 'Блокировка входа уже включена (после 10 неверных паролей или раньше) - менять нечего' }
      $v
    }
    change = { param($a, $b)
      $to = [ordered]@{ threshold = 10; window = 600; duration = 600 }
      Lockout-Write $to
      @{ changes = @(Lockout-Changes $b $to $false) }
    }
    undo = { param($b)
      Lockout-Write $b
      @(Lockout-Changes $b $b $true)
    }
  }
  'require-cad' = @{
    capture = { param($a)
      $p = Get-RegState $UACKEY 'DisableCAD'
      $w = Get-RegState $WINLOGON 'DisableCAD'
      # Политика важнее значения в Winlogon; без обоих в домене Ctrl+Alt+Del требуется, вне домена - нет.
      $eff = $(if ($p.existed) { Fve-Int $p } elseif ($w.existed) { Fve-Int $w } elseif (Part-Of-Domain) { 0 } else { 1 })
      if ($eff -eq 0) { throw 'Ctrl+Alt+Del перед входом уже требуется - менять нечего' }
      Deep-Capture @(@{ path = $UACKEY; name = 'DisableCAD'; value = 0; kind = 'DWord'; what = (Msg 'Ctrl+Alt+Del перед входом (DisableCAD)') })
    }
    change = { param($a, $b) @{ changes = @(Reg-Change @($b.specs) @($b.regs)) } }
    undo = { param($b) Deep-Undo $b }
  }
  'bitlocker-pin-policy' = @{
    capture = { param($a)
      $ed = Get-RegState $CV 'EditionID'
      if ($ed.existed -and [string]$ed.value -match '^Core') { throw 'В Windows Домашняя BitLocker с ПИН-кодом недоступен' }
      if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\manage-bde.exe'))) { throw 'BitLocker на этом компьютере не установлен' }
      $c = Deep-Capture (Fve-Specs)
      $need = 0
      for ($i = 0; $i -lt $c.specs.Count; $i++) { if (-not $c.regs[$i].existed -or "$($c.regs[$i].value)" -ne "$($c.specs[$i].value)") { $need++ } }
      if (-not $need) { throw 'ПИН-код BitLocker уже разрешён политикой - менять нечего' }
      $c
    }
    change = { param($a, $b) @{ changes = @(Reg-Change @($b.specs) @($b.regs)) } }
    undo = { param($b) Deep-Undo $b }
  }
}
foreach ($k in $LoginFixes.Keys) { $Fixes[$k] = $LoginFixes[$k] }

# ---------- Выполнение ----------
$result = [ordered]@{ ok = $false; action = $Action; id = $Id; record = $null; changes = @(); reboot = $false }
try {
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw 'Нужны права администратора' }
  Ensure-Store
  if ($Action -eq 'apply') {
    if (-not $Fixes.ContainsKey($Id)) { throw "Неизвестное исправление: $Id" }
    $argObj = $null
    if ($Arg) { $argObj = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Arg)) | ConvertFrom-Json }
    $fix = $Fixes[$Id]
    $backup = & $fix.capture $argObj
    $rec = [guid]::NewGuid().ToString()
    # Прежние значения записываем ДО изменения: при сбое их можно вернуть даже вручную.
    Save-Record $rec ([ordered]@{ id = $Id; at = (Get-Date).ToString('o'); backup = $backup })
    # Дальше работаем с той же копией, что легла на диск (так откат и применение видят одинаковые данные).
    $backup = (Load-Record $rec).backup
    try {
      $r = & $fix.change $argObj $backup
    } catch {
      $err = $_.Exception.Message
      try { & $fix.undo $backup | Out-Null } catch {}
      Remove-Item -LiteralPath (Join-Path $Store "$rec.json") -Force -ErrorAction SilentlyContinue
      throw "$err Прежние значения восстановлены."
    }
    $data = Load-Record $rec
    $data | Add-Member -NotePropertyName changes -NotePropertyValue @($r.changes) -Force
    Save-Record $rec $data
    $result.record = $rec; $result.changes = @($r.changes); $result.reboot = [bool]$r.reboot; $result.ok = $true
  } else {
    $data = Load-Record $Record
    if ($data.undone) { throw 'Это исправление уже откачено' }
    $id = [string]$data.id
    if (-not $Fixes.ContainsKey($id)) { throw "Неизвестное исправление: $id" }
    $changes = @(& $Fixes[$id].undo $data.backup)
    $data | Add-Member -NotePropertyName undone -NotePropertyValue (Get-Date).ToString('o') -Force
    Save-Record $Record $data
    $result.id = $id; $result.record = $Record; $result.changes = $changes; $result.ok = $true
  }
} catch {
  $result.error = $_.Exception.Message
}
[IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding $false))
