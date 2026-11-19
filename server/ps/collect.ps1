# Адамант: сбор сведений о защите компьютера. ТОЛЬКО ЧТЕНИЕ - сценарий ничего не меняет в системе.
# Без прав администратора часть сведений недоступна (BitLocker, TPM, порядок загрузки) - тогда раздел
# остаётся пустым, а причина пишется в errors. С правами администратора (полная проверка) - всё.
#   powershell -File collect.ps1              → JSON в stdout
#   powershell -File collect.ps1 -Out f.json  → JSON в файл (для запуска с правами администратора)
param([string]$Out = '')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

$R = [ordered]@{ format = 'adamant-facts'; version = 2; errors = [ordered]@{} }
function Section([string]$name, [scriptblock]$b) {
  try { $R[$name] = & $b } catch { $R.errors[$name] = $_.Exception.Message }
}
function Reg([string]$path, [string]$name) {
  try { $p = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop; return $p.$name } catch { return $null }
}
function IsoDate($d) { if ($null -eq $d) { return $null }; try { return ([datetime]$d).ToString('o') } catch { return $null } }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$R.collectedAt = (Get-Date).ToString('o')
$R.isAdmin = $isAdmin

Section 'meta' {
  $os = Get-CimInstance Win32_OperatingSystem
  $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  [ordered]@{
    computer = $env:COMPUTERNAME
    user = $me.Name
    userSid = $me.User.Value
    osCaption = [string]$os.Caption
    osVersion = [string]$os.Version
    osBuild = [string]$os.BuildNumber
    ubr = Reg $cv 'UBR'
    displayVersion = Reg $cv 'DisplayVersion'
    edition = Reg $cv 'EditionID'
    lastBoot = IsoDate $os.LastBootUpTime
  }
}

# ---------- Порты и службы ----------
Section 'ports' {
  $names = @{}; $paths = @{}
  foreach ($p in Get-Process) { $names[[int]$p.Id] = $p.ProcessName; try { if ($p.Path) { $paths[[int]$p.Id] = $p.Path } } catch {} }
  $svc = @{}
  foreach ($s in Get-CimInstance Win32_Service -Filter "State='Running'") {
    $id = [int]$s.ProcessId
    if ($id -gt 0) { if (-not $svc.ContainsKey($id)) { $svc[$id] = New-Object System.Collections.ArrayList }; [void]$svc[$id].Add([string]$s.Name) }
  }
  function Svc($id) { if ($svc.ContainsKey($id)) { return ,@($svc[$id]) } else { return ,@() } }
  $tcp = @(Get-NetTCPConnection -State Listen | ForEach-Object {
    $id = [int]$_.OwningProcess
    [ordered]@{ proto = 'tcp'; addr = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = $id; proc = $names[$id]; path = $paths[$id]; services = (Svc $id) }
  })
  $udp = @(Get-NetUDPEndpoint | Where-Object { $_.LocalPort -lt 49152 -and $_.LocalAddress -notmatch '^(127\.|::1$)' } | ForEach-Object {
    $id = [int]$_.OwningProcess
    [ordered]@{ proto = 'udp'; addr = [string]$_.LocalAddress; port = [int]$_.LocalPort; pid = $id; proc = $names[$id]; path = $paths[$id]; services = (Svc $id) }
  })
  [ordered]@{ tcp = $tcp; udp = $udp }
}

# ---------- Брандмауэр и сети ----------
Section 'firewall' {
  [ordered]@{
    profiles = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; inbound = [string]$_.DefaultInboundAction } })
    networks = @(Get-NetConnectionProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; category = [string]$_.NetworkCategory; alias = [string]$_.InterfaceAlias; ifIndex = [int]$_.InterfaceIndex } })
  }
}

# ---------- Антивирус ----------
Section 'defender' {
  $r = [ordered]@{}
  try {
    $m = Get-MpComputerStatus
    $r.status = [ordered]@{
      serviceEnabled = [bool]$m.AMServiceEnabled; antivirusEnabled = [bool]$m.AntivirusEnabled
      realTime = [bool]$m.RealTimeProtectionEnabled; tamper = $m.IsTamperProtected
      signatureAge = [int]$m.AntivirusSignatureAge; mode = [string]$m.AMRunningMode
    }
  } catch { $r.statusError = $_.Exception.Message }
  try {
    $r.products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name = [string]$_.displayName; state = [int]$_.productState } })
  } catch { $r.products = @() }
  $r
}

# ---------- SMBv1 ----------
Section 'smb' {
  $r = [ordered]@{}
  try { $c = Get-SmbServerConfiguration; $r.server1 = [bool]$c.EnableSMB1Protocol; $r.server2 = [bool]$c.EnableSMB2Protocol } catch { $r.serverError = $_.Exception.Message }
  $r.clientDriver = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'
  $r.clientStart = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
  if ($isAdmin) { try { $r.feature = [string](Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State } catch {} }
  try { $r.shares = @(Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { [ordered]@{ name = [string]$_.Name; path = [string]$_.Path } }) } catch { $r.shares = @() }
  $r
}

# ---------- Удалённый рабочий стол ----------
Section 'rdp' {
  $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  [ordered]@{
    deny = Reg $ts 'fDenyTSConnections'
    nla = Reg "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
    port = Reg "$ts\WinStations\RDP-Tcp" 'PortNumber'
    policyDeny = Reg $pol 'fDenyTSConnections'
    policyNla = Reg $pol 'UserAuthentication'
  }
}

# ---------- UAC ----------
Section 'uac' {
  $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  [ordered]@{ enableLua = Reg $p 'EnableLUA'; consentAdmin = Reg $p 'ConsentPromptBehaviorAdmin'; secureDesktop = Reg $p 'PromptOnSecureDesktop' }
}

# ---------- Учётные записи ----------
Section 'accounts' {
  $r = [ordered]@{}
  $r.users = @(Get-LocalUser | ForEach-Object { [ordered]@{
    name = [string]$_.Name; sid = [string]$_.SID.Value; enabled = [bool]$_.Enabled
    passwordRequired = [bool]$_.PasswordRequired; passwordLastSet = IsoDate $_.PasswordLastSet; lastLogon = IsoDate $_.LastLogon
  } })
  try {
    $r.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID.Value; kind = [string]$_.ObjectClass; source = [string]$_.PrincipalSource } })
  } catch {
    # Get-LocalGroupMember падает на «осиротевших» записях - читаем группу через ADSI.
    $g = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
    $r.admins = @(([ADSI]"WinNT://$env:COMPUTERNAME/$g,group").psbase.Invoke('Members') | ForEach-Object {
      $n = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
      $sid = try { (New-Object Security.Principal.SecurityIdentifier ($_.GetType().InvokeMember('objectSid', 'GetProperty', $null, $_, $null)), 0).Value } catch { '' }
      [ordered]@{ name = [string]$n; sid = [string]$sid; kind = ''; source = '' }
    })
  }
  $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $r.autoLogon = [string](Reg $wl 'AutoAdminLogon')
  # Сам пароль не читаем и не передаём - только факт, что он записан.
  $r.autoLogonPasswordStored = $null -ne (Reg $wl 'DefaultPassword')
  $r
}

# ---------- Автозагрузка ----------
Section 'autostart' {
  $sid = $me.User.Value
  $items = New-Object System.Collections.ArrayList
  $approvedRoots = @{
    'HKLM-Run' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKLM-Run32' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    'HKCU-Run' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'Startup-User' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    'Startup-Common' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
  }
  function State($loc, $name) {
    if (-not $approvedRoots.ContainsKey($loc)) { return 'on' }
    $v = Reg $approvedRoots[$loc] $name
    if ($v -is [byte[]] -and $v.Length -gt 0 -and ($v[0] -band 1)) { return 'off' }
    return 'on'
  }
  $keys = [ordered]@{
    'HKLM-Run' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'HKLM-Run32' = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    'HKCU-Run' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKLM-RunOnce' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKCU-RunOnce' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
  }
  foreach ($loc in $keys.Keys) {
    try {
      $k = Get-Item -LiteralPath $keys[$loc] -ErrorAction Stop
      foreach ($n in $k.GetValueNames()) {
        if ($n -eq '') { continue }
        [void]$items.Add([ordered]@{ loc = $loc; name = [string]$n; command = [string]$k.GetValue($n, '', 'DoNotExpandEnvironmentNames'); state = (State $loc $n) })
      }
    } catch {}
  }
  $folders = [ordered]@{ 'Startup-User' = [Environment]::GetFolderPath('Startup'); 'Startup-Common' = [Environment]::GetFolderPath('CommonStartup') }
  $sh = New-Object -ComObject WScript.Shell
  foreach ($loc in $folders.Keys) {
    $dir = $folders[$loc]
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($f in Get-ChildItem -LiteralPath $dir -File -Force) {
      if ($f.Name -ieq 'desktop.ini') { continue }
      $cmd = $f.FullName
      if ($f.Extension -ieq '.lnk') { try { $l = $sh.CreateShortcut($f.FullName); $cmd = ('"' + $l.TargetPath + '" ' + $l.Arguments).Trim() } catch {} }
      [void]$items.Add([ordered]@{ loc = $loc; name = [string]$f.Name; command = [string]$cmd; path = [string]$f.FullName; state = (State $loc $f.Name) })
    }
  }
  [ordered]@{ userSid = $sid; items = @($items) }
}

# ---------- Обновления ----------
Section 'updates' {
  $r = [ordered]@{}
  try {
    $h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($h) { $r.lastHotfix = IsoDate $h.InstalledOn; $r.lastHotfixId = [string]$h.HotFixID }
  } catch { $r.hotfixError = $_.Exception.Message }
  try {
    $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $n = $s.GetTotalHistoryCount()
    if ($n -gt 0) {
      $last = $null
      foreach ($e in $s.QueryHistory(0, [Math]::Min($n, 300))) {
        # 2 - успешно, 3 - успешно с ошибками. Обновления баз Defender не считаем: они приходят каждый день.
        if (($e.ResultCode -eq 2 -or $e.ResultCode -eq 3) -and $e.Title -notmatch 'KB2267602|KB4052623|KB915597|Defender|Security Intelligence') {
          if ($null -eq $last -or $e.Date -gt $last) { $last = $e.Date }
        }
      }
      $r.lastUpdate = IsoDate $last
    }
  } catch { $r.historyError = $_.Exception.Message }
  try { $r.service = [string](Get-CimInstance Win32_Service -Filter "Name='wuauserv'").StartMode } catch {}
  $r.noAutoUpdate = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
  $r.rebootRequired = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
  $r
}

# ---------- Шифрование, Secure Boot, TPM ----------
Section 'encryption' {
  $shell = New-Object -ComObject Shell.Application
  $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
    $v = $null
    try { $v = $shell.NameSpace($_.DeviceID + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection') } catch {}
    [ordered]@{ drive = [string]$_.DeviceID; shellState = $v; system = ($_.DeviceID -ieq $env:SystemDrive) }
  })
  $r = [ordered]@{ drives = $drives }
  if ($isAdmin) {
    try {
      $r.volumes = @(Get-BitLockerVolume | ForEach-Object { [ordered]@{
        drive = [string]$_.MountPoint; protection = [string]$_.ProtectionStatus; status = [string]$_.VolumeStatus
        percent = [double]$_.EncryptionPercentage; protectors = @($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
      } })
    } catch { $R.errors.bitlocker = $_.Exception.Message }
  }
  $r
}

Section 'boot' {
  $r = [ordered]@{}
  try {
    Add-Type -Namespace Adamant -Name Fw -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool GetFirmwareType(ref uint t);'
    $t = [uint32]0
    if ([Adamant.Fw]::GetFirmwareType([ref]$t)) { $r.firmware = @{ 1 = 'bios'; 2 = 'uefi' }[[int]$t] }
  } catch {}
  $r.secureBoot = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
  $r.tpmDevices = @(Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" | ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.Status } })
  if ($isAdmin) {
    try { $t = Get-Tpm; $r.tpm = [ordered]@{ present = [bool]$t.TpmPresent; ready = [bool]$t.TpmReady; enabled = [bool]$t.TpmEnabled; manufacturer = [string]$t.ManufacturerIdTxt } } catch {}
    try { $w = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm; if ($w) { $r.tpmSpec = [string]$w.SpecVersion } } catch {}
    try { $r.bcdFirmware = (& "$env:SystemRoot\System32\bcdedit.exe" /enum firmware | Out-String) } catch {}
  }
  $r
}

# ---------- BIOS / UEFI ----------
Section 'firmware' {
  $cs = Get-CimInstance Win32_ComputerSystem
  $b = Get-CimInstance Win32_BIOS
  $r = [ordered]@{
    manufacturer = [string]$cs.Manufacturer; model = [string]$cs.Model
    adminPasswordStatus = $cs.AdminPasswordStatus; powerOnPasswordStatus = $cs.PowerOnPasswordStatus
    biosVendor = [string]$b.Manufacturer; biosVersion = [string]$b.SMBIOSBIOSVersion; biosDate = IsoDate $b.ReleaseDate
    vendor = $null
  }
  # Сведения производителя о паролях BIOS (обычно только с правами администратора).
  try {
    $l = Get-CimInstance -Namespace root/wmi -ClassName Lenovo_BiosPasswordSettings -ErrorAction Stop | Select-Object -First 1
    if ($l) { $s = [int]$l.PasswordState; $r.vendor = [ordered]@{ source = 'Lenovo'; admin = [bool]($s -band 2); powerOn = [bool]($s -band 1) } }
  } catch {}
  if (-not $r.vendor) {
    try {
      $h = Get-CimInstance -Namespace root/HP/InstrumentedBIOS -ClassName HP_BIOSSetting -ErrorAction Stop | Where-Object { $_.Name -in @('Setup Password', 'Power-On Password') }
      if ($h) { $r.vendor = [ordered]@{ source = 'HP'; admin = [bool](($h | Where-Object Name -eq 'Setup Password').IsSet); powerOn = [bool](($h | Where-Object Name -eq 'Power-On Password').IsSet) } }
    } catch {}
  }
  if (-not $r.vendor) {
    try {
      $d = Get-CimInstance -Namespace root/dcim/sysman/wmisecurity -ClassName PasswordObject -ErrorAction Stop
      if ($d) { $r.vendor = [ordered]@{ source = 'Dell'; admin = [bool](($d | Where-Object NameId -eq 'Admin').IsPasswordSet); powerOn = [bool](($d | Where-Object NameId -eq 'System').IsPasswordSet) } }
    } catch {}
  }
  $r
}

# ---------- Дополнительные разделы: server/ps/sections/*.ps1 (тоже только чтение) ----------
# Каждый файл добавляет свои разделы через Section 'имя' { ... } и может пользоваться Reg и IsoDate.
foreach ($sec in @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'sections') -Filter '*.ps1' -ErrorAction SilentlyContinue | Sort-Object Name)) {
  try { . $sec.FullName } catch { $R.errors[$sec.BaseName] = $_.Exception.Message }
}

$json = $R | ConvertTo-Json -Depth 8 -Compress
if ($Out) { [IO.File]::WriteAllText($Out, $json, (New-Object Text.UTF8Encoding $false)) } else { [Console]::Out.Write($json) }
