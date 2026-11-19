# Адамант: физический доступ к компьютеру. ТОЛЬКО ЧТЕНИЕ - ничего не меняет в системе.
# Подмена специальных возможностей на экране входа, флешки, включения и попытки входа за 14 дней,
# автоблокировка, вход после сна, ПИН-код BitLocker при запуске, среда восстановления, защита DMA.
# Журнал «Безопасность» и состав ключей BitLocker - только с правами администратора.

Section 'physical' {
  $r = [ordered]@{ admin = $isAdmin; errors = [ordered]@{} }
  $sys32 = Join-Path $env:SystemRoot 'System32'

  # Помощник на C#: даты подключения устройств (cfgmgr32, работает и для отключённых) и защита DMA ядра.
  $native = $false
  try {
    if (-not ('Adamant.Phys' -as [type])) {
      Add-Type -Namespace Adamant -Name Phys -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct DEVPROPKEY { public Guid fmtid; public uint pid; }
[DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] static extern int CM_Locate_DevNodeW(out uint dn, string id, uint flags);
[DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] static extern int CM_Get_DevNode_PropertyW(uint dn, ref DEVPROPKEY key, out uint type, byte[] buf, ref uint size, uint flags);
[DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, ref byte info, int len, out int ret);
static byte[] Prop(uint dn, string guid, uint pid) {
  DEVPROPKEY k = new DEVPROPKEY(); k.fmtid = new Guid(guid); k.pid = pid;
  uint t; uint sz = 0;
  CM_Get_DevNode_PropertyW(dn, ref k, out t, null, ref sz, 0);
  if (sz == 0 || sz > 4096) return null;
  byte[] b = new byte[sz];
  return CM_Get_DevNode_PropertyW(dn, ref k, out t, b, ref sz, 0) == 0 ? b : null;
}
// [установлен впервые, подключён последний раз, отключён последний раз] (FILETIME или 0), present, parent.
public static object[] Device(string id) {
  uint dn;
  bool present = CM_Locate_DevNodeW(out dn, id, 0) == 0;
  if (!present && CM_Locate_DevNodeW(out dn, id, 1) != 0) return null;
  const string DATES = "83da6326-97a6-4088-9453-a1923f573b29";
  long[] d = new long[3]; uint[] pids = { 101, 102, 103 };
  for (int i = 0; i < 3; i++) { byte[] b = Prop(dn, DATES, pids[i]); if (b != null && b.Length == 8) d[i] = BitConverter.ToInt64(b, 0); }
  if (d[0] == 0) { byte[] b = Prop(dn, DATES, 100); if (b != null && b.Length == 8) d[0] = BitConverter.ToInt64(b, 0); }
  byte[] p = Prop(dn, "4340a6c5-93fa-4706-972c-7b648008a5a7", 8);
  string parent = p == null ? "" : System.Text.Encoding.Unicode.GetString(p).TrimEnd('\0');
  return new object[] { d[0], d[1], d[2], present, parent };
}
// SystemDmaGuardPolicyInformation (202): 1 - защита DMA ядра включена, 0 - нет, -1 - не удалось узнать.
public static int DmaGuard() { byte b = 0; int ret; return NtQuerySystemInformation(202, ref b, 1, out ret) == 0 ? b : -1; }
'@
    }
    $native = $true
  } catch { $r.errors.native = $_.Exception.Message }
  function FileTimeIso([long]$ft) { if ($ft -le 0) { return $null }; try { return [DateTime]::FromFileTime($ft).ToString('o') } catch { return $null } }

  # ---------- Специальные возможности на экране входа ----------
  # Sticky Keys (5 раз Shift), Win+U, экранная клавиатура и т. п. запускаются на экране входа от имени SYSTEM.
  # Подмена файла или «отладчик» в IFEO превращает их в командную строку без пароля.
  try {
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $r.accessibility = @(foreach ($exe in @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')) {
      $path = Join-Path $sys32 $exe
      $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
      $orig = $null; $desc = $null; $mod = $null
      if ($item) {
        $vi = $item.VersionInfo
        $orig = [string]$vi.OriginalFilename
        if ($orig) { $orig = ($orig -replace '\.mui$', '').Trim() }
        $desc = [string]$vi.FileDescription
        $mod = IsoDate $item.LastWriteTime
      }
      $dbg = Reg "$ifeo\$exe" 'Debugger'
      [ordered]@{ exe = $exe; path = $path; exists = [bool]$item; originalName = $orig; description = $desc; modified = $mod; debugger = $(if ($dbg) { [string]$dbg } else { $null }) }
    })
    # Зарегистрированные средства специальных возможностей: подменённая команда запуска - тот же приём.
    $ats = New-Object System.Collections.ArrayList
    try {
      foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs' -ErrorAction SilentlyContinue) {
        $start = [string]$k.GetValue('StartExe'); $at = [string]$k.GetValue('ATExe')
        if ($start -match '[\\.]' -or $at -match '\.') { [void]$ats.Add([ordered]@{ name = [string]$k.PSChildName; startExe = $start; atExe = $at }) }
      }
    } catch {}
    $r.ats = @($ats)
  } catch { $r.errors.accessibility = $_.Exception.Message }

  # ---------- Флешки и внешние диски ----------
  try {
    $usb = New-Object System.Collections.ArrayList
    $add = {
      param($id, $name, $serial)
      $d = $null
      if ($native) { try { $d = [Adamant.Phys]::Device($id) } catch {} }
      $first = $null; $last = $null; $removed = $null; $present = $null
      if ($d) { $first = FileTimeIso $d[0]; $last = FileTimeIso $d[1]; $removed = FileTimeIso $d[2]; $present = [bool]$d[3] }
      [void]$usb.Add([ordered]@{ name = [string]$name; serial = [string]$serial; first = $first; last = $last; removed = $removed; present = $present; id = [string]$id })
    }
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum'
    foreach ($dev in Get-ChildItem -LiteralPath "$root\USBSTOR" -ErrorAction SilentlyContinue) {
      foreach ($inst in Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue) {
        $name = [string]$inst.GetValue('FriendlyName')
        if (-not $name) { $name = ($dev.PSChildName -replace '^\w+&Ven_', '' -replace '&Prod_', ' ' -replace '&Rev_.*$', '' -replace '_', ' ').Trim() }
        & $add "USBSTOR\$($dev.PSChildName)\$($inst.PSChildName)" $name ($inst.PSChildName -replace '&\d+$', '')
      }
    }
    # Быстрые внешние диски (UASP) видны как SCSI-диски, подключённые через USB.
    if ($native) {
      foreach ($dev in Get-ChildItem -LiteralPath "$root\SCSI" -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like 'Disk*' }) {
        foreach ($inst in Get-ChildItem -LiteralPath $dev.PSPath -ErrorAction SilentlyContinue) {
          $id = "SCSI\$($dev.PSChildName)\$($inst.PSChildName)"
          $d = $null; try { $d = [Adamant.Phys]::Device($id) } catch {}
          if ($d -and ([string]$d[4]) -match '^USB') { & $add $id ([string]$inst.GetValue('FriendlyName')) '' }
        }
      }
    }
    # Новые сверху; порядок устойчивый (для сравнения проверок между собой).
    $r.usb = @($usb | Sort-Object -Property @{ Expression = { [string]$_.last }; Descending = $true }, @{ Expression = { [string]$_.first }; Descending = $true }, @{ Expression = { $_.id }; Descending = $false } | Select-Object -First 30)
  } catch { $r.errors.usb = $_.Exception.Message }

  # ---------- Включения, сон и входы за 14 дней ----------
  try {
    $days = 14
    $ms = $days * 86400000
    $since = "TimeCreated[timediff(@SystemTime) <= $ms]"
    $events = New-Object System.Collections.ArrayList
    $seen = @{}
    function AddEvent($at, [string]$kind, $extra) {
      $iso = IsoDate $at
      $key = "$kind|$($extra.user)|$($iso.Substring(0, 19))"
      if ($seen.ContainsKey($key)) { return }
      $seen[$key] = $true
      $e = [ordered]@{ at = $iso; kind = $kind }
      if ($extra) { foreach ($k in $extra.Keys) { if ($null -ne $extra[$k] -and $extra[$k] -ne '') { $e[$k] = $extra[$k] } } }
      [void]$events.Add($e)
    }
    $q = "*[System[$since and (" +
      "(Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12 or EventID=13)) or " +
      "(Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41 or EventID=42)) or " +
      "(Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1) or " +
      "(Provider[@Name='EventLog'] and EventID=6008) or " +
      "(Provider[@Name='Microsoft-Windows-Winlogon'] and EventID=7001))]]"
    $sidNames = @{}
    foreach ($e in @(Get-WinEvent -LogName System -FilterXPath $q -MaxEvents 150 -ErrorAction SilentlyContinue)) {
      $p = $e.ProviderName
      $kind = switch ($e.Id) {
        12 { if ($p -like '*Kernel-General') { 'boot' } }
        13 { if ($p -like '*Kernel-General') { 'shutdown' } }
        42 { 'sleep' }
        1 { if ($p -like '*Power-Troubleshooter') { 'wake' } }
        41 { 'unexpected' }
        6008 { 'unexpected' }
        7001 { 'logon' }
      }
      if (-not $kind) { continue }
      $extra = [ordered]@{ source = 'system' }
      if ($kind -eq 'logon') {
        if ($isAdmin) { continue }  # с правами администратора входы берём из журнала «Безопасность» - там подробнее
        $sid = try { [string]$e.Properties[1].Value } catch { '' }
        if ($sid) {
          if (-not $sidNames.ContainsKey($sid)) { $sidNames[$sid] = try { (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { $sid } }
          $extra.user = $sidNames[$sid]
        }
      }
      AddEvent $e.TimeCreated $kind $extra
    }
    $r.presence = [ordered]@{ days = $days; security = $false; events = $null }
    if ($isAdmin) {
      try {
        # Входы с клавиатуры этого компьютера: 2 - обычный, 7 - разблокировка, 11 - по сохранённому паролю.
        # Неудачные попытки 4625 - только 2 и 7 (то есть за этим компьютером, а не по сети).
        $lt = { param($types) ($types | ForEach-Object { "Data[@Name='LogonType']='$_'" }) -join ' or ' }
        $qs = "*[System[(EventID=4624) and $since] and EventData[$(& $lt @(2, 7, 11))]]"
        $ql = "*[System[(EventID=4800 or EventID=4801) and $since]]"
        $qf = "*[System[(EventID=4625) and $since] and EventData[$(& $lt @(2, 7))]]"
        $sec = @(@(Get-WinEvent -LogName Security -FilterXPath $qs -MaxEvents 300 -ErrorAction SilentlyContinue) + @(Get-WinEvent -LogName Security -FilterXPath $ql -MaxEvents 100 -ErrorAction SilentlyContinue) | Sort-Object TimeCreated -Descending)
        $bad = @(Get-WinEvent -LogName Security -FilterXPath $qf -MaxEvents 50 -ErrorAction SilentlyContinue)
        $n = 0
        foreach ($e in $sec) {
          if ($n -ge 100) { break }
          $x = [xml]$e.ToXml()
          $data = @{}; foreach ($d in $x.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
          if ($e.Id -eq 4624) {
            # Служебные входы Windows (диспетчер окон, драйвер шрифтов) пропускаем.
            if ($data.TargetUserSid -match '^S-1-5-(90|96|18|19|20)(-|$)' -or $data.TargetDomainName -in @('Window Manager', 'Font Driver Host')) { continue }
            $kind = if ($data.LogonType -eq '7') { 'unlock' } else { 'logon' }
            $user = if ($data.TargetDomainName) { "$($data.TargetDomainName)\$($data.TargetUserName)" } else { $data.TargetUserName }
            AddEvent $e.TimeCreated $kind ([ordered]@{ source = 'security'; user = $user; logonType = [int]$data.LogonType })
          } else {
            $kind = if ($e.Id -eq 4800) { 'lock' } else { 'unlock' }
            AddEvent $e.TimeCreated $kind ([ordered]@{ source = 'security'; user = "$($data.TargetDomainName)\$($data.TargetUserName)" })
          }
          $n++
        }
        foreach ($e in $bad) {
          $x = [xml]$e.ToXml()
          $data = @{}; foreach ($d in $x.Event.EventData.Data) { $data[[string]$d.Name] = [string]$d.'#text' }
          $user = if ($data.TargetDomainName -and $data.TargetDomainName -ne '-') { "$($data.TargetDomainName)\$($data.TargetUserName)" } else { $data.TargetUserName }
          AddEvent $e.TimeCreated 'failed-local' ([ordered]@{ source = 'security'; user = $user; logonType = [int]$data.LogonType; status = $data.SubStatus })
        }
        $r.presence.security = $true
      } catch { $r.errors.security = $_.Exception.Message }
    }
    $r.presence.events = @($events | Sort-Object -Property @{ Expression = { [string]$_.at }; Descending = $true } | Select-Object -First 300)
  } catch { $r.errors.presence = $_.Exception.Message }

  # ---------- Автоблокировка и вход после сна ----------
  try {
    $desk = 'HKCU:\Control Panel\Desktop'
    $pol = 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    function Pick($name) { $v = Reg $pol $name; if ($null -ne $v -and "$v" -ne '') { return $v }; return Reg $desk $name }
    function Int($v) { if ($null -eq $v -or "$v" -eq '') { return $null }; try { return [int64]$v } catch { return $null } }
    # Текущие значения схемы питания (последние два числа 0x… в выводе - от сети и от батареи).
    function PowerIdx([string]$sub, [string]$setting) {
      try {
        $hex = @(& (Join-Path $sys32 'powercfg.exe') /qh SCHEME_CURRENT $sub $setting 2>$null | ForEach-Object { if ($_ -match ':\s*0x([0-9a-fA-F]+)\s*$') { [Convert]::ToInt64($Matches[1], 16) } })
        if ($hex.Count -ge 2) { return @($hex[-2], $hex[-1]) }
      } catch {}
      return @($null, $null)
    }
    $cl = PowerIdx 'SUB_NONE' 'CONSOLELOCK'
    $clPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
    $clAc = Int (Reg $clPol 'ACSettingIndex'); if ($null -eq $clAc) { $clAc = $cl[0] }
    $clDc = Int (Reg $clPol 'DCSettingIndex'); if ($null -eq $clDc) { $clDc = $cl[1] }
    $sl = PowerIdx 'SUB_SLEEP' 'STANDBYIDLE'
    $battery = $false
    try { $battery = @(Get-CimInstance Win32_Battery -ErrorAction Stop).Count -gt 0 } catch {}
    $r.lock = [ordered]@{
      screenSaverActive = [string](Pick 'ScreenSaveActive') -eq '1'
      screenSaverExe = [string](Pick 'SCRNSAVE.EXE')
      screenSaverSecure = [string](Pick 'ScreenSaverIsSecure') -eq '1'
      screenSaverTimeout = Int (Pick 'ScreenSaveTimeOut')
      inactivityTimeout = Int (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs')
      dynamicLock = [string](Reg 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'EnableGoodbye') -eq '1'
      consoleLockAc = $clAc
      consoleLockDc = $clDc
      delayLock = Int (Reg $desk 'DelayLockInterval')
      sleepAc = $sl[0]
      sleepDc = $sl[1]
      battery = $battery
    }
  } catch { $r.errors.lock = $_.Exception.Message }

  # ---------- BitLocker: что нужно при запуске ----------
  try {
    $fve = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $b = [ordered]@{
      protectors = @(); preboot = $null
      policy = [ordered]@{ useAdvancedStartup = Reg $fve 'UseAdvancedStartup'; useTpm = Reg $fve 'UseTPM'; useTpmPin = Reg $fve 'UseTPMPIN'; useTpmKey = Reg $fve 'UseTPMKey'; useTpmKeyPin = Reg $fve 'UseTPMKeyPIN' }
    }
    if ($isAdmin) {
      try {
        $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $b.protection = [string]$v.ProtectionStatus
        $b.protectors = @($v.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType })
        $pre = @($b.protectors | Where-Object { $_ -in @('TpmPin', 'TpmPinStartupKey', 'TpmStartupKey', 'ExternalKey', 'Password') })
        $b.preboot = if ([string]$v.ProtectionStatus -ne 'On' -or -not $b.protectors.Count) { 'none' } elseif ($pre.Count) { 'pin' } elseif ($b.protectors -contains 'Tpm') { 'tpm-only' } else { $null }
      } catch { $r.errors.bitlocker = $_.Exception.Message }
    }
    $r.bitlocker = $b
  } catch { $r.errors.bitlocker = $_.Exception.Message }

  # ---------- Среда восстановления Windows (WinRE) ----------
  try {
    $w = [ordered]@{ enabled = $null; source = $null }
    if ($isAdmin) {
      try {
        $out = @(& (Join-Path $sys32 'reagentc.exe') /info 2>$null)
        foreach ($l in $out) { if ($l -match 'RE.*:\s*(Enabled|Disabled)\s*$') { $w.enabled = $Matches[1] -eq 'Enabled'; $w.source = 'reagentc'; break } }
      } catch {}
    }
    if ($null -eq $w.enabled) {
      # ReAgent.xml обычно читается и без прав администратора.
      try {
        $x = [xml](Get-Content -LiteralPath (Join-Path $sys32 'Recovery\ReAgent.xml') -Raw -ErrorAction Stop)
        $st = [string]$x.WindowsRE.InstallState.state
        if ($st -ne '') { $w.enabled = $st -eq '1'; $w.source = 'reagent.xml' }
      } catch {}
    }
    $r.winre = $w
  } catch { $r.errors.winre = $_.Exception.Message }

  # ---------- Защита памяти от устройств Thunderbolt/USB4 (Kernel DMA Protection) ----------
  try {
    $tb = $false
    foreach ($d in Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -ErrorAction SilentlyContinue) {
      foreach ($i in Get-ChildItem -LiteralPath $d.PSPath -ErrorAction SilentlyContinue) {
        if (("$($i.GetValue('Service')) $($i.GetValue('DeviceDesc'))") -match 'thunderbolt|usb4|\bTbt') { $tb = $true; break }
      }
      if ($tb) { break }
    }
    $g = if ($native) { [Adamant.Phys]::DmaGuard() } else { -1 }
    $r.dma = [ordered]@{ protection = $(if ($g -lt 0) { $null } else { $g -eq 1 }); thunderbolt = $tb }
  } catch { $r.errors.dma = $_.Exception.Message }

  $r
}
