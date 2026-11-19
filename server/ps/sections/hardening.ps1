# Адамант: глубокие проверки защиты от взлома (раздел hardening). ТОЛЬКО ЧТЕНИЕ.
# Подключается из collect.ps1 (там же функции Section, Reg, IsoDate и переменная $isAdmin).
# Почти всё читается из реестра - это быстро и работает без прав администратора.

Section 'hardening' {
  $r = [ordered]@{ admin = [bool]$isAdmin }
  $build = 0
  try { $build = [int][Environment]::OSVersion.Version.Build } catch {}
  $r.build = $build
  try { $r.partOfDomain = [bool](Get-CimInstance Win32_ComputerSystem -Property PartOfDomain).PartOfDomain } catch { $r.partOfDomain = $null }

  # ---------- Кража паролей из памяти ----------
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $r.lsa = [ordered]@{
    runAsPPL = Reg $lsa 'RunAsPPL'
    runAsPPLBoot = Reg $lsa 'RunAsPPLBoot'
    lmCompat = Reg $lsa 'LmCompatibilityLevel'
    noLmHash = Reg $lsa 'NoLMHash'
    lsaCfgFlags = Reg $lsa 'LsaCfgFlags'
    lsaCfgFlagsPolicy = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' 'LsaCfgFlags'
    pplEvent = $null
  }
  # Событие Wininit 12 при загрузке: «LSASS.exe запущен как защищённый процесс с уровнем N». Журнал «Система» читается без прав администратора.
  try {
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('System', [System.Diagnostics.Eventing.Reader.PathType]::LogName, "*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=12)]]")
    $q.ReverseDirection = $true
    $rd = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    $e = $rd.ReadEvent()
    if ($e) {
      $lvl = $null
      try { $lvl = [int]$e.Properties[0].Value } catch {}
      $r.lsa.pplEvent = [ordered]@{ at = IsoDate $e.TimeCreated; level = $lvl }
      $e.Dispose()
    }
    $rd.Dispose()
  } catch {}
  $r.wdigest = [ordered]@{ useLogonCredential = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' }
  $r.cachedLogons = Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'

  # ---------- Изоляция ядра (VBS, целостность памяти, Credential Guard) ----------
  $dg = [ordered]@{ vbs = $null; running = @(); configured = @(); available = @() }
  try {
    $d = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
    $dg.vbs = [int]$d.VirtualizationBasedSecurityStatus
    # 1 - Credential Guard, 2 - целостность памяти (HVCI), 3 - System Guard; 0 - ничего.
    $dg.running = @($d.SecurityServicesRunning | Where-Object { $_ } | ForEach-Object { [int]$_ })
    $dg.configured = @($d.SecurityServicesConfigured | Where-Object { $_ } | ForEach-Object { [int]$_ })
    $dg.available = @($d.AvailableSecurityProperties | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
  } catch { $dg.error = $_.Exception.Message }
  $dgKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
  $dg.hvciEnabled = Reg "$dgKey\Scenarios\HypervisorEnforcedCodeIntegrity" 'Enabled'
  $dg.vbsEnabled = Reg $dgKey 'EnableVirtualizationBasedSecurity'
  $r.deviceGuard = $dg

  # ---------- Microsoft Defender: дополнительная защита ----------
  # Исключения Defender здесь не читаются - это отдельная проверка.
  $mp = [ordered]@{ available = $false }
  try {
    $p = Get-MpPreference -ErrorAction Stop
    $mp.available = $true
    $mp.cfa = $p.EnableControlledFolderAccess
    $mp.pua = $p.PUAProtection
    $mp.maps = $p.MAPSReporting
    $mp.samples = $p.SubmitSamplesConsent
    $ids = @($p.AttackSurfaceReductionRules_Ids)
    $acts = @($p.AttackSurfaceReductionRules_Actions)
    $asr = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $ids.Count; $i++) {
      if (-not $ids[$i]) { continue }
      $act = $null
      if ($i -lt $acts.Count -and $null -ne $acts[$i]) { $act = [int]$acts[$i] }
      [void]$asr.Add([ordered]@{ id = ([string]$ids[$i]).ToLower(); action = $act })
    }
    $mp.asr = @($asr)
  } catch { $mp.error = $_.Exception.Message }
  $r.mp = $mp

  # ---------- SmartScreen и блокировка уязвимых драйверов ----------
  $r.smartScreen = [ordered]@{
    explorer = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
    policy = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    policyLevel = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel'
    smartAppControl = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
  }
  $r.driverBlocklist = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'

  # ---------- Сеть: подмена имён и удалённое управление ----------
  $r.llmnr = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
  $r.netbiosNodeType = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NodeType'
  try {
    $r.netbios = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -Property Description, TcpipNetbiosOptions, Index -ErrorAction Stop | ForEach-Object {
      [ordered]@{ name = [string]$_.Description; option = $(if ($null -ne $_.TcpipNetbiosOptions) { [int]$_.TcpipNetbiosOptions } else { $null }); index = [int]$_.Index }
    })
  } catch { $r.netbios = @(); $r.netbiosError = $_.Exception.Message }
  $autoDetect = $null
  try {
    # Reg разворачивает массив байтов, поэтому ключ читаем напрямую. Байт 8, бит 0x08 - «Определять параметры автоматически».
    $ck = Get-Item -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction Stop
    $b = $ck.GetValue('DefaultConnectionSettings')
    if ($b -is [byte[]] -and $b.Length -gt 8) { $autoDetect = [bool]($b[8] -band 8) }
  } catch {}
  $r.wpad = [ordered]@{ autoDetect = $autoDetect; serviceStart = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' 'Start' }

  $sig = [ordered]@{
    serverReg = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
    clientReg = Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
    server = $null; client = $null
  }
  try { $sig.server = [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch {}
  try { $sig.client = [bool](Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature } catch {}
  $r.smbSigning = $sig

  $svc = [ordered]@{}
  foreach ($n in @('WinRM', 'RemoteRegistry', 'Spooler')) {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if ($s) { $svc[$n] = [ordered]@{ status = [string]$s.Status; start = [string]$s.StartType } } else { $svc[$n] = $null }
  }
  $r.services = $svc
  $listeners = 0
  try { $listeners = @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -ErrorAction Stop).Count } catch {}
  $r.winrmListeners = $listeners
  $r.remoteAssistance = [ordered]@{
    allow = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp'
    policy = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp'
  }
  $printers = New-Object System.Collections.ArrayList
  try {
    foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers' -ErrorAction Stop) {
      [void]$printers.Add([ordered]@{ name = [string]$k.PSChildName; port = [string]$k.GetValue('Port', '') })
    }
  } catch {}
  $r.printers = @($printers)

  # ---------- Устаревшие лазейки ----------
  $r.ps2 = [ordered]@{ engine = Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion' }
  $r.execPolicy = [ordered]@{
    machinePolicy = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy'
    userPolicy = Reg 'HKCU:\Software\Policies\Microsoft\Windows\PowerShell' 'ExecutionPolicy'
    machine = Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' 'ExecutionPolicy'
    user = Reg 'HKCU:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' 'ExecutionPolicy'
  }
  $ex = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
  $r.autorun = [ordered]@{
    machineDriveTypes = Reg "HKLM:\$ex" 'NoDriveTypeAutoRun'
    userDriveTypes = Reg "HKCU:\$ex" 'NoDriveTypeAutoRun'
    machineNoAutorun = Reg "HKLM:\$ex" 'NoAutorun'
    userNoAutorun = Reg "HKCU:\$ex" 'NoAutorun'
    disableAutoplay = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay'
  }
  $office = New-Object System.Collections.ArrayList
  foreach ($app in @('Word', 'Excel', 'PowerPoint', 'Access', 'Visio', 'Publisher')) {
    if (-not (Test-Path -LiteralPath "HKCU:\Software\Microsoft\Office\16.0\$app")) { continue }
    $pol = "HKCU:\Software\Policies\Microsoft\Office\16.0\$app\Security"
    [void]$office.Add([ordered]@{
      app = $app
      vbaWarnings = Reg "HKCU:\Software\Microsoft\Office\16.0\$app\Security" 'VBAWarnings'
      policyVbaWarnings = Reg $pol 'VBAWarnings'
      blockInternet = Reg $pol 'blockcontentexecutionfrominternet'
    })
  }
  $r.office = @($office)

  # Автоблокировка (для исправления lock-timeout).
  $r.lock = [ordered]@{ inactivityTimeoutSecs = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' }
  $r
}
