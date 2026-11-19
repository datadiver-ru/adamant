# Страж: способы закрепиться в системе и перехватить трафик. ТОЛЬКО ЧТЕНИЕ.
# Службы и задания не от Microsoft, подписки WMI, корневые сертификаты, файл hosts, DNS, прокси,
# исключения антивируса. Подключается из collect.ps1 (есть Section, Reg, IsoDate, $isAdmin).

# Путь к программе из командной строки службы или задания: кавычки, переменные среды, \SystemRoot\, \??\.
function GuardExe([string]$cmd) {
  $c = [Environment]::ExpandEnvironmentVariables([string]$cmd).Trim()
  if (-not $c) { return '' }
  if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); $p = if ($e -gt 0) { $c.Substring(1, $e - 1) } else { $c.Trim('"') } }
  else {
    $p = $c
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|dll|sys|ps1|vbs|js))(\s|$)', 'IgnoreCase')
    if ($m.Success) { $p = $m.Groups[1].Value } elseif ($c -match '^\S+') { $p = $Matches[0] }
  }
  $p = $p -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', ($env:SystemRoot + '\')
  if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
  return $p
}

$guardCompany = @{}
function GuardCompany([string]$p) {
  if (-not $p) { return '' }
  if ($guardCompany.ContainsKey($p)) { return $guardCompany[$p] }
  $v = ''
  try { if ([IO.File]::Exists($p)) { $v = [string][Diagnostics.FileVersionInfo]::GetVersionInfo($p).CompanyName } else { $v = $null } } catch {}
  $guardCompany[$p] = $v
  return $v
}

# Папки, куда может писать обычный пользователь или программа без прав, - оттуда подпись проверяем отдельно.
$guardRiskyDir = '(?i)\\(Users|Temp|ProgramData)\\'
$guardMsCompany = '(?i)Microsoft|Майкрософт'
$guardMsDir = '(?i)^(' + ((@($env:SystemRoot, ${env:ProgramFiles}, ${env:ProgramFiles(x86)}, ($env:ProgramData + '\Microsoft\Windows Defender')) | Where-Object { $_ } | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')\\'
function GuardSigner([string]$p) {
  # Подпись - только для файлов из «рискованных» папок: проверка медленная, а таких файлов единицы.
  if (-not $p -or $p -notmatch $guardRiskyDir) { return $null }
  if (-not [IO.File]::Exists($p)) { return [ordered]@{ status = 'Missing'; subject = '' } }
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $cn = ''
    if ($s.SignerCertificate) { $cn = [string]$s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
    return [ordered]@{ status = [string]$s.Status; subject = $cn }
  } catch { return [ordered]@{ status = 'Error'; subject = '' } }
}
# Командные строки бывают с секретами (ключ VPN, пароль в аргументах): берём только первую строку и прячем значения.
function GuardCut([string]$s, [int]$n) {
  if ($null -eq $s) { return '' }
  $s = ([string]($s -split '[\r\n]')[0]).Trim()
  $s = $s -replace '(?i)((private|preshared|secret|passw|pwd|token|apikey|api_key|auth)\w*\s*[=:]\s*)\S+', '$1***' -replace '(?i)(--?(password|pass|pwd|token|key|secret)[\s=]+)\S+', '$1***'
  if ($s.Length -gt $n) { return $s.Substring(0, $n) + '…' }
  return $s
}

Section 'persistence' {
  $r = [ordered]@{ admin = $isAdmin; errors = [ordered]@{} }

  # ---------- Службы не от Microsoft ----------
  try {
    $hklm = [Microsoft.Win32.Registry]::LocalMachine
    $r.services = @(foreach ($s in Get-CimInstance Win32_Service) {
      $cmd = [string]$s.PathName
      # Без прав администратора у части служб PathName пустой - берём ImagePath из реестра.
      if (-not $cmd) { try { $k = $hklm.OpenSubKey("SYSTEM\CurrentControlSet\Services\$($s.Name)"); if ($k) { $cmd = [string]$k.GetValue('ImagePath'); $k.Close() } } catch {} }
      $exe = GuardExe $cmd
      $file = $exe
      if ($exe -match '(?i)\svchost\.exe$') {
        # Службы внутри svchost: важна библиотека ServiceDll.
        $dll = $null
        foreach ($sub in @("SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters", "SYSTEM\CurrentControlSet\Services\$($s.Name)")) {
          if ($dll) { break }
          try { $k = $hklm.OpenSubKey($sub); if ($k) { $dll = $k.GetValue('ServiceDll'); $k.Close() } } catch {}
        }
        # Библиотеку не видно (закрыта для чтения) - служба Windows внутри системного svchost.
        if (-not $dll) { continue }
        $file = GuardExe $dll
      }
      $company = GuardCompany $file
      if ($company -match $guardMsCompany -and $file -match $guardMsDir) { continue }
      [ordered]@{
        name = [string]$s.Name; displayName = [string]$s.DisplayName; path = GuardCut $cmd 300; file = [string]$file
        startMode = [string]$s.StartMode; state = [string]$s.State; account = [string]$s.StartName; company = $company; signer = (GuardSigner $file)
      }
    })
  } catch { $r.errors.services = $_.Exception.Message }

  # ---------- Задания планировщика вне \Microsoft\ ----------
  # Из \Microsoft\ берём только задания, которые запускают что-то из временных или пользовательских папок.
  # Описание задания читаем из XML: так в разы быстрее, чем через свойство Definition.
  try {
    $sch = New-Object -ComObject Schedule.Service
    $sch.Connect()
    $tasks = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push($sch.GetFolder('\'))
    $hidden = 0
    $risky = '(?i)\(AppData|Temp|Users\Public|Downloads)\|-e(nc|ncodedcommand)?\s|mshta|https?://|\ProgramData\(?!Microsoft\)'
    while ($stack.Count -gt 0) {
      $fo = $stack.Pop()
      $ms = ($fo.Path -eq '\Microsoft') -or ($fo.Path -like '\Microsoft\*')
      try { foreach ($sub in $fo.GetFolders(0)) { $stack.Push($sub) } } catch {}
      $list = $null
      try { $list = $fo.GetTasks(1) } catch { $hidden++; continue }
      foreach ($t in $list) {
        try {
          $xml = [string]$t.Xml
          if ($ms -and $xml -notmatch $risky) { continue }
          $doc = [xml]$xml
          $acts = @(
            foreach ($a in @($doc.Task.Actions.Exec)) { if ($a) { [ordered]@{ exe = [string]$a.Command; args = GuardCut ([string]$a.Arguments) 200 } } }
            foreach ($a in @($doc.Task.Actions.ComHandler)) { if ($a) { [ordered]@{ exe = 'COM ' + [string]$a.ClassId; args = '' } } }
          )
          $text = ($acts | ForEach-Object { $_.exe + ' ' + $_.args }) -join ' '
          if ($ms -and $text -notmatch $risky) { continue }
          $exe = if ($acts.Count -and $acts[0].exe -notlike 'COM *') { GuardExe $acts[0].exe } else { '' }
          [void]$tasks.Add([ordered]@{
            path = [string]$t.Path; name = [string]$t.Name; state = [int]$t.State; enabled = [bool]$t.Enabled
            author = GuardCut ([string]$doc.Task.RegistrationInfo.Author) 100; actions = $acts; ms = $ms
            company = (GuardCompany $exe); signer = (GuardSigner $exe)
          })
        } catch { $hidden++ }
      }
    }
    $r.tasks = @($tasks)
    $r.tasksHidden = $hidden
  } catch { $r.errors.tasks = $_.Exception.Message }

  # ---------- Постоянные подписки WMI (root\subscription) ----------
  try {
    $w = [ordered]@{ visible = $true }
    $w.filters = @(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { [ordered]@{ name = [string]$_.Name; query = GuardCut ([string]$_.Query) 300 } })
    $w.consumers = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | ForEach-Object {
      $cls = [string]$_.CimClass.CimClassName
      $c = [ordered]@{ name = [string]$_.Name; type = $cls; command = '' }
      if ($cls -eq 'CommandLineEventConsumer') { $c.command = GuardCut (([string]$_.ExecutablePath + ' ' + [string]$_.CommandLineTemplate).Trim()) 300 }
      elseif ($cls -eq 'ActiveScriptEventConsumer') { $c.command = GuardCut (([string]$_.ScriptingEngine + ': ' + [string]$_.ScriptFileName + ' ' + [string]$_.ScriptText).Trim()) 300 }
      $c
    })
    $w.bindings = @(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object { [ordered]@{ filter = [string]$_.Filter.Name; consumer = [string]$_.Consumer.Name } })
    $r.wmi = $w
  } catch { $r.wmi = [ordered]@{ visible = $false }; $r.errors.wmi = $_.Exception.Message }

  # ---------- Корневые сертификаты ----------
  # CurrentUser\Root в PowerShell показывает и сертификаты компьютера, поэтому личные берём по реестру.
  try {
    $certs = New-Object System.Collections.ArrayList
    $st = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    $st.Open('ReadOnly')
    foreach ($c in $st.Certificates) { [void]$certs.Add([ordered]@{ store = 'LocalMachine'; thumbprint = [string]$c.Thumbprint; subject = [string]$c.Subject; issuer = $(if ($c.Issuer -ne $c.Subject) { [string]$c.Issuer } else { '' }); notBefore = IsoDate $c.NotBefore }) }
    $st.Close()
    $own = @()
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\SystemCertificates\Root\Certificates')
    if ($k) { $own = @($k.GetSubKeyNames() | ForEach-Object { $_.ToUpperInvariant() }); $k.Close() }
    if ($own.Count) {
      $st = New-Object Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
      $st.Open('ReadOnly')
      foreach ($c in $st.Certificates) { if ($own -contains $c.Thumbprint.ToUpperInvariant()) { [void]$certs.Add([ordered]@{ store = 'CurrentUser'; thumbprint = [string]$c.Thumbprint; subject = [string]$c.Subject; issuer = $(if ($c.Issuer -ne $c.Subject) { [string]$c.Issuer } else { '' }); notBefore = IsoDate $c.NotBefore }) } }
      $st.Close()
    }
    $r.rootCerts = @($certs)
  } catch { $r.errors.rootCerts = $_.Exception.Message }

  # ---------- Файл hosts ----------
  try {
    $hp = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $h = [ordered]@{ entries = @(); total = 0 }
    if ([IO.File]::Exists($hp)) {
      $all = @(foreach ($l in [IO.File]::ReadAllLines($hp)) {
        $x = ($l -replace '#.*$', '').Trim()
        if (-not $x) { continue }
        $p = @($x -split '\s+')
        if ($p.Count -lt 2) { continue }
        foreach ($n in $p[1..($p.Count - 1)]) { [ordered]@{ ip = [string]$p[0]; name = ([string]$n).ToLowerInvariant() } }
      })
      $h.total = $all.Count
      $h.entries = @($all | Select-Object -First 300)
    }
    $r.hosts = $h
  } catch { $r.errors.hosts = $_.Exception.Message }

  # ---------- DNS по работающим адаптерам ----------
  try {
    $r.dns = @(foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
      if ($n.OperationalStatus -ne 'Up' -or $n.NetworkInterfaceType -eq 'Loopback') { continue }
      # fec0:0:0:ffff::1..3 - заглушки Windows, когда DNS для IPv6 не задан.
      $servers = @($n.GetIPProperties().DnsAddresses | ForEach-Object { $_.ToString() } | Where-Object { $_ -notmatch '^fec0:0:0:ffff::' })
      if (-not $servers.Count) { continue }
      [ordered]@{ name = [string]$n.Name; description = [string]$n.Description; type = [string]$n.NetworkInterfaceType; servers = $servers }
    })
  } catch { $r.errors.dns = $_.Exception.Message }

  # ---------- Прокси ----------
  try {
    $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $p = [ordered]@{ enabled = [bool]((Reg $is 'ProxyEnable') -eq 1); server = [string](Reg $is 'ProxyServer'); pac = [string](Reg $is 'AutoConfigURL'); bypass = GuardCut ([string](Reg $is 'ProxyOverride')) 200; winhttp = '' }
    # WinHTTP (службы Windows): двоичное значение WinHttpSettings - флаги в байте 8, затем длина и строка прокси.
    $b = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings'
    if ($b -is [byte[]] -and $b.Length -ge 16) {
      $len = [BitConverter]::ToInt32($b, 12)
      if (($b[8] -band 2) -and $len -gt 0 -and 16 + $len -le $b.Length) { $p.winhttp = [Text.Encoding]::ASCII.GetString($b, 16, $len) }
    }
    $r.proxy = $p
  } catch { $r.errors.proxy = $_.Exception.Message }

  # ---------- Исключения Microsoft Defender ----------
  # Без прав администратора Windows их скрывает (кроме заданных политикой) - тогда visible = false.
  $ex = [ordered]@{ visible = $false; paths = @(); processes = @(); extensions = @() }
  try {
    foreach ($kind in @('Paths', 'Processes', 'Extensions')) {
      $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$kind")
      if ($k) { $ex[$kind.ToLowerInvariant()] = @($k.GetValueNames()); $k.Close() }
    }
  } catch {}
  if ($isAdmin) {
    try {
      $mp = Get-MpPreference
      $vals = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)
      if (-not ($vals | Where-Object { [string]$_ -like 'N/A*' })) {
        $ex.visible = $true
        $ex.paths = @(@($ex.paths) + @($mp.ExclusionPath | Where-Object { $_ }) | Select-Object -Unique)
        $ex.processes = @(@($ex.processes) + @($mp.ExclusionProcess | Where-Object { $_ }) | Select-Object -Unique)
        $ex.extensions = @(@($ex.extensions) + @($mp.ExclusionExtension | Where-Object { $_ }) | Select-Object -Unique)
      }
    } catch { $r.errors.exclusions = $_.Exception.Message }
  }
  $r.exclusions = $ex
  $r
}
