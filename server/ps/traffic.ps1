# Адамант: сеть и трафик этого компьютера. ТОЛЬКО ЧТЕНИЕ, без запросов в сеть.
#  - adapters  - адаптеры: тип, состояние, адреса IPv4/IPv6, шлюз, DNS, тип сети (общественная/частная), байты с включения;
#  - rate      - сколько байт принято и отправлено за -Seconds секунд (два замера статистики адаптеров);
#  - wifi      - текст «netsh wlan show interfaces» (разбирает server/rules-ready.js); ключи сетей не читаются;
#  - tcp, udp  - соединения и открытые порты с номером процесса; procs - имя и путь процессов;
#  - dns       - кэш DNS этого компьютера (имена сайтов, к которым уже обращались) - чтобы показать имя вместо адреса.
#                Новых DNS-запросов сценарий не делает;
#  - shares    - общие папки (Win32_Share); sharing - включённые правила брандмауэра «Общий доступ к файлам»
#                и «Обнаружение сети» с профилями;
#  - vpn       - VPN-подключения Windows (Get-VpnConnection).
param([ValidateRange(1, 5)][int]$Seconds = 2)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

$R = [ordered]@{ format = 'adamant-traffic'; version = 1; at = (Get-Date).ToUniversalTime().ToString('o'); errors = [ordered]@{} }
function Part([string]$name, [scriptblock]$sb) {
  try { $R[$name] = & $sb } catch { $R[$name] = $null; $R.errors[$name] = [string]$_.Exception.Message }
}

# ---- адаптеры
Part 'adapters' {
  $gw = @{}; $gw6 = @{}
  foreach ($r in Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) { $gw[[int]$r.ifIndex] = [string]$r.NextHop }
  foreach ($r in Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue) { $gw6[[int]$r.ifIndex] = [string]$r.NextHop }
  $cat = @{}; $net = @{}
  foreach ($p in Get-NetConnectionProfile -ErrorAction SilentlyContinue) { $cat[[int]$p.InterfaceIndex] = [string]$p.NetworkCategory; $net[[int]$p.InterfaceIndex] = [string]$p.Name }
  $dns = @{}
  foreach ($d in Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
    $i = [int]$d.InterfaceIndex
    if (-not $dns[$i]) { $dns[$i] = New-Object System.Collections.ArrayList }
    foreach ($s in @($d.ServerAddresses)) { if ($s -and -not $dns[$i].Contains([string]$s)) { [void]$dns[$i].Add([string]$s) } }
  }
  $ip4 = @{}; $ip6 = @{}
  foreach ($a in Get-NetIPAddress -ErrorAction SilentlyContinue) {
    $i = [int]$a.InterfaceIndex
    if ($a.AddressFamily -eq 'IPv4') { if (-not $ip4[$i]) { $ip4[$i] = @() }; $ip4[$i] += [string]$a.IPAddress }
    elseif ($a.PrefixOrigin -ne 'WellKnown' -and [string]$a.IPAddress -notmatch '^(fe80|::1)') { if (-not $ip6[$i]) { $ip6[$i] = @() }; $ip6[$i] += [string]$a.IPAddress }
  }
  $stats = @{}
  foreach ($s in Get-NetAdapterStatistics -ErrorAction SilentlyContinue) { $stats[[string]$s.Name] = $s }
  @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    $i = [int]$_.ifIndex; $st = $stats[[string]$_.Name]
    [ordered]@{
      alias = [string]$_.Name; description = [string]$_.InterfaceDescription; ifIndex = $i; status = [string]$_.Status
      media = [string]$_.PhysicalMediaType; virtual = [bool]$_.Virtual; hardware = [bool]$_.HardwareInterface
      speed = [string]$_.LinkSpeed; mac = [string]$_.MacAddress
      ipv4 = @($ip4[$i]); ipv6 = @($ip6[$i]); gateway = $gw[$i]; gateway6 = $gw6[$i]; dns = @($dns[$i])
      category = $cat[$i]; network = $net[$i]
      rx = $(if ($st) { [int64]$st.ReceivedBytes } else { $null }); tx = $(if ($st) { [int64]$st.SentBytes } else { $null })
    }
  })
}

# ---- скорость: второй замер через несколько секунд
Part 'rate' {
  $a = @{}; foreach ($s in Get-NetAdapterStatistics -ErrorAction SilentlyContinue) { $a[[string]$s.Name] = $s }
  $t0 = Get-Date
  Start-Sleep -Seconds $Seconds
  $sec = ((Get-Date) - $t0).TotalSeconds
  [ordered]@{
    seconds = [math]::Round($sec, 2)
    adapters = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Where-Object { $a.ContainsKey([string]$_.Name) } | ForEach-Object {
      $p = $a[[string]$_.Name]
      [ordered]@{ alias = [string]$_.Name; rx = [int64]($_.ReceivedBytes - $p.ReceivedBytes); tx = [int64]($_.SentBytes - $p.SentBytes) }
    })
  }
}

# ---- Wi-Fi (тот же способ, что в sections/readiness.ps1)
Part 'wifi' {
  $svc = Get-Service -Name 'WlanSvc' -ErrorAction SilentlyContinue
  if (-not $svc -or [string]$svc.Status -ne 'Running') { return $null }
  $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
  $ErrorActionPreference = 'Continue'
  $t = (& $netsh wlan show interfaces 2>$null | Out-String)
  if ($t -match [char]0xFFFD) {
    $old = [Console]::OutputEncoding
    try { [Console]::OutputEncoding = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage); $t = (& $netsh wlan show interfaces 2>$null | Out-String) } catch {} finally { try { [Console]::OutputEncoding = $old } catch {} }
  }
  (@($t -split "`r?`n" | Where-Object { $_ -notmatch '(?i)key content|содержимое ключа|keymaterial' } | ForEach-Object { $_.TrimEnd() }) -join "`n").Trim()
}

# ---- соединения
Part 'tcp' {
  @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in @('Established', 'Listen', 'SynSent', 'SynReceived') } |
    Select-Object -First 3000 | ForEach-Object {
      [ordered]@{ la = [string]$_.LocalAddress; lp = [int]$_.LocalPort; ra = [string]$_.RemoteAddress; rp = [int]$_.RemotePort; state = [string]$_.State; pid = [int]$_.OwningProcess }
    })
}
Part 'udp' {
  @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 1500 | ForEach-Object { [ordered]@{ la = [string]$_.LocalAddress; lp = [int]$_.LocalPort; pid = [int]$_.OwningProcess } })
}
Part 'procs' {
  $ids = @{}
  foreach ($c in @($R.tcp) + @($R.udp)) { if ($c) { $ids[[int]$c.pid] = $true } }
  $o = [ordered]@{}
  foreach ($p in Get-Process -Id @($ids.Keys) -ErrorAction SilentlyContinue) {
    $path = $null; try { $path = [string]$p.Path } catch {}
    $o[[string]$p.Id] = [ordered]@{ name = [string]$p.ProcessName; path = $path }
  }
  $o
}

# ---- кэш DNS (только то, что уже есть на компьютере)
Part 'dns' {
  @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Type -in 1, 12, 28 -and $_.Data } | Select-Object -First 4000 | ForEach-Object {
    [ordered]@{ name = [string]$_.Entry; ip = [string]$_.Data }
  })
}

# ---- общие папки и общий доступ
Part 'shares' {
  @(Get-CimInstance -ClassName Win32_Share -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; path = [string]$_.Path; type = [int64]$_.Type } })
}
Part 'sharing' {
  # Группы правил по ресурсу (не зависят от языка Windows): общий доступ к файлам и принтерам, обнаружение сети.
  $groups = [ordered]@{ files = '@FirewallAPI.dll,-28502'; discovery = '@FirewallAPI.dll,-32752' }
  $o = [ordered]@{}
  foreach ($k in $groups.Keys) {
    $rules = @(Get-NetFirewallRule -Group $groups[$k] -ErrorAction SilentlyContinue | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Inbound' })
    $o[$k] = @($rules | ForEach-Object { [string]$_.Profile } | Sort-Object -Unique)
  }
  $o
}
Part 'vpn' {
  @(Get-VpnConnection -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ name = [string]$_.Name; status = [string]$_.ConnectionStatus; split = [bool]$_.SplitTunneling } })
}

[Console]::Out.Write((ConvertTo-Json -InputObject $R -Depth 6 -Compress))
