# Адамант: сведения о сетевых адаптерах и соседях (таблица ARP). ТОЛЬКО ЧТЕНИЕ.
#   -Mode adapters  - адаптеры с IPv4, шлюзами и типом сети
#   -Mode neighbors - известные компьютеру устройства своей сети (IP и MAC)
param([ValidateSet('adapters', 'neighbors')][string]$Mode = 'adapters')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false

if ($Mode -eq 'adapters') {
  $ad = @{}
  foreach ($a in Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue) {
    $ad[[int]$a.ifIndex] = [ordered]@{ description = [string]$a.InterfaceDescription; virtual = [bool]$a.Virtual; hardware = [bool]$a.HardwareInterface; status = [string]$a.Status; mac = [string]$a.MacAddress }
  }
  $gw = @{}
  foreach ($r in Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) { $gw[[int]$r.ifIndex] = [string]$r.NextHop }
  $cat = @{}
  foreach ($p in Get-NetConnectionProfile -ErrorAction SilentlyContinue) { $cat[[int]$p.InterfaceIndex] = [string]$p.NetworkCategory }
  $list = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^127\.' } | ForEach-Object {
    $i = [int]$_.InterfaceIndex
    $a = $ad[$i]
    [ordered]@{
      alias = [string]$_.InterfaceAlias; ifIndex = $i; address = [string]$_.IPAddress; prefix = [int]$_.PrefixLength
      gateway = $gw[$i]; category = $cat[$i]
      description = $(if ($a) { $a.description } else { '' }); virtual = $(if ($a) { $a.virtual } else { $true })
      hardware = $(if ($a) { $a.hardware } else { $false }); status = $(if ($a) { $a.status } else { '' }); mac = $(if ($a) { $a.mac } else { '' })
    }
  })
  [Console]::Out.Write((ConvertTo-Json -InputObject $list -Depth 4 -Compress))
} else {
  $list = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.State -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent') -and $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)' } |
    ForEach-Object { [ordered]@{ ip = [string]$_.IPAddress; mac = [string]$_.LinkLayerAddress; state = [string]$_.State; ifIndex = [int]$_.ifIndex } })
  [Console]::Out.Write((ConvertTo-Json -InputObject $list -Depth 3 -Compress))
}
