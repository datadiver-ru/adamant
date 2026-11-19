# Адамант: кнопка «Тревога» (полная версия). Запускается ТОЛЬКО по кнопке пользователя, с правами администратора.
#   -Mode isolate - отключить от сети: выключить физические сетевые адаптеры, которые сейчас работают
#                   (кабель и Wi-Fi), и записать, какие программы запускались за последние 30 минут;
#   -Mode restore - включить обратно адаптеры из списка -Names (base64 от JSON-массива имён) - те, что выключили мы.
# Ответ - JSON в файл -Out (так его читает сервер после окна UAC).
param(
  [Parameter(Mandatory = $true)][ValidateSet('isolate', 'restore')][string]$Mode,
  [ValidatePattern('^[A-Za-z0-9+/=]{0,4000}$')][string]$Names = '',
  [Parameter(Mandatory = $true)][ValidatePattern('\.json$')][string]$Out
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$r = [ordered]@{ ok = $false; mode = $Mode; adapters = @(); failed = @(); processes = @() }

function Iso($d) { if ($d) { return ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }; return $null }

try {
  if ($Mode -eq 'isolate') {
    $list = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    foreach ($a in $list) {
      try {
        Disable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction Stop
        $r.adapters += [ordered]@{ name = [string]$a.Name; description = [string]$a.InterfaceDescription; media = [string]$a.MediaType }
      } catch { $r.failed += [ordered]@{ name = [string]$a.Name; error = $_.Exception.Message } }
    }
    # Что запускалось за последние 30 минут: то, что могло вызвать тревогу. Только запись, ничего не завершаем.
    try {
      $since = (Get-Date).AddMinutes(-30)
      $win = [string]$env:SystemRoot
      $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.CreationDate -and $_.CreationDate -gt $since } | Sort-Object CreationDate -Descending | Select-Object -First 40)
      foreach ($p in $procs) {
        $path = [string]$p.ExecutablePath
        $sig = $null
        if ($path -and -not $path.StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) {
          try { $sig = [string](Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop).Status } catch { $sig = 'unknown' }
        }
        $r.processes += [ordered]@{ pid = [int]$p.ProcessId; parent = [int]$p.ParentProcessId; name = [string]$p.Name; path = $path; started = (Iso $p.CreationDate); signature = $sig }
      }
    } catch { }
    $r.ok = ($r.adapters.Count -gt 0) -or ($list.Count -eq 0 -and $r.failed.Count -eq 0)
    $r.none = ($list.Count -eq 0)
  } else {
    $want = @()
    if ($Names) { $want = @((New-Object Text.UTF8Encoding $false).GetString([Convert]::FromBase64String($Names)) | ConvertFrom-Json) }
    foreach ($n in $want) {
      try {
        Enable-NetAdapter -Name ([string]$n) -Confirm:$false -ErrorAction Stop
        $r.adapters += [ordered]@{ name = [string]$n }
      } catch { $r.failed += [ordered]@{ name = [string]$n; error = $_.Exception.Message } }
    }
    $r.ok = ($r.failed.Count -eq 0)
  }
} catch { $r.error = $_.Exception.Message }
[IO.File]::WriteAllText($Out, ($r | ConvertTo-Json -Depth 5 -Compress), (New-Object Text.UTF8Encoding $false))
