# Адамант: кто пользовался камерой, микрофоном и местоположением (ТОЛЬКО ЧТЕНИЕ). Подключается из collect.ps1.
# Источник - журнал разрешений Windows: HKCU\...\CapabilityAccessManager\ConsentStore\{webcam,microphone,location}.
# Берём только имя или путь программы, время начала и конца использования и разрешение - больше ничего.
# Раздел 'privacy': { webcam, microphone, location } - каждый:
#   value         - разрешение для пользователя ('Allow' | 'Deny' | null), machineValue - для всего компьютера
#   apps[]        - { name, path (для обычных программ), packaged, value, start, stop (ISO), inUse, exists, signature }
#                   signature - состояние подписи файла (только для недавно работавших программ вне Program Files/Windows)
#   count         - сколько программ в журнале (apps обрезан до 40, свежие первыми)

Section 'privacy' {
  $base = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
  function FileTime($v) {
    try { if ($null -ne $v -and [long]$v -gt 0) { return [DateTime]::FromFileTimeUtc([long]$v).ToString('o') } } catch {}
    return $null
  }
  function Entry($key, [string]$name, [string]$path, [bool]$packaged) {
    $start = $key.GetValue('LastUsedTimeStart'); $stop = $key.GetValue('LastUsedTimeStop')
    [ordered]@{
      name = $name; path = $path; packaged = $packaged; value = [string]$key.GetValue('Value')
      start = (FileTime $start); stop = (FileTime $stop)
      inUse = ($null -ne $start -and [long]$start -gt 0 -and ($null -eq $stop -or [long]$stop -eq 0))
      startTicks = [long]("0" + $start)
    }
  }
  $r = [ordered]@{}
  $checked = 0
  $recent = (Get-Date).ToUniversalTime().AddDays(-14).ToFileTimeUtc()
  $trusted = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
  foreach ($cap in 'webcam', 'microphone', 'location') {
    $c = [ordered]@{
      value = Reg "HKCU:\$base\$cap" 'Value'
      machineValue = Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap" 'Value'
      count = 0; apps = @()
    }
    $apps = New-Object System.Collections.ArrayList
    $k = $null
    try { $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("$base\$cap") } catch {}
    if ($k) {
      foreach ($s in $k.GetSubKeyNames()) {
        try {
          if ($s -eq 'NonPackaged') {
            $np = $k.OpenSubKey('NonPackaged')
            foreach ($p in $np.GetSubKeyNames()) {
              $pk = $np.OpenSubKey($p)
              if (-not $pk) { continue }
              $path = $p.Replace('#', '\')
              [void]$apps.Add((Entry $pk ([IO.Path]::GetFileName($path)) $path $false))
              $pk.Close()
            }
            $np.Close()
          } else {
            $sk = $k.OpenSubKey($s)
            if (-not $sk) { continue }
            [void]$apps.Add((Entry $sk ($s -replace '_[a-z0-9]{13}$', '') $null $true))
            $sk.Close()
          }
        } catch {}
      }
      $k.Close()
    }
    $c.count = $apps.Count
    $sorted = @($apps | Sort-Object { $_.startTicks } -Descending | Select-Object -First 40)
    foreach ($a in $sorted) {
      $ticks = $a.startTicks
      $a.Remove('startTicks')
      if (-not $a.path) { continue }
      $a.exists = $null; $a.signature = $null
      if ($ticks -lt $recent) { continue }
      try { $a.exists = [bool](Test-Path -LiteralPath $a.path -PathType Leaf) } catch {}
      $inTrusted = $false
      foreach ($t in $trusted) { if ($a.path.StartsWith($t, [StringComparison]::OrdinalIgnoreCase)) { $inTrusted = $true } }
      # Подпись проверяем только у программ вне Program Files и Windows не больше чем у 3 файлов и только до 60 МБ: проверка большого файла занимает секунды.
      if ($a.exists -and -not $inTrusted -and $checked -lt 3) {
        try {
          $fi = Get-Item -LiteralPath $a.path -ErrorAction Stop
          if ($fi.Length -lt 60MB) { $a.signature = [string](Get-AuthenticodeSignature -LiteralPath $a.path -ErrorAction Stop).Status; $checked++ }
        } catch {}
      }
    }
    $c.apps = $sorted
    $r[$cap] = $c
  }
  $r
}
