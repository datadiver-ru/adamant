# Адамант: свежие скачанные программы и сценарии в папке «Загрузки» (ТОЛЬКО ЧТЕНИЕ). Подключается из collect.ps1.
# Смотрит файлы за 30 дней (в самой папке и на один уровень глубже): отметку Windows «скачано из интернета»
# (поток Zone.Identifier - откуда скачан, только имя сайта) и цифровую подпись. Содержимое файлов не читается.
# Раздел 'downloads':
#   dir     - папка «Загрузки»
#   items[] - { name, path, ext, size, at (ISO), zone (3 - интернет, 4 - опасная зона, null - отметки нет),
#               host (сайт, откуда скачан), sig ('valid'|'unsigned'|'bad'|'unknown'|null), signer, double, rtlo }
#   count, truncated

Section 'downloads' {
  $dir = $null
  try {
    $v = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' '{374DE290-123F-4565-9164-39C4925E467B}'
    if ($v) { $dir = [Environment]::ExpandEnvironmentVariables([string]$v) }
  } catch { }
  if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { $dir = Join-Path $env:USERPROFILE 'Downloads' }
  $r = [ordered]@{ dir = $dir; items = @(); count = 0; truncated = $false }
  if (-not (Test-Path -LiteralPath $dir)) { return $r }

  $exts = @('.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.dll', '.scr', '.com', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.lnk', '.reg', '.cpl', '.chm', '.jar', '.iso', '.img', '.vhd', '.vhdx', '.docm', '.xlsm', '.pptm')
  $signable = @('.exe', '.msi', '.msix', '.msixbundle', '.appx', '.appxbundle', '.dll', '.scr', '.com', '.ps1', '.vbs', '.js', '.wsf', '.cpl', '.cab')
  $since = (Get-Date).AddDays(-30)
  $files = New-Object System.Collections.ArrayList
  $level = @(Get-Item -LiteralPath $dir)
  foreach ($depth in 0, 1) {
    $next = @()
    foreach ($d in $level) {
      foreach ($e in @(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue)) {
        if ($e.PSIsContainer) { if ($depth -eq 0 -and -not ($e.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $next += $e } ; continue }
        if ($exts -notcontains $e.Extension.ToLowerInvariant()) { continue }
        $t = $e.LastWriteTime
        if ($e.CreationTime -gt $t) { $t = $e.CreationTime }
        if ($t -lt $since) { continue }
        [void]$files.Add(@{ f = $e; at = $t })
      }
    }
    $level = $next | Select-Object -First 200
  }
  $r.count = $files.Count
  $r.truncated = $files.Count -gt 80
  $items = New-Object System.Collections.ArrayList
  foreach ($x in @($files | Sort-Object { $_.at } -Descending | Select-Object -First 80)) {
    $f = $x.f
    $ext = $f.Extension.ToLowerInvariant()
    $zone = $null; $hostName = $null
    try {
      $z = Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction Stop
      foreach ($line in $z) {
        if ($line -match '^ZoneId=(\d+)') { $zone = [int]$Matches[1] }
        elseif ($line -match '^(HostUrl|ReferrerUrl)=(.+)$' -and -not $hostName) { try { $hostName = ([Uri]$Matches[2].Trim()).Host } catch { } }
      }
    } catch { }
    $sig = $null; $signer = $null
    $pe = @('.exe', '.dll', '.scr', '.cpl') -contains $ext
    $hasCert = $null
    if ($zone -ge 3 -and $pe) {
      # Есть ли подпись - по заголовку файла (таблица сертификатов), без чтения всего файла.
      $fs = $null
      try {
        $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
        $br = New-Object IO.BinaryReader($fs)
        $fs.Position = 0x3C; $off = $br.ReadInt32()
        $fs.Position = $off
        if ($br.ReadUInt32() -eq 0x4550) {
          $fs.Position = $off + 24
          $magic = $br.ReadUInt16()
          $dd = $off + 24 + $(if ($magic -eq 0x20b) { 112 } else { 96 })
          $fs.Position = $dd + 4 * 8
          [void]$br.ReadUInt32(); $hasCert = ($br.ReadUInt32() -gt 0)
        }
      } catch { } finally { if ($fs) { $fs.Dispose() } }
      if ($hasCert -eq $false) { $sig = 'unsigned' }
      elseif ($hasCert -and $f.Length -ge 100MB) {
        # Большой установщик: подпись есть, но целиком её не пересчитываем (это долго) - только кто подписал.
        $sig = 'signed'
        try { $c = [Security.Cryptography.X509Certificates.X509Certificate2]([Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($f.FullName)); $cn = $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); $signer = $cn.Substring(0, [Math]::Min(80, $cn.Length)) } catch { }
      }
    }
    if ($zone -ge 3 -and $null -eq $sig -and $signable -contains $ext -and $f.Length -lt 100MB) {
      try {
        $s = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
        switch ([string]$s.Status) {
          'Valid' { $sig = 'valid' }
          'NotSigned' { $sig = 'unsigned' }
          'HashMismatch' { $sig = 'bad' }
          'NotTrusted' { $sig = 'bad' }
          default { $sig = 'unknown' }
        }
        if ($s.SignerCertificate) { $cn = [string]$s.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); $signer = $cn.Substring(0, [Math]::Min(80, $cn.Length)) }
      } catch { $sig = 'unknown' }
    }
    $name = $f.Name
    [void]$items.Add([ordered]@{
      name = $name; path = $f.FullName; ext = $ext; size = [int64]$f.Length; at = $x.at.ToString('o')
      zone = $zone; host = $hostName; sig = $sig; signer = $signer
      double = ($name -match '\.(pdf|docx?|xlsx?|pptx?|rtf|txt|jpe?g|png|gif|mp3|mp4|avi|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|cpl)$')
      rtlo = ($name.IndexOf([char]0x202E) -ge 0)
    })
  }
  $r.items = @($items)
  $r
}
