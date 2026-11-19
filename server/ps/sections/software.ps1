# Адамант: установленные программы (ТОЛЬКО ЧТЕНИЕ). Подключается из collect.ps1.
# Источник - разделы Uninstall реестра (HKLM, HKLM WOW6432Node, HKCU). Win32_Product не используется:
# он медленный и запускает проверку (а иногда и «починку») всех MSI-пакетов.
# Раздел 'software':
#   items[]    - { name, version, publisher, installDate ('yyyy-MM-dd' или null), scope ('hklm'|'hklm32'|'hkcu') }
#   count      - сколько программ найдено (до обрезки), truncated - список обрезан до 400
#   flashFiles - модули Flash, оставшиеся в System32/SysWOW64\Macromed\Flash (встроенный в Windows Flash)

Section 'software' {
  $roots = @(
    @{ hive = [Microsoft.Win32.Registry]::LocalMachine; path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'hklm' },
    @{ hive = [Microsoft.Win32.Registry]::LocalMachine; path = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'hklm32' },
    @{ hive = [Microsoft.Win32.Registry]::CurrentUser; path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'; scope = 'hkcu' }
  )
  $items = New-Object System.Collections.ArrayList
  $seen = @{}
  $total = 0
  foreach ($root in $roots) {
    $k = $null
    try { $k = $root.hive.OpenSubKey($root.path) } catch {}
    if (-not $k) { continue }
    foreach ($sub in $k.GetSubKeyNames()) {
      $sk = $null
      try { $sk = $k.OpenSubKey($sub) } catch {}
      if (-not $sk) { continue }
      try {
        $name = [string]$sk.GetValue('DisplayName')
        if (-not $name.Trim()) { continue }
        # Системные компоненты и обновления - не программы пользователя.
        if ([int]("0" + $sk.GetValue('SystemComponent')) -eq 1) { continue }
        if ($sk.GetValue('ParentKeyName')) { continue }
        if ([string]$sk.GetValue('ReleaseType') -match 'Update|Hotfix') { continue }
        if ($name -match '^(Security Update|Update for|Hotfix for|Обновление (безопасности )?для)\b' -or $name -match '\(KB\d{6,}\)') { continue }
        $ver = ([string]$sk.GetValue('DisplayVersion')).Trim()
        $key = ($name.Trim() + '|' + $ver).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $total++
        if ($items.Count -ge 400) { continue }
        $d = [string]$sk.GetValue('InstallDate')
        $date = $null
        if ($d -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
        [void]$items.Add([ordered]@{
          name = $name.Trim(); version = $ver; publisher = ([string]$sk.GetValue('Publisher')).Trim(); installDate = $date; scope = $root.scope
        })
      } catch {} finally { $sk.Close() }
    }
    $k.Close()
  }
  $flash = New-Object System.Collections.ArrayList
  foreach ($dir in @("$env:SystemRoot\System32\Macromed\Flash", "$env:SystemRoot\SysWOW64\Macromed\Flash")) {
    try {
      if (Test-Path -LiteralPath $dir) {
        foreach ($f in Get-ChildItem -LiteralPath $dir -Filter '*.ocx' -File -ErrorAction SilentlyContinue) { [void]$flash.Add([string]$f.FullName) }
      }
    } catch {}
  }
  [ordered]@{ count = $total; truncated = ($total -gt $items.Count); items = @($items); flashFiles = @($flash) }
}
