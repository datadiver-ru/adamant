# Адамант: расширения браузеров и политики браузеров (ТОЛЬКО ЧТЕНИЕ). Подключается из collect.ps1.
# Файлы профилей читаются с общим доступом (браузер может быть открыт) и ничего в них не меняется.
# Раздел 'browsers':
#   list[]     - { id ('chrome'|'edge'|'yandex'|'brave'|'opera'|'vivaldi'|'firefox'), name, profiles[] }
#     profiles[] - { profile, extensions[] }
#       extensions[] - { id, name, version, enabled, installed (ISO или null), location, store, unpacked, policy, default,
#                        updateHost, perms[] (разрешения и адреса сайтов), mv, signed (Firefox), foreign (Firefox) }
#   policies[] - { browser, scope ('hklm'|'hkcu'), forced[] { id, host }, values { имя: значение } } - только если политики есть
#   domain     - компьютер в домене организации (тогда политики браузера - обычное дело)
# История, пароли и cookies не читаются.

Section 'browsers' {
  Add-Type -AssemblyName System.Web.Extensions
  $js = New-Object Web.Script.Serialization.JavaScriptSerializer
  $js.MaxJsonLength = [int]::MaxValue
  $js.RecursionLimit = 200

  function ReadShared([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    $fs = $null
    try {
      $fs = New-Object IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
      if ($fs.Length -gt 64MB) { return $null }
      $sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
      return $sr.ReadToEnd()
    } catch { return $null } finally { if ($fs) { $fs.Dispose() } }
  }
  function ReadJson([string]$p) {
    $t = ReadShared $p
    if (-not $t) { return $null }
    try { return $js.DeserializeObject($t) } catch { return $null }
  }
  function Get([object]$d, [string]$k) {
    if ($d -is [Collections.IDictionary] -and $d.ContainsKey($k)) { return $d[$k] }
    return $null
  }
  function Strings($x) {
    $out = New-Object System.Collections.ArrayList
    foreach ($v in @($x)) { if ($v -is [string] -and $v) { [void]$out.Add($v) } }
    return ,$out
  }
  function UrlHost([string]$u) {
    if (-not $u) { return $null }
    try { return ([Uri]$u).Host.ToLowerInvariant() } catch { return $null }
  }
  # Имя вида __MSG_appName__ - из _locales\<язык>\messages.json самого расширения.
  function LocalName([string]$name, [string]$dir, [string]$locale) {
    if (-not $name -or $name -notmatch '^__MSG_(.+)__$') { return $name }
    $key = $Matches[1]
    foreach ($loc in @($locale, 'en', 'en_US', 'ru') | Where-Object { $_ } | Select-Object -Unique) {
      $m = ReadJson (Join-Path $dir ('_locales\' + $loc + '\messages.json'))
      if (-not $m) { continue }
      foreach ($k in $m.Keys) { if ($k -ieq $key) { $msg = Get $m[$k] 'message'; if ($msg) { return [string]$msg } } }
    }
    return $name
  }
  function FromFileTimeMicro($v) {
    try {
      $n = [int64]([string]$v)
      if ($n -le 0) { return $null }
      return ([datetime]::FromFileTimeUtc($n * 10)).ToString('o')
    } catch { return $null }
  }

  # ---------- Chromium: Chrome, Edge, Яндекс, Brave, Vivaldi, Opera
  $chromium = @(
    @{ id = 'chrome'; name = 'Google Chrome'; dir = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data') },
    @{ id = 'edge'; name = 'Microsoft Edge'; dir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data') },
    @{ id = 'yandex'; name = 'Yandex Browser'; dir = (Join-Path $env:LOCALAPPDATA 'Yandex\YandexBrowser\User Data') },
    @{ id = 'brave'; name = 'Brave'; dir = (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') },
    @{ id = 'vivaldi'; name = 'Vivaldi'; dir = (Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data') },
    @{ id = 'opera'; name = 'Opera'; dir = (Join-Path $env:APPDATA 'Opera Software\Opera Stable'); single = $true }
  )
  $list = New-Object System.Collections.ArrayList
  foreach ($b in $chromium) {
    if (-not (Test-Path -LiteralPath $b.dir)) { continue }
    $profiles = New-Object System.Collections.ArrayList
    $dirs = @()
    if ($b.single) { $dirs = @(@{ dir = $b.dir; name = 'Opera' }) }
    else {
      $ls = ReadJson (Join-Path $b.dir 'Local State')
      $cache = Get (Get $ls 'profile') 'info_cache'
      if ($cache -is [Collections.IDictionary] -and $cache.Count) {
        foreach ($k in $cache.Keys) { $dirs += @{ dir = (Join-Path $b.dir $k); name = [string](Get $cache[$k] 'name') } }
      } else {
        foreach ($d in Get-ChildItem -LiteralPath $b.dir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) { $dirs += @{ dir = $d.FullName; name = $d.Name } }
      }
    }
    foreach ($p in $dirs | Select-Object -First 20) {
      if (-not (Test-Path -LiteralPath $p.dir)) { continue }
      $settings = @{}
      foreach ($f in @('Preferences', 'Secure Preferences')) {
        $j = ReadJson (Join-Path $p.dir $f)
        $s = Get (Get $j 'extensions') 'settings'
        if ($s -is [Collections.IDictionary]) { foreach ($k in $s.Keys) { $settings[$k] = $s[$k] } }
      }
      $exts = New-Object System.Collections.ArrayList
      foreach ($id in $settings.Keys) {
        if ($exts.Count -ge 100) { break }
        $e = $settings[$id]
        if (-not ($e -is [Collections.IDictionary])) { continue }
        $loc = [int]("0" + (Get $e 'location'))
        # 5 и 10 - встроенные части самого браузера.
        if ($loc -eq 5 -or $loc -eq 10) { continue }
        $rel = [string](Get $e 'path')
        $extDir = $null
        if ($rel) { if ([IO.Path]::IsPathRooted($rel)) { $extDir = $rel } else { $extDir = Join-Path $p.dir ('Extensions\' + $rel) } }
        $man = Get $e 'manifest'
        if (-not ($man -is [Collections.IDictionary]) -and $extDir) { $man = ReadJson (Join-Path $extDir 'manifest.json') }
        # Без описания расширения (manifest.json) - остаток удалённого или служебная запись.
        if (-not ($man -is [Collections.IDictionary]) -or -not (Get $man 'name')) { continue }
        # Темы и приложения - не расширения.
        if ((Get $man 'theme') -or (Get $man 'app')) { continue }
        $state = Get $e 'state'
        $reasons = Get $e 'disable_reasons'
        $enabled = $true
        if ($null -ne $state) { $enabled = ([int]$state -eq 1) }
        elseif ($null -ne $reasons) { $enabled = (@($reasons).Count -eq 0 -or ($reasons -is [int] -and $reasons -eq 0)) }
        $perms = New-Object System.Collections.ArrayList
        foreach ($x in (Strings (Get $man 'permissions'))) { [void]$perms.Add($x) }
        foreach ($x in (Strings (Get $man 'host_permissions'))) { [void]$perms.Add($x) }
        foreach ($cs in @(Get $man 'content_scripts')) { foreach ($x in (Strings (Get $cs 'matches'))) { [void]$perms.Add($x) } }
        $name = [string](Get $man 'name')
        if ($extDir) { $name = LocalName $name $extDir ([string](Get $man 'default_locale')) }
        [void]$exts.Add([ordered]@{
          id = [string]$id; name = $name; version = [string](Get $man 'version'); enabled = [bool]$enabled
          installed = (FromFileTimeMicro $(if (Get $e 'first_install_time') { Get $e 'first_install_time' } else { Get $e 'install_time' })); location = $loc
          store = [bool](Get $e 'from_webstore'); unpacked = ($loc -eq 4); policy = ($loc -eq 7 -or $loc -eq 8)
          default = [bool](Get $e 'was_installed_by_default'); updateHost = (UrlHost ([string](Get $man 'update_url')))
          perms = @($perms | Select-Object -Unique | Select-Object -First 40); mv = [int]("0" + (Get $man 'manifest_version'))
        })
      }
      [void]$profiles.Add([ordered]@{ profile = $(if ($p.name) { $p.name } else { Split-Path $p.dir -Leaf }); extensions = @($exts) })
    }
    if ($profiles.Count) { [void]$list.Add([ordered]@{ id = $b.id; name = $b.name; profiles = @($profiles) }) }
  }

  # ---------- Firefox
  $ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
  if (Test-Path -LiteralPath $ffRoot) {
    $profiles = New-Object System.Collections.ArrayList
    foreach ($d in Get-ChildItem -LiteralPath $ffRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 20) {
      $j = ReadJson (Join-Path $d.FullName 'extensions.json')
      if (-not $j) { continue }
      $exts = New-Object System.Collections.ArrayList
      foreach ($a in @(Get $j 'addons')) {
        if ($exts.Count -ge 100) { break }
        if ((Get $a 'type') -ne 'extension') { continue }
        $loc = [string](Get $a 'location')
        if ($loc -match '^app-(builtin|system-defaults|system-addons)$' -or (Get $a 'isBuiltin') -or (Get $a 'isSystem')) { continue }
        $perms = New-Object System.Collections.ArrayList
        $up = Get $a 'userPermissions'
        foreach ($x in (Strings (Get $up 'permissions'))) { [void]$perms.Add($x) }
        foreach ($x in (Strings (Get $up 'origins'))) { [void]$perms.Add($x) }
        $inst = $null
        try { $ms = [int64](Get $a 'installDate'); if ($ms -gt 0) { $inst = ([DateTimeOffset]::FromUnixTimeMilliseconds($ms)).UtcDateTime.ToString('o') } } catch { }
        $signed = Get $a 'signedState'
        [void]$exts.Add([ordered]@{
          id = [string](Get $a 'id'); name = [string](Get (Get $a 'defaultLocale') 'name'); version = [string](Get $a 'version')
          enabled = ([bool](Get $a 'active') -and -not [bool](Get $a 'userDisabled')); installed = $inst; location = $loc
          store = ($loc -eq 'app-profile' -and -not [bool](Get $a 'foreignInstall')); unpacked = ($loc -eq 'app-temporary')
          policy = ($loc -eq 'app-system-policy'); default = $false; updateHost = (UrlHost ([string](Get $a 'sourceURI')))
          perms = @($perms | Select-Object -Unique | Select-Object -First 40); mv = [int]("0" + (Get $a 'manifestVersion'))
          signed = $(if ($null -eq $signed) { $null } else { [int]$signed }); foreign = [bool](Get $a 'foreignInstall')
        })
      }
      [void]$profiles.Add([ordered]@{ profile = $d.Name; extensions = @($exts) })
    }
    if ($profiles.Count) { [void]$list.Add([ordered]@{ id = 'firefox'; name = 'Mozilla Firefox'; profiles = @($profiles) }) }
  }

  # ---------- Политики браузеров: так вредоносные программы ставят неудаляемые расширения и подменяют поиск.
  $want = @('HomepageLocation', 'HomepageIsNewTabPage', 'NewTabPageLocation', 'DefaultSearchProviderEnabled', 'DefaultSearchProviderSearchURL', 'DefaultSearchProviderName', 'ProxyMode', 'ProxyServer', 'ProxyPacUrl', 'RestoreOnStartup', 'DeveloperToolsAvailability', 'ExtensionInstallSources')
  $roots = @(
    @{ browser = 'chrome'; path = 'SOFTWARE\Policies\Google\Chrome' },
    @{ browser = 'edge'; path = 'SOFTWARE\Policies\Microsoft\Edge' },
    @{ browser = 'yandex'; path = 'SOFTWARE\Policies\YandexBrowser' },
    @{ browser = 'brave'; path = 'SOFTWARE\Policies\BraveSoftware\Brave' },
    @{ browser = 'firefox'; path = 'SOFTWARE\Policies\Mozilla\Firefox' }
  )
  $policies = New-Object System.Collections.ArrayList
  foreach ($r in $roots) {
    foreach ($hive in @(@{ scope = 'hklm'; key = [Microsoft.Win32.Registry]::LocalMachine }, @{ scope = 'hkcu'; key = [Microsoft.Win32.Registry]::CurrentUser })) {
      $k = $null
      try { $k = $hive.key.OpenSubKey($r.path) } catch { }
      if (-not $k) { continue }
      try {
        $forced = New-Object System.Collections.ArrayList
        foreach ($sub in @('ExtensionInstallForcelist', 'Extensions\Install')) {
          $fk = $null
          try { $fk = $k.OpenSubKey($sub) } catch { }
          if (-not $fk) { continue }
          foreach ($n in $fk.GetValueNames()) {
            $v = [string]$fk.GetValue($n)
            $parts = $v.Split(';')
            $hostName = $null
            if ($parts.Count -gt 1) { $hostName = UrlHost $parts[1] } elseif ($v -match '^https?://') { $hostName = UrlHost $v }
            [void]$forced.Add([ordered]@{ id = $parts[0].Trim(); host = $hostName })
          }
          $fk.Close()
        }
        $vals = [ordered]@{}
        foreach ($n in $k.GetValueNames()) { if ($want -contains $n) { $v = $k.GetValue($n); $vals[$n] = $(if ($v -is [int]) { $v } else { ([string]$v).Substring(0, [Math]::Min(200, ([string]$v).Length)) }) } }
        if ($k.GetSubKeyNames() -contains 'RestoreOnStartupURLs') { $vals['RestoreOnStartupURLs'] = $true }
        if ($forced.Count -or $vals.Count) { [void]$policies.Add([ordered]@{ browser = $r.browser; scope = $hive.scope; forced = @($forced); values = $vals }) }
      } finally { $k.Close() }
    }
  }
  $domain = $false
  try { $domain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain } catch { }
  [ordered]@{ list = @($list); policies = @($policies); domain = $domain }
}
