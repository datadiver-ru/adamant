# Адамант: Wi-Fi и готовность к беде (ТОЛЬКО ЧТЕНИЕ). Подключается из collect.ps1.
#
# Раздел 'wifi' - сохранённые сети и текущее подключение. Ответы netsh переводятся на язык Windows,
# поэтому здесь они не разбираются: в отчёт идёт текст, его разбирает server/rules-ready.js
# (подписи по-русски и по-английски). Пароли сетей НЕ читаются: команда без key=clear,
# а строки с содержимым ключа на всякий случай вырезаются.
#   service    - состояние службы WlanSvc ('Running', 'Stopped', 'missing')
#   interfaces - текст «netsh wlan show interfaces»
#   profiles[] - { name, text } - текст «netsh wlan show profile name=…» (до 40 сетей)
#
# Раздел 'readiness' - копии и восстановление:
#   restore     - { rpSessionInterval, disableSR, policyDisableSR, policyDisableConfig, lastCreated, lastSkipped,
#                   points, lastPoint, protectedDrives[], systemDrive } (points, lastPoint, protectedDrives - только с правами администратора)
#   fileHistory - { configured, lastBackup, policyDisabled }
#   oneDrive    - { accounts[] { account, folder }, roots[] }
#   knownFolders - { desktop, documents, pictures }

Section 'wifi' {
  $r = [ordered]@{ service = 'missing'; interfaces = $null; profiles = @() }
  $svc = Get-Service -Name 'WlanSvc' -ErrorAction SilentlyContinue
  if (-not $svc) { return $r }
  $r.service = [string]$svc.Status
  if ($r.service -ne 'Running') { return $r }
  $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
  function NetshText([string[]]$a) {
    $ErrorActionPreference = 'Continue'
    $t = (& $netsh @a 2>$null | Out-String)
    # netsh пишет в кодировке консоли. Если русский текст пришёл «квадратиками» - читаем ещё раз в кодировке OEM (866).
    if ($t -match [char]0xFFFD) {
      $old = [Console]::OutputEncoding
      try {
        [Console]::OutputEncoding = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
        $t = (& $netsh @a 2>$null | Out-String)
      } catch {} finally { try { [Console]::OutputEncoding = $old } catch {} }
    }
    # Никогда не передаём ключ сети, даже если он вдруг оказался в ответе.
    $lines = @($t -split "`r?`n" | Where-Object { $_ -notmatch '(?i)key content|содержимое ключа|keymaterial' } | ForEach-Object { $_.TrimEnd() })
    return (($lines -join "`n").Trim())
  }
  $r.interfaces = NetshText @('wlan', 'show', 'interfaces')
  $list = NetshText @('wlan', 'show', 'profiles')
  $names = New-Object System.Collections.ArrayList
  foreach ($line in ($list -split "`n")) {
    if ($line -match '^\s+.+?\s+:\s(.+?)\s*$') {
      $n = $Matches[1]
      if ($n -match '^<.*>$' -or $n.Contains('"') -or $names.Contains($n)) { continue }
      [void]$names.Add($n)
    }
  }
  $r.profiles = @($names | Select-Object -First 40 | ForEach-Object {
    [ordered]@{ name = [string]$_; text = (NetshText @('wlan', 'show', 'profile', "name=$_")) }
  })
  if (-not $names.Count) { $r.profilesText = $list }
  $r
}

Section 'readiness' {
  $r = [ordered]@{}
  # ---- Точки восстановления
  $sr = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
  $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
  $rs = [ordered]@{
    rpSessionInterval = Reg $sr 'RPSessionInterval'; disableSR = Reg $sr 'DisableSR'
    policyDisableSR = Reg $pol 'DisableSR'; policyDisableConfig = Reg $pol 'DisableConfig'
    lastCreated = $null; lastSkipped = $null; points = $null; lastPoint = $null; protectedDrives = $null
    systemDrive = [string]$env:SystemDrive
  }
  # Журнал «Приложение» доступен без прав администратора: 8194 - точка создана, 8216 - пропущена, потому что недавно уже создана.
  foreach ($id in 8194, 8216) {
    try {
      $e = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'System Restore'; Id = $id } -MaxEvents 1 -ErrorAction Stop
      if ($e) { if ($id -eq 8194) { $rs.lastCreated = IsoDate $e.TimeCreated } else { $rs.lastSkipped = IsoDate $e.TimeCreated } }
    } catch {}
  }
  if ($isAdmin) {
    try {
      $pts = @(Get-ComputerRestorePoint -ErrorAction Stop)
      $rs.points = $pts.Count
      if ($pts.Count) {
        $last = $pts | Sort-Object SequenceNumber | Select-Object -Last 1
        $rs.lastPoint = IsoDate ([Management.ManagementDateTimeConverter]::ToDateTime($last.CreationTime))
      }
    } catch { $R.errors.restorePoints = $_.Exception.Message }
    try {
      $k = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients' -ErrorAction Stop
      $v = $k.GetValue('{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}')
      $drives = New-Object System.Collections.ArrayList
      foreach ($s in @($v)) { if ([string]$s -match '\(([A-Za-z])%3A\)') { [void]$drives.Add($Matches[1].ToUpper() + ':') } }
      $rs.protectedDrives = @($drives)
    } catch {}
  }
  $r.restore = $rs

  # ---- История файлов
  $fhDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\FileHistory\Configuration'
  $fh = [ordered]@{ configured = $false; lastBackup = $null; policyDisabled = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory' 'Disabled' }
  try { $fh.configured = [bool](@(Get-ChildItem -LiteralPath $fhDir -Filter 'Config*.xml' -File -ErrorAction Stop).Count) } catch {}
  $pu = Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory' 'ProtectedUpToTime'
  try { if ($pu -and [long]$pu -gt 0) { $fh.lastBackup = [DateTime]::FromFileTimeUtc([long]$pu).ToString('o') } } catch {}
  $r.fileHistory = $fh

  # ---- OneDrive: учётные записи и папки
  $accounts = New-Object System.Collections.ArrayList
  try {
    foreach ($k in Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction Stop) {
      $uf = [string]$k.GetValue('UserFolder')
      if ($uf) { [void]$accounts.Add([ordered]@{ account = [string]$k.PSChildName; folder = $uf }) }
    }
  } catch {}
  $roots = @(@($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial) | Where-Object { $_ } | Select-Object -Unique)
  $r.oneDrive = [ordered]@{ accounts = @($accounts); roots = $roots }
  $r.knownFolders = [ordered]@{
    desktop = [Environment]::GetFolderPath('Desktop'); documents = [Environment]::GetFolderPath('MyDocuments'); pictures = [Environment]::GetFolderPath('MyPictures')
  }
  $r
}
